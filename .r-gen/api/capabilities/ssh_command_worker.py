"""Direct SSH execution adapter for the existing durable Hunt worker lifecycle."""
from __future__ import annotations

import asyncio
import json
import math
import hashlib
import threading
import time

from .network_inputs import CapabilityInputError
from .ssh_channel import OutputCapture, run_command
from .ssh_transport import SSH_TRANSPORTS
try:
    from hunt.capability_executor import CapabilityAdapterResult
    from hunt.ssh_routing import (publish_session, session_key, output_key, cancel_key, OUTPUT_TTL)
    from runtime.credential_store import PostgresCredentialProfileStore
    from runtime.credentials import SSH_CREDENTIAL_KINDS, parse_credential_secret
    from secret_store import decrypt_secret
    from targets.hunt_authority import read_hunt_authority, pin_authorized_first_contact
except ModuleNotFoundError:
    from ..hunt.capability_executor import CapabilityAdapterResult
    from ..hunt.ssh_routing import (publish_session, session_key, output_key, cancel_key, OUTPUT_TTL)
    from ..runtime.credential_store import PostgresCredentialProfileStore
    from ..runtime.credentials import SSH_CREDENTIAL_KINDS, parse_credential_secret
    from ..secret_store import decrypt_secret
    from ..targets.hunt_authority import read_hunt_authority, pin_authorized_first_contact


class SshCommandExecutionAdapter:
    adapter_name = 'paramiko.exec'
    adapter_version = '1'

    def __init__(self, *, prepared, pool, run, target, policy, target_url, revalidate,
                 capability_input, redis, action_id, worker_id, transports=SSH_TRANSPORTS):
        self.prepared, self.pool, self.run, self.target = prepared, pool, run, target
        self.policy, self.target_url, self.revalidate = policy, target_url, revalidate
        self.input, self.redis = capability_input, redis
        self.action_id, self.worker_id, self.transports = action_id, worker_id, transports
        self.capability_name = prepared.capability_name

    async def execute(self, *, heartbeat, cancelled):
        values = dict(self.prepared.redacted_execution)
        hunt_id = str(self.run['id'])
        stop_key = cancel_key(hunt_id, str(self.action_id))
        progress_key = output_key(hunt_id, str(self.action_id))
        stopped = threading.Event()
        session = None
        reused = False
        attempted_connection = False
        started = time.monotonic()
        last_guard = last_heartbeat = 0.0
        deadline_exceeded = False
        deadline = started + self.prepared.estimated_budget['tool_wall_seconds'] - 1
        observation = {'kind': 'ssh_command_observation', 'command_dispatched': False}
        input_hash = hashlib.sha256(json.dumps(self.input, sort_keys=True, separators=(',', ':'),
                                              ensure_ascii=False).encode()).hexdigest()
        capture = OutputCapture(values.get('max_output_bytes', 1024))

        def is_cancelled():
            return stopped.is_set() or cancelled() or bool(self.redis.exists(stop_key))

        async def validate(*, require_key=False):
            async with self.pool.acquire() as conn:
                current = await conn.fetchrow('SELECT * FROM hunt_runs WHERE id=$1', self.run['id'])
                if not current or current['status'] not in {'active', 'awaiting_planner', 'budget_exhausted'}:
                    raise CapabilityInputError('Hunt stopped')
                await self.revalidate(conn, run=current, target=self.target, target_url=self.target_url,
                    policy=self.policy, capability_name=self.capability_name, capability_input=self.input)
                authority = await read_hunt_authority(conn, self.run.get('device_target_id') or self.run['target_id'])
                key = next((item['fingerprint'] for item in authority['ssh_host_keys']
                            if item['port'] == values['port']), None)
                if require_key and key != session.fingerprint:
                    raise CapabilityInputError('SSH host trust changed')
                resolved = await PostgresCredentialProfileStore().load_for_worker(conn,
                    profile_id=values['profile_id'], target_kind=self.target.target_kind,
                    target_id=self.target.target_id, capability='ssh.exec')
                if resolved.metadata.current_version != values['profile_version']:
                    raise CapabilityInputError('SSH identity version changed; start a Hunt with the current identity')
                if resolved.metadata.auth_kind not in SSH_CREDENTIAL_KINDS:
                    raise CapabilityInputError('Selected profile is not an SSH identity')
                return authority, key, resolved

        async def threaded(function, *args, guard=True, phase_seconds=None, **kwargs):
            nonlocal last_guard, last_heartbeat, deadline_exceeded
            stage_deadline = min(deadline, time.monotonic()+phase_seconds) if phase_seconds else deadline
            task = asyncio.create_task(asyncio.to_thread(function, *args, **kwargs))
            try:
                while True:
                    done, _ = await asyncio.wait({task}, timeout=0.1)
                    if time.monotonic() >= stage_deadline:
                        deadline_exceeded = True
                        stopped.set()
                    if is_cancelled():
                        stopped.set()
                        session.close()
                    if task in done:
                        return await task
                    now = time.monotonic()
                    if now - last_heartbeat >= 10:
                        await heartbeat()
                        last_heartbeat = now
                    if guard and now - last_guard >= 1:
                        await validate(require_key=True)
                        last_guard = now
            except BaseException:
                stopped.set()
                session.close()
                # Drain the actual thread after fencing its socket, not just its awaiter.
                await asyncio.shield(asyncio.gather(task, return_exceptions=True))
                raise

        last_publish = 0.0
        def progress(value):
            nonlocal last_publish
            now = time.monotonic()
            if now-last_publish >= 0.1:
                self.redis.set(progress_key, json.dumps({**value, 'status': 'running',
                    'session_id': session.session_id, 'input_sha256': input_hash}), ex=OUTPUT_TTL)
                last_publish = now

        try:
            if self.capability_name == 'ssh.close':
                closed = self.transports.remove(values['session_id'], hunt_id=hunt_id,
                                                 target_digest=self.target.digest)
                self.redis.delete(session_key(values['session_id']))
                return CapabilityAdapterResult(status='success',
                    observations=({'kind': 'ssh_session_observation', 'session_id': values['session_id'],
                                   'connection_closed': True, 'was_open': closed},),
                    actual_budget={'tool_wall_seconds': 0}, parser_version='ssh-command/v1',
                    redacted_execution=values)
            if is_cancelled():
                raise asyncio.CancelledError()
            binding = (hunt_id, self.target.digest, values['address'], values['port'],
                       str(values['profile_id']), values['profile_version'])
            session, reused = self.transports.acquire(binding, values['session_id'])
            if reused:
                values['port'] = session.binding[3]
            authority, key, resolved = await validate()
            if not reused:
                attempted_connection = True
                observed = await threaded(session.connect, values['address'], values['port'], is_cancelled, guard=False)
                if key and key != observed:
                    raise CapabilityInputError('SSH host key does not match the operator pin')
                if not key:
                    if not authority['ssh_trust_first_contact']:
                        observation['observed_host_key'] = observed
                        raise CapabilityInputError('Save the verified SSH key or authorize first-contact trust before credential use')
                    async with self.pool.acquire() as conn:
                        await pin_authorized_first_contact(conn,
                            self.run.get('device_target_id') or self.run['target_id'], values['port'], observed)
            # Current grant/version/pin are checked even when reusing authentication.
            _, _, resolved = await validate(require_key=True)
            material = parse_credential_secret(resolved.metadata.auth_kind, decrypt_secret(resolved.encrypted_secret))
            capture = OutputCapture(values['max_output_bytes'],
                (material.get('secret'), material.get('secondary_secret')))
            if not reused:
                await threaded(session.authenticate, material, resolved.metadata.auth_kind, is_cancelled)
            del material
            if is_cancelled():
                raise asyncio.CancelledError()
            await validate(require_key=True)
            observation.update(session_id=session.session_id, connection_reused=reused,
                host_key_fingerprint=session.fingerprint, authentication_seconds=round(time.monotonic()-started, 4))
            command_result = await threaded(run_command, session, values,
                command=self.input['command'], cwd=self.input.get('cwd'), stopped=is_cancelled,
                capture=capture, on_progress=progress, outcome=observation, phase_seconds=values['timeout_seconds']+0.25)
            observation.update(command_result)
            if command_result['cancelled']:
                status = 'cancelled'
            elif command_result['timed_out'] or capture.truncated or command_result['execution_uncertain']:
                status = 'partial'
            elif command_result['exit_status'] is None:
                status = 'failed'
            else:
                status = 'success'
            errors = (command_result['error'],) if command_result.get('error') else ()
        except asyncio.CancelledError:
            status, errors = 'cancelled', ('cancelled',)
            observation.update(cancelled=True, execution_uncertain=True, remote_termination_confirmed=False)
        except CapabilityInputError as exc:
            status, errors = 'failed', (str(exc),)
        except Exception as exc:
            status, errors = 'failed', ('ssh_execution:' + type(exc).__name__,)
        finally:
            if session is not None:
                self.transports.release(session)
        if deadline_exceeded:
            status, errors = 'partial', ('ssh_action_deadline',)
            observation.update(timed_out=True, cancelled=False, execution_uncertain=bool(observation['command_dispatched']),
                               remote_termination_confirmed=False)
        observation.update(capture.public(final=True))
        if status in {'failed', 'cancelled'} and observation['command_dispatched'] and observation.get('exit_status') is None:
            observation.update(execution_uncertain=True, remote_termination_confirmed=False)
        if session is not None:
            keep = status == 'success' and session.usable() and not is_cancelled()
            if keep:
                publish_session(self.redis, session_id=session.session_id, hunt_id=hunt_id, worker_id=self.worker_id)
            else:
                self.transports.remove(session.session_id)
                self.redis.delete(session_key(session.session_id))
            observation['connection_closed'] = not keep
        observation['total_seconds'] = round(time.monotonic()-started, 4)
        self.redis.set(progress_key, json.dumps({**observation, 'status': status,
            'input_sha256': input_hash}), ex=OUTPUT_TTL)
        self.redis.delete(stop_key)
        actual = {'tool_wall_seconds': math.ceil(time.monotonic()-started)}
        for key_name in ('hosts_attempted', 'tcp_ports_attempted'):
            if key_name in self.prepared.estimated_budget:
                actual[key_name] = int(attempted_connection)
        if 'device_fragility_points' in self.prepared.estimated_budget:
            actual['device_fragility_points'] = self.prepared.estimated_budget['device_fragility_points'] if attempted_connection or observation['command_dispatched'] else 0
        return CapabilityAdapterResult(status=status, observations=(observation,), errors=errors,
            partial=status == 'partial', timed_out=status == 'partial' and bool(observation.get('timed_out')),
            execution_started=attempted_connection or bool(observation['command_dispatched']),
            actual_budget=actual, parser_version='ssh-command/v1', redacted_execution=values)
