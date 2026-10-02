"""One target-bound SSH authentication action; credentials stay in the worker."""
from __future__ import annotations

import asyncio
import math
import re
import threading
import time
from typing import Any, Mapping

from hunt.capability_executor import CapabilityAdapterResult
from runtime.credential_store import PostgresCredentialProfileStore
from runtime.credentials import SSH_CREDENTIAL_KINDS, parse_credential_secret
from runtime.models import PreparedExecution
from secret_store import decrypt_secret
from .network_inputs import CapabilityInputError, _addresses, _require_network_policy
try:
    from targets.hunt_authority import read_hunt_authority, pin_authorized_first_contact
except ModuleNotFoundError:
    from ..targets.hunt_authority import read_hunt_authority, pin_authorized_first_contact


class SshConnectAdapter:
    capability_name = 'ssh.connect'
    adapter_name = 'paramiko'
    adapter_version = '1'

    def prepare(self, *, target, args, policy, context=None):
        _require_network_policy(policy)
        if set(args) - {'port','host_key_fingerprint'}:
            raise CapabilityInputError('SSH accepts only a port and optional host-key fingerprint')
        refs = [dict(item) for item in (context or {}).get('credential_refs') or ()
                if isinstance(item, Mapping) and item.get('principal_slot') == 'ssh'
                and item.get('source') == 'credential_profiles'
                and item.get('auth_kind') in SSH_CREDENTIAL_KINDS
                and 'ssh.connect' in (item.get('allowed_capabilities') or ())]
        if len(refs) != 1:
            raise CapabilityInputError('Select exactly one stored SSH credential profile granted ssh.connect')
        ref = refs[0]
        port = args.get('port', ref.get('service_port') or 22)
        if type(port) is not int or not 1 <= port <= 65535:
            raise CapabilityInputError('SSH port must be an integer between 1 and 65535')
        fingerprint = args.get('host_key_fingerprint')
        if fingerprint is not None and not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', str(fingerprint)):
            raise CapabilityInputError('SSH host-key fingerprint must use OpenSSH SHA256 format')
        values = {'address':_addresses(target)[0], 'port':port,
                  'profile_id':ref['profile_id'], 'profile_version':ref['profile_version'],
                  'host_key_fingerprint':fingerprint, 'commands_executed':False,
                  'device_fragility_points':3 if target.target_kind == 'device' else 0}
        return PreparedExecution('ssh.connect','paramiko','1',(),
            {'hosts_attempted':1,'tcp_ports_attempted':1,'tool_wall_seconds':120,
             **({'device_fragility_points':values['device_fragility_points']} if values['device_fragility_points'] else {})}, PreparedExecution.digest_input(values), values,
            'ssh-authentication/v1')


class SshExecutionAdapter:
    """Reuse the existing bounded Paramiko driver without exposing commands or secrets."""
    capability_name = 'ssh.connect'
    adapter_name = 'paramiko'
    adapter_version = '1'

    def __init__(self, *, prepared, pool, run, target, policy, target_url, revalidate):
        self.prepared, self.pool, self.run = prepared, pool, run
        self.target, self.policy, self.target_url = target, policy, target_url
        self.revalidate = revalidate

    async def execute(self, *, heartbeat, cancelled):
        from scanner_tools.ssh_scanner import ssh_auth_methods
        values = dict(self.prepared.redacted_execution)
        stopped = threading.Event()
        started = time.monotonic()
        traffic = False

        async def ssh_call(**kwargs):
            nonlocal traffic
            if cancelled() or stopped.is_set():
                raise asyncio.CancelledError()
            traffic = True
            task = asyncio.create_task(ssh_auth_methods(values['address'],port=values['port'],
                timeout=8,cancel_check=lambda: stopped.is_set() or cancelled(),**kwargs))
            try:
                while True:
                    done, _ = await asyncio.wait({task},timeout=0.2)
                    if cancelled():
                        stopped.set()
                    if task in done:
                        result = await task
                        if stopped.is_set():
                            raise asyncio.CancelledError()
                        return result
                    await heartbeat()
            except BaseException:
                stopped.set()
                # The thread observes cancellation before authentication; drain it so no
                # socket operation continues after this action has been terminalized.
                await asyncio.shield(task)
                raise

        observations = []
        try:
            if cancelled():
                raise asyncio.CancelledError()
            fingerprint = values.get('host_key_fingerprint')
            provenance = 'planner_hint' if fingerprint else None
            async with self.pool.acquire() as conn:
                await self.revalidate(conn,run=self.run,target=self.target,
                    target_url=self.target_url,policy=self.policy,capability_name=self.capability_name)
                authority = await read_hunt_authority(conn, self.run.get('device_target_id') or self.run['target_id'])
                trusted_key = next((key for key in authority['ssh_host_keys'] if key['port'] == values['port']), None)
                trusted = trusted_key['fingerprint'] if trusted_key else None
                if trusted:
                    if fingerprint and fingerprint != trusted:
                        raise CapabilityInputError('Planner SSH fingerprint differs from the operator’s saved host key')
                    fingerprint = trusted
                    provenance = 'operator_authorized_first_contact' if trusted_key.get('source') == 'authorized_first_contact' else 'operator_saved'
            if not trusted:
                probe = await ssh_call()
                observed = (probe.get('host_key') or {}).get('fingerprint_sha256')
                observations.append({'kind':'ssh_host_key_observation','address':values['address'],
                    'port':values['port'],'host_key':probe.get('host_key'),
                    'authentication_attempted':False,'commands_executed':False})
                if not authority['ssh_trust_first_contact']:
                    raise CapabilityInputError(f'SSH host key {observed or "unavailable"} is not trusted. Save its verified fingerprint or authorize first-contact trust in target Hunt permissions.')
                if fingerprint and fingerprint != observed:
                    raise CapabilityInputError('Observed SSH host key differs from the requested fingerprint')
                fingerprint = observed
                provenance = 'operator_authorized_first_contact'
                if not fingerprint:
                    raise CapabilityInputError('SSH host key could not be established')
                async with self.pool.acquire() as conn:
                    await pin_authorized_first_contact(conn, self.run.get('device_target_id') or self.run['target_id'],
                                                       values['port'], fingerprint)
            if cancelled():
                raise asyncio.CancelledError()
            async with self.pool.acquire() as conn:
                await self.revalidate(conn,run=self.run,target=self.target,
                    target_url=self.target_url,policy=self.policy,capability_name=self.capability_name)
                current_authority = await read_hunt_authority(conn, self.run.get('device_target_id') or self.run['target_id'])
                current_key = next((key['fingerprint'] for key in current_authority['ssh_host_keys']
                                    if key['port'] == values['port']), None)
                if current_key != fingerprint and (current_key or not current_authority['ssh_trust_first_contact']):
                    raise CapabilityInputError('SSH trust changed before authentication')
                resolved = await PostgresCredentialProfileStore().load_for_worker(conn,
                    profile_id=values['profile_id'],target_kind=self.target.target_kind,
                    target_id=self.target.target_id,capability=self.capability_name)
                if resolved.metadata.current_version != values['profile_version']:
                    raise CapabilityInputError('SSH credentials changed since Hunt admission; select the current version in a new Hunt')
                if resolved.metadata.auth_kind not in SSH_CREDENTIAL_KINDS:
                    raise CapabilityInputError('Selected profile is not an SSH identity')
                material = parse_credential_secret(resolved.metadata.auth_kind,decrypt_secret(resolved.encrypted_secret))
            credential = {'username':material.get('username'),'secret':material.get('secret'),
                'secondary_secret':material.get('secondary_secret'),
                'auth_kind':'ssh_password' if resolved.metadata.auth_kind == 'ssh_password' else 'ssh_private_key'}
            result = await ssh_call(credential=credential,expected_host_key_fingerprint=fingerprint)
            success = bool(result.get('authentication_succeeded'))
            observation = {'kind':'ssh_authentication_observation','address':values['address'],
                'transport':'tcp','port':values['port'],'service_name':'ssh',
                'credential_profile_id':values['profile_id'],'profile_version':values['profile_version'],
                'host_key':result.get('host_key'),'authentication_attempted':bool(result.get('authentication_attempted')),
                'host_key_provenance':provenance,
                'authentication_succeeded':success,'authentication_method':result.get('authentication_method'),
                'authentication_error':result.get('authentication_error'),
                'negotiated_algorithms':result.get('negotiated_algorithms') or {},
                'commands_executed':False,'connection_closed':True}
            observations.append(observation)
            status, errors = ('success',()) if success else ('failed',(result.get('authentication_error') or 'ssh_connection_failed',))
        except asyncio.CancelledError:
            status, errors = 'cancelled', ('cancelled',)
        except CapabilityInputError as exc:
            status, errors = 'failed', (str(exc),)
        except Exception as exc:
            status, errors = 'failed', (f'ssh_contract:{type(exc).__name__}',)
        return CapabilityAdapterResult(status=status,observations=tuple(observations),errors=errors,
            actual_budget={'hosts_attempted':int(traffic),'tcp_ports_attempted':int(traffic),
                'tool_wall_seconds':math.ceil(time.monotonic()-started),
                **({'device_fragility_points':values['device_fragility_points'] if traffic else 0}
                   if values['device_fragility_points'] else {})},execution_started=traffic,
            parser_version='ssh-authentication/v1',redacted_execution=values)
