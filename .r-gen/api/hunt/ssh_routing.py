"""Worker-owned SSH transport routing, not authority or a second work queue engine.

Directory entries contain no credentials. The existing durable Hunt reservation
is still required before a command can run, including on the owning worker.
"""
from __future__ import annotations

import hashlib
import json
from uuid import UUID

WORKER_TTL = 8
DIRECTORY_TTL = 420
OUTPUT_TTL = 900


def _uuid(value) -> str:
    return str(UUID(str(value)))


def worker_key(worker_id: str) -> str:
    return 'hunt:ssh:worker:' + hashlib.sha256(worker_id.encode()).hexdigest()


def worker_queue(base_queue: str, worker_id: str) -> str:
    return base_queue + ':ssh:' + hashlib.sha256(worker_id.encode()).hexdigest()


def session_key(session_id: str) -> str:
    return 'hunt:ssh:session:' + _uuid(session_id)


def output_key(hunt_id: str, action_id: str) -> str:
    return 'hunt:ssh:output:' + _uuid(hunt_id) + ':' + _uuid(action_id)


def cancel_key(hunt_id: str, action_id: str) -> str:
    return 'hunt:ssh:cancel:' + _uuid(hunt_id) + ':' + _uuid(action_id)


def publish_session(redis, *, session_id, hunt_id, worker_id):
    redis.set(session_key(session_id), json.dumps({
        'hunt_id': _uuid(hunt_id), 'worker_id': worker_id,
    }), ex=DIRECTORY_TTL)


def route_session(redis, *, base_queue, hunt_id, session_id):
    """Never reroute an established session to a new worker or re-execute a command."""
    raw = redis.get(session_key(session_id))
    try:
        value = json.loads(raw) if raw is not None else {}
        worker_id = value['worker_id']
        if value['hunt_id'] != _uuid(hunt_id) or not isinstance(worker_id, str):
            raise ValueError('session_binding_mismatch')
        if not redis.exists(worker_key(worker_id)):
            raise ValueError('ssh_session_worker_unavailable')
        return worker_queue(base_queue, worker_id)
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError('ssh_session_unavailable') from exc


def seal_input(name, values):
    if name != 'ssh.exec':
        return dict(values)
    try:
        from secret_store import encrypt_secret
    except ModuleNotFoundError:
        from ..secret_store import encrypt_secret
    return {'encrypted_ssh_input': encrypt_secret(json.dumps(dict(values)))}


def unseal_input(name, values):
    if name != 'ssh.exec':
        return dict(values)
    try:
        from secret_store import decrypt_secret
    except ModuleNotFoundError:
        from ..secret_store import decrypt_secret
    if set(values) != {'encrypted_ssh_input'} or not str(values.get('encrypted_ssh_input', '')).startswith('enc:fernet:'):
        raise ValueError('SSH queued input must be encrypted')
    result = json.loads(decrypt_secret(values['encrypted_ssh_input']))
    if not isinstance(result, dict):
        raise ValueError('Invalid SSH queued input')
    return result


def owner_available(redis, queue_name, base_queue):
    prefix = base_queue + ':ssh:'
    return not queue_name.startswith(prefix) or bool(redis.exists('hunt:ssh:worker:' + queue_name[len(prefix):]))
