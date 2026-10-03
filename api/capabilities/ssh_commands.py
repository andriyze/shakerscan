"""Prepare direct SSH actions from frozen target and credential references."""
from __future__ import annotations

from typing import Mapping
from uuid import UUID

from .network_inputs import CapabilityInputError, _addresses, _require_network_policy
try:
    from runtime.models import PreparedExecution
    from runtime.credentials import SSH_CREDENTIAL_KINDS
    from runtime.ssh_command_contract import (command_audit, SSH_SETUP_SECONDS,
        SSH_COMMAND_SECONDS, SSH_MAX_COMMAND_SECONDS, SSH_MAX_OUTPUT_BYTES)
except ModuleNotFoundError:
    from ..runtime.models import PreparedExecution
    from ..runtime.credentials import SSH_CREDENTIAL_KINDS
    from ..runtime.ssh_command_contract import (command_audit, SSH_SETUP_SECONDS,
        SSH_COMMAND_SECONDS, SSH_MAX_COMMAND_SECONDS, SSH_MAX_OUTPUT_BYTES)


def _integer(value, low, high, name):
    if type(value) is not int or not low <= value <= high:
        raise CapabilityInputError(f'{name} must be an integer from {low} to {high}')
    return value


class SshCommandAdapter:
    adapter_name = 'paramiko.exec'
    adapter_version = '1'

    def __init__(self, capability_name):
        self.capability_name = capability_name

    def prepare(self, *, target, args, policy, context=None):
        if self.capability_name == 'ssh.exec':
            _require_network_policy(policy)
        if set(args) - {'command', 'cwd', 'port', 'session_id', 'timeout_seconds', 'max_output_bytes'}:
            raise CapabilityInputError('Unsupported SSH input')
        session_id = args.get('session_id')
        try:
            session_id = str(UUID(str(session_id))) if session_id is not None else None
        except ValueError as exc:
            raise CapabilityInputError('Invalid SSH session ID') from exc
        if self.capability_name == 'ssh.close':
            if not session_id or set(args) - {'session_id', 'port'}:
                raise CapabilityInputError('ssh.close requires only the session ID and optional port')
            values = {'session_id': session_id, 'port': args.get('port'), 'target_digest': target.digest}
            return PreparedExecution(self.capability_name, self.adapter_name, '1', (),
                {'tool_wall_seconds': 5}, PreparedExecution.digest_input(values), values, 'ssh-command/v1')
        refs = [dict(item) for item in (context or {}).get('credential_refs') or ()
                if isinstance(item, Mapping) and item.get('principal_slot') == 'ssh'
                and item.get('source') == 'credential_profiles'
                and item.get('auth_kind') in SSH_CREDENTIAL_KINDS
                and 'ssh.exec' in (item.get('allowed_capabilities') or ())]
        if len(refs) != 1:
            raise CapabilityInputError('Select a stored SSH identity with explicit ssh.exec permission; ssh.connect is authentication only')
        ref = refs[0]
        command = args.get('command')
        if not isinstance(command, str) or not command.strip() or '\x00' in command or len(command.encode()) > 8192:
            raise CapabilityInputError('SSH command must be nonblank UTF-8 text of at most 8192 bytes without NUL')
        cwd = args.get('cwd')
        if cwd is not None and (not isinstance(cwd, str) or not cwd.startswith('/')
                               or '\x00' in cwd or len(cwd.encode()) > 2048):
            raise CapabilityInputError('cwd must be an absolute POSIX directory of at most 2048 bytes')
        port = (None if session_id and 'port' not in args else
                _integer(args.get('port', ref.get('service_port') or 22), 1, 65535, 'port'))
        timeout = _integer(args.get('timeout_seconds', SSH_COMMAND_SECONDS), 1, SSH_MAX_COMMAND_SECONDS, 'timeout_seconds')
        maximum = _integer(args.get('max_output_bytes', 65536), 1024, SSH_MAX_OUTPUT_BYTES, 'max_output_bytes')
        values = {'session_id': session_id, 'address': _addresses(target)[0], 'port': port,
                  'target_digest': target.digest, 'profile_id': ref['profile_id'],
                  'profile_version': ref['profile_version'], 'timeout_seconds': timeout,
                  'max_output_bytes': maximum, **command_audit({'command': command, 'cwd': cwd})}
        budget = {**({'hosts_attempted': 1, 'tcp_ports_attempted': 1} if not session_id else {}),
                  'tool_wall_seconds': timeout + 2 + (0 if session_id else SSH_SETUP_SECONDS),
                  **({'device_fragility_points': 1 if session_id else 3} if target.target_kind == 'device' else {})}
        return PreparedExecution(self.capability_name, self.adapter_name, '1', (), budget,
            PreparedExecution.digest_input(values), values, 'ssh-command/v1')
