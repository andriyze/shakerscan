"""Canonical bounds and non-secret audit projections for direct Hunt SSH commands."""
from __future__ import annotations

import hashlib
from typing import Any, Mapping

SSH_COMMAND_CAPABILITIES = frozenset({'ssh.exec', 'ssh.close'})
SSH_CONNECT_SECONDS = 10
SSH_SETUP_SECONDS = 30
SSH_COMMAND_SECONDS = 30
SSH_MAX_COMMAND_SECONDS = 300
SSH_MAX_OUTPUT_BYTES = 262_144
SSH_SESSION_IDLE_SECONDS = 120
SSH_SESSION_LIFETIME_SECONDS = 1800
SSH_MAX_SESSIONS = 32


def command_audit(values: Mapping[str, Any]) -> dict[str, Any]:
    """No command text, shell input or working-directory values in audit summaries."""
    result = dict(values)
    for name in ('command', 'cwd'):
        value = result.pop(name, None)
        if value is not None:
            raw = str(value).encode('utf-8')
            result[f'{name}_sha256'] = hashlib.sha256(raw).hexdigest()
            result[f'{name}_bytes'] = len(raw)
    return result


def ssh_command_specs(spec, schema, kinds):
    shared = {
        'port': {'type': 'integer', 'minimum': 1, 'maximum': 65535},
        'session_id': {'type': 'string', 'format': 'uuid'},
    }
    placement = {'network_reachability': True, 'credentials_resolved_server_side': True,
                 'credential_binding': 'ssh', 'remote_command_execution': True}
    return (
        spec('ssh.exec', 'Execute an operator-delegated command directly on the bound SSH target. '
             'Requires an explicit ssh.exec credential grant; ssh.connect alone grants no commands. '
             'Returns an opaque reusable session and output; never launches device inventory.',
             'network_tcp', 'credential', kinds, 'paramiko.exec', '1', 'active_testing',
             {'hosts_attempted': 1, 'tcp_ports_attempted': 1, 'tool_wall_seconds': 62,
              'device_fragility_points': 3}, placement,
             schema({**shared,
                 'command': {'type': 'string', 'minLength': 1, 'maxLength': 8192},
                 'cwd': {'type': 'string', 'minLength': 1, 'maxLength': 2048,
                         'description': 'Optional absolute POSIX working directory; each command uses a new channel.'},
                 'timeout_seconds': {'type': 'integer', 'minimum': 1, 'maximum': SSH_MAX_COMMAND_SECONDS},
                 'max_output_bytes': {'type': 'integer', 'minimum': 1024, 'maximum': SSH_MAX_OUTPUT_BYTES},
             }, required=('command',)),
             'ssh-command/v1', ('ssh_command_observation', 'tool_receipt'),
             default_timeout_ms=332_000, hunt_executor='worker_network',
             credential_transport='exact_origin', credential_interruption='cooperative'),
        spec('ssh.close', 'Close this Hunt\'s reusable SSH transport without executing a command.',
             'network_tcp', 'read_only', kinds, 'paramiko.exec', '1', None,
             {'tool_wall_seconds': 5}, {'network_reachability': False, 'credential_binding': 'ssh'},
             schema(shared, required=('session_id',)),
             'ssh-command/v1', ('ssh_session_observation', 'tool_receipt'),
             default_timeout_ms=5_000, hunt_executor='worker_network'),
    )
