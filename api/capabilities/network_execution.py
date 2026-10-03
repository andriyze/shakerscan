"""Compose the canonical network executor without growing the worker monolith."""
from .network import NetworkExecutionAdapter


def build_network_execution(*, prepared, parser, pool, run, target, policy, target_url,
                            revalidate, capability_input, redis, action_id, worker_id,
                            command_runner, max_stdout_bytes, max_stderr_bytes):
    common = dict(prepared=prepared, pool=pool, run=run, target=target, policy=policy,
                  target_url=target_url, revalidate=revalidate)
    if prepared.capability_name == 'ssh.connect':
        from .ssh import SshExecutionAdapter
        return SshExecutionAdapter(**common)
    if prepared.capability_name in {'ssh.exec', 'ssh.close'}:
        from .ssh_command_worker import SshCommandExecutionAdapter
        return SshCommandExecutionAdapter(**common, capability_input=capability_input,
            redis=redis, action_id=action_id, worker_id=worker_id)
    return NetworkExecutionAdapter(prepared=prepared, parser=parser, command_runner=command_runner,
        max_stdout_bytes=max_stdout_bytes, max_stderr_bytes=max_stderr_bytes)
