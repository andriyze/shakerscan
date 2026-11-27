"""Import-layout-independent SSH audit projection shared by the Hunt router."""
try:
    from runtime.ssh_command_contract import command_audit as redact_ssh_command
except ModuleNotFoundError:
    from ..runtime.ssh_command_contract import command_audit as redact_ssh_command
