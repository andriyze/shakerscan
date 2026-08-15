"""
SSH Scanner module: Check SSH server configuration for security issues.

Uses Paramiko to detect authentication methods supported by SSH servers.
Reports password authentication as a medium severity finding per CIS/NIST guidance.
"""

import asyncio
import base64
import hashlib
import io
import socket
import time
from typing import Any

try:
    from ..redaction import redact_text
except ImportError:  # pragma: no cover - flat scanner runtime
    from redaction import redact_text

try:
    from .device_shell import validate_shell_plan
except ImportError:  # pragma: no cover - flat scanner runtime
    from device_shell import validate_shell_plan

# Paramiko - optional import for SSH scanning
try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False


SSH_HOST_REVIEW_BUNDLES: dict[str, str] = {
    "identity_runtime": "id 2>/dev/null; uname -a 2>/dev/null; uptime 2>/dev/null; date 2>/dev/null; (cat /etc/os-release 2>/dev/null || true)",
    "network_listeners": "(ip address 2>/dev/null || ifconfig -a 2>/dev/null || true); (ip route 2>/dev/null || route -n 2>/dev/null || true); (ss -lntup 2>/dev/null || netstat -lntup 2>/dev/null || true)",
    "processes_services": "(ps -eo user,pid,ppid,comm 2>/dev/null || ps -o user,pid,ppid,comm 2>/dev/null || true); (systemctl list-units --type=service --all --no-pager 2>/dev/null || rc-status 2>/dev/null || true)",
    "accounts_privilege": "awk -F: '{print $1 \":\" $3 \":\" $4 \":\" $7}' /etc/passwd 2>/dev/null; (getcap -r /bin /sbin /usr/bin /usr/sbin 2>/dev/null || true)",
    "filesystem_hardening": "mount 2>/dev/null; df -P 2>/dev/null; (sysctl kernel.randomize_va_space fs.suid_dumpable 2>/dev/null || true); (getenforce 2>/dev/null || true)",
    "software_packages": "(dpkg-query -W -f='${Package} ${Version}\\n' 2>/dev/null || rpm -qa 2>/dev/null || opkg list-installed 2>/dev/null || apk info -vv 2>/dev/null || true) | sed -n '1,400p'",
    "update_metadata": "for p in /etc/update* /etc/*release /var/lib/update* /var/lib/rauc /var/lib/swupdate; do test -e \"$p\" && stat -c '%A %U %G %s %y %n' \"$p\" 2>/dev/null; done",
}
DEFAULT_SSH_HOST_REVIEW_BUNDLES = tuple(SSH_HOST_REVIEW_BUNDLES)
MAX_SSH_BUNDLE_BYTES = 64 * 1024
MAX_SSH_REVIEW_BYTES = 256 * 1024
MAX_SSH_SHELL_COMMAND_BYTES = 64 * 1024
MAX_SSH_SHELL_TOTAL_BYTES = 256 * 1024


def ssh_host_key_fingerprint(key: Any) -> str:
    """Return the OpenSSH-style SHA256 fingerprint without exposing key data."""
    material = bytes(key.asbytes())
    encoded = base64.b64encode(hashlib.sha256(material).digest()).decode().rstrip("=")
    return f"SHA256:{encoded}"


def _collect_ssh_host_review(
    transport: Any,
    bundles: list[str] | tuple[str, ...],
    *,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """Execute only server-owned read-only command bundles on an authenticated transport."""
    requested = list(dict.fromkeys(str(item) for item in bundles))
    unknown = [item for item in requested if item not in SSH_HOST_REVIEW_BUNDLES]
    if unknown:
        return {"status": "rejected", "error": "unsupported_bundle", "bundles": [], "unknown": unknown}
    results: list[dict[str, Any]] = []
    total_bytes = 0
    for bundle in requested:
        command = SSH_HOST_REVIEW_BUNDLES[bundle]
        stdout = bytearray()
        stderr = bytearray()
        timed_out = False
        output_limit_hit = False
        exit_status: int | None = None
        started = time.monotonic()
        channel = None
        try:
            channel = transport.open_session(timeout=timeout)
            channel.settimeout(0.2)
            channel.exec_command(command)
            deadline = started + timeout
            while time.monotonic() < deadline:
                if total_bytes + len(stdout) + len(stderr) >= MAX_SSH_REVIEW_BYTES:
                    output_limit_hit = True
                    break
                progressed = False
                if channel.recv_ready() and total_bytes + len(stdout) + len(stderr) < MAX_SSH_REVIEW_BYTES:
                    remaining = min(
                        MAX_SSH_BUNDLE_BYTES - len(stdout) - len(stderr),
                        MAX_SSH_REVIEW_BYTES - total_bytes - len(stdout) - len(stderr),
                    )
                    if remaining > 0:
                        stdout.extend(channel.recv(min(8192, remaining)))
                    else:
                        output_limit_hit = True
                        break
                    progressed = True
                if channel.recv_stderr_ready() and total_bytes + len(stdout) + len(stderr) < MAX_SSH_REVIEW_BYTES:
                    remaining = min(
                        MAX_SSH_BUNDLE_BYTES - len(stdout) - len(stderr),
                        MAX_SSH_REVIEW_BYTES - total_bytes - len(stdout) - len(stderr),
                    )
                    if remaining > 0:
                        stderr.extend(channel.recv_stderr(min(8192, remaining)))
                    else:
                        output_limit_hit = True
                        break
                    progressed = True
                if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                    exit_status = int(channel.recv_exit_status())
                    break
                if not progressed:
                    time.sleep(0.02)
            else:
                timed_out = True
        except Exception as exc:
            results.append({
                "bundle": bundle,
                "status": "error",
                "error": type(exc).__name__,
                "duration_ms": int((time.monotonic() - started) * 1000),
            })
            continue
        finally:
            if channel is not None:
                try:
                    channel.close()
                except Exception:
                    pass
        raw_stdout = bytes(stdout)
        raw_stderr = bytes(stderr)
        total_bytes += len(raw_stdout) + len(raw_stderr)
        decoded_stdout = raw_stdout.decode("utf-8", errors="replace").replace("\x00", "")
        decoded_stderr = raw_stderr.decode("utf-8", errors="replace").replace("\x00", "")
        bundle_truncated = (
            output_limit_hit
            or len(raw_stdout) + len(raw_stderr) >= MAX_SSH_BUNDLE_BYTES
            or total_bytes >= MAX_SSH_REVIEW_BYTES
        )
        results.append({
            "bundle": bundle,
            "status": "timeout" if timed_out else "truncated" if bundle_truncated else "completed",
            "exit_status": exit_status,
            "stdout": redact_text(decoded_stdout),
            "stderr": redact_text(decoded_stderr),
            "stdout_sha256": hashlib.sha256(raw_stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(raw_stderr).hexdigest(),
            "truncated": bundle_truncated,
            "duration_ms": int((time.monotonic() - started) * 1000),
        })
        if total_bytes >= MAX_SSH_REVIEW_BYTES:
            break
    completed = sum(1 for item in results if item.get("status") == "completed")
    return {
        "schema_version": "device-ssh-host-review/v1",
        "capability_id": "ssh-authenticated-host-review",
        "status": "completed" if completed == len(requested) else "partial" if completed else "failed",
        "requested_bundles": requested,
        "completed_bundles": completed,
        "total_bytes": total_bytes,
        "commands_server_owned": True,
        "outputs_redacted": True,
        "bundles": results,
    }


def _execute_ssh_shell_plan(transport: Any, raw_plan: dict[str, Any]) -> dict[str, Any]:
    """Execute an exact, digest-verified, user-confirmed remote-device command plan."""
    try:
        plan = validate_shell_plan(raw_plan)
    except ValueError as exc:
        return {"status": "rejected", "error": str(exc), "commands": []}
    if (
        raw_plan.get("confirmation_basis") != "explicit_user_exact_command_confirmation"
        or raw_plan.get("confirmed_plan_digest") != plan.get("plan_digest")
        or not raw_plan.get("confirmed_at")
    ):
        return {"status": "rejected", "error": "explicit user confirmation is missing", "commands": []}
    results: list[dict[str, Any]] = []
    total_bytes = 0
    timeout = float(plan["timeout_seconds"])
    for index, command in enumerate(plan["commands"], start=1):
        stdout = bytearray()
        stderr = bytearray()
        timed_out = False
        truncated = False
        exit_status: int | None = None
        started = time.monotonic()
        channel = None
        try:
            channel = transport.open_session(timeout=timeout)
            channel.settimeout(0.2)
            channel.exec_command(command)
            deadline = started + timeout
            while time.monotonic() < deadline:
                progressed = False
                used = len(stdout) + len(stderr)
                remaining = min(
                    MAX_SSH_SHELL_COMMAND_BYTES - used,
                    MAX_SSH_SHELL_TOTAL_BYTES - total_bytes - used,
                )
                if remaining <= 0:
                    truncated = True
                    break
                if channel.recv_ready():
                    stdout.extend(channel.recv(min(8192, remaining)))
                    progressed = True
                used = len(stdout) + len(stderr)
                remaining = min(
                    MAX_SSH_SHELL_COMMAND_BYTES - used,
                    MAX_SSH_SHELL_TOTAL_BYTES - total_bytes - used,
                )
                if remaining <= 0:
                    truncated = True
                    break
                if channel.recv_stderr_ready():
                    stderr.extend(channel.recv_stderr(min(8192, remaining)))
                    progressed = True
                if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                    exit_status = int(channel.recv_exit_status())
                    break
                if not progressed:
                    time.sleep(0.02)
            else:
                timed_out = True
        except Exception as exc:
            results.append({
                "index": index,
                "command": command,
                "command_sha256": hashlib.sha256(command.encode()).hexdigest(),
                "status": "error",
                "error": type(exc).__name__,
                "duration_ms": int((time.monotonic() - started) * 1000),
            })
            continue
        finally:
            if channel is not None:
                try:
                    channel.close()
                except Exception:
                    pass
        raw_stdout = bytes(stdout)
        raw_stderr = bytes(stderr)
        total_bytes += len(raw_stdout) + len(raw_stderr)
        truncated = truncated or len(raw_stdout) + len(raw_stderr) >= MAX_SSH_SHELL_COMMAND_BYTES or total_bytes >= MAX_SSH_SHELL_TOTAL_BYTES
        results.append({
            "index": index,
            "command": command,
            "command_sha256": hashlib.sha256(command.encode()).hexdigest(),
            "status": "timeout" if timed_out else "truncated" if truncated else "completed",
            "exit_status": exit_status,
            "stdout": redact_text(raw_stdout.decode("utf-8", errors="replace").replace("\x00", "")),
            "stderr": redact_text(raw_stderr.decode("utf-8", errors="replace").replace("\x00", "")),
            "stdout_sha256": hashlib.sha256(raw_stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(raw_stderr).hexdigest(),
            "truncated": truncated,
            "duration_ms": int((time.monotonic() - started) * 1000),
        })
        if total_bytes >= MAX_SSH_SHELL_TOTAL_BYTES:
            break
    completed = sum(1 for item in results if item.get("status") == "completed" and item.get("exit_status") == 0)
    return {
        "schema_version": "device-agent-ssh-shell-result/v1",
        "capability_id": "agent-confirmed-ssh-shell",
        "plan_id": plan["plan_id"],
        "plan_digest": plan["plan_digest"],
        "confirmation_basis": raw_plan["confirmation_basis"],
        "confirmed_at": raw_plan["confirmed_at"],
        "remote_device_only": True,
        "pty_allocated": False,
        "stdin_forwarded": False,
        "status": "completed" if completed == len(plan["commands"]) else "partial" if completed else "failed",
        "commands_requested": len(plan["commands"]),
        "commands_completed": completed,
        "total_bytes": total_bytes,
        "commands": results,
    }


def classify_negotiated_ssh_algorithms(
    negotiated: dict[str, Any],
    *,
    key_type: str,
    key_bits: int,
) -> tuple[list[str], str | None]:
    """Classify negotiated legacy algorithms without requiring a live server."""
    weak: list[str] = []
    highest: str | None = None
    high_markers = ("3des", "blowfish", "arcfour", "des-cbc", "hmac-md5", "ssh-dss")
    for kind, algorithm in negotiated.items():
        lowered = str(algorithm or "").lower()
        if any(marker in lowered for marker in high_markers):
            weak.append(f"{kind}:{algorithm}")
            highest = "high"
        elif "hmac-sha1" in lowered:
            weak.append(f"{kind}:{algorithm}")
            if highest is None:
                highest = "medium"
    if key_type == "ssh-rsa" and key_bits and key_bits < 2048:
        weak.append(f"host_key:{key_type}-{key_bits}")
        highest = "high"
    return sorted(set(weak)), highest


async def ssh_auth_methods(
    host: str,
    port: int = 22,
    timeout: int = 10,
    credential: dict[str, Any] | None = None,
    host_review_bundles: list[str] | tuple[str, ...] | None = None,
    expected_host_key_fingerprint: str | None = None,
    shell_plan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Check SSH authentication methods using Paramiko.

    Uses Transport.auth_none() which returns allowed auth methods in the
    BadAuthenticationType exception when called with any username.

    Args:
        host: Target hostname or IP
        port: SSH port (default 22)
        timeout: Connection timeout in seconds

    Returns:
        Dict with auth_methods, password_auth_enabled, banner, and findings
    """
    result: dict[str, Any] = {
        "banner": None,
        "auth_methods": [],
        "auth_methods_complete": False,
        "password_auth_enabled": False,
        "keyboard_interactive_enabled": False,
        "publickey_enabled": False,
        "host_key": None,
        "pinned_host_key_fingerprint": expected_host_key_fingerprint,
        "negotiated_algorithms": {},
        "weak_algorithms": [],
        "weak_algorithm_severity": None,
        "port": port,
        "scan_completed": False,
        "authentication_attempted": False,
        "authentication_succeeded": False,
        "authentication_method": None,
        "authentication_error": None,
        "host_review": None,
        "shell_execution": None,
        "error": None,
        "findings": []
    }

    if not HAS_PARAMIKO:
        result["error"] = "Paramiko not installed - SSH scanning unavailable"
        return result

    def _check_ssh() -> dict[str, Any]:
        """Synchronous SSH check to run in thread."""
        check_result = {
            "banner": None,
            "auth_methods": [],
            "auth_methods_complete": False,
            "host_key": None,
            "pinned_host_key_fingerprint": expected_host_key_fingerprint,
            "negotiated_algorithms": {},
            "weak_algorithms": [],
            "weak_algorithm_severity": None,
            "authentication_attempted": False,
            "authentication_succeeded": False,
            "authentication_method": None,
            "authentication_error": None,
            "host_review": None,
            "shell_execution": None,
            "error": None
        }

        transport = None
        try:
            # Create transport with timeout
            # create_connection supports IPv4, IPv6, and hostnames without
            # forcing the caller to guess an address family.
            sock = socket.create_connection((host, port), timeout=timeout)

            transport = paramiko.Transport(sock)
            transport.banner_timeout = timeout
            transport.handshake_timeout = timeout

            # Start the transport (performs key exchange)
            transport.connect()

            # Get the banner
            check_result["banner"] = transport.remote_version
            server_key = transport.get_remote_server_key()
            key_type = str(server_key.get_name() or "unknown")
            key_bits = int(server_key.get_bits() or 0)
            try:
                fingerprint = ssh_host_key_fingerprint(server_key)
            except (AttributeError, TypeError, ValueError):
                fingerprint = None
            check_result["host_key"] = {
                "type": key_type,
                "bits": key_bits,
                "fingerprint_sha256": fingerprint,
            }
            if credential and expected_host_key_fingerprint and fingerprint != expected_host_key_fingerprint:
                check_result["authentication_error"] = "host_key_mismatch"
                check_result["error"] = "SSH host key did not match the previously observed device key"
                return check_result
            negotiated = {
                "cipher_in": transport.remote_cipher,
                "cipher_out": transport.local_cipher,
                "mac_in": transport.remote_mac,
                "mac_out": transport.local_mac,
                "host_key": key_type,
            }
            check_result["negotiated_algorithms"] = negotiated
            weak, weak_severity = classify_negotiated_ssh_algorithms(
                negotiated,
                key_type=key_type,
                key_bits=key_bits,
            )
            check_result["weak_algorithms"] = weak
            check_result["weak_algorithm_severity"] = weak_severity

            def _enumerate_methods(auth_transport: Any, username: str) -> tuple[list[str], bool]:
                try:
                    auth_transport.auth_none(username or "scanner_probe")
                    return ["none"], True
                except paramiko.BadAuthenticationType as exc:
                    methods = sorted({str(item) for item in exc.allowed_types if str(item)})
                    return methods, bool(methods)
                except paramiko.AuthenticationException:
                    return ["unknown"], False
                except Exception:
                    return ["unknown"], False

            if credential:
                auth_kind = str(credential.get("auth_kind") or "")
                username = str(credential.get("username") or "")
                secret = str(credential.get("secret") or "")
                # Authentication-method enumeration and the supplied credential
                # attempt are independent observations. A fresh transport keeps
                # auth_none state from contaminating the real attempt.
                enum_transport = None
                try:
                    enum_sock = socket.create_connection((host, port), timeout=timeout)
                    enum_transport = paramiko.Transport(enum_sock)
                    enum_transport.banner_timeout = timeout
                    enum_transport.handshake_timeout = timeout
                    enum_transport.connect()
                    methods, complete = _enumerate_methods(enum_transport, username)
                    check_result["auth_methods"] = methods
                    check_result["auth_methods_complete"] = complete
                except Exception:
                    check_result["auth_methods"] = ["unknown"]
                    check_result["auth_methods_complete"] = False
                finally:
                    if enum_transport:
                        try:
                            enum_transport.close()
                        except Exception:
                            pass
                check_result["authentication_attempted"] = True
                check_result["authentication_method"] = auth_kind
                try:
                    if auth_kind == "ssh_password":
                        transport.auth_password(username, secret, fallback=False)
                    elif auth_kind == "ssh_private_key":
                        passphrase = credential.get("secondary_secret") or None
                        key = None
                        loaders = [
                            getattr(paramiko, name, None)
                            for name in ("Ed25519Key", "ECDSAKey", "RSAKey", "DSSKey")
                        ]
                        for key_class in loaders:
                            if key_class is None:
                                continue
                            try:
                                key = key_class.from_private_key(io.StringIO(secret), password=passphrase)
                                break
                            except Exception:
                                continue
                        if key is None:
                            raise ValueError("unsupported_private_key")
                        transport.auth_publickey(username, key)
                    else:
                        raise ValueError("unsupported_auth_kind")
                    check_result["authentication_succeeded"] = bool(transport.is_authenticated())
                    if check_result["authentication_succeeded"] and host_review_bundles:
                        check_result["host_review"] = _collect_ssh_host_review(
                            transport,
                            host_review_bundles,
                        )
                    if check_result["authentication_succeeded"] and shell_plan:
                        check_result["shell_execution"] = _execute_ssh_shell_plan(transport, shell_plan)
                except paramiko.BadAuthenticationType as e:
                    check_result["authentication_error"] = "authentication_method_rejected"
                except paramiko.AuthenticationException:
                    check_result["authentication_error"] = "authentication_rejected"
                except ValueError as e:
                    sentinel = str(e)
                    check_result["authentication_error"] = (
                        sentinel
                        if sentinel in {"unsupported_private_key", "unsupported_auth_kind"}
                        else "authentication_error:ValueError"
                    )
                except Exception as e:
                    check_result["authentication_error"] = f"authentication_error:{type(e).__name__}"
            else:
                # auth_none returns allowed types when auth fails. No password or
                # key is guessed; this is the existing posture-only capability probe.
                methods, complete = _enumerate_methods(transport, "scanner_probe")
                check_result["auth_methods"] = methods
                check_result["auth_methods_complete"] = complete

        except TimeoutError:
            check_result["error"] = f"Connection timeout after {timeout}s"
        except OSError as e:
            check_result["error"] = f"Connection failed: {e}"
        except paramiko.SSHException as e:
            check_result["error"] = f"SSH error: {e}"
        except Exception as e:
            check_result["error"] = f"Unexpected error: {e}"
        finally:
            if transport:
                try:
                    transport.close()
                except Exception:
                    pass

        return check_result

    # Run the blocking SSH check in a thread
    try:
        check_result = await asyncio.to_thread(_check_ssh)
    except Exception as e:
        result["error"] = f"Thread execution error: {e}"
        return result

    # Update result with check results
    result["banner"] = check_result.get("banner")
    result["auth_methods"] = check_result.get("auth_methods", [])
    result["auth_methods_complete"] = bool(check_result.get("auth_methods_complete"))
    result["host_key"] = check_result.get("host_key")
    result["pinned_host_key_fingerprint"] = check_result.get("pinned_host_key_fingerprint")
    result["negotiated_algorithms"] = check_result.get("negotiated_algorithms", {})
    result["weak_algorithms"] = check_result.get("weak_algorithms", [])
    result["weak_algorithm_severity"] = check_result.get("weak_algorithm_severity")
    result["authentication_attempted"] = bool(check_result.get("authentication_attempted"))
    result["authentication_succeeded"] = bool(check_result.get("authentication_succeeded"))
    result["authentication_method"] = check_result.get("authentication_method")
    result["authentication_error"] = check_result.get("authentication_error")
    result["host_review"] = check_result.get("host_review")
    result["shell_execution"] = check_result.get("shell_execution")
    result["error"] = check_result.get("error")

    if result["error"]:
        return result

    # Analyze auth methods
    auth_methods = result["auth_methods"]
    result["password_auth_enabled"] = "password" in auth_methods
    result["keyboard_interactive_enabled"] = "keyboard-interactive" in auth_methods
    result["publickey_enabled"] = "publickey" in auth_methods
    result["scan_completed"] = True

    # Generate findings
    if result["password_auth_enabled"]:
        result["findings"].append({
            "title": "SSH Password Authentication Enabled",
            "severity": "medium",
            "cwe": "CWE-287",
            "evidence": {
                "host": host,
                "port": port,
                "auth_methods": auth_methods,
                "banner": result["banner"],
                "recommendation": "Disable password authentication in sshd_config (PasswordAuthentication no)"
            }
        })

    # keyboard-interactive can also be used for password auth in some configs
    if result["keyboard_interactive_enabled"] and not result["password_auth_enabled"]:
        result["findings"].append({
            "title": "SSH Keyboard-Interactive Authentication Enabled",
            "severity": "low",
            "cwe": "CWE-287",
            "evidence": {
                "host": host,
                "port": port,
                "auth_methods": auth_methods,
                "banner": result["banner"],
                "recommendation": "Review keyboard-interactive auth configuration - may allow password-based access"
            }
        })

    if result["weak_algorithms"]:
        result["findings"].append({
            "title": "SSH Negotiated Weak Cryptographic Algorithm",
            "severity": result["weak_algorithm_severity"] or "medium",
            "cwe": "CWE-327",
            "evidence": {
                "host": host,
                "port": port,
                "banner": result["banner"],
                "host_key": result["host_key"],
                "negotiated_algorithms": result["negotiated_algorithms"],
                "weak_algorithms": result["weak_algorithms"],
                "recommendation": "Disable legacy SSH ciphers, MACs, and undersized host keys"
            }
        })

    return result


async def full_ssh_scan(
    host: str,
    port: int = 22,
    timeout: int = 10,
    credential: dict[str, Any] | None = None,
    host_review_bundles: list[str] | tuple[str, ...] | None = None,
    expected_host_key_fingerprint: str | None = None,
    shell_plan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Perform a full SSH security scan.

    Currently wraps ssh_auth_methods but can be extended with additional checks
    like weak algorithm detection, key size analysis, etc.

    Args:
        host: Target hostname or IP
        port: SSH port (default 22)
        timeout: Connection timeout in seconds

    Returns:
        Complete SSH scan results
    """
    return await ssh_auth_methods(
        host,
        port,
        timeout,
        credential=credential,
        host_review_bundles=host_review_bundles,
        expected_host_key_fingerprint=expected_host_key_fingerprint,
        shell_plan=shell_plan,
    )
