"""
SSH Scanner module: Check SSH server configuration for security issues.

Uses Paramiko to detect authentication methods supported by SSH servers.
Reports password authentication as a medium severity finding per CIS/NIST guidance.
"""

import asyncio
import io
import socket
from typing import Any

# Paramiko - optional import for SSH scanning
try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False


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
        "password_auth_enabled": False,
        "keyboard_interactive_enabled": False,
        "publickey_enabled": False,
        "host_key": None,
        "negotiated_algorithms": {},
        "weak_algorithms": [],
        "weak_algorithm_severity": None,
        "port": port,
        "scan_completed": False,
        "authentication_attempted": False,
        "authentication_succeeded": False,
        "authentication_method": None,
        "authentication_error": None,
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
            "host_key": None,
            "negotiated_algorithms": {},
            "weak_algorithms": [],
            "weak_algorithm_severity": None,
            "authentication_attempted": False,
            "authentication_succeeded": False,
            "authentication_method": None,
            "authentication_error": None,
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
            check_result["host_key"] = {"type": key_type, "bits": key_bits}
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

            if credential:
                auth_kind = str(credential.get("auth_kind") or "")
                username = str(credential.get("username") or "")
                secret = str(credential.get("secret") or "")
                check_result["authentication_attempted"] = True
                check_result["authentication_method"] = auth_kind
                try:
                    if auth_kind == "ssh_password":
                        transport.auth_password(username, secret, fallback=False)
                        check_result["auth_methods"] = ["password"]
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
                        check_result["auth_methods"] = ["publickey"]
                    else:
                        raise ValueError("unsupported_auth_kind")
                    check_result["authentication_succeeded"] = bool(transport.is_authenticated())
                except paramiko.BadAuthenticationType as e:
                    check_result["auth_methods"] = list(e.allowed_types)
                    check_result["authentication_error"] = "authentication_method_rejected"
                except paramiko.AuthenticationException:
                    check_result["authentication_error"] = "authentication_rejected"
                except ValueError as e:
                    check_result["authentication_error"] = str(e)
                except Exception as e:
                    check_result["authentication_error"] = f"authentication_error:{type(e).__name__}"
            else:
                # auth_none returns allowed types when auth fails. No password or
                # key is guessed; this is the existing posture-only capability probe.
                try:
                    transport.auth_none("scanner_probe")
                    check_result["auth_methods"] = ["none"]
                except paramiko.BadAuthenticationType as e:
                    check_result["auth_methods"] = list(e.allowed_types)
                except paramiko.AuthenticationException:
                    check_result["auth_methods"] = ["unknown"]

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
    result["host_key"] = check_result.get("host_key")
    result["negotiated_algorithms"] = check_result.get("negotiated_algorithms", {})
    result["weak_algorithms"] = check_result.get("weak_algorithms", [])
    result["weak_algorithm_severity"] = check_result.get("weak_algorithm_severity")
    result["authentication_attempted"] = bool(check_result.get("authentication_attempted"))
    result["authentication_succeeded"] = bool(check_result.get("authentication_succeeded"))
    result["authentication_method"] = check_result.get("authentication_method")
    result["authentication_error"] = check_result.get("authentication_error")
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
    return await ssh_auth_methods(host, port, timeout, credential=credential)
