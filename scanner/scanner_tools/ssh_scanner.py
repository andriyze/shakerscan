"""
SSH Scanner module: Check SSH server configuration for security issues.

Uses Paramiko to detect authentication methods supported by SSH servers.
Reports password authentication as a medium severity finding per CIS/NIST guidance.
"""

import asyncio
import socket
from typing import Any

# Paramiko - optional import for SSH scanning
try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False


async def ssh_auth_methods(host: str, port: int = 22, timeout: int = 10) -> dict[str, Any]:
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
        "port": port,
        "scan_completed": False,
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
            "error": None
        }

        transport = None
        try:
            # Create transport with timeout
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))

            transport = paramiko.Transport(sock)
            transport.banner_timeout = timeout
            transport.handshake_timeout = timeout

            # Start the transport (performs key exchange)
            transport.connect()

            # Get the banner
            check_result["banner"] = transport.remote_version

            # auth_none returns allowed types when auth fails
            # We use a probe username - doesn't need to be valid
            try:
                transport.auth_none("scanner_probe")
                # If auth_none succeeds, server allows anonymous access (very rare)
                check_result["auth_methods"] = ["none"]
            except paramiko.BadAuthenticationType as e:
                # This is the expected path - server returns allowed methods
                check_result["auth_methods"] = list(e.allowed_types)
            except paramiko.AuthenticationException:
                # Auth failed but no method list returned
                # Try to infer from what we know
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

    return result


async def full_ssh_scan(host: str, port: int = 22, timeout: int = 10) -> dict[str, Any]:
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
    return await ssh_auth_methods(host, port, timeout)
