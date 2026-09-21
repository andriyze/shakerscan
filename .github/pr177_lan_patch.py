"""Temporary, hash-guarded editor for PR 177; removed after applying and testing."""
from pathlib import Path
import hashlib

p = Path("scanner.sh")
b = p.read_bytes()
expected = "ff0eac41d577532fa03513383f2e0e4f4ec503bf"
actual = hashlib.sha1(f"blob {len(b)}\0".encode() + b).hexdigest()
if actual != expected:
    raise SystemExit(f"scanner.sh changed concurrently: {actual}; refusing to overwrite")
s = b.decode()

def replace(old, new):
    global s
    if s.count(old) != 1:
        raise SystemExit(f"expected one patch anchor: {old[:100]!r}, found {s.count(old)}")
    s = s.replace(old, new, 1)

lan = r'''# Discover only up, private LAN interfaces. Never probe an external host or select
# loopback, Docker bridges, Tailscale, or common VPN/tunnel interfaces.
lan_ipv4_candidates() {
    local records
    if command_exists ip; then
        records="$(ip -o -4 addr show up 2>/dev/null)" || return 1
        records="$(printf '%s\n' "$records" | awk '{ iface=$2; sub(/@.*/, "", iface); split($4, a, "/"); print iface, a[1] }')"
    elif command_exists ifconfig; then
        records="$(ifconfig -a 2>/dev/null)" || return 1
        records="$(printf '%s\n' "$records" | awk '
            /^[^ \t]/ { iface=$1; sub(/:$/, "", iface); up=($0 ~ /[<,]UP[,>]/) }
            up && $1 == "inet" { print iface, $2 }
        ')"
    else
        echo 'Error: --lan needs ip (Linux) or ifconfig (macOS/BSD).' >&2
        return 1
    fi
    printf '%s\n' "$records" | awk '
        $1 ~ /^(lo[0-9]*|docker.*|br-.*|virbr.*|veth.*|cni.*|flannel.*|tailscale.*|tun[0-9]*|tap[0-9]*|utun[0-9]*|wg.*|zt.*)$/ { next }
        {
            n=split($2, a, "."); valid=(n == 4)
            for (i=1; i<=n; i++) if (a[i] !~ /^[0-9]+$/ || a[i]+0 > 255) valid=0
            if (valid && (a[1]+0 == 10 || (a[1]+0 == 172 && a[2]+0 >= 16 && a[2]+0 <= 31) || (a[1]+0 == 192 && a[2]+0 == 168)))
                print $1, $2
        }
    ' | sort -u
}

lan_default_interface() {
    if command_exists ip; then
        ip -4 route show default 2>/dev/null | awk '{ for (i=1;i<NF;i++) if ($i == "dev") { print $(i+1); exit } }'
    elif command_exists route; then
        route -n get default 2>/dev/null | awk '$1 == "interface:" {print $2; exit}'
    fi
}

select_lan_ipv4() {
    local requested="${1:-}" candidates selected preferred count
    candidates="$(lan_ipv4_candidates)" || return 1
    if [ -n "$requested" ]; then
        selected="$(printf '%s\n' "$candidates" | awk -v ip="$requested" '$2 == ip { print $2; exit }')"
        if [ -z "$selected" ]; then
            echo "Error: --lan bind address must be an assigned RFC1918 IPv4 on an up LAN interface: $requested" >&2
            return 1
        fi
    else
        selected="$(printf '%s\n' "$candidates" | awk 'NF == 2 { print $2 }' | sort -u)"
        count="$(printf '%s\n' "$selected" | awk 'NF {n++} END {print n+0}')"
        if [ "$count" -gt 1 ]; then
            preferred="$(lan_default_interface)"
            selected="$(printf '%s\n' "$candidates" | awk -v iface="$preferred" '$1 == iface { print $2 }' | sort -u)"
            count="$(printf '%s\n' "$selected" | awk 'NF {n++} END {print n+0}')"
        fi
        if [ "$count" -ne 1 ]; then
            echo 'Error: --lan could not select one private LAN IPv4 address.' >&2
            echo 'Use: shakerscan start --lan --bind-host <assigned-LAN-IP>' >&2
            [ -z "$candidates" ] || printf 'Candidates (interface address):\n%s\n' "$candidates" >&2
            return 1
        fi
    fi
    printf '%s\n' "$selected"
}

print_lan_client_help() {
    [ "${LAN_ACCESS:-0}" -eq 1 ] || return 0
    local url="http://${SHAKERSCAN_BIND_HOST}:${SHAKERSCAN_API_PORT:-8080}"
    echo
    echo '[lan] From another trusted machine on this network (client only; no Docker):'
    echo '  pipx install shakerscan'
    printf '  shakerscan doctor --url %s\n' "$url"
    printf '  shakerscan api --url %s GET /health\n' "$url"
    printf '  shakerscan mcp --url %s\n' "$url"
    echo '[lan] Or select this instance for all client commands in this shell:'
    printf '  export SHAKERSCAN_API_URL=%s\n' "$url"
    echo '  export SHAKERSCAN_MCP_ALLOW_REMOTE_API=true'
    echo '  shakerscan api GET /findings'
    echo '  shakerscan mcp'
    printf '[lan] Web UI: http://%s:%s\n' "$SHAKERSCAN_BIND_HOST" "${SHAKERSCAN_UI_PORT:-3000}"
    echo '[lan] Configured client commands do not fall back to pub.shakerscan.com.'
    echo '[lan] To return to localhost: shakerscan restart --bind-host 127.0.0.1 --public-host localhost'
}

'''
replace("REMOTE_ACCESS=0\n", "REMOTE_ACCESS=0\nLAN_ACCESS=0\n")
replace("format_url_host() {", lan + "format_url_host() {")
replace('    if [ "$REMOTE_ACCESS" -ne 1 ]; then\n        return 0\n    fi\n',
        '    if [ "$REMOTE_ACCESS" -ne 1 ] && [ "${LAN_ACCESS:-0}" -ne 1 ] && [ "${SHAKERSCAN_BIND_HOST_EXPLICIT:-0}" -ne 1 ]; then\n        return 0\n    fi\n')
replace('    local explicit_shell_bind="${SHAKERSCAN_BIND_HOST_EXPLICIT:-0}"\n\n    if [ "$REMOTE_ACCESS" -eq 1 ]; then', r'''    local explicit_shell_bind="${SHAKERSCAN_BIND_HOST_EXPLICIT:-0}"
    local lan_ip requested_bind=""

    if [ "${LAN_ACCESS:-0}" -eq 1 ]; then
        if [ "$explicit_shell_bind" = 1 ]; then
            requested_bind="$cached_bind"
        fi
        lan_ip="$(select_lan_ipv4 "$requested_bind")" || return 1
        export SHAKERSCAN_BIND_HOST="$lan_ip"
        if [ "${SHAKERSCAN_PUBLIC_HOST_EXPLICIT:-0}" != 1 ]; then
            export SHAKERSCAN_PUBLIC_HOST="$lan_ip"
        fi
        # A private subnet is not an authenticated transport. Do not grant the
        # Tailscale-only token-over-HTTP exception to ordinary LAN traffic.
        unset SHAKERSCAN_TRUSTED_REMOTE_TRANSPORT
        export SHAKERSCAN_PUBLIC_API_URL="http://$(format_url_host "$(public_access_host)"):${SHAKERSCAN_API_PORT:-8080}"
        echo "[lan] UI/API will bind only to ${lan_ip}. Datastore bindings are unchanged."
        echo '[lan] WARNING: reachable LAN users can operate this OSS instance. HTTP is unencrypted.' >&2
        echo '[lan] Restrict access with a firewall; do not forward these ports to the Internet.' >&2
    elif [ "$REMOTE_ACCESS" -eq 1 ]; then''')
replace('        --remote|--tailscale)\n', '        --lan)\n            LAN_ACCESS=1\n            shift\n            ;;\n        --remote|--tailscale)\n')
# Help must work without discovering interfaces or mutating access/runtime state.
access = '''load_access_env

if ! configure_access_mode; then
    exit 1
fi

configure_runtime_mode "$COMMAND"

'''
replace(access, "")
replace('case $COMMAND in\n    help|--help|-h|install-deps|doctor|env|agent|ai)', r'''if [ "$LAN_ACCESS" -eq 1 ]; then
    if [ "$REMOTE_ACCESS" -eq 1 ]; then
        echo 'Error: --lan cannot be combined with --remote/--tailscale.' >&2
        exit 2
    fi
    case "$COMMAND" in
        start|restart) ;;
        *) echo 'Error: --lan is supported only by start and restart.' >&2; exit 2 ;;
    esac
fi

''' + access + 'case $COMMAND in\n    help|--help|-h|install-deps|doctor|env|agent|ai)')
replace('    start)\n        print_banner\n        start_services\n', '    start)\n        print_banner\n        start_services\n        print_lan_client_help\n')
replace('    restart)\n        restart_services\n', '    restart)\n        restart_services\n        print_lan_client_help\n')
replace('print_help() {\n', 'print_help() {\n    echo "Trusted LAN: shakerscan start --lan [--bind-host <assigned-LAN-IPv4>]"\n    echo "Also supports restart --lan. Cannot combine --lan with --remote/--tailscale."\n    echo ""\n')
p.write_text(s, encoding="utf-8")

p = Path("docs/client.md")
s = p.read_text()
anchor = "## Connect\n"
assert s.count(anchor) == 1
s = s.replace(anchor, '''## Use an OSS server on the same LAN

Run `shakerscan start --lan` on the machine with the full OSS engine. On the laptop,
install only the pipx/Homebrew client and use the API URL printed by the server:

```bash
shakerscan doctor --url http://192.168.1.50:8080
shakerscan api --url http://192.168.1.50:8080 GET /findings
shakerscan mcp --url http://192.168.1.50:8080
```

An explicit `--url`, or `SHAKERSCAN_API_URL` plus `SHAKERSCAN_MCP_ALLOW_REMOTE_API=true`,
selects that server, with no public fallback. The laptop needs no Docker. The LAN is the
trust boundary: this mode adds no login, encryption, or remote shell. Existing API/Hunt
approvals remain enforced. See [LAN access](lan-access.md) for networking, multi-NIC selection,
MCP registration, persistence, and returning to localhost-only operation.

''' + anchor)
p.write_text(s, encoding="utf-8")
p = Path("README.md")
s = p.read_text()
anchor = "## Install and start\n"
assert s.count(anchor) == 1
s = s.replace(anchor, '''## Control an OSS server from a laptop on your LAN

On the machine with the full engine, run `shakerscan start --lan`. On the laptop, install
only the pipx/Homebrew client, then point API/MCP commands at the address the server prints:

```bash
pipx install shakerscan
shakerscan api --url http://192.168.1.50:8080 GET /health
shakerscan mcp --url http://192.168.1.50:8080
```

LAN mode is explicit, IPv4-only, and for trusted networks: reachable users can operate the OSS
instance. It does not add authentication or encryption. Fresh installs remain localhost-only;
see [LAN access](docs/lan-access.md) for firewall guidance and setup details.

''' + anchor)
p.write_text(s, encoding="utf-8")
print("Applied LAN startup, laptop guidance, and documentation patches.")
