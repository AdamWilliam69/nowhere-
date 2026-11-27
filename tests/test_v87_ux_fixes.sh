#!/usr/bin/env bash
# v8.7 Live-Install UX, Container Diagnostics & Runtime Polish Regression Suite
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
V87="${REPO_ROOT}/nowhere-install.sh"
TMP="$(mktemp -d /tmp/test-v87.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

awk '/^\[ "\$EUID" -ne 0 \]/ { next } /^case "\$ACTION" in/ { exit } { print }' "$V87" > "$TMP/lib.sh"

PASS=0
FAIL=0
ok()   { PASS=$((PASS + 1)); printf '  [PASS] %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  [FAIL] %s\n' "$1"; }

echo "=== v8.7 UX, Diagnostics & Runtime Polish Test Suite ==="

# V87-01: ensure_adam_shortcut installs shortcuts when missing & writable; skips cleanly when non-writable
mkdir -p "$TMP/v01/bin" "$TMP/v01/ro"
chmod 555 "$TMP/v01/ro"
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    # Non-writable target directory skips gracefully with rc 0
    (
        MANAGER_PATH="'"$TMP/v01/ro/adam-nowhere-manager.sh"'"
        eval "$(declare -f ensure_adam_shortcut | sed "s#/usr/local/bin#'"$TMP/v01/ro"'#g")"
        ensure_adam_shortcut
    )
    [ ! -e "'"$TMP/v01/ro/adam"'" ]

    # Writable target directory installs adam + zt/pz/cxpz/cq cleanly
    MANAGER_PATH="'"$TMP/v01/bin/adam-nowhere-manager.sh"'"
    ensure_manager_copy() { printf "#!/bin/bash\necho ok\n" > "$MANAGER_PATH"; chmod +x "$MANAGER_PATH"; }
    eval "$(declare -f install_shortcuts | sed "s#/usr/local/bin#'"$TMP/v01/bin"'#g")"
    eval "$(declare -f ensure_adam_shortcut | sed "s#/usr/local/bin#'"$TMP/v01/bin"'#g")"
    out="$(ensure_adam_shortcut)"
    [ -x "'"$TMP/v01/bin/adam"'" ] && [ -x "'"$TMP/v01/bin/zt"'" ] && [ -x "'"$TMP/v01/bin/pz"'" ]
    [[ "$out" == *"adam"* ]]
'; then ok "V87-01: ensure_adam_shortcut installs shortcuts automatically and skips read-only dirs"; else fail "V87-01"; fi

# V87-02: do_probe accepts CLI target/--local, handles non-TTY EOF, and falls back to 127.0.0.1 on NAT hairpin failure
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    BIN_PATH="'"$TMP/v02-nowhere"'"
    cat > "$BIN_PATH" << "EOF"
#!/bin/bash
if [ "$1" = "probe" ]; then
    case "$2" in
        *203.0.113.10*) echo "Result  TRANSPORT_FAILED"; exit 1 ;;
        *127.0.0.1*)    echo "Result  OK ($3)"; exit 0 ;;
    esac
fi
exit 1
EOF
    chmod +x "$BIN_PATH"
    current_role() { echo "portal"; }
    load_saved_config() {
        SHARED_KEY="0123456789abcdef0123456789abcdef"
        PUBLIC_HOST="203.0.113.10"
        TLS_MODE="1"; PORT_MODE="same"; PORT="2443"; NET="mix"
        VECTOR_CARRIER="tcp"; MORPH="1"; HANDSHAKE_TIMEOUT="auto"
        LISTEN_HOST=""; TCP_FAMILY=""; UDP_FAMILY=""
    }
    get_tls_fingerprint() { echo "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; }
    # Public fails with TRANSPORT_FAILED -> auto loopback succeeds on 127.0.0.1
    out="$(do_probe custom.example:443 </dev/null 2>&1)"
    [[ "$out" == *"TRANSPORT_FAILED"* ]]
    [[ "$out" == *"Result  OK (custom.example:443)"* ]]
    # Explicit --local goes straight to 127.0.0.1 with non-TTY default target
    out2="$(do_probe --local </dev/null 2>&1)"
    [[ "$out2" != *"TRANSPORT_FAILED"* ]]
    [[ "$out2" == *"Result  OK (example.com:443)"* ]]
'; then ok "V87-02: do_probe supports CLI target/--local, non-TTY default & cloud NAT loopback fallback"; else fail "V87-02"; fi

# V87-03: get_tls_fingerprint reads current PID journalctl FIRST without calling nowhere fingerprint
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    TLS_MODE="1"; PORT_MODE="same"; PORT="2443"; NET="mix"; MORPH="1"
    SHARED_KEY="0123456789abcdef0123456789abcdef"
    _CACHED_TLS_FP=""
    BIN_PATH="'"$TMP/v03-nowhere"'"
    cat > "$BIN_PATH" << "EOF"
#!/bin/bash
echo "ACTIVE_PROBE_CALLED" > "'"$TMP/v03-probed"'"
exit 1
EOF
    chmod +x "$BIN_PATH"
    systemctl() { echo "9876"; }
    journalctl() {
        [[ " $* " == *"_PID=9876"* ]] && echo "tls certificate fingerprint: 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    }
    fp="$(get_tls_fingerprint)"
    [ "$fp" = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" ]
    [ ! -f "'"$TMP/v03-probed"'" ]
'; then ok "V87-03: get_tls_fingerprint prefers current-PID journalctl without spurious TLS EOF probes"; else fail "V87-03"; fi

# V87-04: _doctor_json distinguishes unconfigured vs not-installed & reports SCRIPT_VERSION 8.7
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    [ "$SCRIPT_VERSION" = "8.7" ]
    BIN_PATH="/nonexistent"; SNELL_BIN="/nonexistent"; XRAY_BIN="/nonexistent"
    REALM_BIN="/nonexistent"; CADDY_BIN="/nonexistent"; CF_TUNNEL_BIN="/bin/true"
    CONFIG_DIR="/nonexistent"; SNELL_DIR="/nonexistent"; XRAY_CONF_DIR="/nonexistent"; XRAY_NODE_DIR="/nonexistent"
    REALM_DIR="/nonexistent"; CADDY_DIR="/nonexistent"; CF_TUNNEL_DIR="/nonexistent"; MAINT_DIR="/nonexistent"
    systemctl() { return 1; }
    out="$(_doctor_json)"
    printf "%s" "$out" | python3 -c "import json,sys; d=json.load(sys.stdin); assert d[\"script_version\"]==\"8.7\" and d[\"services\"][\"cloudflared\"][\"installed\"] is True and d[\"services\"][\"cloudflared\"][\"state\"]==\"unconfigured\" and d[\"services\"][\"snell\"][\"state\"]==\"not-installed\", d"
'; then ok "V87-04: _doctor_json distinguishes unconfigured vs not-installed and reports v8.7"; else fail "V87-04"; fi

# V87-05: do_doctor container ss fallback (no process names), concise Xray version & ufw fallback text
mkdir -p "$TMP/v05/xray" "$TMP/v05/conf.d"
cat > "$TMP/v05/xray/bin" << 'EOF'
#!/bin/bash
echo "Xray 26.11.9 (Xray, Penetrates Everything.) abc1234 (go1.27.3 linux/amd64)"
EOF
chmod +x "$TMP/v05/xray/bin"
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    BIN_PATH="/nonexistent"; SNELL_BIN="/nonexistent"; REALM_BIN="/nonexistent"; CADDY_BIN="/nonexistent"; CF_TUNNEL_BIN="/nonexistent"
    XRAY_BIN="'"$TMP/v05/xray/bin"'"; XRAY_CONF_DIR="'"$TMP/v05"'"; XRAY_NODE_DIR="/nonexistent"; XRAY_FWD_DIR="/nonexistent"
    CONFIG_DIR="/nonexistent"; SNELL_DIR="/nonexistent"; REALM_DIR="/nonexistent"; CADDY_DIR="/nonexistent"; CF_TUNNEL_DIR="/nonexistent"; MAINT_DIR="/nonexistent"
    systemctl() { return 1; }
    managed_ports() { printf "24443/tcp\n2443/udp\n"; }
    # Simulate container ss -tlnp / -ulnp hiding process names
    ss() {
        case "$1" in
            -tlnp) printf "LISTEN 0 128 *:24443 *:*\n" ;;
            -ulnp) printf "UNCONN 0 0 *:2443 *:*\n" ;;
        esac
    }
    ufw() { return 1; }
    out="$(do_doctor)"
    [[ "$out" == *"*:24443"* ]]
    [[ "$out" == *"*:2443"* ]]
    [[ "$out" != *"无 Nowhere/Snell/Xray"* ]]
    [[ "$out" == *"Xray     : v26.11.9"* ]]
    [[ "$out" != *"Penetrates Everything"* ]]
    [[ "$out" == *"不可用（容器/内核受限）"* ]]
'; then ok "V87-05: do_doctor handles container ss port fallback, concise Xray version & restricted ufw"; else fail "V87-05"; fi

# V87-06: fw_status warns and exits non-zero when ufw fails in container/restricted kernel
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    ufw_installed() { return 0; }
    ufw() { echo "ERROR: problem running iptables" >&2; return 1; }
    out="$(fw_status 2>&1)" && exit 1 || true
    [[ "$out" == *"无法读取 ufw 状态"* ]]
'; then ok "V87-06: fw_status reports clear warning when ufw fails in restricted kernel"; else fail "V87-06"; fi

# V87-07: snell_health_check & xray_health_check downgrade read-only ip_local_reserved_ports to advisory
mkdir -p "$TMP/v07/snell" "$TMP/v07/snell/ports" "$TMP/v07/xray/nodes" "$TMP/v07/xray/conf.d"
cat > "$TMP/v07/snell/snell-server.conf" << 'EOF'
[snell-server]
listen = 0.0.0.0:31234
psk = AbCdEfGhIjKlMnOpQrStUvWxYz012345
EOF
cat > "$TMP/v07/snell/snell.service" << 'EOF'
[Service]
Restart=always
EOF
cat > "$TMP/v07/xray/nodes/vision-24443.env" << 'EOF'
N_TYPE="vision"
N_PORT="24443"
N_SNI="www.intel.com"
N_PBK="PUBKEY"
N_SID="aabbccdd"
EOF
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    SNELL_BIN="/bin/true"; SNELL_CONF="'"$TMP/v07/snell/snell-server.conf"'"; SNELL_PORTS_DIR="'"$TMP/v07/snell/ports"'"
    SNELL_SERVICE="'"$TMP/v07/snell/snell.service"'"; SNELL_STATE_FILE="'"$TMP/v07/snell/state"'"
    XRAY_BIN="/bin/true"; XRAY_NODE_DIR="'"$TMP/v07/xray/nodes"'"; XRAY_CONF_D="'"$TMP/v07/xray/conf.d"'"; XRAY_STATE_FILE="'"$TMP/v07/xray/state"'"
    MAINT_ENV="'"$TMP/v07/maint.env"'"
    printf "MAINT_WATCHDOG=\"1\"\n" > "$MAINT_ENV"
    health_check_common() { return 0; }
    tcp_listening() { return 0; }
    ufw_active() { return 1; }
    reserved_port_ok() { return 1; }
    reserved_ports_writable() { return 1; }
    snell_installed_version() { echo "v6.0.0"; }
    snell_query_latest() { SNELL_LATEST="v6.0.0"; SNELL_LATEST_STABLE="v6.0.0"; SNELL_SOURCE_OK=1; SNELL_NEWER_MAJOR=""; }
    xray_installed_version() { echo "v26.11.9"; }
    xray_test_conf() { return 0; }
    xray_query_latest() { XRAY_LATEST="v26.11.9"; XRAY_LATEST_ANY="v26.11.9"; XRAY_LATEST_STABLE="v26.11.9"; }
    check_ntp_sync() { return 0; }
    systemctl() { return 0; }
    out_s="$(snell_health_check)"
    [[ "$out_s" == *"容器/受限内核中只读"* ]]
    out_x="$(xray_health_check)"
    [[ "$out_x" == *"容器/受限内核中只读"* ]]
'; then ok "V87-07: snell/xray health checks downgrade read-only ip_local_reserved_ports to advisory"; else fail "V87-07"; fi

# V87-08: xray_add_ss strictly re-prompts on invalid cipher choice instead of silently defaulting
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    xray_new_node_begin() { XN_PORT="24444"; XN_LISTEN="::"; XN_TAG="ss-24444"; XN_NAME="SS2022-24444"; }
    udp_listening() { return 1; }
    xray_commit_node() { printf "%s" "$2" > "'"$TMP/v08-committed.json"'"; }
    # Pass invalid "24444" first, then valid "2" (aes-256-gcm)
    out="$(printf "24444\n2\n" | xray_add_ss 2>&1)"
    [[ "$out" == *"无效选择"* ]]
    grep -q "2022-blake3-aes-256-gcm" "'"$TMP/v08-committed.json"'"
'; then ok "V87-08: xray_add_ss rejects invalid cipher choice and re-prompts cleanly"; else fail "V87-08"; fi

# V87-09: xray_show_node compacts ML-DSA-65 pqv summary & guards oversized QR code
mkdir -p "$TMP/v09/nodes"
LONG_PQV="$(python3 -c 'print("A" * 2600)')"
cat > "$TMP/v09/nodes/vision-24443.env" << EOF
N_TAG="vision-24443"
N_TYPE="vision"
N_PORT="24443"
N_UUID="11111111-2222-4333-8444-555555555555"
N_SNI="www.intel.com"
N_PBK="PUBKEY123"
N_SID="aabbccdd"
N_SIDS="aabbccdd,11223344"
N_FP="chrome"
N_PQV="${LONG_PQV}"
N_NAME="Vision-24443"
EOF
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    XRAY_NODE_DIR="'"$TMP/v09/nodes"'"; XRAY_STATE_FILE="'"$TMP/v09/state"'"
    printf "XRAY_PUBLIC_HOST=\"1.2.3.4\"\n" > "$XRAY_STATE_FILE"
    out="$(xray_show_node vision-24443)"
    # Summary line shows compact preview with byte size, NOT 2600 chars
    printf "%s\n" "$out" | grep -q "ML-DSA-65(pqv): AAAAAAAAAAAA\.\.\.AAAAAAAA (2600B)"
    # Share link still carries the full pqv
    printf "%s\n" "$out" | grep -q "&pqv=${LONG_PQV:-'"$LONG_PQV"'}"
'; then ok "V87-09: xray_show_node summarizes long ML-DSA-65 pqv while keeping full vless:// link"; else fail "V87-09"; fi

# V87-10: Aligned ZH/EN menu banner with v8.7, Tab-formatted Caddyfile, and bracketed [::]:PORT xray fwd
mkdir -p "$TMP/v10/caddy/sites" "$TMP/v10/caddy-data" "$TMP/v10/fwd"
cat > "$TMP/v10/caddy/sites/s01.env" << 'EOF'
SITE_ENABLED="1"
SITE_MODE="http"
SITE_PORT="24447"
SITE_DOMAIN="test.local"
SITE_UPSTREAM="127.0.0.1:18080"
SITE_REMARK="demo"
EOF
cat > "$TMP/v10/fwd/f01.env" << 'EOF'
FWD_ID="f01"
FWD_ENABLED="1"
FWD_PROTO="tcp"
FWD_LIP="::"
FWD_LPORT="24445"
FWD_RHOST="127.0.0.1"
FWD_RPORT="18080"
FWD_FOLLOW="0"
FWD_REMARK="demo"
EOF
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    # Check ZH & EN banner display width alignment (all 4 box lines == 64 columns)
    menu_time_ip() { :; }; menu_status_summary() { :; }
    for lang in zh en; do
        ADAM_LANG="$lang"
        menu_out="$(printf "0\n" | show_menu)"
        banner="$(printf "%s\n" "$menu_out" | grep "^[╔║╚]")"
        printf "%s\n" "$banner" | grep -q "v8.7"
        python3 - "$banner" << "PY"
import sys, unicodedata
lines = sys.argv[1].splitlines()
assert len(lines) == 4, lines
def w(s):
    return sum(2 if unicodedata.east_asian_width(c) in ("W", "F") else 1 for c in s)
widths = [w(l) for l in lines]
assert len(set(widths)) == 1 and widths[0] == 64, f"misaligned banner widths: {widths}\n" + "\n".join(lines)
PY
    done

    # Caddyfile & site config use Tabs (no 4-space indentation)
    CADDY_DIR="'"$TMP/v10/caddy"'"; CADDY_SITES_DIR="$CADDY_DIR/sites"
    CADDY_FILE="$CADDY_DIR/Caddyfile"; CADDY_DATA_DIR="'"$TMP/v10/caddy-data"'"; CADDY_STATE_FILE="$CADDY_DIR/state"
    caddy_write_main_config
    caddy_render_site s01
    grep -q $'\''^\tadmin off$'\'' "$CADDY_FILE"
    grep -q $'\''^\tencode zstd gzip$'\'' "$CADDY_SITES_DIR/s01.caddy"
    ! grep -q "^    " "$CADDY_FILE" "$CADDY_SITES_DIR/s01.caddy"

    # xray_fwd_list formats :: as [::]:24445
    XRAY_FWD_DIR="'"$TMP/v10/fwd"'"
    fwd_out="$(xray_fwd_list)"
    [[ "$fwd_out" == *"[::]:24445"* ]]
    [[ "$fwd_out" != *":::24445"* ]]
'; then ok "V87-10: Aligned ZH/EN v8.7 banner, Tab-formatted Caddyfile & bracketed [::]:PORT xray fwd"; else fail "V87-10"; fi

echo ""
echo "v8.7 Summary: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
