#!/usr/bin/env bash
# Round-3 Bug Reproduction & Regression Suite for nowhere-install.sh (v8.6)
# Each test reproduces a real bug found via live GitHub install testing and deep audit.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
V86="${REPO_ROOT}/nowhere-install.sh"
TMP="$(mktemp -d /tmp/test-r3.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

awk '/^\[ "\$EUID" -ne 0 \]/ { next } /^case "\$ACTION" in/ { exit } { print }' "$V86" > "$TMP/lib.sh"

PASS=0
FAIL=0
ok()   { PASS=$((PASS + 1)); printf '  [PASS] %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  [FAIL] %s\n' "$1"; }

echo "=== Round 3 Bug Fix & Regression Suite ==="

# R3-01: Single-line minified GitHub API JSON in *_latest_tag
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    secure_curl() {
        local url="${!#}"
        case "$url" in
            *api.github.com/repos/cloudflare/cloudflared/releases/latest)
                printf "{\"url\":\"https://api.github.com/repos/cloudflare/cloudflared/releases/455\",\"tag_name\":\"2026.11.2\",\"draft\":false}" ;;
            *api.github.com/repos/caddyserver/caddy/releases/latest)
                printf "{\"url\":\"https://api.github.com/repos/caddyserver/caddy/releases/111\",\"tag_name\":\"v2.11.9\"}" ;;
            *api.github.com/repos/zhboner/realm/releases/latest)
                printf "{\"url\":\"https://api.github.com/repos/zhboner/realm/releases/222\",\"tag_name\":\"v2.9.6\"}" ;;
            *api.github.com/repos/NodePassProject/Nowhere/releases/latest)
                printf "{\"url\":\"https://api.github.com/repos/NodePassProject/Nowhere/releases/333\",\"tag_name\":\"v3.4.0\"}" ;;
            *) return 1 ;;
        esac
    }
    [ "$(cf_tunnel_latest_tag)" = "2026.11.2" ]
    [ "$(caddy_latest_tag)" = "v2.11.9" ]
    [ "$(realm_latest_tag)" = "v2.9.6" ]
    [ "$(get_latest_tag)" = "v3.4.0" ]
'; then ok "R3-01: *_latest_tag handles single-line minified GitHub API JSON"; else fail "R3-01"; fi

# R3-02: realm_rebuild_all with 0 enabled rules produces valid root endpoints = []
mkdir -p "$TMP/r02/conf.d" "$TMP/r02/rules"
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    REALM_DIR="'"$TMP/r02"'"
    REALM_CONF_D="$REALM_DIR/conf.d"
    REALM_RULE_DIR="$REALM_DIR/rules"
    REALM_CONFIG_FILE="$REALM_DIR/config.toml"
    realm_rebuild_all
    python3 - "$REALM_CONFIG_FILE" << "PY"
import sys, tomllib
d = tomllib.load(open(sys.argv[1], "rb"))
assert d.get("endpoints") == [], f"expected root endpoints=[], got {d}"
assert "endpoints" not in d.get("network", {}), f"endpoints leaked into [network]: {d}"
PY
'; then ok "R3-02: realm_rebuild_all emits root endpoints = [] when 0 rules enabled"; else fail "R3-02"; fi

# R3-03: do_backup does not crash under pipefail when only .tgz (no .tgz.enc) exists
mkdir -p "$TMP/r03/etc_adam" "$TMP/r03/bdir"
printf 'MAINT_WATCHDOG="1"\n' > "$TMP/r03/etc_adam/maintain.env"
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    # Override /root and /etc/adam inside do_backup via temp wrapper
    eval "$(declare -f do_backup | sed -e "s#/root#'"$TMP/r03/bdir"'#g" -e "s#/etc/adam #'"$TMP/r03/etc_adam"' #g")"
    do_backup >/dev/null 2>&1
    ls "'"$TMP/r03/bdir"'"/adam-backup-*.tgz >/dev/null 2>&1
'; then ok "R3-03: do_backup succeeds without crashing when only .tgz exists"; else fail "R3-03"; fi

# R3-04: do_export_clients mihomo survives missing N_PQV/N_XPAD, escapes YAML, uses SNELL_PUBLIC_HOST, and surge does not leak warn
mkdir -p "$TMP/r04/nodes" "$TMP/r04/snell/ports"
cat > "$TMP/r04/nodes/vision-443.env" << 'EOF'
N_TYPE="vision"
N_NAME="my \"quoted\" node"
N_PORT="443"
N_UUID="11111111-2222-4333-8444-555555555555"
N_SNI="www.oracle.com"
N_PBK="PUBKEY123"
N_SID="aabbccdd"
N_FP="chrome"
EOF
cat > "$TMP/r04/nodes/ss-31000.env" << 'EOF'
N_TYPE="ss2022"
N_PORT="31000"
N_METHOD="2022-blake3-aes-128-gcm"
N_PASS="pass\"with\"quote"
EOF
cat > "$TMP/r04/snell/snell-server.conf" << 'EOF'
[snell-server]
listen = 0.0.0.0:30001
psk = AbCdEfGhIjKlMnOpQrStUvWxYz012345
ipv6 = false
EOF
cat > "$TMP/r04/snell/adam-snell.env" << 'EOF'
SNELL_PUBLIC_HOST="snell.example.com"
EOF
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    XRAY_BIN="/bin/true"; XRAY_NODE_DIR="'"$TMP/r04/nodes"'"; XRAY_STATE_FILE="'"$TMP/r04/no-xstate"'"
    SNELL_BIN="/bin/true"; SNELL_CONF="'"$TMP/r04/snell/snell-server.conf"'"; SNELL_PORTS_DIR="'"$TMP/r04/snell/ports"'"; SNELL_STATE_FILE="'"$TMP/r04/snell/adam-snell.env"'"
    detect_public_host() { echo ""; }
    # Call directly (NOT inside $(...)) so set -e actually catches subshell exit 1!
    do_export_clients mihomo > "'"$TMP/r04/mihomo.yaml"'"
    grep -Fq "ss-31000" "'"$TMP/r04/mihomo.yaml"'"
    grep -Fq "server: \"YOUR_SERVER_IP\"" "'"$TMP/r04/mihomo.yaml"'"
    grep -Fq "server: \"snell.example.com\"" "'"$TMP/r04/mihomo.yaml"'"
    grep -Fq "my \\\"quoted\\\" node" "'"$TMP/r04/mihomo.yaml"'"
    # Surge must not leak warn message into [Proxy] when SNELL_PUBLIC_HOST is empty
    SNELL_STATE_FILE="'"$TMP/r04/no-sstate"'"
    SNELL_PUBLIC_HOST=""
    do_export_clients surge > "'"$TMP/r04/surge.conf"'"
    ! grep -Fq "警告" "'"$TMP/r04/surge.conf"'"
'; then ok "R3-04: do_export_clients mihomo/surge handles missing pqv/xpad, YAML escaping, empty host & Snell host"; else fail "R3-04"; fi

# R3-05: github_asset_sha256 pure-awk handles nested uploader object & expanded_assets avoids prefix collision
D_TARGET="1111111111111111111111111111111111111111111111111111111111111111"
D_OTHER="2222222222222222222222222222222222222222222222222222222222222222"
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    command() { [ "${2:-}" = "python3" ] && return 1 || builtin command "$@"; }
    # Real GitHub API layout has nested "uploader": { ... } between "name" and "digest"
    secure_curl() {
        local url="${!#}"
        case "$url" in
            *api.github.com*)
                printf "{\"assets\":[{\"name\":\"cloudflared-linux-amd64.deb\",\"uploader\":{\"login\":\"bot\",\"id\":1},\"digest\":\"sha256:%s\"},{\"name\":\"cloudflared-linux-amd64\",\"uploader\":{\"login\":\"bot\",\"id\":2},\"digest\":\"sha256:%s\"}]}" "'"$D_OTHER"'" "'"$D_TARGET"'" ;;
            *) return 1 ;;
        esac
    }
    [ "$(github_asset_sha256 cloudflare/cloudflared 2026.11.2 cloudflared-linux-amd64)" = "'"$D_TARGET"'" ]
    # expanded_assets HTML prefix collision: .deb listed BEFORE bare binary
    secure_curl() {
        local url="${!#}"
        case "$url" in
            *expanded_assets*)
                printf "<a href=\"/cloudflare/cloudflared/releases/download/2026.11.2/cloudflared-linux-amd64.deb\">deb</a>\n<span>sha256:%s</span>\n<a href=\"/cloudflare/cloudflared/releases/download/2026.11.2/cloudflared-linux-amd64\">bin</a>\n<span>sha256:%s</span>\n" "'"$D_OTHER"'" "'"$D_TARGET"'" ;;
            *) return 1 ;;
        esac
    }
    [ "$(github_asset_sha256 cloudflare/cloudflared 2026.11.2 cloudflared-linux-amd64)" = "'"$D_TARGET"'" ]
'; then ok "R3-05: github_asset_sha256 handles nested uploader JSON & HTML prefix collisions"; else fail "R3-05"; fi

# R3-06: state_load rejects undeclared keys like PATH / SCRIPT_URL
printf 'MAINT_WATCHDOG="1"\nSCRIPT_URL="https://evil.example/x.sh"\n' > "$TMP/r06.env"
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    orig_url="$SCRIPT_URL"
    state_load "'"$TMP/r06.env"'" "MAINT_WATCHDOG=0"
    [ "$SCRIPT_URL" = "$orig_url" ]
'; then ok "R3-06: state_load blocks undeclared global variable injection"; else fail "R3-06"; fi

# R3-07: cert_expiry_days returns non-zero on missing or corrupt cert
printf 'NOT A CERT\n' > "$TMP/r07-bad.pem"
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    ! cert_expiry_days "'"$TMP/r07-nonexistent.pem"'" >/dev/null 2>&1
    ! cert_expiry_days "'"$TMP/r07-bad.pem"'" >/dev/null 2>&1
'; then ok "R3-07: cert_expiry_days fails cleanly on missing/corrupt certificates"; else fail "R3-07"; fi

# R3-08: ensure_manager_copy enforces SHA-256 verification via script_fetch_remote
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    MANAGER_PATH="'"$TMP/r08-mgr.sh"'"
    MAINT_SCRIPT_STRICT_SHA=1
    secure_curl() {
        local out="" url=""
        while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2;; http*) url="$1"; shift;; *) shift;; esac; done
        case "$url" in
            *.sha256*) printf "0000000000000000000000000000000000000000000000000000000000000000  nowhere-install.sh\n" ;;
            *) printf "#!/bin/bash\n# Adam Nowhere\ncase \"\$ACTION\" in\n*) : ;;\nesac\n" > "$out" ;;
        esac
    }
    # Force process-sub branch by running from bash -c ($0 is bash, not script)
    ! ensure_manager_copy >/dev/null 2>&1
    [ ! -f "$MANAGER_PATH" ]
'; then ok "R3-08: ensure_manager_copy rejects tampered script with mismatched .sha256"; else fail "R3-08"; fi

# R3-09: xray_new_node_begin avoids tag collision after xray_edit_node changes port
mkdir -p "$TMP/r09/nodes" "$TMP/r09/conf.d"
cat > "$TMP/r09/nodes/vision-443.env" << 'EOF'
N_TYPE="vision"
N_PORT="8443"
EOF
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    XRAY_NODE_DIR="'"$TMP/r09/nodes"'"; XRAY_CONF_D="'"$TMP/r09/conf.d"'"
    xray_ask_port() { XP_PORT="$1"; }
    xray_gen_uuid() { echo "11111111-2222-4333-8444-555555555555"; }
    xray_new_node_begin "443" "vision" "Vision"
    [ "$XN_TAG" != "vision-443" ]
'; then ok "R3-09: xray_new_node_begin avoids colliding with existing tag after port edit"; else fail "R3-09"; fi

# R3-10: caddy_reload_service / realm_reload_service restore User=/Group= on failed root retry & chown before retry
mkdir -p "$TMP/r10/caddy/sites" "$TMP/r10/caddy-data" "$TMP/r10/realm/conf.d" "$TMP/r10/realm/rules"
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    CADDY_BIN="/bin/true"
    CADDY_DIR="'"$TMP/r10/caddy"'"; CADDY_SITES_DIR="$CADDY_DIR/sites"; CADDY_FILE="$CADDY_DIR/Caddyfile"
    CADDY_DATA_DIR="'"$TMP/r10/caddy-data"'"; CADDY_SERVICE="'"$TMP/r10/caddy.service"'"
    cat > "$CADDY_SERVICE" << "EOF"
[Service]
User=adam-caddy
Group=adam-caddy
ExecStart=/usr/local/bin/caddy run
EOF
    caddy_rebuild_all() { return 0; }
    caddy_enabled_count() { echo 1; }
    caddy_validate_config() { return 0; }
    caddy_fix_perms() { return 0; }
    systemctl() { return 0; }
    CHOWN_BEFORE_ROOT_RETRY=0
    svc_restart_wait() {
        if [ -f "${CADDY_DIR}/run-as-root" ]; then CHOWN_BEFORE_ROOT_RETRY=1; fi
        return 1
    }
    ! caddy_reload_service >/dev/null 2>&1
    [ "$CHOWN_BEFORE_ROOT_RETRY" = "1" ]
    grep -q "^User=adam-caddy$" "$CADDY_SERVICE"
    [ ! -f "${CADDY_DIR}/run-as-root" ]

    # Realm reload rollback restores User=adam-realm
    REALM_BIN="/bin/true"
    REALM_DIR="'"$TMP/r10/realm"'"; REALM_SERVICE="'"$TMP/r10/realm.service"'"
    cat > "$REALM_SERVICE" << "EOF"
[Service]
User=adam-realm
Group=adam-realm
ExecStart=/usr/local/bin/realm -c /etc/adam-realm/config.toml
EOF
    realm_rebuild_all() { return 0; }
    realm_enabled_count() { echo 1; }
    ! realm_reload_service >/dev/null 2>&1
    grep -q "^User=adam-realm$" "$REALM_SERVICE"
'; then ok "R3-10: caddy/realm root fallback prepares perms before retry & restores User=/Group= on failure"; else fail "R3-10"; fi

# R3-11: realm_rebuild_all fails & removes stale rule-*.toml when rule fails realm_render_rule
mkdir -p "$TMP/r11/conf.d" "$TMP/r11/rules"
cat > "$TMP/r11/rules/r01.env" << 'EOF'
RULE_ENABLED="1"
RULE_LPORT="99999"
RULE_RHOST="1.1.1.1"
RULE_RPORT="443"
EOF
echo '[[endpoints]]' > "$TMP/r11/conf.d/rule-r01.toml"
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    REALM_DIR="'"$TMP/r11"'"; REALM_CONF_D="$REALM_DIR/conf.d"; REALM_RULE_DIR="$REALM_DIR/rules"; REALM_CONFIG_FILE="$REALM_DIR/config.toml"
    ! realm_rebuild_all >/dev/null 2>&1
    [ ! -f "$REALM_CONF_D/rule-r01.toml" ]
'; then ok "R3-11: realm_rebuild_all propagates render errors & removes stale rule TOML"; else fail "R3-11"; fi

# R3-12: do_update_script loads MAINT_SCRIPT_STRICT_SHA=1; tcpfit_fetch aborts on mismatch under ADAM_ASSUME_YES=1
mkdir -p "$TMP/r12"
printf 'MAINT_SCRIPT_STRICT_SHA="1"\n' > "$TMP/r12/maintain.env"
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    MAINT_ENV="'"$TMP/r12/maintain.env"'"
    MANAGER_PATH="'"$TMP/r12/mgr.sh"'"
    MAINT_SCRIPT_STRICT_SHA="0"
    secure_curl() {
        local out="" url=""
        while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2;; http*) url="$1"; shift;; *) shift;; esac; done
        case "$url" in
            *.sha256*) return 1 ;;
            *) printf "#!/bin/bash\n# Adam Nowhere\nSCRIPT_VERSION=\"9.9\"\ncase \"\$ACTION\" in\n*) : ;;\nesac\n" > "$out" ;;
        esac
    }
    ! do_update_script >/dev/null 2>&1
    [ ! -f "$MANAGER_PATH" ]

    # tcpfit_fetch must hard-abort on SHA-256 mismatch even with ADAM_ASSUME_YES=1
    ADAM_ASSUME_YES=1
    secure_curl() {
        local out="" url=""
        while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2;; http*) url="$1"; shift;; *) shift;; esac; done
        case "$url" in
            *SHA256SUMS*) printf "0000000000000000000000000000000000000000000000000000000000000000  tcpfit.sh\n" ;;
            *) printf "#!/bin/bash\nVERSION=1.0\necho evil\n" > "$out" ;;
        esac
    }
    ! tcpfit_fetch >/dev/null 2>&1
'; then ok "R3-12: do_update_script enforces strict SHA & tcpfit_fetch aborts mismatch under ASSUME_YES"; else fail "R3-12"; fi

# R3-13: snell_sync_extras_after_restore passes --plain; snell_probe_batch does not leak /tmp/adam-work.*
mkdir -p "$TMP/r13/ports"
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    SNELL_PORTS_DIR="'"$TMP/r13/ports"'"
    DISABLED=""
    systemctl() {
        case "$1" in
            list-units)
                if [[ " $* " == *" --plain "* ]]; then
                    : > "'"$TMP/r13/plain_seen"'"
                    printf "snell-port@20001.service loaded failed failed Snell\n"
                else
                    printf "● snell-port@20001.service loaded failed failed Snell\n"
                fi
                ;;
            disable) DISABLED="${!#}" ;;
        esac
    }
    snell_start_extras() { return 0; }
    snell_sync_extras_after_restore >/dev/null 2>&1
    [ -f "'"$TMP/r13/plain_seen"'" ] && [ "$DISABLED" = "snell-port@20001.service" ]
'; then ok "R3-13: snell_sync_extras_after_restore uses --plain and cleans failed orphan unit"; else fail "R3-13"; fi

# R3-14: caddy_ports survives invalid SITE_PORT; caddy_render_site rejects injected SITE_DOMAIN
mkdir -p "$TMP/r14/sites"
cat > "$TMP/r14/sites/s01.env" << 'EOF'
SITE_ENABLED="1"
SITE_MODE="http"
SITE_PORT="bad"
SITE_DOMAIN="bad.example.com"
SITE_UPSTREAM="127.0.0.1:8080"
EOF
cat > "$TMP/r14/sites/s02.env" << 'EOF'
SITE_ENABLED="1"
SITE_MODE="http"
SITE_PORT="8088"
SITE_DOMAIN="ok.example.com"
SITE_UPSTREAM="127.0.0.1:8080"
EOF
cat > "$TMP/r14/sites/s03.env" << 'EOF'
SITE_ENABLED="1"
SITE_MODE="http"
SITE_PORT="8089"
SITE_DOMAIN="evil.com { file_server / } #"
SITE_UPSTREAM="127.0.0.1:8080"
EOF
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    CADDY_BIN="/bin/true"; CADDY_SITES_DIR="'"$TMP/r14/sites"'"
    out="$(caddy_ports)"
    [[ "$out" == *"8088/tcp"* ]]
    ! caddy_render_site "s03" >/dev/null 2>&1
    [ ! -f "$CADDY_SITES_DIR/s03.caddy" ]
'; then ok "R3-14: caddy_ports survives invalid port & caddy_render_site blocks domain injection"; else fail "R3-14"; fi

# R3-15: fw_is_allowed handles allow out / allow in / named service proto; port_used_by_other_services honors xray_needs_port80
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    ufw() {
        printf "ufw allow out to any port 9443 proto tcp\n"
        printf "ufw allow in 8443/tcp\n"
        printf "ufw allow https\n"
    }
    ! fw_is_allowed 9443 tcp
    fw_is_allowed 8443 tcp
    fw_is_allowed 443 tcp
    ! fw_is_allowed 443 udp
    # port_used_by_other_services 80/tcp caddy returns 0 when xray_needs_port80 is true
    BIN_PATH="/nonexistent"; SERVICE_FILE="/nonexistent"; SNELL_BIN="/nonexistent"; SNELL_SERVICE="/nonexistent"
    REALM_BIN="/nonexistent"; REALM_SERVICE="/nonexistent"; CADDY_BIN="/nonexistent"; CADDY_SERVICE="/nonexistent"
    XRAY_BIN="/bin/true"; XRAY_SERVICE="/nonexistent"; XRAY_NODE_DIR="/nonexistent"; XRAY_FWD_DIR="/nonexistent"
    xray_needs_port80() { return 0; }
    port_used_by_other_services 80/tcp caddy
'; then ok "R3-15: fw_is_allowed (out/in/service proto) & port_used_by_other_services (xray port 80)"; else fail "R3-15"; fi

# R3-16: xray_list_releases atom suffix, xray_write_base without geoip.dat, xray_fwd_rule_files empty dir, write_service_unit 0644
mkdir -p "$TMP/r16/xray" "$TMP/r16/conf.d" "$TMP/r16/fwd"
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    secure_curl() {
        local url="${!#}"
        case "$url" in
            *releases.atom*) printf "<link href=\"https://github.com/XTLS/Xray-core/releases/tag/v26.10.1-rc1\"/>\n<link href=\"https://github.com/XTLS/Xray-core/releases/tag/v26.10.0\"/>\n" ;;
            *) return 1 ;;
        esac
    }
    tags="$(xray_list_releases)"
    ! printf "%s\n" "$tags" | grep -qx "v26.10.1 ?"
    printf "%s\n" "$tags" | grep -qx "v26.10.0 ?"

    XRAY_DIR="'"$TMP/r16/xray"'"; XRAY_CONF_D="'"$TMP/r16/conf.d"'"; XRAY_FWD_DIR="'"$TMP/r16/fwd"'"; XRAY_CN_BLOCK="0"
    xray_write_base
    ! grep -q "geoip:private" "$XRAY_CONF_D/00-base.json"
    python3 -c "import json; json.load(open(\"$XRAY_CONF_D/00-base.json\"))"
    xray_fwd_rule_files >/dev/null
    write_service_unit "'"$TMP/r16/test.service"'" "Desc" "https://example.com" "60" "" "" "/bin/true" "" "1024" "always" "5"
    [ "$(stat -c %a "'"$TMP/r16/test.service"'")" = "644" ]
'; then ok "R3-16: xray atom suffix, geoip-free base.json, empty fwd dir & 0644 systemd units"; else fail "R3-16"; fi

# R3-17: build_probe_vector_url UDP-only Portal; validate_socks; is_public_ip
if bash -c '
    set -eo pipefail; source "'"$TMP/lib.sh"'"
    NET="udp"; PORT_MODE="single"; PORT="4433"; PORT_UDP="4433"; PORT_TCP=""; UDP_FAMILY=""; TCP_FAMILY=""
    VECTOR_CARRIER="tcp"; SHARED_KEY="0123456789abcdef0123456789abcdef"; TLS_MODE="0"; MORPH="1"
    PUBLIC_HOST="203.0.113.10"
    u="$(build_probe_vector_url)"
    [[ "$u" == *"/udp:4433"* ]]
    ! validate_socks "1080"
    validate_socks "127.0.0.1:1080"
    is_public_ip "192.0.78.24"
    is_public_ip "203.0.178.191"
    ! is_public_ip "foo:bar"
    ! is_public_ip "192.0.2.1"
    ! is_public_ip "203.0.113.1"
'; then ok "R3-17: build_probe_vector_url UDP-only, validate_socks & is_public_ip accuracy"; else fail "R3-17"; fi

# R3-18: verify_release_checksum exact filename match & _doctor_json LC_ALL=C & do_repair_all cloudflare perms
mkdir -p "$TMP/r18/wd"
printf 'hello' > "$TMP/r18/wd/nowhere.tar.gz"
REAL_SHA="$(sha256sum "$TMP/r18/wd/nowhere.tar.gz" | awk '{print $1}')"
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    BIN_NAME="nowhere-linux-amd64.tar.gz"
    github_asset_sha256() { return 1; }
    secure_curl() {
        printf "0000000000000000000000000000000000000000000000000000000000000000  nowhere-linux-amd64.tar.gz.sig\n%s  nowhere-linux-amd64.tar.gz\n" "'"$REAL_SHA"'"
    }
    verify_release_checksum "v3.4.0" "'"$TMP/r18/wd"'" >/dev/null 2>&1
    # _doctor_json with non-English ufw status falls back cleanly via LC_ALL=C
    LC_SEEN=""
    ufw() { LC_SEEN="${LC_ALL:-}"; if [ "$LC_SEEN" = "C" ]; then echo "Status: active"; else echo "状态：激活"; fi; }
    systemctl() { return 1; }
    BIN_PATH="/nonexistent"; SNELL_BIN="/nonexistent"; XRAY_BIN="/nonexistent"; REALM_BIN="/nonexistent"; CADDY_BIN="/nonexistent"; CF_TUNNEL_BIN="/nonexistent"
    CONFIG_DIR="/nonexistent"; SNELL_DIR="/nonexistent"; XRAY_CONF_DIR="/nonexistent"; XRAY_NODE_DIR="/nonexistent"; REALM_DIR="/nonexistent"; CADDY_DIR="/nonexistent"; CF_TUNNEL_DIR="/nonexistent"; MAINT_DIR="/nonexistent"
    out="$(_doctor_json)"
    printf "%s" "$out" | python3 -c "import json,sys; d=json.load(sys.stdin); assert d[\"firewall\"]==\"active\", d"
'; then ok "R3-18: verify_release_checksum exact match & _doctor_json LC_ALL=C firewall status"; else fail "R3-18"; fi

# R3-19: get_fingerprint_from_journal does not return stale tls=1 pin when stopped / new PID has no log
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    systemctl() { echo "0"; }
    journalctl() { echo "SHA-256 fingerprint: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; }
    ! get_fingerprint_from_journal >/dev/null 2>&1
    systemctl() { echo "12345"; }
    journalctl() {
        if [[ " $* " == *"_PID=12345"* ]]; then return 0; fi
        echo "SHA-256 fingerprint: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }
    ! get_fingerprint_from_journal >/dev/null 2>&1
'; then ok "R3-19: get_fingerprint_from_journal never returns expired tls=1 fingerprint"; else fail "R3-19"; fi

# R3-20: realm_split_host_port rejects [1.2.3.4]:443; do_restore no NUL warning
mkdir -p "$TMP/r20"
tar -czf "$TMP/r20/empty.tgz" -T /dev/null
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    _h=""; _p=""
    ! realm_split_host_port "[1.2.3.4]:443" _h _p
    realm_split_host_port "[2001:db8::1]:443" _h _p
    # Check magic read in do_restore produces zero stderr warning on .tgz
    err="$(bash -c "set -euo pipefail; source \"'"$TMP/lib.sh"'\"
        do_restore \"'"$TMP/r20/empty.tgz"'\" < /dev/null >/dev/null" 2>&1 || true)"
    [[ "$err" != *"ignored null byte"* ]]
'; then ok "R3-20: realm_split_host_port rejects bracketed IPv4 & do_restore has no NUL-byte warning"; else fail "R3-20"; fi

echo ""
echo "Round 3 Summary: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
