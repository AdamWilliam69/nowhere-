#!/usr/bin/env bash
# Standalone regression & core v8.6 security/CSPRNG/anti-fingerprint test suite
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${REPO_ROOT}/nowhere-install.sh"
PASS=0
FAIL=0

ok()   { PASS=$((PASS + 1)); printf '  [PASS] %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  [FAIL] %s\n' "$1"; }

TMP="$(mktemp -d /tmp/test-regressions.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

awk '/^\[ "\$EUID" -ne 0 \]/ { next } /^case "\$ACTION" in/ { exit } { print }' "$SCRIPT" > "$TMP/lib.sh"

echo "=== Part 1: Regression Fixes ==="

# BUG-01: check_port_occupied_by_other excludes own process
r86="$(bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    ss() { printf "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\nLISTEN 0 4096 *:443 *:* users:((\"caddy\",pid=123,fd=7))\n"; }
    check_port_occupied_by_other tcp 443 caddy
')"
if [ -z "$r86" ]; then ok "BUG-01: check_port_occupied_by_other excludes own process"; else fail "BUG-01: got [$r86]"; fi

# BUG-02: Caddy 128-hex SHA-512 checksums.txt verification
mkdir -p "$TMP/b02/wd"
cp /bin/true "$TMP/b02/caddy"
tar -czf "$TMP/b02/caddy.tar.gz" -C "$TMP/b02" caddy
SHA512_CADDY="$(sha512sum "$TMP/b02/caddy.tar.gz" | awk '{print $1}')"
ARCH_C="$(case "$(uname -m)" in x86_64|amd64) echo amd64;; aarch64|arm64) echo arm64;; *) echo amd64;; esac)"
printf '%s  caddy_2.9.0_linux_%s.tar.gz\n' "$SHA512_CADDY" "$ARCH_C" > "$TMP/b02/checksums.txt"
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    github_asset_sha256() { return 1; }
    secure_curl() {
        local out="" url=""
        while [ $# -gt 0 ]; do
            case "$1" in -o) out="$2"; shift 2 ;; http*) url="$1"; shift ;; *) shift ;; esac
        done
        case "$url" in
            *checksums.txt) cp "'"$TMP/b02/checksums.txt"'" "$out" ;;
            *.tar.gz) cp "'"$TMP/b02/caddy.tar.gz"'" "$out" ;;
            *) return 1 ;;
        esac
    }
    caddy_fetch_binary v2.9.0 "'"$TMP/b02/wd"'" >/dev/null 2>&1
'; then ok "BUG-02: Caddy SHA-512 checksums.txt verification succeeds"; else fail "BUG-02"; fi

# BUG-03: xray_ensure_geo_data fetches dlc.dat + .sha256sum cleanly with zero .tmp leaks
mkdir -p "$TMP/b03/src" "$TMP/b03/x"
dd if=/dev/urandom bs=1024 count=20 of="$TMP/b03/src/geoip.dat" status=none
dd if=/dev/urandom bs=1024 count=20 of="$TMP/b03/src/dlc.dat" status=none
sha256sum "$TMP/b03/src/geoip.dat" | awk '{print $1 "  geoip.dat"}' > "$TMP/b03/src/geoip.dat.sha256sum"
sha256sum "$TMP/b03/src/dlc.dat"   | awk '{print $1 "  dlc.dat"}'   > "$TMP/b03/src/dlc.dat.sha256sum"
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    XRAY_DIR="'"$TMP/b03/x"'"
    secure_curl() {
        local out="" url=""
        while [ $# -gt 0 ]; do
            case "$1" in -o) out="$2"; shift 2 ;; http*) url="$1"; shift ;; *) shift ;; esac
        done
        case "$url" in
            */geoip.dat) cp "'"$TMP/b03/src/geoip.dat"'" "$out" ;;
            */geoip.dat.sha256sum) cp "'"$TMP/b03/src/geoip.dat.sha256sum"'" "$out" ;;
            */dlc.dat) cp "'"$TMP/b03/src/dlc.dat"'" "$out" ;;
            */dlc.dat.sha256sum) cp "'"$TMP/b03/src/dlc.dat.sha256sum"'" "$out" ;;
            *) return 22 ;;
        esac
    }
    xray_ensure_geo_data >/dev/null 2>&1
    [ "$(ls "'"$TMP/b03/x"'"/*.tmp 2>/dev/null | wc -l || true)" -eq 0 ]
    cmp -s "'"$TMP/b03/src/dlc.dat"'" "'"$TMP/b03/x/geosite.dat"'"
'; then ok "BUG-03: xray_ensure_geo_data verifies dlc.dat+.sha256sum with 0 .tmp leaks"; else fail "BUG-03"; fi

# BUG-04: random_free_port uses CSPRNG and avoids TCP/UDP/managed_ports
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    tcp_listening() { return 1; }
    udp_listening() { [ "$1" -lt 40000 ]; }
    port_used_by_other_services() { [ "${1%/*}" -lt 45000 ]; }
    detect_ssh_ports() { echo 22; }
    RANDOM=42; a="$(random_free_port)"
    RANDOM=42; b="$(random_free_port)"
    [ "$a" -ge 45000 ] && [ "$b" -ge 45000 ] && [ "$a" != "$b" ]
'; then ok "BUG-04: random_free_port uses CSPRNG and avoids UDP & managed ports"; else fail "BUG-04"; fi

# BUG-05: caddy_write_main_config keeps CADDY_DATA_DIR at 0700
mkdir -p "$TMP/b05/c" "$TMP/b05/d"
chmod 700 "$TMP/b05/d"
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    CADDY_DIR="'"$TMP/b05/c"'"; CADDY_SITES_DIR="'"$TMP/b05/c/sites"'"; CADDY_DATA_DIR="'"$TMP/b05/d"'"; CADDY_FILE="'"$TMP/b05/c/Caddyfile"'"
    caddy_write_main_config >/dev/null 2>&1
    [ "$(stat -c %a "'"$TMP/b05/d"'")" = "700" ]
'; then ok "BUG-05: caddy_write_main_config preserves CADDY_DATA_DIR mode 0700"; else fail "BUG-05"; fi

# BUG-07: cf_tunnel_setup_token preserves trimmed token with trailing whitespace
tok86="$(bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    CF_TUNNEL_DIR="'"$TMP/b07"'"; CF_TUNNEL_ENV="'"$TMP/b07/tunnel.env"'"; CF_TUNNEL_SERVICE="'"$TMP/b07/svc"'"; CF_TUNNEL_BIN="/bin/true"
    cf_tunnel_installed() { return 0; }
    systemctl() { return 0; }
    printf "eyJhIjoiMTIzIn0= \n" | cf_tunnel_setup_token >/dev/null 2>&1
    sed -n "s/^TUNNEL_TOKEN=//p" "'"$TMP/b07/tunnel.env"'"
')"
if [ "$tok86" = '"eyJhIjoiMTIzIn0="' ]; then ok "BUG-07: cf_tunnel_setup_token trims trailing whitespace safely"; else fail "BUG-07: got [$tok86]"; fi

# BUG-08: realm_reload_service returns non-zero on rebuild failure
rc86=0
bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    realm_installed() { return 0; }; realm_enabled_count() { echo 1; }; realm_rebuild_all() { return 1; }; systemctl() { return 0; }
    realm_reload_service >/dev/null 2>&1
' || rc86=$?
if [ "$rc86" -ne 0 ]; then ok "BUG-08: realm_reload_service propagates rebuild failure (rc=$rc86)"; else fail "BUG-08"; fi

# BUG-09: port_used_by_other_services ignores leftover dirs of uninstalled services
mkdir -p "$TMP/b09/snell"
printf '[snell-server]\nlisten = 0.0.0.0:28888\npsk = abc\n' > "$TMP/b09/snell/snell-server.conf"
rc86=0
bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    BIN_PATH="/nonexistent/nw"; SERVICE_FILE="/nonexistent/nw.svc"
    SNELL_BIN="/nonexistent/snell"; SNELL_SERVICE="/nonexistent/snell.svc"
    SNELL_DIR="'"$TMP/b09/snell"'"; SNELL_CONF="'"$TMP/b09/snell/snell-server.conf"'"; SNELL_PORTS_DIR="'"$TMP/b09/snell/ports"'"
    XRAY_BIN="/nonexistent/x"; XRAY_SERVICE="/nonexistent/x.svc"; REALM_BIN="/nonexistent/r"; REALM_SERVICE="/nonexistent/r.svc"; CADDY_BIN="/nonexistent/c"; CADDY_SERVICE="/nonexistent/c.svc"
    port_used_by_other_services 28888/tcp xray
' || rc86=$?
if [ "$rc86" -ne 0 ]; then ok "BUG-09: port_used_by_other_services ignores uninstalled ghost configs"; else fail "BUG-09"; fi

# BUG-10: do_restore rejects evil & traversal symlinks while allowing safe letsencrypt live->archive symlink
mkdir -p "$TMP/b10/etc/nowhere" "$TMP/b10/good/etc/letsencrypt/live/ex.com" "$TMP/b10/good/etc/letsencrypt/archive/ex.com" "$TMP/b10/trav/etc/letsencrypt/live/ex.com"
ln -s /etc/shadow "$TMP/b10/etc/nowhere/evil"
tar -czf "$TMP/b10/evil.tgz" -C "$TMP/b10" etc/nowhere/evil
echo "cert" > "$TMP/b10/good/etc/letsencrypt/archive/ex.com/fullchain1.pem"
ln -s ../../archive/ex.com/fullchain1.pem "$TMP/b10/good/etc/letsencrypt/live/ex.com/fullchain.pem"
tar -czf "$TMP/b10/good.tgz" -C "$TMP/b10/good" etc/letsencrypt
ln -s ../../archive/../../../etc/shadow "$TMP/b10/trav/etc/letsencrypt/live/ex.com/fullchain.pem"
tar -czf "$TMP/b10/trav.tgz" -C "$TMP/b10/trav" etc/letsencrypt
rc_evil=0; bash -c 'set -euo pipefail; source "'"$TMP/lib.sh"'"; current_role() { echo none; }; confirm() { return 1; }; do_restore "'"$TMP/b10/evil.tgz"'" >/dev/null 2>&1' || rc_evil=$?
rc_trav=0; bash -c 'set -euo pipefail; source "'"$TMP/lib.sh"'"; current_role() { echo none; }; confirm() { return 1; }; do_restore "'"$TMP/b10/trav.tgz"'" >/dev/null 2>&1' || rc_trav=$?
rc_good=0; bash -c 'set -euo pipefail; source "'"$TMP/lib.sh"'"; current_role() { echo none; }; confirm() { return 1; }; do_restore "'"$TMP/b10/good.tgz"'" >/dev/null 2>&1' || rc_good=$?
if [ "$rc_evil" -ne 0 ] && [ "$rc_trav" -ne 0 ] && [ "$rc_good" -eq 0 ]; then
    ok "BUG-10: do_restore rejects evil/traversal symlinks and allows safe letsencrypt symlinks"
else
    fail "BUG-10: evil=$rc_evil trav=$rc_trav good=$rc_good"
fi

# BUG-11: snell_fix_perms & xray_fix_perms enforce chmod even when system group absent
mkdir -p "$TMP/b11/s" "$TMP/b11/x/nodes"
touch "$TMP/b11/s/snell-server.conf" "$TMP/b11/x/nodes/a.env"
chmod 666 "$TMP/b11/s/snell-server.conf" "$TMP/b11/x/nodes/a.env"
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    getent() { return 2; }
    SNELL_DIR="'"$TMP/b11/s"'"; SNELL_CONF="'"$TMP/b11/s/snell-server.conf"'"; SNELL_PORTS_DIR="'"$TMP/b11/s/ports"'"; SNELL_STATE_FILE="'"$TMP/b11/s/s.env"'"; SNELL_VERSION_FILE="'"$TMP/b11/s/v.txt"'"; SNELL_BIN="/nonexistent"
    XRAY_CONF_DIR="'"$TMP/b11/x"'"; XRAY_CONF_D="'"$TMP/b11/x/conf.d"'"; XRAY_CERT_DIR="'"$TMP/b11/x/certs"'"; XRAY_NODE_DIR="'"$TMP/b11/x/nodes"'"; XRAY_FWD_DIR="'"$TMP/b11/x/fwd"'"; XRAY_STATE_FILE="'"$TMP/b11/x/s.env"'"; XRAY_DIR="/nonexistent"; XRAY_BIN="/nonexistent"
    snell_fix_perms; xray_fix_perms
    [ "$(stat -c %a "'"$TMP/b11/s/snell-server.conf"'")" = "640" ]
    [ "$(stat -c %a "'"$TMP/b11/x/nodes/a.env"'")" = "600" ]
'; then ok "BUG-11: snell_fix_perms & xray_fix_perms enforce 640/600 unconditionally"; else fail "BUG-11"; fi

# BUG-14d: tcp_port_conflict detects mixed own + other listener
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    ss_port_lines() {
        printf "LISTEN 0 128 0.0.0.0:443 0.0.0.0:* users:((\"caddy\",pid=1,fd=5))\n"
        printf "LISTEN 0 128 [::]:443 [::]:* users:((\"nginx\",pid=2,fd=6))\n"
    }
    tcp_port_conflict 443 caddy
'; then ok "BUG-14d: tcp_port_conflict catches mixed own+other listeners"; else fail "BUG-14d"; fi

# BUG-16: port_used_by_other_services avoids SIGPIPE under pipefail
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    BIN_PATH="/nonexistent"; SERVICE_FILE="/nonexistent"; SNELL_BIN="/bin/true"; SNELL_SERVICE="/nonexistent"
    snell_all_ports() { seq 10000 35000; }
    port_used_by_other_services 10000/tcp xray
'; then ok "BUG-16: port_used_by_other_services avoids SIGPIPE under pipefail"; else fail "BUG-16"; fi

echo ""
echo "=== Part 2: Core v8.6 Capabilities ==="

# 1. CSPRNG Engine
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    h="$(csprng_hex 16)"; [[ "$h" =~ ^[0-9a-f]{32}$ ]]
    b="$(csprng_base64 32)"; [ "${#b}" -ge 40 ]
    for _ in $(seq 1 30); do v="$(csprng_int 32 48)"; [ "$v" -ge 32 ] && [ "$v" -le 48 ]; done
    a1="$(csprng_alnum 40 "A-Za-z0-9_-")"; [[ "$a1" =~ ^[A-Za-z0-9_-]{40}$ ]]
    a2="$(bash -c "set -euo pipefail; source \"'"$TMP/lib.sh"'\"
        command() { [ \"\${2:-}\" = python3 ] && return 1 || builtin command \"\$@\"; }
        csprng_alnum 40 \"A-Za-z0-9_-\"")"
    [[ "$a2" =~ ^[A-Za-z0-9_-]{40}$ ]]
    sid="$(csprng_short_id)"; [[ "$sid" =~ ^([0-9a-f]{2}){4,8}$ ]]
    up="$(csprng_url_path)"; [[ "$up" =~ ^/[a-z0-9]+/[a-z0-9]+/[a-z0-9]{8,12}$ ]]
    for _ in $(seq 1 15); do
        psk="$(snell_gen_psk)"
        [ "${#psk}" -ge 32 ] && [ "${#psk}" -le 48 ]
        [[ "$psk" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{30,46}[A-Za-z0-9]$ ]]
    done
'; then ok "CSPRNG Engine: hex, base64, unbiased int, alnum (Python + awk), short_id, url_path, Snell 32-48 PSK"; else fail "CSPRNG Engine"; fi

# 2. verify_elf_binary
mkdir -p "$TMP/elf"
printf '#!/bin/sh\necho hi\n' > "$TMP/elf/script.sh"
ln -s /bin/true "$TMP/elf/link"
python3 - "$TMP/elf/wrong.elf" "$(uname -m)" <<'PY'
import sys
b = bytearray(64); b[0:4] = b'\x7fELF'; b[4] = 2; b[5] = 1; b[6] = 1
b[18] = 0xb7 if sys.argv[2] in ('x86_64', 'amd64') else 0x3e; b[19] = 0x00
open(sys.argv[1], 'wb').write(b)
PY
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    verify_elf_binary /bin/true
    ! verify_elf_binary "'"$TMP/elf/script.sh"'"
    ! verify_elf_binary "'"$TMP/elf/link"'"
    ! verify_elf_binary "'"$TMP/elf/wrong.elf"'"
'; then ok "verify_elf_binary: native ELF accepted; script/symlink/wrong-arch rejected"; else fail "verify_elf_binary"; fi

# 3. github_asset_sha256 (Python, pure-awk, expanded_assets HTML)
D1="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
D2="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    secure_curl() {
        local url="${!#}"
        case "$url" in
            *api.github.com*) printf "{\"assets\":[{\"name\":\"other.tar.gz\",\"digest\":\"sha256:%s\"},{\"name\":\"target.tar.gz\",\"digest\":\"sha256:%s\"}]}" "'"$D1"'" "'"$D2"'" ;;
            *) return 1 ;;
        esac
    }
    [ "$(github_asset_sha256 org/repo v1.0 target.tar.gz)" = "'"$D2"'" ]
    command() { [ "${2:-}" = "python3" ] && return 1 || builtin command "$@"; }
    [ "$(github_asset_sha256 org/repo v1.0 target.tar.gz)" = "'"$D2"'" ]
    secure_curl() {
        local url="${!#}"
        case "$url" in
            *expanded_assets*) printf "<a href=\"/org/repo/releases/download/v1.0/target.tar.gz\">t</a>\n<span>sha256:%s</span>\n" "'"$D2"'" ;;
            *) return 1 ;;
        esac
    }
    [ "$(github_asset_sha256 org/repo v1.0 target.tar.gz)" = "'"$D2"'" ]
'; then ok "github_asset_sha256: Python JSON, pure-awk JSON, and expanded_assets fallback"; else fail "github_asset_sha256"; fi

# 4. xray_gen_self_signed_cert
mkdir -p "$TMP/cert"
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    xray_gen_self_signed_cert "cdn.example.com" "'"$TMP/cert"'"
    txt="$(openssl x509 -in "'"$TMP/cert/fullchain.pem"'" -noout -text)"
    [[ "$txt" == *"prime256v1"* ]] && [[ "$txt" == *"DNS:cdn.example.com"* ]]
    days="$(cert_expiry_days "'"$TMP/cert/fullchain.pem"'")"
    [ "$days" -ge 364 ] && [ "$days" -le 731 ]
    [ "$(stat -c %a "'"$TMP/cert/privkey.pem"'")" = "640" ]
'; then ok "xray_gen_self_signed_cert: ECDSA P-256, SAN, 365-730d CSPRNG validity, 0640 perms"; else fail "xray_gen_self_signed_cert"; fi

# 5. xray_pick_fp PQ-safe REALITY guard
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    for _ in $(seq 1 40); do
        xray_pick_fp reality <<< "" >/dev/null
        case "$XR_FP" in chrome|firefox|safari) ;; *) exit 1 ;; esac
    done
    xray_pick_fp reality < <(printf "5\nn\n") >/dev/null
    [ "$XR_FP" = "chrome" ]
    xray_pick_fp tls <<< "5" >/dev/null
    [ "$XR_FP" = "edge" ]
'; then ok "xray_pick_fp: PQ-safe REALITY guard + TLS edge/ios support"; else fail "xray_pick_fp"; fi

# 6. Nowhere v3.3.0 HANDSHAKE_TIMEOUT=auto
mkdir -p "$TMP/nw"
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    SERVICE_FILE="'"$TMP/nw/nowhere.service"'"; CONFIG_FILE="'"$TMP/nw/nowhere.env"'"
    HANDSHAKE_TIMEOUT="auto"; NOWHERE_USER="nowhere"
    nowhere_write_portal_unit
    ! grep -q "NOW_HANDSHAKE_TIMEOUT" "$SERVICE_FILE"
    HANDSHAKE_TIMEOUT="15s"
    nowhere_write_portal_unit
    grep -q "^Environment=NOW_HANDSHAKE_TIMEOUT=15s$" "$SERVICE_FILE"
'; then ok "nowhere_write_portal_unit: auto omits NOW_HANDSHAKE_TIMEOUT; custom sets Environment="; else fail "nowhere_write_portal_unit"; fi

# 7. env_file_safe
mkdir -p "$TMP/env"
printf 'N_TAG="vision-443"\nN_FP="firefox"\nN_SPX="/v2/events/a1b2c3d4"\n' > "$TMP/env/good.env"
printf 'N_TAG="$(id)"\n' > "$TMP/env/bad1.env"
printf 'EVIL="1"\n' > "$TMP/env/bad2.env"
ln -s "$TMP/env/good.env" "$TMP/env/link.env"
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    env_file_safe "'"$TMP/env/good.env"'"
    ! env_file_safe "'"$TMP/env/bad1.env"'"
    ! env_file_safe "'"$TMP/env/bad2.env"'"
    ! env_file_safe "'"$TMP/env/link.env"'"
'; then ok "env_file_safe: accepts valid env; rejects injection, unknown keys & symlinks"; else fail "env_file_safe"; fi

# 8. _doctor_check_perm
mkdir -p "$TMP/wd/etc/nowhere" "$TMP/wd/run"
touch "$TMP/wd/etc/nowhere/nowhere.env"
chmod 644 "$TMP/wd/etc/nowhere/nowhere.env"
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    ! _doctor_check_perm "'"$TMP/wd/etc/nowhere/nowhere.env"'" strict >/dev/null
    chmod 600 "'"$TMP/wd/etc/nowhere/nowhere.env"'"
    _doctor_check_perm "'"$TMP/wd/etc/nowhere/nowhere.env"'" strict >/dev/null
'; then ok "_doctor_check_perm: flags 0644 secret config and passes 0600"; else fail "_doctor_check_perm"; fi

# 9. maint_watchdog two-stage self-heal + 30-min cooldown
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    MAINT_WATCHDOG=1; MAINT_LOG="'"$TMP/wd/maint.log"'"; NOTIFY_ENV="'"$TMP/wd/no-notify.env"'"
    maint_load() { MAINT_WATCHDOG=1; }
    maint_lock() { return 0; }
    snell_extra_ports() { return 0; }
    maint_unit_installed() { [ "$1" = "adam-realm" ]; }
    systemctl() { return 0; }
    HEALED=0
    maint_unit_healthy() { [ "$HEALED" = "1" ]; }
    _realm_repair_core() { HEALED=1; return 0; }
    eval "$(declare -f maint_watchdog | sed "s#/run/adam-wd-heal#'"$TMP/wd/run/adam-wd-heal"'#g")"
    maint_watchdog >/dev/null 2>&1
    grep -q "经二段自动修复已恢复" "$MAINT_LOG"
    HEALED=0
    _realm_repair_core() { echo "SHOULD_NOT_RUN" >> "$MAINT_LOG"; return 0; }
    maint_watchdog >/dev/null 2>&1
    grep -q "二段自愈冷却中" "$MAINT_LOG"
    ! grep -q "SHOULD_NOT_RUN" "$MAINT_LOG"
'; then ok "maint_watchdog: two-stage self-heal recovers & enforces 30-min cooldown"; else fail "maint_watchdog"; fi

echo ""
printf 'Regressions Summary: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
