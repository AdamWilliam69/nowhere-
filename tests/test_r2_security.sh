#!/usr/bin/env bash
# Round-2 deep security, permission consistency, and pipefail audit test suite
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${REPO_ROOT}/nowhere-install.sh"
TMP="$(mktemp -d /tmp/test-r2-sec.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
awk '/^\[ "\$EUID" -ne 0 \]/ { next } /^case "\$ACTION" in/ { exit } { print }' "$SCRIPT" > "$TMP/lib.sh"

PASS=0; FAIL=0
ok()   { PASS=$((PASS + 1)); printf '  [PASS] %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  [FAIL] %s\n' "$1"; }

echo "=== Round 2 Security & Permission Audit ==="

# R2-BUG-01: CONFIG_DIR stays 750 across nowhere_fix_perms, record_installed_version, save_install_draft
mkdir -p "$TMP/r1/etc/nowhere/certs"
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    CONFIG_DIR="'"$TMP/r1/etc/nowhere"'"; VERSION_FILE="'"$TMP/r1/etc/nowhere/version.txt"'"
    CONFIG_FILE="'"$TMP/r1/etc/nowhere/nowhere.env"'"; EGRESS_CONFIG_FILE="'"$TMP/r1/etc/nowhere/egress.env"'"
    TLS_PIN_FILE="'"$TMP/r1/etc/nowhere/tls-pin.txt"'"; EGRESS_CONFIG_TXT="'"$TMP/r1/etc/nowhere/egress-config.txt"'"
    INSTALL_DRAFT_FILE="'"$TMP/r1/etc/nowhere/.draft"'"; ROLE_FILE="'"$TMP/r1/etc/nowhere/role"'"
    PREV_VERSION_FILE="'"$TMP/r1/etc/nowhere/prev.txt"'"; BIN_PATH="/nonexistent"
    chown() { return 0; }
    nowhere_fix_perms
    [ "$(stat -c %a "$CONFIG_DIR")" = "750" ]
    record_installed_version "v3.3.0"
    [ "$(stat -c %a "$CONFIG_DIR")" = "750" ]
    save_install_draft
    [ "$(stat -c %a "$CONFIG_DIR")" = "750" ]
    [ "$(stat -c %a "$INSTALL_DRAFT_FILE")" = "600" ]
'; then ok "R2-BUG-01: CONFIG_DIR remains 0750 across fix_perms/record_installed_version/save_install_draft"; else fail "R2-BUG-01"; fi

# R2-BUG-02: Caddy 0750 / 0640 / 0700 consistent with _doctor_check_perm
mkdir -p "$TMP/r2/caddy/sites" "$TMP/r2/caddy_data"
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    CADDY_DIR="'"$TMP/r2/caddy"'"; CADDY_SITES_DIR="'"$TMP/r2/caddy/sites"'"; CADDY_DATA_DIR="'"$TMP/r2/caddy_data"'"
    CADDY_FILE="'"$TMP/r2/caddy/Caddyfile"'"; CADDY_STATE_FILE="'"$TMP/r2/caddy/adam-caddy.env"'"
    chown() { return 0; }
    caddy_write_main_config; caddy_save_state; caddy_fix_perms
    [ "$(stat -c %a "$CADDY_DIR")" = "750" ]
    [ "$(stat -c %a "$CADDY_SITES_DIR")" = "750" ]
    [ "$(stat -c %a "$CADDY_FILE")" = "640" ]
    [ "$(stat -c %a "$CADDY_DATA_DIR")" = "700" ]
    _doctor_check_perm "$CADDY_DIR" group_ro >/dev/null
    _doctor_check_perm "$CADDY_SITES_DIR" group_ro >/dev/null
'; then ok "R2-BUG-02: Caddy dirs 0750/0640/0700 pass do_doctor with 0 warnings"; else fail "R2-BUG-02"; fi

# R2-BUG-03: env_file_safe & state_load block key injection & trailing-backslash quote escape
mkdir -p "$TMP/r3"
printf 'N_A;touch %s/pwned1;X="y"\n' "$TMP/r3" > "$TMP/r3/inj_key.env"
printf 'N_A="foo\\"\nN_B=" ; touch %s/pwned2 #"\n' "$TMP/r3" > "$TMP/r3/inj_quote.env"
printf 'N_TAG="ok-1"\nN_REMARK="hello \\"world\\" \\\\ ok"\n' > "$TMP/r3/legit.env"
printf 'MAINT_WATCHDOG="1\\"\nEVIL=" ; touch %s/pwned3 #"\n' "$TMP/r3" > "$TMP/r3/bad_state.env"
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    ! env_file_safe "'"$TMP/r3/inj_key.env"'"
    ! env_file_safe "'"$TMP/r3/inj_quote.env"'"
    env_file_safe "'"$TMP/r3/legit.env"'"
    state_load "'"$TMP/r3/bad_state.env"'" "MAINT_WATCHDOG=0"
    [ ! -e "'"$TMP/r3/pwned1"'" ] && [ ! -e "'"$TMP/r3/pwned2"'" ] && [ ! -e "'"$TMP/r3/pwned3"'" ]
    [ "$MAINT_WATCHDOG" = "0" ]
'; then ok "R2-BUG-03: env_file_safe & state_load block key & escaped-quote injection"; else fail "R2-BUG-03"; fi

# R2-BUG-04: realm_import_rules catches symlink even in >64KB tar archive under pipefail
mkdir -p "$TMP/r4/etc/adam-realm/rules"
ln -s /etc/shadow "$TMP/r4/etc/adam-realm/rules/000_evil.env"
for i in $(seq -w 1 1500); do
    : > "$TMP/r4/etc/adam-realm/rules/r_${i}_padding_filename_for_pipe_buffer.env"
done
tar -czf "$TMP/r4/evil_big.tgz" -C "$TMP/r4" etc/adam-realm
rc4=0
bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    realm_installed() { return 0; }
    realm_import_rules <<< "'"$TMP/r4/evil_big.tgz"'" >/dev/null 2>&1
' || rc4=$?
if [ "$rc4" -ne 0 ]; then ok "R2-BUG-04: realm_import_rules blocks symlink in >64KB archive under pipefail"; else fail "R2-BUG-04: rc4=$rc4"; fi

# R2-BUG-05: detect_binary detects musl even when ldd --version exits 1 under pipefail
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    ldd() { echo "musl libc (x86_64) Version 1.2.5" >&2; return 1; }
    detect_binary
    [ "$LIBC" = "musl" ]
'; then ok "R2-BUG-05: detect_binary detects musl when ldd --version exits 1"; else fail "R2-BUG-05"; fi

# R2-BUG-06: xray_uninstall does NOT delete unrelated 80/tcp when Xray had no HTTP-01 node
mkdir -p "$TMP/r6/opt" "$TMP/r6/etc/nodes"
touch "$TMP/r6/opt/xray"; chmod +x "$TMP/r6/opt/xray"
echo 'N_TYPE="vision"' > "$TMP/r6/etc/nodes/vision-443.env"
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    XRAY_DIR="'"$TMP/r6/opt"'"; XRAY_BIN="'"$TMP/r6/opt/xray"'"; XRAY_SERVICE="'"$TMP/r6/svc"'"
    XRAY_CONF_DIR="'"$TMP/r6/etc"'"; XRAY_NODE_DIR="'"$TMP/r6/etc/nodes"'"; XRAY_FWD_DIR="'"$TMP/r6/etc/fwd"'"
    CONFIG_FILE="/nonexistent"
    systemctl() { return 0; }; userdel() { return 0; }; reserved_ports_sync() { return 0; }
    port_used_by_other_services() { return 1; }; ufw_installed() { return 0; }
    ufw() { echo "UFW_CALLED: $*" >> "'"$TMP/r6/ufw.log"'"; return 0; }
    confirm() { return 0; }
    xray_uninstall >/dev/null 2>&1
    ! grep -q "80/tcp" "'"$TMP/r6/ufw.log"'" 2>/dev/null
'; then ok "R2-BUG-06: xray_uninstall preserves unrelated 80/tcp rule"; else fail "R2-BUG-06"; fi

# R2-BUG-07: state_save creates file atomically with mode 600
mkdir -p "$TMP/r7"
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    FOO="bar"
    state_save "'"$TMP/r7/state.env"'" "'"$TMP/r7"'" 750 FOO
    [ "$(stat -c %a "'"$TMP/r7/state.env"'")" = "600" ]
'; then ok "R2-BUG-07: state_save writes atomically with mode 600"; else fail "R2-BUG-07"; fi

echo ""
printf 'R2 Security Summary: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
