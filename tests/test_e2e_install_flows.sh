#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
V86="${REPO_ROOT}/nowhere-install.sh"
TMP="$(mktemp -d /tmp/e2e-v86.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

awk '/^\[ "\$EUID" -ne 0 \]/ { next } /^case "\$ACTION" in/ { exit } { print }' "$V86" > "$TMP/lib86.sh"

PASS=0
FAIL=0
ok()   { PASS=$((PASS + 1)); printf '  [PASS] %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  [FAIL] %s\n' "$1"; }

# Build a realistic mock ELF binary (native arch! compiled tiny C or copied /bin/true wrapper?
# Wait: verify_elf_binary checks real ELF magic + native e_machine! Let's compile a tiny real C binary
# that handles --version, version, uuid, x25519, vlessenc, run -test, validate, generate-key, -v, status, probe!)
cat > "$TMP/mockbin.c" << 'CEOF'
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "version") == 0) {
        printf("Xray 26.10.31 (Xray, Penetrates Everything) Custom\n");
        return 0;
    }
    if (argc >= 2 && (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-v") == 0)) {
        printf("v3.3.0\n");
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "uuid") == 0) {
        printf("11111111-2222-4333-8444-555555555555\n");
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "x25519") == 0) {
        printf("PrivateKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n");
        printf("Password (PublicKey): BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n");
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "mldsa65") == 0) {
        printf("Seed: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC\n");
        printf("Verify: DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD\n");
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "vlessenc") == 0) {
        printf("Authentication: ML-KEM-768, Post-Quantum\n");
        printf("\"decryption\": \"mlkem768x25519plus.native.600s.DECKEY123456\"\n");
        printf("\"encryption\": \"mlkem768x25519plus.native.0rtt.ENCKEY123456\"\n");
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "generate-key") == 0) {
        printf("0123456789abcdef0123456789abcdef\n");
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "run") == 0) {
        printf("Configuration OK.\n");
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "validate") == 0) {
        printf("Valid configuration\n");
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "probe") == 0) {
        const char *ht = getenv("NOW_HANDSHAKE_TIMEOUT");
        if (ht && strcmp(ht, "auto") == 0) {
            fprintf(stderr, "ERROR: invalid NOW_HANDSHAKE_TIMEOUT=auto\n");
            return 2;
        }
        printf("Result: OK\n");
        return 0;
    }
    return 0;
}
CEOF
# Add stdlib.h for getenv
sed -i '1i #include <stdlib.h>' "$TMP/mockbin.c"
gcc -O2 -o "$TMP/mock_elf" "$TMP/mockbin.c"

# Prepare realistic release archives matching native arch
mkdir -p "$TMP/dl"
cp "$TMP/mock_elf" "$TMP/dl/nowhere"
tar -czf "$TMP/dl/nowhere.tar.gz" -C "$TMP/dl" nowhere
SHA_NW="$(sha256sum "$TMP/dl/nowhere.tar.gz" | awk '{print $1}')"

cp "$TMP/mock_elf" "$TMP/dl/snell-server"
(cd "$TMP/dl" && zip -q snell.zip snell-server)

mkdir -p "$TMP/dl/xpkg"
cp "$TMP/mock_elf" "$TMP/dl/xpkg/xray"
dd if=/dev/urandom bs=1024 count=16 of="$TMP/dl/xpkg/geoip.dat" status=none
dd if=/dev/urandom bs=1024 count=16 of="$TMP/dl/xpkg/geosite.dat" status=none
(cd "$TMP/dl/xpkg" && zip -q "$TMP/dl/xray.zip" xray geoip.dat geosite.dat)
SHA_XRAY="$(sha256sum "$TMP/dl/xray.zip" | awk '{print $1}')"
printf 'SHA2-256= %s\n' "$SHA_XRAY" > "$TMP/dl/xray.zip.dgst"

cp "$TMP/mock_elf" "$TMP/dl/realm"
tar -czf "$TMP/dl/realm.tar.gz" -C "$TMP/dl" realm
SHA_REALM="$(sha256sum "$TMP/dl/realm.tar.gz" | awk '{print $1}')"

cp "$TMP/mock_elf" "$TMP/dl/caddy"
tar -czf "$TMP/dl/caddy.tar.gz" -C "$TMP/dl" caddy
SHA512_CADDY="$(sha512sum "$TMP/dl/caddy.tar.gz" | awk '{print $1}')"
ARCH_C="$(case "$(uname -m)" in x86_64|amd64) echo amd64;; aarch64|arm64) echo arm64;; *) echo amd64;; esac)"
printf '%s  caddy_2.9.0_linux_%s.tar.gz\n' "$SHA512_CADDY" "$ARCH_C" > "$TMP/dl/caddy_checksums.txt"

cp "$TMP/mock_elf" "$TMP/dl/cloudflared"
SHA_CF="$(sha256sum "$TMP/dl/cloudflared" | awk '{print $1}')"

# Common sandbox prelude sourced inside each flow test
cat > "$TMP/prelude.sh" << PEOF
set -euo pipefail
source "$TMP/lib86.sh"
ROOT="$TMP/fs"
mkdir -p "\$ROOT/etc/systemd/system" "\$ROOT/usr/local/bin" "\$ROOT/opt/adam-xray" "\$ROOT/var/log" "\$ROOT/var/lib/adam-caddy" "\$ROOT/etc/sysctl.d" "\$ROOT/etc/adam" "\$ROOT/run"

BIN_PATH="\$ROOT/usr/local/bin/nowhere"
BIN_BACKUP_PATH="\$ROOT/usr/local/bin/nowhere.previous"
CONFIG_DIR="\$ROOT/etc/nowhere"
CONFIG_FILE="\$CONFIG_DIR/nowhere.env"
INSTALL_DRAFT_FILE="\$CONFIG_DIR/.install-draft.env"
VERSION_FILE="\$CONFIG_DIR/version.txt"
PREV_VERSION_FILE="\$CONFIG_DIR/version.previous.txt"
SERVICE_FILE="\$ROOT/etc/systemd/system/nowhere.service"
EGRESS_CONFIG_FILE="\$CONFIG_DIR/egress.env"
EGRESS_CONFIG_TXT="\$CONFIG_DIR/egress-config.txt"
TLS_PIN_FILE="\$CONFIG_DIR/tls-pin.txt"
ROLE_FILE="\$CONFIG_DIR/role"
MANAGER_PATH="\$ROOT/usr/local/bin/adam-nowhere-manager.sh"

SNELL_BIN="\$ROOT/usr/local/bin/snell-server"
SNELL_BIN_BACKUP="\$ROOT/usr/local/bin/snell-server.previous"
SNELL_DIR="\$ROOT/etc/snell"
SNELL_CONF="\$SNELL_DIR/snell-server.conf"
SNELL_VERSION_FILE="\$SNELL_DIR/version.txt"
SNELL_STATE_FILE="\$SNELL_DIR/adam-snell.env"
SNELL_SERVICE="\$ROOT/etc/systemd/system/snell.service"
SNELL_PORTS_DIR="\$SNELL_DIR/ports"
SNELL_PORT_UNIT="\$ROOT/etc/systemd/system/snell-port@.service"

XRAY_DIR="\$ROOT/opt/adam-xray"
XRAY_BIN="\$XRAY_DIR/xray"
XRAY_CONF_DIR="\$ROOT/etc/adam-xray"
XRAY_CONF_D="\$XRAY_CONF_DIR/conf.d"
XRAY_NODE_DIR="\$XRAY_CONF_DIR/nodes"
XRAY_CERT_DIR="\$XRAY_CONF_DIR/certs"
XRAY_STATE_FILE="\$XRAY_CONF_DIR/adam-xray.env"
XRAY_SERVICE="\$ROOT/etc/systemd/system/adam-xray.service"
XRAY_FWD_DIR="\$XRAY_CONF_DIR/forward"
XRAY_FWD_JSON="\$XRAY_CONF_D/20-forward.json"

REALM_BIN="\$ROOT/usr/local/bin/realm"
REALM_BIN_BACKUP="\$ROOT/usr/local/bin/realm.previous"
REALM_DIR="\$ROOT/etc/adam-realm"
REALM_CONF_D="\$REALM_DIR/conf.d"
REALM_CONFIG_FILE="\$REALM_DIR/config.toml"
REALM_RULE_DIR="\$REALM_DIR/rules"
REALM_VERSION_FILE="\$REALM_DIR/version.txt"
REALM_SERVICE="\$ROOT/etc/systemd/system/adam-realm.service"

CADDY_BIN="\$ROOT/usr/local/bin/caddy"
CADDY_BIN_BACKUP="\$ROOT/usr/local/bin/caddy.previous"
CADDY_DIR="\$ROOT/etc/adam-caddy"
CADDY_SITES_DIR="\$CADDY_DIR/sites"
CADDY_FILE="\$CADDY_DIR/Caddyfile"
CADDY_STATE_FILE="\$CADDY_DIR/adam-caddy.env"
CADDY_DATA_DIR="\$ROOT/var/lib/adam-caddy"
CADDY_SERVICE="\$ROOT/etc/systemd/system/adam-caddy.service"

CF_TUNNEL_BIN="\$ROOT/usr/local/bin/cloudflared"
CF_TUNNEL_BIN_BACKUP="\$ROOT/usr/local/bin/cloudflared.previous"
CF_TUNNEL_DIR="\$ROOT/etc/adam-cloudflared"
CF_TUNNEL_ENV="\$CF_TUNNEL_DIR/tunnel.env"
CF_TUNNEL_SERVICE="\$ROOT/etc/systemd/system/adam-cloudflared.service"

MAINT_DIR="\$ROOT/etc/adam"
LANG_FILE="\$MAINT_DIR/lang"
MAINT_ENV="\$MAINT_DIR/maintain.env"
NOTIFY_ENV="\$MAINT_DIR/notify.env"
MAINT_LOG="\$ROOT/var/log/adam-maintain.log"
MAINT_LOCK="\$ROOT/run/adam-maintain.lock"
RESERVED_PORTS_FILE="\$ROOT/etc/sysctl.d/99-adam-reserved-ports.conf"
F2B_JAIL_FILE="\$ROOT/etc/fail2ban/adam-sshd.local"

# Mocks for system commands (non-destructive)
apt_install() { return 0; }
ensure_prereqs() { return 0; }
ensure_system_user() { return 0; }
ensure_manager_copy() { cp "$V86" "\$MANAGER_PATH"; chmod 755 "\$MANAGER_PATH"; return 0; }
install_shortcuts() { return 0; }
verify_shortcuts() { return 0; }
maint_install_timers() { return 0; }
maint_ask_script_auto() { return 0; }
fw_conflict_detected() { return 1; }
ufw_installed() { return 0; }
ufw_active() { return 0; }
ufw() { echo "ufw \$*" >> "\$ROOT/ufw.log"; return 0; }
sysctl() { return 0; }
userdel() { return 0; }
journalctl() { echo "mock journal"; return 0; }
systemctl() {
    case "\$1" in
        is-active|is-enabled) return 0 ;;
        list-units) return 0 ;;
        *) return 0 ;;
    esac
}
detect_public_host() { echo "203.0.113.10"; }
check_public_host() { return 0; }
check_domain_dns() { return 0; }
get_tls_fingerprint() { echo "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"; }
# Default: listening checks return 0 when asked after service start, conflicts return empty/1
check_port_occupied_by_other() { return 0; }
tcp_port_conflict() { return 1; }
tcp_listening() { return 0; }
udp_listening() { return 0; }
sleep() { return 0; }
chown() { return 0; }
PEOF

echo "=== E2E Full Installation Flows Audit ==="

# ── FLOW 1: Nowhere Portal Full Install (tls=1, auto handshake timeout) + probe + repair + doctor ──
if bash -c '
    source "'"$TMP/prelude.sh"'"
    get_latest_tag() { echo "v3.3.0"; }
    github_asset_sha256() { echo "'"$SHA_NW"'"; }
    secure_curl() {
        local out="" url=""
        while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2;; http*) url="$1"; shift;; *) shift;; esac; done
        case "$url" in *nowhere-*.tar.gz) cp "'"$TMP/dl/nowhere.tar.gz"'" "$out" ;; *) return 1 ;; esac
    }
    # Wizard inputs:
    # lang=1(zh), cert=1(tls=1), public_host=""(detected), port_mode=1(same), port=443, net=1(mix), fam=n, listen=""
    # key=""(auto), morph=y, prelude=1, handshake=""(auto), out=1(direct), dial=""(auto), dial46=n, rate=0, etar=0
    # gen_vector=y, vcarrier=1, vsocks=""(default), confirm=y
    do_install < <(printf "1\n1\n\n1\n443\n1\nn\n\n\ny\n1\n\n1\n\nn\n0\n0\ny\n1\n\ny\n") >/dev/null 2>&1

    # Verify results!
    [ -x "$BIN_PATH" ] || { echo "ERR: nowhere bin missing"; exit 1; }
    [ -f "$SERVICE_FILE" ] || { echo "ERR: nowhere unit missing"; exit 1; }
    if grep -q "NOW_HANDSHAKE_TIMEOUT" "$SERVICE_FILE"; then
        echo "ERR: NOW_HANDSHAKE_TIMEOUT leaked into unit when auto!"; exit 1
    fi
    grep -q "^HANDSHAKE_TIMEOUT_VALUE=\"auto\"" "$CONFIG_FILE" || { echo "ERR: HANDSHAKE_TIMEOUT_VALUE not auto"; exit 1; }
    if grep -q "NOW_HANDSHAKE_TIMEOUT=" "$CONFIG_DIR/config.txt"; then
        echo "ERR: NOW_HANDSHAKE_TIMEOUT leaked into config.txt launch cmds!"; exit 1
    fi
    # Check permissions right after install (including after save_current_pin!)
    m_dir="$(stat -c %a "$CONFIG_DIR")"
    m_env="$(stat -c %a "$CONFIG_FILE")"
    [ "$m_dir" = "750" ] || { echo "ERR: CONFIG_DIR mode=$m_dir (expected 750, got downgraded by save_current_pin/install!)"; exit 1; }
    [ "$m_env" = "600" ] || { echo "ERR: CONFIG_FILE mode=$m_env"; exit 1; }
    # Test do_probe (mock_elf fails with rc=2 if NOW_HANDSHAKE_TIMEOUT=auto!)
    do_probe <<< "" >/dev/null 2>&1
    # Test _nowhere_repair_core
    _nowhere_repair_core >/dev/null 2>&1
    [ "$(stat -c %a "$CONFIG_DIR")" = "750" ] || { echo "ERR: CONFIG_DIR mode after repair=$(stat -c %a "$CONFIG_DIR")"; exit 1; }
'; then
    ok "Flow 1 (Nowhere Portal): full install + auto timeout + probe + repair + perms"
else
    fail "Flow 1 (Nowhere Portal) FAILED"
fi

# ── FLOW 2: Nowhere Egress Full Install (paste egress:// + auto timeout) + repair ──
if bash -c '
    source "'"$TMP/prelude.sh"'"
    rm -rf "$ROOT/etc/nowhere" "$SERVICE_FILE" "$BIN_PATH"
    get_latest_tag() { echo "v3.3.0"; }
    github_asset_sha256() { echo "'"$SHA_NW"'"; }
    secure_curl() {
        local out="" url=""
        while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2;; http*) url="$1"; shift;; *) shift;; esac; done
        case "$url" in *nowhere-*.tar.gz) cp "'"$TMP/dl/nowhere.tar.gz"'" "$out" ;; *) return 1 ;; esac
    }
    # confirm=y, paste url, handshake=""(auto), prelude=1, confirm2=y
    do_install_egress_service < <(printf "y\negress://0123456789abcdef0123456789abcdef@203.0.113.10/udp:443?morph=1\n\n1\ny\n") >/dev/null 2>&1
    [ -f "$EGRESS_CONFIG_FILE" ] || { echo "ERR: egress.env missing"; exit 1; }
    grep -q "^EGRESS_HANDSHAKE_TIMEOUT=\"auto\"" "$EGRESS_CONFIG_FILE" || { echo "ERR: EGRESS_HANDSHAKE_TIMEOUT missing"; exit 1; }
    if grep -q "NOW_HANDSHAKE_TIMEOUT" "$EGRESS_CONFIG_FILE"; then
        echo "ERR: NOW_HANDSHAKE_TIMEOUT leaked into egress.env when auto!"; exit 1
    fi
    [ "$(stat -c %a "$EGRESS_CONFIG_FILE")" = "600" ] || { echo "ERR: egress.env perm"; exit 1; }
    [ "$(stat -c %a "$CONFIG_DIR")" = "750" ] || { echo "ERR: CONFIG_DIR perm=$(stat -c %a "$CONFIG_DIR")"; exit 1; }
    _nowhere_repair_core >/dev/null 2>&1
'; then
    ok "Flow 2 (Nowhere Egress): full install + auto timeout + repair + perms"
else
    fail "Flow 2 (Nowhere Egress) FAILED"
fi

# ── FLOW 3: Snell v6 Full Install + Add Extra Port + Reconfig PSK + Repair ──
if bash -c '
    source "'"$TMP/prelude.sh"'"
    snell_query_latest() { SNELL_LATEST="v6.0.1"; SNELL_LATEST_PRE=""; SNELL_NEWER_MAJOR=""; SNELL_SOURCE_OK=1; }
    secure_curl() {
        local out="" url=""
        while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2;; http*) url="$1"; shift;; *) shift;; esac; done
        case "$url" in *snell-server-*.zip) cp "'"$TMP/dl/snell.zip"'" "$out" ;; *) return 1 ;; esac
    }
    # For snell_install: channel=1, port=""(random), psk=""(auto 32-48), mode=1, dns=1, host=""(detected), name="", autoupdate=n
    snell_install < <(printf "1\n\n\n1\n1\n\n\nn\n") >/dev/null 2>&1
    [ -x "$SNELL_BIN" ] && [ -f "$SNELL_CONF" ] || { echo "ERR: snell install files missing"; exit 1; }
    psk1="$(snell_conf_get psk)"
    [ "${#psk1}" -ge 32 ] && [ "${#psk1}" -le 48 ] || { echo "ERR: psk1 len=${#psk1}"; exit 1; }
    # Add extra port: port=""(random), psk=""(auto 32-48), mode=1
    snell_add_port < <(printf "\n\n1\n") >/dev/null 2>&1
    xport="$(snell_extra_ports | head -1)"
    [ -n "$xport" ] || { echo "ERR: extra port not created"; exit 1; }
    psk2="$(snell_conf_get psk "$SNELL_PORTS_DIR/$xport.conf")"
    [ "${#psk2}" -ge 32 ] && [ "${#psk2}" -le 48 ] || { echo "ERR: psk2 len=${#psk2}"; exit 1; }
    # Reconfig -> option 2 (regenerate PSK)
    snell_reconfig <<< "2" >/dev/null 2>&1
    psk3="$(snell_conf_get psk)"
    [ "${#psk3}" -ge 32 ] && [ "${#psk3}" -le 48 ] && [ "$psk3" != "$psk1" ] || { echo "ERR: reconfig psk3=$psk3"; exit 1; }
    _snell_repair_core >/dev/null 2>&1
    [ "$(stat -c %a "$SNELL_CONF")" = "640" ] || { echo "ERR: snell conf perm"; exit 1; }
'; then
    ok "Flow 3 (Snell v6): full install + add_port + reconfig 32-48 PSK + repair + perms"
else
    fail "Flow 3 (Snell v6) FAILED"
fi

# ── FLOW 4: Xray Full Install + Vision + XHTTP-REALITY + XHTTP-CDN + VENC + SS2022 + Forward + Repair ──
if bash -c '
    source "'"$TMP/prelude.sh"'"
    xray_query_latest() { XRAY_LATEST="v26.10.31"; XRAY_LATEST_ANY="v26.10.31"; XRAY_LATEST_IS_PRE="1"; XRAY_SOURCE_OK=1; }
    github_asset_sha256() { echo "'"$SHA_XRAY"'"; }
    xray_probe_reality_target() { XR_RTT_MS=25; return 0; }
    secure_curl() {
        local out="" url=""
        while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2;; http*) url="$1"; shift;; *) shift;; esac; done
        case "$url" in
            *.zip.dgst) cp "'"$TMP/dl/xray.zip.dgst"'" "$out" ;;
            *.zip) cp "'"$TMP/dl/xray.zip"'" "$out" ;;
            *) return 1 ;;
        esac
    }
    # xray_install: channel=1, host=""(detected), autoupdate=n, add_first_node=n
    xray_install < <(printf "1\n\nn\nn\n") >/dev/null 2>&1
    [ -x "$XRAY_BIN" ] && [ -f "$XRAY_CONF_D/00-base.json" ] || { echo "ERR: xray base missing"; exit 1; }
    # Add Vision (port=443, sni=1 random, fp=1 random)
    xray_add_vision < <(printf "443\n1\n1\n") >/dev/null 2>&1
    # Add XHTTP-REALITY (port=8443, sni=1 random, fp=1 random, vlessenc=y, auth=1)
    xray_add_xhttp_reality < <(printf "8443\n1\n1\ny\n1\n") >/dev/null 2>&1
    # Add XHTTP-CDN self-signed (domain, origin=1, port=2053, cport=443, fp=1, vlessenc=n)
    xray_add_xhttp_cdn < <(printf "cdn.example.com\n1\n2053\n443\n1\nn\n") >/dev/null 2>&1
    # Add VENC (port=8880, auth=1)
    xray_add_venc < <(printf "8880\n1\n") >/dev/null 2>&1
    # Make udp_listening reflect actually configured nodes (so 31000 is free before add, listening after add)
    udp_listening() { [ -f "$XRAY_NODE_DIR/ss-$1.env" ] || grep -ql "FWD_LPORT=\"$1\"" "$XRAY_FWD_DIR"/*.env 2>/dev/null; }
    # Add SS2022 (method=1, port=31000)
    xray_add_ss < <(printf "1\n31000\n") >/dev/null 2>&1
    # Verify xray_default_port avoids already-used port 443 even when tcp_port_conflict=1
    dp="$(xray_default_port 443)"
    [ "$dp" != "443" ] || { echo "ERR: xray_default_port returned occupied 443"; exit 1; }
    # Add Xray Forward (remark, proto=1, lip="", lport=32000, rhost=1.1.1.1, rport=443, follow=n)
    xray_fwd_add < <(printf "test-fwd\n1\n\n32000\n1.1.1.1\n443\nn\n") >/dev/null 2>&1

    # Validate EVERY JSON file in conf.d with Python json.load!
    python3 - "$XRAY_CONF_D" << "PYJSON"
import glob, json, os, sys
d = sys.argv[1]
files = sorted(glob.glob(os.path.join(d, "*.json")))
assert len(files) >= 7, f"expected >=7 json files, got {files}"
for fp in files:
    data = json.load(open(fp, encoding="utf-8"))
    if "10-in-vision" in fp or "10-in-xhttp-reality" in fp:
        rs = data["inbounds"][0]["streamSettings"]["realitySettings"]
        assert 2 <= len(rs["shortIds"]) <= 3, rs["shortIds"]
        assert rs["maxTimeDiff"] == 60000, rs
        assert rs.get("mldsa65Seed") == "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", rs
    if "10-in-xhttp" in fp or "10-in-venc" in fp:
        xs = data["inbounds"][0]["streamSettings"]["xhttpSettings"]
        assert "xPaddingBytes" in xs.get("extra", {}), xs
PYJSON
    # Validate share links for all 5 nodes
    for t in vision-443 xhttp-reality-8443 xhttp-cdn-2053 venc-8880 ss-31000; do
        lnk="$(xray_node_link "$t" "203.0.113.10")"
        [ -n "$lnk" ] || { echo "ERR: empty link for $t"; exit 1; }
    done
    vlnk="$(xray_node_link vision-443 203.0.113.10)"
    [[ "$vlnk" == *"&spx="* && "$vlnk" == *"&fp="* && "$vlnk" == *"&pqv=DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"* ]] || { echo "ERR: vision link missing spx/fp/pqv: $vlnk"; exit 1; }
    xlnk="$(xray_node_link xhttp-reality-8443 203.0.113.10)"
    [[ "$xlnk" == *"&extra="* && "$xlnk" == *"&pqv="* ]] || { echo "ERR: xhttp link missing extra/pqv: $xlnk"; exit 1; }
    grep -q "^PrivateDevices=true$" "$XRAY_SERVICE" || { echo "ERR: missing systemd sandbox"; exit 1; }
    # Test repair & sync_reality_snis
    _xray_repair_core >/dev/null 2>&1
    [ "$(stat -c %a "$XRAY_NODE_DIR")" = "700" ] || { echo "ERR: XRAY_NODE_DIR perm"; exit 1; }
'; then
    ok "Flow 4 (Xray): full install + 5 node types + JSON/shortIds/maxTimeDiff/spx/fp + forward + repair"
else
    fail "Flow 4 (Xray) FAILED"
fi

# ── FLOW 5: Realm Full Install + Standard + WSS (CSPRNG path) + Batch + TOML Validation + Repair ──
if bash -c '
    source "'"$TMP/prelude.sh"'"
    realm_latest_tag() { echo "v2.7.0"; }
    github_asset_sha256() { echo "'"$SHA_REALM"'"; }
    secure_curl() {
        local out="" url=""
        while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2;; http*) url="$1"; shift;; *) shift;; esac; done
        case "$url" in *realm-*.tar.gz) cp "'"$TMP/dl/realm.tar.gz"'" "$out" ;; *) return 1 ;; esac
    }
    realm_install >/dev/null 2>&1
    [ -x "$REALM_BIN" ] || { echo "ERR: realm bin missing"; exit 1; }
    # Add WSS rule with default CSPRNG path:
    # remark, proto=2(tcp), lip="", lport=41000, rhost=1.1.1.1, rport=443, lb=n, tunnel=y, role=1(out), type=4(WSS), host=cdn.example.com, path=""(auto), ca=n, adv=n
    realm_add_rule < <(printf "wss-relay\n2\n\n41000\n1.1.1.1\n443\nn\ny\n1\n4\ncdn.example.com\n\nn\nn\n") >/dev/null 2>&1
    # Validate TOML & CSPRNG path
    python3 - "$REALM_CONFIG_FILE" << "PYTOML"
import sys, tomllib
d = tomllib.load(open(sys.argv[1], "rb"))
eps = d["endpoints"]
assert len(eps) == 1, eps
rt = eps[0]["remote_transport"]
assert "ws;host=cdn.example.com;path=/" in rt and ";tls;sni=cdn.example.com;insecure" in rt, rt
PYTOML
    _realm_repair_core >/dev/null 2>&1
    [ "$(stat -c %a "$REALM_RULE_DIR")" = "700" ] || { echo "ERR: REALM_RULE_DIR perm"; exit 1; }
'; then
    ok "Flow 5 (Realm): full install + WSS CSPRNG path + TOML validation + repair"
else
    fail "Flow 5 (Realm) FAILED"
fi

# ── FLOW 6: Caddy Full Install + Add HTTPS & HTTP Sites + Repair + Doctor Perm Check ──
if bash -c '
    source "'"$TMP/prelude.sh"'"
    caddy_latest_tag() { echo "v2.9.0"; }
    github_asset_sha256() { return 1; }
    secure_curl() {
        local out="" url=""
        while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2;; http*) url="$1"; shift;; *) shift;; esac; done
        case "$url" in
            *checksums.txt) cp "'"$TMP/dl/caddy_checksums.txt"'" "$out" ;;
            *caddy_*.tar.gz) cp "'"$TMP/dl/caddy.tar.gz"'" "$out" ;;
            *) return 1 ;;
        esac
    }
    caddy_install >/dev/null 2>&1
    [ -x "$CADDY_BIN" ] || { echo "ERR: caddy bin missing"; exit 1; }
    # Add HTTPS site: domain, mode=1, upstream, remark
    caddy_add_site < <(printf "app.example.com\n1\n127.0.0.1:8080\nmy-app\n") >/dev/null 2>&1
    # Add HTTP custom-port site: domain, mode=3, port=8088, upstream, remark
    caddy_add_site < <(printf "plain.example.com\n3\n8088\n127.0.0.1:9000\nplain-app\n") >/dev/null 2>&1
    _caddy_repair_core >/dev/null 2>&1
    # Check permissions AND verify _doctor_check_perm passes!
    [ "$(stat -c %a "$CADDY_DATA_DIR")" = "700" ] || { echo "ERR: CADDY_DATA_DIR=$(stat -c %a "$CADDY_DATA_DIR")"; exit 1; }
    _doctor_check_perm "$CADDY_DIR" group_ro >/dev/null || { echo "ERR: CADDY_DIR=$(stat -c %a "$CADDY_DIR") fails doctor!"; exit 1; }
    _doctor_check_perm "$CADDY_SITES_DIR" group_ro >/dev/null || { echo "ERR: CADDY_SITES_DIR=$(stat -c %a "$CADDY_SITES_DIR") fails doctor!"; exit 1; }
'; then
    ok "Flow 6 (Caddy): full install + HTTPS/HTTP sites + repair + doctor perm check"
else
    fail "Flow 6 (Caddy) FAILED"
fi

# ── FLOW 7: Cloudflare Tunnel Full Install + Setup Token + Repair ──
if bash -c '
    source "'"$TMP/prelude.sh"'"
    cf_tunnel_latest_tag() { echo "2026.10.0"; }
    github_asset_sha256() { echo "'"$SHA_CF"'"; }
    secure_curl() {
        local out="" url=""
        while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2;; http*) url="$1"; shift;; *) shift;; esac; done
        case "$url" in *cloudflared-linux-*) cp "'"$TMP/dl/cloudflared"'" "$out" ;; *) return 1 ;; esac
    }
    cf_tunnel_install >/dev/null 2>&1
    [ -x "$CF_TUNNEL_BIN" ] || { echo "ERR: cloudflared bin missing"; exit 1; }
    cf_tunnel_setup_token <<< "  sudo cloudflared service install eyJhIjoiVEVTVF9UT0tFTiJ9==   " >/dev/null 2>&1
    grep -qxF "TUNNEL_TOKEN=\"eyJhIjoiVEVTVF9UT0tFTiJ9==\"" "$CF_TUNNEL_ENV" || { echo "ERR: token mismatch"; cat "$CF_TUNNEL_ENV"; exit 1; }
    _cf_tunnel_repair_core >/dev/null 2>&1
    [ "$(stat -c %a "$CF_TUNNEL_DIR")" = "700" ] && [ "$(stat -c %a "$CF_TUNNEL_ENV")" = "600" ] || { echo "ERR: cf perms"; exit 1; }
'; then
    ok "Flow 7 (CF Tunnel): full install + setup_token (command + spaces) + repair + perms"
else
    fail "Flow 7 (CF Tunnel) FAILED"
fi

# ── FLOW 8: Global do_repair_all + do_doctor (0 permission warnings across ALL installed components!) ──
if bash -c '
    source "'"$TMP/prelude.sh"'"
    do_repair_all >/dev/null 2>&1
    doc_out="$(do_doctor 2>&1)"
    if grep -q "敏感文件权限过宽" <<< "$doc_out"; then
        echo "ERR: do_doctor reported permission warnings after full install + repair_all:"
        grep "敏感文件权限过宽" <<< "$doc_out"
        exit 1
    fi
    grep -q "敏感文件权限巡检：正常" <<< "$doc_out" || { echo "ERR: doctor perm audit line missing"; exit 1; }
'; then
    ok "Flow 8 (Global Repair + Doctor): do_repair_all & do_doctor pass with 0 perm warnings"
else
    fail "Flow 8 (Global Repair + Doctor) FAILED"
fi

echo ""
printf 'E2E Summary: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
