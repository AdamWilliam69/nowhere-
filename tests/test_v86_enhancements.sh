#!/usr/bin/env bash
# Comprehensive tests for all v8.6 repository enhancements
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${REPO_ROOT}/nowhere-install.sh"
SHA_FILE="${REPO_ROOT}/nowhere-install.sh.sha256"
TMP="$(mktemp -d /tmp/test-v86-enh.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

awk '/^\[ "\$EUID" -ne 0 \]/ { next } /^case "\$ACTION" in/ { exit } { print }' "$SCRIPT" > "$TMP/lib.sh"

PASS=0; FAIL=0
ok()   { PASS=$((PASS + 1)); printf '  [PASS] %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  [FAIL] %s\n' "$1"; }

echo "=== v8.6 Enhancement Test Suite ==="

# 1. Script self-update SHA-256 verification (matching hash passes; tampered script rejected; strict mode rejects missing .sha256)
mkdir -p "$TMP/e1"
cat > "$TMP/e1/remote.sh" << 'EOF'
#!/bin/bash
# Adam Nowhere test
SCRIPT_VERSION="8.7"
case "$ACTION" in
    *) : ;;
esac
EOF
GOOD_SHA="$(sha256sum "$TMP/e1/remote.sh" | awk '{print $1}')"
BAD_SHA="0000000000000000000000000000000000000000000000000000000000000000"
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    SCRIPT_URL="https://example.com/nowhere-install.sh"
    SCRIPT_SHA256_URL="https://example.com/nowhere-install.sh.sha256"
    # Case A: valid SHA256 passes
    secure_curl() {
        local out="" url=""
        while [ $# -gt 0 ]; do
            case "$1" in -o) out="$2"; shift 2 ;; http*) url="$1"; shift ;; *) shift ;; esac
        done
        case "$url" in
            *.sha256*) printf "%s  nowhere-install.sh\n" "'"$GOOD_SHA"'" ;;
            *) cp "'"$TMP/e1/remote.sh"'" "$out" ;;
        esac
    }
    script_fetch_remote "'"$TMP/e1/dst_ok.sh"'"
    [ "$REMOTE_SCRIPT_VERSION" = "8.7" ]
    # Case B: tampered SHA256 rejected
    secure_curl() {
        local out="" url=""
        while [ $# -gt 0 ]; do
            case "$1" in -o) out="$2"; shift 2 ;; http*) url="$1"; shift ;; *) shift ;; esac
        done
        case "$url" in
            *.sha256*) printf "%s  nowhere-install.sh\n" "'"$BAD_SHA"'" ;;
            *) cp "'"$TMP/e1/remote.sh"'" "$out" ;;
        esac
    }
    ! script_fetch_remote "'"$TMP/e1/dst_bad.sh"'" >/dev/null 2>&1
    # Case C: strict mode rejects missing .sha256
    MAINT_SCRIPT_STRICT_SHA=1
    secure_curl() {
        local out="" url=""
        while [ $# -gt 0 ]; do
            case "$1" in -o) out="$2"; shift 2 ;; http*) url="$1"; shift ;; *) shift ;; esac
        done
        case "$url" in
            *.sha256*) return 22 ;;
            *) cp "'"$TMP/e1/remote.sh"'" "$out" ;;
        esac
    }
    ! script_fetch_remote "'"$TMP/e1/dst_strict.sh"'" >/dev/null 2>&1
    # Case D: repo root .sha256 matches built nowhere-install.sh
    ( cd "'"$REPO_ROOT"'" && sha256sum -c --status "'"$SHA_FILE"'" )
'; then ok "ENH-01: script_fetch_remote enforces .sha256 (accepts valid, rejects tamper & strict-missing)"; else fail "ENH-01"; fi

# 2. systemd sandbox hardening in write_service_unit
mkdir -p "$TMP/e2"
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    write_service_unit "'"$TMP/e2/test.service"'" "Test Svc" "" "60" "nobody" "nogroup" "/bin/true" "CAP_NET_BIND_SERVICE" "65536" "always" "3" "ProtectSystem=full"
    for d in NoNewPrivileges=true PrivateDevices=true ProtectKernelTunables=true ProtectKernelModules=true ProtectControlGroups=true RestrictNamespaces=true LockPersonality=true RestrictSUIDSGID=true; do
        grep -q "^${d}$" "'"$TMP/e2/test.service"'"
    done
'; then ok "ENH-02: write_service_unit emits all 8 systemd sandbox hardening directives"; else fail "ENH-02"; fi

# 3. Encrypted backup/restore (AES-256-CBC PBKDF2 600k iter via fd:3) + wrong passphrase rejection
mkdir -p "$TMP/e3/src/etc/adam" "$TMP/e3/baks"
echo 'MAINT_WATCHDOG="1"' > "$TMP/e3/src/etc/adam/maintain.env"
tar -czf "$TMP/e3/plain.tgz" -C "$TMP/e3/src" etc/adam
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    _backup_encrypt_file "'"$TMP/e3/plain.tgz"'" "'"$TMP/e3/baks/test.tgz.enc"'" "SuperSecretPass99!"
    [ "$(head -c 8 "'"$TMP/e3/baks/test.tgz.enc"'")" = "Salted__" ]
    # Wrong passphrase fails
    ! _backup_decrypt_file "'"$TMP/e3/baks/test.tgz.enc"'" "'"$TMP/e3/wrong.tgz"'" "WrongPass!"
    # Right passphrase decrypts cleanly and passes do_restore validation
    _backup_decrypt_file "'"$TMP/e3/baks/test.tgz.enc"'" "'"$TMP/e3/dec.tgz"'" "SuperSecretPass99!"
    cmp -s "'"$TMP/e3/plain.tgz"'" "'"$TMP/e3/dec.tgz"'"
    # do_restore auto-detects .tgz.enc via ADAM_BACKUP_PASSPHRASE and passes all validation up to confirm
    current_role() { echo none; }
    confirm() { return 1; }
    ADAM_BACKUP_PASSPHRASE="SuperSecretPass99!" do_restore "'"$TMP/e3/baks/test.tgz.enc"'" >/dev/null 2>&1
    ! ( ADAM_BACKUP_PASSPHRASE="WrongPass!" do_restore "'"$TMP/e3/baks/test.tgz.enc"'" >/dev/null 2>&1 )
'; then ok "ENH-03: AES-256-CBC PBKDF2 backup/restore roundtrip & wrong-passphrase rejection"; else fail "ENH-03"; fi

# 4. GITHUB_TOKEN strictly scoped to https://api.github.com/* via -K (never leaked to other URLs or cmdline)
mkdir -p "$TMP/e4"
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    GITHUB_TOKEN="ghp_testTokenSecret1234567890"
    curl() {
        local saw_k=0 kcontent="" a
        local -a args=("$@")
        for ((i=0; i<${#args[@]}; i++)); do
            a="${args[$i]}"
            # Token must NEVER appear directly on cmdline
            [[ "$a" != *"ghp_testTokenSecret"* ]] || { echo "LEAKED_CMDLINE"; return 1; }
            if [ "$a" = "-K" ]; then
                saw_k=1
                kcontent="$(cat "${args[$((i+1))]}")"
            fi
        done
        printf "K=%d|%s\n" "$saw_k" "$kcontent"
    }
    out_gh="$(secure_curl -fsS https://api.github.com/repos/XTLS/Xray-core/releases/latest)"
    [[ "$out_gh" == "K=1|header = \"Authorization: Bearer ghp_testTokenSecret1234567890\"" ]]
    out_other="$(secure_curl -fsS https://dl.nssurge.com/snell/snell-server.zip)"
    [ "$out_other" = "K=0|" ]
    out_raw="$(secure_curl -fsS https://raw.githubusercontent.com/org/repo/main/a.sh)"
    [ "$out_raw" = "K=0|" ]
    out_mixed="$(secure_curl -fsS https://api.github.com/x https://evil.example.com/steal)"
    [ "$out_mixed" = "K=0|" ]
'; then ok "ENH-04: GITHUB_TOKEN injected via -K strictly for api.github.com only (0 cmdline or cross-host leak)"; else fail "ENH-04"; fi

# 5. NTP sync check (check_ntp_sync synced / unsynced / unknown)
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    timedatectl() { echo "yes"; }
    check_ntp_sync
    timedatectl() { echo "no"; }
    rc=0; check_ntp_sync || rc=$?; [ "$rc" -eq 1 ]
'; then ok "ENH-05: check_ntp_sync accurately reports synced (0) and unsynced (1)"; else fail "ENH-05"; fi

# 6. Alert notifications (Telegram / Bark / Webhook) via secure_curl -K
mkdir -p "$TMP/e6"
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    NOTIFY_ENV="'"$TMP/e6/notify.env"'"; MAINT_DIR="'"$TMP/e6"'"
    NOTIFY_ENABLED="1"; NOTIFY_TYPE="telegram"; NOTIFY_TG_TOKEN="123456:ABC_def-123"; NOTIFY_TG_CHAT_ID="-100998877"
    notify_save
    [ "$(stat -c %a "$NOTIFY_ENV")" = "600" ]
    env_file_safe "$NOTIFY_ENV"
    secure_curl() {
        local payload="" kurl="" i
        local -a a=("$@")
        for ((i=0; i<${#a[@]}; i++)); do
            [[ "${a[$i]}" != *"123456:ABC_def-123"* ]] || return 1
            [ "${a[$i]}" = "-d" ] && payload="${a[$((i+1))]}"
            [ "${a[$i]}" = "-K" ] && kurl="$(cat "${a[$((i+1))]}")"
        done
        printf "%s\n%s\n" "$kurl" "$payload" > "'"$TMP/e6/tg_capture.txt"'"
    }
    notify_send "Alert Title" "Body with \"quotes\""
    grep -q "https://api.telegram.org/bot123456:ABC_def-123/sendMessage" "'"$TMP/e6/tg_capture.txt"'"
    python3 - "'"$TMP/e6/tg_capture.txt"'" << "PY"
import json, sys
lines = open(sys.argv[1], encoding="utf-8").read().splitlines()
d = json.loads(lines[1])
assert d["chat_id"] == "-100998877" and "Alert Title" in d["text"] and "quotes" in d["text"], d
PY
    # Bark
    NOTIFY_TYPE="bark"; NOTIFY_BARK_URL="https://api.day.app/MySecretKey/"
    notify_save
    notify_send "Bark Title" "Bark Body"
    grep -q "https://api.day.app/MySecretKey" "'"$TMP/e6/tg_capture.txt"'"
    # Webhook rejects non-HTTPS
    NOTIFY_TYPE="webhook"; NOTIFY_WEBHOOK_URL="http://insecure.example.com/hook"
    notify_save
    ! notify_send "Bad" "HTTP"
'; then ok "ENH-06: notify_send supports Telegram/Bark/Webhook via -K (0 token in cmdline, HTTPS-only, valid JSON)"; else fail "ENH-06"; fi

# 7. Xray ML-DSA-65 PQ signature, XHTTP xPaddingBytes & link formatting (&pqv= &extra=)
mkdir -p "$TMP/e7/nodes" "$TMP/e7/conf.d"
cat > "$TMP/e7/fake-xray" << 'EOF'
#!/usr/bin/env bash
if [ "${1:-}" = "mldsa65" ]; then
    echo "Seed: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    echo "Verify: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    exit 0
fi
exit 1
EOF
chmod +x "$TMP/e7/fake-xray"
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    XRAY_BIN="'"$TMP/e7/fake-xray"'"; XRAY_NODE_DIR="'"$TMP/e7/nodes"'"
    xray_gen_mldsa65
    [ "$XM_SEED" = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ]
    [ "$XM_VERIFY" = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" ]
    cat > "'"$TMP/e7/nodes/xhttp-reality-8443.env"'" << EEOF
N_TAG="xhttp-reality-8443"
N_TYPE="xhttp-reality"
N_PORT="8443"
N_UUID="11111111-2222-4333-8444-555555555555"
N_SNI="www.nvidia.com"
N_PBK="PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP"
N_SID="a1b2c3d4"
N_SIDS="a1b2c3d4,112233445566"
N_SPX="/v2/query/abc12345"
N_FP="firefox"
N_PQV="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
N_PATH="/api/telemetry/xyz98765"
N_XPAD="180-950"
N_ENC="none"
N_NAME="TestXHTTP"
EEOF
    link="$(xray_node_link xhttp-reality-8443 1.2.3.4)"
    [[ "$link" == *"&pqv=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"* ]]
    [[ "$link" == *"&extra=%7B%22xPaddingBytes%22%3A%22180-950%22%7D"* ]]
    [[ "$link" == *"&spx=%2Fv2%2Fquery%2Fabc12345"* ]]
    # Older Xray without mldsa65 gracefully returns 1
    XRAY_BIN="/bin/false"
    ! xray_gen_mldsa65
'; then ok "ENH-07: xray_gen_mldsa65 + XHTTP xPaddingBytes emit valid &pqv= and &extra= links (graceful fallback)"; else fail "ENH-07"; fi

# 8. REALITY SNI RTT speed ranking picks lowest-latency verified target
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    XRAY_SNI_POOL="slow.example.com fast.example.com mid.example.com bad.example.com slow2.example.com"
    xray_probe_reality_target() {
        case "$1" in
            slow.example.com)  XR_RTT_MS=180; return 0 ;;
            fast.example.com)  XR_RTT_MS=19;  return 0 ;;
            mid.example.com)   XR_RTT_MS=75;  return 0 ;;
            slow2.example.com) XR_RTT_MS=210; return 0 ;;
            *) XR_RTT_MS=99999; return 1 ;;
        esac
    }
    xray_ask_sni <<< "1" >/dev/null
    [ "$XR_SNI" = "fast.example.com" ]
'; then ok "ENH-08: xray_ask_sni ranks candidate RTT and picks lowest-latency target (19ms)"; else fail "ENH-08"; fi

# 9. xray_edit_node hot-rotates SNI, shortIds+spiderX, fp, port, and XHTTP path+xPaddingBytes atomically
mkdir -p "$TMP/e9/conf.d" "$TMP/e9/nodes"
cat > "$TMP/e9/conf.d/10-in-xhttp-reality-8443.json" << 'EOF'
{
  "inbounds": [
    {
      "tag": "xhttp-reality-8443",
      "listen": "0.0.0.0",
      "port": 8443,
      "protocol": "vless",
      "settings": { "clients": [{ "id": "11111111-2222-4333-8444-555555555555" }], "decryption": "none" },
      "streamSettings": {
        "network": "xhttp",
        "security": "reality",
        "xhttpSettings": { "path": "/v1/old/aaa11111", "mode": "auto", "extra": { "xPaddingBytes": "100-500" } },
        "realitySettings": { "show": false, "target": "www.old.com:443", "xver": 0, "serverNames": ["www.old.com"], "privateKey": "K", "shortIds": ["11223344", "55667788"], "maxTimeDiff": 60000 }
      }
    }
  ]
}
EOF
cp "$TMP/e7/nodes/xhttp-reality-8443.env" "$TMP/e9/nodes/xhttp-reality-8443.env"
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    XRAY_BIN="'"$TMP/e7/fake-xray"'"; XRAY_CONF_D="'"$TMP/e9/conf.d"'"; XRAY_NODE_DIR="'"$TMP/e9/nodes"'"; XRAY_STATE_FILE="'"$TMP/e9/state.env"'"; XRAY_PUBLIC_HOST="1.2.3.4"
    xray_require() { return 0; }; xray_reload() { return 0; }; xray_fix_perms() { return 0; }
    xray_host_domain() { return 1; }; ufw_active() { return 1; }; reserved_ports_sync() { return 0; }
    tcp_port_conflict() { return 1; }; port_used_by_other_services() { return 1; }; xray_port_used() { return 1; }
    xray_probe_reality_target() { XR_RTT_MS=25; return 0; }
    # 1) Change SNI (option 1 -> custom option 3 -> www.oracle.com)
    printf "1\n3\nwww.oracle.com\n" | xray_edit_node xhttp-reality-8443 >/dev/null
    grep -q "\"www.oracle.com:443\"" "'"$TMP/e9/conf.d/10-in-xhttp-reality-8443.json"'"
    # 2) Rotate shortIds + spiderX (option 2)
    old_sid="$(awk -F= "/^N_SID=/{print \$2}" "'"$TMP/e9/nodes/xhttp-reality-8443.env"'")"
    printf "2\n" | xray_edit_node xhttp-reality-8443 >/dev/null
    new_sid="$(awk -F= "/^N_SID=/{print \$2}" "'"$TMP/e9/nodes/xhttp-reality-8443.env"'")"
    [ "$old_sid" != "$new_sid" ]
    # 3) Change fp (option 3 -> choice 3 = firefox)
    printf "3\n3\n" | xray_edit_node xhttp-reality-8443 >/dev/null
    grep -q "N_FP=\"firefox\"" "'"$TMP/e9/nodes/xhttp-reality-8443.env"'"
    # 4) Change port (option 4 -> 29443)
    printf "4\n29443\n" | xray_edit_node xhttp-reality-8443 >/dev/null
    grep -q "\"port\": 29443" "'"$TMP/e9/conf.d/10-in-xhttp-reality-8443.json"'"
    grep -q "N_PORT=\"29443\"" "'"$TMP/e9/nodes/xhttp-reality-8443.env"'"
    # 5) Rotate XHTTP path + xPaddingBytes (option 5)
    printf "5\n" | xray_edit_node xhttp-reality-8443 >/dev/null
    ! grep -q "/v1/old/aaa11111" "'"$TMP/e9/conf.d/10-in-xhttp-reality-8443.json"'"
    # 6) Enable / rotate REALITY ML-DSA-65 PQ signature (option 6)
    printf "6\n" | xray_edit_node xhttp-reality-8443 >/dev/null
    grep -q "\"mldsa65Seed\": \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"" "'"$TMP/e9/conf.d/10-in-xhttp-reality-8443.json"'"
    grep -q "N_PQV=\"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\"" "'"$TMP/e9/nodes/xhttp-reality-8443.env"'"
    # 7) Automatic rollback when xray_reload fails!
    xray_reload() { return 1; }
    ! printf "4\n29999\n" | xray_edit_node xhttp-reality-8443 >/dev/null 2>&1
    grep -q "\"port\": 29443" "'"$TMP/e9/conf.d/10-in-xhttp-reality-8443.json"'"
    grep -q "N_PORT=\"29443\"" "'"$TMP/e9/nodes/xhttp-reality-8443.env"'"
'; then ok "ENH-09: xray_edit_node hot-rotates SNI/shortIds/fp/port/XHTTP/ML-DSA-65 + atomic rollback"; else fail "ENH-09"; fi

# 10. do_doctor --json emits valid JSON schema
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    BIN_PATH="/nonexistent"; SNELL_BIN="/nonexistent"; XRAY_BIN="/nonexistent"; REALM_BIN="/nonexistent"; CADDY_BIN="/nonexistent"; CF_TUNNEL_BIN="/nonexistent"
    CONFIG_DIR="'"$TMP/e10/nw"'"; SNELL_DIR="'"$TMP/e10/sn"'"; XRAY_CONF_DIR="'"$TMP/e10/xr"'"; XRAY_NODE_DIR="'"$TMP/e10/xr/nodes"'"
    XRAY_FWD_DIR="'"$TMP/e10/xr/fwd"'"; XRAY_CONF_D="'"$TMP/e10/xr/conf.d"'"; XRAY_CERT_DIR="'"$TMP/e10/xr/certs"'"
    REALM_DIR="'"$TMP/e10/rm"'"; REALM_CONF_D="'"$TMP/e10/rm/conf.d"'"; REALM_RULE_DIR="'"$TMP/e10/rm/rules"'"
    CADDY_DIR="'"$TMP/e10/cd"'"; CADDY_SITES_DIR="'"$TMP/e10/cd/sites"'"; CADDY_DATA_DIR="'"$TMP/e10/cd_data"'"
    CF_TUNNEL_DIR="'"$TMP/e10/cf"'"; CF_TUNNEL_ENV="'"$TMP/e10/cf/t.env"'"; MAINT_ENV="'"$TMP/e10/m.env"'"; NOTIFY_ENV="'"$TMP/e10/n.env"'"
    CONFIG_FILE="'"$TMP/e10/nw/nw.env"'"; EGRESS_CONFIG_FILE="'"$TMP/e10/nw/eg.env"'"; TLS_PIN_FILE="'"$TMP/e10/nw/pin"'"
    SNELL_STATE_FILE="'"$TMP/e10/sn/st"'"; SNELL_CONF="'"$TMP/e10/sn/c"'"; SNELL_PORTS_DIR="'"$TMP/e10/sn/p"'"; XRAY_STATE_FILE="'"$TMP/e10/xr/st"'"
    ROLE_FILE="'"$TMP/e10/nw/role"'"
    timedatectl() { echo "yes"; }
    systemctl() { return 1; }
    out="$(do_doctor --json)"
    printf "%s" "$out" | python3 -c "import json,sys; d=json.load(sys.stdin); assert d[\"script_version\"]==sys.argv[1] and d[\"ntp_sync\"]==\"synced\" and isinstance(d[\"perm_issues\"], list) and \"xray\" in d[\"services\"]" "$SCRIPT_VERSION"
'; then ok "ENH-10: do_doctor --json emits valid structured JSON"; else fail "ENH-10"; fi

# 11. do_export_clients (Mihomo / sing-box / Surge) + Mihomo REALITY fp=chrome normalization
mkdir -p "$TMP/e11/nodes" "$TMP/e11/snell/ports"
cat > "$TMP/e11/nodes/vision-443.env" << 'EOF'
N_TAG="vision-443"
N_TYPE="vision"
N_PORT="443"
N_UUID="11111111-2222-4333-8444-555555555555"
N_SNI="www.nvidia.com"
N_PBK="PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP"
N_SID="a1b2c3d4"
N_FP="randomized"
N_NAME="VisionNode"
EOF
cat > "$TMP/e11/nodes/ss-31000.env" << 'EOF'
N_TAG="ss-31000"
N_TYPE="ss2022"
N_PORT="31000"
N_METHOD="2022-blake3-aes-128-gcm"
N_PASS="AAAAAAAAAAAAAAAAAAAAAA=="
N_NAME="SSNode"
EOF
printf '[snell-server]\nlisten = 0.0.0.0:25000\npsk = TestSnellPsk1234567890123456789012\nipv6 = false\n' > "$TMP/e11/snell/snell-server.conf"
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    XRAY_BIN="/bin/true"; XRAY_NODE_DIR="'"$TMP/e11/nodes"'"; XRAY_STATE_FILE="'"$TMP/e11/xstate"'"
    XRAY_PUBLIC_HOST="203.0.113.10"
    SNELL_CONF="'"$TMP/e11/snell/snell-server.conf"'"; SNELL_PORTS_DIR="'"$TMP/e11/snell/ports"'"
    detect_public_host() { echo "203.0.113.10"; }
    m="$(do_export_clients mihomo)"
    [[ "$m" == *"client-fingerprint: chrome"* ]]
    [[ "$m" == *"normalized client-fingerprint from randomized -> chrome"* ]]
    [[ "$m" == *"type: snell"* ]]
    [[ "$m" == *"type: ss"* ]]
    sb="$(do_export_clients singbox)"
    printf "%s" "$sb" | python3 -c "import json,sys; d=json.load(sys.stdin); assert len(d[\"outbounds\"])==2"
    sg="$(do_export_clients surge)"
    [[ "$sg" == *"[Proxy]"* ]] && [[ "$sg" == *"snell"* ]] && [[ "$sg" == *"encrypt-method=2022-blake3-aes-128-gcm"* ]]
'; then ok "ENH-11: do_export_clients generates valid Mihomo YAML (w/ fp guard), sing-box JSON, and Surge config"; else fail "ENH-11"; fi

# 12. ADAM_ASSUME_YES=1 & cross-distro _pkg_map_name
if bash -c '
    set -euo pipefail; source "'"$TMP/lib.sh"'"
    ADAM_ASSUME_YES=1 confirm "Proceed?" n
    [ "$(_pkg_map_name dnf iproute2)" = "iproute" ]
    [ "$(_pkg_map_name yum gnupg)" = "gnupg2" ]
    [ "$(_pkg_map_name apk qrencode)" = "libqrencode-tools" ]
    [ "$(_pkg_map_name apt iproute2)" = "iproute2" ]
'; then ok "ENH-12: ADAM_ASSUME_YES=1 non-interactive confirm & cross-distro package mapping"; else fail "ENH-12"; fi

echo ""
printf 'Enhancements Summary: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
