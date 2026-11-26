# ══════════════════════════════════════════════════════════════
#   v8.6 核心安全下载、CSPRNG 随机引擎、ELF/SHA256 校验与预检
# ══════════════════════════════════════════════════════════════

# 读取只读 GITHUB_TOKEN（优先环境变量，其次 MAINT_ENV，防 API 60次/h 匿名限流）
_resolve_github_token() {
    local tok="${GITHUB_TOKEN:-}"
    if [ -z "$tok" ] && [ -f "${MAINT_ENV:-}" ] && [ ! -L "${MAINT_ENV:-}" ] && [ -r "${MAINT_ENV:-}" ]; then
        tok="$(awk -F= '/^GITHUB_TOKEN="[^"]*"$/ { v=$2; gsub(/^"|"$/, "", v); print v; exit }' "$MAINT_ENV" 2>/dev/null || true)"
    fi
    if [[ "$tok" =~ ^[A-Za-z0-9_.-]{10,256}$ ]]; then
        printf '%s' "$tok"
    fi
}

# 强制 HTTPS 且 TLS ≥ 1.2（含重定向也不允许降级到 HTTP）
# 当且仅当本次请求全部 URL 均为 https://api.github.com/* 且配置了 GITHUB_TOKEN 时，通过 -K 私有 fd 注入认证头（不暴露于 ps 命令行，且绝不泄露给其他域名）
secure_curl() {
    local tok="" arg has_gh_api=0 has_other_url=0
    for arg in "$@"; do
        case "$arg" in
            https://api.github.com/*) has_gh_api=1 ;;
            http://*|https://*)       has_other_url=1 ;;
        esac
    done
    if [ "$has_gh_api" = "1" ] && [ "$has_other_url" = "0" ]; then
        tok="$(_resolve_github_token)"
    fi
    if [ -n "$tok" ]; then
        curl --proto '=https' --tlsv1.2 -K <(printf 'header = "Authorization: Bearer %s"\n' "$tok") "$@"
    else
        curl --proto '=https' --tlsv1.2 "$@"
    fi
}

# csprng_hex NBYTES：输出 2*NBYTES 位小写十六进制随机串（无 pipefail SIGPIPE 风险）
csprng_hex() {
    local n="${1:-16}" out=""
    [[ "$n" =~ ^[1-9][0-9]*$ ]] || return 1
    if command -v openssl >/dev/null 2>&1; then
        out="$(openssl rand -hex "$n" 2>/dev/null | tr -d ' \r\n' || true)"
    fi
    if [ "${#out}" -ne $((n * 2)) ] && command -v python3 >/dev/null 2>&1; then
        out="$(python3 -c 'import secrets,sys; print(secrets.token_hex(int(sys.argv[1])))' "$n" 2>/dev/null | tr -d ' \r\n' || true)"
    fi
    if [ "${#out}" -ne $((n * 2)) ] && [ -r /dev/urandom ]; then
        out="$(od -An -tx1 -N "$n" /dev/urandom 2>/dev/null | tr -d ' \t\r\n' || true)"
    fi
    [[ "$out" =~ ^[0-9a-f]+$ ]] && [ "${#out}" -eq $((n * 2)) ] || return 1
    printf '%s' "$out"
}

# csprng_base64 NBYTES：输出 NBYTES 字节 CSPRNG 的标准 Base64（无换行）
csprng_base64() {
    local n="${1:-32}" out=""
    [[ "$n" =~ ^[1-9][0-9]*$ ]] || return 1
    if command -v openssl >/dev/null 2>&1; then
        out="$(openssl rand -base64 "$n" 2>/dev/null | tr -d ' \r\n' || true)"
    fi
    if [ -z "$out" ] && command -v python3 >/dev/null 2>&1; then
        out="$(python3 -c 'import base64,os,sys; print(base64.b64encode(os.urandom(int(sys.argv[1]))).decode())' "$n" 2>/dev/null | tr -d ' \r\n' || true)"
    fi
    if [ -z "$out" ] && [ -r /dev/urandom ]; then
        out="$(dd if=/dev/urandom bs="$n" count=1 status=none 2>/dev/null | base64 2>/dev/null | tr -d ' \r\n' || true)"
    fi
    [ -n "$out" ] || return 1
    printf '%s' "$out"
}

# csprng_int MIN MAX：闭区间 [MIN, MAX] 无偏均匀随机整数（拒绝采样，彻底替代 $RANDOM）
csprng_int() {
    local min="$1" max="$2" range limit h val tries=0
    [[ "$min" =~ ^-?[0-9]+$ && "$max" =~ ^-?[0-9]+$ ]] && [ "$min" -le "$max" ] || return 1
    if [ "$min" -eq "$max" ]; then printf '%s' "$min"; return 0; fi
    range=$((max - min + 1))
    # 使用 31 位无符号空间（2147483648）做拒绝采样，避免取模偏差并兼容 32/64 位整数运算
    limit=$((2147483648 - (2147483648 % range)))
    while [ "$tries" -lt 64 ]; do
        tries=$((tries + 1))
        h="$(csprng_hex 4)" || return 1
        val=$(( 16#${h} & 0x7fffffff ))
        if [ "$val" -lt "$limit" ]; then
            printf '%s' "$((min + (val % range)))"
            return 0
        fi
    done
    return 1
}

# csprng_alnum LEN [CHARSET]：CSPRNG 随机字符串（无 tr|head SIGPIPE；支持 A-Za-z0-9 / A-Za-z0-9_- / a-z0-9 或字面字符表）
csprng_alnum() {
    local len="${1:-32}" spec="${2:-A-Za-z0-9}" chars="" out="" chunk need
    [[ "$len" =~ ^[1-9][0-9]*$ ]] || return 1
    case "$spec" in
        A-Za-z0-9)   chars='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' ;;
        A-Za-z0-9_-) chars='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-' ;;
        a-z0-9)      chars='abcdefghijklmnopqrstuvwxyz0123456789' ;;
        *)           chars="$spec" ;;
    esac
    [ "${#chars}" -ge 2 ] || return 1
    if command -v python3 >/dev/null 2>&1; then
        out="$(python3 -c 'import secrets,sys; n=int(sys.argv[1]); c=sys.argv[2]; print("".join(secrets.choice(c) for _ in range(n)))' "$len" "$chars" 2>/dev/null || true)"
        if [ "${#out}" -eq "$len" ]; then printf '%s' "$out"; return 0; fi
    fi
    # 无 python3 时用固定字节块读取 + awk 拒绝采样（零管道截断、零 SIGPIPE）
    local tries=0
    while [ "${#out}" -lt "$len" ] && [ "$tries" -lt 16 ]; do
        tries=$((tries + 1))
        need=$(( (len - ${#out}) * 3 + 16 ))
        chunk="$(od -An -tu1 -N "$need" /dev/urandom 2>/dev/null | awk -v cs="$chars" -v want="$((len - ${#out}))" '
            BEGIN { clen = length(cs); lim = 256 - (256 % clen); got = 0; res = "" }
            {
                for (i = 1; i <= NF && got < want; i++) {
                    b = $i + 0
                    if (b < lim) {
                        res = res substr(cs, (b % clen) + 1, 1)
                        got++
                    }
                }
            }
            END { printf "%s", res }' || true)"
        out="${out}${chunk}"
    done
    [ "${#out}" -ge "$len" ] || return 1
    printf '%s' "${out:0:$len}"
}

# csprng_short_id [BYTES]：生成 REALITY 变长偶数位 shortId（默认随机 4–8 字节即 8–16 位 hex）
# shellcheck disable=SC2120
csprng_short_id() {
    local bytes="${1:-}"
    if [ -z "$bytes" ]; then
        bytes="$(csprng_int 4 8)" || return 1
    fi
    [[ "$bytes" =~ ^[1-8]$ ]] || return 1
    csprng_hex "$bytes"
}

# csprng_url_path：生成拟真多段无扩展名 API 路径（如 /v2/telemetry/k8m3p9x2a1），避免 Cloudflare 缓存静态扩展名
csprng_url_path() {
    local -a seg1=(api v1 v2 v3 app edge gateway service stream sync)
    local -a seg2=(events query telemetry metrics session profile config feed status update health)
    local i1 i2 tlen tok
    i1="$(csprng_int 0 $((${#seg1[@]} - 1)))" || return 1
    i2="$(csprng_int 0 $((${#seg2[@]} - 1)))" || return 1
    tlen="$(csprng_int 8 12)" || return 1
    tok="$(csprng_alnum "$tlen" 'a-z0-9')" || return 1
    printf '/%s/%s/%s' "${seg1[$i1]}" "${seg2[$i2]}" "$tok"
}

# verify_elf_binary PATH：校验目标为非符号链接常规文件、ELF 魔数正确且 e_machine 与本机架构匹配
verify_elf_binary() {
    local f="$1" hdr want_em
    [ -f "$f" ] && [ ! -L "$f" ] && [ -s "$f" ] || return 1
    hdr="$(od -An -tx1 -N 20 "$f" 2>/dev/null | tr -s ' \t\r\n' ' ' | sed 's/^ //; s/ $//' || true)"
    # 前 4 字节必须是 7f 45 4c 46（\x7fELF）
    case "$hdr" in
        "7f 45 4c 46 "*) ;;
        *) return 1 ;;
    esac
    case "$(uname -m)" in
        x86_64|amd64)   want_em="3e 00" ;;
        aarch64|arm64)  want_em="b7 00" ;;
        armv7l|armv6l)  want_em="28 00" ;;
        i386|i686)      want_em="03 00" ;;
        riscv64)        want_em="f3 00" ;;
        *)              return 0 ;;
    esac
    # 偏移 18..19（1-indexed 字段 19..20）为小端 ELF e_machine
    local em
    em="$(printf '%s\n' "$hdr" | awk '{print $19, $20}')"
    [ "$em" = "$want_em" ]
}

# github_asset_sha256 REPO TAG ASSET：提取 GitHub Release 官方资产 SHA256（64 位小写 hex）
# 1) GitHub API releases/tags（Python 优先，无 Python 用纯 awk 状态机解析）
# 2) API 被限流时自动回退抓取 github.com/.../releases/expanded_assets/<tag> 页面
github_asset_sha256() {
    local repo="$1" tag="$2" asset="$3" json="" html="" digest=""
    json="$(secure_curl -fsS --max-time 20 "https://api.github.com/repos/${repo}/releases/tags/${tag}" 2>/dev/null || true)"
    if [ -n "$json" ] && command -v python3 >/dev/null 2>&1; then
        digest="$(printf '%s' "$json" | _GH_ASSET="$asset" python3 -c 'import json,os,sys
try: data = json.load(sys.stdin)
except Exception: sys.exit(0)
want = os.environ.get("_GH_ASSET", "")
for a in data.get("assets", []):
    if isinstance(a, dict) and a.get("name") == want:
        d = (a.get("digest") or "").strip().lower()
        if d.startswith("sha256:"): d = d[7:]
        if len(d) == 64: print(d)
        break' 2>/dev/null || true)"
    fi
    if [ -z "$digest" ] && [ -n "$json" ]; then
        # 纯 awk 兜底：兼容多行与压缩 JSON，精确匹配资产对象内的 name 与 digest
        digest="$(printf '%s\n' "$json" | awk -v want="$asset" '
            BEGIN { RS="\\{"; FS="\"" }
            {
                nm=""; dg=""
                for (i = 2; i <= NF; i += 2) {
                    if ($i == "name" && $(i+1) ~ /^[[:space:]]*:[[:space:]]*$/ && nm == "") nm = $(i+2)
                    if ($i == "digest" && $(i+1) ~ /^[[:space:]]*:[[:space:]]*$/ && dg == "") dg = $(i+2)
                }
                if (nm == want && dg != "") {
                    sub(/^sha256:/, "", dg)
                    dg = tolower(dg)
                    if (dg ~ /^[0-9a-f]{64}$/) { print dg; exit }
                }
            }' 2>/dev/null || true)"
    fi
    if [ -z "$digest" ]; then
        html="$(secure_curl -fsSL --max-time 20 "https://github.com/${repo}/releases/expanded_assets/${tag}" 2>/dev/null || true)"
        if [ -n "$html" ]; then
            digest="$(printf '%s\n' "$html" | awk -v want="/${asset}" '
                index($0, want) > 0 { hit = 1; n = 0 }
                hit {
                    n++
                    if (match($0, /sha256:[0-9a-fA-F]{64}/)) {
                        print tolower(substr($0, RSTART + 7, 64))
                        exit
                    }
                    if (n > 25) hit = 0
                }' 2>/dev/null || true)"
        fi
    fi
    if [[ "$digest" =~ ^[0-9a-f]{64}$ ]]; then
        printf '%s' "$digest"
        return 0
    fi
    return 1
}

# preflight_install_check COMP_NAME BIN_PATH CONF_DIR：安装前架构、磁盘空间与目标路径预检
preflight_install_check() {
    local comp="$1" binp="$2" confd="$3" arch avail_mb check_dir
    arch="$(uname -m)"
    check_dir="$(dirname "$binp")"
    [ -d "$check_dir" ] || check_dir="/"
    avail_mb="$(df -Pm "$check_dir" 2>/dev/null | awk 'NR==2 {print $4}' || true)"
    info "$(L '安装预检：')${comp}  |  $(L '架构:') ${arch}  |  $(L '二进制:') ${binp}  |  $(L '配置目录:') ${confd}"
    if [[ "$avail_mb" =~ ^[0-9]+$ ]]; then
        if [ "$avail_mb" -lt 30 ]; then
            warn "$(L '磁盘剩余空间严重不足（仅') ${avail_mb}MB$(L ' < 30MB），已中止安装以避免损坏配置')"
            return 1
        elif [ "$avail_mb" -lt 200 ]; then
            warn "$(L '目标分区剩余空间偏低（')${avail_mb}MB$(L ' < 200MB），建议先清理日志或磁盘后再安装')"
            if [ -t 0 ]; then
                confirm "$(L '仍要继续安装？')" n || return 1
            fi
        fi
    fi
    return 0
}

# env_file_safe FILE：source 前校验 .env 文件安全（拒绝符号链接、非法键名、未转义 $ / ` / " 等可执行内容）
env_file_safe() {
    local f="$1" line key val rest n=0
    [ -f "$f" ] && [ ! -L "$f" ] || return 1
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            ""|"#"*) continue ;;
            *=*) key="${line%%=*}"; rest="${line#*=}" ;;
            *) return 1 ;;
        esac
        n=$((n + 1))
        [[ "$key" =~ ^(RULE|FWD|SITE|N|CF|NOWHERE|EGRESS|NOTIFY)_[A-Z0-9_]+$ ]] || return 1
        case "$rest" in
            \"*\") val="${rest:1:${#rest}-2}" ;;
            *) return 1 ;;
        esac
        val="${val//\\\\/}"
        val="${val//\\\$/}"
        val="${val//\\\`/}"
        val="${val//\\\"/}"
        case "$val" in *'$'*|*'`'*|*'"'*|*'\') return 1 ;; esac
    done < "$f"
    [ "$n" -gt 0 ] || return 1
    return 0
}

# _json_escape STR：将字符串转义为合法 JSON 字符串内容（不含首尾双引号）
_json_escape() {
    local s="${1:-}"
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import json,sys; print(json.dumps(sys.argv[1])[1:-1], end="")' "$s" 2>/dev/null && return 0
    fi
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
}

# check_ntp_sync：检测系统时间是否已 NTP 同步（保护 Xray REALITY maxTimeDiff: 60000）
# 返回：0=已同步；1=明确未同步；2=无法检测（如精简容器无 timedatectl/chronyc）
check_ntp_sync() {
    local val=""
    if command -v timedatectl >/dev/null 2>&1; then
        val="$(timedatectl show -p NTPSynchronized --value 2>/dev/null | tr -d ' \r\n' || true)"
        case "$val" in
            yes) return 0 ;;
            no)  return 1 ;;
        esac
    fi
    if command -v chronyc >/dev/null 2>&1; then
        val="$(chronyc tracking 2>/dev/null || true)"
        if [ -n "$val" ]; then
            if printf '%s\n' "$val" | grep -qi 'Leap status.*:.*Not synchronised'; then return 1; fi
            if printf '%s\n' "$val" | grep -qi 'Leap status.*:.*Normal'; then return 0; fi
        fi
    fi
    if command -v ntpstat >/dev/null 2>&1; then
        ntpstat >/dev/null 2>&1 && return 0 || return 1
    fi
    return 2
}

# fix_ntp_sync：尝试启用系统 NTP 同步（用于 repair 自愈）
fix_ntp_sync() {
    if command -v timedatectl >/dev/null 2>&1; then
        timedatectl set-ntp true >/dev/null 2>&1 || true
    fi
    if systemctl list-unit-files systemd-timesyncd.service 2>/dev/null | awk '/^systemd-timesyncd\.service/{f=1} END{exit !f}'; then
        systemctl enable --now systemd-timesyncd >/dev/null 2>&1 || true
    elif systemctl list-unit-files chrony.service 2>/dev/null | awk '/^chrony\.service/{f=1} END{exit !f}'; then
        systemctl enable --now chrony >/dev/null 2>&1 || true
    elif systemctl list-unit-files chronyd.service 2>/dev/null | awk '/^chronyd\.service/{f=1} END{exit !f}'; then
        systemctl enable --now chronyd >/dev/null 2>&1 || true
    fi
    return 0
}

# 告警通知配置（Telegram Bot / Bark / Webhook，存放在 /etc/adam/notify.env，0600 权限）
notify_load() {
    NOTIFY_ENABLED="0"
    NOTIFY_TYPE=""
    NOTIFY_TG_TOKEN=""
    NOTIFY_TG_CHAT_ID=""
    NOTIFY_BARK_URL=""
    NOTIFY_WEBHOOK_URL=""
    [ -f "$NOTIFY_ENV" ] && [ ! -L "$NOTIFY_ENV" ] || return 0
    env_file_safe "$NOTIFY_ENV" || return 0
    # shellcheck disable=SC1090
    source "$NOTIFY_ENV" 2>/dev/null || true
    return 0
}

notify_save() {
    state_save "$NOTIFY_ENV" "$MAINT_DIR" 755 NOTIFY_ENABLED NOTIFY_TYPE NOTIFY_TG_TOKEN NOTIFY_TG_CHAT_ID NOTIFY_BARK_URL NOTIFY_WEBHOOK_URL
}

# notify_send TITLE BODY [force]：发送运维告警（走 secure_curl HTTPS TLS>=1.2，不暴露密钥到命令行）
notify_send() {
    local title="$1" body="$2" force="${3:-}" host full_msg payload url_clean
    notify_load
    if [ "$force" != "force" ] && [ "$NOTIFY_ENABLED" != "1" ]; then return 0; fi
    host="$(hostname -s 2>/dev/null || echo 'vps')"
    full_msg="[${host}] ${title}"$'\n'"${body}"
    case "$NOTIFY_TYPE" in
        telegram)
            [[ "$NOTIFY_TG_TOKEN" =~ ^[0-9]+:[A-Za-z0-9_-]+$ ]] || return 1
            [[ "$NOTIFY_TG_CHAT_ID" =~ ^-?[0-9]+$ ]] || return 1
            payload="{\"chat_id\":\"$(_json_escape "$NOTIFY_TG_CHAT_ID")\",\"text\":\"$(_json_escape "$full_msg")\"}"
            secure_curl -fsS --max-time 10 -H 'Content-Type: application/json' \
                -d "$payload" \
                -K <(printf 'url = "https://api.telegram.org/bot%s/sendMessage"\n' "$NOTIFY_TG_TOKEN") \
                >/dev/null 2>&1 || return 1
            ;;
        bark)
            [[ "$NOTIFY_BARK_URL" == https://* ]] || return 1
            [[ "$NOTIFY_BARK_URL" != *'"'* && "$NOTIFY_BARK_URL" != *$'\n'* && "$NOTIFY_BARK_URL" != *$'\r'* ]] || return 1
            url_clean="${NOTIFY_BARK_URL%/}"
            payload="{\"title\":\"$(_json_escape "[${host}] ${title}")\",\"body\":\"$(_json_escape "$body")\"}"
            secure_curl -fsS --max-time 10 -H 'Content-Type: application/json' \
                -d "$payload" \
                -K <(printf 'url = "%s"\n' "$url_clean") \
                >/dev/null 2>&1 || return 1
            ;;
        webhook)
            [[ "$NOTIFY_WEBHOOK_URL" == https://* ]] || return 1
            [[ "$NOTIFY_WEBHOOK_URL" != *'"'* && "$NOTIFY_WEBHOOK_URL" != *$'\n'* && "$NOTIFY_WEBHOOK_URL" != *$'\r'* ]] || return 1
            payload="{\"host\":\"$(_json_escape "$host")\",\"title\":\"$(_json_escape "$title")\",\"body\":\"$(_json_escape "$body")\",\"text\":\"$(_json_escape "$full_msg")\"}"
            secure_curl -fsS --max-time 10 -H 'Content-Type: application/json' \
                -d "$payload" \
                -K <(printf 'url = "%s"\n' "$NOTIFY_WEBHOOK_URL") \
                >/dev/null 2>&1 || return 1
            ;;
        *)
            return 1
            ;;
    esac
    return 0
}


