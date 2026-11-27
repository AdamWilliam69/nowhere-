# record_previous_version TAG：只把符合 ^v?[0-9] 的版本号写入 PREV_VERSION_FILE（M1）
record_previous_version() {
    local v="$1"
    [[ "$v" =~ ^v?[0-9] ]] || return 0
    echo "$v" > "$PREV_VERSION_FILE"
}

# pick_udp_port_avoiding TCP_PORT：优先 CSPRNG 选高位空闲端口，避开 TCP_PORT、在监听端口与已托管服务端口（M9 / v8.6）
pick_udp_port_avoiding() {
    local tcp="$1" cand i
    for ((i = 0; i < 40; i++)); do
        cand="$(csprng_int 20000 55000 2>/dev/null || echo 0)"
        [ "$cand" -ge 20000 ] || continue
        if [ "$cand" != "$tcp" ] && ! udp_listening "$cand" && ! tcp_listening "$cand" \
            && ! port_used_by_other_services "${cand}/udp" nowhere \
            && ! port_used_by_other_services "${cand}/tcp" nowhere; then
            printf '%s' "$cand"; return 0
        fi
    done
    cand=2001
    while [ "$cand" -le 65535 ]; do
        if [ "$cand" != "$tcp" ] && ! udp_listening "$cand" && ! tcp_listening "$cand" \
            && ! port_used_by_other_services "${cand}/udp" nowhere; then
            printf '%s' "$cand"; return 0
        fi
        cand=$((cand + 1))
    done
    return 1
}

# 本机 nowhere.service 当前扮演的角色：portal / egress / none
current_role() {
    local r=""
    if [ -f "$ROLE_FILE" ]; then r="$(tr -d ' \r\n' < "$ROLE_FILE" 2>/dev/null || true)"; fi
    case "$r" in portal|egress) printf '%s' "$r"; return 0 ;; esac
    if [ -f "$SERVICE_FILE" ] && grep -q 'NOWHERE_EGRESS' "$SERVICE_FILE" 2>/dev/null; then
        printf 'egress'
    elif [ -f "$CONFIG_FILE" ]; then
        printf 'portal'
    else
        printf 'none'
    fi
    return 0
}

# 最新 Release tag：先问 GitHub API；被限流（共享出口 IP 很常见，未认证 60 次/小时）
# 时改为解析 releases/latest 的跳转地址，不依赖 API。
get_latest_tag() {
    github_latest_tag "$REPO"
}

# 下载 + 校验 + 解压 + 试运行指定 tag 的二进制；成功后路径写入全局 DL_BINARY。
# 旧版把这段逻辑在三个函数里各抄了一遍，这里收敛成一处。
fetch_nowhere_release() {
    local tag="$1" url
    detect_binary
    DL_BINARY=""
    make_workdir || return 1
    local workdir="$WORKDIR"
    url="https://github.com/${REPO}/releases/download/${tag}/${BIN_NAME}"
    if ! secure_curl -fL --retry 3 --connect-timeout 10 --max-time 300 -o "$workdir/nowhere.tar.gz" "$url"; then
        warn "$(L '下载失败（该版本可能没有') ${ARCH_NAME}-${LIBC} $(L '的发布文件）:') ${url}"
        return 1
    fi
    verify_release_checksum "$tag" "$workdir" || { warn "$(L '安装包 SHA256 校验失败，已中止')"; return 1; }
    tar -xzf "$workdir/nowhere.tar.gz" --no-same-owner -C "$workdir/" || { warn "$(L '解压失败')"; return 1; }
    DL_BINARY="$(find "$workdir" -type f -name nowhere 2>/dev/null | head -1 || true)"
    if [ -z "$DL_BINARY" ]; then warn "$(L '解压后未找到 nowhere 二进制')"; return 1; fi
    if ! verify_elf_binary "$DL_BINARY"; then
        warn "$(L '下载到的 nowhere 不是本机架构的 ELF 可执行文件，已中止')"
        return 1
    fi
    chmod 755 "$DL_BINARY"
    if ! upgrade_binary_precheck "$DL_BINARY" --version; then
        warn "$(L '下载到的二进制无法在本机运行（架构或 libc 不匹配），已中止，现有安装未被改动')"
        return 1
    fi
    return 0
}

# 升级跨过关键版本时的互通提醒（依据官方 v3.2.0 / v3.3.0 文档）
print_upgrade_notes() {
    local from="$1" to="$2"
    if version_ge "$to" "v3.2.0" && ! version_ge "$from" "v3.2.0"; then
        warn "$(L 'v3.2.0 起 Portal 强制 Authenticated Prelude、不再有回退：仍停留在 v3.0.x 的 Vector/Egress/Anywhere 在 morph=1 的 TLS/TCP 载体上会被静默拒绝')"
        warn "$(L '请把所有对端升级到') ≥ $(L 'v3.1.0（建议与本机同版本）；QUIC 载体与 morph=0 不受这条影响')"
    fi
    if version_ge "$to" "v3.3.0" && ! version_ge "$from" "v3.3.0"; then
        info "$(L 'v3.3.0 新增：Egress 可走 TLS/TCP（egress://KEY')@$(L 'HOST/tcp:PORT）、多台 Egress 可同时注册、NOW_MORPH_UDP_PRELUDE、握手超时默认按共享密钥派生（3–30s）')"
        info "$(L '现有 URL / 密钥 / 证书无需迁移；要用 TLS 载体的 Egress，出口机也需') ≥ v3.3.0"
    fi
    return 0
}

# SSH 实际监听端口（空格分隔）：当前会话端口 + sshd 生效配置 + 实际监听，取并集
detect_ssh_ports() {
    local ports="" p
    p="$(echo "${SSH_CONNECTION:-}" | awk '{print $4}')"
    if [[ "$p" =~ ^[0-9]+$ ]]; then ports="$p"; fi
    if command -v sshd >/dev/null 2>&1; then
        ports="${ports} $(sshd -T 2>/dev/null | awk '/^port /{print $2}' | tr '\n' ' ' || true)"
    fi
    if command -v ss >/dev/null 2>&1; then
        ports="${ports} $(ss -tlnp 2>/dev/null | awk '/"sshd"/ {n=split($4,a,":"); print a[n]}' | tr '\n' ' ' || true)"
    fi
    # shellcheck disable=SC2086
    ports="$(printf '%s\n' $ports | awk '/^[0-9]+$/ && $1>=1 && $1<=65535' | sort -un | tr '\n' ' ' || true)"
    ports="${ports% }"
    printf '%s' "${ports:-22}"
}

# is_ip ADDR [1=允许 CIDR]
is_ip() {
    local v="${1:-}" cidr="${2:-0}"
    [ -n "$v" ] || return 1
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import ipaddress,sys
v = sys.argv[1]
try:
    if sys.argv[2] == "1" and "/" in v:
        ipaddress.ip_network(v, strict=False)
    else:
        ipaddress.ip_address(v)
except Exception:
    sys.exit(1)' "$v" "$cidr" 2>/dev/null
        return $?
    fi
    local re4='^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$' re6='^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$'
    if [[ "$v" =~ $re4 ]]; then return 0; fi
    if [[ "$v" == *:* ]] && [[ "$v" =~ $re6 ]]; then return 0; fi
    return 1
}

# 主机名 / IP（可带方括号的 IPv6）字符集校验：这些值会写进被 source 的配置文件
is_safe_host() {
    local re='^[][A-Za-z0-9.:_-]+$'
    [[ -n "${1:-}" && "$1" =~ $re ]]
}

svc_state() {
    if systemctl is-active --quiet "$1" 2>/dev/null; then
        printf '%s' "${GREEN}$(L '运行中')${NC}"
    else
        printf '%s' "${RED}$(L '未运行')${NC}"
    fi
}

# ── 架构 / 二进制 ─────────────────────────────────────────────

detect_binary() {
    ARCH=$(uname -m)
    case $ARCH in
        x86_64|amd64)  ARCH_NAME="x86_64" ;;
        aarch64|arm64) ARCH_NAME="aarch64" ;;
        *)             error "$(L '不支持的架构:') ${ARCH}" ;;
    esac
    LIBC="gnu"
    if command -v ldd >/dev/null 2>&1; then
        local _ldd_out=""
        _ldd_out="$(ldd --version 2>&1 || true)"
        if [[ "${_ldd_out,,}" == *musl* ]]; then
            LIBC="musl"
        fi
    fi
    BIN_NAME="nowhere-${ARCH_NAME}-unknown-linux-${LIBC}.tar.gz"
}

record_installed_version() {
    local tag="$1"
    install -d -m 750 "$CONFIG_DIR"
    echo "$tag" > "$VERSION_FILE"
    nowhere_fix_perms
}

read_installed_version() {
    [ -f "$VERSION_FILE" ] || return 0
    cat "$VERSION_FILE" 2>/dev/null || true
}

read_previous_version() {
    [ -f "$PREV_VERSION_FILE" ] && cat "$PREV_VERSION_FILE" || echo ""
}

# 取 tag 的主版本号，如 v3.0.0 -> 3；解析不了返回空
version_major() {
    echo "$1" | sed -n 's/^v\?\([0-9][0-9]*\)\..*/\1/p'
}

# upgrade_binary_precheck bin [version_flag]：新二进制预检（文件存在+可执行+试跑）。
# version_flag 为空时只做可执行与文件校验。Nowhere 用 --version；Snell 脚本里没有
# --version 用法，已有用 -v（snell_installed_version / snell_fetch），故 Snell 用 -v。
upgrade_binary_precheck() {
    local bin="$1" flag="${2:-}"
    [ -f "$bin" ] && [ -x "$bin" ] || return 1
    [ -z "$flag" ] && return 0
    timeout 10 "$bin" "$flag" >/dev/null 2>&1
}

# 升级通用收尾：替换已由调用方完成；重启 → 等待 sleep_secs → 健康检查 → 失败打 log_lines 行日志并回滚
# upgrade_binary_finish unit restart_fn healthy_fn rollback_fn rollback_arg sleep_secs log_lines
upgrade_binary_finish() {
    local unit="$1" restart_fn="$2" healthy_fn="$3" rollback_fn="$4" rollback_arg="${5:-}" sleep_secs="${6:-2}" log_lines="${7:-20}"
    "$restart_fn" 2>/dev/null || true
    sleep "$sleep_secs"
    if "$healthy_fn"; then return 0; fi
    warn "$(L '新版本启动失败，日志如下：')"
    journalctl -u "$unit" -n "$log_lines" --no-pager 2>/dev/null || true
    if [ -n "$rollback_fn" ]; then "$rollback_fn" "$rollback_arg" 2>/dev/null || true; fi
    return 1
}

_upgrade_restart_nowhere() { systemctl restart nowhere; }
_upgrade_healthy_nowhere() { nowhere_healthy; }

# Nowhere 回滚到本地备份二进制（install_nowhere_version 的回滚段抽出，供 upgrade_binary_finish 回调）
nowhere_rollback_binary() {
    local prev="${1:-}"
    [ -f "$BIN_BACKUP_PATH" ] || return 1
    warn "$(L '正在自动回滚到备份二进制')${prev:+(${prev})}..."
    install -m 755 "$BIN_BACKUP_PATH" "$BIN_PATH"
    [ -n "$prev" ] && record_installed_version "$prev"
    systemctl restart nowhere 2>/dev/null || true
    sleep 2
    if systemctl is-active --quiet nowhere; then
        success "$(L '已自动回滚，服务恢复运行:') $(${BIN_PATH} --version 2>&1 | awk "NR==1" || true)"
        notify_send "Nowhere Auto-Rollback" "Upgrade failed; automatically rolled back to ${prev:-previous} and service recovered." || true
    else
        warn "$(L '回滚后服务仍未启动，请立即查看日志: journalctl -u nowhere -n 50 --no-pager')"
        notify_send "Nowhere Rollback Alert" "Upgrade failed and nowhere is STILL DOWN after rollback. Check journalctl -u nowhere." || true
    fi
    return 0
}

install_nowhere_version() {
    maint_lock_manual || return 1
    local target_tag="$1"
    _CACHED_TLS_FP=""
    detect_binary

    local major
    major="$(version_major "$target_tag")"
    if [ -n "$major" ] && [ "$major" -lt 3 ]; then
        warn "$(L '目标版本') ${target_tag} $(L '属于 NW')${major} $(L '协议代，与本脚本生成的 v3')(NW3) $(L '配置/对端不互通')"
        read -rp "$(L '仍要安装该旧版本吗？')[y/N]: " OLD_CONFIRM || { [ -n "$OLD_CONFIRM" ] || return 1; }
        if [[ ! "$OLD_CONFIRM" =~ ^[Yy]$ ]]; then
            info "$(L '已取消')"
            return 1
        fi
    fi
    if [ -n "$major" ] && [ "$major" -gt 3 ]; then
        warn "$(L '目标版本') ${target_tag} $(L '属于新的协议代（NW')${major}$(L '），本脚本只适配 NW3：URL 语法、密钥格式、对端兼容性都可能已变化')"
        read -rp "$(L '仍要安装吗？')[y/N]: " NEW_CONFIRM || { [ -n "$NEW_CONFIRM" ] || return 1; }
        if [[ ! "$NEW_CONFIRM" =~ ^[Yy]$ ]]; then
            info "$(L '已取消')"
            return 1
        fi
    fi

    info "$(L '下载并校验') ${target_tag} (${ARCH_NAME}-${LIBC}) ..."
    fetch_nowhere_release "$target_tag" || return 1

    local cur_tag
    cur_tag="$(read_installed_version)"
    install -d -m 750 "$CONFIG_DIR"
    if [ -f "$BIN_PATH" ]; then
        cp "$BIN_PATH" "$BIN_BACKUP_PATH"
        record_previous_version "$cur_tag"
    fi

    # install 会先删除旧文件再写入新文件，运行中的进程不受影响；随后一次 restart 完成切换，
    # 比旧版的 stop -> 替换 -> start 少一段停机窗口
    install -m 755 "$DL_BINARY" "$BIN_PATH"
    record_installed_version "$target_tag"

    if [ ! -f "$SERVICE_FILE" ]; then
        success "$(L '二进制已更新到') ${target_tag}$(L '（未检测到 nowhere.service，未启动服务）')"
        return 0
    fi

    # 启动失败自动用本地备份二进制回滚，不把服务留在宕机状态
    if upgrade_binary_finish nowhere _upgrade_restart_nowhere _upgrade_healthy_nowhere nowhere_rollback_binary "$cur_tag" 2 20; then
        success "$(L '已切换到') ${target_tag}: $(${BIN_PATH} --version 2>&1 | awk "NR==1" || true)"
        print_upgrade_notes "$cur_tag" "$target_tag"
        return 0
    fi
    return 1
}

# ── 通用小工具 ────────────────────────────────────────────────

urlencode() {
    local input="${1:-}"
    python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$input" 2>/dev/null \
        || echo -n "$input" | od -An -tx1 | tr ' ' % | tr -d '\n'
}

urldecode() {
    local input="${1:-}"
    python3 -c 'import sys, urllib.parse; print(urllib.parse.unquote(sys.argv[1]))' "$input" 2>/dev/null \
        || printf '%s' "$input"
}

# 编码文件路径（crt=/key= 的值）：保留 / 不编码，只编码空格、&、#、% 等会切断 URL 查询串
# 的字符。默认 Let's Encrypt 路径不含这些字符，输出与旧版逐字相同；特殊路径不再被 & 截断。
# 注意：不能用 urlencode（safe=""）把 / 编成 %2F，那会改变路径原意。
encode_path() {
    local input="${1:-}"
    python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe="/"))' "$input" 2>/dev/null \
        || printf '%s' "$input"
}

# 编码 SOCKS 地址（out=/in= 的值）：v3 按「最后一个 @」切主机、再按「第一个原文 :」切用户名/密码
# （编码后的 %3A 不算分隔符），随后对用户名/密码各百分号解码一次。
# 官方示例：out=a%3Ab:p%40ss@127.0.0.1:1080 表示用户名 a:b、密码 p@ss。
# 实测结论：用户名/密码内部的原文 : 与 @ 都会被拒（reserved characters ... must be percent-encoded），
# 只有那个分隔用的第一个原文 : 可以保留。主机:端口保持原文。
# 所以：用户名全编码，密码全编码，拼接为 编码后用户名 + ":" + 编码后密码 + "@" + 主机:端口。
encode_socks() {
    local socks="$1" userinfo endpoint user pass
    if [[ "$socks" == *@* ]]; then
        userinfo="${socks%@*}"
        endpoint="${socks##*@}"
        if [[ "$userinfo" == *:* ]]; then
            user="${userinfo%%:*}"
            pass="${userinfo#*:}"
            printf '%s:%s@%s' "$(urlencode "$user")" "$(urlencode "$pass")" "$endpoint"
            return 0
        fi
    fi
    printf '%s' "$socks"
}

format_host_for_url() {
    local host="${1:-}"
    if [[ -z "$host" ]]; then
        printf ''
    elif [[ "$host" == \[*\] ]]; then
        printf '%s' "$host"
    elif [[ "$host" == *:* ]]; then
        printf '[%s]' "$host"
    else
        printf '%s' "$host"
    fi
}

# v3 密钥：恰好 32 位小写十六进制（nowhere generate-key 的输出格式）
is_valid_key() {
    [[ "$1" =~ ^[0-9a-f]{32}$ ]]
}

# 本地生成符合 v3 规范的密钥（16 随机字节 -> 32 位小写 hex）
# 装好二进制后优先用官方 nowhere generate-key，两者格式一致；兜底走全局 CSPRNG 引擎
gen_key() {
    if [ -x "$BIN_PATH" ]; then
        local k
        k="$("$BIN_PATH" generate-key 2>/dev/null | tr -d ' \r\n' || true)"
        if is_valid_key "$k"; then
            printf '%s' "$k"
            return 0
        fi
    fi
    csprng_hex 16
}

# 是否为公网 IP（排除私网/回环/链路本地/CGNAT/文档段/组播；IPv6 排除回环/链路本地/ULA/文档段）
is_public_ip() {
    local ip="$1" a b
    ip="${ip#[}"; ip="${ip%]}"
    if [[ "$ip" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
        a="${BASH_REMATCH[1]}"; b="${BASH_REMATCH[2]}"
        local c="${BASH_REMATCH[3]}" d="${BASH_REMATCH[4]}"
        [ "$a" -le 255 ] && [ "$b" -le 255 ] && [ "$c" -le 255 ] && [ "$d" -le 255 ] || return 1
        case "$a" in
            0|127) return 1 ;;
            10) return 1 ;;
            100) [ "$b" -ge 64 ] && [ "$b" -le 127 ] && return 1 ;;
            169) [ "$b" = "254" ] && return 1 ;;
            172) [ "$b" -ge 16 ] && [ "$b" -le 31 ] && return 1 ;;
            192)
                case "$b" in
                    0)   [ "$c" = "0" ] || [ "$c" = "2" ] && return 1 ;;
                    168) return 1 ;;
                esac
                ;;
            198)
                case "$b" in
                    18|19) return 1 ;;
                    51)    [ "$c" = "100" ] && return 1 ;;
                esac
                ;;
            203) [ "$b" = "0" ] && [ "$c" = "113" ] && return 1 ;;
            224|225|226|227|228|229|230|231|232|233|234|235|236|237|238|239) return 1 ;;
            24[0-9]|25[0-9]) return 1 ;;
        esac
        return 0
    fi
    local low="${ip,,}"
    [[ "$low" == *:* ]] && [[ "$low" =~ ^[0-9a-f:]+$ ]] || return 1
    case "$low" in
        ::1|::|::ffff:*) return 1 ;;
        fe8*|fe9*|fea*|feb*|fc*|fd*|ff*) return 1 ;;
        2001:db8*) return 1 ;;
    esac
    return 0
}

detect_public_host() {
    local detected="" u cand
    for u in https://api.ipify.org https://ipv4.icanhazip.com https://ifconfig.me/ip; do
        detected="$(secure_curl -4fsS --max-time 4 "$u" 2>/dev/null | tr -d ' \r\n' || true)"
        if [[ "$detected" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then break; fi
        detected=""
    done
    if [ -z "$detected" ]; then
        # 纯 IPv6 机器：再查一次 IPv6 出口地址（只接受公网段）
        detected="$(secure_curl -6fsS --max-time 4 https://api64.ipify.org 2>/dev/null | tr -d ' \r\n' || true)"
        [[ "$detected" =~ ^[0-9A-Fa-f:]+$ ]] && is_public_ip "$detected" || detected=""
    fi
    if [ -z "$detected" ]; then
        # hostname -I 可能先返回内网地址：只取其中第一个公网 IP，取不到返回空
        # （空值会强制手动输入，而不是悄悄用内网 IP 生成一堆连不上的分享链接）
        for cand in $(hostname -I 2>/dev/null || true); do
            if is_public_ip "$cand"; then detected="$cand"; break; fi
        done
    fi
    printf '%s' "$detected"
}

# 解析域名到 IP 列表（每行一个），解析不到返回空
resolve_host_ips() {
    local host="$1" out=""
    if command -v getent >/dev/null 2>&1; then
        out="$(getent hosts "$host" 2>/dev/null | awk '{print $1}' || true)"
    fi
    if [ -z "$out" ] && command -v host >/dev/null 2>&1; then
        out="$(host "$host" 2>/dev/null | awk '/has address|has IPv6 address/ {print $NF}' || true)"
    fi
    if [ -z "$out" ] && command -v dig >/dev/null 2>&1; then
        out="$(dig +short "$host" 2>/dev/null | grep -E '^[0-9A-Fa-f:.]+$' || true)"
    fi
    printf '%s' "$out"
}

# 校验分享链接用的公网地址：IP 必须是公网 IP；域名必须能解析，且解析结果须与本机公网 IP 一致
# （不一致可能是 CDN/多线，也可能是填错；调用方据此警告并由用户确认是否仍用）。返回 0=可用，1=有问题
check_public_host() {
    local host="$1" detected="" resolved="" rip
    if [ -z "$host" ]; then
        warn "$(L '公网地址为空')"
        return 1
    fi
    if [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ "$host" == *:* ]]; then
        if ! is_public_ip "$host"; then
            warn "$(L '该地址不是公网 IP（内网/保留地址），客户端连不上：')${host}"
            return 1
        fi
        return 0
    fi
    resolved="$(resolve_host_ips "$host")"
    if [ -z "$resolved" ]; then
        warn "$(L '该域名解析不到任何 IP，请检查域名/DNS：')${host}"
        return 1
    fi
    detected="$(detect_public_host)"
    if [ -n "$detected" ]; then
        while IFS= read -r rip; do
            [ "$rip" = "$detected" ] && return 0
        done <<< "$resolved"
        warn "$(L '该域名解析到的 IP 与本机公网 IP 不一致（可能是 CDN/多线，也可能是填错）：')$(printf '%s' "$resolved" | tr '\n' ' ' | sed 's/ $//')$(L '，')$(L '本机公网 IP：')${detected}"
        return 1
    fi
    return 0
}

mask_secret() {
    local value="${1:-}"
    local length="${#value}"
    if [[ "$length" -le 8 ]]; then
        printf '***'
    else
        printf '%s...%s' "${value:0:4}" "${value: -4}"
    fi
}

# SOCKS5 地址展示（打码密码部分），v3 里它出现在 Portal 的 out= 或 Vector 的 in=（带认证时）
display_socks() {
    local socks="${1:-none}"
    if [[ -z "$socks" || "$socks" == "none" ]]; then
        printf 'none'
    elif [[ "$socks" == *@* ]]; then
        printf '***@%s' "${socks##*@}"
    else
        printf '%s' "$socks"
    fi
}

validate_port() {
    # 10# 规范化：08/09 之类带前导 0 的输入不能按八进制解析（L1）
    [[ "$1" =~ ^[0-9]+$ ]] || return 1
    [[ "${#1}" -le 5 ]] || return 1
    local _vp=$((10#$1))
    [ "$_vp" -ge 1 ] && [ "$_vp" -le 65535 ]
}

# v3.3 新增：握手超时为持续时间格式（官方示例 5s / 250ms / 1h）；须为正数+单位，
# 非法值会被 v3.3 在启动时直接拒绝（启动失败并点名该变量）
validate_duration() {
    [[ "$1" =~ ^[1-9][0-9]*(ms|s|m|h)$ ]]
}

# v8.6：Nowhere v3.3.0 起允许 auto（不传 NOW_HANDSHAKE_TIMEOUT，由官方按 Shared Key 派生 3s–30s）或自定义时长
validate_handshake_timeout() {
    [ "${1:-}" = "auto" ] || validate_duration "${1:-}"
}

# rate/etar 官方取值范围 0..=2147483647（Mbps），超出会被 v3 在启动时直接拒绝
validate_rate() {
    [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -le 2147483647 ]
}

# dial/dial4/dial6 只接受 IP 字面量或 auto；fam: any/4/6，IPv6 时拒绝 IPv4-mapped 地址
validate_ip_or_auto() {
    local v="${1:-}" fam="${2:-any}"
    [ "$v" = "auto" ] && return 0
    [ -n "$v" ] || return 1
    python3 -c 'import ipaddress,sys
try: ip = ipaddress.ip_address(sys.argv[1])
except Exception: sys.exit(1)
fam = sys.argv[2]
if fam == "4" and ip.version != 4: sys.exit(1)
if fam == "6" and (ip.version != 6 or ip.ipv4_mapped is not None): sys.exit(1)
sys.exit(0)' "$v" "$fam" 2>/dev/null
}

# sanitize_nowhere_params：端口/时长/限速/分端口冲突一次校验并修正（向导、加载、重配、Egress 解析共用，M17）
# 读全局与调用方 locals（bash 动态作用域）；只修正内存里的值，不写文件；恒返回 0
sanitize_nowhere_params() {
    if [ -n "${PORT:-}" ]; then
        validate_port "$PORT" || { warn "$(L '端口不合法，重置为443')"; PORT=443; }
    fi
    if [ -n "${TCP_PORT:-}" ]; then
        validate_port "$TCP_PORT" || { warn "$(L '端口不合法，重置为2000')"; TCP_PORT=2000; }
    fi
    if [ -n "${UDP_PORT:-}" ]; then
        validate_port "$UDP_PORT" || { warn "$(L '端口不合法，重置为2001')"; UDP_PORT=2001; }
    fi
    if [ "${PORT_MODE:-}" = "split" ] && [ -n "${TCP_PORT:-}" ] && [ "$TCP_PORT" = "${UDP_PORT:-}" ]; then
        UDP_PORT="$(pick_udp_port_avoiding "$TCP_PORT" || echo 2001)"
        warn "$(L '分端口模式下 TCP 与 UDP 端口不能相同，已将 UDP 端口改为') ${UDP_PORT}"
    fi
    if [ -n "${HANDSHAKE_TIMEOUT:-}" ]; then
        validate_handshake_timeout "$HANDSHAKE_TIMEOUT" || { warn "$(L '格式不合法（须为 auto 或正数+单位，如 10s / 500ms / 1m / 1h），已重置为 auto')"; HANDSHAKE_TIMEOUT="auto"; }
    fi
    if [ -n "${RATE:-}" ]; then validate_rate "$RATE" || { warn "$(L '限速不合法，已清空（不限速）')"; RATE=""; }; fi
    if [ -n "${ETAR:-}" ]; then validate_rate "$ETAR" || { warn "$(L '限速不合法，已清空（不限速）')"; ETAR=""; }; fi
    if [ -n "${DIAL:-}" ]; then validate_ip_or_auto "$DIAL" || { warn "$(L '出站源 IP 不合法，已重置为 auto')"; DIAL="auto"; }; fi
    if [ -n "${DIAL4:-}" ]; then validate_ip_or_auto "$DIAL4" 4 || { warn "$(L '出站源 IP 不合法，已重置为 auto')"; DIAL4="auto"; }; fi
    if [ -n "${DIAL6:-}" ]; then validate_ip_or_auto "$DIAL6" 6 || { warn "$(L '出站源 IP 不合法，已重置为 auto')"; DIAL6="auto"; }; fi
    case "${MORPH_TCP_PRELUDE:-}" in ""|fade|full8|low7) : ;; *) MORPH_TCP_PRELUDE="fade" ;; esac
    case "${MORPH_UDP_PRELUDE:-}" in ""|fade|full8|low7) : ;; *) MORPH_UDP_PRELUDE="fade" ;; esac
    if [ -n "${eg_port:-}" ]; then validate_port "$eg_port" || { warn "$(L '端口不合法，重置为 443')"; eg_port=443; }; fi
    if [ -n "${eg_handshake:-}" ]; then validate_handshake_timeout "$eg_handshake" || { warn "$(L '格式不合法（须为 auto 或正数+单位，如 10s），已重置为 auto')"; eg_handshake="auto"; }; fi
    return 0
}

# 把值安全地写进双引号 env 行：转义 \ " $ `，避免 source 配置文件时被展开/截断
dq_escape() {
    local v="$1"
    v="${v//\\/\\\\}"
    v="${v//\"/\\\"}"
    v="${v//$/\\$}"
    v="${v//\`/\\\`}"
    printf '%s' "$v"
}

validate_socks() {
    local socks="$1" endpoint userinfo host port
    [[ -z "$socks" || "$socks" == "none" ]] && return 0
    [[ "$socks" != *[[:space:]]* ]] || return 1
    endpoint="$socks"
    if [[ "$endpoint" == *@* ]]; then
        userinfo="${endpoint%@*}"
        endpoint="${endpoint##*@}"
        [[ "$userinfo" == *:* ]] || return 1
    fi
    if [[ "$endpoint" == \[*\]:* ]]; then
        host="${endpoint#\[}"; host="${host%%\]:*}"
        port="${endpoint##*\]:}"
    else
        [[ "$endpoint" == *:* ]] || return 1
        [[ "$endpoint" != *:*:* ]] || return 1
        host="${endpoint%:*}"; port="${endpoint##*:}"
    fi
    [[ -n "$host" ]] || return 1
    validate_port "$port"
}

# 证书信任参数（Vector/Egress 共用）：
#   tls=2 真实证书：默认按端点主机名走系统 CA 校验；公网地址与证书域名不一致时补 sni=
#   tls=1 自签证书：必须 pin=证书 SHA-256 指纹（64 位小写 hex），否则校验必然失败
# 自签指纹取不到（服务未启动等）时返回 1，调用方应留空并提示稍后用Nowhere 菜单 4/10 重新生成
append_trust_params() {
    local query="$1"
    if [ "$TLS_MODE" = "2" ]; then
        if [[ -n "$DOMAIN" && "$PUBLIC_HOST" != "$DOMAIN" ]]; then
            query="${query}&sni=$(urlencode "$DOMAIN")"
        fi
        printf '%s' "$query"
        return 0
    fi
    local fp
    fp="$(get_tls_fingerprint 2>/dev/null || true)"
    if [ -n "$fp" ]; then
        printf '%s&pin=%s' "$query" "$fp"
        return 0
    fi
    printf '%s' "$query"
    return 1
}

# ── URL 构建（v3 语法） ───────────────────────────────────────

# Portal 监听端点：空/ * = 通配；mix 同端口写 HOST:PORT，分端口写 HOST/tcp:P/udp:P
build_portal_endpoint() {
    local host tcp_seg udp_seg
    if [[ -z "$LISTEN_HOST" || "$LISTEN_HOST" == "*" ]]; then
        host="*"
    else
        host="$(format_host_for_url "$LISTEN_HOST")"
    fi
    tcp_seg="tcp${TCP_FAMILY:-}"
    udp_seg="udp${UDP_FAMILY:-}"
    if [[ "$PORT_MODE" == "split" ]]; then
        printf '%s/%s:%s/%s:%s' "$host" "$tcp_seg" "$TCP_PORT" "$udp_seg" "$UDP_PORT"
    else
        case "$NET" in
            tcp) printf '%s/%s:%s' "$host" "$tcp_seg" "$PORT" ;;
            udp) printf '%s/%s:%s' "$host" "$udp_seg" "$PORT" ;;
            *)   # 同端口双栈：地址族受限时不能用紧凑形 HOST:PORT，必须写显式载体路径
                 if [[ -n "${TCP_FAMILY:-}" || -n "${UDP_FAMILY:-}" ]]; then
                     printf '%s/%s:%s/%s:%s' "$host" "$tcp_seg" "$PORT" "$udp_seg" "$PORT"
                 else
                     printf '%s:%s' "$host" "$PORT"
                 fi ;;
        esac
    fi
}

# 实际生效的 TCP/UDP 端口（供防火墙、指纹、客户端链接使用）
tcp_port() { if [[ "$PORT_MODE" == "split" ]]; then printf '%s' "$TCP_PORT"; else printf '%s' "$PORT"; fi }
udp_port() { if [[ "$PORT_MODE" == "split" ]]; then printf '%s' "$UDP_PORT"; else printf '%s' "$PORT"; fi }
has_tcp() { [[ "$PORT_MODE" == "split" || "$NET" == "mix" || "$NET" == "tcp" ]]; }
has_udp() { [[ "$PORT_MODE" == "split" || "$NET" == "mix" || "$NET" == "udp" ]]; }

build_portal_url() {
    local query endpoint
    endpoint="$(build_portal_endpoint)"
    query="tls=${TLS_MODE}"
    if [[ "$TLS_MODE" == "2" ]]; then
        local _url_crt="${CRT_RUNTIME:-$CRT}" _url_key="${KEY_PEM_RUNTIME:-$KEY_PEM}"
        query="${query}&crt=$(encode_path "$_url_crt")&key=$(encode_path "$_url_key")"
    fi
    query="${query}&morph=${MORPH}"
    case "$OUT_TYPE" in
        egress)
            query="${query}&out=egress"
            ;;
        socks)
            query="${query}&out=$(encode_socks "$SOCKS")"
            ;;
        *) : ;;
    esac
    if [[ "$OUT_TYPE" != "egress" ]]; then
        if [[ "$DIAL_MODE" == "dual" ]]; then
            [[ -n "$DIAL4" && "$DIAL4" != "auto" ]] && query="${query}&dial4=$(urlencode "$DIAL4")"
            [[ -n "$DIAL6" && "$DIAL6" != "auto" ]] && query="${query}&dial6=$(urlencode "$DIAL6")"
        elif [[ -n "$DIAL" && "$DIAL" != "auto" ]]; then
            query="${query}&dial=$(urlencode "$DIAL")"
        fi
    fi
    [[ -n "$RATE" && "$RATE" != "0" ]] && query="${query}&rate=${RATE}"
    [[ -n "$ETAR" && "$ETAR" != "0" ]] && query="${query}&etar=${ETAR}"
    printf 'portal://%s@%s?%s' "$SHARED_KEY" "$endpoint" "$query"
}

build_client_links() {
    local host host_part encoded_name base query port
    UDP_LINK=""; TCP_LINK=""; IMPORT_UDP=""; IMPORT_TCP=""
    host="${PUBLIC_HOST:-}"
    [[ -z "$host" ]] && host="$(detect_public_host)"
    if [[ -z "$host" ]]; then
        warn "$(L '未能确定公网地址，无法生成 Anywhere 分享链接')"
        return 0
    fi
    host_part="$(format_host_for_url "$host")"
    encoded_name="$(urlencode "Nowhere-${DOMAIN}")"
    base="nowhere://${SHARED_KEY}@${host_part}"

    # Anywhere 分享链接（v3 文档格式）：nowhere://KEY@HOST:PORT?net=tcp|udp&morph=0|1#名称
    # net 默认 tcp；morph 默认 1。注意：需 Anywhere 已支持 NW3 才能真正连通（见文末说明）
    if has_udp; then
        port="$(udp_port)"
        query="net=udp&morph=${MORPH}"
        UDP_LINK="${base}:${port}?${query}#${encoded_name}"
        IMPORT_UDP="anywhere://add-proxy?link=$(urlencode "$UDP_LINK")"
    fi
    if has_tcp; then
        port="$(tcp_port)"
        if [[ "$MORPH" == "1" ]]; then
            query="morph=1"
        else
            query="morph=0"
        fi
        TCP_LINK="${base}:${port}?${query}#${encoded_name}"
        IMPORT_TCP="anywhere://add-proxy?link=$(urlencode "$TCP_LINK")"
    fi
}

# 本地 Vector 客户端：vector://KEY@HOST/tcp:PORT 或 /udp:PORT，二选一载体 + in=本地SOCKS5
# 注意：官方端点表规定 HOST:PORT 紧凑形对 Vector 只代表 TLS（对 Egress 只代表 QUIC），
# 不是“双栈自动选”，所以这里不把 udp 载体写成紧凑形；同端口双栈 Portal 的紧凑形 Vector
# 等价于 tcp 载体，显式写法与之一致且更明确。
build_vector_info() {
    VECTOR_URL=""
    [ "$GENERATE_VECTOR" != "1" ] && return 0

    local host host_part port carrier query
    host="${PUBLIC_HOST:-}"
    [[ -z "$host" ]] && host="$(detect_public_host)"
    if [[ -z "$host" ]]; then
        warn "$(L '未能确定公网地址，无法生成 Vector 连接串，可稍后通过Nowhere 菜单「4')) $(L '查看连接信息」重试')"
        return 0
    fi
    host_part="$(format_host_for_url "$host")"
    carrier="${VECTOR_CARRIER:-tcp}"
    if [[ "$carrier" == "udp" ]] && has_udp; then
        port="$(udp_port)"
        carrier="udp${UDP_FAMILY:-}"
    elif has_tcp; then
        port="$(tcp_port)"
        carrier="tcp${TCP_FAMILY:-}"
    else
        port="$(udp_port)"
        carrier="udp${UDP_FAMILY:-}"
    fi

    query="in=$(encode_socks "$VECTOR_SOCKS")&morph=${MORPH}"
    [[ -n "$RATE" && "$RATE" != "0" ]] && query="${query}&rate=${RATE}"
    [[ -n "$ETAR" && "$ETAR" != "0" ]] && query="${query}&etar=${ETAR}"
    local trust_query
    if trust_query="$(append_trust_params "$query")"; then
        query="$trust_query"
    else
        warn "$(L '未能获取自签证书指纹，Vector 连接串暂缺 pin=（服务启动后可用 Nowhere 菜单 4 重新生成）')"
    fi
    VECTOR_URL="vector://${SHARED_KEY}@${host_part}/${carrier}:${port}?${query}"
}

# 远程 Egress 出口：egress://KEY@HOST/udp:PORT 或 /tcp:PORT，在出口机上运行，无需其开放入站端口。
# v3.3.0 起 Egress 可走 QUIC 或 TLS（一个连接串只选一种载体）；紧凑形 HOST:PORT 对 Egress 代表 QUIC，
# 这里始终写显式载体路径。
build_egress_info() {
    EGRESS_URL=""
    [ "$GENERATE_EGRESS" != "1" ] && return 0

    local host host_part port query carrier
    host="${PUBLIC_HOST:-}"
    [[ -z "$host" ]] && host="$(detect_public_host)"
    if [[ -z "$host" ]]; then
        warn "$(L '未能确定公网地址，无法生成 Egress 连接串，可稍后通过Nowhere 菜单「4')) $(L '查看连接信息」重试')"
        return 0
    fi
    host_part="$(format_host_for_url "$host")"
    if [[ "${EGRESS_CARRIER:-udp}" == "tcp" ]] && has_tcp; then
        port="$(tcp_port)"; carrier="tcp${TCP_FAMILY:-}"
    elif has_udp; then
        port="$(udp_port)"; carrier="udp${UDP_FAMILY:-}"
    else
        port="$(tcp_port)"; carrier="tcp${TCP_FAMILY:-}"
    fi

    query="morph=${MORPH}"
    # dial 与 dial4/dial6 互斥（官方配置表）：dual 时只出 dial4/dial6，single 时只出 dial
    if [[ "${EGRESS_DIAL_MODE:-single}" == "dual" ]]; then
        [[ -n "${EGRESS_DIAL4:-}" && "$EGRESS_DIAL4" != "auto" ]] && query="${query}&dial4=$(urlencode "$EGRESS_DIAL4")"
        [[ -n "${EGRESS_DIAL6:-}" && "$EGRESS_DIAL6" != "auto" ]] && query="${query}&dial6=$(urlencode "$EGRESS_DIAL6")"
    elif [[ -n "${EGRESS_DIAL:-}" && "$EGRESS_DIAL" != "auto" ]]; then
        query="${query}&dial=$(urlencode "$EGRESS_DIAL")"
    fi
    [[ -n "$RATE" && "$RATE" != "0" ]] && query="${query}&rate=${RATE}"
    [[ -n "$ETAR" && "$ETAR" != "0" ]] && query="${query}&etar=${ETAR}"
    local trust_query
    if trust_query="$(append_trust_params "$query")"; then
        query="$trust_query"
    else
        warn "$(L '未能获取自签证书指纹，Egress 连接串暂缺 pin=（服务启动后可用 Nowhere 菜单 4 重新生成）')"
    fi
    EGRESS_URL="egress://${SHARED_KEY}@${host_part}/${carrier}:${port}?${query}"
}

# 供 probe 使用的 Vector URL（不需要 in=）；传入 --local 时优先走本机回环地址（绕过云 VPS NAT 无回流）
build_probe_vector_url() {
    local local_mode=0 host host_part port carrier query
    [ "${1:-}" = "--local" ] && local_mode=1
    if [ "$local_mode" = "1" ]; then
        if [ -n "${LISTEN_HOST:-}" ] && [ "$LISTEN_HOST" != "*" ] && [ "$LISTEN_HOST" != "0.0.0.0" ] && [ "$LISTEN_HOST" != "::" ] && [ "$LISTEN_HOST" != "[::]" ]; then
            host="$LISTEN_HOST"
        elif [ "${TCP_FAMILY:-}" = "6" ] || { ! has_tcp && [ "${UDP_FAMILY:-}" = "6" ]; }; then
            host="::1"
        else
            host="127.0.0.1"
        fi
    else
        host="${PUBLIC_HOST:-}"
        [[ -z "$host" ]] && host="$(detect_public_host)"
        if [[ -z "$host" ]]; then
            warn "$(L '未能确定公网地址，无法生成 Vector 探针链接')"
            return 1
        fi
    fi
    host_part="$(format_host_for_url "$host")"
    carrier="${VECTOR_CARRIER:-tcp}"
    if [[ "$carrier" == "udp" ]] && has_udp; then
        port="$(udp_port)"
        carrier="udp${UDP_FAMILY:-}"
    elif has_tcp; then
        carrier="tcp${TCP_FAMILY:-}"
        port="$(tcp_port)"
    else
        port="$(udp_port)"
        carrier="udp${UDP_FAMILY:-}"
    fi
    query="morph=${MORPH}"
    local trust_query
    if trust_query="$(append_trust_params "$query")"; then
        query="$trust_query"
    fi
    printf 'vector://%s@%s/%s:%s?%s' "$SHARED_KEY" "$host_part" "$carrier" "$port" "$query"
}

# 从当前 nowhere 服务的启动日志提取指纹（供纯 UDP / TCP 探测失败时兜底）。
# 关键点：严格按 systemctl MainPID 过滤当前运行进程的日志；服务未运行（MainPID=0）或当前 PID 无记录时
# 绝不回退读历史 -n 500（避免返回上一次重启已过期的 tls=1 内存自签指纹）。
# 日志里指纹可能是不带冒号的 64 位 hex，也可能是 AA:BB:... 冒号分隔形，两种都兼容，
# 统一输出为不带冒号的小写 hex。取不到返回 1，不输出、不伪造。
get_fingerprint_from_journal() {
    local log fp main_pid
    main_pid="$(systemctl show -p MainPID --value nowhere 2>/dev/null | tr -d ' \r\n' || true)"
    if [[ ! "$main_pid" =~ ^[1-9][0-9]*$ ]]; then
        return 1
    fi
    log="$(journalctl -u nowhere _PID="$main_pid" --no-pager 2>/dev/null || true)"
    fp="$(printf '%s' "$log" | grep -i 'fingerprint' | grep -oE '[0-9a-fA-F]{64}' | tail -1 | tr 'A-F' 'a-f' || true)"
    if [ -z "$fp" ]; then
        fp="$(printf '%s' "$log" | grep -i 'fingerprint' | grep -oE '([0-9a-fA-F]{2}:){31}[0-9a-fA-F]{2}' | tail -1 | tr -d ':' | tr 'A-F' 'a-f' || true)"
    fi
    if [ -n "$fp" ]; then
        printf '%s' "$fp"
        return 0
    fi
    return 1
}

# 纯获取指纹（64 位小写 hex，无冒号），不打印不警告，供 pin= 拼接用
# v8.7 顺序：优先按当前运行 MainPID 读启动日志（零网络建连、不向 nowhere 日志刷 unexpected-eof 报错）
# -> 官方 nowhere fingerprint（自动处理 Morph）-> openssl s_client（仅 morph=0）
get_tls_fingerprint() {
    [[ "$TLS_MODE" != "1" ]] && return 1
    # 单次展示流程内缓存：调用方在父 shell 预热 _CACHED_TLS_FP 后，子 shell 可直接命中
    if [ -n "${_CACHED_TLS_FP:-}" ]; then printf '%s' "$_CACHED_TLS_FP"; return 0; fi
    local jfp
    jfp="$(get_fingerprint_from_journal 2>/dev/null || true)"
    if [ -n "$jfp" ]; then
        _CACHED_TLS_FP="$jfp"
        printf '%s' "$jfp"
        return 0
    fi
    if ! has_tcp; then
        return 1
    fi
    local port probe_host="127.0.0.1"
    port="$(tcp_port)"
    if [ -n "${LISTEN_HOST:-}" ] && [ "$LISTEN_HOST" != "*" ] && [ "$LISTEN_HOST" != "0.0.0.0" ] && [ "$LISTEN_HOST" != "::" ] && [ "$LISTEN_HOST" != "[::]" ]; then
        probe_host="$(format_host_for_url "$LISTEN_HOST")"
    elif [ "${TCP_FAMILY:-}" = "6" ]; then
        probe_host="[::1]"
    fi
    if [ -x "$BIN_PATH" ]; then
        local out fp
        out="$(timeout 8 "$BIN_PATH" fingerprint "nowhere://${SHARED_KEY}@${probe_host}:${port}?morph=${MORPH}" 2>/dev/null || true)"
        fp="$(echo "$out" | grep -oE '[0-9a-f]{64}' | head -1 || true)"
        if [ -n "$fp" ]; then
            _CACHED_TLS_FP="$fp"
            echo "$fp"
            return 0
        fi
    fi
    # Morph 开启时 TLS 包在 Morph 信封里，openssl s_client 不可能握手成功，
    # 旧版会在这里白等 5 轮（最长约 45 秒）再失败
    if [ "${MORPH:-1}" = "1" ]; then return 1; fi
    local sni="${PUBLIC_HOST:-localhost}"
    local fingerprint output
    for _ in 1 2 3 4 5; do
        output="$(timeout 8 openssl s_client -connect "${probe_host}:${port}" \
            -servername "$sni" -showcerts </dev/null 2>/dev/null \
            | openssl x509 -noout -fingerprint -sha256 2>/dev/null || true)"
        fingerprint="${output#*=}"
        if [[ -n "$fingerprint" && "$fingerprint" != "$output" ]]; then
            fingerprint="$(echo "$fingerprint" | tr -d ':' | tr 'A-F' 'a-f')"
            _CACHED_TLS_FP="$fingerprint"
            echo "$fingerprint"
            return 0
        fi
        sleep 1
    done
    return 1
}

print_tls_fingerprint() {
    if [[ "$TLS_MODE" == "2" ]]; then
        # tls=2：直接对证书文件算指纹（需要 pin= 的对端在证书续期后要同步更新）
        if [[ -n "${CRT:-}" && -f "$CRT" ]]; then
            local fp2
            fp2="$(openssl x509 -in "$CRT" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f' || true)"
            if [ -n "$fp2" ]; then
                echo
                info "$(L '当前 tls=2 证书 SHA-256 指纹（续期后会变化）：')"
                echo -e "  ${GREEN}${fp2}${NC}"
            fi
        fi
        return 0
    fi
    if [[ "$TLS_MODE" != "1" ]]; then
        return 0
    fi
    if ! has_tcp; then
        # 纯 QUIC/UDP：先走日志兜底，能取到就直接打印，取不到再提示手动查日志
        local journal_fp
        journal_fp="$(get_tls_fingerprint 2>/dev/null || true)"
        if [ -n "$journal_fp" ]; then
            echo
            info "$(L '已从当前服务启动日志读取到自签证书 SHA-256 指纹：')"
            echo -e "  ${GREEN}${journal_fp}${NC}"
            warn "$(L 'tls=1 证书只存在内存中，Nowhere 每次重启后指纹都会变化，pin= 需同步重新生成（Nowhere 菜单 4 或 pz 命令）')"
        else
            warn "$(L '当前为纯 QUIC/UDP Portal，没有 TLS 监听，且启动日志中未找到指纹')"
            warn "$(L '自签模式下 Vector/Egress 的 pin 请从 Portal 启动日志含 fingerprint 的一行获取')"
        fi
        return 0
    fi
    echo
    info "$(L '正在获取自签证书 SHA-256 指纹...')"
    local fingerprint
    fingerprint="$(get_tls_fingerprint || true)"
    if [ -n "$fingerprint" ]; then
        echo -e "  ${GREEN}${fingerprint}${NC}"
        warn "$(L 'tls=1 证书只存在内存中，Nowhere 每次重启后指纹都会变化，pin= 需同步重新生成（Nowhere 菜单 4 或 pz 命令）')"
    else
        warn "$(L '暂未获取到指纹，可稍后运行: journalctl -u nowhere -n 100') | grep fingerprint"
    fi
}

ensure_ipv4_preference() {
    local has_ipv6_addr=false
    if ip -6 addr show scope global 2>/dev/null | awk '/inet6/{f=1} END{exit !f}'; then
        has_ipv6_addr=true
    fi

    [ "$has_ipv6_addr" = false ] && return 0

    info "$(L '检测到本机配置了 IPv6 地址，测试实际是否能连通外网...')"
    if secure_curl -6 -fsS --max-time 5 https://www.cloudflare.com >/dev/null 2>&1; then
        success "$(L 'IPv6 连通性正常，无需调整')"
        return 0
    fi

    warn "$(L 'IPv6 地址已配置，但实际无法连通外网（VPS常见问题：分配了地址却未正确路由）')"
    warn "$(L '这会导致 curl/certbot 优先尝试 IPv6 而报错') 'Network is unreachable'"

    if ! grep -q "^precedence ::ffff:0:0/96" /etc/gai.conf 2>/dev/null; then
        mkdir -p "$(dirname "$GAI_BACKUP")"
        if [ ! -e "$GAI_BACKUP" ] && [ ! -e "${GAI_BACKUP}.absent" ]; then
            if [ -f /etc/gai.conf ]; then
                cp -a /etc/gai.conf "$GAI_BACKUP"
            else
                : > "${GAI_BACKUP}.absent"
            fi
        fi
        info "$(L '写入 /etc/gai.conf，让系统优先选用 IPv4（不关闭IPv6，只调整地址选择优先级）')"
        [ -n "$(tail -c 1 /etc/gai.conf 2>/dev/null)" ] && echo >> /etc/gai.conf
        echo "precedence ::ffff:0:0/96  100" >> /etc/gai.conf
    fi

    if secure_curl -fsS --max-time 5 https://acme-v02.api.letsencrypt.org/directory >/dev/null 2>&1; then
        success "$(L '已修正为 IPv4 优先，现在可以正常连接 Let')'s Encrypt"
    else
        warn "$(L '调整后仍无法连接，请检查 VPS 出网本身是否正常: ping -c 3 8.8.8.8')"
    fi
}

# 确保管理脚本副本存在于 MANAGER_PATH（快捷命令和 Snell 自动更新定时器都依赖它）。
# 一律"先写临时文件再 install 覆盖"：install 会换一个新 inode，另一个会话里正在运行的
# 旧副本不会被原地改写而执行错乱（旧版用 cp / curl -o 直接覆盖，存在这个问题）。
ensure_manager_copy() {
    local self_path tmp
    self_path="$(readlink -f "$0" 2>/dev/null || true)"

    if [ -z "$self_path" ] || [ ! -f "$self_path" ] || ! grep -q "Adam Nowhere" "$self_path" 2>/dev/null; then
        # 管道/进程替换运行：$0 指向 /dev/fd/63、bash 或匿名管道，无法直接复制自身。
        # 复用 script_fetch_remote：强制 HTTPS TLS1.2、防缓存击穿、结尾截断校验、bash -n 与官方 .sha256 校验。
        info "$(L '通过管道/进程替换运行，无法直接复制自身，正在从脚本地址重新下载一份...')"
        make_workdir || return 1
        tmp="${WORKDIR}/adam-manager.sh"
        if ! script_fetch_remote "$tmp"; then
            rm -f "$tmp"
            warn "$(L '重新下载脚本失败，管理脚本副本无法安装')"
            warn "$(L '请改用文件方式运行：curl -fsSL') ${SCRIPT_URL} -o ${MANAGER_PATH} && chmod +x ${MANAGER_PATH} && ${MANAGER_PATH}"
            return 1
        fi
        install -m 755 "$tmp" "$MANAGER_PATH"
        rm -f "$tmp"
        self_path="$MANAGER_PATH"
        local remote_ver
        remote_ver="${REMOTE_SCRIPT_VERSION:-$(grep -m1 '^SCRIPT_VERSION=' "$MANAGER_PATH" 2>/dev/null | cut -d'"' -f2 || true)}"
        if [ -n "${SCRIPT_VERSION:-}" ] && [ -n "$remote_ver" ] && [ "${remote_ver#v}" != "${SCRIPT_VERSION#v}" ]; then
            warn "$(L '注意：下载到的脚本版本为') ${remote_ver}$(L '，与当前运行的') ${SCRIPT_VERSION} $(L '不一致（可能新版尚未推送到') ${SCRIPT_URL}$(L '），管理命令将指向下载到的版本')"
        fi
    fi

    if [ "$self_path" != "$MANAGER_PATH" ]; then
        install -m 755 "$self_path" "$MANAGER_PATH"
    fi
    chmod +x "$MANAGER_PATH"
    return 0
}

# 校验快捷命令与管理脚本副本是否就绪（安装/重配结束时调用；只警告，不中断安装）
verify_shortcuts() {
    if [ -x /usr/local/bin/adam ] && [ -x "$MANAGER_PATH" ]; then
        success "$(L '快捷命令已就绪：输入 adam 打开菜单')"
        return 0
    fi
    warn "$(L '快捷命令未能安装（服务本身不受影响）')"
    info "$(L '修复：重新运行安装脚本文件，或执行：')"
    echo "  curl -fsSL ${SCRIPT_URL} -o ${MANAGER_PATH} && chmod +x ${MANAGER_PATH} && ${MANAGER_PATH} shortcuts"
    return 1
}

install_shortcuts() {
    local mode="${1:-}"
    if [ "$mode" != "--no-header" ] && [ "$mode" != "--quiet" ]; then
        step "$(L '安装快捷命令')"
        divider
    fi
    if ! ensure_manager_copy; then
        [ "$mode" = "--quiet" ] || warn "$(L '快捷命令无法安装')"
        return 1
    fi

    # 快捷命令只是薄壳：先校验管理脚本副本在位，缺失时给出修复方法而不是报看不懂的错
    local spec name args
    for spec in "adam:" "zt:status" "pz:config" "cxpz:reconfig" "cq:restart"; do
        name="${spec%%:*}"; args="${spec#*:}"
        cat > "/usr/local/bin/${name}" << SHORTEOF
#!/bin/bash
if [ ! -x "${MANAGER_PATH}" ]; then
    echo "管理脚本副本缺失：${MANAGER_PATH}" >&2
    echo "修复：重新运行安装脚本文件，或执行：" >&2
    echo "  curl -fsSL ${SCRIPT_URL} -o ${MANAGER_PATH} && chmod +x ${MANAGER_PATH} && ${MANAGER_PATH} shortcuts" >&2
    exit 1
fi
exec "${MANAGER_PATH}" ${args} "\$@"
SHORTEOF
        chmod +x "/usr/local/bin/${name}"
    done

    local missing=0 n
    for n in adam zt pz cxpz cq; do
        [ -x "/usr/local/bin/${n}" ] || missing=1
    done
    [ -x "$MANAGER_PATH" ] || missing=1
    if [ "$missing" = "1" ]; then
        [ "$mode" = "--quiet" ] || warn "$(L '快捷命令安装失败：请检查 /usr/local/bin 是否可写，并确认管理脚本副本存在：')${MANAGER_PATH}"
        return 1
    fi

    if [ "$mode" != "--quiet" ]; then
        success "$(L '快捷命令已安装完成')"
        echo -e "  ${CYAN}adam${NC}   $(L '— 打开管理菜单')"
        echo -e "  ${CYAN}zt${NC}     $(L '— 查看服务状态')"
        echo -e "  ${CYAN}pz${NC}     $(L '— 查看节点/连接信息')"
        echo -e "  ${CYAN}cxpz${NC}   $(L '— 重新修改配置')"
        echo -e "  ${CYAN}cq${NC}     $(L '— 快速重启服务')"
    fi
    return 0
}

# 任意组件安装或首次打开主菜单时自动确保 /usr/local/bin/adam 就绪（已就绪或目录不可写时静默跳过）
ensure_adam_shortcut() {
    [ -x /usr/local/bin/adam ] && [ -x "$MANAGER_PATH" ] && return 0
    local mgr_dir
    mgr_dir="$(dirname "$MANAGER_PATH")"
    [ -w /usr/local/bin ] && [ -w "$mgr_dir" ] || return 0
    if install_shortcuts --quiet >/dev/null 2>&1; then
        info "$(L '快捷命令已自动就绪：以后可直接输入 adam 打开管理菜单')"
    fi
    return 0
}

# ── 证书申请与自动续期（v2 新增/重构） ──────────────────────────
# v4.4: tls=1 证书只存在内存中、无文件可续期，指纹每次重启都会变。
# save_current_pin 把当前指纹写进 ${TLS_PIN_FILE}（600 权限，含更新时间），
# 供重启后对照、给对端更新 pin= 用；config.txt 本身每次查看都会按最新 pin 重建。
# tls=2 走系统 CA 校验不靠 pin，直接返回。取不到指纹时不写旧值、不伪造。
save_current_pin() {
    local fp
    [ "$(current_role)" = "portal" ] || return 0
    [ -f "$CONFIG_FILE" ] || return 0
    load_saved_config 2>/dev/null || return 0
    [ "${TLS_MODE:-}" = "1" ] || return 0
    fp="$(get_tls_fingerprint 2>/dev/null | grep -oE '[0-9a-f]{64}' | head -1 || true)"
    if [ -z "$fp" ]; then
        warn "$(L '未能读取当前自签指纹，')${TLS_PIN_FILE} $(L '未更新（服务刚重启时可稍等再用 Nowhere 菜单 10 查看）')"
        return 1
    fi
    install -d -m 750 "$CONFIG_DIR"
    (
        umask 077
        {
            echo "fingerprint=${fp}"
            echo "updated=$(date '+%Y-%m-%d %H:%M:%S %Z')"
            echo "note=tls=1 fingerprint changes on every restart; Vector/Egress pin= must be updated to this value"
        } > "$TLS_PIN_FILE"
    )
    chmod 600 "$TLS_PIN_FILE"
    nowhere_fix_perms
    info "$(L '自签指纹已更新到') ${TLS_PIN_FILE}$(L '（Vector/Egress 的 pin= 请同步改为新值）')"
    return 0
}


# acme.sh --reloadcmd 调用的同步脚本：重拷证书副本到 ${CONFIG_DIR}/certs 再 restart Nowhere
install_nowhere_cert_sync_script() {
    local script="${CONFIG_DIR}/cert-sync.sh"
    install -d -m 750 "$CONFIG_DIR"
    cat > "$script" << SYNCEOF
#!/bin/bash
# acme.sh reloadcmd: re-sync the service-readable cert copies, then restart Nowhere
if [ -f "${CONFIG_DIR}/nowhere.env" ]; then
    # shellcheck disable=SC1091
    source "${CONFIG_DIR}/nowhere.env" 2>/dev/null || true
fi
_crt="\${CRT_VALUE:-}"; _key="\${KEY_PEM_VALUE:-}"
_dest="${CONFIG_DIR}/certs"
if [ -n "\$_crt" ] && [ -n "\$_key" ] && [ -f "\$_crt" ] && [ -f "\$_key" ] && [ "\$_crt" != "\$_dest/fullchain.pem" ]; then
    install -d -m 750 -o root -g nowhere "\$_dest" 2>/dev/null || install -d -m 750 "\$_dest" 2>/dev/null || true
    install -m 640 -o root -g nowhere "\$_crt" "\$_dest/fullchain.pem" 2>/dev/null || install -m 600 "\$_crt" "\$_dest/fullchain.pem" 2>/dev/null || true
    install -m 640 -o root -g nowhere "\$_key" "\$_dest/privkey.pem" 2>/dev/null || install -m 600 "\$_key" "\$_dest/privkey.pem" 2>/dev/null || true
fi
systemctl restart nowhere 2>/dev/null || true
SYNCEOF
    chmod 700 "$script"
}

# 每日维护兜底：续期后副本与源证书不一致时同步（覆盖 acme.sh/certbot 两路）
nowhere_sync_cert_copy() {
    [ "$(current_role)" = "portal" ] || return 0
    [ -f "$CONFIG_FILE" ] || return 0
    load_saved_config 2>/dev/null || return 0
    [ "${TLS_MODE:-}" = "2" ] || return 0
    local dest="${CONFIG_DIR}/certs"
    [ -d "$dest" ] || return 0
    [ -f "$CRT" ] && [ -f "$KEY_PEM" ] || return 0
    # 源路径与副本路径相同时跳过，避免自己拷贝自己
    [ "$CRT" != "$dest/fullchain.pem" ] || return 0
    if cmp -s "$CRT" "$dest/fullchain.pem" && cmp -s "$KEY_PEM" "$dest/privkey.pem"; then return 0; fi
    install -m 640 -o root -g nowhere "$CRT" "$dest/fullchain.pem" 2>/dev/null || install -m 600 "$CRT" "$dest/fullchain.pem" 2>/dev/null || return 1
    install -m 640 -o root -g nowhere "$KEY_PEM" "$dest/privkey.pem" 2>/dev/null || install -m 600 "$KEY_PEM" "$dest/privkey.pem" 2>/dev/null || return 1
    systemctl restart nowhere 2>/dev/null || true
    info "$(L '证书副本已同步')"
    return 0
}

# restart_nowhere_with_fallback [check_listen]：写 unit 已由调用方完成；这里做
# daemon-reload/enable/restart → 低权回退 → 返回 active/监听状态。
# $1=1 时 Portal 还须校验已配载体端口真实在监听；返回 0=正常，1=异常
restart_nowhere_with_fallback() {
    local check_listen="${1:-0}"
    systemctl daemon-reload
    systemctl enable nowhere 2>/dev/null || true
    systemctl restart nowhere || true
    sleep 3
    if ! systemctl is-active --quiet nowhere && [ "${NOWHERE_USER:-root}" = "nowhere" ]; then
        warn "$(L '低权用户启动失败，回退为 root 运行')"
        sed -i 's/^User=nowhere/User=root/; s/^Group=nowhere/Group=root/' "$SERVICE_FILE"
        systemctl daemon-reload
        systemctl restart nowhere || true
        sleep 3
        NOWHERE_USER="root"
    fi
    systemctl is-active --quiet nowhere || return 1
    if [ "$check_listen" = "1" ] && [ "$(current_role)" = "portal" ]; then
        if has_tcp && ! tcp_listening "$(tcp_port)"; then return 1; fi
        if has_udp && ! udp_listening "$(udp_port)"; then return 1; fi
    fi
    return 0
}

# 证书是否覆盖指定域名：逐个 SAN 精确比对，并支持一级通配符（*.example.com）。
# 旧版用 grep "DNS:${domain}" 做子串匹配：会把 example.com.evil.org 之类前缀相同的名字当成匹配，
# 也识别不了通配符证书。
# 统一询问 Cloudflare 凭证：先问认证方式（1=Global API Key，2=API Token 建议），
# Token 只需 Token，Global Key 才需邮箱。成功时设置 CF_AUTH_TYPE(1/2)、CF_EMAIL、CF_KEY；失败返回 1
prompt_cloudflare_creds() {
    local choice key email
    echo "  1) $(L 'Global API Key（需邮箱）')"
    echo "  2) $(L 'API Token（建议，只需 Token，需 Zone:DNS:Edit 权限）')"
    while true; do
        read -rp "$(L '选择') [$(L '1/2，默认2')]: " choice || { [ -n "$choice" ] || return 1; }
        case "${choice:-2}" in
            1) CF_AUTH_TYPE="1"; break ;;
            2) CF_AUTH_TYPE="2"; break ;;
            *) warn "$(L '无效选择')" ;;
        esac
    done
    if [ "$CF_AUTH_TYPE" = "1" ]; then
        while true; do
            read -rp "Cloudflare Email ($(L '输入 q 取消')): " email || { [ -n "$email" ] || return 1; }
            email="$(printf '%s' "$email" | tr -d ' \r\n')"
            [ "$email" = "q" ] && return 1
            [ -n "$email" ] && break
            warn "$(L 'Cloudflare 邮箱不能为空')"
        done
        CF_EMAIL="$email"
    else
        CF_EMAIL=""
    fi
    while true; do
        read -rsp "$(L 'Cloudflare API Token（建议）或 Global API Key（输入不回显）:') " key || { [ -n "$key" ] || return 1; }; echo
        key="$(printf '%s' "$key" | tr -d ' \r\n')"
        [ "$key" = "q" ] && return 1
        [ -n "$key" ] && break
        warn "$(L 'Cloudflare 凭证不能为空')"
    done
    CF_KEY="$key"
    return 0
}

# 按 CF_AUTH_TYPE 写 /etc/cloudflare/credentials.ini（Token 只写 token，Global Key 写邮箱+key），600
write_cloudflare_creds() {
    install -d -m 700 /etc/cloudflare
    local _cftmp=""
    (
        umask 077
        _cftmp="$(mktemp /etc/cloudflare/.creds.XXXXXX)" || exit 1
        if [ "${CF_AUTH_TYPE:-2}" = "1" ]; then
            printf 'dns_cloudflare_email = %s\ndns_cloudflare_api_key = %s\n' "$CF_EMAIL" "$CF_KEY" > "$_cftmp"
        else
            printf 'dns_cloudflare_api_token = %s\n' "$CF_KEY" > "$_cftmp"
        fi
        chmod 600 "$_cftmp"
        mv -f "$_cftmp" /etc/cloudflare/credentials.ini
    )
    chmod 600 /etc/cloudflare/credentials.ini 2>/dev/null || true
}

# 整文件重写 nowhere.env（与 do_install 原 heredoc 内容一致，敏感值走 dq_escape）。
# 调用前须保证各 *_VALUE 全局变量已就位（do_install 向导结束时、do_migrate_tls2 已 load_saved_config 并改好待变项）。
write_portal_env() {
    local _wpe_tmp=""
    _wpe_tmp="$(mktemp "${CONFIG_DIR}/.nowhere.env.XXXXXX")" || return 1
    cat > "$_wpe_tmp" << ENVEOF
NOWHERE_PORTAL="${NOWHERE_PORTAL}"
DOMAIN_VALUE="${DOMAIN}"
PUBLIC_HOST_VALUE="${PUBLIC_HOST}"
LISTEN_HOST_VALUE="${LISTEN_HOST}"
PORT_MODE_VALUE="${PORT_MODE}"
PORT_VALUE="${PORT}"
TCP_PORT_VALUE="${TCP_PORT}"
UDP_PORT_VALUE="${UDP_PORT}"
SHARED_KEY_VALUE="${SHARED_KEY}"
NET_VALUE="${NET}"
TLS_MODE_VALUE="${TLS_MODE}"
CERT_METHOD_VALUE="${CERT_METHOD}"
CRT_VALUE="${CRT:-}"
KEY_PEM_VALUE="${KEY_PEM:-}"
CRT_RUNTIME_VALUE="${CRT_RUNTIME:-${CRT:-}}"
KEY_PEM_RUNTIME_VALUE="${KEY_PEM_RUNTIME:-${KEY_PEM:-}}"
OUT_TYPE_VALUE="${OUT_TYPE}"
SOCKS_VALUE="$(dq_escape "$SOCKS")"
DIAL_MODE_VALUE="${DIAL_MODE}"
DIAL_VALUE="${DIAL}"
DIAL4_VALUE="${DIAL4}"
DIAL6_VALUE="${DIAL6}"
RATE_VALUE="${RATE}"
ETAR_VALUE="${ETAR}"
MORPH_VALUE="${MORPH}"
MORPH_TCP_PRELUDE_VALUE="${MORPH_TCP_PRELUDE}"
HANDSHAKE_TIMEOUT_VALUE="${HANDSHAKE_TIMEOUT}"
TCP_FAMILY_VALUE="${TCP_FAMILY}"
UDP_FAMILY_VALUE="${UDP_FAMILY}"
EGRESS_DIAL_VALUE="${EGRESS_DIAL}"
EGRESS_DIAL_MODE_VALUE="${EGRESS_DIAL_MODE}"
EGRESS_DIAL4_VALUE="${EGRESS_DIAL4}"
EGRESS_DIAL6_VALUE="${EGRESS_DIAL6}"
EGRESS_CARRIER_VALUE="${EGRESS_CARRIER}"
MORPH_UDP_PRELUDE_VALUE="${MORPH_UDP_PRELUDE}"
GENERATE_VECTOR_VALUE="${GENERATE_VECTOR}"
VECTOR_CARRIER_VALUE="${VECTOR_CARRIER}"
VECTOR_SOCKS_VALUE="$(dq_escape "$VECTOR_SOCKS")"
GENERATE_EGRESS_VALUE="${GENERATE_EGRESS}"
ENVEOF
    chmod 600 "$_wpe_tmp" || { rm -f "$_wpe_tmp"; return 1; }
    mv -f "$_wpe_tmp" "$CONFIG_FILE" || { rm -f "$_wpe_tmp"; return 1; }
    chmod 600 "$CONFIG_FILE"
}

# ensure_system_user name [group]：建组+建用户（--system, nologin, no-create-home）；已存在返回 0；失败返回 1
ensure_system_user() {
    local name="$1" grp="${2:-$1}"
    getent group "$grp" >/dev/null 2>&1 || groupadd --system "$grp" 2>/dev/null || return 1
    if ! id "$name" >/dev/null 2>&1; then
        useradd --system --gid "$grp" --no-create-home --shell /usr/sbin/nologin "$name" 2>/dev/null || return 1
    fi
    return 0
}

# 为 Portal 创建专用低权用户 nowhere（新装/重配时）。任一步失败回退 root，不中断安装。
# 成功时设置 NOWHERE_USER="nowhere"；失败时 NOWHERE_USER="root"
setup_nowhere_user() {
    NOWHERE_USER="root"
    command -v useradd >/dev/null 2>&1 || return 0
    if ! ensure_system_user nowhere; then warn "$(L '创建专用低权用户失败，继续以 root 运行')"; return 0; fi
    install -d -m 750 -o root -g nowhere "$CONFIG_DIR" 2>/dev/null || { warn "$(L '创建专用低权用户失败，继续以 root 运行')"; return 0; }
    NOWHERE_USER="nowhere"
    return 0
}

# v8.6：收敛 Nowhere 敏感配置与证书副本权限（不跟随符号链接；无论 nowhere 用户是否存在都强制 chmod）
nowhere_fix_perms() {
    local grp="root" f
    getent group nowhere >/dev/null 2>&1 && grp="nowhere"
    if [ -d "$CONFIG_DIR" ] && [ ! -L "$CONFIG_DIR" ]; then
        chown -h "root:${grp}" "$CONFIG_DIR" 2>/dev/null || true
        chmod 750 "$CONFIG_DIR" 2>/dev/null || true
    fi
    if [ -d "${CONFIG_DIR}/certs" ] && [ ! -L "${CONFIG_DIR}/certs" ]; then
        chown -h "root:${grp}" "${CONFIG_DIR}/certs" 2>/dev/null || true
        chmod 750 "${CONFIG_DIR}/certs" 2>/dev/null || true
        find "${CONFIG_DIR}/certs" -mindepth 1 -type d ! -type l -exec chown -h "root:${grp}" {} + -exec chmod 750 {} + 2>/dev/null || true
        find "${CONFIG_DIR}/certs" -mindepth 1 -type f ! -type l -exec chown -h "root:${grp}" {} + -exec chmod 640 {} + 2>/dev/null || true
    fi
    for f in "$CONFIG_FILE" "$EGRESS_CONFIG_FILE" "$TLS_PIN_FILE" "${CONFIG_DIR}/config.txt" "$EGRESS_CONFIG_TXT" "$INSTALL_DRAFT_FILE"; do
        [ -f "$f" ] && [ ! -L "$f" ] || continue
        chown -h root:root "$f" 2>/dev/null || true
        chmod 600 "$f" 2>/dev/null || true
    done
    for f in "$ROLE_FILE" "$VERSION_FILE" "$PREV_VERSION_FILE"; do
        [ -f "$f" ] && [ ! -L "$f" ] || continue
        chown -h root:root "$f" 2>/dev/null || true
        chmod 644 "$f" 2>/dev/null || true
    done
    if [ -f "$BIN_PATH" ] && [ ! -L "$BIN_PATH" ]; then
        chown -h root:root "$BIN_PATH" 2>/dev/null || true
        chmod 755 "$BIN_PATH" 2>/dev/null || true
    fi
    return 0
}

# 写出 Portal 的 systemd unit：HANDSHAKE_TIMEOUT 为空或 auto 时省略 NOW_HANDSHAKE_TIMEOUT（启用 v3.3.0 官方按密钥派生 3–30s）
nowhere_write_portal_unit() {
    local extra="EnvironmentFile=${CONFIG_FILE}"
    if [ -n "${HANDSHAKE_TIMEOUT:-}" ] && [ "$HANDSHAKE_TIMEOUT" != "auto" ]; then
        extra="${extra}
Environment=NOW_HANDSHAKE_TIMEOUT=${HANDSHAKE_TIMEOUT}"
    fi
    extra="${extra}
PrivateTmp=false
ProtectSystem=full
ProtectHome=read-only"
    write_service_unit "$SERVICE_FILE" "Nowhere Portal" "https://github.com/${REPO}" "" "${NOWHERE_USER:-root}" "${NOWHERE_USER:-root}" "${BIN_PATH} \${NOWHERE_PORTAL}" "CAP_NET_BIND_SERVICE" "1048576" "on-failure" "3" "$extra"
}

# 一键修复核心逻辑（quiet 模式供看门狗二段自愈调用）
_nowhere_repair_core() {
    local quiet="${1:-}" role
    [ -x "$BIN_PATH" ] || return 1
    role="$(current_role)"
    setup_nowhere_user || true
    if [ "$role" = "egress" ]; then
        [ -f "$EGRESS_CONFIG_FILE" ] || return 1
        local eg_pre="fade"
        eg_pre="$(awk -F= '/^EGRESS_PRELUDE=/{gsub(/"/,"",$2); print $2; exit}' "$EGRESS_CONFIG_FILE" 2>/dev/null || true)"
        case "$eg_pre" in fade|full8|low7) ;; *) eg_pre="fade" ;; esac
        write_service_unit "$SERVICE_FILE" "Nowhere Egress" "https://github.com/${REPO}" "" "${NOWHERE_USER:-root}" "${NOWHERE_USER:-root}" "${BIN_PATH} \${NOWHERE_EGRESS}" "" "1048576" "on-failure" "3" "EnvironmentFile=${EGRESS_CONFIG_FILE}
Environment=NOW_MORPH_TCP_PRELUDE=${eg_pre}
Environment=NOW_MORPH_UDP_PRELUDE=${eg_pre}
PrivateTmp=false
ProtectSystem=full
ProtectHome=read-only"
        nowhere_fix_perms
        systemctl daemon-reload
        systemctl reset-failed nowhere >/dev/null 2>&1 || true
        maint_install_timers || true
        restart_nowhere_with_fallback 0
        return $?
    fi
    # Portal 角色
    [ -f "$CONFIG_FILE" ] || return 1
    load_saved_config 2>/dev/null || return 1
    sanitize_nowhere_params
    if [ "$NOWHERE_USER" = "nowhere" ]; then
        sync_portal_cert_copy || { NOWHERE_USER="root"; CRT_RUNTIME="${CRT:-}"; KEY_PEM_RUNTIME="${KEY_PEM:-}"; }
    else
        CRT_RUNTIME="${CRT:-}"
        KEY_PEM_RUNTIME="${KEY_PEM:-}"
    fi
    NOWHERE_PORTAL="$(build_portal_url)"
    write_portal_env || return 1
    nowhere_write_portal_unit || return 1
    nowhere_fix_perms
    systemctl daemon-reload
    systemctl reset-failed nowhere >/dev/null 2>&1 || true
    reserved_ports_sync || true
    if ufw_active; then
        if has_tcp; then ufw allow "$(tcp_port)/tcp" >/dev/null 2>&1 || true; fi
        if has_udp; then ufw allow "$(udp_port)/udp" >/dev/null 2>&1 || true; fi
        if [ "${CERT_METHOD:-}" = "letsencrypt-http" ]; then ufw allow 80/tcp >/dev/null 2>&1 || true; fi
    fi
    maint_install_timers || true
    if ! restart_nowhere_with_fallback 1; then
        return 1
    fi
    if [ "${TLS_MODE:-}" = "1" ]; then
        save_current_pin >/dev/null 2>&1 || true
    fi
    nowhere_healthy
}

# Nowhere 一键修复（用户菜单 / CLI 入口）
nowhere_repair() {
    step "$(L 'Nowhere 一键修复')"
    divider
    if [ ! -x "$BIN_PATH" ]; then
        warn "$(L '未找到 Nowhere 二进制，请先安装')"
        return 1
    fi
    if _nowhere_repair_core; then
        success "$(L 'Nowhere 修复完成，服务运行正常')"
        return 0
    fi
    warn "$(L '修复后 Nowhere 仍未正常启动或监听，最近日志：')"
    journalctl -u nowhere -n 20 --no-pager 2>/dev/null || true
    return 1
}

# tls=2 时把源证书复制到 CONFIG_DIR/certs 供低权用户读取（User=nowhere 读不到 /etc/letsencrypt 的私钥）。
# 保持 CRT/KEY_PEM 为原始源路径不变，将副本路径写入 CRT_RUNTIME/KEY_PEM_RUNTIME（供 Portal URL 使用）。
sync_portal_cert_copy() {
    CRT_RUNTIME="${CRT:-}"
    KEY_PEM_RUNTIME="${KEY_PEM:-}"
    [ "${TLS_MODE:-}" = "2" ] || return 0
    [ -f "$CRT" ] && [ -f "$KEY_PEM" ] || return 1
    local dest="${CONFIG_DIR}/certs"
    install -d -m 750 -o root -g nowhere "$dest" 2>/dev/null || return 1
    if [ "$CRT" != "$dest/fullchain.pem" ]; then
        install -m 640 -o root -g nowhere "$CRT" "$dest/fullchain.pem" 2>/dev/null || return 1
    fi
    if [ "$KEY_PEM" != "$dest/privkey.pem" ]; then
        install -m 640 -o root -g nowhere "$KEY_PEM" "$dest/privkey.pem" 2>/dev/null || return 1
    fi
    CRT_RUNTIME="$dest/fullchain.pem"
    KEY_PEM_RUNTIME="$dest/privkey.pem"
    return 0
}

cert_covers_domain() {
    local crt="$1" domain="${2,,}" sans name wild
    sans="$(openssl x509 -in "$crt" -noout -ext subjectAltName 2>/dev/null | tr ',' '\n' | sed -n 's/^[[:space:]]*DNS://p' || true)"
    wild="*.${domain#*.}"
    while IFS= read -r name; do
        [ -n "$name" ] || continue
        name="${name,,}"
        if [ "$name" = "$domain" ] || [ "$name" = "$wild" ]; then return 0; fi
    done <<< "$sans"
    return 1
}

# cert_key_matches crt key：证书与私钥是否匹配（公钥比对）
cert_key_matches() {
    local crt="$1" key="$2"
    openssl x509 -in "$crt" -noout -pubkey 2>/dev/null | \
        cmp -s - <(openssl pkey -in "$key" -pubout 2>/dev/null)
}

# cert_covers crt domain [days]：证书覆盖域名（SAN）且剩余有效期 > days 天（默认 0）
cert_covers() {
    local crt="$1" domain="$2" days="${3:-0}"
    openssl x509 -in "$crt" -noout -checkend "$(( days * 86400 ))" >/dev/null 2>&1 || return 1
    cert_covers_domain "$crt" "$domain"
}

# 证书有效性：文件存在、私钥匹配、SAN/CN 含域名、剩余有效期 > 30 天
cert_is_valid() {
    local domain="$1" crt="$2" key="$3"
    [ -n "$domain" ] && [ -f "$crt" ] && [ -f "$key" ] || return 1
    cert_key_matches "$crt" "$key" || return 1
    cert_covers "$crt" "$domain" 30 && return 0
    # CN 兜底保留在 cert_is_valid 里：SAN 未覆盖时，CN 等于域名且剩余 >30 天仍算有效
    openssl x509 -in "$crt" -noout -checkend 2592000 >/dev/null 2>&1 || return 1
    local cn
    cn="$(openssl x509 -in "$crt" -noout -subject 2>/dev/null | sed -n 's/.*CN *= *\([^,\/]*\).*/\1/p' || true)"
    [ "${cn,,}" = "${domain,,}" ] && return 0
    return 1
}

# 证书剩余有效天数（整数）；取不到返回非 0
cert_expiry_days() {
    local crt="$1" end_str end_s now_s
    [ -f "$crt" ] && [ -r "$crt" ] || return 1
    end_str="$(openssl x509 -in "$crt" -noout -enddate 2>/dev/null | cut -d= -f2- || true)"
    [ -n "$end_str" ] || return 1
    end_s="$(date -d "$end_str" +%s 2>/dev/null)" || return 1
    [ -n "$end_s" ] || return 1
    now_s="$(date +%s)"
    echo $(( (end_s - now_s) / 86400 ))
}

# 签发后校验：文件存在、未过期、私钥匹配、SAN 含域名
verify_issued_cert() {
    local domain="$1" crt="$2" key="$3" days
    [ -f "$crt" ] && [ -f "$key" ] || { warn "$(L '证书文件未生成：')${crt}"; return 1; }
    openssl x509 -in "$crt" -noout -checkend 0 >/dev/null 2>&1 || { warn "$(L '证书已过期或无法解析')"; return 1; }
    if ! cert_key_matches "$crt" "$key"; then
        warn "$(L '证书与私钥不匹配')"
        return 1
    fi
    if ! cert_covers "$crt" "$domain" 0; then
        warn "$(L '证书 SAN 中不包含域名') ${domain}$(L '（可能签发了错误的域名）')"
        openssl x509 -in "$crt" -noout -ext subjectAltName 2>/dev/null || true
        return 1
    fi
    days="$(cert_expiry_days "$crt" || echo "?")"
    success "$(L '证书校验通过：')${domain}$(L '，剩余有效期约') ${days} $(L '天')"
    return 0
}

# HTTP-01 前的 DNS 预检：只告警不中断（DNS 可能正在传播）
check_domain_dns() {
    local domain="$1" myip resolved=""
    myip="$(detect_public_host)"
    if command -v dig >/dev/null 2>&1; then
        resolved="$(dig +short "$domain" A 2>/dev/null | grep -E '^[0-9.]+$' | head -1 || true)"
    else
        resolved="$(getent ahosts "$domain" 2>/dev/null | awk '{print $1}' | grep -E '^[0-9.]+$' | head -1 || true)"
    fi
    if [ -z "$resolved" ]; then
        warn "$(L '域名') ${domain} $(L '当前解析不到任何 A 记录（DNS 未生效或拼写错误），HTTP-01 很可能失败')"
        return 1
    fi
    if [ -n "$myip" ] && [ "$resolved" != "$myip" ]; then
        warn "$(L '域名') ${domain} $(L '解析到') ${resolved}$(L '，但本机公网 IP 疑似') ${myip}$(L '：两者不一致时 HTTP-01 会失败')"
        warn "$(L '若刚修改 DNS，请确认已传播：dig +short') ${domain}$(L '（或等待 10-30 分钟后重试）')"
        return 1
    fi
    success "$(L 'DNS 预检通过：')${domain} -> ${resolved}"
    return 0
}

# 发布包 SHA256 校验（v3 修订：改为“能取到官方校验值就必须通过”）：
# 1) 首选 GitHub Release API 返回的资产 digest（sha256:...，官方发布即带，所有版本可查）；
# 2) 兜底仓库校验文件——旧实现用 sha256sum -c 按校验文件里的原名找文件，
#    而下载到本地的文件名是 nowhere.tar.gz，永远对不上（且上游根本未提供校验文件，旧逻辑恒跳过）；
#    新实现提取哈希字段与本地实算值直接比对，不依赖文件名；
# 3) 两者都取不到时才告警跳过。
verify_release_checksum() {
    local tag="$1" workdir="$2"
    local tarball="${workdir}/nowhere.tar.gz"
    [ -f "$tarball" ] || { warn "$(L '校验时找不到已下载的安装包')"; return 1; }
    local actual digest=""
    actual="$(sha256sum "$tarball" | awk '{print $1}')"

    # v8.6：统一走 github_asset_sha256（Python / 纯 awk / expanded_assets 限流兜底）
    digest="$(github_asset_sha256 "$REPO" "$tag" "$BIN_NAME" || true)"
    if [ -n "$digest" ]; then
        if [ "$digest" = "$actual" ]; then
            success "$(L 'SHA256 校验通过（GitHub 官方资产 digest）')"
            return 0
        fi
        warn "$(L 'SHA256 校验失败：官方 digest=')${digest}$(L '，本地实算=')${actual}$(L '，安装包可能被篡改或下载损坏')"
        return 1
    fi

    local sumfile url expected
    for sumfile in "SHA256SUMS" "sha256sums.txt" "checksums.txt"; do
        url="https://github.com/${REPO}/releases/download/${tag}/${sumfile}"
        secure_curl -fsSL --max-time 15 -o "${workdir}/${sumfile}" "$url" 2>/dev/null || continue
        expected="$(awk -v f="$BIN_NAME" '{fn=$2; sub(/^\*/,"",fn); sub(/^\.\//,"",fn); if(fn==f){print tolower($1); exit}}' "${workdir}/${sumfile}" 2>/dev/null || true)"
        [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || continue
        if [ "$expected" = "$actual" ]; then
            success "$(L 'SHA256 校验通过（')${sumfile}$(L '）')"
            return 0
        fi
        warn "$(L 'SHA256 校验失败（')${sumfile}$(L '）：期望') ${expected}$(L '，实算') ${actual}"
        return 1
    done
    echo -e "${RED}$(L '警告：SHA256 校验已被跳过，安装包未经校验')${NC}" >&2
    warn "$(L '无法取得官方校验值（API digest 与校验文件均不可用），跳过校验（本次经 HTTPS 直连 GitHub 下载）')"
    return 0
}

# certbot 续期 cron 兜底（Nowhere 与 Xray 共用）：规范为 0 3,15 * * * certbot renew --quiet，
# deploy hook 由 renewal-hooks/deploy 自动跑，不再写进 cron 行。
# 清理时：deploy hook 文件在位时可删全部 certbot renew 行（含旧 deploy-hook 行）；
# 否则只删无 deploy-hook 的 plain 行，保留 Portal 的 deploy-hook cron 行（v10 保护，不回归）。
certbot_renewal_cron_ensure() {
    command -v crontab >/dev/null 2>&1 || return 1
    if [ -x /etc/letsencrypt/renewal-hooks/deploy/restart-nowhere.sh ]; then
        (crontab -l 2>/dev/null | grep -v 'certbot renew' || true; echo '0 3,15 * * * certbot renew --quiet') | crontab -
    else
        (crontab -l 2>/dev/null | grep -v 'certbot renew --quiet$' || true; echo '0 3,15 * * * certbot renew --quiet') | crontab -
    fi
}

# obtain_portal_cert：cert_is_valid 复用检查 → 按 CERT_METHOD 分派签发 → 统一 verify_issued_cert + 续期注册
# 调用前须设好 DOMAIN/EMAIL/CERT_METHOD/CRT/KEY_PEM（DNS-01 通用还需 DNS_API）；失败时 error 退出
obtain_portal_cert() {
    if [ "$CERT_METHOD" = "letsencrypt-dns" ]; then
        if [ ! -x "${ACME_HOME}/acme.sh" ]; then
            info "$(L '安装 acme.sh...')"
            if ! secure_curl -fsSL --max-time 60 https://get.acme.sh | bash -s email="${EMAIL}"; then
                warn "$(L 'acme.sh 安装失败，请检查网络后重试')"
                return 1
            fi
        fi
        [ -x "${ACME_HOME}/acme.sh" ] || { warn "$(L 'acme.sh 安装后仍找不到可执行文件（')${ACME_HOME}$(L '/acme.sh）')"; return 1; }
        . "${ACME_HOME}/acme.sh.env" 2>/dev/null || true
    fi
    if [ "$CERT_METHOD" = "cloudflare-dns" ]; then
        if [ -n "${CF_KEY:-}" ]; then
            write_cloudflare_creds
        elif [ ! -s /etc/cloudflare/credentials.ini ]; then
            prompt_cloudflare_creds || return 1
            write_cloudflare_creds
        fi
    fi
    if cert_is_valid "$DOMAIN" "$CRT" "$KEY_PEM"; then
        info "$(L '检测到有效证书（剩余') $(cert_expiry_days "$CRT") $(L '天，域名匹配），跳过申请')"
        if [ "$CERT_METHOD" = "letsencrypt-dns" ]; then
            install_nowhere_cert_sync_script
        fi
    elif [ "$CERT_METHOD" = "letsencrypt-http" ]; then
        if has_tcp && [ "$(tcp_port)" = "80" ]; then
            warn "$(L 'HTTP-01 与 80 端口监听冲突：续期时 certbot 需独占 80 端口，服务将无法同时监听 80')"
        fi
        if tcp_listening 80; then
            warn "$(L '80 端口已被其他进程占用，HTTP-01 签发前请先停掉该服务或改用 DNS-01')"
            systemctl stop nowhere 2>/dev/null || true
            if tcp_listening 80; then warn "$(L '80 端口仍被占用，证书签发已中止')"; return 1; fi
        fi
        info "$(L '申请证书中（HTTP-01，需 80 端口）...')"
        ufw allow 80/tcp 2>/dev/null || true
        if ! certbot certonly \
            --standalone \
            --preferred-challenges http \
            --non-interactive \
            --agree-tos \
            --email "${EMAIL}" \
            -d "${DOMAIN}" \
            --http-01-port 80 --http-01-address 0.0.0.0; then
            warn "$(L '证书申请失败，请检查：1')) $(L '域名是否正确 2')) $(L '80 端口是否对外开放 3')) $(L '域名是否已指向本 VPS（见上方 DNS 预检结果）')"
            return 1
        fi
        verify_issued_cert "$DOMAIN" "$CRT" "$KEY_PEM" || { warn "$(L '证书签发后校验未通过，请看上方告警')"; return 1; }
        success "$(L '证书申请成功')"
    elif [ "$CERT_METHOD" = "cloudflare-dns" ]; then
        info "$(L '申请证书中（Cloudflare DNS-01，约需 30-60 秒）...')"
        if ! certbot certonly \
            --dns-cloudflare \
            --dns-cloudflare-credentials /etc/cloudflare/credentials.ini \
            --non-interactive \
            --agree-tos \
            --email "${EMAIL}" \
            -d "${DOMAIN}" \
            --dns-cloudflare-propagation-seconds 30; then
            warn "$(L '证书申请失败，请检查：1')) $(L 'CF API Key/Token 是否正确 2')) $(L '域名是否在该 CF 账号下 3')) $(L 'Token 是否有 Zone:DNS:Edit 权限')"
            return 1
        fi
        verify_issued_cert "$DOMAIN" "$CRT" "$KEY_PEM" || { warn "$(L '证书签发后校验未通过，请看上方告警')"; return 1; }
        success "$(L '证书申请成功')"
    elif [ "$CERT_METHOD" = "letsencrypt-dns" ]; then
        info "$(L '申请证书中（DNS-01:') ${DNS_API}$(L '；不加 --force，避免重复签发触发 LE 频率限制）...')"
        if ! "${ACME_HOME}/acme.sh" --issue --server letsencrypt -d "${DOMAIN}" --dns "${DNS_API}"; then
            warn "$(L '证书签发失败：请检查 DNS API 凭证是否正确、域名 DNS 是否由所选服务商托管')"
            return 1
        fi
        install -d -m 700 "$(dirname "$CRT")"
        install_nowhere_cert_sync_script
        if ! "${ACME_HOME}/acme.sh" --install-cert -d "${DOMAIN}" \
            --key-file "${KEY_PEM}" \
            --fullchain-file "${CRT}" \
            --reloadcmd "${CONFIG_DIR}/cert-sync.sh"; then
            warn "$(L '证书安装（install-cert）失败')"
            return 1
        fi
        verify_issued_cert "$DOMAIN" "$CRT" "$KEY_PEM" || { warn "$(L '证书签发后校验未通过，请看上方告警')"; return 1; }
        success "$(L '证书申请成功')"
    else
        warn "$(L '未知证书方式')"
        return 1
    fi
    case "$CERT_METHOD" in
        letsencrypt-dns) setup_acmesh_renewal ;;
        *) setup_certbot_renewal ;;
    esac
    return 0
}
# certbot 续期链路：deploy hook + 确保 timer 生效（缺失时 cron 兜底）+ 可选 dry-run 演练
setup_certbot_renewal() {
    mkdir -p /etc/letsencrypt/renewal-hooks/deploy
    cat > /etc/letsencrypt/renewal-hooks/deploy/restart-nowhere.sh << HOOKEOF
#!/bin/bash
# Renewal hook: re-sync the service-readable cert copies (root:nowhere 640 so both root and nowhere can read), then restart
sync_ok=1
if [ -d "${CONFIG_DIR}/certs" ] && [ -f "${CRT}" ] && [ -f "${KEY_PEM}" ] && [ "${CRT}" != "${CONFIG_DIR}/certs/fullchain.pem" ]; then
    install -m 640 -o root -g nowhere "${CRT}" "${CONFIG_DIR}/certs/fullchain.pem" 2>/dev/null \
        || install -m 600 "${CRT}" "${CONFIG_DIR}/certs/fullchain.pem" 2>/dev/null || sync_ok=0
    install -m 640 -o root -g nowhere "${KEY_PEM}" "${CONFIG_DIR}/certs/privkey.pem" 2>/dev/null \
        || install -m 600 "${KEY_PEM}" "${CONFIG_DIR}/certs/privkey.pem" 2>/dev/null || sync_ok=0
fi
if [ "\$sync_ok" = "1" ]; then
    systemctl restart nowhere
else
    echo "nowhere cert copy failed, skip restart to avoid starting with a bad cert" >&2
    logger -t nowhere-renewal "cert copy failed, skipped nowhere restart" 2>/dev/null || true
fi
HOOKEOF
    chmod +x /etc/letsencrypt/renewal-hooks/deploy/restart-nowhere.sh
    # pre/post hook：仅 HTTP-01 且 nowhere 实际占用 80 端口时才停机，避免 DNS-01 或 443 端口场景无故断流
    if [ "$CERT_METHOD" = "letsencrypt-http" ]; then
        mkdir -p /etc/letsencrypt/renewal-hooks/pre /etc/letsencrypt/renewal-hooks/post
        cat > /etc/letsencrypt/renewal-hooks/pre/stop-nowhere.sh << 'HOOKEOF'
#!/bin/bash
if ss -tlnp 2>/dev/null | awk 'NR>1 && /"nowhere"/{n=split($4,a,":"); if(a[n]=="80") f=1} END{exit !f}'; then
    systemctl stop nowhere 2>/dev/null && touch /run/nowhere-stopped-by-certbot
fi
HOOKEOF
        cat > /etc/letsencrypt/renewal-hooks/post/start-nowhere.sh << 'HOOKEOF'
#!/bin/bash
if [ -f /run/nowhere-stopped-by-certbot ]; then
    rm -f /run/nowhere-stopped-by-certbot
    systemctl start nowhere 2>/dev/null || true
fi
HOOKEOF
        chmod +x /etc/letsencrypt/renewal-hooks/pre/stop-nowhere.sh /etc/letsencrypt/renewal-hooks/post/start-nowhere.sh
    else
        rm -f /etc/letsencrypt/renewal-hooks/pre/stop-nowhere.sh /etc/letsencrypt/renewal-hooks/post/start-nowhere.sh /run/nowhere-stopped-by-certbot
    fi
    info "$(L '已安装续期 hook：证书更新后自动 restart nowhere')"

    if systemctl list-unit-files certbot.timer 2>/dev/null | awk '/^certbot\.timer/{f=1} END{exit !f}'; then
        systemctl enable --now certbot.timer 2>/dev/null || warn "$(L 'certbot.timer 启用失败，请手动执行：systemctl enable --now certbot.timer')"
        if systemctl is-active --quiet certbot.timer 2>/dev/null; then
            success "$(L '自动续期已就绪：certbot.timer 运行中（每天两次检查续期）')"
        else
            warn "$(L 'certbot.timer 未在运行，自动续期可能不工作，请手动检查')"
        fi
    else
        warn "$(L '未找到 certbot.timer，改用 cron 兜底（每天 3:00 / 15:00 检查续期）')"
        if certbot_renewal_cron_ensure; then
            success "$(L 'cron 续期任务已写入')"
        else
            warn "$(L 'certbot.timer 未在运行，自动续期可能不工作，请手动检查')"
        fi
    fi

    echo ""
    read -rp "$(L '是否立即做一次续期演练（certbot renew --dry-run，不消耗 LE 配额）？')[Y/n]: " DRYRUN || { [ -n "$DRYRUN" ] || return 1; }
    if [[ ! "${DRYRUN:-y}" =~ ^[Nn]$ ]]; then
        info "$(L '演练中（约需 30-90 秒）...')"
        if certbot renew --dry-run 2>&1 | tail -5; then
            success "$(L '续期演练通过，自动续期链路可信')"
        else
            warn "$(L '续期演练未通过：请根据上方报错排查（如 80 端口被占、DNS 凭证失效），否则证书到期后服务会中断')"
        fi
    else
        warn "$(L '已跳过演练：建议 90 天内用Nowhere 菜单「11')) $(L '检查证书状态 / 手动续期」验证一次')"
    fi
}

# acme.sh 续期链路：确认其自带的 cron 定时任务已就绪
setup_acmesh_renewal() {
    if crontab -l 2>/dev/null | awk '/acme\.sh.*--cron/{f=1} END{exit !f}'; then
        success "$(L '自动续期已就绪：acme.sh 的 cron 定时任务存在（每天检查，到期自动续签并执行 --reloadcmd 重启 nowhere）')"
    else
        warn "$(L '未在 root 的 crontab 中找到 acme.sh 定时任务，自动续期可能不工作')"
        warn "$(L '可手动补加：')(crontab -l 2>/dev/null; echo '0 0 * * * \"${ACME_HOME}/acme.sh\" --cron --home \"${ACME_HOME}\"') | crontab -"
    fi
    info "$(L '当前该域名的证书状态：')"
    "${ACME_HOME}/acme.sh" --list 2>/dev/null | grep -E "Main_Domain|${DOMAIN}" || true
}

# 主菜单时间 + 公网 IP：同一进程内只探测一次，避免每次刷新菜单都等网络
# （直接调用、不包在 $() 里，否则赋值落在子 shell、缓存不生效）
menu_time_ip() {
    if [ -z "${_MENU_PUBLIC_IP_DONE:-}" ]; then
        _MENU_PUBLIC_IP="$(detect_public_host)"
        _MENU_PUBLIC_IP_DONE=1
    fi
    echo -e "  $(L '时间'): $(date '+%Y-%m-%d %H:%M:%S')  IP: ${_MENU_PUBLIC_IP:-$(L '未知')}"
}

menu_status_summary() {
    echo -e "  Nowhere : $(nowhere_state_text)"
    echo -e "  Snell   : $(snell_state_text)"
    echo -e "  Xray    : $(xray_state_text)"
    echo -e "  Realm   : $(realm_state_text)"
    echo -e "  $(L '反代')    : $(proxy_state_text)"
    echo -e "  $(L '防火墙')  : $(fw_state_text)      Fail2ban : $(f2b_state_text)      $(L '保活巡检') : $(maint_timer_state adam-watchdog.timer)"
}

show_menu() {
    clear 2>/dev/null || true
    local b1_l b1_t b1_r b2_l b2_t b2_r
    if [ "${ADAM_LANG:-zh}" = "en" ]; then
        b1_l=14
        b1_t="Adam Nowhere Portal Manager · v${SCRIPT_VERSION}"
        b1_r=$((62 - b1_l - 31 - ${#SCRIPT_VERSION}))
        b2_l=2
        b2_t="Nowhere ${TARGET_NW_VERSION} · Snell v${SNELL_MAJOR} · Xray · Realm · Proxy · Tuning"
        b2_r=$((62 - b2_l - 50 - ${#TARGET_NW_VERSION} - ${#SNELL_MAJOR}))
    else
        b1_l=11
        b1_t="Adam Nowhere Portal 一键管理脚本 · v${SCRIPT_VERSION}"
        b1_r=$((62 - b1_l - 36 - ${#SCRIPT_VERSION}))
        b2_l=4
        b2_t="Nowhere ${TARGET_NW_VERSION} · Snell v${SNELL_MAJOR} · Xray · Realm · 反代 · 调优"
        b2_r=$((62 - b2_l - 47 - ${#TARGET_NW_VERSION} - ${#SNELL_MAJOR}))
    fi
    [ "$b1_r" -lt 0 ] && b1_r=0
    [ "$b2_r" -lt 0 ] && b2_r=0
    echo -e "${BOLD}${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    printf '║%*s%s%*s║\n' "$b1_l" "" "$b1_t" "$b1_r" ""
    printf '║%*s%s%*s║\n' "$b2_l" "" "$b2_t" "$b2_r" ""
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    menu_time_ip
    menu_status_summary
    divider
    echo -e "  ${BOLD}── $(L '协议安装') ──${NC}"
    echo -e "  ${BOLD}1)${NC} $(L 'Nowhere（Portal / Egress：')$(L '安装、配置、连接信息、证书、版本')$(L '）')"
    echo -e "  ${BOLD}2)${NC} Snell v${SNELL_MAJOR}$(L '（')$(L '安装、跟随测试版更新、健康检查、配置')$(L '）')"
    echo -e "  ${BOLD}3)${NC} $(L 'Xray（SS2022 / VLESS：REALITY Vision、XHTTP REALITY、XHTTP CDN、VLESS Encryption）')"
    echo -e "  ${BOLD}── $(L '系统管理') ──${NC}"
    echo -e "  ${BOLD}4)${NC} $(L '脚本更新')$(L '（')$(L '更新本管理脚本 / 重装快捷命令')$(L '）')"
    echo -e "  ${BOLD}5)${NC} $(L '防火墙')$(L '（')$(L 'ufw：安装、放行与删除端口、启停')$(L '）')"
    echo -e "  ${BOLD}6)${NC} $(L 'Fail2ban（')$(L '封禁时长、被封 IP、启停')$(L '）')"
    echo -e "  ${BOLD}7)${NC} $(L '系统调优')$(L '（')$(L 'TCP 调优 tcpfit / XanMod 内核 / DNS / IPv4·IPv6 优先级 / 禁用 IPv6')$(L '）')"
    echo -e "  ${BOLD}8)${NC} $(L '自动维护')$(L '（')$(L '保活巡检 / 脚本与内核自动更新')$(L '）')"
    echo -e "  ${BOLD}9)${NC} Realm $(L '端口转发（TCP / UDP 转发、负载均衡、WS / TLS 隧道）')"
    echo -e "  ${BOLD}10)${NC} $(L '域名反代（Caddy 多域名自动 HTTPS / Cloudflare Tunnel）')"
    echo -e "  ${BOLD}0)${NC} $(L '退出')"
    divider
    if [ -x /usr/local/bin/adam ]; then
        echo -e "  ${YELLOW}$(L '提示：可直接输入')${NC} ${CYAN}adam${NC} ${YELLOW}$(L '唤出此菜单，或用')${NC} ${CYAN}zt${NC}/${CYAN}pz${NC}/${CYAN}cxpz${NC}/${CYAN}cq${NC} ${YELLOW}$(L '快捷执行；')${NC}${CYAN}adam help${NC} ${YELLOW}$(L '查看全部子命令')${NC}"
        divider
    fi
    read -rp "$(L '请选择操作') [0-10]: " MENU_CHOICE || exit 0
}

nowhere_state_text() {
    local role ver
    role="$(current_role)"
    case "$role" in portal) role="Portal" ;; egress) role="Egress" ;; *) role="" ;; esac
    if [ -x "$BIN_PATH" ]; then
        ver="$(read_installed_version)"
        printf '%s' "${ver:-$(L '未知')}${role:+ · ${role}} · $(svc_state nowhere)"
    else
        printf '%s' "${YELLOW}$(L '未安装')${NC}"
    fi
}

nowhere_menu() {
    local choice
    while true; do
        clear 2>/dev/null || true
        echo -e "${BOLD}${CYAN}━━━ Nowhere $(L '管理')$(L '（')${TARGET_NW_VERSION} $(L '/ NW3）') ━━━${NC}"
        echo -e "  $(L '当前状态'): $(nowhere_state_text)"
        divider
        local _tls2_note=""
        if grep -q '^TLS_MODE_VALUE="2"' "$CONFIG_FILE" 2>/dev/null; then _tls2_note="$(L '（当前已是 tls=2）')"; fi
        echo -e "  ${BOLD}── $(L '安装与配置') ──${NC}"
        echo -e "  ${GREEN}1)${NC}  ${GREEN}$(L '安装')${NC} Nowhere Portal$(L '（向导）')"
        echo -e "  ${GREEN}2)${NC}  $(L '本机安装为 Egress 服务')$(L '（出口机用，QUIC 或 TLS 载体）')"
        echo -e "  ${GREEN}3)${NC}  $(L '重新配置')$(L '（修改参数）')"
        echo -e "  ${GREEN}4)${NC}  $(L '查看连接信息 / 导入链接')"
        echo -e "  ${GREEN}5)${NC}  $(L '生成 v3 共享密钥')$(L '（32 位十六进制）')"
        echo -e "  ${BOLD}── $(L '运行与排查') ──${NC}"
        echo -e "  ${GREEN}6)${NC}  $(L '查看服务状态')$(L '（含 nowhere status）')"
        echo -e "  ${GREEN}7)${NC}  $(L '查看实时日志')"
        echo -e "  ${GREEN}8)${NC}  $(L '重启服务')"
        echo -e "  ${GREEN}9)${NC}  $(L '连通性探测 probe')$(L '（真实 TCP Flow 测试）')"
        echo -e "  ${BOLD}── $(L '证书') ──${NC}"
        echo -e "  ${GREEN}10)${NC} $(L '查看证书指纹')$(L '（tls=1 自签 / tls=2 文件证书）')"
        echo -e "  ${GREEN}11)${NC} $(L '检查证书状态 / 手动续期')"
        echo -e "  ${BOLD}── $(L '版本') ──${NC}"
        echo -e "  ${GREEN}12)${NC} $(L '查看当前版本 / 检查更新')"
        echo -e "  ${GREEN}13)${NC} $(L '更新 Nowhere 二进制')$(L '（更新到最新版）')"
        echo -e "  ${GREEN}14)${NC} $(L '选择指定版本')$(L '（版本切换 / 回退到历史版本）')"
        echo -e "  ${GREEN}15)${NC} $(L '快速回退到上一个版本')"
        echo -e "  ${BOLD}──${NC}"
        echo -e "  ${GREEN}16)${NC} ${RED}$(L '卸载')${NC} Nowhere"
        maint_load
        echo -e "  ${GREEN}17)${NC} $(L 'tls=1 升级为真实证书 (tls=2)')${_tls2_note}"
        echo -e "  ${GREEN}18)${NC} $(L 'Nowhere 自动更新（仅 NW3 同代安全更新）') [$(maint_onoff "${MAINT_NOWHERE_AUTO:-0}")]"
        echo -e "  ${GREEN}19)${NC} $(L '一键修复（单元 / 权限 / 证书同步 / 保留端口 / 防火墙）')"
        echo -e "  ${GREEN}0)${NC}  $(L '返回主菜单')"
        divider
        read -rp "$(L '请选择') [0-19]: " choice || return 0
        case "$choice" in
            1)  run_action do_install ;;
            2)  run_action do_install_egress_service ;;
            3)  run_action do_reconfig ;;
            4)  run_action do_show_config ;;
            5)  run_action do_genkey ;;
            6)  run_action do_show_status ;;
            7)  run_action do_show_logs ;;
            8)  run_action do_restart ;;
            9)  run_action do_probe ;;
            10) run_action do_fingerprint ;;
            11) run_action do_cert_status ;;
            12) run_action do_show_version ;;
            13) run_action do_update ;;
            14) run_action do_select_version ;;
            15) run_action do_rollback ;;
            16) run_action do_uninstall ;;
            17) run_action do_migrate_tls2 ;;
            18) run_action maint_toggle MAINT_NOWHERE_AUTO ;;
            19) run_action nowhere_repair ;;
            0)  return 0 ;;
            *)  warn "$(L '无效选择')" ;;
        esac
        pause_return
    done
}

script_menu() {
    local choice
    while true; do
        clear 2>/dev/null || true
        maint_load
        echo -e "${BOLD}${CYAN}━━━ $(L '脚本更新') ━━━${NC}"
        echo -e "  $(L '当前版本'): ${SCRIPT_VERSION}    $(L '每日自动从仓库更新'): $(maint_onoff "$MAINT_SCRIPT_AUTO")"
        divider
        echo -e "  ${GREEN}1)${NC} $(L '立即更新本管理脚本')$(L '（从仓库拉取）')"
        echo -e "  ${GREEN}2)${NC} $(L '每日自动从仓库更新') $(L '开') / $(L '关')"
        echo -e "  ${GREEN}3)${NC} $(L '重装快捷命令')$(L '（adam / zt / pz / cxpz / cq）')"
        echo -e "  ${GREEN}4)${NC} $(L '语言（中文 / English）')"
        echo -e "  ${GREEN}0)${NC} $(L '返回主菜单')"
        divider
        read -rp "$(L '请选择') [0-4]: " choice || return 0
        case "$choice" in
            1) run_action do_update_script ;;
            2) run_action maint_toggle MAINT_SCRIPT_AUTO ;;
            3) run_action install_shortcuts ;;
            4) run_action set_lang_menu ;;
            0) return 0 ;;
            *) warn "$(L '无效选择')" ;;
        esac
        pause_return
    done
}

# 精确检测端口是否被其他进程占用：只比对 ss 第 4 列（本地地址）最后一个冒号后的端口号，
# 不用 grep ":端口\b"（会误命中 IPv6 地址段里的十六进制段）
# check_port_occupied_by_other PROTO PORT [EXCLUDE_PROC，默认 nowhere]
# v8.6（BUG-01）：修复 awk -v own="\"${own}\""（旧版 "\""own"\"" 被 bash 拼成了字面量 "own"，永远不排除自身进程）
check_port_occupied_by_other() {
    local proto="$1" port="$2" own="${3:-nowhere}" flag="-tlnp"
    command -v ss >/dev/null 2>&1 || return 0
    [ "$proto" = "udp" ] && flag="-ulnp"
    ss "$flag" 2>/dev/null | awk -v p="$port" -v own="\"${own}\"" '
        NR == 1 { next }
        own != "\"__none__\"" && index($0, own) > 0 { next }
        {
            n = split($4, a, ":")
            if (a[n] == p) print $0
        }'
}

# ── Nowhere Portal 安装草稿（断点续装）与模块化向导 ─────────────

save_install_draft() {
    install -d -m 750 "$CONFIG_DIR" 2>/dev/null || return 0
    local tmp
    tmp="$(umask 077; mktemp "${CONFIG_DIR}/.draft.XXXXXX" 2>/dev/null || true)"
    [ -n "$tmp" ] || return 0
    ( umask 077; cat > "$tmp" ) << DRAFTEOF
TLS_MODE="${TLS_MODE:-2}"
CERT_METHOD="${CERT_METHOD:-cloudflare-dns}"
DOMAIN="$(dq_escape "${DOMAIN:-}")"
PUBLIC_HOST="$(dq_escape "${PUBLIC_HOST:-}")"
EMAIL="$(dq_escape "${EMAIL:-}")"
DNS_API="$(dq_escape "${DNS_API:-}")"
PORT_MODE="${PORT_MODE:-same}"
PORT="${PORT:-443}"
TCP_PORT="${TCP_PORT:-443}"
UDP_PORT="${UDP_PORT:-443}"
NET="${NET:-mix}"
TCP_FAMILY="${TCP_FAMILY:-}"
UDP_FAMILY="${UDP_FAMILY:-}"
LISTEN_HOST="$(dq_escape "${LISTEN_HOST:-}")"
SHARED_KEY="${SHARED_KEY:-}"
MORPH="${MORPH:-1}"
MORPH_TCP_PRELUDE="${MORPH_TCP_PRELUDE:-fade}"
MORPH_UDP_PRELUDE="${MORPH_UDP_PRELUDE:-fade}"
HANDSHAKE_TIMEOUT="${HANDSHAKE_TIMEOUT:-auto}"
OUT_TYPE="${OUT_TYPE:-direct}"
SOCKS="$(dq_escape "${SOCKS:-none}")"
DIAL_MODE="${DIAL_MODE:-single}"
DIAL="${DIAL:-auto}"
DIAL4="${DIAL4:-auto}"
DIAL6="${DIAL6:-auto}"
RATE="${RATE:-0}"
ETAR="${ETAR:-0}"
GENERATE_VECTOR="${GENERATE_VECTOR:-1}"
VECTOR_CARRIER="${VECTOR_CARRIER:-tcp}"
VECTOR_SOCKS="$(dq_escape "${VECTOR_SOCKS:-$DEFAULT_VECTOR_SOCKS}")"
GENERATE_EGRESS="${GENERATE_EGRESS:-0}"
EGRESS_CARRIER="${EGRESS_CARRIER:-udp}"
EGRESS_DIAL_MODE="${EGRESS_DIAL_MODE:-single}"
EGRESS_DIAL="${EGRESS_DIAL:-auto}"
EGRESS_DIAL4="${EGRESS_DIAL4:-auto}"
EGRESS_DIAL6="${EGRESS_DIAL6:-auto}"
DRAFTEOF
    chmod 600 "$tmp" 2>/dev/null || true
    mv -f "$tmp" "$INSTALL_DRAFT_FILE" 2>/dev/null || rm -f "$tmp"
    return 0
}

load_install_draft() {
    [ -f "$INSTALL_DRAFT_FILE" ] || return 1
    # shellcheck disable=SC1090
    source "$INSTALL_DRAFT_FILE" 2>/dev/null || return 1
    sanitize_nowhere_params
    return 0
}

clear_install_draft() {
    rm -f "$INSTALL_DRAFT_FILE"
}

_nw_prompt_cert_and_net() {
    step "$(L '第 1 步：选择证书获取方式')"
    divider
    echo -e "${BOLD}$(L 'TLS 证书方式：')${NC}"
    echo "  1) $(L '自签证书 tls=1  - 无需域名，快速测试（Vector/Egress 必须用 pin= 锁定指纹，指纹随重启变化）')"
    echo "  2) Let'$(L 's Encrypt HTTP-01 - 需要开放 80 端口（自动续期）')"
    echo "  3) Let'$(L 's Encrypt DNS-01 通用 - 支持多种 DNS 服务商（自动续期）')"
    echo "  4) $(L 'Cloudflare DNS-01 - 需要 CF API Key（自动续期，推荐）')"
    while true; do
        read -rp "$(L '请选择') [$(L '1/2/3/4，默认4')]: " CERT_CHOICE || { [ -n "$CERT_CHOICE" ] || return 1; }
        CERT_CHOICE=${CERT_CHOICE:-4}
        case $CERT_CHOICE in
            1) TLS_MODE=1; CERT_METHOD="self-signed" ; break ;;
            2) TLS_MODE=2; CERT_METHOD="letsencrypt-http" ; break ;;
            3) TLS_MODE=2; CERT_METHOD="letsencrypt-dns" ; break ;;
            4) TLS_MODE=2; CERT_METHOD="cloudflare-dns" ; break ;;
            *) warn "$(L '无效选择')" ;;
        esac
    done

    if [ "$TLS_MODE" = "1" ]; then
        warn "$(L '提醒（v3 官方说明）：Vector/Egress 默认校验系统 CA + 主机名，自签证书必须改用 pin= 指纹锁定')"
        warn "$(L '自签证书仅建议测试用，生产环境请用真实域名 + CA 签发证书（选 2/3/4）')"
    fi

    step "$(L '第 2 步：基础网络信息')"
    divider
    if [ "$TLS_MODE" = "2" ]; then
        while true; do
            read -rp "$(L '请输入域名（如: nhk.example.com）:') " DOMAIN || { [ -n "$DOMAIN" ] || return 1; }
            DOMAIN=$(echo "$DOMAIN" | tr -d ' \r\n')
            DOMAIN="${DOMAIN,,}"
            [[ -z "$DOMAIN" ]] && { echo -e "${RED}$(L '域名不能为空')${NC}"; continue; }
            [[ "$DOMAIN" != *.* ]] && { echo -e "${RED}$(L '域名格式不正确')${NC}"; continue; }
            [[ ! "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] && { echo -e "${RED}$(L '域名只能包含字母、数字、点和连字符')${NC}"; continue; }
            break
        done
        PUBLIC_HOST="$DOMAIN"
    else
        info "$(L '自签模式无需域名，将自动探测公网 IP 作为客户端连接地址')"
        DETECTED_IP="$(detect_public_host)"
        while true; do
            read -rp "$(L '公网 IP/域名（用于 Anywhere/Vector/Egress 连接，回车使用探测值') ${DETECTED_IP:-$(L '未探测到，请手动输入')}$(L '）:') " PUBLIC_HOST || { [ -n "$PUBLIC_HOST" ] || return 1; }
            PUBLIC_HOST=${PUBLIC_HOST:-$DETECTED_IP}
            PUBLIC_HOST=$(echo "$PUBLIC_HOST" | tr -d ' \r\n')
            is_safe_host "$PUBLIC_HOST" && break
            echo -e "${RED}$(L '地址不能为空，且只能包含字母、数字和 . : - _') [ ]${NC}"
        done
        DOMAIN="$PUBLIC_HOST"
        DOMAIN="${DOMAIN,,}"; PUBLIC_HOST="${PUBLIC_HOST,,}"
    fi

    EMAIL=""
    if [ "$TLS_MODE" = "2" ]; then
        while true; do
            read -rp "$(L '请输入邮箱（用于证书申请/找回）:') " EMAIL || { [ -n "$EMAIL" ] || return 1; }
            EMAIL=$(echo "$EMAIL" | tr -d ' \r\n')
            [[ ! "$EMAIL" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] && { echo -e "${RED}$(L '邮箱格式不正确')${NC}"; continue; }
            break
        done
    fi

    DNS_API=""
    if [ "$CERT_METHOD" = "cloudflare-dns" ]; then
        if [ -s /etc/cloudflare/credentials.ini ] && confirm "$(L '检测到已有 Cloudflare 凭证文件（/etc/cloudflare/credentials.ini），是否直接复用？')" y; then
            CF_KEY=""
        else
            prompt_cloudflare_creds || return 1
            write_cloudflare_creds
        fi
    elif [ "$CERT_METHOD" = "letsencrypt-dns" ]; then
        while true; do
            echo ""
            echo -e "${BOLD}$(L 'DNS 服务商：')${NC}"
            echo "  1) Cloudflare  2) DNSPod  3) $(L '阿里云  4')) $(L '其他/手动')"
            read -rp "$(L '选择') [$(L '1-4，默认1')]: " DNS_PROVIDER || { [ -n "$DNS_PROVIDER" ] || return 1; }
            DNS_PROVIDER=${DNS_PROVIDER:-1}
            case $DNS_PROVIDER in
                1)
                    read -rp "Cloudflare Email: " CF_EMAIL || { [ -n "$CF_EMAIL" ] || return 1; }
                    read -rsp "$(L 'Cloudflare API Key（输入不回显）:') " CF_KEY || { [ -n "$CF_KEY" ] || return 1; }; echo
                    if [ -z "$CF_EMAIL" ] || [ -z "$CF_KEY" ]; then warn "$(L 'Cloudflare 凭证不能为空')"; continue; fi
                    export CF_Email="${CF_EMAIL}" CF_Key="${CF_KEY}"
                    DNS_API="dns_cf"; break ;;
                2)
                    read -rp "DNSPod ID: " DNSPOD_ID || { [ -n "$DNSPOD_ID" ] || return 1; }
                    read -rsp "$(L 'DNSPod Token（输入不回显）:') " DNSPOD_TOKEN || { [ -n "$DNSPOD_TOKEN" ] || return 1; }; echo
                    if [ -z "$DNSPOD_ID" ] || [ -z "$DNSPOD_TOKEN" ]; then warn "$(L 'DNSPod 凭证不能为空')"; continue; fi
                    export DP_Id="${DNSPOD_ID}" DP_Key="${DNSPOD_TOKEN}"
                    DNS_API="dns_dp"; break ;;
                3)
                    read -rp "$(L '阿里云 AccessKey ID:') " ALI_ID || { [ -n "$ALI_ID" ] || return 1; }
                    read -rsp "$(L '阿里云 AccessKey Secret（输入不回显）:') " ALI_SECRET || { [ -n "$ALI_SECRET" ] || return 1; }; echo
                    if [ -z "$ALI_ID" ] || [ -z "$ALI_SECRET" ]; then warn "$(L '阿里云凭证不能为空')"; continue; fi
                    export Ali_Key="${ALI_ID}" Ali_Secret="${ALI_SECRET}"
                    DNS_API="dns_ali"; break ;;
                *)
                    warn "$(L '「其他/手动」需要交互式完成 DNS TXT 验证，本脚本暂不接管，请改选 1-3')"
                    continue ;;
            esac
        done
    fi
    return 0
}

_nw_prompt_listen() {
    step "$(L '第 3 步：监听参数')"
    divider
    echo -e "${BOLD}$(L '端口模式（v3 端点路径语法）：')${NC}"
    echo "  1) $(L 'TLS 与 QUIC 共用同一端口，如') *$(L ':443（推荐）')"
    echo "  2) $(L 'TLS 与 QUIC 分开端口，如') */tcp:2000/udp:2001"
    read -rp "$(L '选择') [$(L '1/2，默认1')]: " PORT_MODE_CHOICE || { [ -n "$PORT_MODE_CHOICE" ] || return 1; }
    case ${PORT_MODE_CHOICE:-1} in
        2) PORT_MODE="split" ;;
        *) PORT_MODE="same" ;;
    esac

    if [ "$PORT_MODE" = "split" ]; then
        NET="mix"
        while true; do
            read -rp "$(L 'TLS/TCP 端口（回车默认2000）:') " TCP_PORT || { [ -n "$TCP_PORT" ] || return 1; }
            TCP_PORT=${TCP_PORT:-2000}
            validate_port "$TCP_PORT" && { TCP_PORT=$((10#$TCP_PORT)); break; }
            warn "$(L '端口不合法（1-65535）')"
        done
        while true; do
            read -rp "$(L 'QUIC/UDP 端口（回车默认2001）:') " UDP_PORT || { [ -n "$UDP_PORT" ] || return 1; }
            UDP_PORT=${UDP_PORT:-2001}
            if ! validate_port "$UDP_PORT"; then warn "$(L '端口不合法（1-65535）')"; continue; fi
            UDP_PORT=$((10#$UDP_PORT))
            if [ "$TCP_PORT" = "$UDP_PORT" ]; then
                UDP_PORT="$(pick_udp_port_avoiding "$TCP_PORT" || echo 2001)"
                warn "$(L '分端口模式下 TCP 与 UDP 端口不能相同，已将 UDP 端口改为') ${UDP_PORT}"
            fi
            break
        done
        PORT="$TCP_PORT"
    else
        while true; do
            read -rp "$(L '监听端口（回车默认443）:') " PORT || { [ -n "$PORT" ] || return 1; }
            PORT=${PORT:-443}
            validate_port "$PORT" && { PORT=$((10#$PORT)); break; }
            warn "$(L '端口不合法（1-65535）')"
        done
        TCP_PORT="$PORT"
        UDP_PORT="$PORT"

        echo ""
        echo -e "${BOLD}$(L '传输模式（决定端点路径，TCP 与 UDP 都能承载 TCP/UDP 业务流）：')${NC}"
        echo "  1) $(L 'mix - TLS/TCP + QUIC/UDP 双栈（HOST:PORT，推荐）')"
        echo "  2) $(L 'tcp - 仅 TLS/TCP（HOST/tcp:PORT）')"
        echo "  3) $(L 'udp - 仅 QUIC/UDP（HOST/udp:PORT）')"
        read -rp "$(L '选择') [$(L '1/2/3，默认1')]: " NET_CHOICE || { [ -n "$NET_CHOICE" ] || return 1; }
        case ${NET_CHOICE:-1} in
            1) NET="mix" ;; 2) NET="tcp" ;; 3) NET="udp" ;; *) NET="mix" ;;
        esac
    fi

    TCP_FAMILY=""; UDP_FAMILY=""
    read -rp "$(L '是否限制监听地址族？（默认不限；IPv6 未真正开通的 VPS 可选仅 IPv4）')[y/N]: " FAM_CHOICE || { [ -n "$FAM_CHOICE" ] || return 1; }
    if [[ "$FAM_CHOICE" =~ ^[Yy]$ ]]; then
        if has_tcp; then
            read -rp "  $(L 'TCP 地址族') [$(L '4=仅IPv4 / 6=仅IPv6 / 回车=不限')]: " TCP_FAMILY_IN || { [ -n "$TCP_FAMILY_IN" ] || return 1; }
            case "$TCP_FAMILY_IN" in 4) TCP_FAMILY="4" ;; 6) TCP_FAMILY="6" ;; *) TCP_FAMILY="" ;; esac
        fi
        if has_udp; then
            read -rp "  $(L 'UDP 地址族') [$(L '4=仅IPv4 / 6=仅IPv6 / 回车=不限')]: " UDP_FAMILY_IN || { [ -n "$UDP_FAMILY_IN" ] || return 1; }
            case "$UDP_FAMILY_IN" in 4) UDP_FAMILY="4" ;; 6) UDP_FAMILY="6" ;; *) UDP_FAMILY="" ;; esac
        fi
    fi

    read -rp "$(L '监听地址（回车=') * $(L '通配，全监听；也可填具体 IP）:') " LISTEN_HOST || { [ -n "$LISTEN_HOST" ] || return 1; }
    LISTEN_HOST=${LISTEN_HOST:-}
    LISTEN_HOST=$(echo "$LISTEN_HOST" | tr -d ' \r\n')
    if [[ -n "$LISTEN_HOST" && "$LISTEN_HOST" != "*" ]] && ! is_safe_host "$LISTEN_HOST"; then
        warn "$(L '监听地址格式不合法，已改为') * $(L '通配')"
        LISTEN_HOST=""
    fi
    return 0
}

_nw_prompt_security() {
    while true; do
        read -rsp "$(L '共享密钥 Shared Key（输入不回显，回车自动生成 32 位十六进制）:') " SHARED_KEY || { [ -n "$SHARED_KEY" ] || return 1; }; echo
        if [ -z "$SHARED_KEY" ]; then
            SHARED_KEY="$(gen_key || true)"
            if is_valid_key "$SHARED_KEY"; then
                info "$(L '已生成密钥:') ${SHARED_KEY}"
                break
            fi
            warn "$(L '生成随机密钥失败，请手动输入 32 位小写十六进制密钥')"
            continue
        fi
        if is_valid_key "$SHARED_KEY"; then
            break
        fi
        warn "$(L '该密钥不符合 v3 规范：必须是恰好 32 位小写十六进制字符（0-9a-f）')"
        warn "$(L '旧版任意字符串/Base64 密钥在 v3 会被拒绝启动，请重新输入或直接回车自动生成')"
    done

    echo ""
    echo -e "${BOLD}$(L 'Morph 流量乱形')${NC}$(L '（')${YELLOW}$(L 'v3 默认开启 morph=1；仅做流量形态混淆，不提供额外加密；两端必须一致，没有协商/回退')${NC}$(L '）：')"
    read -rp "$(L '是否开启') [Y/n]: " MORPH_CHOICE || { [ -n "$MORPH_CHOICE" ] || return 1; }
    if [[ "$MORPH_CHOICE" =~ ^[Nn]$ ]]; then MORPH="0"; else MORPH="$DEFAULT_MORPH"; fi

    MORPH_TCP_PRELUDE="fade"; MORPH_UDP_PRELUDE="fade"
    if [ "$MORPH" = "1" ]; then
        echo ""
        echo -e "${BOLD}$(L 'Morph Prelude 策略')${NC}$(L '（')${YELLOW}$(L 'NOW_MORPH_TCP_PRELUDE / NOW_MORPH_UDP_PRELUDE，后者为 v3.3.0 新增。只对发起端（Vector / Egress）生效，Portal 自身不使用；这里的选择会写进下方生成的 Vector / Egress 启动命令。接收端三种通吃、两端无需一致、不进分享链接')${NC}$(L '）：')"
        echo "  1) fade  - ASCII→$(L '低7位')→$(L '全8位渐变（默认，推荐）')"
        echo "  2) $(L 'full8 - 全程全 8 位随机')"
        echo "  3) $(L 'low7  - 全程低 7 位随机')"
        read -rp "$(L '选择') [$(L '1/2/3，默认1')]: " PRELUDE_CHOICE || { [ -n "$PRELUDE_CHOICE" ] || return 1; }
        case ${PRELUDE_CHOICE:-1} in
            2) MORPH_TCP_PRELUDE="full8" ;;
            3) MORPH_TCP_PRELUDE="low7" ;;
            *) MORPH_TCP_PRELUDE="fade" ;;
        esac
        MORPH_UDP_PRELUDE="$MORPH_TCP_PRELUDE"
    fi

    HANDSHAKE_TIMEOUT="auto"
    echo ""
    echo -e "${BOLD}$(L '握手超时')${NC}$(L '（')${YELLOW}$(L 'NOW_HANDSHAKE_TIMEOUT；v3.3.0 起默认 auto（省略环境变量，由官方按 Shared Key 派生 3s–30s，抗固定超时指纹）；也可自定义时长如 10s / 500ms / 1m / 1h')${NC}$(L '）：')"
    read -rp "$(L '握手超时') [$(L '回车默认') auto]: " HANDSHAKE_TIMEOUT_IN || { [ -n "$HANDSHAKE_TIMEOUT_IN" ] || return 1; }
    HANDSHAKE_TIMEOUT=${HANDSHAKE_TIMEOUT_IN:-auto}
    validate_handshake_timeout "$HANDSHAKE_TIMEOUT" || { warn "$(L '格式不合法（须为 auto 或正数+单位，如 10s / 500ms / 1m / 1h），已重置为 auto')"; HANDSHAKE_TIMEOUT="auto"; }
    return 0
}

_nw_prompt_outbound() {
    echo ""
    echo -e "${BOLD}$(L 'Portal 出口 out=（Portal 固定出口，运行期间不可变）：')${NC}"
    echo "  1) $(L 'direct - Portal 直接访问目标（默认）')"
    echo "  2) $(L 'SOCKS5 上游 - 经一层 SOCKS5 代理出站（链式代理）')"
    echo "  3) $(L 'egress - 远程 Egress 出口（目标解析/拨号在另一台主动回连的机器上，该机无需开放入站端口；可同时接多台）')"
    read -rp "$(L '选择') [$(L '1/2/3，默认1')]: " OUT_CHOICE || { [ -n "$OUT_CHOICE" ] || return 1; }
    case ${OUT_CHOICE:-1} in
        2) OUT_TYPE="socks" ;;
        3) OUT_TYPE="egress" ;;
        *) OUT_TYPE="direct" ;;
    esac

    SOCKS="none"
    if [ "$OUT_TYPE" = "socks" ]; then
        while true; do
            read -rsp "$(L 'SOCKS5 地址，格式 user:pass')@$(L 'host:port（输入不回显）:') " SOCKS || { [ -n "$SOCKS" ] || return 1; }; echo
            if [ -z "$SOCKS" ]; then SOCKS="none"; OUT_TYPE="direct"; break; fi
            if validate_socks "$SOCKS"; then break; fi
            warn "$(L 'SOCKS5 格式不合法，已重置为 none 并改回 direct')"
            if confirm "$(L '是否重新输入 SOCKS5 地址？')" y; then continue; else SOCKS="none"; OUT_TYPE="direct"; break; fi
        done
    fi

    DIAL_MODE="single"; DIAL="$DEFAULT_DIAL"; DIAL4="auto"; DIAL6="auto"
    if [ "$OUT_TYPE" = "egress" ]; then
        info "$(L 'out=egress 时 Portal 不能再设置 dial/dial4/dial6（与官方约束一致），目标源地址请在 Egress 端配置')"
    else
        echo ""
        read -rp "$(L '出站源 IP dial（回车默认 auto；填 IP 会限定地址族，绑定失败不回退）:') " DIAL || { [ -n "$DIAL" ] || return 1; }
        DIAL=${DIAL:-$DEFAULT_DIAL}
        validate_ip_or_auto "$DIAL" any || { warn "$(L 'dial 不是合法 IP 字面量，已重置为 auto')"; DIAL="auto"; }
        read -rp "$(L '是否改用 dial4/dial6 分别绑定 IPv4/IPv6 源地址？')[y/N]: " DIAL46_CHOICE || { [ -n "$DIAL46_CHOICE" ] || return 1; }
        if [[ "$DIAL46_CHOICE" =~ ^[Yy]$ ]]; then
            DIAL_MODE="dual"
            read -rp "  $(L 'dial4（IPv4 源地址，回车默认 auto）:') " DIAL4 || { [ -n "$DIAL4" ] || return 1; }
            DIAL4=${DIAL4:-auto}
            read -rp "  $(L 'dial6（IPv6 源地址，回车默认 auto）:') " DIAL6 || { [ -n "$DIAL6" ] || return 1; }
            DIAL6=${DIAL6:-auto}
            validate_ip_or_auto "$DIAL4" 4 || { warn "$(L 'dial4 不是合法 IPv4 字面量，已重置为 auto')"; DIAL4="auto"; }
            validate_ip_or_auto "$DIAL6" 6 || { warn "$(L 'dial6 不是合法 IPv6 字面量（IPv4-mapped 地址不被 v3 接受），已重置为 auto')"; DIAL6="auto"; }
            DIAL="auto"
        fi
    fi

    echo ""
    echo -e "${BOLD}$(L '限速设置（Portal/Vector/Egress 通用语义，0=不限速）：')${NC}"
    read -rp "$(L '上行限速 Mbps，Vector')→$(L '目标（0=不限速）:') " RATE || { [ -n "$RATE" ] || return 1; }
    RATE=${RATE:-0}
    validate_rate "$RATE" || { warn "$(L '输入不合法（须为 0..2147483647 的整数），重置为0')"; RATE=0; }

    read -rp "$(L '下行限速 Mbps，目标')→$(L 'Vector（0=不限速）:') " ETAR || { [ -n "$ETAR" ] || return 1; }
    ETAR=${ETAR:-0}
    validate_rate "$ETAR" || { warn "$(L '输入不合法（须为 0..2147483647 的整数），重置为0')"; ETAR=0; }
    return 0
}

_nw_prompt_clients() {
    echo ""
    echo -e "${BOLD}$(L '本地 Vector 客户端连接信息')${NC}$(L '（可选，在电脑/路由器上跑本地 SOCKS5 入口用 in=）：')"
    read -rp "$(L '是否生成 Vector 连接信息？')[Y/n]: " GEN_VECTOR || { [ -n "$GEN_VECTOR" ] || return 1; }
    GEN_VECTOR=${GEN_VECTOR:-y}
    if [[ "$GEN_VECTOR" =~ ^[Yy]$ ]]; then
        GENERATE_VECTOR="1"
        if has_tcp && has_udp; then
            echo "  $(L 'Vector 载体（二选一，v3 一条连接只用一种载体）  1')) tcp/TLS  2) udp/QUIC"
            read -rp "  $(L '选择') [$(L '1/2，默认1')]: " VCARRIER_CHOICE || { [ -n "$VCARRIER_CHOICE" ] || return 1; }
            case ${VCARRIER_CHOICE:-1} in 2) VECTOR_CARRIER="udp" ;; *) VECTOR_CARRIER="tcp" ;; esac
        elif has_udp; then
            VECTOR_CARRIER="udp"
            info "  $(L '当前 Portal 仅 QUIC/UDP，Vector 载体自动选 udp')"
        else
            VECTOR_CARRIER="tcp"
            info "  $(L '当前 Portal 仅 TLS/TCP，Vector 载体自动选 tcp')"
        fi
        while true; do
            read -rp "  $(L '本地 SOCKS5 监听 in=（回车默认') ${DEFAULT_VECTOR_SOCKS}$(L '，可带 user:pass')@$(L '）:') " VECTOR_SOCKS || { [ -n "$VECTOR_SOCKS" ] || return 1; }
            VECTOR_SOCKS=${VECTOR_SOCKS:-$DEFAULT_VECTOR_SOCKS}
            if validate_socks "$VECTOR_SOCKS"; then break; fi
            warn "$(L '格式不合法:') ${VECTOR_SOCKS}"
        done
    else
        GENERATE_VECTOR="0"
        VECTOR_CARRIER="tcp"; VECTOR_SOCKS="$DEFAULT_VECTOR_SOCKS"
    fi

    GENERATE_EGRESS="0"
    EGRESS_DIAL_MODE="single"; EGRESS_DIAL4="auto"; EGRESS_DIAL6="auto"
    if has_udp; then EGRESS_CARRIER="udp"; else EGRESS_CARRIER="tcp"; fi
    if [ "$OUT_TYPE" = "egress" ]; then
        echo ""
        echo -e "${BOLD}$(L '远程 Egress 出口机连接信息')${NC}$(L '（在出口机上运行 egress:// 主动回连本 Portal）：')"
        read -rp "$(L '是否生成 Egress 连接信息？')[Y/n]: " GEN_EGRESS || { [ -n "$GEN_EGRESS" ] || return 1; }
        GEN_EGRESS=${GEN_EGRESS:-y}
        if [[ "$GEN_EGRESS" =~ ^[Yy]$ ]]; then
            GENERATE_EGRESS="1"
            if has_tcp && has_udp; then
                echo "  $(L 'Egress 回连载体（v3.3.0 起两种都可用；一个连接串只选一种，多台出口机可以混用）')"
                echo "    1) $(L 'udp / QUIC - 一条连接承载多条 Flow（推荐）')"
                echo "    2) $(L 'tcp / TLS  - 每条 Flow 独占一条 TLS 连接，出口机自动维护预建连接池；UDP 被限制的网络选这个（出口机需') ≥ $(L 'v3.3.0）')"
                read -rp "  $(L '选择') [$(L '1/2，默认1')]: " ECARRIER_CHOICE || { [ -n "$ECARRIER_CHOICE" ] || return 1; }
                case ${ECARRIER_CHOICE:-1} in 2) EGRESS_CARRIER="tcp" ;; *) EGRESS_CARRIER="udp" ;; esac
            elif has_udp; then
                EGRESS_CARRIER="udp"
            else
                EGRESS_CARRIER="tcp"
                info "  $(L '当前 Portal 仅 TLS/TCP，Egress 载体自动选 tcp（出口机需') ≥ $(L 'v3.3.0）')"
            fi
            read -rp "  $(L 'Egress 端出站源 IP dial（在出口机上绑定目标连接源地址，回车默认 auto）:') " EGRESS_DIAL || { [ -n "$EGRESS_DIAL" ] || return 1; }
            EGRESS_DIAL=${EGRESS_DIAL:-auto}
            validate_ip_or_auto "$EGRESS_DIAL" any || { warn "$(L 'Egress dial 不是合法 IP 字面量，已重置为 auto')"; EGRESS_DIAL="auto"; }
            read -rp "  $(L '是否改用 dial4/dial6 分别绑定 IPv4/IPv6 目标出站源地址？')[y/N]: " EGRESS_DIAL46_CHOICE || { [ -n "$EGRESS_DIAL46_CHOICE" ] || return 1; }
            if [[ "$EGRESS_DIAL46_CHOICE" =~ ^[Yy]$ ]]; then
                EGRESS_DIAL_MODE="dual"
                read -rp "    $(L 'dial4（IPv4 源地址，回车默认 auto）:') " EGRESS_DIAL4 || { [ -n "$EGRESS_DIAL4" ] || return 1; }
                EGRESS_DIAL4=${EGRESS_DIAL4:-auto}
                read -rp "    $(L 'dial6（IPv6 源地址，回车默认 auto）:') " EGRESS_DIAL6 || { [ -n "$EGRESS_DIAL6" ] || return 1; }
                EGRESS_DIAL6=${EGRESS_DIAL6:-auto}
                validate_ip_or_auto "$EGRESS_DIAL4" 4 || { warn "$(L 'Egress dial4 不是合法 IPv4 字面量，已重置为 auto')"; EGRESS_DIAL4="auto"; }
                validate_ip_or_auto "$EGRESS_DIAL6" 6 || { warn "$(L 'Egress dial6 不是合法 IPv6 字面量（IPv4-mapped 地址不被 v3 接受），已重置为 auto')"; EGRESS_DIAL6="auto"; }
                EGRESS_DIAL="auto"
            fi
        fi
    fi
    return 0
}

_nw_print_install_summary() {
    echo ""
    divider
    echo -e "${BOLD}$(L '配置确认：')${NC}"
    divider
    echo -e "  $(L '域名/主机     :') ${GREEN}${DOMAIN}${NC}"
    echo -e "  $(L '公网地址      :') ${GREEN}${PUBLIC_HOST}${NC}"
    echo -e "  $(L '邮箱          :') ${GREEN}${EMAIL:-$(L '（自签模式不需要）')}${NC}"
    echo -e "  $(L '证书方式      :') ${GREEN}${CERT_METHOD}${NC}"
    echo -e "  $(L '端口模式      :') ${GREEN}${PORT_MODE}$(L '（TCP') $(tcp_port) / UDP $(udp_port)$(L '）')${NC}"
    echo -e "  $(L '监听地址      :') ${GREEN}$([ -z "$LISTEN_HOST" ] && echo "*（通配）" || echo "$LISTEN_HOST")${NC}"
    echo -e "  $(L '传输模式      :') ${GREEN}${NET}${NC}"
    echo -e "  $(L 'Portal 端点   :') ${GREEN}$(build_portal_endpoint)${NC}"
    echo -e "  $(L '共享密钥      :') ${GREEN}$(mask_secret "$SHARED_KEY")$(L '（32 位十六进制）')${NC}"
    echo -e "  $(L 'Morph 乱形    :') ${GREEN}$([ "$MORPH" = "1" ] && echo "开启 morph=1（默认）" || echo "关闭 morph=0")${NC}"
    [ "$MORPH" = "1" ] && echo -e "  $(L 'Prelude 策略  :') ${GREEN}${MORPH_TCP_PRELUDE}$(L '（写入生成的 Vector / Egress 启动命令，Portal 自身不使用）')${NC}"
    echo -e "  $(L '握手超时      :') ${GREEN}$([ "${HANDSHAKE_TIMEOUT:-auto}" = "auto" ] && echo "auto ($(L '按密钥派生 3–30s'))" || echo "${HANDSHAKE_TIMEOUT}")${NC}"
    echo -e "  $(L 'Portal 出口   :') ${GREEN}${OUT_TYPE}$([ "$OUT_TYPE" = "socks" ] && echo " ($(display_socks "$SOCKS"))")${NC}"
    if [ "$OUT_TYPE" != "egress" ]; then
        if [ "$DIAL_MODE" = "dual" ]; then
            echo -e "  $(L '出站源IP      :') ${GREEN}dial4=${DIAL4} dial6=${DIAL6}${NC}"
        else
            echo -e "  $(L '出站源IP      :') ${GREEN}dial=${DIAL}${NC}"
        fi
    fi
    echo -e "  $(L '上/下行限速   :') ${GREEN}${RATE} / ${ETAR} Mbps${NC}"
    if [ "$GENERATE_VECTOR" = "1" ]; then
        echo -e "  $(L 'Vector客户端  :') ${GREEN}$(L '生成（carrier=')${VECTOR_CARRIER} in=${VECTOR_SOCKS}$(L '）')${NC}"
    fi
    if [ "$GENERATE_EGRESS" = "1" ]; then
        if [ "$EGRESS_DIAL_MODE" = "dual" ]; then
            echo -e "  $(L 'Egress出口机  :') ${GREEN}$(L '生成（载体') ${EGRESS_CARRIER}$(L '，dial4=')${EGRESS_DIAL4} dial6=${EGRESS_DIAL6}$(L '）')${NC}"
        else
            echo -e "  $(L 'Egress出口机  :') ${GREEN}$(L '生成（载体') ${EGRESS_CARRIER}$(L '，dial=')${EGRESS_DIAL}$(L '）')${NC}"
        fi
    fi
    divider
}

do_install() {
    maint_lock_manual || return
    local OLD_NW_PORTS="" resumed=0
    OLD_NW_PORTS="$(nowhere_ports 2>/dev/null || true)"
    if [ "$(current_role)" = "egress" ]; then
        warn "$(L '本机当前是 Egress 角色：继续安装会把 nowhere.service 换成 Portal')"
        read -rp "$(L '确认继续') [y/N]: " ROLE_CONFIRM || { [ -n "$ROLE_CONFIRM" ] || return 1; }
        [[ ! "$ROLE_CONFIRM" =~ ^[Yy]$ ]] && { info "$(L '已取消')"; return; }
    fi
    ensure_prereqs
    preflight_install_check "Nowhere Portal" "$BIN_PATH" "$CONFIG_DIR" || return 1

    # 断点续装：若存在上次未完成的安装草稿，可直接载入并局部修改，无需从头重填
    if [ -f "$INSTALL_DRAFT_FILE" ]; then
        info "$(L '检测到上次未完成的安装草稿：') ${INSTALL_DRAFT_FILE}"
        echo "  1) $(L '载入草稿，直接进入确认/局部修改并继续（推荐）')"
        echo "  2) $(L '丢弃草稿，重新从头填写')"
        echo "  0) $(L '返回主菜单')"
        local draft_c=""
        read -rp "$(L '选择') [1/2/0, $(L '默认') 1]: " draft_c || return 0
        case "${draft_c:-1}" in
            1)
                if load_install_draft; then
                    resumed=1
                    success "$(L '已载入上次安装草稿（可直接确认或局部修改）')"
                else
                    clear_install_draft
                fi
                ;;
            2) clear_install_draft ;;
            *) info "$(L '已取消')"; return 0 ;;
        esac
    fi

    if [ "$resumed" != "1" ]; then
        step "$(L '第 0 步：选择语言')"
        divider
        echo "  1) 中文 (zh)"
        echo "  2) English (en)"
        read -rp "$(L '选择') [1/2, $(L '默认') ${ADAM_LANG}]: " _inst_lang || { [ -n "$_inst_lang" ] || return 1; }
        case "$_inst_lang" in 2) set_lang en ;; 1) set_lang zh ;; *) : ;; esac

        _nw_prompt_cert_and_net || return 1
        _nw_prompt_listen || return 1
        step "$(L '第 4 步：协议与安全参数')"
        divider
        _nw_prompt_security || return 1
        _nw_prompt_outbound || return 1
        _nw_prompt_clients || return 1
        save_install_draft
    fi

    # 交互式确认 + 局部修改循环：任何一项填错都可就地修改，无需从头开始
    local CONFIRM=""
    while true; do
        _nw_print_install_summary
        echo -e "${BOLD}$(L '操作选项：')${NC}"
        echo "  y) $(L '确认并开始安装')"
        echo "  1) $(L '修改 证书方式 / 域名 / 邮箱 / DNS 凭证')"
        echo "  2) $(L '修改 端口模式 / 监听端口 / 传输模式 / 监听地址')"
        echo "  3) $(L '修改 共享密钥 / Morph / Prelude / 握手超时')"
        echo "  4) $(L '修改 Portal 出口 / 出站源 IP / 限速')"
        echo "  5) $(L '修改 Vector / Egress 客户端连接信息选项')"
        echo "  n) $(L '取消退出（可选择保留草稿以便下次继续）')"
        read -rp "$(L '请选择') [y/1-5/n]: " CONFIRM || return 1
        case "${CONFIRM,,}" in
            y|yes) save_install_draft; break ;;
            1) _nw_prompt_cert_and_net && { save_install_draft; info "$(L '已更新安装配置，请再次核对')"; } ;;
            2) _nw_prompt_listen && { save_install_draft; info "$(L '已更新安装配置，请再次核对')"; } ;;
            3) _nw_prompt_security && { save_install_draft; info "$(L '已更新安装配置，请再次核对')"; } ;;
            4) _nw_prompt_outbound && { save_install_draft; info "$(L '已更新安装配置，请再次核对')"; } ;;
            5) _nw_prompt_clients && { save_install_draft; info "$(L '已更新安装配置，请再次核对')"; } ;;
            n|no|0|q)
                if confirm "$(L '是否保留已填写的配置草稿以便下次直接继续？')" y; then
                    save_install_draft
                    info "$(L '草稿已保留：')${INSTALL_DRAFT_FILE}"
                else
                    clear_install_draft
                    info "$(L '草稿已清除')"
                fi
                info "$(L '已取消')"
                return 0
                ;;
            *) warn "$(L '无效选择')" ;;
        esac
    done

    if [ -f "$CONFIG_FILE" ]; then
        local backup_dir
        backup_dir="${CONFIG_DIR}.bak.$(date +%Y%m%d-%H%M%S)"
        if cp -a "$CONFIG_DIR" "$backup_dir"; then
            info "$(L '检测到已有配置，已备份到') ${backup_dir}$(L '（本次安装中途失败时可手动恢复）')"
            ls -1d "${CONFIG_DIR}".bak.* 2>/dev/null | sort -r | tail -n +4 | tr '\n' '\0' | xargs -r -0 rm -rf || true
        else
            if ! confirm "$(L '配置备份失败，仍要继续吗？')" n; then info "$(L '已取消')"; return; fi
        fi
    fi

    step "$(L '第 5 步：安装系统依赖')"
    divider
    apt_install curl wget tar socat openssl python3 qrencode iproute2 ca-certificates
    if fw_conflict_detected; then
        warn "$(L '检测到 firewalld 或 cnblock 防火墙链已在运行，跳过 ufw 安装（避免两套防火墙混用）；端口放行请用现有防火墙管理')"
    else
        apt_install ufw
    fi
    if [ "$TLS_MODE" = "2" ]; then
        apt_install certbot
        [ "$CERT_METHOD" = "cloudflare-dns" ] && apt_install python3-certbot-dns-cloudflare
    fi
    success "$(L '依赖安装完成')"

    # 第 6 步：证书签发支持失败就地重试 / 换凭证 / 切方式 / 暂存草稿
    if [ "$TLS_MODE" = "2" ]; then
        ensure_ipv4_preference
        step "$(L '第 6 步：申请 TLS 证书')"
        divider
        while [ "$TLS_MODE" = "2" ]; do
            if [ "$CERT_METHOD" = "letsencrypt-dns" ]; then
                CRT="${CONFIG_DIR}/certs/${DOMAIN}/fullchain.pem"
                KEY_PEM="${CONFIG_DIR}/certs/${DOMAIN}/privkey.pem"
            else
                CRT="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
                KEY_PEM="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
            fi
            if [ "$CERT_METHOD" = "letsencrypt-http" ]; then
                check_domain_dns "$DOMAIN" || true
            fi
            if obtain_portal_cert; then
                info "$(L '证书路径:') ${CRT}"
                info "$(L '私钥路径:') ${KEY_PEM}"
                break
            fi
            echo ""
            warn "$(L '证书申请未成功，请选择下一步（无需从头填写配置）：')"
            echo "  1) $(L '重试当前证书申请')"
            echo "  2) $(L '重新输入 Cloudflare / DNS 凭证并重试')"
            echo "  3) $(L '更换证书方式 / 域名（如改用 DNS-01 或自签 tls=1）')"
            echo "  0) $(L '暂停并保留安装草稿（修好 DNS/80端口 后重新运行安装即可继续）')"
            local cert_rec=""
            read -rp "$(L '选择') [1/2/3/0]: " cert_rec || { save_install_draft; return 1; }
            case "$cert_rec" in
                1) continue ;;
                2)
                    if [ "$CERT_METHOD" = "cloudflare-dns" ]; then
                        prompt_cloudflare_creds && write_cloudflare_creds
                    else
                        _nw_prompt_cert_and_net || true
                    fi
                    save_install_draft
                    ;;
                3)
                    _nw_prompt_cert_and_net || true
                    if [ "$TLS_MODE" = "2" ]; then
                        apt_install certbot || true
                        [ "$CERT_METHOD" = "cloudflare-dns" ] && apt_install python3-certbot-dns-cloudflare || true
                    fi
                    save_install_draft
                    ;;
                *)
                    save_install_draft
                    info "$(L '草稿已保留：')${INSTALL_DRAFT_FILE}"
                    return 1
                    ;;
            esac
        done
    fi

    # 第 7 步：二进制下载支持重试，不因网络抖动丢弃全部配置
    step "$(L '第 7 步：下载 Nowhere 二进制')"
    divider
    detect_binary
    while true; do
        info "$(L '正在获取最新版本号...')"
        LATEST="$(get_latest_tag)"
        if [ -z "$LATEST" ]; then
            warn "$(L '无法获取版本号（GitHub API 与 releases/latest 跳转均失败），请检查网络')"
            if confirm "$(L '下载失败，是否立即重试？')" y; then continue; fi
            save_install_draft
            info "$(L '已暂存安装草稿，网络恢复后重新运行安装可直接继续')"
            return 1
        fi
        LATEST_MAJOR="$(version_major "$LATEST")"
        if [ -n "$LATEST_MAJOR" ] && [ "$LATEST_MAJOR" -lt 3 ]; then
            error "$(L '当前最新版为') ${LATEST}$(L '，低于 v3.0.0，与本脚本的 NW3 配置不兼容，已中止（请检查仓库状态）')"
        fi
        if [ -n "$LATEST_MAJOR" ] && [ "$LATEST_MAJOR" -gt 3 ]; then
            warn "$(L '当前最新版为') ${LATEST}$(L '，已进入新的协议代（NW')${LATEST_MAJOR}$(L '）；本脚本的向导按 NW3 生成配置，可能无法直接使用')"
            read -rp "$(L '仍要继续安装该版本吗？')[y/N]: " NEWMAJOR_CONFIRM || { [ -n "$NEWMAJOR_CONFIRM" ] || return 1; }
            [[ ! "$NEWMAJOR_CONFIRM" =~ ^[Yy]$ ]] && { info "$(L '已取消')"; return 0; }
        fi
        info "$(L '最新版本:') ${LATEST} (${ARCH_NAME}-${LIBC})"
        if fetch_nowhere_release "$LATEST"; then
            break
        fi
        if confirm "$(L '下载失败，是否立即重试？')" y; then continue; fi
        save_install_draft
        info "$(L '已暂存安装草稿，网络恢复后重新运行安装可直接继续')"
        return 1
    done
    install -m 755 "$DL_BINARY" "${BIN_PATH}"
    record_installed_version "$LATEST"
    success "Nowhere $(${BIN_PATH} --version 2>&1 | awk "NR==1" || true) $(L '安装完成')"

    # 第 8 步：端口占用检测提前到写入最终配置之前；被占用时支持就地换端口
    step "$(L '第 8 步：安装前端口占用检测')"
    divider
    while true; do
        EXISTING_PROC=""; EXISTING_TCP=""; EXISTING_UDP=""
        if command -v ss >/dev/null 2>&1; then
            if has_tcp; then EXISTING_TCP="$(check_port_occupied_by_other tcp "$(tcp_port)")"; fi
            if has_udp; then EXISTING_UDP="$(check_port_occupied_by_other udp "$(udp_port)")"; fi
        fi
        EXISTING_PROC="${EXISTING_TCP}${EXISTING_UDP}"
        if [ -z "$EXISTING_PROC" ]; then
            success "$(L '目标端口空闲，可以使用')"
            break
        fi
        warn "$(L '检测到目标端口已被其他进程占用：')"
        [ -n "$EXISTING_TCP" ] && echo "$EXISTING_TCP"
        [ -n "$EXISTING_UDP" ] && echo "$EXISTING_UDP"
        echo ""
        warn "$(L '目标端口被占用，请选择处理方式（无需从头填写）：')"
        echo "  1) $(L '立即更换监听端口并重新检测（推荐）')"
        echo "  2) $(L '重新检测当前端口（如果你已停掉占用进程）')"
        echo "  3) $(L '忽略占用强制继续')"
        echo "  0) $(L '暂停并保留安装草稿')"
        local p_act=""
        read -rp "$(L '选择') [1/2/3/0]: " p_act || { save_install_draft; return 1; }
        case "$p_act" in
            1) _nw_prompt_listen || true; save_install_draft ;;
            2) continue ;;
            3) break ;;
            *) save_install_draft; info "$(L '草稿已保留：')${INSTALL_DRAFT_FILE}"; return 0 ;;
        esac
    done

    step "$(L '第 9 步：保存配置')"
    divider
    install -d -m 750 "$CONFIG_DIR"
    setup_nowhere_user || true
    if [ "$NOWHERE_USER" = "nowhere" ]; then
        sync_portal_cert_copy || { warn "$(L '证书副本同步失败，回退 root 运行')"; NOWHERE_USER="root"; }
    else
        CRT_RUNTIME="${CRT:-}"
        KEY_PEM_RUNTIME="${KEY_PEM:-}"
    fi
    sanitize_nowhere_params
    NOWHERE_PORTAL="$(build_portal_url)"
    write_portal_env || error "$(L '配置保存失败，已中止')"
    echo "portal" > "$ROLE_FILE"
    success "$(L '配置已保存至') ${CONFIG_FILE}"

    step "$(L '第 10 步：配置防火墙（先于服务启动，避免中间态连不通）')"
    divider
    local -a NW_FW_SPECS=()
    if has_tcp; then NW_FW_SPECS+=("$(tcp_port)/tcp"); fi
    if has_udp; then NW_FW_SPECS+=("$(udp_port)/udp"); fi
    if [ "$CERT_METHOD" = "letsencrypt-http" ]; then NW_FW_SPECS+=("80/tcp"); fi
    fw_allow_for_service "${NW_FW_SPECS[@]}"
    if [ -n "$OLD_NW_PORTS" ]; then fw_prune_old_specs "$OLD_NW_PORTS"; fi
    reserved_ports_sync || true

    step "$(L '第 11 步：创建并启动系统服务')"
    divider
    nowhere_write_portal_unit
    nowhere_fix_perms

    restart_nowhere_with_fallback 0 || true

    local _nw_missing=""
    if has_tcp && ! tcp_listening "$(tcp_port)"; then _nw_missing="${_nw_missing} tcp:$(tcp_port)"; fi
    if has_udp && ! udp_listening "$(udp_port)"; then _nw_missing="${_nw_missing} udp:$(udp_port)"; fi

    local _nw_active=0
    systemctl is-active --quiet nowhere && _nw_active=1
    if [ "$_nw_active" = "1" ] && [ -z "$_nw_missing" ]; then
        success "$(L '服务启动成功，且已确认端口正在监听')"
        clear_install_draft
    elif [ "$_nw_active" = "1" ] && [ -n "$_nw_missing" ]; then
        warn "$(L 'systemd 显示服务 active，但未检测到端口实际在监听') $(L '（存在端口未监听：')${_nw_missing# }$(L '）')"
        warn "$(L '常见原因：证书路径错误、端口被抢占、密钥格式不合 v3 规范（必须 32 位小写十六进制）')"
        journalctl -u nowhere -n 30 --no-pager
        warn "$(L '服务处于不确定状态，建议排查后再连接客户端，否则会一直 timeout')"
    else
        warn "$(L '服务未能启动，查看日志排查：')"
        journalctl -u nowhere -n 30 --no-pager
        save_install_draft
        warn "$(L '服务启动失败，已保留安装草稿；排查后重新运行安装可直接续装')"
        error "$(L '安装中止')"
    fi

    step "$(L '第 12 步：生成连接信息')"
    divider
    _CACHED_TLS_FP=""
    [ "$TLS_MODE" = "1" ] && _CACHED_TLS_FP="$(get_tls_fingerprint 2>/dev/null || true)"
    build_client_links
    build_vector_info
    build_egress_info
    print_all_info
    save_current_pin >/dev/null 2>&1 || true

    step "$(L '第 13 步：安装快捷命令')"
    divider
    install_shortcuts --no-header || true
    if ! verify_shortcuts; then
        warn "$(L '安装完成，但快捷命令校验未通过（服务本身不受影响），请稍后执行 adam shortcuts 重新安装')"
    fi
    maint_install_timers >/dev/null 2>&1 || true
    nowhere_fix_perms
}

print_all_info() {
    local udp_section="" tcp_section="" vector_section="" egress_section="" hs_env="" hs_disp=""
    if [ -n "${HANDSHAKE_TIMEOUT:-}" ] && [ "$HANDSHAKE_TIMEOUT" != "auto" ]; then
        hs_env="NOW_HANDSHAKE_TIMEOUT=${HANDSHAKE_TIMEOUT} "
        hs_disp="${HANDSHAKE_TIMEOUT}"
    else
        hs_disp="auto ($(L '按密钥派生 3–30s'))"
    fi

    if [[ -n "$UDP_LINK" ]]; then
        udp_section="
$(L '【Anywhere 分享链接 —— QUIC/UDP（net=udp）】')
$(L '链接：')
${UDP_LINK}

$(L '一键导入深链（手机点击，需 Anywhere 已支持 NW3）：')
${IMPORT_UDP}
"
    fi

    if [[ -n "$TCP_LINK" ]]; then
        tcp_section="
$(L '【Anywhere 分享链接 —— TLS/TCP（net=tcp，默认）】')
$(L '链接：')
${TCP_LINK}

$(L '一键导入深链（手机点击，需 Anywhere 已支持 NW3）：')
${IMPORT_TCP}
"
    fi

    if [ "$GENERATE_VECTOR" = "1" ]; then
        if [[ -n "$VECTOR_URL" ]]; then
            vector_section="
$(L '【本地 Vector 客户端 —— 在电脑/路由器上跑本地 SOCKS5 入口】')
$(L '载体:') ${VECTOR_CARRIER}  $(L '本地监听 in=')${VECTOR_SOCKS}
$(L '连接串：')
${VECTOR_URL}

$(L '启动命令：')
${hs_env}NOW_MORPH_TCP_PRELUDE=${MORPH_TCP_PRELUDE} NOW_MORPH_UDP_PRELUDE=${MORPH_UDP_PRELUDE} nowhere '${VECTOR_URL}'
$([ "$TLS_MODE" = "1" ] && echo "
※ $(L '用的是 pin=证书指纹 锁定方式，Portal 每次重启该指纹都会变，重启后需要重新生成本连接串（Nowhere 菜单 4 或 pz 命令）')")
"
        else
            vector_section="
$(L '【本地 Vector 客户端】')
$(L '生成失败：未能获取到有效的连接参数，可稍后通过Nowhere 菜单「4')) $(L '查看连接信息」重试')
"
        fi
    fi

    if [ "$GENERATE_EGRESS" = "1" ]; then
        if [[ -n "$EGRESS_URL" ]]; then
            egress_section="
$(L '【远程 Egress 出口机 —— 在出口机上运行，主动回连本 Portal，无需出口机开放入站端口】')
$(L '回连载体:') ${EGRESS_CARRIER}
$(L '连接串：')
${EGRESS_URL}

$(L '出口机启动命令（或在出口机上运行本脚本 Nowhere 菜单 2，直接粘贴上面的连接串装成 systemd 服务）：')
${hs_env}NOW_MORPH_TCP_PRELUDE=${MORPH_TCP_PRELUDE} NOW_MORPH_UDP_PRELUDE=${MORPH_UDP_PRELUDE} nowhere '${EGRESS_URL}'
※ $(L '本 Portal 已固定 out=egress：没有可用的 Egress 时，新连接会在 Flow 建立超时（NOW_FLOW_SETUP_TIMEOUT，默认 20s）内等待注册，超时即失败，不会回退直连')
※ $(L 'v3.3.0 起同一 Portal 可同时接受多台 Egress（TLS / QUIC 可混用，Portal 按先进先出轮转，不保证均衡）；使用 tcp 载体的出口机需') ≥ v3.3.0
$([ "$TLS_MODE" = "1" ] && echo "※ 同 Vector，pin= 指纹随 Portal 重启变化，重启后需同步更新出口机连接串")
"
        else
            egress_section="
$(L '【远程 Egress 出口机】')
$(L '生成失败：未能获取到有效的连接参数，可稍后通过Nowhere 菜单「4')) $(L '查看连接信息」重试')
"
        fi
    fi

    ( umask 077; cat > "${CONFIG_DIR}/config.txt" ) << CONFEOF
════════════════════════════════════════════════════════════════
  $(L 'Nowhere Portal 连接信息（')${TARGET_NW_VERSION} $(L '/ NW3）')
  $(L '更新时间:') $(date '+%Y-%m-%d %H:%M:%S')
════════════════════════════════════════════════════════════════

$(L '【服务端启动参数（Portal URL，用于 systemd ExecStart）】')
${NOWHERE_PORTAL}
※ $(L 'v3 的 alpn/net/log/pool/up/down/socks')($(L 'Vector旧名')) $(L '等旧参数均已移除或改名，')
  $(L '未知参数会被静默忽略，千万不要再往启动串里手动拼旧参数。')

$(L '【客户端连接参数】')
  $(L '域名/公网地址 :') ${PUBLIC_HOST}
  $(L 'TCP 端口      :') $(tcp_port)
  $(L 'UDP 端口      :') $(udp_port)
  $(L '共享密钥      :') ${SHARED_KEY}$(L '（32 位小写十六进制，两端必须完全一致）')
  $(L '传输模式      :') ${NET}$(L '（端口模式') ${PORT_MODE}$(L '）')
  $(L 'Morph 乱形    :') $([ "$MORPH" = "1" ] && echo "开启 morph=1（v3 默认，客户端必须同步开启）" || echo "关闭 morph=0（客户端必须同步关闭）")
  $(L 'Prelude 策略  :') ${MORPH_TCP_PRELUDE}$(L '（NOW_MORPH_TCP_PRELUDE / NOW_MORPH_UDP_PRELUDE，只在发起端 Vector / Egress 上设置，Portal 不使用；接收端通吃、两端无需一致）')
  $(L '握手超时      :') ${hs_disp}$(L '（NOW_HANDSHAKE_TIMEOUT；v3.3.0 起未设置时从 Shared Key 派生 3s–30s，显式设置可固定）')
  TLS           : $([ "$TLS_MODE" = "1" ] && echo "自签证书(tls=1，靠 pin= 指纹锁定)" || echo "真实证书(tls=2，系统 CA + 主机名校验)")
  $(L 'Portal 出口   :') ${OUT_TYPE}
${udp_section}${tcp_section}${vector_section}${egress_section}
$(L '【Anywhere 手动填写】')
  $(L '服务器 :') ${PUBLIC_HOST}
  $(L '端口   :') $(if has_tcp; then tcp_port; else udp_port; fi)
  $(L '密钥   :') ${SHARED_KEY}
  $(L 'TLS    : 开启')
  $(L 'ALPN   : nw3（v3 固定，不可改，App 内无需/无法填写 alpn 时忽略此项）')
  Morph  : ${MORPH}$(L '（务必和服务端保持一致）')

$(L '【防火墙提醒】')
$(if has_tcp && has_udp; then echo "  需放行: TCP $(tcp_port) 和 UDP $(udp_port)"; elif has_tcp; then echo "  需放行: TCP $(tcp_port)"; else echo "  需放行: UDP $(udp_port)"; fi)
$([ "$TLS_MODE" = "1" ] && echo "
$(L '【TLS 提示】')
  $(L 'tls=1 为临时自签证书，每次重启指纹会变化，仅建议测试用')
  $(L 'v3 客户端默认校验系统 CA 与主机名，自签场景必须用 pin= 锁定指纹')")

$(L '【版本兼容提醒】')
  $(L '本配置为 NW3 协议：v1/v2 的 Portal/Vector 以及未支持 NW3 的')
  $(L 'Anywhere/第三方客户端无法与本服务端互通，升级需整条链路一起升。')
  $(L 'v3.2.0 起 Portal 强制 Authenticated Prelude：morph=1 且走 TLS/TCP 的对端')
  $(L '（Vector / Egress / Anywhere）必须') ≥ $(L 'v3.1.0，更旧的版本会被静默拒绝。')
  $(L '分享链接与 anywhere:// 深链格式已按 v3 文档更新，但能否导入成功')
  $(L '取决于你手机上的 Anywhere 版本是否已支持 NW3，请以实测为准。')
════════════════════════════════════════════════════════════════
CONFEOF
    chmod 600 "${CONFIG_DIR}/config.txt"

    echo ""
    echo -e "${BOLD}${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║              ✅  $(L '操作完成！')                                  ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    cat "${CONFIG_DIR}/config.txt"
    echo ""
    if [[ -n "$IMPORT_UDP" ]]; then
        echo -e "${BOLD}✅ $(L '最快导入方式（QUIC/UDP）：')${NC}"
        echo -e "$(L '在手机浏览器打开，自动跳转 Anywhere 导入（需 Anywhere 支持 NW3）：')"
        echo -e "${CYAN}${IMPORT_UDP}${NC}"
    elif [[ -n "$IMPORT_TCP" ]]; then
        echo -e "${BOLD}✅ $(L '最快导入方式（TLS/TCP）：')${NC}"
        echo -e "$(L '在手机浏览器打开，自动跳转 Anywhere 导入（需 Anywhere 支持 NW3）：')"
        echo -e "${CYAN}${IMPORT_TCP}${NC}"
    fi
    if command -v qrencode >/dev/null 2>&1; then
        if [[ -n "$UDP_LINK" ]]; then
            echo ""
            echo -e "${BOLD}📱 $(L '扫码导入 Anywhere（QUIC/UDP）：')${NC}"
            qrencode -t ANSIUTF8 "$UDP_LINK" || true
        fi
        if [[ -n "$TCP_LINK" ]]; then
            echo ""
            echo -e "${BOLD}📱 $(L '扫码导入 Anywhere（TLS/TCP）：')${NC}"
            qrencode -t ANSIUTF8 "$TCP_LINK" || true
        fi
    fi
    echo ""
    print_tls_fingerprint
    echo ""
    echo -e "${BOLD}📋 $(L '常用命令：')${NC}"
    echo -e "  $(L '状态 :') ${CYAN}systemctl status nowhere${NC} / ${CYAN}nowhere status${NC}"
    echo -e "  $(L '日志 :') ${CYAN}journalctl -u nowhere -f${NC}"
    echo -e "  $(L '配置 :') ${CYAN}cat ${CONFIG_DIR}/config.txt${NC}"
    echo -e "  $(L '重启 :') ${CYAN}systemctl restart nowhere${NC}"
    echo -e "  $(L '探测 :') ${CYAN}adam probe${NC}$(L '（真实 TCP Flow 连通性测试）')"
    divider
}

load_saved_config() {
    [ ! -f "$CONFIG_FILE" ] && error "$(L '未找到配置文件，请先执行安装')"
    # shellcheck disable=SC1090
    source "$CONFIG_FILE"
    DOMAIN="$DOMAIN_VALUE"
    PUBLIC_HOST="$PUBLIC_HOST_VALUE"
    LISTEN_HOST="${LISTEN_HOST_VALUE:-}"
    PORT_MODE="${PORT_MODE_VALUE:-same}"
    PORT="$PORT_VALUE"
    TCP_PORT="${TCP_PORT_VALUE:-$PORT}"
    UDP_PORT="${UDP_PORT_VALUE:-$PORT}"
    SHARED_KEY="$SHARED_KEY_VALUE"
    NET="$NET_VALUE"
    TLS_MODE="$TLS_MODE_VALUE"
    CERT_METHOD="$CERT_METHOD_VALUE"
    CRT="$CRT_VALUE"
    KEY_PEM="$KEY_PEM_VALUE"
    CRT_RUNTIME="${CRT_RUNTIME_VALUE:-$CRT}"
    KEY_PEM_RUNTIME="${KEY_PEM_RUNTIME_VALUE:-$KEY_PEM}"
    # 兼容 v8.4 旧配置（CRT_VALUE 曾被覆写成副本路径）：若原始 LE/acme 证书在位则自动还原源路径
    if [ "$TLS_MODE" = "2" ] && [ "$CRT" = "${CONFIG_DIR}/certs/fullchain.pem" ] && [ -n "${DOMAIN:-}" ]; then
        if [ "$CERT_METHOD" = "letsencrypt-dns" ] && [ -f "${CONFIG_DIR}/certs/${DOMAIN}/fullchain.pem" ]; then
            CRT="${CONFIG_DIR}/certs/${DOMAIN}/fullchain.pem"
            KEY_PEM="${CONFIG_DIR}/certs/${DOMAIN}/privkey.pem"
        elif [ -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]; then
            CRT="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
            KEY_PEM="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
        fi
    fi
    # 兼容旧版（v1.5 脚本）配置文件：旧字段 ALPN/POOL/LOG/SOCKS含义已变，只做迁移提示不直接沿用
    OUT_TYPE="${OUT_TYPE_VALUE:-}"
    if [[ -z "$OUT_TYPE" ]]; then
        if [[ -n "${SOCKS_VALUE:-}" && "${SOCKS_VALUE}" != "none" ]]; then
            OUT_TYPE="socks"
            SOCKS="$SOCKS_VALUE"
            warn "$(L '检测到旧版配置：SOCKS5 已由 socks= 迁移为 Portal 的 out=，已自动沿用该地址')"
        else
            OUT_TYPE="direct"
            SOCKS="none"
        fi
        warn "$(L '检测到旧版（NW1）配置文件。v3 还要求：密钥改为 32 位十六进制、删除 alpn/net/log/pool 参数，建议用Nowhere 菜单「3')) $(L '重新配置」按 v3 向导重装一次')"
    else
        SOCKS="${SOCKS_VALUE:-none}"
    fi
    DIAL_MODE="${DIAL_MODE_VALUE:-single}"
    DIAL="${DIAL_VALUE:-auto}"
    DIAL4="${DIAL4_VALUE:-auto}"
    DIAL6="${DIAL6_VALUE:-auto}"
    RATE="$RATE_VALUE"
    ETAR="$ETAR_VALUE"
    MORPH="${MORPH_VALUE:-$DEFAULT_MORPH}"
    MORPH_TCP_PRELUDE="${MORPH_TCP_PRELUDE_VALUE:-fade}"
    case "$MORPH_TCP_PRELUDE" in fade|full8|low7) : ;; *) MORPH_TCP_PRELUDE="fade" ;; esac
    HANDSHAKE_TIMEOUT="${HANDSHAKE_TIMEOUT_VALUE:-auto}"
    validate_handshake_timeout "$HANDSHAKE_TIMEOUT" || HANDSHAKE_TIMEOUT="auto"
    TCP_FAMILY="${TCP_FAMILY_VALUE:-}"
    UDP_FAMILY="${UDP_FAMILY_VALUE:-}"
    EGRESS_DIAL="${EGRESS_DIAL_VALUE:-auto}"
    EGRESS_DIAL_MODE="${EGRESS_DIAL_MODE_VALUE:-single}"
    case "$EGRESS_DIAL_MODE" in single|dual) : ;; *) EGRESS_DIAL_MODE="single" ;; esac
    EGRESS_DIAL4="${EGRESS_DIAL4_VALUE:-auto}"
    EGRESS_DIAL6="${EGRESS_DIAL6_VALUE:-auto}"
    EGRESS_CARRIER="${EGRESS_CARRIER_VALUE:-udp}"
    case "$EGRESS_CARRIER" in tcp|udp) : ;; *) EGRESS_CARRIER="udp" ;; esac
    MORPH_UDP_PRELUDE="${MORPH_UDP_PRELUDE_VALUE:-$MORPH_TCP_PRELUDE}"
    case "$MORPH_UDP_PRELUDE" in fade|full8|low7) : ;; *) MORPH_UDP_PRELUDE="fade" ;; esac
    GENERATE_VECTOR="${GENERATE_VECTOR_VALUE:-0}"
    # 旧配置里存的是 VECTOR_UP/VECTOR_DOWN 双向载体，v3 Vector 只有单载体：优先取上行值
    VECTOR_CARRIER="${VECTOR_CARRIER_VALUE:-${VECTOR_UP_VALUE:-tcp}}"
    VECTOR_SOCKS="${VECTOR_SOCKS_VALUE:-$DEFAULT_VECTOR_SOCKS}"
    GENERATE_EGRESS="${GENERATE_EGRESS_VALUE:-0}"
    NOWHERE_PORTAL="${NOWHERE_PORTAL:-$(build_portal_url)}"
    sanitize_nowhere_params

    if ! is_valid_key "$SHARED_KEY"; then
        warn "$(L '当前保存的共享密钥不符合 v3 规范（必须是恰好 32 位小写十六进制字符）')"
        warn "$(L 'v3 会直接拒绝用该密钥启动。请用Nowhere 菜单「3')) $(L '重新配置」生成新密钥，并同步更新所有 Vector/Egress/Anywhere 对端')"
    fi
}

# 只下载并安装二进制，不触碰任何服务（供本机 Egress 安装用：服务文件尚未生成时，
# 不能复用 install_nowhere_version，那个函数会在装完后直接重启 nowhere）。
install_nowhere_binary_only() {
    info "$(L '正在获取最新版本号...')"
    local latest latest_major
    latest="$(get_latest_tag)"
    [ -z "$latest" ] && { warn "$(L '无法获取版本号，请检查网络')"; return 1; }
    latest_major="$(version_major "$latest")"
    if [ -n "$latest_major" ] && [ "$latest_major" -lt 3 ]; then
        warn "$(L '当前最新版为') ${latest}$(L '，低于 v3.0.0，与 NW3 配置不兼容，已中止')"
        return 1
    fi
    detect_binary
    info "$(L '最新版本:') ${latest} (${ARCH_NAME}-${LIBC})"
    fetch_nowhere_release "$latest" || return 1
    install -d -m 750 "$CONFIG_DIR"
    if [ -f "$BIN_PATH" ]; then
        cp "$BIN_PATH" "$BIN_BACKUP_PATH"
        record_previous_version "$(read_installed_version)"
    fi
    install -m 755 "$DL_BINARY" "$BIN_PATH"
    record_installed_version "$latest"
    success "Nowhere $(${BIN_PATH} --version 2>&1 | awk "NR==1" || true) $(L '安装完成')"
    return 0
}

# 解析 egress:// 连接串（Portal 端 Nowhere 菜单 4 / pz 生成的那一串）。
# 结果写入 PE_KEY / PE_HOST / PE_PORT / PE_CARRIER / PE_FAMILY / PE_MORPH。
# 同时限制字符集：这串内容会原样写进 systemd 的 EnvironmentFile。
# 从 egress:// 查询串取单个参数的值（值须为 URL 安全字符，直接取原值）
egress_query_param() {
    local q="&$1&" k="$2" v
    case "$q" in
        *"&${k}="*) v="${q##*&${k}=}"; v="${v%%&*}"; urldecode "$v"; return 0 ;;
        *) return 1 ;;
    esac
}

parse_egress_url() {
    local u="$1" rest query=""
    local re_path='^(.+)/(tcp|udp)([46]?):([0-9]+)$' re_compact='^(\[[^]]+\]|[^:]+):([0-9]+)$'
    local re_host='^[][A-Za-z0-9.:_-]+$' re_query='^[A-Za-z0-9=&%._:~-]+$'
    PE_KEY=""; PE_HOST=""; PE_PORT=""; PE_CARRIER=""; PE_FAMILY=""; PE_MORPH="1"
    PE_SNI=""; PE_PIN=""; PE_DIAL="auto"; PE_DIAL4="auto"; PE_DIAL6="auto"; PE_RATE="0"; PE_ETAR="0"
    [[ "$u" == egress://*@* ]] || return 1
    rest="${u#egress://}"
    PE_KEY="${rest%%@*}"
    is_valid_key "$PE_KEY" || return 1
    rest="${rest#*@}"
    if [[ "$rest" == *\?* ]]; then query="${rest#*\?}"; rest="${rest%%\?*}"; fi
    if [[ "$rest" =~ $re_path ]]; then
        PE_HOST="${BASH_REMATCH[1]}"; PE_CARRIER="${BASH_REMATCH[2]}"
        PE_FAMILY="${BASH_REMATCH[3]}"; PE_PORT="${BASH_REMATCH[4]}"
    elif [[ "$rest" =~ $re_compact ]]; then
        # 官方端点表：HOST:PORT 紧凑形对 Egress 代表 QUIC
        PE_HOST="${BASH_REMATCH[1]}"; PE_CARRIER="udp"; PE_PORT="${BASH_REMATCH[2]}"
    else
        return 1
    fi
    validate_port "$PE_PORT" || return 1
    PE_PORT="$((10#$PE_PORT))"
    [[ "$PE_HOST" =~ $re_host ]] || return 1
    if [ -n "$query" ]; then
        [[ "$query" =~ $re_query ]] || return 1
        if [[ "&${query}&" == *"&morph=0&"* ]]; then PE_MORPH="0"; fi
        local _v
        _v="$(egress_query_param "$query" sni || true)"; [ -n "$_v" ] && PE_SNI="$_v"
        _v="$(egress_query_param "$query" pin || true)"; [ -n "$_v" ] && PE_PIN="$_v"
        _v="$(egress_query_param "$query" dial || true)"; [ -n "$_v" ] && PE_DIAL="$_v"
        _v="$(egress_query_param "$query" dial4 || true)"; [ -n "$_v" ] && PE_DIAL4="$_v"
        _v="$(egress_query_param "$query" dial6 || true)"; [ -n "$_v" ] && PE_DIAL6="$_v"
        _v="$(egress_query_param "$query" rate || true)"; [ -n "$_v" ] && PE_RATE="$_v"
        _v="$(egress_query_param "$query" etar || true)"; [ -n "$_v" ] && PE_ETAR="$_v"
    fi
    return 0
}

# 本机安装为 Egress 服务（在出口机上运行，主动回连 Portal）。
# v3.3.0 起 Egress 可选 QUIC/UDP 或 TLS/TCP 载体，同一 Portal 可同时接多台 Egress。
# 注意：这会覆盖本机现有的 nowhere.service（同一服务名），一台机器同一时间只能是
# Portal 或 Egress 其中一种角色；Egress 配置单独存在 egress.env，不读写 Portal 的 nowhere.env，
# 角色记录在 ${CONFIG_DIR}/role，状态/配置/重启等命令据此区分。
do_install_egress_service() {
    step "$(L '本机安装为 Egress 服务')"
    divider
    warn "$(L '本机将作为出口机（Egress），主动回连 Portal；这会覆盖本机现有的 nowhere.service')"
    warn "$(L 'Portal 侧必须已设 out=egress，并放行所选载体的端口（QUIC = UDP 端口，TLS = TCP 端口）')"
    if [ "$(current_role)" = "portal" ]; then
        warn "$(L '检测到本机当前是 Portal 角色：继续会把本机切换为 Egress（Portal 配置文件保留，但服务被替换）')"
    fi
    read -rp "$(L '确认继续') [y/N]: " EG_CONFIRM || { [ -n "$EG_CONFIRM" ] || return 1; }
    [[ ! "$EG_CONFIRM" =~ ^[Yy]$ ]] && { info "$(L '已取消')"; return; }
    local old_portal_specs=""
    old_portal_specs="$(nowhere_ports 2>/dev/null || true)"
    ensure_prereqs
    preflight_install_check "Nowhere Egress" "$BIN_PATH" "$CONFIG_DIR" || return 1

    local eg_host="" eg_port="" eg_key="" eg_morph="1" eg_sni="" eg_pin="" eg_carrier="udp" eg_family="" eg_handshake="auto"
    local eg_dial_mode eg_dial eg_dial4 eg_dial6 eg_rate eg_etar eg_prelude="fade"
    local eg_url="" eg_query eg_host_part eg_paste=""

    echo ""
    info "$(L '可以直接粘贴 Portal 端（Nowhere 菜单 4 / pz）生成的 egress:// 连接串，跳过逐项填写')"
    read -rsp "$(L '粘贴 egress:// 连接串（输入不回显，回车 = 逐项填写）:') " eg_paste || { [ -n "$eg_paste" ] || return 1; }; echo
    eg_paste="$(printf '%s' "$eg_paste" | tr -d ' \r\n')"
    if [ -n "$eg_paste" ]; then
        if parse_egress_url "$eg_paste"; then
            eg_url="$eg_paste"; eg_key="$PE_KEY"; eg_host="$PE_HOST"; eg_port="$PE_PORT"
            eg_carrier="$PE_CARRIER"; eg_family="$PE_FAMILY"; eg_morph="$PE_MORPH"
            eg_sni="$PE_SNI"; eg_pin="$PE_PIN"; eg_dial="$PE_DIAL"; eg_dial4="$PE_DIAL4"; eg_dial6="$PE_DIAL6"
            eg_rate="$PE_RATE"; eg_etar="$PE_ETAR"
            if [ "$PE_DIAL4" != "auto" ] || [ "$PE_DIAL6" != "auto" ]; then eg_dial_mode="dual"; else eg_dial_mode="single"; fi
            if [ -n "$eg_sni" ] && ! is_safe_host "$eg_sni"; then warn "$(L '连接串里的 SNI 格式不合法，已忽略')"; eg_sni=""; fi
            if [ -n "$eg_pin" ] && [[ ! "$eg_pin" =~ ^[0-9a-f]{64}$ ]]; then warn "$(L '连接串里的 pin 不是 64 位小写十六进制，已忽略')"; eg_pin=""; fi
            validate_ip_or_auto "$eg_dial" any || { warn "$(L '连接串里的 dial 不是合法 IP，已重置为 auto')"; eg_dial="auto"; }
            validate_ip_or_auto "$eg_dial4" 4 || { warn "$(L '连接串里的 dial4 不是合法 IPv4，已重置为 auto')"; eg_dial4="auto"; }
            validate_ip_or_auto "$eg_dial6" 6 || { warn "$(L '连接串里的 dial6 不是合法 IPv6，已重置为 auto')"; eg_dial6="auto"; }
            validate_rate "$eg_rate" || { warn "$(L '连接串里的上行限速不合法，已重置为 0')"; eg_rate="0"; }
            validate_rate "$eg_etar" || { warn "$(L '连接串里的下行限速不合法，已重置为 0')"; eg_etar="0"; }
            # 按清洗后的字段重建 eg_url，确保非法参数被彻底剔除、IPv6 dial/dial6 正确编码
            eg_host_part="$(format_host_for_url "$eg_host")"
            eg_query="morph=${eg_morph}"
            if [ "$eg_dial_mode" = "dual" ]; then
                [[ "$eg_dial4" != "auto" ]] && eg_query="${eg_query}&dial4=$(urlencode "$eg_dial4")"
                [[ "$eg_dial6" != "auto" ]] && eg_query="${eg_query}&dial6=$(urlencode "$eg_dial6")"
            elif [ "$eg_dial" != "auto" ]; then
                eg_query="${eg_query}&dial=$(urlencode "$eg_dial")"
            fi
            [[ "$eg_rate" != "0" ]] && eg_query="${eg_query}&rate=${eg_rate}"
            [[ "$eg_etar" != "0" ]] && eg_query="${eg_query}&etar=${eg_etar}"
            [[ -n "$eg_sni" ]] && eg_query="${eg_query}&sni=$(urlencode "$eg_sni")"
            [[ -n "$eg_pin" ]] && eg_query="${eg_query}&pin=${eg_pin}"
            eg_url="egress://${eg_key}@${eg_host_part}/${eg_carrier}${eg_family}:${eg_port}?${eg_query}"
            # 握手超时不在连接串里：粘贴后也要问一次，否则静默落回 10s
            read -rp "$(L '握手超时 NOW_HANDSHAKE_TIMEOUT（回车默认 auto=按 Shared Key 派生 3s–30s；或自定义如 10s/500ms/1m/1h）:') " eg_handshake || { [ -n "$eg_handshake" ] || return 1; }
            eg_handshake=${eg_handshake:-auto}
            validate_handshake_timeout "$eg_handshake" || { warn "$(L '格式不合法（须为 auto 或正数+单位，如 10s），已重置为 auto')"; eg_handshake="auto"; }
            success "$(L '连接串解析通过：')${eg_host} ${eg_carrier}${eg_family}:${eg_port}$(L '，morph=')${eg_morph}"
        else
            warn "$(L '连接串格式不合法（应为 egress://32位hex密钥')@$(L '主机/udp')|$(L 'tcp:端口')?$(L '参数），改为逐项填写')"
        fi
    fi

    if [ -z "$eg_url" ]; then
        while true; do
            read -rp "$(L 'Portal 公网地址（域名或 IP，Egress 回连用）:') " eg_host || { [ -n "$eg_host" ] || return 1; }
            eg_host=$(echo "$eg_host" | tr -d ' \r\n')
            if is_safe_host "$eg_host"; then break; fi
            warn "$(L '地址不能为空，且只能包含字母、数字和 . : - _') [ ]"
        done
        echo ""
        echo "$(L '回连载体（须与 Portal 已开放的监听对应；v3.3.0 起两种都可用）：')"
        echo "  1) $(L 'udp / QUIC（默认）- 一条连接承载多条 Flow')"
        echo "  2) $(L 'tcp / TLS        - 每条 Flow 独占一条 TLS 连接，自动维护预建连接池（Hydra）；UDP 被限制的网络选这个')"
        read -rp "$(L '选择') [$(L '1/2，默认1')]: " EG_CARRIER_CHOICE || { [ -n "$EG_CARRIER_CHOICE" ] || return 1; }
        case ${EG_CARRIER_CHOICE:-1} in 2) eg_carrier="tcp" ;; *) eg_carrier="udp" ;; esac
        read -rp "$(L 'Portal 的') ${eg_carrier^^} $(L '端口（回车默认 443）:') " eg_port || { [ -n "$eg_port" ] || return 1; }
        eg_port=${eg_port:-443}
        validate_port "$eg_port" || { warn "$(L '端口不合法，重置为 443')"; eg_port=443; }
        read -rp "$(L '地址族（回车=不限；4=仅 IPv4；6=仅 IPv6）:') " eg_family || { [ -n "$eg_family" ] || return 1; }
        case "$eg_family" in 4|6) : ;; *) eg_family="" ;; esac
        while true; do
            read -rsp "$(L '共享密钥（必须与 Portal 完全一致，32 位小写十六进制，输入不回显）:') " eg_key || { [ -n "$eg_key" ] || return 1; }; echo
            if is_valid_key "$eg_key"; then
                break
            fi
            warn "$(L '密钥不符合 v3 规范：必须是恰好 32 位小写十六进制字符，不能回车自动生成（必须与 Portal 一致）')"
        done
        read -rp "$(L 'Morph 是否开启（须与 Portal 一致）')[Y/n]: " eg_morph || { [ -n "$eg_morph" ] || return 1; }
        if [[ "$eg_morph" =~ ^[Nn]$ ]]; then eg_morph="0"; else eg_morph="1"; fi
        echo ""
        echo "$(L 'Portal 证书信任方式：')"
        echo "  1) $(L 'tls=2 真实证书：走系统 CA + 主机名校验（默认）')"
        echo "  2) $(L 'tls=1 自签证书：必须用 pin= 锁定 Portal 证书指纹（指纹随 Portal 重启变化）')"
        read -rp "$(L '选择') [$(L '1/2，默认1')]: " EG_TLS_CHOICE || { [ -n "$EG_TLS_CHOICE" ] || return 1; }
        case ${EG_TLS_CHOICE:-1} in
            2)
                while true; do
                    read -rsp "$(L 'Portal 自签证书指纹 pin（64 位 hex，可从 Portal 机 Nowhere 菜单 10 查看，输入不回显，回车=暂不填）:') " eg_pin || { [ -n "$eg_pin" ] || return 1; }; echo
                    eg_pin=$(echo "$eg_pin" | tr -d ' \r\n' | tr 'A-F' 'a-f')
                    if [ -z "$eg_pin" ]; then
                        warn "$(L '未填 pin：自签证书走系统 CA 校验必然失败，服务会反复重连')"
                        read -rp "$(L '仍要继续（稍后需手动改 egress.env 补 pin）？')[y/N]: " EG_PIN_CONFIRM || { [ -n "$EG_PIN_CONFIRM" ] || return 1; }
                        [[ ! "$EG_PIN_CONFIRM" =~ ^[Yy]$ ]] && { info "$(L '已取消')"; return; }
                        break
                    fi
                    if [[ "$eg_pin" =~ ^[0-9a-f]{64}$ ]]; then
                        break
                    fi
                    warn "$(L 'pin 必须是 64 位小写十六进制字符')"
                done
                ;;
            *)
                read -rp "  $(L 'SNI（证书域名与回连地址不一致时填，回车=用回连地址）:') " eg_sni || { [ -n "$eg_sni" ] || return 1; }
                eg_sni=$(echo "$eg_sni" | tr -d ' \r\n')
                if [ -n "$eg_sni" ] && ! is_safe_host "$eg_sni"; then warn "$(L 'SNI 格式不合法，已忽略')"; eg_sni=""; fi
                ;;
        esac
        eg_dial_mode="single"; eg_dial="auto"; eg_dial4="auto"; eg_dial6="auto"
        echo ""
        read -rp "$(L 'Egress 到目标的出站源 IP dial（回车默认 auto，只影响目标连接，不影响回连 Portal）:') " eg_dial || { [ -n "$eg_dial" ] || return 1; }
        eg_dial=${eg_dial:-auto}
        validate_ip_or_auto "$eg_dial" any || { warn "$(L 'dial 不是合法 IP 字面量，已重置为 auto')"; eg_dial="auto"; }
        read -rp "$(L '是否改用 dial4/dial6 分别绑定 IPv4/IPv6 目标出站源地址？')[y/N]: " EG_DIAL46 || { [ -n "$EG_DIAL46" ] || return 1; }
        if [[ "$EG_DIAL46" =~ ^[Yy]$ ]]; then
            eg_dial_mode="dual"
            read -rp "  $(L 'dial4（IPv4 源地址，回车默认 auto）:') " eg_dial4 || { [ -n "$eg_dial4" ] || return 1; }
            eg_dial4=${eg_dial4:-auto}
            read -rp "  $(L 'dial6（IPv6 源地址，回车默认 auto）:') " eg_dial6 || { [ -n "$eg_dial6" ] || return 1; }
            eg_dial6=${eg_dial6:-auto}
            validate_ip_or_auto "$eg_dial4" 4 || { warn "$(L 'dial4 不是合法 IPv4 字面量，已重置为 auto')"; eg_dial4="auto"; }
            validate_ip_or_auto "$eg_dial6" 6 || { warn "$(L 'dial6 不是合法 IPv6 字面量，已重置为 auto')"; eg_dial6="auto"; }
            eg_dial="auto"
        fi
        read -rp "$(L '上行限速 Mbps（0=不限速）:') " eg_rate || { [ -n "$eg_rate" ] || return 1; }
        eg_rate=${eg_rate:-0}
        validate_rate "$eg_rate" || { warn "$(L '输入不合法，重置为 0')"; eg_rate=0; }
        read -rp "$(L '下行限速 Mbps（0=不限速）:') " eg_etar || { [ -n "$eg_etar" ] || return 1; }
        eg_etar=${eg_etar:-0}
        validate_rate "$eg_etar" || { warn "$(L '输入不合法，重置为 0')"; eg_etar=0; }
        read -rp "$(L '握手超时 NOW_HANDSHAKE_TIMEOUT（回车默认 auto=按 Shared Key 派生 3s–30s；或自定义如 10s/500ms/1m/1h）:') " eg_handshake || { [ -n "$eg_handshake" ] || return 1; }
        eg_handshake=${eg_handshake:-auto}
        validate_handshake_timeout "$eg_handshake" || { warn "$(L '格式不合法（须为 auto 或正数+单位，如 10s），已重置为 auto')"; eg_handshake="auto"; }
        eg_host_part="$(format_host_for_url "$eg_host")"
        eg_query="morph=${eg_morph}"
        if [ "$eg_dial_mode" = "dual" ]; then
            [[ "$eg_dial4" != "auto" ]] && eg_query="${eg_query}&dial4=$(urlencode "$eg_dial4")"
            [[ "$eg_dial6" != "auto" ]] && eg_query="${eg_query}&dial6=$(urlencode "$eg_dial6")"
        elif [ "$eg_dial" != "auto" ]; then
            eg_query="${eg_query}&dial=$(urlencode "$eg_dial")"
        fi
        [[ "$eg_rate" != "0" ]] && eg_query="${eg_query}&rate=${eg_rate}"
        [[ "$eg_etar" != "0" ]] && eg_query="${eg_query}&etar=${eg_etar}"
        [[ -n "$eg_sni" ]] && eg_query="${eg_query}&sni=$(urlencode "$eg_sni")"
        [[ -n "$eg_pin" ]] && eg_query="${eg_query}&pin=${eg_pin}"
        eg_url="egress://${eg_key}@${eg_host_part}/${eg_carrier}${eg_family}:${eg_port}?${eg_query}"
    fi

    if [ "$eg_morph" = "1" ]; then
        echo ""
        echo -e "${BOLD}$(L 'Morph Prelude 策略')${NC}$(L '（Egress 是发起端，这个设置在本机生效；Portal 三种都收，两端无需一致）：')"
        echo "  1) $(L 'fade（默认）  2')) full8  3) low7"
        read -rp "$(L '选择') [$(L '1/2/3，默认1')]: " EG_PRELUDE_CHOICE || { [ -n "$EG_PRELUDE_CHOICE" ] || return 1; }
        case ${EG_PRELUDE_CHOICE:-1} in 2) eg_prelude="full8" ;; 3) eg_prelude="low7" ;; *) eg_prelude="fade" ;; esac
    fi

    echo ""
    divider
    echo -e "  $(L 'Portal 地址 :') ${GREEN}${eg_host}:${eg_port} (${eg_carrier}${eg_family})${NC}"
    echo -e "  $(L '共享密钥    :') ${GREEN}$(mask_secret "$eg_key")${NC}"
    echo -e "  Morph       : ${GREEN}${eg_morph}$([ "$eg_morph" = "1" ] && echo "（Prelude ${eg_prelude}）")${NC}"
    echo -e "  Egress URL  : ${GREEN}${eg_url/$eg_key/$(mask_secret "$eg_key")}${NC}"
    divider
    read -rp "$(L '确认安装为 Egress 服务') [y/N]: " EG_CONFIRM2 || { [ -n "$EG_CONFIRM2" ] || return 1; }
    [[ ! "$EG_CONFIRM2" =~ ^[Yy]$ ]] && { info "$(L '已取消')"; return; }
    step "$(L '安装系统依赖')"
    divider
    apt_install curl tar ca-certificates python3 || warn "$(L '部分依赖安装失败，继续尝试')"
    local need_download=1 have_ver=""
    if [ -x "$BIN_PATH" ]; then
        have_ver="$(${BIN_PATH} --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
        local have_major=""
        have_major="$(version_major "$have_ver")"
        if [ -z "$have_major" ] || [ "$have_major" -lt 3 ]; then
            warn "$(L '本机现有二进制版本过低或无法识别（需要 Nowhere v3 及以上），将下载最新版')"
        elif [ "$eg_carrier" = "tcp" ] && ! version_ge "${have_ver:-0}" "3.3.0"; then
            warn "$(L 'TLS 载体的 Egress 需要 Nowhere') ≥ $(L 'v3.3.0，本机现有二进制为') ${have_ver:-$(L '未知')}$(L '，将下载最新版')"
        else
            read -rp "$(L '已检测到 nowhere 二进制（')${have_ver:-$(L '未知版本')}$(L '），是否跳过下载直接使用？')[Y/n]: " EG_REUSE || { [ -n "$EG_REUSE" ] || return 1; }
            if [[ ! "${EG_REUSE:-y}" =~ ^[Nn]$ ]]; then
                need_download=0
                info "$(L '复用现有二进制:') $(${BIN_PATH} --version 2>&1 | awk "NR==1" || true)"
            fi
        fi
    fi
    if [ "$need_download" = "1" ]; then
        while true; do
            if install_nowhere_binary_only; then break; fi
            confirm "$(L '下载失败，是否立即重试？')" y || { warn "$(L '二进制下载失败，安装中止')"; return 1; }
        done
    fi
    step "$(L '保存 Egress 配置并创建 systemd 服务')"
    divider
    install -d -m 750 "$CONFIG_DIR"
    eg_handshake="${eg_handshake:-auto}"
    validate_handshake_timeout "$eg_handshake" || eg_handshake="auto"
    sanitize_nowhere_params
    # v8.6：auto 时不写 NOW_HANDSHAKE_TIMEOUT（严禁把字面量 auto 传给 nowhere 进程导致启动拒绝）
    (
        umask 077
        {
        printf 'NOWHERE_EGRESS="%s"
' "$eg_url"
        printf 'EGRESS_PORTAL_HOST="%s"
' "$eg_host"
        printf 'EGRESS_PORTAL_PORT="%s"
' "$eg_port"
        printf 'EGRESS_CARRIER="%s"
' "$eg_carrier"
        printf 'EGRESS_MORPH="%s"
' "$eg_morph"
        printf 'EGRESS_PRELUDE="%s"
' "$eg_prelude"
        printf 'EGRESS_HANDSHAKE_TIMEOUT="%s"
' "$eg_handshake"
        if [ "$eg_handshake" != "auto" ]; then
            printf 'NOW_HANDSHAKE_TIMEOUT="%s"
' "$eg_handshake"
        fi
        } > "$EGRESS_CONFIG_FILE"
    )
    chmod 600 "$EGRESS_CONFIG_FILE"
    setup_nowhere_user || true
    write_service_unit "$SERVICE_FILE" "Nowhere Egress" "https://github.com/${REPO}" "" "${NOWHERE_USER:-root}" "${NOWHERE_USER:-root}" "${BIN_PATH} \${NOWHERE_EGRESS}" "" "1048576" "on-failure" "3" "EnvironmentFile=${EGRESS_CONFIG_FILE}
Environment=NOW_MORPH_TCP_PRELUDE=${eg_prelude}
Environment=NOW_MORPH_UDP_PRELUDE=${eg_prelude}
PrivateTmp=false
ProtectSystem=full
ProtectHome=read-only"
    echo "egress" > "$ROLE_FILE"
    nowhere_fix_perms
    restart_nowhere_with_fallback 0 || true
    if systemctl is-active --quiet nowhere; then
        success "$(L 'Egress 服务已启动（注册结果请看日志：ACCEPTED 为成功；BUSY 表示 Portal 的待命注册容量已满（主要出现在 TLS 载体），本机会自动重试）')"
    else
        warn "$(L 'Egress 服务未能启动，日志如下：')"
        journalctl -u nowhere -n 30 --no-pager || true
        warn "$(L '安装中止：请按日志排查（常见：密钥 / pin / 端口 / Portal 未设 out=egress / 载体与 Portal 监听不对应）')"
        return 1
    fi
    ( umask 077; cat > "$EGRESS_CONFIG_TXT" ) << EGCONFEOF
════════════════════════════════════════════════════════════════
  $(L 'Nowhere Egress 连接信息（')${TARGET_NW_VERSION} $(L '/ NW3）')
  $(L '更新时间:') $(date '+%Y-%m-%d %H:%M:%S')
════════════════════════════════════════════════════════════════

$(L '【出口机启动参数（Egress URL，用于 systemd ExecStart）】')
${eg_url}

$(L '【说明】')
  $(L 'Portal 地址 :') ${eg_host}:${eg_port} (${eg_carrier}${eg_family})
  Morph       : ${eg_morph}$(L '（须与 Portal 一致）')$([ "$eg_morph" = "1" ] && echo "，Prelude 策略 ${eg_prelude}")
  $(L '握手超时    :') ${eg_handshake}$(L '（NOW_HANDSHAKE_TIMEOUT，v3.3.0 起未设置时从 Shared Key 派生 3s–30s）')
  $(L '本机角色    : Egress（主动回连 Portal，无需本机开放入站端口）')
  $(L 'v3.3.0 起同一 Portal 可同时接受多台 Egress（TLS / QUIC 可混用，Portal 按先进先出轮转，不保证均衡）。')
  $(L 'TLS 载体下每条 Flow 独占一条连接，本机会自动预建待命连接；BUSY 表示 Portal 的待命容量已满。')
  $(L 'tls=1 时 pin 随 Portal 重启变化，Portal 重启后需在本机更新 egress.env 里的 pin 并重启服务。')
════════════════════════════════════════════════════════════════
EGCONFEOF
    chmod 600 "$EGRESS_CONFIG_TXT"
    cat "$EGRESS_CONFIG_TXT"
    if [ -n "$old_portal_specs" ] && ufw_installed; then
        echo ""
        if confirm "$(L '本机不再是 Portal：删除防火墙里原 Portal 端口的放行规则（')$(echo $old_portal_specs)$(L '）？')" y; then
            local ops
            while IFS= read -r ops; do
                [ -n "$ops" ] || continue
                if [ "$ops" = "80/tcp" ] && xray_needs_port80; then continue; fi
                if port_used_by_other_services "$ops" nowhere; then
                    info "$(L '端口') ${ops} $(L '仍被其他服务使用，保留防火墙规则')"
                    continue
                fi
                fw_delete_spec "$ops"
            done < <(printf '%s\n' "$old_portal_specs" | tr ' ' '\n' | grep -v '^$')
        fi
    fi
    reserved_ports_sync || true
    echo ""
    info "$(L '常用命令：systemctl status nowhere / journalctl -u nowhere -f /') ${MANAGER_PATH} status"
    install_shortcuts || true
    verify_shortcuts || true
    maint_install_timers >/dev/null 2>&1 || true
    nowhere_fix_perms
}

# Xray 是否还在用 Cloudflare 凭证（有 xhttp-tls 域名证书节点即依赖它续期）
xray_uses_cf_creds() {
    [ -n "${XRAY_NODE_DIR:-}" ] && [ -d "$XRAY_NODE_DIR" ] || return 1
    grep -l 'N_TYPE="xhttp-tls"' "${XRAY_NODE_DIR}"/*.env >/dev/null 2>&1
}

# xray_needs_port80：Xray 任一节点证书由 certbot standalone（HTTP-01）签发时，续期仍需 80 端口（L10）
xray_needs_port80() {
    local f dom
    [ -n "${XRAY_NODE_DIR:-}" ] && [ -d "$XRAY_NODE_DIR" ] || return 1
    for f in "${XRAY_NODE_DIR}"/*.env; do
        [ -f "$f" ] || continue
        dom="$(sed -n 's#^N_CERT_SRC="/etc/letsencrypt/live/\([^/]*\)/.*#\1#p' "$f" | head -1 || true)"
        [ -n "$dom" ] || continue
        if grep -q '^authenticator *= *standalone' "/etc/letsencrypt/renewal/${dom}.conf" 2>/dev/null; then return 0; fi
    done
    return 1
}

# Xray 任一节点证书来源是否指向 acme.sh（M5：删 acme.sh cron 前先查）
xray_uses_acmesh() {
    [ -n "${XRAY_NODE_DIR:-}" ] && [ -d "$XRAY_NODE_DIR" ] || return 1
    grep -rl 'acme\.sh' "${XRAY_NODE_DIR}"/*.env >/dev/null 2>&1
}

do_uninstall() {
    maint_lock_manual || return
    step "$(L '卸载 Nowhere')"
    divider
    read -rp "$(L '确认卸载') [y/N]: " CONFIRM || { [ -n "$CONFIRM" ] || return 1; }
    [[ ! "$CONFIRM" =~ ^[Yy]$ ]] && { info "$(L '已取消')"; return; }
    local old_specs s cron_now
    old_specs="$(nowhere_ports 2>/dev/null || true)"
    systemctl disable --now nowhere 2>/dev/null || true
    local _had_deploy_hook=0
    [ -x /etc/letsencrypt/renewal-hooks/deploy/restart-nowhere.sh ] && _had_deploy_hook=1
    rm -f "$SERVICE_FILE" "$BIN_PATH" "$BIN_BACKUP_PATH" "$ROLE_FILE" "${CONFIG_DIR}/cert-sync.sh"
    rm -f /etc/letsencrypt/renewal-hooks/deploy/restart-nowhere.sh           /etc/letsencrypt/renewal-hooks/pre/stop-nowhere.sh           /etc/letsencrypt/renewal-hooks/post/start-nowhere.sh           /run/nowhere-stopped-by-certbot
    cron_now="$(crontab -l 2>/dev/null || true)"
    local _cron_changed=0
    # 卸载前若存在本脚本的 deploy hook 且无 Xray 续期依赖，则清理 certbot renew 兜底 cron
    if [ "$_had_deploy_hook" = "1" ] && ! xray_needs_port80 && ! xray_uses_cf_creds; then
        if [[ "$cron_now" == *"certbot renew"* ]]; then
            cron_now="$(printf '%s\n' "$cron_now" | grep -v 'certbot renew' || true)"
            _cron_changed=1
            info "$(L '已移除 certbot 续期的 cron 兜底任务')"
        fi
    elif [[ "$cron_now" == *"certbot renew --quiet --deploy-hook"* ]]; then
        cron_now="$(printf '%s\n' "$cron_now" | grep -v 'certbot renew --quiet --deploy-hook' || true)"
        _cron_changed=1
        info "$(L '已移除 certbot 续期的 cron 兜底任务')"
    fi
    # acme.sh cron：Xray 仍在用 acme.sh 续期时保留，否则删除
    if [[ "$cron_now" == *"acme.sh"*"--cron"* ]]; then
        if xray_uses_acmesh; then
            warn "$(L 'Xray 仍在使用 acme.sh 续期，已保留 acme.sh 的 cron 任务')"
        else
            cron_now="$(printf '%s\n' "$cron_now" | grep -v 'acme.sh.*--cron' || true)"
            _cron_changed=1
            info "$(L '已移除 acme.sh 的 cron 续期任务')"
        fi
    fi
    if [ "$_cron_changed" = "1" ]; then
        printf '%s\n' "$cron_now" | crontab - 2>/dev/null || true
    fi
    if [ -d "$ACME_HOME" ]; then
        warn "$(L 'acme.sh 目录仍保留，如确认不再需要请手动删除：rm -rf ~/.acme.sh')"
    fi
    if [ -n "$old_specs" ] && ufw_installed; then
        if confirm "$(L '同时删除防火墙里 Nowhere 端口的放行规则（')$(echo $old_specs)$(L '）？')" y; then
            while IFS= read -r s; do
                [ -n "$s" ] || continue
                if [ "$s" = "80/tcp" ] && xray_needs_port80; then continue; fi
                port_used_by_other_services "$s" nowhere && continue
                fw_delete_spec "$s"
            done < <(printf '%s\n' "$old_specs" | tr ' ' '\n' | grep -v '^$')
        fi
    fi
    if [ -f /etc/cloudflare/credentials.ini ]; then
        if xray_uses_cf_creds; then
            warn "$(L 'Cloudflare 凭证仍被 Xray 域名证书节点使用（xhttp-tls，续期也依赖它），未删除；如 Xray 已卸载或不再用该凭证，请手动删除')"
        elif confirm "$(L '删除保存的 Cloudflare API 凭证（/etc/cloudflare/credentials.ini）？')" n; then
            rm -f /etc/cloudflare/credentials.ini
            info "$(L '已删除 Cloudflare 凭证')"
        fi
    fi
    if realm_installed || [ -d "$REALM_DIR" ] || [ -f "$REALM_SERVICE" ]; then
        if confirm "$(L '是否同时卸载 Realm 端口转发？')" n; then
            realm_uninstall_do
        fi
    fi
    if caddy_installed || cf_tunnel_installed || [ -d "$CADDY_DIR" ] || [ -d "$CF_TUNNEL_DIR" ]; then
        if confirm "$(L '是否同时卸载域名反代（Caddy / Cloudflare Tunnel）？')" n; then
            caddy_uninstall_do || true
            cf_tunnel_uninstall_do || true
        fi
    fi
    read -rp "$(L '是否同时删除快捷命令 adam/zt/pz/cxpz/cq？')[y/N]: " RM_SHORTCUTS || { [ -n "$RM_SHORTCUTS" ] || return 1; }
    if [[ "$RM_SHORTCUTS" =~ ^[Yy]$ ]]; then
        if [ -x "$SNELL_BIN" ] || [ -x "$XRAY_BIN" ] || ufw_installed || f2b_installed; then
            warn "$(L '删除后 Snell / Xray / 防火墙 / Fail2ban 的管理入口需改用') ${MANAGER_PATH} $(L '直接运行（Snell 自动更新不受影响）')"
        fi
        rm -f /usr/local/bin/adam /usr/local/bin/zt /usr/local/bin/pz /usr/local/bin/cxpz /usr/local/bin/cq
        info "$(L '快捷命令已删除（管理脚本副本') ${MANAGER_PATH} $(L '已保留，如需清除请手动删除）')"
    fi
    systemctl daemon-reload
    reserved_ports_sync || true
    warn "$(L '已保留') ${CONFIG_DIR}$(L '（含密钥配置与证书文件），如需彻底清除请手动: rm -rf') ${CONFIG_DIR}"
    success "$(L 'Nowhere 已卸载')"
}

do_update() {
    maint_lock_manual || return
    step "$(L '更新 Nowhere 二进制（更新到最新版）')"
    divider
    local current
    current="$(read_installed_version)"
    info "$(L '当前版本:') ${current}"
    info "$(L '正在获取最新版本号...')"
    local latest
    latest="$(get_latest_tag)"
    [ -z "$latest" ] && error "$(L '无法获取版本号（GitHub API 与 releases/latest 跳转均失败），请检查网络')"
    info "$(L '最新版本:') ${latest}"

    if [ "$current" = "$latest" ]; then
        info "$(L '已经是最新版本，无需更新')"
        return
    fi

    local cur_major latest_major cross_major=0
    cur_major="$(version_major "$current")"
    latest_major="$(version_major "$latest")"
    if [[ -n "$cur_major" && -n "$latest_major" && "$cur_major" != "$latest_major" ]]; then
        cross_major=1
        warn "$(L '这是跨协议代升级（NW')${cur_major} -> NW${latest_major}$(L '）：新旧对端不互通，Vector/Egress/Anywhere 必须一起升级')"
        warn "$(L '且不同协议代的密钥格式、URL 参数可能不兼容，仅换二进制不重配大概率启动失败或连不上')"
        read -rp "$(L '确认跨代升级') [y/N]: " MAJOR_CONFIRM || { [ -n "$MAJOR_CONFIRM" ] || return 1; }
        [[ ! "$MAJOR_CONFIRM" =~ ^[Yy]$ ]] && { info "$(L '已取消')"; return; }
    elif [ "$(current_role)" = "portal" ] && version_ge "$latest" "v3.2.0" && ! version_ge "$current" "v3.2.0"; then
        warn "$(L '本次升级会跨过 v3.2.0：此后 Portal 只接受带认证的 Morph TCP Prelude，仍在 v3.0.x 的 Vector/Egress/Anywhere（morph=1 + TLS/TCP）会连不上')"
        warn "$(L '稳妥做法：先把对端升级到') ≥ $(L 'v3.1.0，再升级本机 Portal')"
        read -rp "$(L '对端已就绪，继续升级') [y/N]: " PRELUDE_CONFIRM || { [ -n "$PRELUDE_CONFIRM" ] || return 1; }
        [[ ! "$PRELUDE_CONFIRM" =~ ^[Yy]$ ]] && { info "$(L '已取消')"; return; }
    fi

    install_nowhere_version "$latest" || error "$(L '更新失败')"
    if [ "$cross_major" = "1" ]; then
        warn "$(L '跨代升级后请接着用Nowhere 菜单「3')) $(L '重新配置」按新版向导重建配置（新密钥 + 新 URL），再同步更新所有对端')"
    fi
}


# Nowhere 定时自动更新（仅限 NW3 同大版本，不跨代；校验 SHA256 + 预检 + 失败自动回滚）
nowhere_autoupdate() {
    [ -x "$BIN_PATH" ] || return 0
    local current latest cur_major latest_major
    current="$(read_installed_version)"
    latest="$(get_latest_tag)"
    if [ -z "$latest" ]; then
        echo "[Nowhere] $(L '未能获取官方版本信息，本次跳过；当前') ${current:-$(L '未知')}"
        return 1
    fi
    cur_major="$(version_major "$current")"
    latest_major="$(version_major "$latest")"
    if [ -n "$latest_major" ] && [ "$latest_major" != "3" ]; then
        echo "[Nowhere] $(L '最新版本属于另一个大版本（v')${latest_major}$(L '），不自动跨大版本，当前') ${current:-$(L '未知')}"
        return 0
    fi
    if [ -n "$cur_major" ] && [ "$cur_major" != "3" ]; then
        echo "[Nowhere] $(L '当前安装的是') ${current:-$(L '未知')}$(L '，不自动跨大版本')"
        return 0
    fi
    if [ -n "$current" ] && [ "$current" = "$latest" ]; then
        echo "[Nowhere] $(L '已是最新:') ${current}"
        return 0
    fi
    if [ -n "$current" ] && version_ge "$current" "$latest"; then
        echo "[Nowhere] $(L '已是最新:') ${current}"
        return 0
    fi
    # 跨 v3.2.0 存在 Authenticated Prelude 兼容要求，定时任务跳过并提示手动升级
    if [ "$(current_role)" = "portal" ] && [ -n "$current" ] && version_ge "$latest" "v3.2.0" && ! version_ge "$current" "v3.2.0"; then
        maint_log "[Nowhere] 发现 ${latest}（跨 v3.2.0 需先升级对端），跳过自动更新"
        return 0
    fi
    echo "[Nowhere] $(L '发现新版本:') ${current:-$(L '未知')} -> ${latest}$(L '，开始更新')"
    if install_nowhere_version "$latest"; then
        save_current_pin >/dev/null 2>&1 || true
        maint_log "[Nowhere] $(L '已自动更新:') ${current:-$(L '未知')} -> ${latest}"
        return 0
    fi
    maint_log "[Nowhere] $(L '自动更新到') ${latest} $(L '失败，当前仍为') $(read_installed_version)"
    return 1
}

do_show_version() {
    step "$(L '版本信息')"
    divider
    local current previous
    current="$(read_installed_version)"
    previous="$(read_previous_version)"

    if [ -x "$BIN_PATH" ]; then
        echo -e "  $(L '当前运行的二进制  :') ${GREEN}$(${BIN_PATH} --version 2>&1 | awk "NR==1" || true)${NC}"
    else
        warn "$(L '未检测到已安装的 Nowhere 二进制')"
    fi
    echo -e "  $(L '记录的版本 tag    :') ${GREEN}${current}${NC}"
    [ -n "$previous" ] && echo -e "  $(L '上一个版本 tag    :') ${YELLOW}${previous}${NC}$(L '（可用「版本回退」快速切回）')"
    echo -e "  $(L '本机角色          :') ${GREEN}$(current_role)${NC}"
    echo -e "  $(L '管理脚本版本      :') ${GREEN}${SCRIPT_VERSION}${NC}$(L '（适配 Nowhere') ${TARGET_NW_VERSION}$(L '）')"

    echo ""
    info "$(L '正在查询 GitHub 最新版本...')"
    local latest
    latest="$(get_latest_tag)"
    if [ -n "$latest" ]; then
        if [ "$current" = "$latest" ]; then
            success "$(L '已是最新版本') (${latest})"
        else
            warn "$(L '有新版本可用:') ${latest}$(L '（当前') ${current}$(L '），可用 Nowhere 菜单「13')) $(L '更新 Nowhere 二进制」升级')"
        fi
    else
        warn "$(L '无法查询最新版本，请检查网络')"
    fi
}

do_select_version() {
    step "$(L '选择要安装的版本（支持回退到历史版本）')"
    divider
    local current
    current="$(read_installed_version)"
    info "$(L '当前版本:') ${current}"
    info "$(L '正在获取版本列表...')"

    local tags=() line
    while IFS= read -r line; do
        [ -n "$line" ] && tags+=("$line")
    done < <(secure_curl -fs --max-time 20 "https://api.github.com/repos/${REPO}/releases?per_page=20" 2>/dev/null | github_extract_tag_names || true)

    if [ "${#tags[@]}" -eq 0 ]; then
        error "$(L '未能获取版本列表，请检查网络')$(L '（可能被 GitHub 限流，请稍后重试）')"
    fi

    echo ""
    local i=1 t
    for t in "${tags[@]}"; do
        if [ "$t" = "$current" ]; then
            echo -e "  ${BOLD}${i})${NC} ${t}  ${GREEN}← $(L '当前版本')${NC}"
        else
            echo -e "  ${BOLD}${i})${NC} ${t}"
        fi
        i=$((i+1))
    done
    echo -e "  ${BOLD}0)${NC} $(L '取消')"
    divider
    read -rp "$(L '选择要切换到的版本序号:') " VER_CHOICE || { [ -n "$VER_CHOICE" ] || return 1; }

    [[ "$VER_CHOICE" == "0" || -z "$VER_CHOICE" ]] && { info "$(L '已取消')"; return; }
    if ! [[ "$VER_CHOICE" =~ ^[0-9]+$ ]] || [ "${#VER_CHOICE}" -gt 5 ]; then
        warn "$(L '无效选择')"
        return
    fi
    VER_CHOICE=$((10#$VER_CHOICE))
    if [ "$VER_CHOICE" -lt 1 ] || [ "$VER_CHOICE" -gt "${#tags[@]}" ]; then
        warn "$(L '无效选择')"
        return
    fi

    local target="${tags[$((VER_CHOICE-1))]}"
    if [ "$target" = "$current" ]; then
        info "$(L '已经是该版本，无需切换')"
        return
    fi

    read -rp "$(L '确认切换到') ${target} [y/N]: " CONFIRM || { [ -n "$CONFIRM" ] || return 1; }
    [[ ! "$CONFIRM" =~ ^[Yy]$ ]] && { info "$(L '已取消')"; return; }

    install_nowhere_version "$target" || error "$(L '切换失败，服务可能未正常启动，请检查日志')"
}

do_rollback() {
    step "$(L '版本回退')"
    divider
    if [ ! -f "$BIN_BACKUP_PATH" ]; then
        warn "$(L '没有可用于回退的本地备份版本')"
        info "$(L '备份仅在执行过「更新」或「选择版本」之后才会生成')"
        return
    fi

    local current previous
    current="$(read_installed_version)"
    previous="$(read_previous_version)"
    echo -e "  $(L '当前版本 :') ${GREEN}${current}${NC}"
    echo -e "  $(L '回退目标 :') ${YELLOW}${previous:-$(L '未知版本（本地备份二进制）')}${NC}"
    divider
    read -rp "$(L '确认回退') [y/N]: " CONFIRM || { [ -n "$CONFIRM" ] || return 1; }
    [[ ! "$CONFIRM" =~ ^[Yy]$ ]] && { info "$(L '已取消')"; return; }

    if ! "$BIN_BACKUP_PATH" --version >/dev/null 2>&1; then
        warn "$(L '新二进制试运行失败')"
        info "$(L '备份二进制无法运行，回退已中止')"
        return 1
    fi

    local tmp_bin rolled_to had_bin=0
    make_workdir || return 1
    tmp_bin="${WORKDIR}/nowhere.swap"
    if [ -f "$BIN_PATH" ]; then
        cp "$BIN_PATH" "$tmp_bin" || { warn "$(L '备份当前二进制失败，回退中止')"; return 1; }
        had_bin=1
    fi

    _CACHED_TLS_FP=""
    # install 直接替换运行中的二进制，随后一次 restart 完成切换（与 install_nowhere_version 一致，
    # 比旧版 stop -> 替换 -> start 少一段停机窗口）；任一步失败即中止，避免半交换状态
    install -m 755 "$BIN_BACKUP_PATH" "$BIN_PATH" || { warn "$(L '回退替换失败，当前二进制未动')"; return 1; }
    if [ "$had_bin" = "1" ]; then
        install -m 755 "$tmp_bin" "$BIN_BACKUP_PATH" || { install -m 755 "$tmp_bin" "$BIN_PATH" 2>/dev/null || true; warn "$(L '备份交换失败，已尽力恢复原二进制')"; return 1; }
        rm -f "$tmp_bin"
    fi

    record_previous_version "$current"
    # 回滚后以实际安装的二进制版本为准；版本文件只写版本号，不写本地化文案
    rolled_to="$("$BIN_PATH" --version 2>&1 | grep -oE 'v?[0-9]+\.[0-9]+\.[0-9]+([-.][A-Za-z0-9._]+)?' | head -1 || true)"
    case "$rolled_to" in v*) : ;; [0-9]*) rolled_to="v$rolled_to" ;; esac
    [ -z "$rolled_to" ] && rolled_to="$previous"
    [ -n "$rolled_to" ] && echo "$rolled_to" > "$VERSION_FILE"

    nowhere_fix_perms
    systemctl restart nowhere 2>/dev/null || true
    sleep 2
    if systemctl is-active --quiet nowhere; then
        success "$(L '已回退到:') $(${BIN_PATH} --version 2>&1 | awk "NR==1" || true)"
        if [ "$(current_role)" = "portal" ] && [ -f "$CONFIG_FILE" ]; then
            ( load_saved_config 2>/dev/null && [ "${TLS_MODE:-}" = "1" ] && save_current_pin >/dev/null 2>&1 ) || true
        fi
    else
        warn "$(L '回退后服务启动失败，日志如下：')"
        journalctl -u nowhere -n 20 --no-pager || true
    fi
}

do_reconfig() {
    step "$(L '重新配置')"
    divider
    warn "$(L '将重新走一遍安装向导并覆盖当前配置')"
    warn "$(L '注意：v3 密钥与 URL 语法已变更，重新配置后务必把新的 Vector/Egress/Anywhere 连接信息同步到所有对端，旧链接无法继续使用')"
    read -rp "$(L '确认继续') [y/N]: " CONFIRM || { [ -n "$CONFIRM" ] || return 1; }
    [[ ! "$CONFIRM" =~ ^[Yy]$ ]] && return
    do_install
}

do_show_config() {
    step "$(L '连接信息')"
    divider
    if [ "$(current_role)" = "egress" ]; then
        if [ -f "$EGRESS_CONFIG_TXT" ]; then
            cat "$EGRESS_CONFIG_TXT"
        else
            warn "$(L '本机为 Egress 角色，但未找到') ${EGRESS_CONFIG_TXT}$(L '，请用 Nowhere 菜单 2 重新安装')"
        fi
        return 0
    fi
    if [ -f "$CONFIG_FILE" ]; then
        load_saved_config
        _CACHED_TLS_FP=""
        [ "${TLS_MODE:-}" = "1" ] && _CACHED_TLS_FP="$(get_tls_fingerprint 2>/dev/null || true)"
        # 每次查看都按当前保存参数重新生成（含最新自签 pin），避免展示过期指纹的旧串
        NOWHERE_PORTAL="$(build_portal_url)"
        build_client_links
        build_vector_info
        build_egress_info
        print_all_info
        save_current_pin >/dev/null 2>&1 || true
    elif [ -f "${CONFIG_DIR}/config.txt" ]; then
        cat "${CONFIG_DIR}/config.txt"
    else
        warn "$(L '未找到配置，请先安装')"
    fi
}

do_show_status() {
    step "$(L '服务状态')"
    divider
    # systemctl status 在服务停止时返回非 0：旧版在 set -e 下会在这里直接退出，
    # 恰好是服务挂了、最需要看后面日志的时候
    systemctl status nowhere --no-pager || true
    divider
    if [ -x "$BIN_PATH" ]; then
        info "$(L 'Nowhere 本地实例快照（nowhere status，v3 内置遥测）：')"
        "$BIN_PATH" status 2>&1 || warn "$(L 'nowhere status 未能读取到实例（服务未运行，或二进制版本低于 v2.1.2 无此命令）')"
        divider
    fi
    info "$(L '最近日志（20行）：')"
    journalctl -u nowhere -n 20 --no-pager || true
}

do_show_logs() {
    step "$(L '实时日志（Ctrl+C 退出）')"
    divider
    journalctl -u nowhere -f || true
}

do_fingerprint() {
    if [ "$(current_role)" = "egress" ]; then
        info "$(L '本机是 Egress 角色，没有监听证书；Portal 的证书指纹请在 Portal 机上查看')"
        return 0
    fi
    load_saved_config
    print_tls_fingerprint
}

do_restart() {
    _CACHED_TLS_FP=""
    if svc_restart_wait nowhere 1 15; then
        success "$(L '已重启')"
    else
        error "$(L '重启失败，请按上方日志排查')"
    fi
    if [ "$(current_role)" = "egress" ] || [ ! -f "$CONFIG_FILE" ]; then
        return 0
    fi
    load_saved_config
    print_tls_fingerprint
    if [[ "${TLS_MODE:-}" == "1" ]]; then
        save_current_pin || true
        warn "$(L '自签证书指纹已随本次重启变化，请用 pz / Nowhere 菜单 4 重新生成带新 pin= 的 Vector/Egress 连接串并同步到对端')"
    fi
    return 0
}

do_genkey() {
    step "$(L '生成 v3 共享密钥')"
    divider
    local k
    k="$(gen_key)"
    if is_valid_key "$k"; then
        echo -e "  ${GREEN}${k}${NC}"
        info "$(L '格式：32 位小写十六进制（16 随机字节）。Portal、Vector、Egress、Anywhere 四端必须填完全相同的这串字符')"
    else
        error "$(L '生成失败：openssl 与 nowhere 二进制均不可用')"
    fi
}

_run_nowhere_probe_cmd() {
    local vurl="$1" tgt="$2"
    (
        export NOW_MORPH_TCP_PRELUDE="${MORPH_TCP_PRELUDE:-fade}"
        export NOW_MORPH_UDP_PRELUDE="${MORPH_UDP_PRELUDE:-fade}"
        if [ -z "${HANDSHAKE_TIMEOUT:-}" ] || [ "$HANDSHAKE_TIMEOUT" = "auto" ]; then
            unset NOW_HANDSHAKE_TIMEOUT
        else
            export NOW_HANDSHAKE_TIMEOUT="$HANDSHAKE_TIMEOUT"
        fi
        "$BIN_PATH" probe "$vurl" "$tgt"
    )
}

do_probe() {
    step "$(L '连通性探测 probe（真实 TCP Flow，不发送业务数据）')"
    divider
    [ -x "$BIN_PATH" ] || error "$(L '未找到 Nowhere 二进制，请先安装')"
    if [ "$(current_role)" = "egress" ]; then
        info "$(L '本机是 Egress 角色：probe 需要以 Vector 身份连接 Portal，请在 Portal 机或客户端机上执行')"
        return 0
    fi
    local local_mode=0 arg target=""
    for arg in "$@"; do
        case "$arg" in
            --local|-l) local_mode=1 ;;
            *) [ -z "$target" ] && target="$arg" ;;
        esac
    done
    load_saved_config
    is_valid_key "$SHARED_KEY" || error "$(L '当前密钥不符合 v3 规范，无法探测，请先用 Nowhere 菜单 3 重新配置')"
    _CACHED_TLS_FP=""
    [ "${TLS_MODE:-}" = "1" ] && _CACHED_TLS_FP="$(get_tls_fingerprint 2>/dev/null || true)"
    local vector_url
    if [ "$local_mode" = "1" ]; then
        vector_url="$(build_probe_vector_url --local || true)"
    else
        vector_url="$(build_probe_vector_url || true)"
    fi
    [ -n "$vector_url" ] || error "$(L '未能确定公网地址，无法生成 Vector 探针链接')"
    if [ -z "$target" ]; then
        if [ -t 0 ]; then
            read -rp "$(L '目标地址 host:port（回车默认 example.com:443）:') " target || { [ -n "$target" ] || return 1; }
        else
            read -r target 2>/dev/null || true
        fi
    fi
    target=${target:-example.com:443}
    info "Vector: ${vector_url/$SHARED_KEY/$(mask_secret "$SHARED_KEY")}"
    info "Target: ${target}"
    # v8.6：HANDSHAKE_TIMEOUT=auto 时不传 NOW_HANDSHAKE_TIMEOUT（避免把字面量 auto 传给 nowhere 导致启动拒绝）
    local probe_out="" probe_rc=0
    probe_out="$(_run_nowhere_probe_cmd "$vector_url" "$target" 2>&1)" || probe_rc=$?
    [ -n "$probe_out" ] && printf '%s\n' "$probe_out"
    if [ "$probe_rc" -eq 0 ]; then
        return 0
    fi
    # v8.7：公网探测因云厂商 NAT 无回流（Hairpin NAT）失败时，在 tls=1 下自动回环自测定位故障边界
    if [ "$local_mode" = "0" ] && [[ "$probe_out" == *"TRANSPORT_FAILED"* ]]; then
        if [ "${TLS_MODE:-}" = "1" ]; then
            local local_url
            local_url="$(build_probe_vector_url --local || true)"
            if [ -n "$local_url" ] && [ "$local_url" != "$vector_url" ]; then
                info "$(L '公网地址本机回连超时（云厂商 NAT 常见无回流限制），自动改用本机回环地址复测...')"
                info "Vector: ${local_url/$SHARED_KEY/$(mask_secret "$SHARED_KEY")}"
                if _run_nowhere_probe_cmd "$local_url" "$target"; then
                    success "$(L '本机回环探测通过：Portal 服务端与出口链路均正常（公网回连失败通常仅因云厂商 NAT 无回流或安全组未放行）')"
                    return 0
                fi
            fi
        else
            info "$(L '提示：若本机处于 AWS/GCP/阿里云等 NAT 环境，公网地址本机回连常因无回流失败，请从客户端侧验证或检查云安全组端口')"
        fi
    fi
    warn "$(L '探测未成功（Result 非 OK）。常见原因：Portal 出口不可达、没有可用的 Egress（会等到 Flow 建立超时）、对端 Morph/pin/密钥不一致、目标本身不可达')"
    return 1
}

# svc_restart_wait UNIT [SECONDS] [LOG_LINES]：重启 → 等待 → 仍未 active 则打日志并返回 1（M14）
svc_restart_wait() {
    local unit="$1" secs="${2:-2}" lines="${3:-20}"
    systemctl restart "$unit" 2>/dev/null || true
    sleep "$secs"
    if systemctl is-active --quiet "$unit" 2>/dev/null; then return 0; fi
    journalctl -u "$unit" -n "$lines" --no-pager 2>/dev/null || true
    return 1
}

do_migrate_tls2() {
    step "$(L 'tls=1 升级为真实证书') (tls=2)"
    divider
    local MIG_BAK=""
    if [ "$(current_role)" != "portal" ]; then
        warn "$(L '本机不是 Portal 角色（当前：')$(current_role)$(L '），无需迁移证书')"
        return 0
    fi
    [ -f "$CONFIG_FILE" ] || error "$(L '未找到配置文件，请先执行安装')"
    load_saved_config
    if [ "${TLS_MODE:-}" != "1" ]; then
        info "$(L '当前已是 tls=2 真实证书模式，无需迁移（证书状态见 Nowhere 菜单 11）')"
        return 0
    fi
    warn "$(L '迁移后 Portal 改用域名 + CA 证书（tls=2），Vector/Egress 不再需要 pin=；')"
    warn "$(L '旧的 pin= 连接串随即失效，需用新生成的连接串同步所有对端。')"
    echo ""
    echo "  1) Let'$(L 's Encrypt HTTP-01 - 需要域名解析到本机 + 开放 80 端口（自动续期）')"
    echo "  2) $(L 'Cloudflare DNS-01 - 需要 CF API Key/Token（自动续期，推荐；80 端口可不开）')"
    echo "  $(L '（通用 DNS-01 / acme.sh 请用 Nowhere 菜单 3 重新配置）')"
    read -rp "$(L '选择') [$(L '1/2，回车取消')]: " MIG_METHOD || { [ -n "$MIG_METHOD" ] || return 1; }
    case "$MIG_METHOD" in
        1) MIG_CERT_METHOD="letsencrypt-http" ;;
        2) MIG_CERT_METHOD="cloudflare-dns" ;;
        *) info "$(L '已取消')"; return 0 ;;
    esac
    while true; do
        read -rp "$(L '域名（须已解析到本机）:') " MIG_DOMAIN || { [ -n "$MIG_DOMAIN" ] || return 1; }
        MIG_DOMAIN=$(echo "$MIG_DOMAIN" | tr -d ' \r\n')
        MIG_DOMAIN="${MIG_DOMAIN,,}"
        if [ -n "$MIG_DOMAIN" ] && [[ "$MIG_DOMAIN" == *.* ]] && is_safe_host "$MIG_DOMAIN"; then break; fi
        warn "$(L '域名格式不正确')"
    done
    while true; do
        read -rp "$(L 'ACME 邮箱（Let')'$(L 's Encrypt 账户用）:') " MIG_EMAIL || { [ -n "$MIG_EMAIL" ] || return 1; }
        MIG_EMAIL=$(echo "$MIG_EMAIL" | tr -d ' \r\n')
        if [[ "$MIG_EMAIL" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then break; fi
        warn "$(L '邮箱格式不正确')"
    done
    if [ "$MIG_CERT_METHOD" = "cloudflare-dns" ]; then
        if [ -s /etc/cloudflare/credentials.ini ] && confirm "$(L '检测到已有 Cloudflare 凭证文件（/etc/cloudflare/credentials.ini），是否直接复用？')" y; then
            CF_KEY=""
        else
            prompt_cloudflare_creds || { info "$(L '已取消')"; return 0; }
            write_cloudflare_creds
        fi
    fi
    read -rp "$(L '确认把') ${MIG_DOMAIN} $(L '的证书装到本 Portal 并重启服务？')[y/N]: " MIG_CONFIRM || { [ -n "$MIG_CONFIRM" ] || return 1; }
    [[ "$MIG_CONFIRM" =~ ^[Yy]$ ]] || { info "$(L '已取消')"; return 0; }

    DOMAIN="$MIG_DOMAIN"; PUBLIC_HOST="$MIG_DOMAIN"; EMAIL="$MIG_EMAIL"
    CERT_METHOD="$MIG_CERT_METHOD"; TLS_MODE="2"
    CRT="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
    KEY_PEM="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
    CRT_RUNTIME="$CRT"
    KEY_PEM_RUNTIME="$KEY_PEM"
    apt_install certbot || error "$(L 'certbot 安装失败')"
    [ "$CERT_METHOD" = "cloudflare-dns" ] && apt_install python3-certbot-dns-cloudflare
    ensure_ipv4_preference
    while true; do
        if [ "$CERT_METHOD" = "letsencrypt-http" ]; then
            check_domain_dns "$DOMAIN" || true
        fi
        if obtain_portal_cert; then break; fi
        if ! confirm "$(L '证书获取失败，是否重试或更换证书方式？')" y; then return 1; fi
        if [ "$CERT_METHOD" = "cloudflare-dns" ]; then
            prompt_cloudflare_creds && write_cloudflare_creds || return 1
        fi
    done

    # 同步保存的配置：域名 / TLS 模式 / 证书路径 / 重建的 Portal URL / 握手超时（整文件重写，与 do_install 一致）
    # 低权用户运行时：先把新证书同步到服务可读的副本，再生成 URL（URL 里嵌证书路径）；同步失败自动回退 root
    if grep -q '^User=nowhere' "$SERVICE_FILE" 2>/dev/null; then
        NOWHERE_USER="nowhere"
        if ! sync_portal_cert_copy; then
            warn "$(L '证书副本同步失败，服务可能无法读取新证书')"
            NOWHERE_USER="root"
            CRT_RUNTIME="$CRT"
            KEY_PEM_RUNTIME="$KEY_PEM"
        fi
    else
        NOWHERE_USER="root"
    fi
    NOWHERE_PORTAL="$(build_portal_url)"
    MIG_BAK="${CONFIG_FILE}.bak.$(date +%Y%m%d-%H%M%S)"
    local MIG_SVC_BAK
    MIG_SVC_BAK="${SERVICE_FILE}.bak.$(date +%Y%m%d-%H%M%S)"
    cp -f "$CONFIG_FILE" "$MIG_BAK" 2>/dev/null || warn "$(L '旧配置备份失败，迁移继续（失败时无法自动恢复）')"
    [ -f "$SERVICE_FILE" ] && cp -p "$SERVICE_FILE" "$MIG_SVC_BAK" 2>/dev/null || MIG_SVC_BAK=""
    write_portal_env || error "$(L '配置保存失败，已中止')"
    # v8.6：统一由 nowhere_write_portal_unit 同步 unit（auto 时不写 NOW_HANDSHAKE_TIMEOUT，避免旧 unit 残留或写入字面量 auto）
    nowhere_write_portal_unit
    nowhere_fix_perms
    systemctl daemon-reload
    _CACHED_TLS_FP=""
    if restart_nowhere_with_fallback 1; then
        [ -n "$MIG_BAK" ] && rm -f "$MIG_BAK"
        [ -n "$MIG_SVC_BAK" ] && rm -f "$MIG_SVC_BAK"
        success "$(L '迁移完成：已是 tls=2，服务运行中')"
    else
        warn "$(L '迁移重启失败，已恢复旧配置并再次重启，请按日志排查')"
        if [ -n "$MIG_BAK" ] && [ -f "$MIG_BAK" ]; then mv -f "$MIG_BAK" "$CONFIG_FILE"; fi
        if [ -n "$MIG_SVC_BAK" ] && [ -f "$MIG_SVC_BAK" ]; then mv -f "$MIG_SVC_BAK" "$SERVICE_FILE"; systemctl daemon-reload 2>/dev/null || true; fi
        rm -f /etc/letsencrypt/renewal-hooks/deploy/restart-nowhere.sh /etc/letsencrypt/renewal-hooks/pre/stop-nowhere.sh /etc/letsencrypt/renewal-hooks/post/start-nowhere.sh
        nowhere_fix_perms
        if svc_restart_wait nowhere 2 15; then
            ( load_saved_config 2>/dev/null && save_current_pin >/dev/null 2>&1 ) || true
            warn "$(L '已恢复旧配置，服务已恢复运行（仍为 tls=1）')"
            return 1
        fi
        error "$(L '迁移失败：已恢复旧配置，但服务仍未启动，请按上方日志排查')"
    fi
    rm -f "$TLS_PIN_FILE"
    load_saved_config
    NOWHERE_PORTAL="$(build_portal_url)"
    build_client_links; build_vector_info; build_egress_info
    print_all_info
    warn "$(L '请把上面新的连接串同步到全部 Vector / Egress / Anywhere 对端，旧 pin= 连接串已失效')"
}

do_cert_status() {
    step "$(L '证书状态与续期')"
    divider
    if [ "$(current_role)" = "egress" ]; then
        info "$(L '本机是 Egress 角色，不持有监听证书，无需续期')"
        return 0
    fi
    [ -f "$CONFIG_FILE" ] || error "$(L '未找到配置文件，请先执行安装')"
    load_saved_config
    if [ "$TLS_MODE" != "2" ]; then
        info "$(L '当前为自签模式（tls=1），证书只存在内存中、无需续期')"
        return
    fi
    echo -e "  $(L '域名       :') ${GREEN}${DOMAIN}${NC}"
    echo -e "  $(L '证书路径   :') ${GREEN}${CRT}${NC}"
    echo -e "  $(L '申请方式   :') ${GREEN}${CERT_METHOD}${NC}"
    local days
    days="$(cert_expiry_days "$CRT" 2>/dev/null || echo "")"
    if [ -n "$days" ]; then
        if [ "$days" -lt 0 ]; then
            warn "$(L '证书已过期') $((-days)) $(L '天！请立即手动续期')"
        elif [ "$days" -le 30 ]; then
            warn "$(L '证书剩余') ${days} $(L '天（30 天内到期），建议立即手动续期')"
        else
            success "$(L '证书有效，剩余约') ${days} $(L '天')"
        fi
    else
        warn "$(L '无法读取证书有效期（文件缺失或损坏），建议重新签发')"
    fi
    echo ""
    info "$(L '自动续期链路检查：')"
    case "$CERT_METHOD" in
        letsencrypt-http|cloudflare-dns)
            if systemctl is-active --quiet certbot.timer 2>/dev/null; then
                success "$(L 'certbot.timer 运行中')"
            elif crontab -l 2>/dev/null | awk '/certbot renew/{f=1} END{exit !f}'; then
                success "$(L 'cron 兜底续期任务存在')"
            else
                warn "$(L '未发现有效的自动续期任务！')"
            fi
            [ -x /etc/letsencrypt/renewal-hooks/deploy/restart-nowhere.sh ] \
                && success "$(L '续期 deploy hook 存在（续期后自动重启 nowhere）')" \
                || warn "$(L '续期 deploy hook 缺失（续期后不会自动重启 nowhere）')"
            ;;
        letsencrypt-dns)
            if crontab -l 2>/dev/null | awk '/acme\.sh.*--cron/{f=1} END{exit !f}'; then
                success "$(L 'acme.sh cron 续期任务存在')"
            else
                warn "$(L '未发现 acme.sh 自动续期任务！')"
            fi
            ;;
    esac
    echo ""
    read -rp "$(L '是否立即手动触发一次续期检查？（仅当证书满足续期条件时才会真的续签）')[y/N]: " DO_RENEW || { [ -n "$DO_RENEW" ] || return 1; }
    if [[ "$DO_RENEW" =~ ^[Yy]$ ]]; then
        case "$CERT_METHOD" in
            letsencrypt-http|cloudflare-dns)
                if certbot renew; then
                    nowhere_sync_cert_copy || true
                    systemctl restart nowhere 2>/dev/null || true
                    success "$(L '续期检查完成')"
                else
                    warn "$(L '续期失败，请看上方报错')"
                fi
                ;;
            letsencrypt-dns)
                "${ACME_HOME}/acme.sh" --renew -d "${DOMAIN}" && success "$(L '续期检查完成（acme.sh 的 --reloadcmd 会自动重启 nowhere）')" \
                    || warn "$(L '续期失败，请看上方报错')"
                ;;
        esac
    fi
}

