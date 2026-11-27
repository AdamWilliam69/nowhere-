# ══════════════════════════════════════════════════════════════
#   Snell Server（Surge 官方）—— v6 一键安装 + 跟随官方发布自动更新
#   版本来源：Surge 知识库的 Snell 发布页（官方没有版本查询 API，只能解析该页的下载链接），
#   并对 dl.nssurge.com 做"下一个版本号"探测作为补充；二进制只从 dl.nssurge.com 下载。
#   官方未提供校验值，这里做的是：HTTPS + zip 完整性 + ELF 检查 + 试运行 + 启动失败自动回滚。
#   路径与社区常见脚本一致（/etc/snell/snell-server.conf、snell.service），已有安装可直接接管。
# ══════════════════════════════════════════════════════════════

snell_arch() {
    case "$(uname -m)" in
        x86_64|amd64)  printf 'amd64' ;;
        aarch64|arm64) printf 'aarch64' ;;
        i386|i686)     printf 'i386' ;;
        armv7l)        printf 'armv7l' ;;
        *) warn "$(L 'Snell 官方未提供该架构的二进制:') $(uname -m)"; return 1 ;;
    esac
}

# v6.0.0 / v6.0.0rc2 / v6.0.0b3 -> 定宽可比较的键；同一 X.Y.Z 下 正式版 > rc > b
snell_ver_key() {
    local v="${1#v}" stage=2 stagenum=0
    local re='^([0-9]+)\.([0-9]+)\.([0-9]+)(([a-z]+)([0-9]*))?$'
    [[ "$v" =~ $re ]] || return 1
    if [ -n "${BASH_REMATCH[5]}" ]; then
        case "${BASH_REMATCH[5]}" in rc) stage=1 ;; *) stage=0 ;; esac
        stagenum="${BASH_REMATCH[6]:-0}"
    fi
    printf '%05d%05d%05d%d%05d' "$((10#${BASH_REMATCH[1]}))" "$((10#${BASH_REMATCH[2]}))" \
        "$((10#${BASH_REMATCH[3]}))" "$stage" "$((10#${stagenum}))"
}

snell_ver_gt() {
    local a b
    a="$(snell_ver_key "$1")" || return 1
    b="$(snell_ver_key "$2")" || return 1
    [[ "$a" > "$b" ]]
}

snell_is_prerelease() { local v="${1#v}"; [[ "$v" =~ [a-z] ]]; }

snell_ver_major() { local v="${1#v}"; printf '%s' "${v%%.*}"; }

snell_conf_get() {   # snell_conf_get KEY [配置文件，默认主配置]
    local file="${2:-$SNELL_CONF}"
    [ -f "$file" ] || return 1
    awk -v k="$1" '
        /^[ \t]*[#;\[]/ { next }
        {
            i = index($0, "="); if (i == 0) next
            kk = substr($0, 1, i - 1); gsub(/[ \t]/, "", kk)
            if (kk == k) { v = substr($0, i + 1); gsub(/^[ \t]+|[ \t\r]+$/, "", v); print v; found = 1; exit }
        }
        END { exit !found }' "$file"
}

# 监听端口：取 listen 的第一个端点
snell_port() {
    local l=""
    l="$(snell_conf_get listen 2>/dev/null || true)"
    l="${l%%,*}"; l="${l##*:}"; l="${l//[[:space:]]/}"
    if [[ "$l" =~ ^[0-9]+$ ]] && [ "$l" -ge 1 ] && [ "$l" -le 65535 ]; then printf '%s' "$l"; fi
    return 0
}

snell_installed_version() {
    local v=""
    # 二进制不在就不算已安装（卸载时保留配置目录的情况下，旧的版本记录不应被当成当前版本）
    if [ ! -x "$SNELL_BIN" ]; then return 0; fi
    if [ -f "$SNELL_VERSION_FILE" ]; then v="$(tr -d ' \r\n' < "$SNELL_VERSION_FILE" 2>/dev/null || true)"; fi
    if [ -z "$v" ] && [ -x "$SNELL_BIN" ]; then
        v="$(timeout 5 "$SNELL_BIN" -v 2>&1 < /dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+[a-z0-9]*' | head -n 1 || true)"
        if [ -n "$v" ] && [ -d "$SNELL_DIR" ]; then echo "$v" > "$SNELL_VERSION_FILE" 2>/dev/null || true; fi
    fi
    printf '%s' "$v"
}

snell_require() {
    if [ ! -x "$SNELL_BIN" ] || [ ! -f "$SNELL_CONF" ]; then
        warn "$(L 'Snell 尚未安装，请先执行「1')) $(L '安装 Snell」（或 adam snell install）')"
        return 1
    fi
    return 0
}

snell_load_state() {
    state_load "$SNELL_STATE_FILE" "SNELL_CHANNEL=beta SNELL_AUTO_UPDATE=0 SNELL_PUBLIC_HOST= SNELL_NODE_NAME=" SNELL_CHANNEL "stable beta"
    return 0
}

snell_save_state() {
    state_save "$SNELL_STATE_FILE" "$SNELL_DIR" 750 SNELL_CHANNEL SNELL_AUTO_UPDATE SNELL_PUBLIC_HOST SNELL_NODE_NAME
}

# 官方发布页上列出的、对应本机架构的全部版本号（每行一个）
snell_remote_versions() {
    local arch="$1" url body found=""
    for url in "${SNELL_KB_URLS[@]}"; do
        body="$(secure_curl -fsSL --max-time 20 -A 'Mozilla/5.0 (adam-manager)' "$url" 2>/dev/null || true)"
        [ -n "$body" ] || continue
        found="$(printf '%s' "$body" \
            | grep -oE "snell-server-v[0-9]+\.[0-9]+\.[0-9]+[a-z0-9]*-linux-${arch}\.zip" \
            | sed -E 's/^snell-server-(v[^-]+)-linux-.*$/\1/' | sort -u || true)"
        if [ -n "$found" ]; then
            printf '%s\n' "$found"
            return 0
        fi
    done
    return 1
}

# 官方没有版本清单接口（下载目录不可列），发布页也可能取不到或滞后。
# 这里按官方的版本演进顺序（X.Y.Zb1..bN → X.Y.Zrc（裸 rc 即 rc1）→ rc2.. → X.Y.Z 正式版 → 补丁 / 下一个次版本）
# 从给定版本往后生成候选版本号，逐个到下载站探测是否存在。思路来自 Eric86777/vps-tcp-tune。
snell_probe_candidates() {
    local cur="${1#v}" maj min pat n i
    local re_b='^([0-9]+)\.([0-9]+)\.([0-9]+)b([0-9]+)$' re_rc='^([0-9]+)\.([0-9]+)\.([0-9]+)rc([0-9]*)$' re_s='^([0-9]+)\.([0-9]+)\.([0-9]+)$'
    if [[ "$cur" =~ $re_b ]]; then
        maj=$((10#${BASH_REMATCH[1]})); min=$((10#${BASH_REMATCH[2]})); pat=$((10#${BASH_REMATCH[3]})); n=$((10#${BASH_REMATCH[4]}))
        for i in 1 2 3 4 5 6 7 8; do echo "v${maj}.${min}.${pat}b$((n + i))"; done
        echo "v${maj}.${min}.${pat}rc"
        for i in 2 3 4 5; do echo "v${maj}.${min}.${pat}rc${i}"; done
        for i in 0 1 2 3; do echo "v${maj}.${min}.$((pat + i))"; done
    elif [[ "$cur" =~ $re_rc ]]; then
        maj=$((10#${BASH_REMATCH[1]})); min=$((10#${BASH_REMATCH[2]})); pat=$((10#${BASH_REMATCH[3]}))
        n="${BASH_REMATCH[4]}"; n=$((10#${n:-1}))
        for i in 1 2 3 4; do echo "v${maj}.${min}.${pat}rc$((n + i))"; done
        for i in 0 1 2 3; do echo "v${maj}.${min}.$((pat + i))"; done
    elif [[ "$cur" =~ $re_s ]]; then
        maj=$((10#${BASH_REMATCH[1]})); min=$((10#${BASH_REMATCH[2]})); pat=$((10#${BASH_REMATCH[3]}))
        # 正式版之后：下一个补丁的测试版与正式版
        echo "v${maj}.${min}.$((pat + 1))b1"; echo "v${maj}.${min}.$((pat + 1))rc"
        for i in 1 2 3 4; do echo "v${maj}.${min}.$((pat + i))"; done
    else
        return 0
    fi
    # 下一个次版本、下一个大版本的起点（大版本只用于提示，不会自动跨过去）
    echo "v${maj}.$((min + 1)).0b1"; echo "v${maj}.$((min + 1)).0rc"; echo "v${maj}.$((min + 1)).0"
    echo "v$((maj + 1)).0.0b1"; echo "v$((maj + 1)).0.0rc"; echo "v$((maj + 1)).0.0"
    return 0
}

snell_dl_exists() {   # snell_dl_exists ARCH VERSION
    secure_curl -fsI --max-time 8 "${SNELL_DL_BASE}/snell-server-${2}-linux-${1}.zip" >/dev/null 2>&1
}

# 并行探测一批候选，输出其中存在的版本
snell_probe_batch() {
    local arch="$1" tmp c
    shift
    tmp="$(mktemp /tmp/adam-snell-probe.XXXXXX 2>/dev/null)" || return 1
    : > "$tmp"
    for c in "$@"; do
        ( if snell_dl_exists "$arch" "$c"; then echo "$c" >> "$tmp"; fi ) &
    done
    wait
    cat "$tmp" 2>/dev/null || true
    rm -f "$tmp"
    return 0
}

# 从 cur 出发往后探测，找到更新的就以它为新起点再探，最多 4 轮（能跨过多次发布）
snell_probe_next() {
    local arch="$1" base="$2" found v best
    local -a cands=()
    for _ in 1 2 3 4; do
        cands=()
        while IFS= read -r v; do [ -n "$v" ] && cands+=("$v"); done < <(snell_probe_candidates "$base")
        [ "${#cands[@]}" -gt 0 ] || break
        found="$(snell_probe_batch "$arch" "${cands[@]}")"
        [ -n "$found" ] || break
        printf '%s\n' "$found"
        best="$base"
        while IFS= read -r v; do
            [ -n "$v" ] || continue
            # 只沿着同一大版本继续追
            if [ "$(snell_ver_major "$v")" = "$(snell_ver_major "$base")" ] && snell_ver_gt "$v" "$best"; then best="$v"; fi
        done < <(printf '%s\n' "$found" | tr ' ' '\n' | grep -v '^$')
        [ "$best" != "$base" ] || break
        base="$best"
    done
    return 0
}

# snell_query_latest ARCH CHANNEL CURRENT
# 结果写入：SNELL_LATEST（按通道与大版本策略可升级到的最高版本）、SNELL_LATEST_PRE（该大版本
# 最新的测试版）、SNELL_NEWER_MAJOR（更高大版本，仅提示）、SNELL_SOURCE_OK（是否取到任何版本信息）
snell_query_latest() {
    local arch="$1" channel="$2" current="$3" all="" v major
    SNELL_LATEST=""; SNELL_LATEST_PRE=""; SNELL_NEWER_MAJOR=""; SNELL_SOURCE_OK=0
    local probe_base="$current"
    all="$(snell_remote_versions "$arch" || true)"
    if [ -z "$probe_base" ] || ! snell_ver_key "$probe_base" >/dev/null 2>&1 \
        || [ "$(snell_ver_major "$probe_base")" != "$SNELL_MAJOR" ]; then
        # 没装过（或装的不是 v6）：从脚本内置的已知版本起步，它本身也作为候选
        probe_base="$SNELL_BASELINE_VERSION"
        if snell_dl_exists "$arch" "$probe_base"; then all="${all}"$'\n'"${probe_base}"; fi
    fi
    all="${all}"$'\n'"$(snell_probe_next "$arch" "$probe_base" || true)"
    while IFS= read -r v; do
        [ -n "$v" ] || continue
        snell_ver_key "$v" >/dev/null 2>&1 || continue
        SNELL_SOURCE_OK=1
        major="$(snell_ver_major "$v")"
        if [ "$major" -gt "$SNELL_MAJOR" ]; then
            if [ -z "$SNELL_NEWER_MAJOR" ] || snell_ver_gt "$v" "$SNELL_NEWER_MAJOR"; then SNELL_NEWER_MAJOR="$v"; fi
            continue
        fi
        [ "$major" -eq "$SNELL_MAJOR" ] || continue
        if snell_is_prerelease "$v"; then
            if [ -z "$SNELL_LATEST_PRE" ] || snell_ver_gt "$v" "$SNELL_LATEST_PRE"; then SNELL_LATEST_PRE="$v"; fi
            [ "$channel" = "beta" ] || continue
        fi
        if [ -z "$SNELL_LATEST" ] || snell_ver_gt "$v" "$SNELL_LATEST"; then SNELL_LATEST="$v"; fi
    done < <(printf '%s\n' "$all" | tr ' ' '\n' | grep -v '^$')
    # 已安装的版本比能查到的都新（发布页滞后、探测窗口里也没有更新的）时，它自己就是"最新"，
    # 避免把更旧的版本报成"官方最新"
    if [ "$SNELL_SOURCE_OK" = "1" ] && [ -n "$current" ] && snell_ver_key "$current" >/dev/null 2>&1 \
        && [ "$(snell_ver_major "$current")" = "$SNELL_MAJOR" ]; then
        if [ -z "$SNELL_LATEST" ] || snell_ver_gt "$current" "$SNELL_LATEST"; then SNELL_LATEST="$current"; fi
    fi
    return 0
}

# 下载并检查指定版本；成功后二进制路径写入 SNELL_DL_BIN
# v8.6：统一 secure_curl + verify_elf_binary（校验 ELF 魔数与本机架构匹配）
snell_fetch() {
    local ver="$1" arch="$2" url out
    SNELL_DL_BIN=""
    make_workdir || return 1
    local wd="$WORKDIR"
    url="${SNELL_DL_BASE}/snell-server-${ver}-linux-${arch}.zip"
    if ! secure_curl -fL --retry 3 --connect-timeout 10 --max-time 300 -o "$wd/snell.zip" "$url"; then
        warn "$(L '下载失败:') ${url}"
        return 1
    fi
    if ! unzip -tq "$wd/snell.zip" >/dev/null 2>&1; then
        warn "$(L '下载到的压缩包不完整或已损坏')"
        return 1
    fi
    unzip -oq "$wd/snell.zip" snell-server -d "$wd" || { warn "$(L '压缩包里没有 snell-server')"; return 1; }
    if ! verify_elf_binary "$wd/snell-server"; then
        warn "$(L '解压出的 snell-server 不是本机架构的 ELF 可执行文件，已中止')"
        return 1
    fi
    chmod 755 "$wd/snell-server"
    if ! upgrade_binary_precheck "$wd/snell-server" -v; then
        out="$(cd "$wd" && timeout 10 ./snell-server -v 2>&1 < /dev/null || true)"
        warn "$(L '新二进制无法在本机运行（缺少依赖库或架构不符）:') ${out}"
        return 1
    fi
    SNELL_DL_BIN="$wd/snell-server"
    info "SHA256: $(sha256sum "$SNELL_DL_BIN" | awk '{print $1}')$(L '（官方未公布校验值，仅供留档比对）')"
    return 0
}

snell_apply_binary() {
    local ver="$1"
    if [ -f "$SNELL_BIN" ]; then cp -f "$SNELL_BIN" "$SNELL_BIN_BACKUP"; fi
    install -m 755 "$SNELL_DL_BIN" "$SNELL_BIN"
    install -d -m 750 "$SNELL_DIR"
    echo "$ver" > "$SNELL_VERSION_FILE"
    chmod 644 "$SNELL_VERSION_FILE"
    snell_fix_perms
}

# v8.6（BUG-11）：无论 snell 组是否存在都强制收敛权限（防止 PSK 明文泄漏），chown 用 -h 不跟随符号链接
snell_fix_perms() {
    local f grp="root"
    getent group snell >/dev/null 2>&1 && grp="snell"
    if [ -d "$SNELL_DIR" ] && [ ! -L "$SNELL_DIR" ]; then
        chown -h "root:${grp}" "$SNELL_DIR" 2>/dev/null || true
        chmod 750 "$SNELL_DIR" 2>/dev/null || true
    fi
    if [ -d "$SNELL_PORTS_DIR" ] && [ ! -L "$SNELL_PORTS_DIR" ]; then
        chown -h "root:${grp}" "$SNELL_PORTS_DIR" 2>/dev/null || true
        chmod 750 "$SNELL_PORTS_DIR" 2>/dev/null || true
    fi
    for f in "$SNELL_CONF" "$SNELL_PORTS_DIR"/*.conf; do
        [ -f "$f" ] && [ ! -L "$f" ] || continue
        chown -h "root:${grp}" "$f" 2>/dev/null || true
        chmod 640 "$f" 2>/dev/null || true
    done
    if [ -f "$SNELL_STATE_FILE" ] && [ ! -L "$SNELL_STATE_FILE" ]; then
        chown -h root:root "$SNELL_STATE_FILE" 2>/dev/null || true
        chmod 600 "$SNELL_STATE_FILE" 2>/dev/null || true
    fi
    if [ -f "$SNELL_VERSION_FILE" ] && [ ! -L "$SNELL_VERSION_FILE" ]; then
        chown -h root:root "$SNELL_VERSION_FILE" 2>/dev/null || true
        chmod 644 "$SNELL_VERSION_FILE" 2>/dev/null || true
    fi
    if [ -f "$SNELL_BIN" ] && [ ! -L "$SNELL_BIN" ]; then
        chown -h root:root "$SNELL_BIN" 2>/dev/null || true
        chmod 755 "$SNELL_BIN" 2>/dev/null || true
    fi
    return 0
}

# ── 多端口：主配置（snell.service）之外，每个附加端口是一份独立配置 + 一个 snell-port@端口 实例 ──

# 附加端口列表（每行一个，升序）
snell_extra_ports() {
    local f p
    [ -d "$SNELL_PORTS_DIR" ] || return 0
    for f in "$SNELL_PORTS_DIR"/*.conf; do
        [ -f "$f" ] || continue
        p="$(basename "$f" .conf)"
        if [[ "$p" =~ ^[0-9]+$ ]]; then echo "$p"; fi
    done | sort -n
    return 0
}

# 全部端口：主端口在前
snell_all_ports() {
    local p
    p="$(snell_port)"
    if [ -n "$p" ]; then echo "$p"; fi
    snell_extra_ports
    return 0
}

snell_port_conf() {   # 端口对应的配置文件路径
    if [ "$1" = "$(snell_port)" ]; then printf '%s' "$SNELL_CONF"; else printf '%s' "${SNELL_PORTS_DIR}/$1.conf"; fi
}

# 端口是否已是本机某份 Snell 配置（服务没运行时 ss 查不到，所以单独判断）
snell_port_taken() {
    local want="$1" p
    while IFS= read -r p; do
        if [ "$p" = "$want" ]; then return 0; fi
    done < <(snell_all_ports)
    return 1
}

snell_write_port_unit() {
    write_service_unit "$SNELL_PORT_UNIT" "Snell Proxy Service (extra port %i)" "https://kb.nssurge.com/surge-knowledge-base/release-notes/snell" "0" "snell" "snell" "${SNELL_BIN} -l info -c ${SNELL_PORTS_DIR}/%i.conf" "CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW" "65536" "always" "3" "ProtectSystem=full
ProtectHome=true
PrivateTmp=true
SyslogIdentifier=snell-server-%i"
}

snell_main_healthy() {
    local port
    systemctl is-active --quiet snell 2>/dev/null || return 1
    port="$(snell_port)"
    [ -n "$port" ] || return 1
    tcp_listening "$port"
}

snell_extra_healthy() {   # snell_extra_healthy 端口
    systemctl is-active --quiet "snell-port@$1" 2>/dev/null || return 1
    tcp_listening "$1"
}

# 主端口与全部附加端口都正常
snell_healthy() {
    local p
    snell_main_healthy || return 1
    while IFS= read -r p; do
        snell_extra_healthy "$p" || return 1
    done < <(snell_extra_ports)
    return 0
}

# 重启主服务与全部附加端口实例（换二进制、回滚、手动重启时用）
snell_restart_all() {
    local p
    systemctl restart snell 2>/dev/null || true
    while IFS= read -r p; do
        systemctl restart "snell-port@${p}" 2>/dev/null || true
    done < <(snell_extra_ports)
    return 0
}

# 配置目录里已有附加端口配置（如卸载时保留了配置后重装）时，把它们的实例重新拉起来
# 恢复后同步 Snell 附加端口实例：停掉配置已不存在的实例，再拉起配置里有的实例（M7）
snell_sync_extras_after_restore() {
    local inst p
    while IFS= read -r inst; do
        [[ "$inst" == snell-port@*.service ]] || continue
        p="${inst#snell-port@}"; p="${p%.service}"
        if [ ! -f "${SNELL_PORTS_DIR}/${p}.conf" ]; then
            systemctl disable --now "$inst" >/dev/null 2>&1 || true
            info "$(L '已停用多余的 Snell 附加端口实例：')${p}"
        fi
    done < <(systemctl list-units --all --plain 'snell-port@*.service' --no-legend 2>/dev/null | awk '{print $1}')
    snell_start_extras
}

snell_start_extras() {
    local p
    [ -n "$(snell_extra_ports)" ] || return 0
    snell_write_port_unit
    systemctl daemon-reload
    while IFS= read -r p; do
        systemctl enable "snell-port@${p}" >/dev/null 2>&1 || true
        systemctl restart "snell-port@${p}" 2>/dev/null || true
        if ufw_installed; then ufw allow "${p}/tcp" >/dev/null 2>&1 || true; fi
        info "$(L '已恢复附加端口') ${p}"
    done < <(snell_extra_ports)
    return 0
}

snell_rollback_binary() {
    local prev="${1:-}"
    if [ ! -f "$SNELL_BIN_BACKUP" ]; then
        warn "$(L '没有可回滚的备份二进制')"
        return 1
    fi
    warn "$(L '正在回滚到旧版本')${prev:+(${prev})} ..."
    install -m 755 "$SNELL_BIN_BACKUP" "$SNELL_BIN"
    if [ -n "$prev" ]; then echo "$prev" > "$SNELL_VERSION_FILE"; fi
    snell_restart_all
    sleep 2
    if snell_healthy; then
        success "$(L '已回滚，服务恢复运行')"
        notify_send "Snell Auto-Rollback" "Upgrade failed; automatically rolled back to ${prev:-previous} and service recovered." || true
    else
        warn "$(L '回滚后服务仍未启动，请查看: journalctl -u snell -n 50 --no-pager')"
        notify_send "Snell Rollback Alert" "Upgrade failed and snell is STILL DOWN after rollback. Check journalctl -u snell." || true
    fi
    return 0
}

# 升级到指定版本（不提问，供手动更新与定时自动更新共用）；启动失败自动回滚
snell_upgrade_to() {
    local ver="$1" arch prev
    arch="$(snell_arch)" || return 1
    prev="$(snell_installed_version)"
    snell_fetch "$ver" "$arch" || return 1
    snell_apply_binary "$ver"
    if [ ! -f "$SNELL_SERVICE" ]; then
        success "$(L 'Snell 二进制已更新到') ${ver}$(L '（未检测到 snell.service，未启动服务）')"
        return 0
    fi
    if upgrade_binary_finish snell snell_restart_all snell_healthy snell_rollback_binary "$prev" 2 15; then
        success "$(L 'Snell 已更新:') ${prev:-$(L '未知')} → ${ver}"
        return 0
    fi
    return 1
}

snell_ensure_user() {
    ensure_system_user snell || { warn "$(L '创建 snell 系统用户失败')"; return 1; }
    return 0
}

snell_ipv6_ok() {
    [ -r /proc/sys/net/ipv6/conf/all/disable_ipv6 ] || return 1
    [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo 1)" = "0" ]
}

# snell_write_conf PORT PSK MODE DNS_PREF [目标文件，默认主配置]
snell_write_conf() {
    local port="$1" psk="$2" mode="$3" pref="$4" dest="${5:-$SNELL_CONF}" listen tmp
    if snell_ipv6_ok; then
        listen="0.0.0.0:${port},[::]:${port}"
    else
        listen="0.0.0.0:${port}"
    fi
    install -d -m 750 "$SNELL_DIR"
    tmp="$(mktemp "${SNELL_DIR}/.conf.XXXXXX")"
    cat > "$tmp" << SNCONFEOF || { rm -f "$tmp"; return 1; }
[snell-server]
mode = ${mode}
listen = ${listen}
psk = ${psk}
dns-ip-preference = ${pref}
SNCONFEOF
    chmod 640 "$tmp"
    install -d -m 750 "$(dirname "$dest")"
    mv -f "$tmp" "$dest" || { rm -f "$tmp"; return 1; }
    snell_fix_perms
}

snell_write_service() {
    write_service_unit "$SNELL_SERVICE" "Snell Proxy Service" "https://kb.nssurge.com/surge-knowledge-base/release-notes/snell" "0" "snell" "snell" "${SNELL_BIN} -l info -c ${SNELL_CONF}" "CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW" "65536" "always" "3" "ProtectSystem=full
ProtectHome=true
PrivateTmp=true
SyslogIdentifier=snell-server"
}

# v8.6：Snell v6 流量特征由 PSK 派生，升级为 CSPRNG 变长 32–48 位（A-Za-z0-9_-，首尾固定字母数字，避免 - 开头被参数解析误认）
snell_gen_psk() {
    local len first mid last
    len="$(csprng_int 32 48 2>/dev/null || echo 36)"
    first="$(csprng_alnum 1 'A-Za-z0-9' 2>/dev/null || true)"
    mid="$(csprng_alnum $((len - 2)) 'A-Za-z0-9_-' 2>/dev/null || true)"
    last="$(csprng_alnum 1 'A-Za-z0-9' 2>/dev/null || true)"
    printf '%s%s%s' "$first" "$mid" "$last"
}

# 端口是否被 snell-server 以外的进程占用
snell_port_conflict() {
    local p="$1"
    tcp_port_conflict "$p" "snell-server"
}

# 询问一个可用的新端口（不能被其他进程占用，也不能是本机已有的 Snell 端口），结果写入 SNELL_ASK_PORT
snell_ask_new_port() {
    local def
    def="$(random_free_port)"
    ask_free_port "$def" snell_port_taken snell_port_conflict SNELL_ASK_PORT
}

# v8.6（BUG-04）：用 CSPRNG 替代 $RANDOM（避免子 shell 复用同一 PRNG 种子），
# 同时避开当前监听的 TCP/UDP 端口、SSH 端口以及全部已托管服务端口（含未运行状态）
random_free_port() {
    local p=0 i ssh_ports=""
    ssh_ports=" $(detect_ssh_ports 2>/dev/null || true) "
    for ((i = 0; i < 50; i++)); do
        p="$(csprng_int 20000 55000 2>/dev/null || echo 0)"
        [[ "$p" =~ ^[0-9]+$ ]] && [ "$p" -ge 20000 ] && [ "$p" -le 55000 ] || continue
        case "$ssh_ports" in *" ${p} "*) continue ;; esac
        if tcp_listening "$p" || udp_listening "$p"; then continue; fi
        if port_used_by_other_services "${p}/tcp" "" || port_used_by_other_services "${p}/udp" ""; then continue; fi
        printf '%s' "$p"
        return 0
    done
    p="$(csprng_int 20000 55000 2>/dev/null || echo 38888)"
    printf '%s' "$p"
}

snell_client_line() {   # snell_client_line [端口，默认主端口]
    local host port psk mode major name conf
    port="${1:-$(snell_port)}"
    conf="$(snell_port_conf "$port")"
    psk="$(snell_conf_get psk "$conf" 2>/dev/null || true)"
    mode="$(snell_conf_get mode "$conf" 2>/dev/null || true)"
    mode="${mode:-default}"
    snell_load_state
    host="${SNELL_PUBLIC_HOST:-$(detect_public_host)}"
    if [ -z "$host" ]; then
        warn "$(L '未能确定公网地址，无法生成 Snell 分享行')"
        return 1
    fi
    name="${SNELL_NODE_NAME:-Snell-v${SNELL_MAJOR}}"
    if [ "$port" != "$(snell_port)" ]; then name="${name}-${port}"; fi
    major="$(snell_ver_major "$(snell_installed_version)")"
    [[ "$major" =~ ^[0-9]+$ ]] || major="$SNELL_MAJOR"
    printf '%s = snell, %s, %s, psk=%s, version=%s, mode=%s, reuse=true' "$name" "$host" "$port" "$psk" "$major" "$mode"
}

# 列出全部端口配置（带序号）。序号 1 始终是主端口
snell_list_ports() {
    local p n=0 conf st kind
    while IFS= read -r p; do
        n=$((n + 1))
        conf="$(snell_port_conf "$p")"
        if tcp_listening "$p"; then st="${GREEN}$(L '监听中')${NC}"; else st="${RED}$(L '未监听')${NC}"; fi
        if [ "$n" -eq 1 ]; then kind="$(L '主端口')  "; else kind="$(L '附加端口')"; fi
        echo -e "  ${BOLD}${n})${NC} ${kind} ${p}    mode $(snell_conf_get mode "$conf" 2>/dev/null || echo default)    ${st}"
    done < <(snell_all_ports)
    return 0
}

# 新增一份端口配置：独立的端口 + PSK + mode，由 snell-port@端口 实例承载
snell_add_port() {
    snell_require || return 1
    local port psk mode="default" pref ans conf
    local pskre='^[A-Za-z0-9_-]{12,255}$'
    step "$(L '新增 Snell 端口配置')"
    divider
    echo "  $(L '现有端口配置：')"
    snell_list_ports
    echo ""
    info "$(L '新端口使用独立的 PSK 与 mode，和现有端口互不影响（可以给不同设备 / 不同用途各用一份）')"
    snell_ask_new_port || return 1
    port="$SNELL_ASK_PORT"
    while true; do
        read -rp "$(L 'PSK（回车自动生成 32-48 位随机串；自定义需 12-255 位，仅限字母、数字、- 和 _）:') " psk || { [ -n "$psk" ] || return 1; }
        if [ -z "$psk" ]; then
            psk="$(snell_gen_psk)"
            if [ "${#psk}" -lt 32 ] || [ "${#psk}" -gt 48 ] || [[ ! "$psk" =~ $pskre ]]; then warn "$(L '随机 PSK 生成失败')"; return 1; fi
            break
        fi
        if [[ "$psk" =~ $pskre ]]; then break; fi
        warn "$(L 'PSK 不符合要求')"
    done
    echo "  $(L 'mode：1')) $(L 'default（默认）  2')) unshaped  3) $(L 'unsafe-raw（明文，仅可信内网）')"
    read -rp "  $(L '选择') [$(L '1/2/3，默认1')]: " ans || { [ -n "$ans" ] || return 1; }
    case "${ans:-1}" in
        2) mode="unshaped" ;;
        3) if confirm "$(L 'unsafe-raw 为明文传输，确认？')" n; then mode="unsafe-raw"; fi ;;
        *) : ;;
    esac
    pref="$(snell_conf_get dns-ip-preference 2>/dev/null || true)"
    conf="${SNELL_PORTS_DIR}/${port}.conf"
    snell_ensure_user || return 1
    snell_write_conf "$port" "$psk" "$mode" "${pref:-default}" "$conf"
    snell_write_port_unit
    systemctl daemon-reload
    systemctl enable "snell-port@${port}" >/dev/null 2>&1 || true
    systemctl restart "snell-port@${port}" 2>/dev/null || true
    sleep 2
    if ! snell_extra_healthy "$port"; then
        warn "$(L '新端口未能启动，已撤回。日志：')"
        journalctl -u "snell-port@${port}" -n 15 --no-pager 2>/dev/null || true
        systemctl disable --now "snell-port@${port}" >/dev/null 2>&1 || true
        rm -f "$conf"
        return 1
    fi
    success "$(L '端口') ${port} $(L '已添加并监听')"
    fw_allow_for_service "${port}/tcp"
    reserved_ports_sync || true
    echo ""
    echo -e "${BOLD}$(L 'Surge 节点配置：')${NC}"
    SNELL_LINE="$(snell_client_line "$port")" && echo -e "${GREEN}${SNELL_LINE}${NC}"
    return 0
}

# 删除某一份端口配置。可删任意一份：
#   删附加端口 = 停掉它的实例并删除配置；
#   删主端口   = 由序号最小的附加端口接替为主配置（它的端口与 PSK 不变，用它的客户端不受影响）；
#   只剩一份时删除等同于卸载，转去走卸载流程。
snell_delete_port() {
    snell_require || return 1
    local target="${1:-}" main p ans promote bak
    local -a all=()
    step "$(L '删除 Snell 端口配置')"
    divider
    main="$(snell_port)"
    while IFS= read -r p; do all+=("$p"); done < <(snell_all_ports)
    if [ "${#all[@]}" -eq 0 ]; then warn "$(L '没有找到任何端口配置')"; return 1; fi
    if [ -z "$target" ]; then
        snell_list_ports
        read -rp "$(L '输入要删除的序号（回车取消）:') " ans || { [ -n "$ans" ] || return 1; }
        if [ -z "$ans" ]; then info "$(L '已取消')"; return 0; fi
        if [[ ! "$ans" =~ ^[0-9]+$ ]] || [ "${#ans}" -gt 5 ]; then warn "$(L '序号无效')"; return 1; fi
        ans=$((10#$ans))
        if [ "$ans" -lt 1 ] || [ "$ans" -gt "${#all[@]}" ]; then warn "$(L '序号无效')"; return 1; fi
        target="${all[$((ans - 1))]}"
    elif ! snell_port_taken "$target"; then
        warn "$(L '端口') ${target} $(L '不是本机的 Snell 端口配置（现有:') ${all[*]}$(L '）')"
        return 1
    fi

    if [ "${#all[@]}" -eq 1 ]; then
        warn "$(L '端口') ${target} $(L '是唯一的一份配置，删除它等于卸载 Snell')"
        snell_uninstall
        return $?
    fi

    if [ "$target" != "$main" ]; then
        confirm "$(L '确认删除附加端口') ${target} $(L '的配置？（使用该端口的客户端将无法连接）')" n || { info "$(L '已取消')"; return 0; }
        systemctl disable --now "snell-port@${target}" >/dev/null 2>&1 || true
        rm -f "${SNELL_PORTS_DIR}/${target}.conf"
    else
        promote="${all[1]}"
        info "$(L '端口') ${target} $(L '是主端口配置：删除后由附加端口') ${promote} $(L '接替为主配置（')${promote} $(L '的端口与 PSK 不变）')"
        confirm "$(L '确认删除主端口') ${target} $(L '的配置？（使用该端口的客户端将无法连接）')" n || { info "$(L '已取消')"; return 0; }
        bak="${SNELL_CONF}.bak"
        cp -f "$SNELL_CONF" "$bak"
        systemctl disable --now "snell-port@${promote}" >/dev/null 2>&1 || true
        cp -f "${SNELL_PORTS_DIR}/${promote}.conf" "$SNELL_CONF"
        snell_fix_perms
        if ! svc_restart_wait snell 2 15 || ! snell_main_healthy; then
            warn "$(L '接替后主服务未能启动，已恢复原样。日志：')"
            mv -f "$bak" "$SNELL_CONF"
            snell_fix_perms
            systemctl restart snell 2>/dev/null || true
            systemctl enable "snell-port@${promote}" >/dev/null 2>&1 || true
            systemctl restart "snell-port@${promote}" 2>/dev/null || true
            return 1
        fi
        rm -f "$bak" "${SNELL_PORTS_DIR}/${promote}.conf"
    fi
    success "$(L '端口') ${target} $(L '的配置已删除')"
    fw_prune_old_specs "${target}/tcp"
    reserved_ports_sync || true
    echo ""
    echo "  $(L '剩余端口配置：')"
    snell_list_ports
    return 0
}

snell_show_config() {
    snell_require || return 1
    step "$(L 'Snell 配置')"
    divider
    snell_load_state
    echo -e "  $(L '版本     :') ${GREEN}$(snell_installed_version)${NC}"
    echo -e "  $(L '配置文件 :') ${GREEN}${SNELL_CONF}${NC}"
    echo -e "  $(L '监听     :') ${GREEN}$(snell_conf_get listen 2>/dev/null || echo '?')${NC}"
    echo -e "  PSK      : ${GREEN}$(snell_conf_get psk 2>/dev/null || echo '?')${NC}"
    echo -e "  mode     : ${GREEN}$(snell_conf_get mode 2>/dev/null || echo 'default')${NC}"
    echo -e "  $(L 'DNS 偏好 :') ${GREEN}$(snell_conf_get dns-ip-preference 2>/dev/null || echo 'default')${NC}"
    echo -e "  $(L '自动更新 :') ${GREEN}$([ "$SNELL_AUTO_UPDATE" = "1" ] && echo "开启（${SNELL_CHANNEL} 通道）" || echo "关闭")${NC}"
    echo ""
    echo -e "${BOLD}$(L 'Surge 节点配置（粘贴到') [Proxy] $(L '段）：')${NC}"
    SNELL_LINE="$(snell_client_line)" && echo -e "${GREEN}${SNELL_LINE}${NC}"
    local xp xconf
    while IFS= read -r xp; do
        xconf="${SNELL_PORTS_DIR}/${xp}.conf"
        echo ""
        echo -e "  ${BOLD}$(L '附加端口') ${xp}${NC}$(L '（')${xconf}$(L '）  mode') $(snell_conf_get mode "$xconf" 2>/dev/null || echo default)  PSK $(snell_conf_get psk "$xconf" 2>/dev/null || echo '?')"
        SNELL_LINE="$(snell_client_line "$xp")" && echo -e "${GREEN}${SNELL_LINE}${NC}"
    done < <(snell_extra_ports)
    echo ""
    echo "  $(L '说明：')"
    echo "  $(L '· mode 必须与服务端一致（官方要求），否则无法连通')"
    echo "  $(L '· v6 的协议特征由 PSK 派生：更换 PSK 等于更换一套流量特征，客户端需同步修改')"
    echo "  $(L '· v6 已移除 QUIC Proxy Mode，UDP 走 UDP over TCP，防火墙只需放行 TCP') $(snell_all_ports | paste -sd, -)$(L '；官方建议客户端屏蔽 QUIC 让应用回落到 HTTP/2')"
    echo "  $(L '· 需要支持 Snell v6 的 Surge 版本；官方未说明 v6 服务端兼容 v4/v5 客户端，第三方客户端是否支持请以其文档为准')"
    return 0
}

snell_enable_autoupdate() {
    snell_load_state
    SNELL_AUTO_UPDATE="1"
    snell_save_state
    maint_install_timers || return 1
    success "$(L '已开启 Snell 自动更新：每日维护任务（凌晨 4–6 点）检查官方发布，')${SNELL_CHANNEL} $(L '通道有 v')${SNELL_MAJOR} $(L '新版本即自动升级，启动失败自动回滚')"
    info "$(L '查看记录: adam maintain-log    或 journalctl -u adam-maintain --no-pager -n 30')"
    return 0
}

snell_disable_autoupdate() {
    snell_load_state
    SNELL_AUTO_UPDATE="0"
    if [ -d "$SNELL_DIR" ]; then snell_save_state; fi
    success "$(L '已关闭 Snell 自动更新（保活巡检不受影响）')"
    return 0
}

snell_toggle_autoupdate() {
    snell_require || return 1
    snell_load_state
    if [ "$SNELL_AUTO_UPDATE" = "1" ]; then
        info "$(L '自动更新当前为：开启（')${SNELL_CHANNEL} $(L '通道）')"
        echo "  1) $(L '关闭自动更新')"
        echo "  2) $(L '切换通道（当前') ${SNELL_CHANNEL}$(L '；beta=跟随最新测试版 b/rc 及正式版，stable=只跟正式版）')"
        echo "  0) $(L '返回')"
        local c
        read -rp "$(L '请选择:') " c || { [ -n "$c" ] || return 1; }
        case "$c" in
            1) snell_disable_autoupdate ;;
            2)
                if [ "$SNELL_CHANNEL" = "stable" ]; then SNELL_CHANNEL="beta"; else SNELL_CHANNEL="stable"; fi
                snell_save_state
                success "$(L '已切换到') ${SNELL_CHANNEL} $(L '通道')"
                ;;
            *) : ;;
        esac
    else
        info "$(L '自动更新当前为：关闭')"
        if confirm "$(L '开启自动更新？')" y; then snell_enable_autoupdate; fi
    fi
    return 0
}

# 定时器调用：全程不提问，输出进 journal
# autoupdate_check CUR LATEST MAJOR SRC_OK GT_FN：0=有新版可升，1=已最新/跳过，2=取不到版本（M10）
# MAJOR 为空表示不做大版本保护；Xray 传已装版本的主版本，同样不自动跨大版本
autoupdate_check() {
    local cur="$1" latest="$2" major="${3:-}" src_ok="${4:-0}" gt_fn="$5" lm=""
    if [ -z "$latest" ]; then
        if [ "$src_ok" = "1" ]; then
            echo "$(L '官方暂无可用版本，当前') ${cur:-$(L '未知')}"
            return 1
        fi
        echo "$(L '未能获取官方版本信息，本次跳过；当前') ${cur:-$(L '未知')}"
        return 2
    fi
    if [ -n "$major" ]; then
        lm="$(version_major "$latest")"
        if [ -n "$lm" ] && [ "$lm" != "$major" ]; then
            echo "$(L '最新版本属于另一个大版本（v')${lm}$(L '），不自动跨大版本，当前') ${cur:-$(L '未知')}"
            return 1
        fi
    fi
    if [ -n "$cur" ] && ! "$gt_fn" "$latest" "$cur"; then
        echo "$(L '已是最新:') ${cur}"
        return 1
    fi
    return 0
}

snell_autoupdate() {
    local arch current
    if [ ! -x "$SNELL_BIN" ]; then
        echo "$(L 'Snell 未安装，跳过')"
        return 0
    fi
    arch="$(snell_arch)" || return 1
    snell_load_state
    current="$(snell_installed_version)"
    if [ "$(snell_ver_major "$current")" != "$SNELL_MAJOR" ]; then
        echo "$(L '当前安装的是') ${current:-$(L '未知版本')}$(L '，不是 v')${SNELL_MAJOR} $(L '系列，自动更新不跨大版本，跳过')"
        return 0
    fi
    snell_query_latest "$arch" "$SNELL_CHANNEL" "$current"
    if [ -n "$SNELL_NEWER_MAJOR" ]; then
        echo "$(L '提示：官方已发布更高大版本') ${SNELL_NEWER_MAJOR}$(L '，需要客户端同步升级，不会自动跨大版本')"
    fi
    local _auc_rc=0
    autoupdate_check "$current" "$SNELL_LATEST" "$SNELL_MAJOR" "$SNELL_SOURCE_OK" snell_ver_gt || _auc_rc=$?
    case "$_auc_rc" in
        0) ;;
        1) return 0 ;;
        *) return 1 ;;
    esac
    echo "$(L '发现新版本:') ${current} → ${SNELL_LATEST}$(L '，开始更新')"
    if snell_upgrade_to "$SNELL_LATEST"; then
        maint_log "[Snell] $(L '已自动更新:') ${current} -> ${SNELL_LATEST}"
        return 0
    fi
    maint_log "[Snell] $(L '自动更新到') ${SNELL_LATEST} $(L '失败，当前仍为') $(snell_installed_version)"
    return 1
}

snell_update() {
    snell_require || return 1
    maint_lock_manual || return 1
    step "$(L '检查 Snell 更新')"
    divider
    local arch current
    arch="$(snell_arch)" || return 1
    snell_load_state
    current="$(snell_installed_version)"
    info "$(L '当前版本:') ${current:-$(L '未知')}$(L '（')${SNELL_CHANNEL} $(L '通道）')"
    info "$(L '正在查询 Surge 官方发布页 ...')"
    snell_query_latest "$arch" "$SNELL_CHANNEL" "$current"
    if [ -n "$SNELL_NEWER_MAJOR" ]; then
        warn "$(L '官方已发布更高大版本') ${SNELL_NEWER_MAJOR}$(L '：跨大版本需要客户端同步升级、配置格式也可能变化，本脚本不自动处理')"
    fi
    if [ -z "$SNELL_LATEST" ]; then
        if [ "$SNELL_SOURCE_OK" = "1" ] && [ -n "$SNELL_LATEST_PRE" ]; then
            info "$(L '正式版通道暂无 v')${SNELL_MAJOR} $(L '版本；测试版最新为') ${SNELL_LATEST_PRE}$(L '（可在「自动更新」里切到 beta 通道）')"
        else
            warn "$(L '未能获取官方版本信息（')${SNELL_KB_URLS[0]} $(L '不可达或页面结构变化）')"
        fi
        return 1
    fi
    info "$(L '官方最新:') ${SNELL_LATEST}"
    if [ -n "$current" ] && ! snell_ver_gt "$SNELL_LATEST" "$current"; then
        success "$(L '已经是最新版本')"
        return 0
    fi
    if ! confirm "$(L '升级到') ${SNELL_LATEST}$(L '？（服务会重启，约 2 秒中断；启动失败自动回滚）')" y; then
        info "$(L '已取消')"
        return 0
    fi
    snell_upgrade_to "$SNELL_LATEST"
}

snell_install() {
    step "$(L '安装 Snell Server（Surge 官方，v')${SNELL_MAJOR}$(L '）')"
    divider
    local arch current latest port="" psk="" mode="default" pref="default" host name keep=0 ans old_port def_port
    local hostre='^[][A-Za-z0-9.:_-]+$' namere='^[A-Za-z0-9._-]+$' pskre='^[A-Za-z0-9_-]{12,255}$'
    arch="$(snell_arch)" || return 1
    preflight_install_check "Snell v${SNELL_MAJOR}" "$SNELL_BIN" "$SNELL_DIR" || return 1
    apt_install curl unzip ca-certificates iproute2 || { warn "$(L '依赖安装失败，请检查 apt 源/网络')"; return 1; }
    snell_load_state
    current="$(snell_installed_version)"
    old_port="$(snell_port)"

    echo -e "${BOLD}$(L '版本通道：')${NC}"
    echo "  1) $(L 'beta   - 跟随官方最新测试版（b / rc），正式版发布后自动转到正式版（默认）')"
    echo "  2) $(L 'stable - 只安装和跟随正式版')"
    read -rp "$(L '选择') [$(L '1/2，默认') $([ "$SNELL_CHANNEL" = "stable" ] && echo 2 || echo 1)]: " ans || { [ -n "$ans" ] || return 1; }
    case "${ans:-}" in
        1) SNELL_CHANNEL="beta" ;;
        2) SNELL_CHANNEL="stable" ;;
        *) : ;;
    esac
    info "$(L '正在查询官方最新版本（发布页 + 下载站探测，约几秒）...')"
    snell_query_latest "$arch" "$SNELL_CHANNEL" "$current"
    latest="$SNELL_LATEST"
    if [ -z "$latest" ] && [ -n "$SNELL_LATEST_PRE" ]; then
        warn "$(L '官方目前只有 v')${SNELL_MAJOR} $(L '的测试版（')${SNELL_LATEST_PRE}$(L '），还没有正式版')"
        if confirm "$(L '安装测试版') ${SNELL_LATEST_PRE}$(L '？（之后的自动更新也会跟随测试通道）')" y; then
            SNELL_CHANNEL="beta"
            latest="$SNELL_LATEST_PRE"
        else
            info "$(L '已取消')"
            return 0
        fi
    fi
    if [ -z "$latest" ]; then
        warn "$(L '未能从官方发布页取得 v')${SNELL_MAJOR} $(L '的版本信息（')${SNELL_KB_URLS[0]} $(L '不可达，或该架构') ${arch} $(L '没有 v')${SNELL_MAJOR} $(L '版本）')"
        while true; do
            read -rp "$(L '可手动输入版本号继续（如 v6.0.0，回车取消）:') " latest || { [ -n "$latest" ] || return 1; }
            latest="${latest//[[:space:]]/}"
            if [ -z "$latest" ]; then info "$(L '已取消')"; return 0; fi
            [[ "$latest" == v* ]] || latest="v${latest}"
            if snell_ver_key "$latest" >/dev/null 2>&1; then break; fi
            warn "$(L '版本号格式不合法')"
        done
    fi
    # 发布页偶尔滞后：本机已装的版本比发布页列出的还新时，重装不降级
    if [ -n "$current" ] && [ "$(snell_ver_major "$current")" = "$SNELL_MAJOR" ] && snell_ver_gt "$current" "$latest"; then
        info "$(L '本机已安装的') ${current} $(L '比发布页列出的') ${latest} $(L '更新，按') ${current} $(L '重装')"
        latest="$current"
    fi
    info "$(L '将安装:') ${latest}$(L '（linux-')${arch}$(L '）')"
    if [ -n "$SNELL_NEWER_MAJOR" ]; then
        info "$(L '提示：官方已有更高大版本') ${SNELL_NEWER_MAJOR}$(L '，本脚本按 v')${SNELL_MAJOR} $(L '的配置格式管理，不自动跨大版本')"
    fi

    if [ -f "$SNELL_CONF" ] && [ -n "$old_port" ] && [ -n "$(snell_conf_get psk 2>/dev/null || true)" ]; then
        info "$(L '检测到已有 Snell 配置（端口') ${old_port}$(L '）')"
        if confirm "$(L '保留现有端口和 PSK？（选 n 重新配置）')" y; then keep=1; fi
    fi

    if [ "$keep" = "1" ]; then
        port="$old_port"
        psk="$(snell_conf_get psk 2>/dev/null || true)"
        mode="$(snell_conf_get mode 2>/dev/null || true)"; mode="${mode:-default}"
        pref="$(snell_conf_get dns-ip-preference 2>/dev/null || true)"; pref="${pref:-default}"
        case "$mode" in default|unshaped|unsafe-raw) : ;; *) mode="default" ;; esac
        case "$pref" in default|prefer-ipv4|prefer-ipv6|ipv4-only|ipv6-only) : ;; *) pref="default" ;; esac
    else
        def_port="$(random_free_port)"
        SNELL_ASK_OLD_PORT="$old_port"
        ask_free_port "$def_port" snell_port_taken_new snell_port_conflict port || return 1
        while true; do
            read -rp "$(L 'PSK（回车自动生成 32-48 位随机串；自定义需 12-255 位，仅限字母、数字、- 和 _）:') " psk || { [ -n "$psk" ] || return 1; }
            if [ -z "$psk" ]; then
                psk="$(snell_gen_psk)"
                if [ "${#psk}" -lt 32 ] || [ "${#psk}" -gt 48 ] || [[ ! "$psk" =~ $pskre ]]; then warn "$(L '随机 PSK 生成失败')"; return 1; fi
                info "$(L '已生成 PSK:') ${psk}"
                break
            fi
            if [[ "$psk" =~ $pskre ]]; then break; fi
            warn "$(L 'PSK 不符合要求')"
        done
        echo ""
        echo -e "${BOLD}$(L 'mode（服务端与客户端必须一致）：')${NC}"
        echo "  1) $(L 'default    - 流量整形混淆 + AES 加密（推荐）')"
        echo "  2) $(L 'unshaped   - 仅 AES 加密、不做混淆，吞吐约高 10%（官方说明：相当于 Snell v3）')"
        echo "  3) $(L 'unsafe-raw - 不加密、不混淆，明文转发（只适合可信内网 / 专线）')"
        read -rp "$(L '选择') [$(L '1/2/3，默认1')]: " ans || { [ -n "$ans" ] || return 1; }
        case "${ans:-1}" in
            2) mode="unshaped" ;;
            3)
                warn "$(L 'unsafe-raw 下所有流量明文传输，公网使用等于裸奔')"
                if confirm "$(L '确认使用 unsafe-raw？')" n; then mode="unsafe-raw"; else mode="default"; fi
                ;;
            *) mode="default" ;;
        esac
        echo ""
        echo -e "${BOLD}$(L '出站 DNS 地址族偏好 dns-ip-preference：')${NC}"
        echo "  1) default  2) prefer-ipv4  3) prefer-ipv6  4) ipv4-only  5) ipv6-only"
        read -rp "$(L '选择') [$(L '1-5，默认1')]: " ans || { [ -n "$ans" ] || return 1; }
        case "${ans:-1}" in
            2) pref="prefer-ipv4" ;; 3) pref="prefer-ipv6" ;; 4) pref="ipv4-only" ;; 5) pref="ipv6-only" ;; *) pref="default" ;;
        esac
    fi

    host="${SNELL_PUBLIC_HOST:-$(detect_public_host)}"
    while true; do
        read -rp "$(L '客户端连接用的公网地址（回车使用') ${host:-$(L '未探测到，请手动输入')}$(L '）:') " ans || { [ -n "$ans" ] || return 1; }
        ans="${ans:-$host}"
        if [[ -n "$ans" && "$ans" =~ $hostre ]]; then host="$ans"; break; fi
        warn "$(L '地址不能为空，且只能包含字母、数字和 . : - _') [ ]"
    done
    name="${SNELL_NODE_NAME:-Snell-v${SNELL_MAJOR}}"
    read -rp "$(L '节点名称（回车使用') ${name}$(L '）:') " ans || { [ -n "$ans" ] || return 1; }
    if [ -n "$ans" ]; then
        if [[ "$ans" =~ $namere ]]; then name="$ans"; else warn "$(L '名称只能包含字母、数字和 . _ -，已使用默认值')"; fi
    fi

    snell_ensure_user || return 1
    while true; do
        info "$(L '下载') ${latest} ..."
        if snell_fetch "$latest" "$arch"; then break; fi
        confirm "$(L '下载失败，是否立即重试？')" y || return 1
    done
    snell_apply_binary "$latest"
    local snell_conf_bak=""
    if [ -f "$SNELL_CONF" ]; then snell_conf_bak="${SNELL_CONF}.bak.$(date +%Y%m%d-%H%M%S)"; cp -f "$SNELL_CONF" "$snell_conf_bak" || snell_conf_bak=""; fi
    snell_write_conf "$port" "$psk" "$mode" "$pref"
    snell_write_service
    systemctl daemon-reload
    systemctl enable snell >/dev/null 2>&1 || true
    systemctl restart snell 2>/dev/null || true
    sleep 2
    if snell_main_healthy; then
        [ -n "$snell_conf_bak" ] && rm -f "$snell_conf_bak"
        success "Snell ${latest} $(L '已启动并监听 TCP') ${port}"
    else
        warn "$(L 'Snell 未能正常启动，最近日志：')"
        journalctl -u snell -n 20 --no-pager 2>/dev/null || true
        if [ -n "$snell_conf_bak" ] && [ -f "$snell_conf_bak" ]; then cp -f "$snell_conf_bak" "$SNELL_CONF"; rm -f "$snell_conf_bak"; snell_fix_perms; info "$(L '已恢复旧配置')"; fi
        snell_rollback_binary "$current" || true
        return 1
    fi

    SNELL_PUBLIC_HOST="$host"; SNELL_NODE_NAME="$name"
    snell_save_state
    snell_start_extras

    fw_allow_for_service "${port}/tcp"
    if [ -n "$old_port" ] && [ "$old_port" != "$port" ]; then fw_prune_old_specs "${old_port}/tcp"; fi

    echo ""
    reserved_ports_sync || true
    if [ "$SNELL_AUTO_UPDATE" = "1" ]; then
        snell_enable_autoupdate || true
    elif confirm "$(L '开启自动更新？（每天检查一次官方发布，')${SNELL_CHANNEL} $(L '通道有 v')${SNELL_MAJOR} $(L '新版本就自动升级，失败自动回滚）')" y; then
        snell_enable_autoupdate || true
    fi
    # 保活巡检默认随安装启用（可在主菜单「8) 自动维护」里关闭）
    maint_ask_script_auto
    maint_install_timers || true
    if snell_is_prerelease "$latest"; then
        warn "$(L '当前安装的是测试版') ${latest}$(L '：客户端需使用支持该版本的 Surge 测试渠道，协议在正式版前仍可能变动，两端要同步')"
    fi
    ensure_adam_shortcut || true
    snell_show_config
    return 0
}

snell_reconfig() {
    snell_require || return 1
    local port psk mode pref old_port choice ans bak
    local pskre='^[A-Za-z0-9_-]{12,255}$'
    port="$(snell_port)"; old_port="$port"
    psk="$(snell_conf_get psk 2>/dev/null || true)"
    mode="$(snell_conf_get mode 2>/dev/null || true)"; mode="${mode:-default}"
    pref="$(snell_conf_get dns-ip-preference 2>/dev/null || true)"; pref="${pref:-default}"
    echo "$(L '当前：端口') ${port} · mode ${mode} $(L '· DNS 偏好') ${pref}"
    echo "  $(L '（这里修改的是主端口配置；附加端口请用「删除端口配置」+「新增端口配置」）')"
    echo "  1) $(L '修改端口')"
    echo "  2) $(L '重新生成 PSK（同时更换一套流量特征）')"
    echo "  3) $(L '自定义 PSK')"
    echo "  4) $(L '修改 mode')"
    echo "  5) $(L '修改 DNS 地址族偏好')"
    echo "  6) $(L '修改节点名称 / 公网地址（只影响生成的 Surge 配置行）')"
    echo "  0) $(L '返回')"
    read -rp "$(L '请选择:') " choice || { [ -n "$choice" ] || return 1; }
    case "$choice" in
        1)
            read -rp "$(L '新的监听端口:') " ans || { [ -n "$ans" ] || return 1; }
            if [[ ! "$ans" =~ ^[0-9]+$ ]] || [ "$((10#$ans))" -lt 1 ] || [ "$((10#$ans))" -gt 65535 ]; then warn "$(L '端口不合法')"; return 1; fi
            ans=$((10#$ans))
            if [ "$ans" != "$old_port" ] && snell_port_taken "$ans"; then warn "$(L '端口') ${ans} $(L '已经是本机的一份 Snell 附加端口配置')"; return 1; fi
            if snell_port_conflict "$ans"; then warn "$(L 'TCP 端口') ${ans} $(L '已被其他进程占用')"; return 1; fi
            port="$ans"
            ;;
        2)
            psk="$(snell_gen_psk)"
            if [ "${#psk}" -lt 32 ] || [ "${#psk}" -gt 48 ] || [[ ! "$psk" =~ $pskre ]]; then warn "$(L '随机 PSK 生成失败')"; return 1; fi
            ;;
        3)
            read -rp "$(L '新的 PSK（12-255 位，仅限字母、数字、- 和 _）:') " ans || { [ -n "$ans" ] || return 1; }
            if [[ ! "$ans" =~ $pskre ]]; then warn "$(L 'PSK 不符合要求')"; return 1; fi
            psk="$ans"
            ;;
        4)
            echo "  1) default  2) unshaped  3) $(L 'unsafe-raw（明文，仅可信内网）')"
            read -rp "$(L '选择:') " ans || { [ -n "$ans" ] || return 1; }
            case "$ans" in
                1) mode="default" ;; 2) mode="unshaped" ;;
                3) if confirm "$(L 'unsafe-raw 为明文传输，确认？')" n; then mode="unsafe-raw"; else return 0; fi ;;
                *) warn "$(L '无效选择')"; return 1 ;;
            esac
            ;;
        5)
            echo "  1) default  2) prefer-ipv4  3) prefer-ipv6  4) ipv4-only  5) ipv6-only"
            read -rp "$(L '选择:') " ans || { [ -n "$ans" ] || return 1; }
            case "$ans" in
                1) pref="default" ;; 2) pref="prefer-ipv4" ;; 3) pref="prefer-ipv6" ;; 4) pref="ipv4-only" ;; 5) pref="ipv6-only" ;;
                *) warn "$(L '无效选择')"; return 1 ;;
            esac
            ;;
        6)
            local hostre='^[][A-Za-z0-9.:_-]+$' namere='^[A-Za-z0-9._-]+$'
            snell_load_state
            read -rp "$(L '公网地址（回车保持') ${SNELL_PUBLIC_HOST:-$(L '未设置')}$(L '）:') " ans || { [ -n "$ans" ] || return 1; }
            if [ -n "$ans" ]; then
                if [[ "$ans" =~ $hostre ]]; then SNELL_PUBLIC_HOST="$ans"; else warn "$(L '地址格式不合法，未修改')"; fi
            fi
            read -rp "$(L '节点名称（回车保持') ${SNELL_NODE_NAME:-Snell-v${SNELL_MAJOR}}$(L '）:') " ans || { [ -n "$ans" ] || return 1; }
            if [ -n "$ans" ]; then
                if [[ "$ans" =~ $namere ]]; then SNELL_NODE_NAME="$ans"; else warn "$(L '名称格式不合法，未修改')"; fi
            fi
            snell_save_state
            snell_show_config
            return 0
            ;;
        *) return 0 ;;
    esac

    bak="${SNELL_CONF}.bak"
    cp -f "$SNELL_CONF" "$bak"
    snell_write_conf "$port" "$psk" "$mode" "$pref"
    if ! svc_restart_wait snell 2 15 || ! snell_main_healthy; then
        warn "$(L '新配置启动失败，已恢复原配置。日志：')"
        mv -f "$bak" "$SNELL_CONF"
        snell_fix_perms
        systemctl restart snell 2>/dev/null || true
        return 1
    fi
    rm -f "$bak"
    success "$(L '配置已更新并重启')"
    if [ "$port" != "$old_port" ]; then
        fw_allow_for_service "${port}/tcp"
        fw_prune_old_specs "${old_port}/tcp"
        reserved_ports_sync || true
    fi
    warn "$(L '客户端需要同步修改，新的配置行如下')"
    snell_show_config
    return 0
}

snell_status() {
    snell_require || return 1
    systemctl status snell --no-pager 2>/dev/null | head -n 12 || true
    divider
    snell_load_state
    echo -e "  $(L '版本     :') $(snell_installed_version)"
    echo -e "  $(L '监听     :') $(snell_conf_get listen 2>/dev/null || echo '?')"
    echo -e "  $(L '自动更新 :') $([ "$SNELL_AUTO_UPDATE" = "1" ] && echo "开启（${SNELL_CHANNEL} 通道）" || echo "关闭")"
    echo "  $(L '最近的维护记录：')"
    if [ -s "$MAINT_LOG" ]; then grep -E 'Snell|snell' "$MAINT_LOG" 2>/dev/null | tail -n 5 || true; else echo "    $(L '（暂无）')"; fi
    return 0
}

# 健康检查（只检测，不改动）。返回 0 = 全部正常
# 全局健康检查行输出：HC_PROBLEMS 累计异常数（M11）
HC_PROBLEMS=0
hc_line() {
    case "$1" in
        0) echo -e "  ${GREEN}✓${NC} $2" ;;
        1) echo -e "  ${RED}✗${NC} $2"; HC_PROBLEMS=$((HC_PROBLEMS + 1)) ;;
        *) echo -e "  ${YELLOW}!${NC} $2" ;;
    esac
}

# health_check_common UNIT：服务运行/自启两行（Snell 与 Xray 健康检查共用，M11）
health_check_common() {
    local unit="$1" active enabled restarts
    active="$(systemctl is-active "$unit" 2>/dev/null || true)"
    enabled="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
    restarts="$(systemctl show "$unit" -p NRestarts --value 2>/dev/null || true)"
    if [ "$active" = "active" ]; then hc_line 0 "$(L '服务运行中（systemd 自动重启次数:') ${restarts:-0}$(L '）')"; else hc_line 1 "$(L '服务未运行（状态:') ${active:-unknown}$(L '）')"; fi
    if [ "$enabled" = "enabled" ]; then hc_line 0 "$(L '已设为开机自启')"; else hc_line 1 "$(L '未设为开机自启')"; fi
}

snell_health_check() {
    snell_require || return 1
    local port arch cur out
    HC_PROBLEMS=0
    step "$(L 'Snell 健康检查')"
    divider
    port="$(snell_port)"
    cur="$(snell_installed_version)"
    health_check_common snell
    if [ -n "$port" ]; then
        if tcp_listening "$port"; then hc_line 0 "TCP ${port} $(L '正在监听')"; else hc_line 1 "TCP ${port} $(L '没有在监听')"; fi
        if [ "$port" -ge 1024 ]; then
            if reserved_port_ok "$port"; then
                hc_line 0 "$(L '端口') ${port} $(L '已加入内核保留端口')"
            elif ! reserved_ports_writable; then
                hc_line 2 "$(L '内核保留端口在当前容器/受限内核中只读，已跳过检查')"
            else
                hc_line 1 "$(L '端口') ${port} $(L '未加入内核保留端口（可能被出站连接占用导致重启后绑定失败）')"
            fi
        fi
        if ufw_active; then
            if fw_is_allowed "$port" tcp; then hc_line 0 "$(L '防火墙已放行') ${port}/tcp"; else hc_line 1 "$(L '防火墙未放行') ${port}/tcp"; fi
        else
            hc_line 2 "$(L 'ufw 未启用（如有云厂商安全组，请确认已放行') ${port}$(L '/tcp）')"
        fi
    else
        hc_line 1 "$(L '配置文件里读不到监听端口')"
    fi
    out="$(timeout 5 "$SNELL_BIN" -v 2>&1 < /dev/null || true)"
    if [[ "$out" == *"not found"* || "$out" == *"cannot execute"* || "$out" == *"GLIBC"* ]]; then
        hc_line 1 "$(L '二进制无法运行:') ${out}"
    else
        hc_line 0 "$(L '二进制可运行（')${cur:-$(L '版本未知')}$(L '）')"
    fi
    local xp
    while IFS= read -r xp; do
        if snell_extra_healthy "$xp"; then hc_line 0 "$(L '附加端口') ${xp} $(L '运行并监听中')"; else hc_line 1 "$(L '附加端口') ${xp} $(L '未运行或没有在监听')"; fi
        if [ "$xp" -ge 1024 ] && ! reserved_port_ok "$xp" && reserved_ports_writable; then hc_line 1 "$(L '附加端口') ${xp} $(L '未加入内核保留端口')"; fi
        if ufw_active && ! fw_is_allowed "$xp" tcp; then hc_line 1 "$(L '防火墙未放行附加端口') ${xp}/tcp"; fi
    done < <(snell_extra_ports)
    if grep -q '^Restart=always' "$SNELL_SERVICE" 2>/dev/null; then hc_line 0 "$(L '服务单元已启用崩溃自动拉起')"; else hc_line 1 "$(L '服务单元未启用 Restart=always（旧版单元）')"; fi
    maint_load
    if [ "$MAINT_WATCHDOG" = "1" ] && systemctl is-active --quiet adam-watchdog.timer 2>/dev/null; then
        hc_line 0 "$(L '保活巡检定时器运行中（每 5 分钟）')"
    elif [ "$MAINT_WATCHDOG" != "1" ]; then
        hc_line 2 "$(L '保活巡检未开启')"
    else
        hc_line 1 "$(L '保活巡检定时器未运行')"
    fi
    snell_load_state
    if [ "$SNELL_AUTO_UPDATE" = "1" ]; then
        if systemctl is-active --quiet adam-maintain.timer 2>/dev/null; then
            hc_line 0 "$(L '自动更新已开启（')${SNELL_CHANNEL} $(L '通道）')"
        else
            hc_line 1 "$(L '自动更新已开启，但每日维护定时器未运行')"
        fi
    else
        hc_line 2 "$(L '自动更新未开启')"
    fi
    arch="$(snell_arch 2>/dev/null || true)"
    if [ -n "$arch" ] && [ -n "$cur" ]; then
        snell_query_latest "$arch" "$SNELL_CHANNEL" "$cur"
        if [ "$SNELL_SOURCE_OK" = "1" ]; then
            if [ -n "$SNELL_LATEST" ] && snell_ver_gt "$SNELL_LATEST" "$cur"; then
                hc_line 2 "$(L '官方有新版本') ${SNELL_LATEST}$(L '（当前') ${cur}$(L '），可用「检查并更新」升级')"
            else
                hc_line 0 "$(L '已是') ${SNELL_CHANNEL} $(L '通道最新版本')"
            fi
            if [ -n "$SNELL_NEWER_MAJOR" ]; then hc_line 2 "$(L '官方已有更高大版本') ${SNELL_NEWER_MAJOR}$(L '（不自动跨大版本）')"; fi
        else
            hc_line 2 "$(L '暂时连不上官方下载站，无法判断是否有新版本')"
        fi
    fi
    divider
    if [ "$HC_PROBLEMS" -eq 0 ]; then
        success "$(L '健康检查通过')"
        return 0
    fi
    warn "$(L '发现') ${HC_PROBLEMS} $(L '项问题，可用「一键修复」处理')"
    return 1
}

# 一键修复核心逻辑（quiet 模式供看门狗二段自愈调用）
_snell_repair_core() {
    local quiet="${1:-}" port rp
    port="$(snell_port)"
    snell_ensure_user || return 1
    snell_write_service
    snell_fix_perms
    systemctl daemon-reload
    systemctl reset-failed snell >/dev/null 2>&1 || true
    systemctl enable snell >/dev/null 2>&1 || true
    reserved_ports_sync || true
    if [ -n "$port" ] && ufw_active; then ufw allow "${port}/tcp" >/dev/null 2>&1 || true; fi
    maint_install_timers || true
    while IFS= read -r rp; do
        [ -n "$rp" ] || continue
        systemctl reset-failed "snell-port@${rp}" >/dev/null 2>&1 || true
        if ufw_active; then ufw allow "${rp}/tcp" >/dev/null 2>&1 || true; fi
    done < <(snell_extra_ports)
    snell_sync_extras_after_restore
    systemctl restart snell 2>/dev/null || true
    sleep 2
    snell_healthy
}

# 一键修复：补齐服务单元 / 权限 / 保留端口 / 防火墙 / 定时器，然后重启并复查
snell_repair() {
    snell_require || return 1
    local xp
    step "$(L 'Snell 一键修复')"
    divider
    if _snell_repair_core; then
        success "$(L '修复完成，服务运行正常')"
        return 0
    fi
    warn "$(L '修复后服务仍未正常监听，最近日志：')"
    if ! snell_main_healthy; then
        journalctl -u snell -n 20 --no-pager 2>/dev/null || true
    fi
    while IFS= read -r xp; do
        [ -n "$xp" ] || continue
        if ! snell_extra_healthy "$xp"; then
            warn "$(L '附加端口') ${xp} $(L '未正常运行，最近日志：')"
            journalctl -u "snell-port@${xp}" -n 15 --no-pager 2>/dev/null || true
        fi
    done < <(snell_extra_ports)
    return 1
}

snell_logs() {
    snell_require || return 1
    info "$(L '实时日志（Ctrl+C 返回）')"
    journalctl -u snell -n 30 -f || true
    return 0
}

snell_restart() {
    snell_require || return 1
    snell_restart_all
    sleep 2
    if snell_healthy; then
        success "$(L 'Snell 已重启（含全部附加端口）')"
    else
        warn "$(L '重启后未检测到服务正常监听：')"
        journalctl -u snell -n 15 --no-pager 2>/dev/null || true
        return 1
    fi
    return 0
}

snell_uninstall() {
    if [ ! -x "$SNELL_BIN" ] && [ ! -f "$SNELL_SERVICE" ]; then
        info "$(L '未检测到 Snell 安装')"
        return 0
    fi
    local port p ports
    port="$(snell_port)"
    ports="$(snell_all_ports | tr '\n' ' ')"
    if ! confirm "$(L '确认卸载 Snell（全部端口配置:') ${ports:-$(L '无')}$(L '）？')" n; then info "$(L '已取消')"; return 0; fi
    systemctl disable --now snell >/dev/null 2>&1 || true
    while IFS= read -r p; do
        systemctl disable --now "snell-port@${p}" >/dev/null 2>&1 || true
    done < <(snell_extra_ports)
    rm -f "$SNELL_PORT_UNIT"
    rm -f "$SNELL_SERVICE" "$SNELL_BIN" "$SNELL_BIN_BACKUP" "$SNELL_VERSION_FILE"
    systemctl daemon-reload
    if [ -n "${ports// /}" ] && ufw_installed; then
        if confirm "$(L '同时删除防火墙里 Snell 端口（')${ports}$(L '）的放行规则？')" y; then
            # v8.6（BUG-09）：删除前校验是否被其他已安装服务复用
            while IFS= read -r p; do
                [ -n "$p" ] || continue
                if port_used_by_other_services "${p}/tcp" snell; then
                    info "$(L '端口') ${p}/tcp $(L '仍被其他服务使用，保留防火墙规则')"
                else
                    fw_delete_spec "${p}/tcp"
                fi
            done < <(printf '%s\n' "$ports" | tr ' ' '\n' | grep -v '^$')
        fi
    fi
    if confirm "$(L '同时删除配置目录') ${SNELL_DIR}$(L '（含 PSK）？')" n; then
        rm -rf "$SNELL_DIR"
        userdel snell >/dev/null 2>&1 || true
    else
        info "$(L '已保留') ${SNELL_DIR}$(L '，重装时可直接沿用端口和 PSK（附加端口也会一并恢复）')"
    fi
    reserved_ports_sync || true
    success "$(L 'Snell 已卸载')"
    return 0
}

snell_state_text() {
    local v
    if [ ! -x "$SNELL_BIN" ]; then
        printf '%s' "${YELLOW}$(L '未安装')${NC}"
        return 0
    fi
    v=""
    if [ -f "$SNELL_VERSION_FILE" ]; then v="$(tr -d ' \r\n' < "$SNELL_VERSION_FILE" 2>/dev/null || true)"; fi
    local n; n="$(snell_all_ports | grep -c . || true)"
    printf '%s' "${v:-$(L '版本未知')} · ${n} $(L '个端口 ·') $(svc_state snell)"
}

snell_menu() {
    local choice
    while true; do
        clear 2>/dev/null || true
        snell_load_state
        echo -e "${BOLD}${CYAN}━━━ $(L 'Snell Server 管理（Surge 官方，v')${SNELL_MAJOR}$(L '）') ━━━${NC}"
        echo -e "  $(L '当前状态:') $(snell_state_text)    $(L '通道:') ${SNELL_CHANNEL}    $(L '自动更新:') $(maint_onoff "$SNELL_AUTO_UPDATE")"
        divider
        echo -e "  ${GREEN}1)${NC}  ${GREEN}$(L '安装')${NC} $(L '/ 重装 Snell（自动获取官方最新版，默认跟随测试版）')"
        echo -e "  ${GREEN}2)${NC}  $(L '检查并更新到官方最新版')"
        echo -e "  ${GREEN}3)${NC}  $(L '查看配置 / Surge 节点配置行（全部端口）')"
        echo -e "  ${GREEN}4)${NC}  $(L '修改主端口配置（端口 / PSK / mode / DNS 偏好 / 节点名）')"
        echo -e "  ${GREEN}5)${NC}  ${GREEN}$(L '新增')${NC}$(L '端口配置（多端口：每个端口独立 PSK）')"
        echo -e "  ${GREEN}6)${NC}  ${RED}$(L '删除')${NC}$(L '某个端口配置（可选任意一个端口）')"
        echo -e "  ${GREEN}7)${NC}  $(L '自动更新 开 / 关 / 切换通道（beta') ⇄ $(L 'stable）')"
        echo -e "  ${GREEN}8)${NC}  $(L '健康检查（只检测）')"
        echo -e "  ${GREEN}9)${NC}  $(L '一键修复（单元 / 保留端口 / 防火墙 / 保活定时器）')"
        echo -e "  ${GREEN}10)${NC} $(L '服务状态')"
        echo -e "  ${GREEN}11)${NC} $(L '实时日志')"
        echo -e "  ${GREEN}12)${NC} $(L '重启服务')"
        echo -e "  ${GREEN}13)${NC} ${RED}$(L '卸载')${NC} Snell"
        echo -e "  ${GREEN}0)${NC}  $(L '返回主菜单')"
        divider
        read -rp "$(L '请选择') [0-13]: " choice || return 0
        case "$choice" in
            1)  run_action snell_install ;;
            2)  run_action snell_update ;;
            3)  run_action snell_show_config ;;
            4)  run_action snell_reconfig ;;
            5)  run_action snell_add_port ;;
            6)  run_action snell_delete_port ;;
            7)  run_action snell_toggle_autoupdate ;;
            8)  run_action snell_health_check ;;
            9)  run_action snell_repair ;;
            10) run_action snell_status ;;
            11) run_action snell_logs ;;
            12) run_action snell_restart ;;
            13) run_action snell_uninstall ;;
            0)  return 0 ;;
            *)  warn "$(L '无效选择')" ;;
        esac
        pause_return
    done
}

snell_cli() {
    local sub="${1:-menu}"
    if [ "$#" -gt 0 ]; then shift; fi
    case "$sub" in
        menu)        snell_menu ;;
        install)     snell_install ;;
        update|check) snell_update ;;
        config|info) snell_show_config ;;
        reconfig)    snell_reconfig ;;
        ports)       snell_require && snell_list_ports ;;
        add-port)    snell_add_port ;;
        del-port)    snell_delete_port "${1:-}" ;;
        status)      snell_status ;;
        logs)        snell_logs ;;
        restart)     snell_restart ;;
        health)      snell_health_check ;;
        repair)      snell_repair ;;
        auto)
            case "${1:-}" in
                on)  snell_require && snell_enable_autoupdate ;;
                off) snell_disable_autoupdate ;;
                *)   snell_toggle_autoupdate ;;
            esac ;;
        uninstall)   snell_uninstall ;;
        *) error "$(L '未知的 snell 子命令:') ${sub}$(L '（可用: install / update / config / reconfig / ports / add-port / del-port') [$(L '端口')] / status / health / repair / logs / restart / auto [on|off] $(L '/ uninstall）')" ;;
    esac
}

