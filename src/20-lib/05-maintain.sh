# ══════════════════════════════════════════════════════════════
#   自动维护：保活（watchdog）/ 每日自动更新 / 端口保留
#   设计参考 Eric86777/vps-tcp-tune 的 Snell 稳定性方案：
#     - 服务单元 Restart=always 且不设启动次数上限（进程崩溃由 systemd 立即拉起）；
#     - 监听端口写入 net.ipv4.ip_local_reserved_ports，避免被本机出站连接当临时端口占走，
#       导致服务重启后绑定失败；
#     - 定时巡检：单元在运行但端口没监听 / 单元已退出时自动重启（systemd 管不到"进程活着但不监听"）；
#     - 每日任务：管理脚本自更新 → Snell / Xray 跟随官方发布更新 → 可选的每日定时重启。
#   参考脚本用 cron + 包装脚本，这里统一用 systemd timer（开机补跑、日志进 journal）。
# ══════════════════════════════════════════════════════════════

# state_load file "VAR=default ..." [whitelist_var "v1 v2 ..."]：读状态文件（不存在则用默认值）；
# 白名单变量取值非法时重置为默认值。state_save file dir dir_mode VAR...：写状态文件（文件 600）。
state_load() {
    local file="$1" defs="$2" wl_var="${3:-}" wl_vals="${4:-}" kv k v cur ok x wl_def="" allowed=" "
    while IFS= read -r kv; do
        [ -n "$kv" ] || continue
        k="${kv%%=*}"; v="${kv#*=}"
        printf -v "$k" '%s' "$v"
        allowed="${allowed}${k} "
        [ "$k" = "$wl_var" ] && wl_def="$v"
    done < <(printf '%s\n' "$defs" | tr ' ' '\n' | grep -v '^$')
    if [ -f "$file" ] && [ ! -L "$file" ]; then
        # v8.6：逐行安全校验后再 source，仅允许 $defs 中声明的键，拒绝任意变量或命令注入
        local _sl_ok=1 _sl_line _sl_k _sl_r _sl_v
        while IFS= read -r _sl_line || [ -n "$_sl_line" ]; do
            case "$_sl_line" in
                ""|"#"*) continue ;;
                *=*) _sl_k="${_sl_line%%=*}"; _sl_r="${_sl_line#*=}" ;;
                *) _sl_ok=0; break ;;
            esac
            [[ "$_sl_k" =~ ^[A-Z][A-Z0-9_]+$ ]] || { _sl_ok=0; break; }
            [[ "$allowed" == *" ${_sl_k} "* ]] || { _sl_ok=0; break; }
            case "$_sl_r" in
                \"*\") _sl_v="${_sl_r:1:${#_sl_r}-2}" ;;
                *) _sl_ok=0; break ;;
            esac
            _sl_v="${_sl_v//\\\\/}"; _sl_v="${_sl_v//\\\$/}"; _sl_v="${_sl_v//\\\`/}"; _sl_v="${_sl_v//\\\"/}"
            case "$_sl_v" in *'$'*|*'`'*|*'"'*|*'\') _sl_ok=0; break ;; esac
        done < "$file"
        if [ "$_sl_ok" = "1" ]; then
            # shellcheck disable=SC1090
            source "$file" 2>/dev/null || true
        fi
    fi
    if [ -n "$wl_var" ] && [ -n "$wl_vals" ]; then
        cur="${!wl_var}"
        ok=0; while IFS= read -r x; do [ -n "$x" ] || continue; [ "$cur" = "$x" ] && ok=1; done < <(printf '%s\n' "$wl_vals" | tr ' ' '\n' | grep -v '^$')
        [ "$ok" = "1" ] || printf -v "$wl_var" '%s' "$wl_def"
    fi
    return 0
}

state_save() {
    local file="$1" dir="$2" dir_mode="$3" tmp v
    shift 3
    install -d -m "$dir_mode" "$dir"
    tmp="$(umask 077; mktemp "${dir}/.$(basename "$file").XXXXXX")" || return 1
    (
        umask 077
        for v in "$@"; do printf '%s="%s"\n' "$v" "$(dq_escape "${!v:-}")"; done > "$tmp"
    ) || { rm -f "$tmp"; return 1; }
    chmod 600 "$tmp"
    mv -f "$tmp" "$file"
}

maint_load() {
    state_load "$MAINT_ENV" "MAINT_WATCHDOG=1 MAINT_SCRIPT_AUTO=0 MAINT_DAILY_RESTART=0 MAINT_SCRIPT_ASKED=0 MAINT_NOWHERE_AUTO=0 MAINT_REALM_AUTO=0 MAINT_CADDY_AUTO=0 MAINT_CF_TUNNEL_AUTO=0 MAINT_SCRIPT_STRICT_SHA=0 GITHUB_TOKEN="
    return 0
}

maint_save() {
    state_save "$MAINT_ENV" "$MAINT_DIR" 755 MAINT_WATCHDOG MAINT_SCRIPT_AUTO MAINT_DAILY_RESTART MAINT_SCRIPT_ASKED MAINT_NOWHERE_AUTO MAINT_REALM_AUTO MAINT_CADDY_AUTO MAINT_CF_TUNNEL_AUTO MAINT_SCRIPT_STRICT_SHA GITHUB_TOKEN
}

# 事件日志：保活重启、自动更新结果。超过约 200KB 时只留最后 400 行（权限收紧为 0600）
maint_log() {
    local msg="$*" size=0
    echo "$msg"
    install -d -m 755 "$(dirname "$MAINT_LOG")" 2>/dev/null || true
    if [ ! -e "$MAINT_LOG" ]; then ( umask 077; : > "$MAINT_LOG" ) 2>/dev/null || true; fi
    printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$msg" >> "$MAINT_LOG" 2>/dev/null || true
    chmod 600 "$MAINT_LOG" 2>/dev/null || true
    size="$(stat -c %s "$MAINT_LOG" 2>/dev/null || echo 0)"
    if [ "${size:-0}" -gt 204800 ]; then
        ( umask 077; tail -n 400 "$MAINT_LOG" > "${MAINT_LOG}.tmp" ) 2>/dev/null && mv -f "${MAINT_LOG}.tmp" "$MAINT_LOG"
    fi
    return 0
}

# 把本脚本管理的监听端口（≥1024 的）写入内核保留端口：持久化文件只含本脚本的端口；
# 运行时取"当前值 ∪ 本脚本端口"，只增不减，不动其他程序保留的端口。
reserved_ports_sync() {
    local csv cur new
    csv="$(managed_ports | awk -F/ '$1 ~ /^[0-9]+$/ && $1 >= 1024 {print $1}' | sort -un | paste -sd, - || true)"
    if [ -z "$csv" ]; then
        rm -f "$RESERVED_PORTS_FILE"
        return 0
    fi
    cat > "$RESERVED_PORTS_FILE" << RSVEOF
# $(L '由 Adam 管理脚本维护：Snell / Xray / Nowhere 的监听端口，避免被本机出站连接当作临时端口占用')
net.ipv4.ip_local_reserved_ports = ${csv}
RSVEOF
    if cur="$(sysctl -n net.ipv4.ip_local_reserved_ports 2>/dev/null)"; then
        # shellcheck disable=SC2086
        new="$(printf '%s\n' ${cur//,/ } ${csv//,/ } | awk 'NF && !s[$0]++' | paste -sd, - || true)"
        if [ -n "$new" ]; then sysctl -w "net.ipv4.ip_local_reserved_ports=${new}" >/dev/null 2>&1 || true; fi
    fi
    return 0
}

reserved_port_ok() {
    local port="$1" cur
    cur="$(sysctl -n net.ipv4.ip_local_reserved_ports 2>/dev/null || true)"
    printf '%s\n' "${cur//,/ }" | tr ' ' '\n' | awk -v p="$port" '
        { n = split($0, a, "-"); if (n == 1 && a[1] == p) f = 1; if (n == 2 && p + 0 >= a[1] + 0 && p + 0 <= a[2] + 0) f = 1 }
        END { exit !f }'
}

reserved_ports_writable() {
    [ -w /proc/sys/net/ipv4/ip_local_reserved_ports ]
}

# ss_port_lines proto port：输出 ss 里第 4 列端口精确等于 port 的监听行（proto=tcp|udp）
ss_port_lines() {
    local proto="$1" p="$2" flag
    command -v ss >/dev/null 2>&1 || return 1
    case "$proto" in tcp) flag="-tlnp" ;; udp) flag="-ulnp" ;; *) return 1 ;; esac
    ss "$flag" 2>/dev/null | awk -v p=":${p}" '{ n = length($4); if (n >= length(p) && substr($4, n - length(p) + 1) == p) print }' || true
    return 0
}

# TCP 端口是否有进程在监听
tcp_listening() {
    local port="$1"
    [ -n "$(ss_port_lines tcp "$port" || true)" ]
}

# 与 tcp_listening 同理：只比对 ss 第 4 列的端口，避免 IPv6 地址段误命中。
# ss 不可用时返回 1（无法确认即不健康，不 fail-open）。
udp_listening() {
    local port="$1"
    [ -n "$(ss_port_lines udp "$port" || true)" ]
}


# TCP 端口是否被"名字不含 $2"的进程占用
# v8.6（BUG-14d）：逐行检查全部监听套接字；只要有任意一行不属于 own（或拿不到进程名）即判定冲突
tcp_port_conflict() {
    local p="$1" own="${2:-__none__}" out line
    out="$(ss_port_lines tcp "$p" || true)"
    [ -n "$out" ] || return 1
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        if [[ "$line" != *"\"${own}\""* ]]; then
            return 0
        fi
    done <<< "$out"
    return 1
}

# 安装 Snell / Xray 时问一次：是否让管理脚本每天自动从仓库拉取更新（之后可在「自动维护」里改）
maint_ask_script_auto() {
    maint_load
    if [ "$MAINT_SCRIPT_ASKED" = "1" ]; then return 0; fi
    if confirm "$(L '让本管理脚本每天自动从仓库拉取更新？（地址:') ${SCRIPT_URL}$(L '；下载后校验完整性，版本不低于本地才替换）')" y; then
        MAINT_SCRIPT_AUTO="1"
    else
        MAINT_SCRIPT_AUTO="0"
    fi
    MAINT_SCRIPT_ASKED="1"
    maint_save
    return 0
}

maint_unit_installed() {
    case "$1" in
        snell-port@*) [ -f "${SNELL_PORTS_DIR}/${1#snell-port@}.conf" ] ;;
        *)            [ -f "/etc/systemd/system/$1.service" ] ;;
    esac
}

nowhere_healthy() {
    # v4.4：只看 active 不够——端口掉了服务仍可显示 active。
    # Egress 没有监听端口，只看 active；Portal 要求全部已配载体端口真实在监听。
    systemctl is-active --quiet nowhere 2>/dev/null || return 1
    [ "$(current_role)" = "portal" ] || return 0
    [ -f "$CONFIG_FILE" ] || return 0
    load_saved_config 2>/dev/null || return 0
    if has_tcp; then
        tcp_listening "$(tcp_port)" || return 1
    fi
    if has_udp; then
        udp_listening "$(udp_port)" || return 1
    fi
    return 0
}

maint_unit_healthy() {
    case "$1" in
        nowhere)   nowhere_healthy ;;
        snell)     snell_main_healthy ;;
        snell-port@*) snell_extra_healthy "${1#snell-port@}" ;;
        adam-xray) xray_healthy ;;
        adam-realm) realm_healthy ;;
        adam-caddy) caddy_healthy ;;
        adam-cloudflared) systemctl is-active --quiet adam-cloudflared 2>/dev/null ;;
        *)         systemctl is-active --quiet "$1" 2>/dev/null ;;
    esac
}

maint_install_timers() {
    if ! ensure_manager_copy >/dev/null 2>&1; then
        warn "$(L '管理脚本未能安装到') ${MANAGER_PATH}$(L '，无法启用定时任务')"
        return 1
    fi
    maint_load
    cat > /etc/systemd/system/adam-watchdog.service << WDSVC
[Unit]
Description=Adam manager: keep Snell / Xray / Nowhere / Realm alive
After=network-online.target

[Service]
Type=oneshot
ExecStart=${MANAGER_PATH} watchdog
WDSVC
    cat > /etc/systemd/system/adam-watchdog.timer << WDTMR
[Unit]
Description=Adam manager: service watchdog (every 5 minutes)

[Timer]
OnBootSec=3min
OnUnitActiveSec=5min
AccuracySec=30s

[Install]
WantedBy=timers.target
WDTMR
    cat > /etc/systemd/system/adam-maintain.service << MTSVC
[Unit]
Description=Adam manager: daily self-update and upstream updates (Snell / Xray)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${MANAGER_PATH} maintain
TimeoutStartSec=30min
MTSVC
    cat > /etc/systemd/system/adam-maintain.timer << MTTMR
[Unit]
Description=Adam manager: daily maintenance

[Timer]
OnCalendar=*-*-* 04:00:00
RandomizedDelaySec=2h
Persistent=true

[Install]
WantedBy=timers.target
MTTMR
    # 旧版（脚本 v4.0）只管 Snell 的定时器，功能已并入 adam-maintain
    systemctl disable --now adam-snell-update.timer >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/adam-snell-update.timer /etc/systemd/system/adam-snell-update.service
    systemctl daemon-reload
    systemctl enable --now adam-maintain.timer >/dev/null 2>&1 || warn "$(L 'adam-maintain.timer 启用失败')"
    if [ "$MAINT_WATCHDOG" = "1" ]; then
        systemctl enable --now adam-watchdog.timer >/dev/null 2>&1 || warn "$(L 'adam-watchdog.timer 启用失败')"
    else
        systemctl disable --now adam-watchdog.timer >/dev/null 2>&1 || true
    fi
    [ -f "$MAINT_ENV" ] || maint_save
    return 0
}

maint_remove_timers() {
    warn "$(L '移除定时器后，Xray 证书同步与自动续期将停止（证书到期前需手动续期或重装定时器）')"
    systemctl disable --now adam-watchdog.timer adam-maintain.timer >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/adam-watchdog.timer /etc/systemd/system/adam-watchdog.service \
          /etc/systemd/system/adam-maintain.timer /etc/systemd/system/adam-maintain.service
    systemctl daemon-reload
    return 0
}

maint_lock() {   # maint_lock [等待秒数]：拿不到锁返回 1 并记日志（L17）
    command -v flock >/dev/null 2>&1 || return 0
    # 同 fd 9 已持锁时可重入（M18）：直接再 flock，成功即返回
    if [ -e /proc/self/fd/9 ]; then
        if flock -w "${1:-0}" 9; then return 0; fi
        maint_log "$(L '另一个维护任务仍在运行，本次跳过')"
        return 1
    fi
    exec 9> "$MAINT_LOCK" || return 0
    if ! flock -w "${1:-0}" 9; then
        exec 9>&-
        maint_log "$(L '另一个维护任务仍在运行，本次跳过')"
        return 1
    fi
    return 0
}

# maint_lock_manual：手动入口拿 maint 锁；拿不到则警告并确认是否仍继续（默认否，M18）
maint_lock_manual() {
    if maint_lock 0; then return 0; fi
    warn "$(L '另一个维护或安装任务正在运行')"
    confirm "$(L '仍要继续吗？')" n
}

# 定时器每 5 分钟调用：全程不提问
# v8.6：两段式自愈 + 告警推送
#   第 1 段：reset-failed + 常规重启
#   第 2 段：若第 1 段未恢复（且距上次同类自愈 ≥ 30 分钟冷却），触发对应服务的权限收敛/证书同步/配置重建/保留端口同步，再复验
maint_watchdog() {
    local unit stamp now last heal_ok old_pin new_pin checked=0 unhealthy=0
    maint_load
    [ "$MAINT_WATCHDOG" = "1" ] || return 0
    # 正在更新 / 安装时不插手，下一轮再看（maint_lock 内部已记日志）
    maint_lock 0 || return 0
    local -a units=(snell)
    while IFS= read -r unit; do units+=("snell-port@${unit}"); done < <(snell_extra_ports)
    units+=(adam-xray nowhere adam-realm adam-caddy adam-cloudflared)
    for unit in "${units[@]}"; do
        maint_unit_installed "$unit" || continue
        # 只管"设为开机自启"的服务：手动 disable 掉的不会被拉起
        systemctl is-enabled --quiet "$unit" 2>/dev/null || continue
        checked=$((checked + 1))
        if maint_unit_healthy "$unit"; then continue; fi
        unhealthy=$((unhealthy + 1))
        maint_log "[$(L '保活')] ${unit} $(L '状态异常（未运行或端口未监听），正在重启')"
        old_pin=""
        [ "$unit" = "nowhere" ] && [ -f "$TLS_PIN_FILE" ] && old_pin="$(cat "$TLS_PIN_FILE" 2>/dev/null || true)"
        systemctl reset-failed "$unit" >/dev/null 2>&1 || true
        systemctl restart "$unit" >/dev/null 2>&1 || true
        sleep 3
        if maint_unit_healthy "$unit"; then
            maint_log "[$(L '保活')] ${unit} $(L '已恢复')"
            if [ "$unit" = "nowhere" ]; then
                save_current_pin >>"$MAINT_LOG" 2>&1 || true
                new_pin="$(cat "$TLS_PIN_FILE" 2>/dev/null || true)"
                if [ -n "$new_pin" ] && [ "$new_pin" != "$old_pin" ]; then
                    notify_send "Nowhere TLS Pin Changed" "Nowhere restarted and tls=1 pin updated. Check ${TLS_PIN_FILE}." || true
                fi
            fi
            continue
        fi
        # 第 2 段自愈：30 分钟冷却，避免持久性故障下每 5 分钟反复重建
        stamp="/run/adam-wd-heal.${unit//@/_}"
        now="$(date +%s 2>/dev/null || echo 0)"
        last="$(cat "$stamp" 2>/dev/null || echo 0)"
        [[ "$last" =~ ^[0-9]+$ ]] || last=0
        if [ $((now - last)) -lt 1800 ]; then
            maint_log "[$(L '保活')] ${unit} $(L '重启后仍异常（二段自愈冷却中），请查看: journalctl -u') ${unit} -n 50 --no-pager"
            continue
        fi
        printf '%s\n' "$now" > "$stamp" 2>/dev/null || true
        maint_log "[$(L '保活')] ${unit} $(L '常规重启未恢复，执行二段自动修复（权限/证书/配置/保留端口）...')"
        heal_ok=0
        case "$unit" in
            nowhere)          _nowhere_repair_core quiet >/dev/null 2>&1 && heal_ok=1 ;;
            snell|snell-port@*) _snell_repair_core quiet >/dev/null 2>&1 && heal_ok=1 ;;
            adam-xray)        _xray_repair_core quiet >/dev/null 2>&1 && heal_ok=1 ;;
            adam-realm)       _realm_repair_core quiet >/dev/null 2>&1 && heal_ok=1 ;;
            adam-caddy)       _caddy_repair_core quiet >/dev/null 2>&1 && heal_ok=1 ;;
            adam-cloudflared) _cf_tunnel_repair_core quiet >/dev/null 2>&1 && heal_ok=1 ;;
        esac
        if [ "$heal_ok" = "1" ] && maint_unit_healthy "$unit"; then
            maint_log "[$(L '保活')] ${unit} $(L '经二段自动修复已恢复')"
            notify_send "Service Self-Healed: ${unit}" "${unit} failed normal restart and recovered via stage-2 auto-repair." || true
            if [ "$unit" = "nowhere" ]; then
                save_current_pin >>"$MAINT_LOG" 2>&1 || true
                new_pin="$(cat "$TLS_PIN_FILE" 2>/dev/null || true)"
                if [ -n "$new_pin" ] && [ "$new_pin" != "$old_pin" ]; then
                    notify_send "Nowhere TLS Pin Changed" "Nowhere recovered and tls=1 pin updated. Check ${TLS_PIN_FILE}." || true
                fi
            fi
        else
            maint_log "[$(L '保活')] ${unit} $(L '二段自动修复后仍异常，请查看: journalctl -u') ${unit} -n 50 --no-pager"
            notify_send "Service Down Alert: ${unit}" "${unit} is still unhealthy after stage-2 auto-repair. Run: journalctl -u ${unit} -n 50 --no-pager" || true
        fi
    done
    if [ -t 1 ] && [ "$unhealthy" -eq 0 ]; then
        if [ "$checked" -gt 0 ]; then
            info "$(L '保活巡检通过：全部') ${checked} $(L '个已启用服务运行正常')"
        else
            info "$(L '暂无已启用的受管服务需要巡检')"
        fi
    fi
    return 0
}

# 取远端脚本到 $1 并做完整性与 SHA-256 校验；远端版本写入 REMOTE_SCRIPT_VERSION
script_fetch_remote() {
    local dst="$1" sha_url sha_txt expected actual ts
    REMOTE_SCRIPT_VERSION=""
    ts="$(date +%s)"
    secure_curl -fsSL --max-time 60 "${SCRIPT_URL}?t=${ts}" -o "$dst" 2>/dev/null \
        || secure_curl -fsSL --max-time 60 "$SCRIPT_URL" -o "$dst" 2>/dev/null || return 1
    # 截断的文件前半段往往是好的：除了标识和语法，还要求结尾的命令分发段在
    grep -q "Adam Nowhere" "$dst" 2>/dev/null || return 1
    grep -q '^case "\$ACTION" in' "$dst" 2>/dev/null || return 1
    bash -n "$dst" 2>/dev/null || return 1
    # v8.6：拉取官方 .sha256 校验文件并强制比对（命中即严格校验，不匹配立即拒绝；缺失时仅在 MAINT_SCRIPT_STRICT_SHA=1 下拒绝）
    sha_url="${SCRIPT_SHA256_URL:-${SCRIPT_URL}.sha256}"
    sha_txt="$(secure_curl -fsSL --max-time 20 "${sha_url}?t=${ts}" 2>/dev/null \
        || secure_curl -fsSL --max-time 20 "$sha_url" 2>/dev/null || true)"
    expected="$(printf '%s\n' "$sha_txt" | awk '{for(i=1;i<=NF;i++) if(length($i)==64 && $i ~ /^[0-9a-fA-F]+$/){print tolower($i); exit}}' || true)"
    if [ -n "$expected" ]; then
        actual="$(sha256sum "$dst" 2>/dev/null | awk '{print tolower($1)}' || true)"
        if [ "$actual" != "$expected" ]; then
            warn "$(L '远端脚本 SHA-256 校验失败，已拒绝替换！预期:') ${expected} $(L '实际:') ${actual}"
            return 1
        fi
    elif [ "${MAINT_SCRIPT_STRICT_SHA:-0}" = "1" ]; then
        warn "$(L '严格校验已开启，但未能获取远端 .sha256 文件，已中止更新')"
        return 1
    fi
    REMOTE_SCRIPT_VERSION="$(grep -m1 '^SCRIPT_VERSION=' "$dst" | cut -d'"' -f2 || true)"
    [ -n "$REMOTE_SCRIPT_VERSION" ]
}

# 自动更新管理脚本（不提问）：远端内容与本地不同、且远端版本号不低于本地时才替换。
# 返回 0 = 已更新；1 = 无需更新或失败
script_self_update_auto() {
    local tmp
    make_workdir || return 1
    tmp="$WORKDIR/manager.sh"
    if ! script_fetch_remote "$tmp"; then
        maint_log "[$(L '脚本')] $(L '未能从') ${SCRIPT_URL} $(L '取得完整脚本，本次跳过')"
        return 1
    fi
    if [ -f "$MANAGER_PATH" ] && cmp -s "$tmp" "$MANAGER_PATH"; then
        echo "[$(L '脚本')] $(L '已是仓库最新（')${SCRIPT_VERSION}$(L '）')"
        return 1
    fi
    if ! version_ge "$REMOTE_SCRIPT_VERSION" "$SCRIPT_VERSION"; then
        maint_log "[$(L '脚本')] $(L '仓库版本') ${REMOTE_SCRIPT_VERSION} $(L '低于本地') ${SCRIPT_VERSION}$(L '，不降级')"
        return 1
    fi
    if [ -f "$MANAGER_PATH" ]; then cp -f "$MANAGER_PATH" "${MANAGER_PATH}.bak"; fi
    install -m 755 "$tmp" "$MANAGER_PATH"
    maint_log "[$(L '脚本')] $(L '已从仓库更新:') ${SCRIPT_VERSION} -> ${REMOTE_SCRIPT_VERSION}$(L '（旧版备份') ${MANAGER_PATH}$(L '.bak）')"
    notify_send "Adam Script Updated" "Updated ${SCRIPT_VERSION} -> ${REMOTE_SCRIPT_VERSION} (SHA-256 verified)." || true
    return 0
}

# 巡检 Nowhere / Xray TLS 证书剩余有效期，小于 14 天发告警通知
maint_check_cert_alerts() {
    local days tag
    if [ -f "$CONFIG_FILE" ] && [ "$(current_role)" = "portal" ]; then
        (
            load_saved_config 2>/dev/null || exit 0
            if [ "${TLS_MODE:-}" = "2" ] && [ -n "${CRT:-}" ] && [ -f "$CRT" ]; then
                days="$(cert_expiry_days "$CRT" 2>/dev/null || echo "")"
                if [[ "$days" =~ ^-?[0-9]+$ ]] && [ "$days" -lt 14 ]; then
                    maint_log "[$(L '证书告警')] Nowhere TLS $(L '证书仅剩') ${days} $(L '天')"
                    notify_send "Certificate Expiry Warning" "Nowhere TLS certificate expires in ${days} days (${CRT})." || true
                fi
            fi
        ) || true
    fi
    if [ -x "$XRAY_BIN" ] && [ "$(xray_node_count)" -gt 0 ]; then
        while IFS= read -r tag; do
            (
                xray_node_load "$tag" || exit 0
                if [ "$N_TYPE" = "xhttp-tls" ] || { [ "$N_TYPE" = "xhttp-cdn" ] && [ "${N_ORIGIN:-tls}" != "plain" ]; }; then
                    if [ -f "${XRAY_CERT_DIR}/${tag}/fullchain.pem" ]; then
                        days="$(cert_expiry_days "${XRAY_CERT_DIR}/${tag}/fullchain.pem" 2>/dev/null || echo "")"
                        if [[ "$days" =~ ^-?[0-9]+$ ]] && [ "$days" -lt 14 ]; then
                            maint_log "[$(L '证书告警')] Xray [${tag}] $(L '证书仅剩') ${days} $(L '天')"
                            notify_send "Certificate Expiry Warning" "Xray [${tag}] certificate expires in ${days} days." || true
                        fi
                    fi
                fi
            ) || true
        done < <(xray_node_tags)
    fi
    return 0
}

# 定时器每日调用：全程不提问
maint_daily() {
    local unit
    maint_load
    maint_lock 300 || return 0
    if [ "$MAINT_SCRIPT_AUTO" = "1" ] && [ "${ADAM_REEXEC:-0}" != "1" ]; then
        if script_self_update_auto; then
            # 换成新脚本继续跑后面的步骤，让新逻辑当天就生效（exec 前显式清理临时目录）
            _cleanup
            exec 9>&- || true
            ADAM_REEXEC=1 exec "$MANAGER_PATH" maintain
        fi
    fi
    if [ -x "$BIN_PATH" ] && [ "${MAINT_NOWHERE_AUTO:-0}" = "1" ]; then
        nowhere_autoupdate || true
    fi
    snell_load_state
    if [ -x "$SNELL_BIN" ] && [ "$SNELL_AUTO_UPDATE" = "1" ]; then
        snell_autoupdate || true
    fi
    xray_load_state
    if [ -x "$XRAY_BIN" ] && [ "$XRAY_AUTO_UPDATE" = "1" ]; then
        xray_autoupdate || true
    fi
    if [ -x "$REALM_BIN" ] && [ "${MAINT_REALM_AUTO:-0}" = "1" ]; then
        realm_autoupdate || true
    fi
    if [ -x "$CADDY_BIN" ] && [ "${MAINT_CADDY_AUTO:-0}" = "1" ]; then
        caddy_autoupdate || true
    fi
    if [ -x "$CF_TUNNEL_BIN" ] && [ "${MAINT_CF_TUNNEL_AUTO:-0}" = "1" ]; then
        cf_tunnel_autoupdate || true
    fi
    if [ -x "$XRAY_BIN" ]; then xray_sync_certs || true; xray_sync_reality_snis || true; fi
    nowhere_sync_cert_copy || true
    maint_check_cert_alerts || true
    reserved_ports_sync || true
    if [ "$MAINT_DAILY_RESTART" = "1" ]; then
        local -a runits=(snell)
        while IFS= read -r unit; do runits+=("snell-port@${unit}"); done < <(snell_extra_ports)
        runits+=(adam-xray nowhere adam-realm)
        for unit in "${runits[@]}"; do
            if systemctl is-active --quiet "$unit" 2>/dev/null; then
                systemctl restart "$unit" >/dev/null 2>&1 || true
                maint_log "[$(L '每日重启')] ${unit} $(L '已重启')"
                # v8.6（BUG-15c）：重启 Nowhere 后留出监听就绪时间再刷 TLS 指纹
                if [ "$unit" = "nowhere" ]; then sleep 3; save_current_pin >>"$MAINT_LOG" 2>&1 || true; fi
            fi
        done
    fi
    return 0
}

maint_timer_state() {
    if systemctl is-active --quiet "$1" 2>/dev/null; then
        printf '%s' "${GREEN}$(L '运行中')${NC}"
    else
        printf '%s' "${YELLOW}$(L '未启用')${NC}"
    fi
}

maint_onoff() { if [ "$1" = "1" ]; then printf '%s' "${GREEN}$(L '开')${NC}"; else printf '%s' "${YELLOW}$(L '关')${NC}"; fi; }

maint_toggle() {   # maint_toggle 变量名
    local name="$1" cur
    maint_load
    cur="${!name}"
    if [ "$cur" = "1" ]; then printf -v "$name" '%s' "0"; else printf -v "$name" '%s' "1"; fi
    maint_save
    maint_install_timers || return 1
    success "$(L '已切换，当前:') $([ "${!name}" = "1" ] && echo 开 || echo 关)"
    return 0
}

maint_toggle_snell() {
    snell_require || return 1
    snell_load_state
    if [ "$SNELL_AUTO_UPDATE" = "1" ]; then snell_disable_autoupdate; else snell_enable_autoupdate; fi
}

maint_toggle_xray() {
    xray_require || return 1
    xray_load_state
    if [ "$XRAY_AUTO_UPDATE" = "1" ]; then XRAY_AUTO_UPDATE="0"; else XRAY_AUTO_UPDATE="1"; fi
    xray_save_state
    if [ "$XRAY_AUTO_UPDATE" = "1" ]; then maint_install_timers || return 1; fi
    success "$(L 'Xray 自动更新:') $([ "$XRAY_AUTO_UPDATE" = "1" ] && echo "开（${XRAY_CHANNEL} 通道）" || echo 关)"
    return 0
}

maint_run_now() {
    info "$(L '立即执行一次每日维护（脚本自更新 / Snell / Xray 更新检查）...')"
    maint_daily
    echo ""
    info "$(L '立即执行一次保活巡检...')"
    exec 9>&- 2>/dev/null || true
    maint_watchdog
    success "$(L '执行完毕')"
    return 0
}

# 辅助：AES-256-CBC PBKDF2 加密/解密（通过 fd:3 传口令，绝不进入命令行参数）
_backup_encrypt_file() {
    local src="$1" dst="$2" pass="$3"
    command -v openssl >/dev/null 2>&1 || return 1
    ( umask 077; openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt -in "$src" -out "$dst" -pass fd:3 3<<<"$pass" 2>/dev/null )
}

_backup_decrypt_file() {
    local src="$1" dst="$2" pass="$3"
    command -v openssl >/dev/null 2>&1 || return 1
    ( umask 077; openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -in "$src" -out "$dst" -pass fd:3 3<<<"$pass" 2>/dev/null )
}

do_backup() {
    local want_enc=0 arg bdir ts dest tmp_tgz pass="" pass2=""
    for arg in "$@"; do
        case "$arg" in --encrypt|-e) want_enc=1 ;; esac
    done
    step "$(L '备份全部配置')"
    divider
    bdir="${ADAM_BACKUP_DIR:-/root}"
    local -a dirs=()
    ts="$(date +%Y%m%d-%H%M%S)"
    local d
    for d in /etc/nowhere /etc/snell /etc/adam-xray /etc/adam-realm /etc/adam-caddy /etc/adam-cloudflared /etc/adam /etc/fail2ban/jail.d/adam-sshd.local /etc/cloudflare/credentials.ini /etc/letsencrypt; do
        [ -e "$d" ] && dirs+=("$d")
    done
    [ "${#dirs[@]}" -gt 0 ] || { warn "$(L '没有找到可备份的配置目录')"; return 1; }
    if [ "$want_enc" = "0" ] && [ -n "${ADAM_BACKUP_PASSPHRASE:-}" ]; then
        want_enc=1
    elif [ "$want_enc" = "0" ] && [ -t 0 ]; then
        if confirm "$(L '使用 AES-256-CBC (PBKDF2) 加密备份文件（推荐用于异地/网盘存放）？')" n; then
            want_enc=1
        fi
    fi
    if [ "$want_enc" = "1" ]; then
        command -v openssl >/dev/null 2>&1 || error "$(L '未找到 openssl，无法加密备份')"
        if [ -n "${ADAM_BACKUP_PASSPHRASE:-}" ]; then
            pass="$ADAM_BACKUP_PASSPHRASE"
        else
            read -rsp "$(L '输入备份加密口令（至少 8 位）:') " pass || return 1; echo ""
            [ "${#pass}" -ge 8 ] || error "$(L '加密口令过短（至少 8 位）')"
            read -rsp "$(L '再次输入加密口令:') " pass2 || return 1; echo ""
            [ "$pass" = "$pass2" ] || error "$(L '两次输入的口令不一致')"
        fi
        make_workdir || return 1
        tmp_tgz="${WORKDIR}/backup.tgz"
        ( umask 077; tar -czf "$tmp_tgz" "${dirs[@]}" 2>/dev/null ) || error "$(L '打包失败')"
        dest="${bdir}/adam-backup-${ts}.tgz.enc"
        _backup_encrypt_file "$tmp_tgz" "$dest" "$pass" || { rm -f "$dest" "$tmp_tgz"; error "$(L '备份加密失败')"; }
        chmod 600 "$dest"
        # 展示明文清单前先读取，再删除明文临时文件
        tar -tzf "$tmp_tgz" 2>/dev/null | awk 'NR<=20' || true
        rm -f "$tmp_tgz"
        { ls -1t "${bdir}"/adam-backup-*.tgz "${bdir}"/adam-backup-*.tgz.enc 2>/dev/null || true; } | tail -n +6 | tr '\n' '\0' | xargs -r -0 rm -f
        success "$(L '加密备份已保存：')${dest}$(L '（AES-256-CBC PBKDF2，只留最近 5 份）')"
        info "$(L '注意：请妥善牢记加密口令，遗忘后无法恢复；定时器单元文件不在备份中，异机恢复后需重装定时器（自动维护菜单 11）')"
        return 0
    fi
    dest="${bdir}/adam-backup-${ts}.tgz"
    # v8.6（BUG-10）：创建即 umask 077，消除 tar 写入与 chmod 600 之间的世界可读窗口
    ( umask 077; tar -czf "$dest" "${dirs[@]}" 2>/dev/null ) || error "$(L '打包失败')"
    chmod 600 "$dest"
    { ls -1t "${bdir}"/adam-backup-*.tgz "${bdir}"/adam-backup-*.tgz.enc 2>/dev/null || true; } | tail -n +6 | tr '\n' '\0' | xargs -r -0 rm -f
    success "$(L '备份已保存：')${dest}$(L '（只留最近 5 份）')"
    warn "$(L '备份含共享密钥与证书私钥，只能放本机，勿外发、勿传网盘')"
    info "$(L '注意：定时器单元文件不在备份中，异机恢复后需重装定时器（自动维护菜单 11）')"
    tar -tzf "$dest" 2>/dev/null | awk 'NR<=20' || true
}

do_restore() {
    local file="${1:-}" work_tgz="" is_enc=0 magic="" pass=""
    step "$(L '恢复配置')"
    divider
    if [ -z "$file" ]; then
        read -rp "$(L '备份文件路径（/root/adam-backup-')*$(L '.tgz 或 .tgz.enc）:') " file || { [ -n "$file" ] || return 1; }
    fi
    [ -f "$file" ] || error "$(L '找不到备份文件：')${file}"
    magic="$(od -An -tx1 -N 8 "$file" 2>/dev/null | tr -d ' \t\r\n' || true)"
    if [[ "$file" == *.enc ]] || [ "$magic" = "53616c7465645f5f" ]; then
        is_enc=1
    fi
    if [ "$is_enc" = "1" ]; then
        command -v openssl >/dev/null 2>&1 || error "$(L '未找到 openssl，无法解密备份')"
        if [ -n "${ADAM_BACKUP_PASSPHRASE:-}" ]; then
            pass="$ADAM_BACKUP_PASSPHRASE"
        else
            read -rsp "$(L '输入备份解密口令:') " pass || return 1; echo ""
        fi
        make_workdir || return 1
        work_tgz="${WORKDIR}/restore.tgz"
        _backup_decrypt_file "$file" "$work_tgz" "$pass" || error "$(L '解密失败（口令错误或文件损坏）')"
        chmod 600 "$work_tgz"
    else
        work_tgz="$file"
    fi
    tar -tzf "$work_tgz" >/dev/null 2>&1 || error "$(L '备份文件损坏或不是有效的 tgz')"
    local bak_role="" cur_role=""
    bak_role="$(tar -xzOf "$work_tgz" etc/nowhere/role 2>/dev/null | tr -d ' \r\n' || true)"
    if [ -z "$bak_role" ]; then bak_role="$(tar -xzOf "$work_tgz" /etc/nowhere/role 2>/dev/null | tr -d ' \r\n' || true)"; fi
    cur_role="$(current_role)"
    if [ -n "$bak_role" ] && [ "$cur_role" != "none" ] && [ "$bak_role" != "$cur_role" ]; then error "$(L '备份内的角色与本机角色不一致，已中止恢复')"; fi
    # v8.6（BUG-10）：拒绝硬链接/设备文件/FIFO；符号链接仅允许 /etc/letsencrypt/live/* 指向 /etc/letsencrypt/archive/*
    local tvline mode link_src link_dst
    while IFS= read -r tvline; do
        [ -n "$tvline" ] || continue
        mode="${tvline:0:1}"
        case "$mode" in
            h|b|c|s|p) error "$(L '备份文件包含不安全的链接或设备节点，已中止'): $tvline" ;;
            l)
                link_src="$(printf '%s' "$tvline" | sed -nE 's/^.* ([^ ]+) -> (.*)$/\1/p')"
                link_dst="$(printf '%s' "$tvline" | sed -nE 's/^.* ([^ ]+) -> (.*)$/\2/p')"
                link_src="${link_src#/}"
                case "$link_src" in
                    etc/letsencrypt/live/*/*)
                        case "$link_dst" in
                            ../../archive/*/*)
                                local _lrel="${link_dst#../../archive/}"
                                case "$_lrel" in *".."*|/*) error "$(L '备份文件包含越界符号链接，已中止'): $tvline" ;; esac ;;
                            *) error "$(L '备份文件包含越界符号链接，已中止'): $tvline" ;;
                        esac ;;
                    *) error "$(L '备份文件包含不允许的符号链接，已中止'): $tvline" ;;
                esac ;;
        esac
    done < <(tar -tvzf "$work_tgz" 2>/dev/null || true)
    # 校验成员路径：只允许恢复到本脚本管理的配置目录，拒绝 ../ 越界成员
    local m
    while IFS= read -r m; do
        case "$m" in
            *".."*) error "$(L '备份文件包含非法路径，已中止'): $m" ;;
            etc/nowhere|etc/nowhere/*|etc/snell|etc/snell/*|etc/adam-realm|etc/adam-realm/*|etc/adam-caddy|etc/adam-caddy/*|etc/adam-cloudflared|etc/adam-cloudflared/*|etc/adam-xray|etc/adam-xray/*|etc/adam|etc/adam/*|etc/fail2ban/jail.d|etc/fail2ban/jail.d/*|etc/cloudflare|etc/cloudflare/*|etc/letsencrypt|etc/letsencrypt/*|/etc/nowhere|/etc/nowhere/*|/etc/snell|/etc/snell/*|/etc/adam-realm|/etc/adam-realm/*|/etc/adam-caddy|/etc/adam-caddy/*|/etc/adam-cloudflared|/etc/adam-cloudflared/*|/etc/adam-xray|/etc/adam-xray/*|/etc/adam|/etc/adam/*|/etc/fail2ban/jail.d|/etc/fail2ban/jail.d/*|/etc/cloudflare|/etc/cloudflare/*|/etc/letsencrypt|/etc/letsencrypt/*) ;;
            *) error "$(L '备份文件包含非法路径，已中止'): $m" ;;
        esac
    done < <(tar -tzf "$work_tgz" 2>/dev/null || true)
    tar -tzf "$work_tgz" 2>/dev/null | awk 'NR<=20' || true
    warn "$(L '恢复会覆盖 /etc/nowhere、/etc/snell、/etc/adam-xray、/etc/adam-realm、/etc/adam-caddy、/etc/adam-cloudflared 等现有配置，并重启已启用的服务')"
    confirm "$(L '确认从') ${file} $(L '恢复？')" n || { info "$(L '已取消')"; return 0; }
    local u
    for u in nowhere snell adam-xray adam-realm adam-caddy adam-cloudflared; do
        systemctl is-active --quiet "$u" 2>/dev/null && systemctl stop "$u" >/dev/null 2>&1 || true
    done
    tar -xzf "$work_tgz" --no-same-owner -C / || error "$(L '解包失败，现有配置可能已不完整，请检查')"
    # v8.6：恢复后统一收敛全部敏感目录/文件权限，防异机 UID/GID 错位
    [ -d "$CONFIG_DIR" ] && nowhere_fix_perms || true
    [ -d "$SNELL_DIR" ] && snell_fix_perms || true
    [ -d "$XRAY_CONF_DIR" ] && xray_fix_perms || true
    [ -d "$REALM_DIR" ] && realm_fix_perms || true
    [ -d "$CADDY_DIR" ] && caddy_fix_perms || true
    [ -d "$CF_TUNNEL_DIR" ] && cf_tunnel_fix_perms || true
    [ -f "$MAINT_ENV" ] && chmod 600 "$MAINT_ENV" 2>/dev/null || true
    [ -f "$NOTIFY_ENV" ] && chmod 600 "$NOTIFY_ENV" 2>/dev/null || true
    [ -f /etc/cloudflare/credentials.ini ] && chmod 600 /etc/cloudflare/credentials.ini 2>/dev/null || true
    systemctl daemon-reload
    for u in nowhere snell adam-xray adam-realm adam-caddy adam-cloudflared; do
        if systemctl is-enabled --quiet "$u" 2>/dev/null; then
            systemctl restart "$u" >/dev/null 2>&1 || warn "${u} $(L '重启失败，请看 journalctl -u') ${u}"
        fi
    done
    snell_sync_extras_after_restore || true
    # 异机恢复：二进制在位但 unit 缺失时自动补齐并拉起
    if realm_installed && [ "$(realm_enabled_count)" -gt 0 ]; then
        [ -f "$REALM_SERVICE" ] || realm_write_service
        realm_reload_service >/dev/null 2>&1 || warn "$(L 'Realm 服务恢复后重载失败，请检查日志')"
    fi
    if caddy_installed && [ "$(caddy_enabled_count)" -gt 0 ]; then
        [ -f "$CADDY_SERVICE" ] || caddy_write_service
        caddy_reload_service >/dev/null 2>&1 || warn "$(L 'Caddy 服务恢复后重载失败，请检查日志')"
    fi
    if cf_tunnel_installed && [ -s "$CF_TUNNEL_ENV" ]; then
        [ -f "$CF_TUNNEL_SERVICE" ] || cf_tunnel_write_service
        systemctl daemon-reload
        systemctl enable --now adam-cloudflared >/dev/null 2>&1 || warn "$(L 'cloudflared 服务恢复后启动失败，请检查日志')"
    fi
    reserved_ports_sync || true
    fw_sync_managed >/dev/null 2>&1 || true
    if f2b_installed; then systemctl restart fail2ban 2>/dev/null || true; fi
    success "$(L '恢复完成（已重启启用的服务）')"
}

# _doctor_check_perm PATH MODE_CLASS [QUIET]（strict=禁组写与全部其他用户；group_ro=禁组写与全部其他用户）
_doctor_check_perm() {
    local p="$1" cls="${2:-strict}" quiet="${3:-}" mode dec bad=0
    [ -e "$p" ] && [ ! -L "$p" ] || return 0
    mode="$(stat -c '%a' "$p" 2>/dev/null || true)"
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 0
    dec=$((8#$mode))
    if [ "$cls" = "strict" ]; then
        # 仅限属主（0600/0700）：组或其他用户有任何位即告警
        if [ $((dec & 077)) -ne 0 ]; then bad=1; fi
    else
        # 属主+只读组（0640/0750）：组写或任何其他用户位即告警
        if [ $((dec & 027)) -ne 0 ]; then bad=1; fi
    fi
    if [ "$bad" = "1" ]; then
        if [ "$quiet" != "quiet" ]; then
            warn "$(L '敏感文件权限过宽:') ${p} (${mode}) — $(L '建议执行 adam repair 收敛权限')"
        fi
        return 1
    fi
    return 0
}

_svc_state_plain() {
    local u="$1" inst="${2:-0}"
    if systemctl is-active --quiet "$u" 2>/dev/null; then printf 'active';
    elif [ -f "/etc/systemd/system/${u}.service" ]; then printf 'inactive';
    elif [ "$inst" = "1" ]; then printf 'unconfigured';
    else printf 'not-installed'; fi
}

_doctor_json() {
    local host ntp_rc=0 ntp_st="unknown" disk_mb fw_st="not-installed" _pf
    local -a perm_list=()
    host="$(hostname -s 2>/dev/null || echo 'unknown')"
    check_ntp_sync || ntp_rc=$?
    case "$ntp_rc" in 0) ntp_st="synced" ;; 1) ntp_st="unsynced" ;; *) ntp_st="unknown" ;; esac
    disk_mb="$(df -Pm / 2>/dev/null | awk 'NR==2 {print $4}' || echo 0)"
    [[ "$disk_mb" =~ ^[0-9]+$ ]] || disk_mb=0
    if command -v ufw >/dev/null 2>&1; then
        fw_st="$(LC_ALL=C ufw status 2>/dev/null | awk 'NR==1 {print $2}' || true)"
        [ -n "$fw_st" ] || fw_st="unknown"
    fi
    for _pf in "$CONFIG_FILE" "$EGRESS_CONFIG_FILE" "$TLS_PIN_FILE" "$SNELL_STATE_FILE" "$XRAY_NODE_DIR" "$XRAY_FWD_DIR" "$XRAY_STATE_FILE" "$CADDY_DATA_DIR" "$CF_TUNNEL_DIR" "$CF_TUNNEL_ENV" "$MAINT_ENV" "$NOTIFY_ENV" /etc/cloudflare/credentials.ini; do
        _doctor_check_perm "$_pf" strict quiet || perm_list+=("$_pf")
    done
    for _pf in "$CONFIG_DIR" "$SNELL_DIR" "$SNELL_CONF" "$SNELL_PORTS_DIR" "$XRAY_CONF_DIR" "$XRAY_CONF_D" "$XRAY_CERT_DIR" "$REALM_DIR" "$REALM_CONF_D" "$CADDY_DIR" "$CADDY_SITES_DIR"; do
        _doctor_check_perm "$_pf" group_ro quiet || perm_list+=("$_pf")
    done
    for _pf in "$SNELL_PORTS_DIR"/*.conf "$XRAY_NODE_DIR"/*.env "$XRAY_FWD_DIR"/*.env "$REALM_RULE_DIR"/*.env "$CADDY_SITES_DIR"/*.env; do
        [ -e "$_pf" ] || continue
        case "$_pf" in
            *.conf) _doctor_check_perm "$_pf" group_ro quiet || perm_list+=("$_pf") ;;
            *)      _doctor_check_perm "$_pf" strict   quiet || perm_list+=("$_pf") ;;
        esac
    done
    local perm_json="" p_item
    for p_item in "${perm_list[@]}"; do
        perm_json="${perm_json:+${perm_json}, }\"$(_json_escape "$p_item")\""
    done
    local wd_st="inactive" mt_st="inactive"
    systemctl is-active --quiet adam-watchdog.timer 2>/dev/null && wd_st="active"
    systemctl is-active --quiet adam-maintain.timer 2>/dev/null && mt_st="active"
    local nw_i=0 sn_i=0 xr_i=0 rm_i=0 cd_i=0 cf_i=0
    [ -x "$BIN_PATH" ] && nw_i=1
    [ -x "$SNELL_BIN" ] && sn_i=1
    [ -x "$XRAY_BIN" ] && xr_i=1
    realm_installed && rm_i=1
    caddy_installed && cd_i=1
    cf_tunnel_installed && cf_i=1
    cat << JEOF
{
  "script_version": "$(_json_escape "$SCRIPT_VERSION")",
  "target_nw_version": "$(_json_escape "$TARGET_NW_VERSION")",
  "hostname": "$(_json_escape "$host")",
  "lang": "$(_json_escape "$ADAM_LANG")",
  "ntp_sync": "${ntp_st}",
  "disk_avail_mb": ${disk_mb},
  "firewall": "$(_json_escape "$fw_st")",
  "timers": {
    "watchdog": "${wd_st}",
    "maintain": "${mt_st}"
  },
  "services": {
    "nowhere": { "installed": $([ "$nw_i" = "1" ] && echo true || echo false), "role": "$(_json_escape "$(current_role)")", "state": "$(_svc_state_plain nowhere "$nw_i")" },
    "snell": { "installed": $([ "$sn_i" = "1" ] && echo true || echo false), "state": "$(_svc_state_plain snell "$sn_i")" },
    "xray": { "installed": $([ "$xr_i" = "1" ] && echo true || echo false), "nodes": $(xray_node_count), "state": "$(_svc_state_plain adam-xray "$xr_i")" },
    "realm": { "installed": $([ "$rm_i" = "1" ] && echo true || echo false), "state": "$(_svc_state_plain adam-realm "$rm_i")" },
    "caddy": { "installed": $([ "$cd_i" = "1" ] && echo true || echo false), "state": "$(_svc_state_plain adam-caddy "$cd_i")" },
    "cloudflared": { "installed": $([ "$cf_i" = "1" ] && echo true || echo false), "state": "$(_svc_state_plain adam-cloudflared "$cf_i")" }
  },
  "perm_issue_count": ${#perm_list[@]},
  "perm_issues": [${perm_json}]
}
JEOF
}

_doctor_ss_managed() {
    local proto="$1" flag out mports p lines=""
    case "$proto" in tcp) flag="-tlnp" ;; udp) flag="-ulnp" ;; *) return 1 ;; esac
    out="$(ss "$flag" 2>/dev/null | grep -E 'nowhere|snell|xray|realm|caddy' || true)"
    if [ -n "$out" ]; then
        printf '%s\n' "$out"
        return 0
    fi
    # 容器或 hidepid=2 环境下 ss -p 不显示进程名，回退按已配置托管端口精确匹配
    mports="$(managed_ports 2>/dev/null | awk -F/ -v pr="$proto" '$2 == pr && $1 ~ /^[0-9]+$/ {print $1}' | sort -un || true)"
    if [ -n "$mports" ]; then
        while IFS= read -r p; do
            [ -n "$p" ] || continue
            out="$(ss_port_lines "$proto" "$p" || true)"
            [ -n "$out" ] && lines="${lines:+${lines}$'\n'}${out}"
        done <<< "$mports"
        if [ -n "$lines" ]; then
            printf '%s\n' "$lines" | awk '!seen[$0]++'
            return 0
        fi
    fi
    return 1
}

do_doctor() {
    if [ "${1:-}" = "--json" ] || [ "${1:-}" = "-j" ]; then
        _doctor_json
        return 0
    fi
    step "$(L '一键诊断（只读，不改任何配置）')"
    divider
    echo "  $(L '管理脚本 :') ${SCRIPT_VERSION}$(L '（适配 Nowhere') ${TARGET_NW_VERSION}$(L '） 语言：')${ADAM_LANG}"
    local nw_v xr_v
    if [ -x "$BIN_PATH" ]; then
        nw_v="$(read_installed_version)"
        [ -n "$nw_v" ] || nw_v="$("$BIN_PATH" --version 2>&1 | awk 'NR==1 {print $1}' || true)"
    else
        nw_v="$(L '未安装')"
    fi
    if [ -x "$XRAY_BIN" ]; then
        xr_v="$(xray_installed_version)"
        [ -n "$xr_v" ] || xr_v="$("$XRAY_BIN" version 2>&1 | awk 'NR==1 {print $2}' || true)"
    else
        xr_v="$(L '未安装')"
    fi
    echo "  Nowhere  : ${nw_v} $(L '· 角色') $(current_role) · $(svc_state nowhere)"
    echo "  Snell    : $([ -x "$SNELL_BIN" ] && { snell_installed_version; } || echo "$(L '未安装')") · $(svc_state snell)"
    echo "  Xray     : ${xr_v} · $(svc_state adam-xray)"
    echo "  Realm    : $(realm_state_text)"
    echo "  $(L '域名反代') : $(proxy_state_text)"
    if [ -x /usr/local/bin/adam ] && [ -x "$MANAGER_PATH" ]; then info "$(L '快捷命令 adam：正常（指向') ${MANAGER_PATH}$(L '）')"; else warn "$(L '快捷命令 adam 不可用：请执行') ${MANAGER_PATH} shortcuts $(L '或重新运行安装脚本')"; fi
    echo "  $(L '保活巡检 :') $(maint_timer_state adam-watchdog.timer)    $(L '每日维护 :') $(maint_timer_state adam-maintain.timer)"
    local _ntp_rc=0
    check_ntp_sync || _ntp_rc=$?
    case "$_ntp_rc" in
        0) echo -e "  $(L '时钟同步 :') ${GREEN}NTP $(L '已同步')${NC}" ;;
        1) warn "$(L '系统时钟未 NTP 同步！Xray REALITY maxTimeDiff 仅容忍 ±60s，建议开启 timedatectl set-ntp true')" ;;
        *) echo "  $(L '时钟同步 :') $(L '未知（容器/精简环境）')" ;;
    esac
    echo ""
    info "$(L '监听端口（ss）：')"
    if command -v ss >/dev/null 2>&1; then
        _doctor_ss_managed tcp || echo "  $(L '（无 Nowhere/Snell/Xray/Realm/Caddy 的 TCP 监听）')"
        _doctor_ss_managed udp || echo "  $(L '（无 Nowhere/Snell/Xray/Realm/Caddy 的 UDP 监听）')"
    else
        warn "$(L 'ss 工具缺失，无法列出监听端口（请安装 iproute2）')"
    fi
    echo ""
    if [ -f "$CONFIG_FILE" ] && [ "$(current_role)" = "portal" ]; then
        load_saved_config 2>/dev/null || true
        if [ "${TLS_MODE:-}" = "2" ] && [ -n "${CRT:-}" ]; then
            local days
            days="$(cert_expiry_days "$CRT" 2>/dev/null || echo "")"
            if [ -n "$days" ]; then
                [ "$days" -lt 0 ] && warn "$(L '证书已过期') $((-days)) $(L '天')" || info "$(L '证书剩余约') ${days} $(L '天')"
            else
                warn "$(L '证书文件无法读取：')${CRT}"
            fi
        elif [ "${TLS_MODE:-}" = "1" ]; then
            if [ -f "$TLS_PIN_FILE" ]; then info "$(L 'tls=1 当前指纹见') ${TLS_PIN_FILE}"; else warn "$(L 'tls=1 且无指纹记录文件，请用 Nowhere 菜单 10 生成')"; fi
        fi
    fi
    if [ -x "$XRAY_BIN" ] && [ "$(xray_node_count)" -gt 0 ]; then
        local _dtag _ddays
        while IFS= read -r _dtag; do
            xray_node_load "$_dtag" || continue
            if [ "$N_TYPE" = "xhttp-tls" ] || { [ "$N_TYPE" = "xhttp-cdn" ] && [ "${N_ORIGIN:-tls}" != "plain" ]; }; then
                if [ -f "${XRAY_CERT_DIR}/${_dtag}/fullchain.pem" ]; then
                    _ddays="$(cert_expiry_days "${XRAY_CERT_DIR}/${_dtag}/fullchain.pem" 2>/dev/null || echo "")"
                    if [[ "$_ddays" =~ ^-?[0-9]+$ ]]; then
                        echo "  Xray [${_dtag}] $(L '证书剩余') ${_ddays} $(L '天')"
                    fi
                else
                    warn "$(L '证书文件无法读取：')${XRAY_CERT_DIR}/${_dtag}/fullchain.pem"
                fi
            fi
        done < <(xray_node_tags)
    fi
    # v8.6：敏感配置文件/密钥/证书目录权限巡检
    local _perm_bad=0 _pf
    for _pf in "$CONFIG_FILE" "$EGRESS_CONFIG_FILE" "$TLS_PIN_FILE" "$SNELL_STATE_FILE" "$XRAY_NODE_DIR" "$XRAY_FWD_DIR" "$XRAY_STATE_FILE" "$CADDY_DATA_DIR" "$CF_TUNNEL_DIR" "$CF_TUNNEL_ENV" "$MAINT_ENV" "$NOTIFY_ENV" /etc/cloudflare/credentials.ini; do
        _doctor_check_perm "$_pf" strict || _perm_bad=$((_perm_bad + 1))
    done
    for _pf in "$CONFIG_DIR" "$SNELL_DIR" "$SNELL_CONF" "$SNELL_PORTS_DIR" "$XRAY_CONF_DIR" "$XRAY_CONF_D" "$XRAY_CERT_DIR" "$REALM_DIR" "$REALM_CONF_D" "$CADDY_DIR" "$CADDY_SITES_DIR"; do
        _doctor_check_perm "$_pf" group_ro || _perm_bad=$((_perm_bad + 1))
    done
    for _pf in "$SNELL_PORTS_DIR"/*.conf "$XRAY_NODE_DIR"/*.env "$XRAY_FWD_DIR"/*.env "$REALM_RULE_DIR"/*.env "$CADDY_SITES_DIR"/*.env; do
        [ -e "$_pf" ] || continue
        case "$_pf" in
            *.conf) _doctor_check_perm "$_pf" group_ro || _perm_bad=$((_perm_bad + 1)) ;;
            *)      _doctor_check_perm "$_pf" strict   || _perm_bad=$((_perm_bad + 1)) ;;
        esac
    done
    if [ "$_perm_bad" -eq 0 ]; then
        info "$(L '敏感文件权限巡检：正常')"
    fi
    # Fail2ban SSH 端口漂移检查
    if f2b_installed && [ -f "$F2B_JAIL_FILE" ]; then
        local _f2b_p _ssh_p _drift=0
        _f2b_p=",$(f2b_get port ""),"
        for _ssh_p in $(detect_ssh_ports); do
            case "$_f2b_p" in *",${_ssh_p},"*) ;; *) _drift=1 ;; esac
        done
        if [ "$_drift" = "1" ]; then
            warn "$(L 'Fail2ban 监控的 SSH 端口（')$(f2b_get port "")$(L '）与当前 SSH 端口（')$(detect_ssh_ports)$(L '）不一致，建议在 Fail2ban 菜单重新应用')"
        fi
    fi
    if command -v ufw >/dev/null 2>&1; then
        local _ufw_line
        _ufw_line="$(ufw status 2>/dev/null | awk 'NR==1' || true)"
        echo "  $(L '防火墙'): ${_ufw_line:-$(L '不可用（容器/内核受限）')}"
    else
        echo "  $(L '防火墙'): $(L '未安装')"
    fi
    echo ""
    info "$(L '磁盘：')$(df -h / 2>/dev/null | tail -1)"
    info "$(L '最近错误日志（nowhere，5 行）：')"
    journalctl -u nowhere -p err -n 5 --no-pager -o cat 2>/dev/null || echo "  $(L '（无）')"
}

# v8.6：全局一键修复（修复全部已安装组件 + 防火墙同步 + 保留端口 + 维护定时器）
do_repair_all() {
    local ok=0 fail=0 total=0
    step "$(L '全局一键修复（全部已安装组件）')"
    divider
    if [ -x "$BIN_PATH" ] || [ -f "$SERVICE_FILE" ]; then
        total=$((total + 1))
        info ">>> Nowhere"
        if _nowhere_repair_core; then
            success "Nowhere: $(L '已修复并运行正常')"
            ok=$((ok + 1))
        else
            warn "Nowhere: $(L '修复后仍异常，请查看 journalctl -u nowhere -n 30 --no-pager')"
            fail=$((fail + 1))
        fi
    fi
    if [ -x "$SNELL_BIN" ] || [ -f "$SNELL_SERVICE" ]; then
        total=$((total + 1))
        info ">>> Snell"
        if _snell_repair_core; then
            success "Snell: $(L '已修复并运行正常')"
            ok=$((ok + 1))
        else
            warn "Snell: $(L '修复后仍异常，请查看 journalctl -u snell -n 30 --no-pager')"
            fail=$((fail + 1))
        fi
    fi
    if [ -x "$XRAY_BIN" ] || [ -f "$XRAY_SERVICE" ]; then
        total=$((total + 1))
        info ">>> Xray"
        if _xray_repair_core; then
            success "Xray: $(L '已修复并运行正常')"
            ok=$((ok + 1))
        else
            warn "Xray: $(L '修复后仍异常，请查看 journalctl -u adam-xray -n 30 --no-pager')"
            fail=$((fail + 1))
        fi
    fi
    if realm_installed || [ -f "$REALM_SERVICE" ]; then
        total=$((total + 1))
        info ">>> Realm"
        if _realm_repair_core; then
            success "Realm: $(L '已修复并运行正常')"
            ok=$((ok + 1))
        else
            warn "Realm: $(L '修复后仍异常，请查看 journalctl -u adam-realm -n 30 --no-pager')"
            fail=$((fail + 1))
        fi
    fi
    if caddy_installed || [ -f "$CADDY_SERVICE" ]; then
        total=$((total + 1))
        info ">>> Caddy"
        if _caddy_repair_core; then
            success "Caddy: $(L '已修复并运行正常')"
            ok=$((ok + 1))
        else
            warn "Caddy: $(L '修复后仍异常，请查看 journalctl -u adam-caddy -n 30 --no-pager')"
            fail=$((fail + 1))
        fi
    fi
    if cf_tunnel_installed || [ -f "$CF_TUNNEL_SERVICE" ]; then
        total=$((total + 1))
        info ">>> Cloudflare Tunnel"
        if _cf_tunnel_repair_core; then
            success "Cloudflare Tunnel: $(L '已修复并运行正常')"
            ok=$((ok + 1))
        else
            warn "Cloudflare Tunnel: $(L '修复后仍异常，请查看 journalctl -u adam-cloudflared -n 30 --no-pager')"
            fail=$((fail + 1))
        fi
    fi
    [ -f "$MAINT_ENV" ] && [ ! -L "$MAINT_ENV" ] && chmod 600 "$MAINT_ENV" 2>/dev/null || true
    [ -f "$NOTIFY_ENV" ] && [ ! -L "$NOTIFY_ENV" ] && chmod 600 "$NOTIFY_ENV" 2>/dev/null || true
    [ -f /etc/cloudflare/credentials.ini ] && [ ! -L /etc/cloudflare/credentials.ini ] && chmod 600 /etc/cloudflare/credentials.ini 2>/dev/null || true
    reserved_ports_sync || true
    if ufw_active; then fw_sync_managed >/dev/null 2>&1 || true; fi
    maint_install_timers || true
    divider
    if [ "$total" -eq 0 ]; then
        info "$(L '未检测到已安装的服务组件，已刷新内核保留端口与维护定时器')"
        return 0
    fi
    if [ "$fail" -eq 0 ]; then
        success "$(L '全局修复完成：全部') ${ok}/${total} $(L '个组件正常')"
        return 0
    fi
    warn "$(L '全局修复完成：')${ok}/${total} $(L '正常，')${fail} $(L '个仍异常')"
    return 1
}

do_log_cleanup() {
    step "$(L '清理日志')"
    divider
    journalctl --disk-usage 2>/dev/null || true
    confirm "$(L '清理 journal 日志，只保留最近 200M？')" n || { info "$(L '已取消')"; return 0; }
    journalctl --vacuum-size=200M || warn "$(L '清理失败')"
    journalctl --disk-usage 2>/dev/null || true
    success "$(L '日志清理完成')"
}

maint_show_log() {
    info "$(L '最近的维护事件（')${MAINT_LOG}$(L '）：')"
    if [ -s "$MAINT_LOG" ]; then tail -n 30 "$MAINT_LOG"; else echo "  $(L '（暂无记录）')"; fi
    echo ""
    info "$(L '最近一次每日任务输出：')"
    journalctl -u adam-maintain --no-pager -n 20 -o cat 2>/dev/null || true
    return 0
}

# 告警通知设置菜单（Telegram / Bark / Webhook）
notify_menu() {
    local ch tok cid url
    notify_load
    step "$(L '运维告警通知设置（Telegram / Bark / Webhook）')"
    divider
    echo -e "  $(L '当前状态:') $(maint_onoff "$NOTIFY_ENABLED")    $(L '通道:') ${NOTIFY_TYPE:-$(L '未配置')}"
    divider
    echo "  1) $(L '配置 Telegram Bot 通知')"
    echo "  2) $(L '配置 Bark 推送（HTTPS）')"
    echo "  3) $(L '配置通用 HTTPS Webhook')"
    echo "  4) $(L '发送测试通知')"
    echo "  5) $(L '开启 / 关闭告警推送')"
    echo "  0) $(L '返回')"
    read -rp "$(L '请选择') [0-5]: " ch || return 0
    case "$ch" in
        1)
            read -rp "$(L '输入 Telegram Bot Token（格式 123456:ABC...）:') " tok || return 0
            tok="$(printf '%s' "$tok" | tr -d ' \r\n')"
            [[ "$tok" =~ ^[0-9]+:[A-Za-z0-9_-]+$ ]] || { warn "$(L 'Bot Token 格式无效')"; return 1; }
            read -rp "$(L '输入 Chat ID（数字，群组可带负号）:') " cid || return 0
            cid="$(printf '%s' "$cid" | tr -d ' \r\n')"
            [[ "$cid" =~ ^-?[0-9]+$ ]] || { warn "$(L 'Chat ID 格式无效')"; return 1; }
            NOTIFY_TYPE="telegram"; NOTIFY_TG_TOKEN="$tok"; NOTIFY_TG_CHAT_ID="$cid"; NOTIFY_ENABLED="1"
            notify_save && success "$(L 'Telegram 通知已保存（0600 权限）')"
            ;;
        2)
            read -rp "$(L '输入 Bark 推送地址（须以 https:// 开头）:') " url || return 0
            url="$(printf '%s' "$url" | tr -d ' \r\n')"
            [[ "$url" == https://* ]] || { warn "$(L '地址必须以 https:// 开头')"; return 1; }
            NOTIFY_TYPE="bark"; NOTIFY_BARK_URL="$url"; NOTIFY_ENABLED="1"
            notify_save && success "$(L 'Bark 通知已保存（0600 权限）')"
            ;;
        3)
            read -rp "$(L '输入 Webhook 地址（须以 https:// 开头）:') " url || return 0
            url="$(printf '%s' "$url" | tr -d ' \r\n')"
            [[ "$url" == https://* ]] || { warn "$(L '地址必须以 https:// 开头')"; return 1; }
            NOTIFY_TYPE="webhook"; NOTIFY_WEBHOOK_URL="$url"; NOTIFY_ENABLED="1"
            notify_save && success "$(L 'Webhook 通知已保存（0600 权限）')"
            ;;
        4)
            if notify_send "Adam Test Alert" "Notification channel (${NOTIFY_TYPE:-unset}) is working." force; then
                success "$(L '测试通知发送成功')"
            else
                warn "$(L '测试通知发送失败，请检查配置与网络')"
                return 1
            fi
            ;;
        5)
            if [ "$NOTIFY_ENABLED" = "1" ]; then NOTIFY_ENABLED="0"; else NOTIFY_ENABLED="1"; fi
            notify_save && success "$(L '告警推送已切换为:') $([ "$NOTIFY_ENABLED" = "1" ] && echo "$(L '开')" || echo "$(L '关')")"
            ;;
        0|"") return 0 ;;
        *) warn "$(L '无效选择')" ;;
    esac
    return 0
}

# 配置只读 GITHUB_TOKEN（提升 api.github.com 限额从 60/h 到 5000/h，绝不向第三方域名发送）
maint_set_github_token() {
    local tok=""
    maint_load
    step "$(L '配置只读 GitHub Token（可选）')"
    divider
    info "$(L '仅对 https://api.github.com/ 注入 Bearer Token，避免共享 VPS 出口 IP 触发 60 次/小时匿名限流；留空输入 clear 可清除')"
    if [ -n "${GITHUB_TOKEN:-}" ]; then
        echo "  $(L '当前状态:') $(L '已配置（长度') ${#GITHUB_TOKEN}$(L '）')"
    else
        echo "  $(L '当前状态:') $(L '未配置')"
    fi
    read -rsp "$(L '输入只读 GitHub Token（或输入 clear 清除，直接回车取消）:') " tok || return 0
    echo ""
    tok="$(printf '%s' "$tok" | tr -d ' \r\n')"
    if [ -z "$tok" ]; then info "$(L '未修改')"; return 0; fi
    if [ "$tok" = "clear" ]; then
        GITHUB_TOKEN=""
        maint_save && success "$(L '已清除 GitHub Token')"
        return 0
    fi
    if [[ ! "$tok" =~ ^[A-Za-z0-9_.-]{10,256}$ ]]; then
        warn "$(L 'Token 格式无效（仅允许字母/数字/_.-，长度 10-256）')"
        return 1
    fi
    GITHUB_TOKEN="$tok"
    maint_save && success "$(L 'GitHub Token 已保存（0600 权限，仅对 api.github.com 生效）')"
    return 0
}

# 多客户端配置导出：adam export [mihomo|singbox|surge]
do_export_clients() {
    local fmt="${1:-}" host tag port psk mfp first=1
    if [ -z "$fmt" ]; then
        step "$(L '导出多客户端配置片段')"
        divider
        echo "  1) Mihomo / Clash Meta (YAML proxies)"
        echo "  2) sing-box (JSON outbounds)"
        echo "  3) Surge ([Proxy] lines)"
        echo "  0) $(L '取消')"
        read -rp "$(L '选择导出格式') [0-3]: " fmt || return 0
        case "$fmt" in
            1) fmt="mihomo" ;;
            2) fmt="singbox" ;;
            3) fmt="surge" ;;
            0|"") return 0 ;;
            *) warn "$(L '无效选择')"; return 1 ;;
        esac
    fi
    xray_load_state 2>/dev/null || true
    host="${XRAY_PUBLIC_HOST:-$(detect_public_host 2>/dev/null || true)}"
    [ -n "$host" ] || host="YOUR_SERVER_IP"
    case "$fmt" in
        mihomo|clash)
            printf '# Generated by Adam Manager v%s (Mihomo / Clash Meta)\n' "$SCRIPT_VERSION"
            printf 'proxies:\n'
            if [ -x "$XRAY_BIN" ] || [ -d "$XRAY_NODE_DIR" ]; then
                while IFS= read -r tag; do
                    [ -n "$tag" ] || continue
                    (
                        xray_node_load "$tag" || exit 0
                        mfp="${N_FP:-chrome}"
                        case "$N_TYPE" in
                            vision)
                                if [ "$mfp" = "randomized" ] || [ "$mfp" = "edge" ] || [ "$mfp" = "ios" ]; then
                                    printf '  # Note: normalized client-fingerprint from %s -> chrome for Mihomo REALITY compatibility\n' "$mfp"
                                    mfp="chrome"
                                fi
                                printf '  - name: "%s"\n    type: vless\n    server: "%s"\n    port: %s\n    uuid: "%s"\n    network: tcp\n    tls: true\n    udp: true\n    flow: xtls-rprx-vision\n    servername: "%s"\n    client-fingerprint: %s\n    reality-opts:\n      public-key: "%s"\n      short-id: "%s"\n' \
                                    "$(_json_escape "${N_NAME:-$tag}")" "$(_json_escape "$host")" "$N_PORT" "$(_json_escape "$N_UUID")" "$(_json_escape "$N_SNI")" "$mfp" "$(_json_escape "$N_PBK")" "$(_json_escape "$N_SID")"
                                if [ -n "${N_PQV:-}" ]; then printf '      # ML-DSA-65 pqv: %s\n' "$N_PQV"; fi
                                ;;
                            xhttp-reality)
                                if [ "$mfp" = "randomized" ] || [ "$mfp" = "edge" ] || [ "$mfp" = "ios" ]; then
                                    printf '  # Note: normalized client-fingerprint from %s -> chrome for Mihomo REALITY compatibility\n' "$mfp"
                                    mfp="chrome"
                                fi
                                printf '  - name: "%s"\n    type: vless\n    server: "%s"\n    port: %s\n    uuid: "%s"\n    network: xhttp\n    tls: true\n    udp: true\n    servername: "%s"\n    client-fingerprint: %s\n    reality-opts:\n      public-key: "%s"\n      short-id: "%s"\n    xhttp-opts:\n      path: "%s"\n      mode: auto\n' \
                                    "$(_json_escape "${N_NAME:-$tag}")" "$(_json_escape "$host")" "$N_PORT" "$(_json_escape "$N_UUID")" "$(_json_escape "$N_SNI")" "$mfp" "$(_json_escape "$N_PBK")" "$(_json_escape "$N_SID")" "$(_json_escape "$N_PATH")"
                                if [ -n "${N_XPAD:-}" ]; then printf '      # xPaddingBytes: %s\n' "$N_XPAD"; fi
                                if [ -n "${N_PQV:-}" ]; then printf '    # ML-DSA-65 pqv: %s\n' "$N_PQV"; fi
                                ;;
                            xhttp-tls|xhttp-cdn)
                                local srv="$host" prt="$N_PORT" mode="auto"
                                if [ "$N_TYPE" = "xhttp-cdn" ]; then srv="$N_DOMAIN"; prt="$N_CPORT"; mode="packet-up"; fi
                                printf '  - name: "%s"\n    type: vless\n    server: "%s"\n    port: %s\n    uuid: "%s"\n    network: xhttp\n    tls: true\n    udp: true\n    servername: "%s"\n    client-fingerprint: %s\n    xhttp-opts:\n      host: "%s"\n      path: "%s"\n      mode: %s\n' \
                                    "$(_json_escape "${N_NAME:-$tag}")" "$(_json_escape "$srv")" "$prt" "$(_json_escape "$N_UUID")" "$(_json_escape "$N_DOMAIN")" "$mfp" "$(_json_escape "$N_DOMAIN")" "$(_json_escape "$N_PATH")" "$mode"
                                if [ -n "${N_XPAD:-}" ]; then printf '      # xPaddingBytes: %s\n' "$N_XPAD"; fi
                                ;;
                            ss2022)
                                printf '  - name: "%s"\n    type: ss\n    server: "%s"\n    port: %s\n    cipher: "%s"\n    password: "%s"\n    udp: true\n' \
                                    "$(_json_escape "${N_NAME:-$tag}")" "$(_json_escape "$host")" "$N_PORT" "$(_json_escape "$N_METHOD")" "$(_json_escape "$N_PASS")"
                                ;;
                        esac
                        exit 0
                    )
                done < <(xray_node_tags)
            fi
            if [ -f "$SNELL_CONF" ]; then
                snell_load_state 2>/dev/null || true
                local shost="${SNELL_PUBLIC_HOST:-$host}"
                port="$(snell_port 2>/dev/null || true)"
                psk="$(snell_conf_get psk "$SNELL_CONF" 2>/dev/null || true)"
                if [ -n "$port" ] && [ -n "$psk" ]; then
                    printf '  - name: "Snell-%s"\n    type: snell\n    server: "%s"\n    port: %s\n    psk: "%s"\n    version: %s\n' \
                        "$port" "$(_json_escape "$shost")" "$port" "$(_json_escape "$psk")" "$SNELL_MAJOR"
                fi
                while IFS= read -r port; do
                    [ -n "$port" ] || continue
                    psk="$(snell_conf_get psk "${SNELL_PORTS_DIR}/${port}.conf" 2>/dev/null || true)"
                    if [ -n "$psk" ]; then
                        printf '  - name: "Snell-%s"\n    type: snell\n    server: "%s"\n    port: %s\n    psk: "%s"\n    version: %s\n' \
                            "$port" "$(_json_escape "$shost")" "$port" "$(_json_escape "$psk")" "$SNELL_MAJOR"
                    fi
                done < <(snell_extra_ports)
            fi
            if [ -f "$CONFIG_FILE" ] && [ "$(current_role)" = "portal" ]; then
                printf '# Nowhere Portal detected: use `adam config` for Anywhere/Vector NW3 import links.\n'
            fi
            ;;
        singbox|sing-box)
            printf '{\n  "outbounds": [\n'
            if [ -x "$XRAY_BIN" ] || [ -d "$XRAY_NODE_DIR" ]; then
                while IFS= read -r tag; do
                    [ -n "$tag" ] || continue
                    local frag=""
                    frag="$(
                        xray_node_load "$tag" || exit 0
                        case "$N_TYPE" in
                            vision)
                                printf '    {"type":"vless","tag":"%s","server":"%s","server_port":%s,"uuid":"%s","flow":"xtls-rprx-vision","tls":{"enabled":true,"server_name":"%s","utls":{"enabled":true,"fingerprint":"%s"},"reality":{"enabled":true,"public_key":"%s","short_id":"%s"}}}' \
                                    "$(_json_escape "${N_NAME:-$tag}")" "$(_json_escape "$host")" "$N_PORT" "$N_UUID" "$(_json_escape "$N_SNI")" "${N_FP:-chrome}" "$N_PBK" "$N_SID"
                                ;;
                            ss2022)
                                printf '    {"type":"shadowsocks","tag":"%s","server":"%s","server_port":%s,"method":"%s","password":"%s"}' \
                                    "$(_json_escape "${N_NAME:-$tag}")" "$(_json_escape "$host")" "$N_PORT" "$N_METHOD" "$(_json_escape "$N_PASS")"
                                ;;
                        esac
                    )"
                    if [ -n "$frag" ]; then
                        if [ "$first" = "1" ]; then first=0; else printf ',\n'; fi
                        printf '%s' "$frag"
                    fi
                done < <(xray_node_tags)
            fi
            printf '\n  ]\n}\n'
            ;;
        surge)
            printf '# Generated by Adam Manager v%s (Surge [Proxy])\n[Proxy]\n' "$SCRIPT_VERSION"
            if [ -f "$SNELL_CONF" ]; then
                local _sline=""
                port="$(snell_port 2>/dev/null || true)"
                if [ -n "$port" ] && _sline="$(snell_client_line "$port" 2>/dev/null)" && [ -n "$_sline" ]; then
                    printf '%s\n' "$_sline"
                fi
                while IFS= read -r port; do
                    [ -n "$port" ] || continue
                    if _sline="$(snell_client_line "$port" 2>/dev/null)" && [ -n "$_sline" ]; then
                        printf '%s\n' "$_sline"
                    fi
                done < <(snell_extra_ports)
            fi
            if [ -x "$XRAY_BIN" ] || [ -d "$XRAY_NODE_DIR" ]; then
                while IFS= read -r tag; do
                    [ -n "$tag" ] || continue
                    (
                        xray_node_load "$tag" || exit 0
                        if [ "$N_TYPE" = "ss2022" ]; then
                            printf '%s = ss, %s, %s, encrypt-method=%s, password=%s, udp-relay=true\n' \
                                "${N_NAME:-$tag}" "$host" "$N_PORT" "$N_METHOD" "$N_PASS"
                        fi
                        exit 0
                    )
                done < <(xray_node_tags)
            fi
            ;;
        *)
            warn "$(L '不支持的导出格式（可用: mihomo / singbox / surge）:') ${fmt}"
            return 1
            ;;
    esac
    return 0
}

maint_menu() {
    local choice
    while true; do
        clear 2>/dev/null || true
        maint_load; snell_load_state; xray_load_state; notify_load
        echo -e "${BOLD}${CYAN}━━━ $(L '自动维护')$(L '（保活 / 自动更新）') ━━━${NC}"
        echo -e "  $(L '保活巡检定时器'): $(maint_timer_state adam-watchdog.timer)    $(L '每日维护定时器'): $(maint_timer_state adam-maintain.timer)"
        divider
        echo -e "  ${GREEN}1)${NC} $(L '保活巡检（每 5 分钟；服务异常先重启，失败自动二段修复）')  [$(maint_onoff "$MAINT_WATCHDOG")]"
        echo -e "  ${GREEN}2)${NC} $(L '管理脚本自动从仓库拉取更新（每日）')                      [$(maint_onoff "$MAINT_SCRIPT_AUTO")]"
        echo -e "  ${GREEN}3)${NC} Snell $(L '跟随官方发布自动更新')$(L '（')${SNELL_CHANNEL} $(L '通道')$(L '）')                  [$(maint_onoff "$SNELL_AUTO_UPDATE")]"
        echo -e "  ${GREEN}4)${NC} Xray $(L '跟随官方发布自动更新')$(L '（')${XRAY_CHANNEL} $(L '通道')$(L '）')              [$(maint_onoff "$XRAY_AUTO_UPDATE")]"
        echo -e "  ${GREEN}5)${NC} $(L 'Nowhere 跟随官方发布自动更新（仅 NW3 同代）')             [$(maint_onoff "${MAINT_NOWHERE_AUTO:-0}")]"
        echo -e "  ${GREEN}6)${NC} $(L 'Realm 跟随官方发布自动更新')                              [$(maint_onoff "${MAINT_REALM_AUTO:-0}")]"
        echo -e "  ${GREEN}7)${NC} $(L 'Caddy 跟随官方发布自动更新')                              [$(maint_onoff "${MAINT_CADDY_AUTO:-0}")]"
        echo -e "  ${GREEN}8)${NC} $(L '每日定时重启 Snell / Xray / Nowhere / Realm（随每日维护执行）') [$(maint_onoff "$MAINT_DAILY_RESTART")]"
        echo -e "  ${GREEN}9)${NC} $(L '立即执行一次维护与巡检')"
        echo -e "  ${GREEN}10)${NC} $(L '查看维护记录')"
        echo -e "  ${GREEN}11)${NC} $(L '重装定时器（修复）')"
        echo -e "  ${GREEN}12)${NC} ${RED}$(L '移除')${NC}$(L '全部定时器')"
        echo -e "  ${GREEN}13)${NC} $(L '备份全部配置（支持 AES-256-CBC 加密）')"
        echo -e "  ${GREEN}14)${NC} $(L '恢复配置（从 .tgz 或 .tgz.enc 备份文件）')"
        echo -e "  ${GREEN}15)${NC} $(L '一键诊断')"
        echo -e "  ${GREEN}16)${NC} $(L '清理日志（保留 200M）')"
        echo -e "  ${GREEN}17)${NC} ${GREEN}$(L '全局一键修复（全部组件 / 权限 / 证书 / 防火墙）')${NC}"
        echo -e "  ${GREEN}18)${NC} $(L 'cloudflared 跟随官方发布自动更新')                         [$(maint_onoff "${MAINT_CF_TUNNEL_AUTO:-0}")]"
        echo -e "  ${GREEN}19)${NC} $(L '告警通知设置（Telegram / Bark / Webhook）')                [$(maint_onoff "${NOTIFY_ENABLED:-0}")]"
        echo -e "  ${GREEN}20)${NC} $(L '导出多客户端配置（Mihomo / sing-box / Surge）')"
        echo -e "  ${GREEN}21)${NC} $(L '配置只读 GitHub Token（提升 API 限额）')                  [$([ -n "${GITHUB_TOKEN:-}" ] && printf '%s' "${GREEN}$(L '已设')${NC}" || printf '%s' "${YELLOW}$(L '未设')${NC}")]"
        echo -e "  ${GREEN}0)${NC} $(L '返回主菜单')"
        divider
        read -rp "$(L '请选择') [0-21]: " choice || return 0
        case "$choice" in
            1) run_action maint_toggle MAINT_WATCHDOG ;;
            2) run_action maint_toggle MAINT_SCRIPT_AUTO ;;
            3) run_action maint_toggle_snell ;;
            4) run_action maint_toggle_xray ;;
            5) run_action maint_toggle MAINT_NOWHERE_AUTO ;;
            6) run_action maint_toggle MAINT_REALM_AUTO ;;
            7) run_action maint_toggle MAINT_CADDY_AUTO ;;
            8) run_action maint_toggle MAINT_DAILY_RESTART ;;
            9) run_action maint_run_now ;;
            10) run_action maint_show_log ;;
            11) run_action maint_install_timers ;;
            12) run_action maint_remove_timers ;;
            13) run_action do_backup ;;
            14) run_action do_restore ;;
            15) run_action do_doctor ;;
            16) run_action do_log_cleanup ;;
            17) run_action do_repair_all ;;
            18) run_action maint_toggle MAINT_CF_TUNNEL_AUTO ;;
            19) run_action notify_menu ;;
            20) run_action do_export_clients ;;
            21) run_action maint_set_github_token ;;
            0) return 0 ;;
            *) warn "$(L '无效选择')" ;;
        esac
        pause_return
    done
}

