# ══════════════════════════════════════════════════════════════
#   Fail2ban 管理 —— 菜单结构参考 3x-ui 的 IP Limit Management
#   3x-ui 的 jail 针对 Xray 的 IP 数量限制；这里没有 Xray，防护对象是 SSH 爆破。
#   配置只写在 jail.d/adam-sshd.local 一个文件里，不碰 jail.conf / jail.local。
# ══════════════════════════════════════════════════════════════

f2b_installed() { command -v fail2ban-client >/dev/null 2>&1; }
f2b_running()   { systemctl is-active --quiet fail2ban 2>/dev/null; }

f2b_require() {
    if ! f2b_installed; then
        warn "$(L '尚未安装 Fail2ban，请先执行「1')) $(L '安装 Fail2ban」（或 adam f2b install）')"
        return 1
    fi
    return 0
}

f2b_require_running() {
    f2b_require || return 1
    if ! f2b_running; then
        warn "$(L 'Fail2ban 服务未运行，请先执行「10')) $(L '启用」或「9')) $(L '重启」')"
        return 1
    fi
    return 0
}

f2b_state_text() {
    local n=""
    if ! f2b_installed; then
        printf '%s' "${YELLOW}$(L '未安装')${NC}"
    elif f2b_running; then
        n="$(fail2ban-client status "$F2B_JAIL" 2>/dev/null | sed -n 's/.*Currently banned:[[:space:]]*//p' || true)"
        printf '%s' "${GREEN}$(L '运行中')${NC}${n:+ ($(L '当前封禁') ${n})}"
    else
        printf '%s' "${RED}$(L '已停止')${NC}"
    fi
}

# f2b_get KEY [DEFAULT]：读取本脚本 jail 文件里的当前值
f2b_get() {
    local key="$1" def="${2:-}" v=""
    if [ -f "$F2B_JAIL_FILE" ]; then
        v="$(awk -v k="$key" '
            /^[ \t]*#/ { next }
            {
                i = index($0, "="); if (i == 0) next
                kk = substr($0, 1, i - 1); gsub(/[ \t]/, "", kk)
                if (kk == k) { v = substr($0, i + 1); gsub(/^[ \t]+|[ \t\r]+$/, "", v); print v; exit }
            }' "$F2B_JAIL_FILE" 2>/dev/null || true)"
    fi
    printf '%s' "${v:-$def}"
}

# 没有活跃 syslog 写入 auth.log 的系统（Debian 12+ 默认不装 rsyslog，但可能残留旧 auth.log）改用 systemd journal（BUG-14a）
f2b_pick_backend() {
    if { [ -s /var/log/auth.log ] || [ -s /var/log/secure ]; } \
        && { systemctl is-active --quiet rsyslog 2>/dev/null || systemctl is-active --quiet syslog-ng 2>/dev/null || ! systemctl is-active --quiet systemd-journald 2>/dev/null; }; then
        printf 'auto'
    else
        printf 'systemd'
    fi
}

f2b_pick_banaction() {
    if command -v iptables >/dev/null 2>&1 && iptables -L -n >/dev/null 2>&1; then
        printf 'iptables-multiport'
    elif [ -f /etc/fail2ban/action.d/nftables-multiport.conf ]; then
        printf 'nftables-multiport'
    else
        printf 'nftables[type=multiport]'
    fi
}

# f2b_write_jail BANTIME FINDTIME MAXRETRY IGNOREIP [BACKEND]
f2b_write_jail() {
    local bantime="$1" findtime="$2" maxretry="$3" ignoreip="$4" backend="${5:-}"
    local ports banaction
    if [ -z "$backend" ]; then backend="$(f2b_pick_backend)"; fi
    ports="$(detect_ssh_ports | tr ' ' ',')"
    banaction="$(f2b_pick_banaction)"
    install -d -m 755 /etc/fail2ban/jail.d
    cat > "$F2B_JAIL_FILE" << F2BEOF
# $(L '由 Adam 管理脚本生成（adam -> Fail2ban 管理）。请通过菜单修改，手动改动会在下次调整时被覆盖。')
# $(L '用 jail.d/')*$(L '.local：读取顺序在 jail.conf、jail.d/')*$(L '.conf、jail.local 之后，同名项以这里为准。')
[sshd]
enabled = true
port = ${ports}
backend = ${backend}
banaction = ${banaction}
bantime = ${bantime}
findtime = ${findtime}
maxretry = ${maxretry}
ignoreip = ${ignoreip}
F2BEOF
    chmod 644 "$F2B_JAIL_FILE"
}

f2b_rewrite_keep() {
    f2b_write_jail "$(f2b_get bantime 30m)" "$(f2b_get findtime 10m)" "$(f2b_get maxretry 5)" \
        "$(f2b_get ignoreip '127.0.0.1/8 ::1')" "${1:-$(f2b_get backend '')}"
}

# 重启并确认 sshd jail 真的起来了（服务 active 不等于 jail 已加载）
f2b_apply() {
    local i
    systemctl enable fail2ban >/dev/null 2>&1 || true
    systemctl restart fail2ban >/dev/null 2>&1 || true
    for i in 1 2 3 4 5 6 7 8 9 10; do
        if fail2ban-client ping >/dev/null 2>&1 && fail2ban-client status "$F2B_JAIL" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

f2b_diagnose_and_fix() {
    local log backend
    log="$( { journalctl -u fail2ban -n 40 --no-pager 2>/dev/null; fail2ban-client -t 2>&1; } || true)"
    backend="$(f2b_get backend auto)"
    if [[ "$log" == *"asynchat"* || "$log" == *"asyncore"* ]]; then
        warn "$(L 'fail2ban 与当前 Python 版本不兼容（缺 asynchat/asyncore，常见于 Ubuntu 24.04 的初版软件包），尝试升级 fail2ban ...')"
        apt-get update -qq || true
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --only-upgrade fail2ban || true
        if f2b_apply; then return 0; fi
    fi
    if [ "$backend" != "systemd" ]; then
        warn "$(L '按日志文件方式启动失败（常见原因：系统没有 /var/log/auth.log），改用 systemd journal 后端重试 ...')"
        apt_install python3-systemd || true
        f2b_rewrite_keep systemd
        if f2b_apply; then return 0; fi
    fi
    warn "$(L 'Fail2ban 仍未能正常启动，最近日志：')"
    journalctl -u fail2ban -n 15 --no-pager 2>/dev/null || true
    fail2ban-client -t 2>&1 | tail -n 5 || true
    return 1
}

f2b_show_settings() {
    echo -e "  $(L '防护端口 :') ${GREEN}$(f2b_get port ssh)${NC}"
    echo -e "  $(L '封禁时长 :') ${GREEN}$(f2b_get bantime 30m)${NC}$(L '（-1 表示永久）')"
    echo -e "  $(L '触发条件 :') ${GREEN}$(f2b_get findtime 10m)${NC} $(L '内失败') ${GREEN}$(f2b_get maxretry 5)${NC} $(L '次')"
    echo -e "  $(L '白名单   :') ${GREEN}$(f2b_get ignoreip '127.0.0.1/8 ::1')${NC}"
    echo -e "  $(L '日志后端 :') ${GREEN}$(f2b_get backend auto)${NC}    $(L '封禁动作:') ${GREEN}$(f2b_get banaction -)${NC}"
}

f2b_install() {
    step "$(L '安装 Fail2ban 并启用 SSH 防护')"
    divider
    local backend ignoreip myip
    local -a pkgs=(fail2ban)
    backend="$(f2b_pick_backend)"
    if [ "$backend" = "systemd" ]; then pkgs+=(python3-systemd); fi
    if ! command -v iptables >/dev/null 2>&1 && ! command -v nft >/dev/null 2>&1; then pkgs+=(nftables); fi
    info "$(L '正在安装:') ${pkgs[*]}"
    apt_install "${pkgs[@]}" || { warn "$(L '安装失败，请检查 apt 源/网络')"; return 1; }

    # 消除 fail2ban 1.x 的 allowipv6 未设置告警（仅当发行版配置里有这一行时才改）
    sed -i 's/^#allowipv6 = auto/allowipv6 = auto/' /etc/fail2ban/fail2ban.conf 2>/dev/null || true

    ignoreip="$(f2b_get ignoreip '127.0.0.1/8 ::1')"
    myip="${SSH_CONNECTION%% *}"
    if [ -n "$myip" ] && is_ip "$myip" && [[ " $ignoreip " != *" $myip "* ]]; then
        if confirm "$(L '把你当前的登录 IP（')${myip}$(L '）加入白名单，避免输错密码把自己封掉？')" y; then
            ignoreip="${ignoreip} ${myip}"
        fi
    fi
    f2b_write_jail "$(f2b_get bantime 30m)" "$(f2b_get findtime 10m)" "$(f2b_get maxretry 5)" "$ignoreip" "$backend"
    if f2b_apply || f2b_diagnose_and_fix; then
        success "$(L 'Fail2ban 已启动，SSH 防护生效')"
        f2b_show_settings
        return 0
    fi
    return 1
}

f2b_require_managed() {
    f2b_require || return 1
    if [ ! -f "$F2B_JAIL_FILE" ]; then
        warn "$(L '未找到本脚本的 SSH 防护配置，请先执行「1')) $(L '安装 Fail2ban」生成')"
        return 1
    fi
    return 0
}

f2b_set_bantime() {
    f2b_require_managed || return 1
    local v="${1:-}" re='^[1-9][0-9]*[smhdw]$'
    if [ -z "$v" ]; then
        echo "$(L '当前封禁时长:') $(f2b_get bantime 30m)"
        read -rp "$(L '新的封禁时长（纯数字=分钟；也可写 10m / 1h / 1d / 1w；-1=永久）')[$(L '默认 30')]: " v || { [ -n "$v" ] || return 1; }
        v="${v:-30}"
    fi
    v="${v//[[:space:]]/}"
    if [[ "$v" =~ ^[1-9][0-9]*$ ]]; then
        v="${v}m"
    elif [[ "$v" =~ $re || "$v" == "-1" ]]; then
        :
    else
        warn "$(L '格式不合法:') ${v}$(L '（示例：30 / 10m / 1h / 1d / -1）')"
        return 1
    fi
    f2b_write_jail "$v" "$(f2b_get findtime 10m)" "$(f2b_get maxretry 5)" "$(f2b_get ignoreip '127.0.0.1/8 ::1')" "$(f2b_get backend '')"
    if f2b_apply || f2b_diagnose_and_fix; then
        success "$(L '封禁时长已改为') ${v}$(L '（对之后的新封禁生效）')"
        return 0
    fi
    return 1
}

f2b_tune() {
    f2b_require_managed || return 1
    local mr ft re='^[1-9][0-9]*[smhdw]?$'
    echo "$(L '当前触发条件:') $(f2b_get findtime 10m) $(L '内失败') $(f2b_get maxretry 5) $(L '次')"
    read -rp "$(L '最大失败次数 maxretry') [$(L '回车保持') $(f2b_get maxretry 5)]: " mr || { [ -n "$mr" ] || return 1; }
    mr="${mr:-$(f2b_get maxretry 5)}"
    if [[ ! "$mr" =~ ^[1-9][0-9]*$ ]]; then warn "$(L 'maxretry 必须是正整数')"; return 1; fi
    read -rp "$(L '统计窗口 findtime（如 10m / 1h，纯数字=分钟）')[$(L '回车保持') $(f2b_get findtime 10m)]: " ft || { [ -n "$ft" ] || return 1; }
    ft="${ft:-$(f2b_get findtime 10m)}"
    ft="${ft//[[:space:]]/}"
    if [[ ! "$ft" =~ $re ]]; then warn "$(L 'findtime 格式不合法')"; return 1; fi
    if [[ "$ft" =~ ^[0-9]+$ ]]; then ft="${ft}m"; fi
    f2b_write_jail "$(f2b_get bantime 30m)" "$ft" "$mr" "$(f2b_get ignoreip '127.0.0.1/8 ::1')" "$(f2b_get backend '')"
    if f2b_apply || f2b_diagnose_and_fix; then
        success "$(L '触发条件已改为:') ${ft} $(L '内失败') ${mr} $(L '次')"
        return 0
    fi
    return 1
}

f2b_unban_all() {
    f2b_require_running || return 1
    if ! confirm "$(L '确认解封当前所有被封禁的 IP？')" y; then
        info "$(L '已取消')"
        return 0
    fi
    if fail2ban-client unban --all >/dev/null 2>&1; then
        success "$(L '已解封所有 IP')"
    else
        warn "$(L '解封失败，请查看: fail2ban-client status') ${F2B_JAIL}"
        return 1
    fi
    return 0
}

f2b_banned() {
    f2b_require_running || return 1
    local jails j out cur total ips
    jails="$(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' | tr -d ',' || true)"
    if [ -z "$jails" ]; then
        echo "  $(L '（没有启用的 jail）')"
        return 0
    fi
    while IFS= read -r j; do
        [ -n "$j" ] || continue
        out="$(fail2ban-client status "$j" 2>/dev/null || true)"
        cur="$(printf '%s\n' "$out" | sed -n 's/.*Currently banned:[[:space:]]*//p')"
        total="$(printf '%s\n' "$out" | sed -n 's/.*Total banned:[[:space:]]*//p')"
        ips="$(printf '%s\n' "$out" | sed -n 's/.*Banned IP list:[[:space:]]*//p')"
        echo -e "  ${BOLD}[${j}]${NC} $(L '当前封禁') ${cur:-0} $(L '个，累计') ${total:-0} $(L '次')"
        if [ -n "$ips" ]; then echo "    ${ips}"; fi
    done < <(printf '%s\n' "$jails" | tr ' ' '\n' | grep -v '^$')
    return 0
}

f2b_banlog() {
    f2b_require || return 1
    local out=""
    info "$(L '最近的封禁 / 解封记录：')"
    if [ -f "$F2B_LOG" ]; then
        out="$(grep -E '\] (Ban|Unban|Restore Ban) ' "$F2B_LOG" 2>/dev/null | tail -n 20 || true)"
    else
        out="$(journalctl -u fail2ban --no-pager -n 2000 2>/dev/null | grep -E '\] (Ban|Unban|Restore Ban) ' | tail -n 20 || true)"
    fi
    if [ -n "$out" ]; then printf '%s\n' "$out"; else echo "  $(L '（暂无记录）')"; fi
    echo ""
    info "$(L '当前封禁列表：')"
    f2b_banned || true
    return 0
}

f2b_ban_ip() {
    f2b_require_running || return 1
    local ip="${1:-}" myip="${SSH_CONNECTION%% *}"
    if [ -z "$ip" ]; then read -rp "$(L '输入要封禁的 IP 地址:') " ip || { [ -n "$ip" ] || return 1; }; fi
    ip="${ip//[[:space:]]/}"
    if ! is_ip "$ip"; then warn "$(L 'IP 地址格式不合法:') ${ip}"; return 1; fi
    if [ -n "$myip" ] && [ "$ip" = "$myip" ]; then
        warn "$(L '这是你当前登录所用的 IP，封禁后会立刻断开且无法重连，已拒绝')"
        return 1
    fi
    if fail2ban-client set "$F2B_JAIL" banip "$ip" >/dev/null 2>&1; then
        success "$(L '已封禁') ${ip}$(L '（时长') $(f2b_get bantime 30m)$(L '）')"
    else
        warn "$(L '封禁失败（jail') ${F2B_JAIL} $(L '是否已启用？）')"
        return 1
    fi
    return 0
}

f2b_unban_ip() {
    f2b_require_running || return 1
    local ip="${1:-}"
    if [ -z "$ip" ]; then read -rp "$(L '输入要解封的 IP 地址:') " ip || { [ -n "$ip" ] || return 1; }; fi
    ip="${ip//[[:space:]]/}"
    if ! is_ip "$ip"; then warn "$(L 'IP 地址格式不合法:') ${ip}"; return 1; fi
    if fail2ban-client unban "$ip" >/dev/null 2>&1 || fail2ban-client set "$F2B_JAIL" unbanip "$ip" >/dev/null 2>&1; then
        success "$(L '已解封') ${ip}"
    else
        warn "$(L '解封失败（该 IP 可能本来就没有被封）')"
        return 1
    fi
    return 0
}

f2b_live_log() {
    f2b_require || return 1
    info "$(L '实时日志（Ctrl+C 返回）')"
    if [ -f "$F2B_LOG" ]; then
        tail -n 20 -f "$F2B_LOG" || true
    else
        journalctl -u fail2ban -n 20 -f || true
    fi
    return 0
}

f2b_status() {
    f2b_require || return 1
    systemctl status fail2ban --no-pager 2>/dev/null | head -n 12 || true
    divider
    if [ -f "$F2B_JAIL_FILE" ]; then
        f2b_show_settings
        divider
    fi
    if f2b_running; then f2b_banned || true; fi
    return 0
}

f2b_restart() {
    f2b_require || return 1
    if f2b_apply; then
        success "$(L 'Fail2ban 已重启')"
    elif [ -f "$F2B_JAIL_FILE" ]; then
        f2b_diagnose_and_fix || return 1
        success "$(L 'Fail2ban 已重启')"
    else
        systemctl is-active --quiet fail2ban || { warn "$(L '重启失败: journalctl -u fail2ban -n 30')"; return 1; }
        success "$(L 'Fail2ban 已重启')"
    fi
    return 0
}

f2b_on() {
    f2b_require || return 1
    systemctl enable --now fail2ban >/dev/null 2>&1 || true
    sleep 1
    if f2b_running; then
        success "$(L 'Fail2ban 已启用（开机自启）')"
    else
        warn "$(L '启动失败: journalctl -u fail2ban -n 30 --no-pager')"
        return 1
    fi
    return 0
}

f2b_off() {
    f2b_require || return 1
    systemctl disable --now fail2ban >/dev/null 2>&1 || true
    success "$(L 'Fail2ban 已停用（现有封禁随服务停止而解除，配置保留）')"
    return 0
}

f2b_whitelist() {
    f2b_require_managed || return 1
    local cur choice ip new="" w
    cur="$(f2b_get ignoreip '127.0.0.1/8 ::1')"
    echo "$(L '当前白名单（这些来源永远不会被封）:') ${cur}"
    echo "  1) $(L '添加 IP / 网段    2')) $(L '移除 IP / 网段    0')) $(L '返回')"
    read -rp "$(L '请选择:') " choice || { [ -n "$choice" ] || return 1; }
    case "$choice" in
        1)
            read -rp "$(L '输入要加入白名单的 IP 或 CIDR 网段:') " ip || { [ -n "$ip" ] || return 1; }
            ip="${ip//[[:space:]]/}"
            if ! is_ip "$ip" 1; then warn "$(L '格式不合法:') ${ip}"; return 1; fi
            if [[ " $cur " == *" $ip "* ]]; then info "$(L '已在白名单中')"; return 0; fi
            new="${cur} ${ip}"
            ;;
        2)
            read -rp "$(L '输入要移除的 IP 或网段:') " ip || { [ -n "$ip" ] || return 1; }
            ip="${ip//[[:space:]]/}"
            while IFS= read -r w; do
                [ -n "$w" ] || continue
                if [ "$w" != "$ip" ]; then new="${new:+$new }$w"; fi
            done < <(printf '%s\n' "$cur" | tr ' ' '\n' | grep -v '^$')
            if [ "$new" = "$cur" ]; then info "$(L '白名单里没有') ${ip}"; return 0; fi
            if [ -z "$new" ]; then new="127.0.0.1/8 ::1"; fi
            ;;
        *) return 0 ;;
    esac
    f2b_write_jail "$(f2b_get bantime 30m)" "$(f2b_get findtime 10m)" "$(f2b_get maxretry 5)" "$new" "$(f2b_get backend '')"
    if f2b_apply || f2b_diagnose_and_fix; then
        success "$(L '白名单已更新:') ${new}"
        return 0
    fi
    return 1
}

f2b_uninstall() {
    f2b_require || return 1
    local choice
    echo -e "  ${GREEN}1)${NC} $(L '只移除本脚本的 SSH 防护配置（保留 Fail2ban 及其他 jail）')"
    echo -e "  ${GREEN}2)${NC} $(L '卸载 Fail2ban（保留 /etc/fail2ban 下你自己的其他配置）')"
    echo -e "  ${GREEN}0)${NC} $(L '返回')"
    read -rp "$(L '请选择:') " choice || { [ -n "$choice" ] || return 1; }
    case "$choice" in
        1)
            rm -f "$F2B_JAIL_FILE"
            systemctl restart fail2ban >/dev/null 2>&1 || true
            sleep 1
            if fail2ban-client status >/dev/null 2>&1; then
                success "$(L '已移除本脚本的 SSH 防护配置')"
            else
                warn "$(L 'Fail2ban 重启后校验失败，请查看: fail2ban-client status')"
                return 1
            fi
            ;;
        2)
            if ! confirm "$(L '确认卸载 Fail2ban？')" n; then info "$(L '已取消')"; return 0; fi
            systemctl disable --now fail2ban >/dev/null 2>&1 || true
            rm -f "$F2B_JAIL_FILE"
            DEBIAN_FRONTEND=noninteractive apt-get remove -y -qq fail2ban || warn "$(L 'apt-get remove 失败，请手动处理')"
            success "$(L 'Fail2ban 已卸载')"
            ;;
        *) return 0 ;;
    esac
    return 0
}

f2b_menu() {
    local choice
    while true; do
        clear 2>/dev/null || true
        echo -e "${BOLD}${CYAN}━━━ $(L 'Fail2ban 管理（SSH 防爆破）') ━━━${NC}"
        echo -e "  $(L '当前状态:') $(f2b_state_text)    $(L '封禁时长:') $(f2b_get bantime '-')"
        divider
        echo -e "  ${GREEN}1)${NC}  ${GREEN}$(L '安装')${NC} $(L 'Fail2ban 并启用 SSH 防护')"
        echo -e "  ${GREEN}2)${NC}  $(L '修改封禁时长')"
        echo -e "  ${GREEN}3)${NC}  $(L '解封所有 IP')"
        echo -e "  ${GREEN}4)${NC}  $(L '封禁日志 / 查看被封 IP')"
        echo -e "  ${GREEN}5)${NC}  $(L '手动封禁一个 IP')"
        echo -e "  ${GREEN}6)${NC}  $(L '手动解封一个 IP')"
        echo -e "  ${GREEN}7)${NC}  $(L '实时日志')"
        echo -e "  ${GREEN}8)${NC}  $(L '服务状态')"
        echo -e "  ${GREEN}9)${NC}  $(L '重启服务')"
        echo -e "  ${GREEN}10)${NC} ${GREEN}$(L '启用')${NC} $(L 'Fail2ban（开机自启）')"
        echo -e "  ${GREEN}11)${NC} ${RED}$(L '停用')${NC} Fail2ban"
        echo -e "  ${GREEN}12)${NC} $(L '修改触发条件（失败次数 / 统计窗口）')"
        echo -e "  ${GREEN}13)${NC} $(L '白名单管理')"
        echo -e "  ${GREEN}14)${NC} ${RED}$(L '卸载')${NC}"
        echo -e "  ${GREEN}0)${NC}  $(L '返回主菜单')"
        divider
        read -rp "$(L '请选择') [0-14]: " choice || return 0
        case "$choice" in
            1)  run_action f2b_install ;;
            2)  run_action f2b_set_bantime ;;
            3)  run_action f2b_unban_all ;;
            4)  run_action f2b_banlog ;;
            5)  run_action f2b_ban_ip ;;
            6)  run_action f2b_unban_ip ;;
            7)  run_action f2b_live_log ;;
            8)  run_action f2b_status ;;
            9)  run_action f2b_restart ;;
            10) run_action f2b_on ;;
            11) run_action f2b_off ;;
            12) run_action f2b_tune ;;
            13) run_action f2b_whitelist ;;
            14) run_action f2b_uninstall ;;
            0)  return 0 ;;
            *)  warn "$(L '无效选择')" ;;
        esac
        pause_return
    done
}

f2b_cli() {
    local sub="${1:-menu}"
    if [ "$#" -gt 0 ]; then shift; fi
    case "$sub" in
        menu)         f2b_menu ;;
        install)      f2b_install ;;
        status)       f2b_status ;;
        banned|list)  f2b_banned ;;
        log|logs)     f2b_banlog ;;
        bantime)      f2b_set_bantime "${1:-}" ;;
        ban)
            [ -n "${1:-}" ] || error "$(L '用法: adam f2b ban <IP>')"
            f2b_ban_ip "$1" ;;
        unban)
            [ -n "${1:-}" ] || error "$(L '用法: adam f2b unban <IP>')"
            f2b_unban_ip "$1" ;;
        unban-all)    f2b_unban_all ;;
        on|enable)    f2b_on ;;
        off|disable)  f2b_off ;;
        restart)      f2b_restart ;;
        uninstall)    f2b_uninstall ;;
        *) error "$(L '未知的 f2b 子命令:') ${sub}$(L '（可用: install / status / banned / log / bantime <时长> / ban <IP> / unban <IP> / unban-all / on / off / restart / uninstall）')" ;;
    esac
}

