# ══════════════════════════════════════════════════════════════
#   防火墙管理（ufw）—— 菜单结构参考 3x-ui 的 Firewall Management
#   与 3x-ui 的差异：启用/删除前保护 SSH 端口；按编号删除时从大到小删
#   （ufw 每删一条后面的编号都会前移，按输入顺序删会删错）；端口可带 /tcp /udp。
# ══════════════════════════════════════════════════════════════

ufw_installed() { command -v ufw >/dev/null 2>&1; }

ufw_active() {
    ufw_installed || return 1
    local out
    out="$(LC_ALL=C ufw status 2>/dev/null || true)"
    [[ "$out" == *"Status: active"* ]]
}

fw_require() {
    if ! ufw_installed; then
        warn "$(L '尚未安装 ufw，请先在防火墙菜单执行「1')) $(L '安装防火墙」（或 adam fw install）')"
        return 1
    fi
    return 0
}

fw_state_text() {
    if ! ufw_installed; then
        printf '%s' "${YELLOW}$(L '未安装')${NC}"
    elif ufw_active; then
        printf '%s' "${GREEN}$(L '已启用')${NC}"
    else
        printf '%s' "${RED}$(L '未启用')${NC}"
    fi
}

# Nowhere Portal 需要的入站端口，每行一个 ufw 规格（Egress 角色不需要入站端口）
nowhere_ports() {
    [ -f "$CONFIG_FILE" ] || return 0
    if [ "$(current_role)" = "egress" ]; then return 0; fi
    (
        # shellcheck disable=SC1090
        source "$CONFIG_FILE" 2>/dev/null || exit 0
        PORT_MODE="${PORT_MODE_VALUE:-same}"; NET="${NET_VALUE:-mix}"
        PORT="${PORT_VALUE:-}"; TCP_PORT="${TCP_PORT_VALUE:-$PORT}"; UDP_PORT="${UDP_PORT_VALUE:-$PORT}"
        [ -n "$PORT" ] || exit 0
        if has_tcp; then echo "$(tcp_port)/tcp"; fi
        if has_udp; then echo "$(udp_port)/udp"; fi
        if [ "${CERT_METHOD_VALUE:-}" = "letsencrypt-http" ]; then echo "80/tcp"; fi
        exit 0
    )
    return 0
}

# 本脚本管理的全部服务端口（Nowhere + Snell + Xray + Realm + Caddy），每行一个 ufw 规格
# v8.6（BUG-09 / BUG-14c）：只统计真正已安装（二进制或 unit 在位）的模块，避免残留配置目录产生幽灵端口；
# Xray 任一节点用 certbot HTTP-01 续期时也纳入 80/tcp，最后去重排序。
managed_ports() {
    {
        if [ -x "$BIN_PATH" ] || [ -f "$SERVICE_FILE" ]; then nowhere_ports; fi
        if [ -x "$SNELL_BIN" ] || [ -f "$SNELL_SERVICE" ]; then
            local sp
            while IFS= read -r sp; do
                if [ -n "$sp" ]; then echo "${sp}/tcp"; fi
            done < <(snell_all_ports)
        fi
        if [ -x "$XRAY_BIN" ] || [ -f "$XRAY_SERVICE" ]; then
            xray_ports
            if xray_needs_port80 2>/dev/null; then echo "80/tcp"; fi
        fi
        if realm_installed || [ -f "$REALM_SERVICE" ]; then realm_ports; fi
        if caddy_installed || [ -f "$CADDY_SERVICE" ]; then caddy_ports; fi
    } | sort -u
    return 0
}

fw_allow_ssh() {
    local p
    while IFS= read -r p; do
        [ -n "$p" ] || continue
        ufw allow "${p}/tcp" >/dev/null 2>&1 || true
    done < <(detect_ssh_ports | tr ' ' '\n')
    return 0
}

fw_sync_managed() {
    local spec n=0
    while IFS= read -r spec; do
        [ -n "$spec" ] || continue
        if ufw allow "$spec" >/dev/null 2>&1; then
            info "$(L '已放行本脚本服务端口:') ${spec}"
            n=$((n + 1))
        fi
    done < <(managed_ports)
    if [ "$n" -eq 0 ]; then
        info "$(L '当前没有由本脚本管理的服务端口需要放行（Nowhere / Snell / Xray / Realm / Caddy 均未安装）')"
    fi
    return 0
}

# fw_is_allowed PORT PROTO：是否已有覆盖该端口的 allow 规则（防火墙未启用时也能查）
# v8.6（BUG-14b）：兼容 OpenSSH/ssh 命名规则、逗号多端口（80,443/tcp、port 22,2222）及端口段（lo:hi）
fw_is_allowed() {
    local port="$1" proto="$2" added line rest spec rng rp lo hi sp tok
    local -a toks=()
    added="$(LC_ALL=C ufw show added 2>/dev/null || true)"
    while IFS= read -r line; do
        case "$line" in
            "ufw allow "*) rest="${line#ufw allow }" ;;
            *) continue ;;
        esac
        # 跳过出站规则，剥离显式入站前缀 "in "
        case "$rest" in
            "out "*) continue ;;
            "in "*)  rest="${rest#in }" ;;
        esac
        # 带来源/接口的规则：ufw allow from 1.2.3.4 to any port 22,2222 proto tcp
        if [[ "$rest" == *" port "* ]]; then
            local p pr
            p="$(printf '%s' "$rest" | sed -nE 's/.* port ([^ ]+).*/\1/p' | head -1 || true)"
            pr="$(printf '%s' "$rest" | grep -oE 'proto [a-z]+' | awk '{print $2}' | head -1 || true)"
            if [ -n "$p" ] && { [ -z "$pr" ] || [ "$pr" = "$proto" ]; }; then
                IFS=',' read -r -a toks <<< "$p"
                for tok in "${toks[@]}"; do
                    if [[ "$tok" =~ ^[0-9]+$ ]] && [ "$tok" = "$port" ]; then return 0; fi
                    if [[ "$tok" =~ ^([0-9]+):([0-9]+)$ ]] && [ "$port" -ge "${BASH_REMATCH[1]}" ] && [ "$port" -le "${BASH_REMATCH[2]}" ]; then return 0; fi
                done
            fi
            continue
        fi
        spec="${rest%% *}"
        # 去掉引号（例如 ufw allow 'Nginx Full'）
        spec="${spec#\'}"; spec="${spec%\'}"; spec="${spec#\"}"; spec="${spec%\"}"
        rng="${spec%%/*}"; rp="${spec#*/}"; [ "$rp" = "$spec" ] && rp=""
        IFS=',' read -r -a toks <<< "$rng"
        for tok in "${toks[@]}"; do
            if [[ "$tok" =~ ^[0-9]+$ ]]; then
                if [ "$tok" = "$port" ] && { [ -z "$rp" ] || [ "$rp" = "$proto" ]; }; then return 0; fi
            elif [[ "$tok" =~ ^([0-9]+):([0-9]+)$ ]]; then
                lo="${BASH_REMATCH[1]}"; hi="${BASH_REMATCH[2]}"
                if [ "$port" -ge "$lo" ] && [ "$port" -le "$hi" ] && { [ -z "$rp" ] || [ "$rp" = "$proto" ]; }; then return 0; fi
            else
                case "${tok,,}" in
                    openssh|ssh)
                        if [ "$port" = "22" ] && [ "$proto" = "tcp" ]; then return 0; fi ;;
                    *)
                        if [ -z "$rp" ] || [ "$rp" = "$proto" ]; then
                            sp="$(getent services "${tok}/${proto}" 2>/dev/null | awk '{print $2}' | cut -d/ -f1 | head -1 || true)"
                            if [ -n "$sp" ] && [ "$sp" = "$port" ]; then return 0; fi
                        fi ;;
                esac
            fi
        done
    done <<< "$added"
    return 1
}

# 是否存在与 ufw 冲突的防火墙：firewalld 在运行，或 cnblock 的 FWIN 链已挂在 INPUT 上
fw_conflict_detected() {
    if systemctl is-active --quiet firewalld 2>/dev/null; then return 0; fi
    if command -v iptables >/dev/null 2>&1 && iptables -S INPUT 2>/dev/null | awk '/-j FWIN/{f=1} END{exit !f}'; then return 0; fi
    return 1
}

# 对外监听中的端口，每行 "端口/协议 进程名"（回环与常见本地服务不算）
fw_listening_ports() {
    command -v ss >/dev/null 2>&1 || return 0
    ss -tulnp 2>/dev/null | awk '
        $1 == "Netid" { next }
        {
            proto = ($1 ~ /^tcp/) ? "tcp" : "udp"
            addr = $5; n = split(addr, a, ":"); port = a[n]
            host = substr(addr, 1, length(addr) - length(port) - 1)
            if (port !~ /^[0-9]+$/) next
            if (host ~ /^127\./ || host == "[::1]" || host == "::1" || host ~ /^\[?fe80/) next
            if (proto == "udp" && (port == 68 || port == 546 || port == 5353 || port == 5355 || port == 323)) next
            proc = "-"
            if (match($0, /users:\(\("[^"]+"/)) proc = substr($0, RSTART + 9, RLENGTH - 10)
            print port "/" proto " " proc
        }' | sort -u -t/ -k1,1n -k2,2 || true
    return 0
}

fw_show_unallowed_listening() {
    local line spec proc port proto shown=0
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        spec="${line%% *}"; proc="${line#* }"
        port="${spec%/*}"; proto="${spec#*/}"
        if ! fw_is_allowed "$port" "$proto"; then
            if [ "$shown" -eq 0 ]; then
                warn "$(L '以下端口正在对外监听，但还没有在防火墙里放行（启用后外部将无法访问）：')"
                shown=1
            fi
            echo -e "    ${YELLOW}${spec}${NC}  ${proc}"
        fi
    done < <(fw_listening_ports)
    if [ "$shown" -eq 1 ]; then
        info "$(L '需要对外提供服务的端口，请用「3')) $(L '放行端口」添加后再启用')"
    fi
    return 0
}

fw_warn_conflicts() {
    local rules=""
    if command -v iptables >/dev/null 2>&1; then
        rules="$(iptables -S INPUT 2>/dev/null || true)"
        if [[ "$rules" == *"-j FWIN"* ]]; then
            warn "$(L '检测到 cnblock 的端口防火墙链 FWIN 已挂在 INPUT 上：两套入站防火墙会叠加（两边都放行才通），建议只保留一套（cnblock fw off，或不启用 ufw）')"
        fi
    fi
    if systemctl is-active --quiet firewalld 2>/dev/null; then
        warn "$(L '检测到 firewalld 正在运行，与 ufw 同时启用会互相覆盖规则，请只保留一个')"
    fi
    if command -v docker >/dev/null 2>&1; then
        info "$(L '提示：Docker 用 -p 发布的端口走 FORWARD 链，不受 ufw 入站规则限制')"
    fi
    return 0
}

fw_enable() {
    fw_require || return 1
    if ufw_active; then
        info "$(L '防火墙已是启用状态')"
        return 0
    fi
    fw_warn_conflicts
    info "$(L '启用前先放行 SSH 端口（')$(detect_ssh_ports)$(L '），避免把自己锁在外面')"
    fw_allow_ssh
    fw_sync_managed
    fw_show_unallowed_listening
    echo ""
    if ! confirm "$(L '确认启用防火墙？（默认拒绝所有入站，仅放行已添加的端口）')" y; then
        info "$(L '已取消，防火墙保持未启用')"
        return 0
    fi
    ufw --force enable >/dev/null 2>&1 || true
    if ufw_active; then
        success "$(L '防火墙已启用（开机自动生效）')"
    else
        warn "$(L '启用失败，请查看: ufw status verbose')"
        return 1
    fi
    return 0
}

fw_disable() {
    fw_require || return 1
    if ! ufw_active; then
        info "$(L '防火墙当前未启用')"
        return 0
    fi
    warn "$(L '停用后所有端口不再受 ufw 过滤（已添加的规则会保留，可随时重新启用）')"
    if ! confirm "$(L '确认停用防火墙？')" n; then
        info "$(L '已取消')"
        return 0
    fi
    ufw disable >/dev/null 2>&1 || true
    success "$(L '防火墙已停用')"
    return 0
}

fw_install() {
    step "$(L '安装防火墙（ufw）')"
    divider
    if ufw_installed; then
        info "$(L 'ufw 已安装')"
    else
        info "$(L '正在安装 ufw ...')"
        apt_install ufw || { warn "$(L 'ufw 安装失败，请检查 apt 源/网络')"; return 1; }
        success "$(L 'ufw 安装完成')"
    fi
    if ufw_active; then
        success "$(L '防火墙已处于启用状态，补齐 SSH 与本脚本服务端口的放行规则')"
        fw_allow_ssh
        fw_sync_managed
        return 0
    fi
    fw_enable
}

# 解析端口输入：80,443,2053 / 400-500 / 可带 /tcp /udp 后缀。结果写入全局数组 FW_SPECS（ufw 规格）
fw_parse_specs() {
    local input="${1//[[:space:]]/}" item a b proto
    local re='^([0-9]+)(-([0-9]+))?(/(tcp|udp))?$'
    local -a items=()
    FW_SPECS=()
    [ -n "$input" ] || return 1
    IFS=',' read -r -a items <<< "$input"
    for item in "${items[@]}"; do
        if [[ ! "$item" =~ $re ]]; then
            warn "$(L '无法识别的端口写法:') ${item}"
            return 1
        fi
        a="${BASH_REMATCH[1]}"; b="${BASH_REMATCH[3]}"; proto="${BASH_REMATCH[5]}"
        a=$((10#$a))
        if [ "$a" -lt 1 ] || [ "$a" -gt 65535 ]; then warn "$(L '端口超出范围:') ${item}"; return 1; fi
        if [ -n "$b" ]; then
            b=$((10#$b))
            if [ "$b" -lt 1 ] || [ "$b" -gt 65535 ]; then warn "$(L '端口超出范围:') ${item}"; return 1; fi
            if [ "$a" -ge "$b" ]; then warn "$(L '端口范围的起点必须小于终点:') ${item}"; return 1; fi
            if [ -n "$proto" ]; then
                FW_SPECS+=("${a}:${b}/${proto}")
            else
                FW_SPECS+=("${a}:${b}/tcp" "${a}:${b}/udp")
            fi
        else
            if [ -n "$proto" ]; then FW_SPECS+=("${a}/${proto}"); else FW_SPECS+=("${a}"); fi
        fi
    done
    return 0
}

fw_open_ports() {
    fw_require || return 1
    local input="${1:-}" spec
    if [ -z "$input" ]; then
        echo "$(L '输入要放行的端口：逗号分隔，支持范围与协议后缀')"
        echo "  $(L '例：80,443,2053    400-500    443/tcp,51820/udp   （不写协议 = TCP 和 UDP 都放行）')"
        read -rp "$(L '端口:') " input || { [ -n "$input" ] || return 1; }
    fi
    if ! fw_parse_specs "$input"; then
        warn "$(L '输入不合法，未做任何修改')"
        return 1
    fi
    for spec in "${FW_SPECS[@]}"; do
        if ufw allow "$spec" >/dev/null 2>&1; then
            success "$(L '已放行') ${spec}"
        else
            warn "$(L '放行失败:') ${spec}"
        fi
    done
    if ! ufw_active; then
        warn "$(L '注意：防火墙当前未启用，规则已保存，启用后才生效')"
    fi
    return 0
}

# fw_spec_has_port SPEC PORT：规格是单端口、逗号多端口、起止范围（400-500 或 400:500）或服务名（OpenSSH/ssh）且包含 PORT 时返回 0（L6 / BUG-14b）
fw_spec_has_port() {
    local spec="${1%%/*}" p="$2" lo hi tok sp
    local -a toks=()
    spec="${spec#\'}"; spec="${spec%\'}"; spec="${spec#\"}"; spec="${spec%\"}"
    IFS=',' read -r -a toks <<< "$spec"
    for tok in "${toks[@]}"; do
        if [[ "$tok" =~ ^[0-9]+$ ]]; then
            [ "$tok" = "$p" ] && return 0
        elif [[ "$tok" =~ ^([0-9]+)[-:]([0-9]+)$ ]]; then
            lo="${BASH_REMATCH[1]}"; hi="${BASH_REMATCH[2]}"
            [ "$p" -ge "$lo" ] && [ "$p" -le "$hi" ] && return 0
        else
            case "${tok,,}" in
                openssh|ssh) [ "$p" = "22" ] && return 0 ;;
                *)
                    sp="$(getent services "$tok" 2>/dev/null | awk '{print $2}' | cut -d/ -f1 | head -1 || true)"
                    [ -n "$sp" ] && [ "$sp" = "$p" ] && return 0 ;;
            esac
        fi
    done
    return 1
}

# fw_spec_has_ssh_port SPEC：规格含任一当前 SSH 端口时返回 0（范围类规则也按 SSH 规则处理，L6）
fw_spec_has_ssh_port() {
    local spec="$1" sp
    while IFS= read -r sp; do
        [ -n "$sp" ] || continue
        if fw_spec_has_port "$spec" "$sp"; then return 0; fi
    done < <(detect_ssh_ports | tr ' ' '\n')
    return 1
}

fw_delete_spec() {
    local spec="$1" out v done_any=0
    local -a variants=()
    if [[ "$spec" == */* ]]; then
        variants=("$spec")
    else
        variants=("$spec" "${spec}/tcp" "${spec}/udp")
    fi
    for v in "${variants[@]}"; do
        out="$(LC_ALL=C ufw delete allow "$v" 2>&1 || true)"
        if [[ "$out" == *"deleted"* || "$out" == *"updated"* ]]; then done_any=1; fi
    done
    if [ "$done_any" -eq 1 ]; then
        success "$(L '已删除放行规则:') ${spec}"
    else
        info "$(L '没有找到') ${spec} $(L '的放行规则')"
    fi
    return 0
}

fw_delete_by_number() {
    local nums n line rule_lhs tok is_ssh listing
    if ! ufw_active; then
        warn "$(L '防火墙未启用时 ufw 不显示规则编号，请改用「按端口」删除')"
        return 1
    fi
    read -rp "$(L '输入要删除的规则编号（逗号分隔，如 3,5）:') " nums || { [ -n "$nums" ] || return 1; }
    nums="${nums//[[:space:]]/}"
    if [[ ! "$nums" =~ ^[0-9]+(,[0-9]+)*$ ]]; then
        warn "$(L '输入不合法，未做任何修改')"
        return 1
    fi
    listing="$(LC_ALL=C ufw status numbered 2>/dev/null || true)"
    local -a _nums=()
    while IFS= read -r n; do [ -n "$n" ] && _nums+=("$n"); done < <(printf '%s\n' "$nums" | tr ',' '\n' | sort -rnu)
    for n in "${_nums[@]}"; do
        line="$(printf '%s\n' "$listing" | grep -E "^\[ *${n}\]" || true)"
        if [ -z "$line" ]; then
            warn "$(L '编号') ${n} $(L '不存在，已跳过')"
            continue
        fi
        # v8.6（BUG-14b）：取 ALLOW/LIMIT 之前的目标列逐词检测，避免带 IP 前缀或 OpenSSH 命名规则漏判 SSH
        rule_lhs="$(printf '%s' "$line" | sed -E 's/^\[ *[0-9]+\] *//; s/[[:space:]]+(ALLOW|DENY|REJECT|LIMIT).*//')"
        is_ssh=0
        for tok in $rule_lhs; do
            if fw_spec_has_ssh_port "$tok"; then is_ssh=1; break; fi
        done
        if [ "$is_ssh" = "1" ] && [[ "$line" == *"ALLOW"* || "$line" == *"LIMIT"* ]]; then
            warn "$(L '规则') [${n}] $(L '是 SSH 端口的放行规则:') ${line#*] }"
            if ! confirm "$(L '删除后可能无法再通过 SSH 登录，确认删除？')" n; then
                info "$(L '已跳过') [${n}]"
                continue
            fi
        fi
        if ufw --force delete "$n" >/dev/null 2>&1; then
            success "$(L '已删除规则') [${n}] ${line#*] }"
        else
            warn "$(L '删除规则') [${n}] $(L '失败')"
        fi
    done
    return 0
}

fw_delete_ports() {
    fw_require || return 1
    local input="${1:-}" choice="" spec p
    if [ -n "$input" ]; then
        choice=2
    else
        echo "$(L '当前规则：')"
        ufw status numbered 2>/dev/null || true
        echo ""
        echo "$(L '删除方式：')"
        echo "  1) $(L '按规则编号（上表方括号里的数字）')"
        echo "  2) $(L '按端口')"
        read -rp "$(L '请选择') [1/2]: " choice || { [ -n "$choice" ] || return 1; }
    fi
    case "$choice" in
        1) fw_delete_by_number ;;
        2)
            if [ -z "$input" ]; then
                read -rp "$(L '输入要删除的端口（写法同放行，如 80,443 或 400-500）:') " input || { [ -n "$input" ] || return 1; }
            fi
            if ! fw_parse_specs "$input"; then
                warn "$(L '输入不合法，未做任何修改')"
                return 1
            fi
            for spec in "${FW_SPECS[@]}"; do
                p="${spec%%/*}"
                if fw_spec_has_ssh_port "$spec"; then
                    warn "${p} $(L '是当前的 SSH 端口')"
                    if ! confirm "$(L '删除后可能无法再通过 SSH 登录，确认删除？')" n; then
                        info "$(L '已跳过') ${spec}"
                        continue
                    fi
                fi
                fw_delete_spec "$spec"
            done
            ;;
        *) warn "$(L '无效选择')"; return 1 ;;
    esac
    return 0
}

fw_list() {
    fw_require || return 1
    if ufw_active; then
        ufw status numbered 2>/dev/null || true
    else
        warn "$(L '防火墙未启用，以下是已保存、启用后才生效的规则：')"
        ufw show added 2>/dev/null || true
    fi
    return 0
}

fw_status() {
    fw_require || return 1
    ufw status verbose 2>/dev/null || true
    return 0
}

# 供安装流程调用：放行指定端口。ufw 已启用时只加规则；未启用时先问再启用，
# 不再像旧版那样无条件 ufw --force enable（会把机器上其他没放行的服务一起挡掉）。
fw_allow_for_service() {
    local spec
    if ! ufw_installed; then
        warn "$(L '未安装 ufw，已跳过防火墙配置（可用主菜单「5')) $(L '防火墙」安装）；请确认云厂商安全组已放行:') $*"
        return 0
    fi
    fw_allow_ssh
    for spec in "$@"; do
        ufw allow "$spec" >/dev/null 2>&1 || warn "$(L '放行失败:') ${spec}"
    done
    if ufw_active; then
        success "$(L '防火墙已放行:') $*"
        return 0
    fi
    info "$(L 'ufw 当前未启用，已预先保存放行规则:') $*"
    fw_warn_conflicts
    fw_sync_managed >/dev/null
    fw_show_unallowed_listening
    if confirm "$(L '是否现在启用防火墙？（默认拒绝入站，仅放行已添加的端口）')" y; then
        ufw --force enable >/dev/null 2>&1 || true
        if ufw_active; then success "$(L '防火墙已启用')"; else warn "$(L '启用失败，请查看: ufw status verbose')"; fi
    else
        warn "$(L '已跳过启用防火墙，请确认云厂商安全组 / 其他防火墙已放行:') $*"
    fi
    return 0
}

# 重新配置换了端口后，清掉旧端口的放行规则（SSH、80、仍在使用的端口不动）
fw_prune_old_specs() {
    local old="$1" spec keep
    ufw_installed || return 0
    keep=" $(managed_ports | tr '\n' ' ') "
    while IFS= read -r spec; do
        [ -n "$spec" ] || continue
        if [ "$spec" = "80/tcp" ] && xray_needs_port80; then continue; fi
        [[ "$keep" == *" ${spec} "* ]] && continue
        fw_spec_has_ssh_port "$spec" && continue
        info "$(L '端口已变更，清理旧的放行规则:') ${spec}"
        fw_delete_spec "$spec"
    done < <(printf '%s\n' "$old" | tr ' ' '\n' | grep -v '^$')
    return 0
}

fw_menu() {
    local choice
    while true; do
        clear 2>/dev/null || true
        echo -e "${BOLD}${CYAN}━━━ $(L '防火墙管理（ufw）') ━━━${NC}"
        echo -e "  $(L '当前状态:') $(fw_state_text)    $(L 'SSH 端口:') $(detect_ssh_ports)"
        divider
        echo -e "  ${GREEN}1)${NC} ${GREEN}$(L '安装')${NC}$(L '防火墙（自动放行 SSH 与本脚本服务端口）')"
        echo -e "  ${GREEN}2)${NC} $(L '端口列表（带编号）')"
        echo -e "  ${GREEN}3)${NC} ${GREEN}$(L '放行')${NC}$(L '端口（TCP / UDP）')"
        echo -e "  ${GREEN}4)${NC} ${RED}$(L '删除')${NC}$(L '已放行的端口')"
        echo -e "  ${GREEN}5)${NC} ${GREEN}$(L '启用')${NC}$(L '防火墙')"
        echo -e "  ${GREEN}6)${NC} ${RED}$(L '停用')${NC}$(L '防火墙')"
        echo -e "  ${GREEN}7)${NC} $(L '防火墙状态（详细）')"
        echo -e "  ${GREEN}8)${NC} $(L '一键放行本脚本服务端口（SSH / Nowhere / Snell / Xray / Realm / Caddy）')"
        echo -e "  ${GREEN}0)${NC} $(L '返回主菜单')"
        divider
        read -rp "$(L '请选择') [0-8]: " choice || return 0
        case "$choice" in
            1) run_action fw_install ;;
            2) run_action fw_list ;;
            3) run_action fw_open_ports ;;
            4) run_action fw_delete_ports ;;
            5) run_action fw_enable ;;
            6) run_action fw_disable ;;
            7) run_action fw_status ;;
            8) run_action fw_sync_cmd ;;
            0) return 0 ;;
            *) warn "$(L '无效选择')" ;;
        esac
        pause_return
    done
}

fw_sync_cmd() {
    fw_require || return 1
    fw_allow_ssh
    info "$(L '已确认 SSH 端口放行:') $(detect_ssh_ports)"
    fw_sync_managed
    return 0
}

fw_cli() {
    local sub="${1:-menu}"
    if [ "$#" -gt 0 ]; then shift; fi
    case "$sub" in
        menu)            fw_menu ;;
        install)         fw_install ;;
        list)            fw_list ;;
        status)          fw_status ;;
        on|enable)       fw_enable ;;
        off|disable)     fw_disable ;;
        allow|open)
            [ -n "${1:-}" ] || error "$(L '用法: adam fw allow <端口')[$(L ',端口...')]$(L '>，如 adam fw allow 443/tcp,8000-8100')"
            fw_open_ports "$1" ;;
        deny|delete|close)
            [ -n "${1:-}" ] || error "$(L '用法: adam fw deny <端口')[$(L ',端口...')]>"
            fw_delete_ports "$1" ;;
        sync)            fw_sync_cmd ;;
        *) error "$(L '未知的 fw 子命令:') ${sub}$(L '（可用: install / list / status / on / off / allow <端口> / deny <端口> / sync）')" ;;
    esac
}

