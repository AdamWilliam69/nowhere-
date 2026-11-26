# ══════════════════════════════════════════════════════════════
#   Xray 端口转发（dokodemo-door，3x-ui 面板 tunnel 同款）
#   存储：${XRAY_CONF_DIR}/forward/fXX.env（600 权限）
#   渲染：${XRAY_CONF_D}/20-forward.json（单个文件含全部已启用规则的 inbounds）
#   无启用规则时删除 20-forward.json；重载失败时用 .bak 恢复并再次重载
# ══════════════════════════════════════════════════════════════

xray_fwd_rule_files() {
    local f
    [ -d "$XRAY_FWD_DIR" ] || return 0
    for f in "${XRAY_FWD_DIR}"/*.env; do
        [ -f "$f" ] && printf '%s\n' "$f"
    done
}

xray_fwd_tags() {
    local f
    [ -d "$XRAY_FWD_DIR" ] || return 0
    for f in "$XRAY_FWD_DIR"/*.env; do
        [ -f "$f" ] || continue
        basename "$f" .env
    done
    return 0
}

xray_fwd_rule_count() {
    local n=0 f
    while IFS= read -r f; do n=$((n + 1)); done < <(xray_fwd_rule_files)
    printf '%s' "$n"
}

xray_fwd_enabled_count() {
    local f n=0
    while IFS= read -r f; do
        grep -q '^FWD_ENABLED="1"$' "$f" 2>/dev/null && n=$((n + 1))
    done < <(xray_fwd_rule_files)
    printf '%s' "$n"
}

# 读取转发规则元数据到 FWD_* 变量（调用方应在子 shell 或 local 环境里用）
xray_fwd_load() {
    FWD_ID=""; FWD_ENABLED=""; FWD_REMARK=""; FWD_PROTO=""; FWD_LIP=""; FWD_LPORT=""; FWD_RHOST=""; FWD_RPORT=""; FWD_FOLLOW="0"
    [ -f "${XRAY_FWD_DIR}/$1.env" ] || return 1
    env_file_safe "${XRAY_FWD_DIR}/$1.env" || return 1
    # shellcheck disable=SC1090
    source "${XRAY_FWD_DIR}/$1.env" 2>/dev/null || return 1
    return 0
}

# 单个 env 文件的某字段值（仅数字/枚举类字段用，不含 remark 等转义值）
xray_fwd_env_get() {
    grep -m1 "^$2=" "$1" 2>/dev/null | cut -d'"' -f2 || true
}

xray_fwd_state_text() {
    local total enabled
    total="$(xray_fwd_rule_count)"
    enabled="$(xray_fwd_enabled_count)"
    if [ ! -x "$XRAY_BIN" ]; then
        printf '%s' "${YELLOW}$(L '未安装')${NC}"
        return 0
    fi
    printf '%s' "${enabled}/${total} $(L '条规则') · $(svc_state adam-xray)"
}

# 全部已启用转发规则的 ufw 端口规格（供 xray_ports / managed_ports 调用）
xray_fwd_ports() {
    local f
    while IFS= read -r f; do
        (
            env_file_safe "$f" || exit 0
            # shellcheck disable=SC1090
            source "$f" 2>/dev/null || exit 0
            [ "${FWD_ENABLED:-0}" = "1" ] || exit 0
            validate_port "${FWD_LPORT:-}" || exit 0
            case "${FWD_PROTO:-both}" in
                tcp)  echo "${FWD_LPORT}/tcp" ;;
                udp)  echo "${FWD_LPORT}/udp" ;;
                both) echo "${FWD_LPORT}/tcp"; echo "${FWD_LPORT}/udp" ;;
            esac
        )
    done < <(xray_fwd_rule_files) | sort -u
}

xray_fwd_default_listen_ip() {
    if ipv6_dualstack_ok; then
        printf '::'
    else
        printf '0.0.0.0'
    fi
}

xray_fwd_next_id() {
    local i=1 id
    while true; do
        id="$(printf 'f%02d' "$i")"
        [ ! -f "${XRAY_FWD_DIR}/${id}.env" ] && { printf '%s' "$id"; return 0; }
        i=$((i + 1))
    done
}

# 单条已启用规则的 inbound JSON（未启用/非法时不输出）
xray_fwd_rule_json() {
    local f="$1" id enabled lip lport proto rhost rport follow network fr
    env_file_safe "$f" || return 0
    id="$(xray_fwd_env_get "$f" FWD_ID)"
    enabled="$(xray_fwd_env_get "$f" FWD_ENABLED)"
    [ "$enabled" = "1" ] || return 0
    lip="$(xray_fwd_env_get "$f" FWD_LIP)"
    lport="$(xray_fwd_env_get "$f" FWD_LPORT)"
    proto="$(xray_fwd_env_get "$f" FWD_PROTO)"
    rhost="$(xray_fwd_env_get "$f" FWD_RHOST)"
    rport="$(xray_fwd_env_get "$f" FWD_RPORT)"
    follow="$(xray_fwd_env_get "$f" FWD_FOLLOW)"
    validate_port "$lport" || return 0
    validate_port "$rport" || return 0
    is_ip "$lip" 0 || return 0
    is_safe_host "$rhost" || return 0
    lport=$((10#$lport))
    rport=$((10#$rport))
    case "$proto" in
        tcp) network="tcp" ;;
        udp) network="udp" ;;
        *)   network="tcp,udp" ;;
    esac
    rhost="${rhost#[}"; rhost="${rhost%]}"
    fr="false"; [ "$follow" = "1" ] && fr="true"
    printf '%s' "{\"tag\":\"fwd-${id}\",\"listen\":\"${lip}\",\"port\":${lport},\"protocol\":\"dokodemo-door\",\"settings\":{\"address\":\"${rhost}\",\"port\":${rport},\"network\":\"${network}\",\"followRedirect\":${fr}}}"
}

# 重建 20-forward.json 并重载；失败时用 .bak 恢复并再次重载
xray_fwd_rebuild() {
    local tmpf first=1 count=0 f frag base_json="${XRAY_CONF_D}/00-base.json"
    install -d -m 750 "$XRAY_CONF_D" 2>/dev/null || true
    install -d -m 700 "$XRAY_FWD_DIR" 2>/dev/null || true
    tmpf="$(mktemp "${XRAY_CONF_D}/.20-forward.XXXXXX")" || { warn "$(L '创建临时文件失败')"; return 1; }
    {
        printf '%s\n' '{' '  "inbounds": ['
        while IFS= read -r f; do
            frag="$(xray_fwd_rule_json "$f")"
            [ -n "$frag" ] || continue
            if [ "$first" = "1" ]; then first=0; else printf '%s\n' ','; fi
            printf '%s' "    ${frag}"
            count=$((count + 1))
        done < <(xray_fwd_rule_files)
        printf '\n%s\n' '  ]' '}'
    } > "$tmpf" || { rm -f "$tmpf"; return 1; }
    [ -f "$XRAY_FWD_JSON" ] && cp -f "$XRAY_FWD_JSON" "${XRAY_FWD_JSON}.bak" || rm -f "${XRAY_FWD_JSON}.bak"
    [ -f "$base_json" ] && cp -f "$base_json" "${base_json}.bak" || rm -f "${base_json}.bak"
    if [ "$count" -eq 0 ]; then
        rm -f "$tmpf" "$XRAY_FWD_JSON"
    else
        mv -f "$tmpf" "$XRAY_FWD_JSON" || { rm -f "$tmpf"; warn "$(L '转发配置文件写入失败')"; return 1; }
        chmod 640 "$XRAY_FWD_JSON" 2>/dev/null || true
    fi
    # 同步刷新 00-base.json 中的 fwd-* 直连路由规则，确保内网/国内目标不被阻断
    xray_load_state
    xray_write_base
    xray_fix_perms
    if [ ! -x "$XRAY_BIN" ]; then
        rm -f "${XRAY_FWD_JSON}.bak" "${base_json}.bak"
        info "$(L 'Xray 未安装，转发配置已保存，重装 Xray 后生效')"
        return 0
    fi
    if xray_reload; then
        rm -f "${XRAY_FWD_JSON}.bak" "${base_json}.bak"
        return 0
    fi
    warn "$(L '转发配置重载失败，恢复上一版本')"
    if [ -f "${XRAY_FWD_JSON}.bak" ]; then mv -f "${XRAY_FWD_JSON}.bak" "$XRAY_FWD_JSON"; else rm -f "$XRAY_FWD_JSON"; fi
    if [ -f "${base_json}.bak" ]; then mv -f "${base_json}.bak" "$base_json"; fi
    xray_fix_perms
    xray_reload >/dev/null 2>&1 || warn "$(L '恢复后重载仍失败，请检查 Xray 配置与日志')"
    return 1
}

xray_fwd_add() {
    xray_require || return 1
    step "$(L '添加 Xray 端口转发')"
    divider

    local id remark proto lip lport rhost rport follow=0 proto_c def_lip occ
    read -rp "$(L '规则备注（可选）: ')" remark || { [ -n "$remark" ] || return 1; }

    echo "$(L '转发协议：')"
    echo "  1) $(L 'TCP + UDP 双栈（默认）')"
    echo "  2) $(L '纯 TCP')"
    echo "  3) $(L '纯 UDP')"
    read -rp "$(L '选择 [1-3，默认 1]: ')" proto_c || { [ -n "$proto_c" ] || return 1; }
    case "${proto_c:-1}" in 2) proto="tcp" ;; 3) proto="udp" ;; *) proto="both" ;; esac

    def_lip="$(xray_fwd_default_listen_ip)"
    while true; do
        read -rp "$(L '本机监听 IP（回车默认 ')${def_lip}$(L '）: ')" lip || { [ -n "$lip" ] || return 1; }
        lip="${lip:-$def_lip}"
        lip="${lip#[}"; lip="${lip%]}"
        is_ip "$lip" 0 && break
        warn "$(L '监听 IP 格式不合法')"
    done

    while true; do
        read -rp "$(L '本机监听端口 (1-65535): ')" lport || { [ -n "$lport" ] || return 1; }
        if ! validate_port "$lport"; then warn "$(L '端口不合法')"; continue; fi
        lport=$((10#$lport))
        if xray_port_used "$lport"; then
            warn "$(L '该端口已被本模块其他规则占用，请换一个') (${lport})"
            continue
        fi
        if command -v ss >/dev/null 2>&1; then
            occ=""
            [ "$proto" != "udp" ] && occ="$(check_port_occupied_by_other tcp "$lport" xray || true)"
            [ -z "$occ" ] && [ "$proto" != "tcp" ] && occ="$(check_port_occupied_by_other udp "$lport" xray || true)"
            if [ -n "$occ" ]; then
                warn "$(L '端口 ')${lport}$(L ' 已被其他进程占用：')"
                echo "$occ"
                confirm "$(L '仍要继续添加？')" n || continue
            fi
        fi
        break
    done

    while true; do
        read -rp "$(L '目标地址（域名或 IP）: ')" rhost || { [ -n "$rhost" ] || return 1; }
        rhost="${rhost//[[:space:]]/}"
        is_safe_host "$rhost" && break
        warn "$(L '目标地址格式不合法')"
    done
    while true; do
        read -rp "$(L '目标端口 (1-65535): ')" rport || { [ -n "$rport" ] || return 1; }
        validate_port "$rport" && break
        warn "$(L '端口不合法')"
    done
    rport=$((10#$rport))

    if confirm "$(L '跟随系统重定向（followRedirect，仅配合 iptables 转发规则使用）？')" n; then follow=1; fi

    id="$(xray_fwd_next_id)"
    local env_file="${XRAY_FWD_DIR}/${id}.env"
    install -d -m 700 "$XRAY_FWD_DIR"
    ( umask 077; cat > "$env_file" ) << FWDEOF
FWD_ID="${id}"
FWD_ENABLED="1"
FWD_REMARK="$(dq_escape "$remark")"
FWD_PROTO="${proto}"
FWD_LIP="${lip}"
FWD_LPORT="${lport}"
FWD_RHOST="${rhost}"
FWD_RPORT="${rport}"
FWD_FOLLOW="${follow}"
FWDEOF
    chmod 600 "$env_file"

    if ! xray_fwd_rebuild; then
        rm -f "$env_file"
        xray_fwd_rebuild >/dev/null 2>&1 || true
        error "$(L '新转发规则未能生效，已自动撤回')"
    fi

    local -a fw_specs=()
    [ "$proto" != "udp" ] && fw_specs+=("${lport}/tcp")
    [ "$proto" != "tcp" ] && fw_specs+=("${lport}/udp")
    fw_allow_for_service "${fw_specs[@]}"
    reserved_ports_sync || true
    success "$(L '转发规则 ')${id}$(L ' 已生效：')${lip}:${lport} -> ${rhost}:${rport}"
}

xray_fwd_list() {
    step "$(L 'Xray 转发规则列表')"
    divider
    local f idx=0 tags status
    while IFS= read -r f; do
        idx=$((idx + 1))
        (
            env_file_safe "$f" || exit 0
            # shellcheck disable=SC1090
            source "$f" 2>/dev/null || exit 0
            tags=""
            [ "${FWD_PROTO:-both}" = "tcp" ] && tags="${tags}[$(L '纯TCP')]"
            [ "${FWD_PROTO:-both}" = "udp" ] && tags="${tags}[$(L '纯UDP')]"
            [ "${FWD_FOLLOW:-0}" = "1" ] && tags="${tags}[followRedirect]"
            if [ "${FWD_ENABLED:-0}" = "1" ]; then
                status="${GREEN}$(L '启用')${NC}"
            else
                status="${YELLOW}$(L '停用')${NC}"
            fi
            echo -e "  ${BOLD}${idx})${NC} [${FWD_ID}] ${status}  ${CYAN}${FWD_LIP}:${FWD_LPORT}${NC} -> ${GREEN}${FWD_RHOST}:${FWD_RPORT}${NC} ${tags}${FWD_REMARK:+  # ${FWD_REMARK}}"
        )
    done < <(xray_fwd_rule_files)
    if [ "$idx" -eq 0 ]; then
        info "$(L '暂无转发规则')"
    fi
}

xray_fwd_pick() {
    local -a files=()
    local f choice
    while IFS= read -r f; do files+=("$f"); done < <(xray_fwd_rule_files)
    [ "${#files[@]}" -gt 0 ] || { info "$(L '暂无规则')"; return 1; }
    xray_fwd_list
    echo ""
    read -rp "$(L '输入规则序号（回车取消）: ')" choice || { [ -n "$choice" ] || return 1; }
    [[ -n "$choice" && "$choice" =~ ^[0-9]+$ ]] || return 1
    choice=$((10#$choice))
    [ "$choice" -ge 1 ] && [ "$choice" -le "${#files[@]}" ] || { warn "$(L '序号无效')"; return 1; }
    PICKED_FWD_FILE="${files[$((choice - 1))]}"
    return 0
}

xray_fwd_toggle() {
    xray_fwd_pick || return 0
    local f="$PICKED_FWD_FILE" cur next bak="${PICKED_FWD_FILE}.bak" lport proto
    env_file_safe "$f" || { warn "$(L '规则文件内容非法，已跳过：')${f}"; return 1; }
    cur="$(grep -m1 '^FWD_ENABLED=' "$f" | cut -d'"' -f2 || echo 0)"
    lport="$(grep -m1 '^FWD_LPORT=' "$f" | cut -d'"' -f2 || true)"
    proto="$(grep -m1 '^FWD_PROTO=' "$f" | cut -d'"' -f2 || echo both)"
    if [ "$cur" = "1" ]; then next="0"; else next="1"; fi
    cp -f "$f" "$bak" || return 1
    if grep -q '^FWD_ENABLED=' "$f"; then
        sed -i "s|^FWD_ENABLED=.*|FWD_ENABLED=\"${next}\"|" "$f" || { mv -f "$bak" "$f"; warn "$(L '规则状态切换失败')"; return 1; }
    else
        printf '%s\n' "FWD_ENABLED=\"${next}\"" >> "$f"
    fi
    if ! xray_fwd_rebuild; then
        mv -f "$bak" "$f"
        xray_fwd_rebuild >/dev/null 2>&1 || true
        warn "$(L '规则状态切换失败')"
        return 1
    fi
    rm -f "$bak"
    if [ "$next" = "1" ] && validate_port "$lport"; then
        local -a fw_specs=()
        [ "$proto" != "udp" ] && fw_specs+=("${lport}/tcp")
        [ "$proto" != "tcp" ] && fw_specs+=("${lport}/udp")
        fw_allow_for_service "${fw_specs[@]}"
    fi
    reserved_ports_sync || true
    success "$(L '规则状态已切换为：')$([ "$next" = "1" ] && echo "$(L '启用')" || echo "$(L '停用')")"
    return 0
}

xray_fwd_delete() {
    xray_fwd_pick || return 0
    local f="$PICKED_FWD_FILE" bak="${PICKED_FWD_FILE}.bak" old_port old_proto fid flip frhost frport
    fid="$(grep -m1 '^FWD_ID=' "$f" | cut -d'"' -f2 || true)"
    flip="$(grep -m1 '^FWD_LIP=' "$f" | cut -d'"' -f2 || true)"
    old_port="$(grep -m1 '^FWD_LPORT=' "$f" | cut -d'"' -f2 || true)"
    old_proto="$(grep -m1 '^FWD_PROTO=' "$f" | cut -d'"' -f2 || true)"
    frhost="$(grep -m1 '^FWD_RHOST=' "$f" | cut -d'"' -f2 || true)"
    frport="$(grep -m1 '^FWD_RPORT=' "$f" | cut -d'"' -f2 || true)"
    confirm "$(L '确认删除规则 [')${fid}] ${flip}:${old_port} -> ${frhost}:${frport}$(L ']？')" n || return 0
    mv -f "$f" "$bak" || return 1
    if ! xray_fwd_rebuild; then
        mv -f "$bak" "$f"
        xray_fwd_rebuild >/dev/null 2>&1 || true
        warn "$(L '服务重载失败，删除未生效，请检查日志')"
        return 1
    fi
    rm -f "$bak"
    if ufw_installed && validate_port "$old_port"; then
        local old_specs=""
        [ "$old_proto" != "udp" ] && old_specs="${old_specs} ${old_port}/tcp"
        [ "$old_proto" != "tcp" ] && old_specs="${old_specs} ${old_port}/udp"
        fw_prune_old_specs "$old_specs"
    fi
    reserved_ports_sync || true
    success "$(L '已删除规则 ')${fid}"
    return 0
}

# TCP 目标连通性与延迟检测（与 realm_test_rules 共用 probe_tcp_host_port）
xray_fwd_test() {
    step "$(L '转发目标连通性测试（TCP 握手延迟）')"
    divider
    local f any=0
    while IFS= read -r f; do
        any=1
        (
            env_file_safe "$f" || exit 0
            # shellcheck disable=SC1090
            source "$f" 2>/dev/null || exit 0
            local res
            if [ "${FWD_PROTO:-both}" = "udp" ]; then
                echo -e "  [${FWD_ID}] ${FWD_RHOST}:${FWD_RPORT}  $(L '跳过（纯 UDP 无法做 TCP 握手探测）')  ${FWD_REMARK}"
                exit 0
            fi
            res="$(probe_tcp_host_port "$FWD_RHOST" "$FWD_RPORT")"
            if [[ "$res" == OK* ]]; then
                echo -e "  [${FWD_ID}] ${FWD_RHOST}:${FWD_RPORT}  ${GREEN}${res}${NC}  ${FWD_REMARK}"
            else
                echo -e "  [${FWD_ID}] ${FWD_RHOST}:${FWD_RPORT}  ${RED}${res}${NC}  ${FWD_REMARK}"
            fi
        )
    done < <(xray_fwd_rule_files)
    if [ "$any" -eq 0 ]; then info "$(L '暂无可测试的规则')"; fi
    return 0
}

xray_fwd_menu() {
    local choice
    while true; do
        clear 2>/dev/null || true
        echo -e "${BOLD}${CYAN}━━━ $(L 'Xray 端口转发（dokodemo-door）') ━━━${NC}"
        echo -e "  $(L '当前状态:') $(xray_fwd_state_text)"
        divider
        echo -e "  ${GREEN}1)${NC}  $(L '添加转发规则')"
        echo -e "  ${GREEN}2)${NC}  $(L '查看转发规则列表')"
        echo -e "  ${GREEN}3)${NC}  $(L '启用 / 停用单条规则')"
        echo -e "  ${GREEN}4)${NC}  $(L '删除转发规则')"
        echo -e "  ${GREEN}5)${NC}  $(L '测试目标连通性与延迟')"
        echo -e "  ${GREEN}6)${NC}  $(L '重启服务 / 查看状态与日志')"
        echo -e "  ${GREEN}0)${NC}  $(L '返回 Xray 菜单')"
        divider
        read -rp "$(L '请选择') [0-6]: " choice || return 0
        case "$choice" in
            1) run_action xray_fwd_add ;;
            2) run_action xray_fwd_list ;;
            3) run_action xray_fwd_toggle ;;
            4) run_action xray_fwd_delete ;;
            5) run_action xray_fwd_test ;;
            6) run_action bash -c 'systemctl restart adam-xray 2>/dev/null || true; systemctl status adam-xray --no-pager || true; journalctl -u adam-xray -n 20 --no-pager || true' ;;
            0) return 0 ;;
            *) warn "$(L '无效选择')" ;;
        esac
        pause_return
    done
}

xray_fwd_cli() {
    local sub="${1:-menu}"
    [ "$#" -gt 0 ] && shift
    case "$sub" in
        menu)      xray_fwd_menu ;;
        add)       xray_fwd_add ;;
        list)      xray_fwd_list ;;
        toggle)    xray_fwd_toggle ;;
        delete)    xray_fwd_delete ;;
        test)      xray_fwd_test ;;
        restart)   xray_fwd_rebuild && success "$(L 'Xray 转发已重启')" ;;
        status)    systemctl status adam-xray --no-pager || true ;;
        *) error "$(L '未知的 xray fwd 子命令:') ${sub}$(L '（可用: add / list / toggle / delete / test / restart / status）')" ;;
    esac
}

