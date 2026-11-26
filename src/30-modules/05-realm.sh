# ══════════════════════════════════════════════════════════════
#   Realm 端口转发（参考 zywe03/realm-xwPF · 适配 adam 脚本架构）
#   合并配置：由 00-base.toml + rule-<id>.toml 原子合并为 /etc/adam-realm/config.toml（realm -c /etc/adam-realm/config.toml）
#   规则元数据：/etc/adam-realm/rules/<id>.env（600 权限）
#   v8.4 合入时按审计逐项修正（A1–A25，见文件头修订记录）
# ══════════════════════════════════════════════════════════════

realm_installed() { [ -x "$REALM_BIN" ]; }

realm_rule_files() {
    local f
    [ -d "$REALM_RULE_DIR" ] || return 0
    for f in "${REALM_RULE_DIR}"/*.env; do
        [ -f "$f" ] && printf '%s\n' "$f"
    done
}

realm_enabled_count() {
    local f n=0
    while IFS= read -r f; do
        grep -q '^RULE_ENABLED="1"$' "$f" 2>/dev/null && n=$((n + 1))
    done < <(realm_rule_files)
    printf '%s' "$n"
}

realm_state_text() {
    local total=0 enabled=0 f ver
    if ! realm_installed; then
        printf '%s' "${YELLOW}$(L '未安装')${NC}"
        return 0
    fi
    while IFS= read -r f; do
        total=$((total + 1))
        grep -q '^RULE_ENABLED="1"$' "$f" 2>/dev/null && enabled=$((enabled + 1))
    done < <(realm_rule_files)
    ver="$(cat "$REALM_VERSION_FILE" 2>/dev/null || echo "$(L '未知')")"
    printf '%s' "${ver} · ${enabled}/${total} $(L '条规则') · $(svc_state adam-realm)"
}

# 输出所有已启用规则的 ufw 端口规格（供 managed_ports / 防火墙 / 保留端口调用）
realm_ports() {
    local f
    while IFS= read -r f; do
        (
            env_file_safe "$f" || exit 0
            # shellcheck disable=SC1090
            source "$f" 2>/dev/null || exit 0
            [ "${RULE_ENABLED:-0}" = "1" ] || exit 0
            validate_port "${RULE_LPORT:-}" || exit 0
            case "${RULE_PROTO:-both}" in
                tcp)  echo "${RULE_LPORT}/tcp" ;;
                udp)  echo "${RULE_LPORT}/udp" ;;
                both) echo "${RULE_LPORT}/tcp"; echo "${RULE_LPORT}/udp" ;;
            esac
        )
    done < <(realm_rule_files) | sort -u
}

# 供 watchdog 保活巡检调用：有启用规则时要求服务 active 且每个监听端口真实在监听
realm_healthy() {
    [ "$(realm_enabled_count)" -gt 0 ] || return 0
    realm_installed || return 1
    systemctl is-active --quiet adam-realm 2>/dev/null || return 1
    command -v ss >/dev/null 2>&1 || return 1
    local spec port proto
    while IFS= read -r spec; do
        [ -n "$spec" ] || continue
        port="${spec%/*}"; proto="${spec#*/}"
        if [ "$proto" = "udp" ]; then
            udp_listening "$port" || return 1
        else
            tcp_listening "$port" || return 1
        fi
    done < <(realm_ports)
    return 0
}

realm_wait_healthy() {
    local i
    for i in 1 2 3 4 5; do
        realm_healthy && return 0
        sleep 1
    done
    return 1
}

# IPv6 双栈监听是否真正可用（内核启用 IPv6 且未设置 bindv6only=1）
ipv6_dualstack_ok() {
    [ -r /proc/sys/net/ipv6/conf/all/disable_ipv6 ] || return 1
    [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo 1)" = "0" ] || return 1
    [ "$(cat /proc/sys/net/ipv6/conf/default/disable_ipv6 2>/dev/null || echo 0)" = "0" ] || return 1
    [ "$(cat /proc/sys/net/ipv6/bindv6only 2>/dev/null || echo 0)" != "1" ]
}

# 检查某个 ufw 端口规格（如 443/tcp）是否仍被除 $2 以外的其他已安装服务使用
# 仅统计二进制或 systemd 服务文件实际存在的组件，避免已卸载但保留配置目录时产生幽灵端口占用
port_used_by_other_services() {
    # v8.6（BUG-16）：先把端口清单收进变量再 grep -q；直接 `生产者 | grep -q` 在 pipefail 下
    # grep 提前退出会让生产者吃 SIGPIPE（141），if 判定为假 → 漏判端口冲突
    local spec="$1" excl="${2:-}" _pu_list=""
    if [ "$excl" != "nowhere" ] && { [ -x "$BIN_PATH" ] || [ -f "$SERVICE_FILE" ]; }; then
        _pu_list="$(nowhere_ports 2>/dev/null || true)"
        if grep -qx -- "$spec" <<< "$_pu_list"; then return 0; fi
    fi
    if [ "$excl" != "snell" ] && [[ "$spec" == */tcp ]] && { [ -x "$SNELL_BIN" ] || [ -f "$SNELL_SERVICE" ]; }; then
        _pu_list="$(snell_all_ports 2>/dev/null || true)"
        if grep -qx -- "${spec%/tcp}" <<< "$_pu_list"; then return 0; fi
    fi
    if [ "$excl" != "xray" ] && { [ -x "$XRAY_BIN" ] || [ -f "$XRAY_SERVICE" ]; }; then
        _pu_list="$(xray_ports 2>/dev/null || true)"
        if grep -qx -- "$spec" <<< "$_pu_list"; then return 0; fi
        if [ "$spec" = "80/tcp" ] && xray_needs_port80 2>/dev/null; then return 0; fi
    fi
    if [ "$excl" != "realm" ] && { realm_installed || [ -f "$REALM_SERVICE" ]; }; then
        _pu_list="$(realm_ports 2>/dev/null || true)"
        if grep -qx -- "$spec" <<< "$_pu_list"; then return 0; fi
    fi
    if [ "$excl" != "caddy" ] && { caddy_installed || [ -f "$CADDY_SERVICE" ]; }; then
        _pu_list="$(caddy_ports 2>/dev/null || true)"
        if grep -qx -- "$spec" <<< "$_pu_list"; then return 0; fi
    fi
    return 1
}

# 严格拆分 host:port（IPv6 必须带方括号 [::1]:443，拒绝裸 IPv6 或方括号包 IPv4）
realm_split_host_port() {
    local item="$1" hvar="$2" pvar="$3" h="" p=""
    if [[ "$item" =~ ^\[([^]]+)\]:([0-9]+)$ ]]; then
        [[ "${BASH_REMATCH[1]}" == *:* ]] || return 1
        h="[${BASH_REMATCH[1]}]"; p="${BASH_REMATCH[2]}"
        is_ip "${BASH_REMATCH[1]}" 0 || return 1
    elif [[ "$item" =~ ^([^:]+):([0-9]+)$ ]]; then
        h="${BASH_REMATCH[1]}"; p="${BASH_REMATCH[2]}"
        is_safe_host "$h" || return 1
    else
        return 1
    fi
    validate_port "$p" || return 1
    p=$((10#$p))
    printf -v "$hvar" '%s' "$h"
    printf -v "$pvar" '%s' "$p"
    return 0
}

realm_default_listen_ip() {
    if ipv6_dualstack_ok; then
        printf '[::]'
    else
        printf '0.0.0.0'
    fi
}

# TOML 双引号字符串转义（只处理 \ 与 "；输入侧已拒绝 " \ 换行）
toml_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    printf '%s' "$s"
}

# 值含 TOML 双引号字符串非法字符（" 或 \）时返回 0（非法）
realm_has_toml_special() {
    case "$1" in *\"*|*\\*|*$'\n'*|*$'\r'*|*$'\t'*) return 0 ;; *) return 1 ;; esac
}

realm_latest_tag() {
    github_latest_tag "$REALM_REPO"
}

realm_fetch_binary() {
    local tag="$1" arch libc asset url digest actual bin
    case "$(uname -m)" in
        x86_64|amd64)  arch="x86_64" ;;
        aarch64|arm64) arch="aarch64" ;;
        *) warn "$(L 'Realm 暂不支持该架构：')$(uname -m)"; return 1 ;;
    esac

    REALM_DL_BIN=""
    make_workdir || return 1
    local workdir="$WORKDIR"
    # 优先 musl 静态构建，避免老系统 GLIBC 版本过低无法运行；
    # 任一构建下载/校验/试运行失败即试另一构建，两个都失败才报错。
    for libc in musl gnu; do
        asset="realm-${arch}-unknown-linux-${libc}.tar.gz"
        url="https://github.com/${REALM_REPO}/releases/download/${tag}/${asset}"
        local subdir="${workdir}/${libc}"
        mkdir -p "$subdir" || { asset=""; continue; }
        if ! secure_curl -fL --retry 3 --connect-timeout 10 --max-time 300 -o "${subdir}/realm.tar.gz" "$url" 2>/dev/null; then
            asset=""; continue
        fi

        actual="$(sha256sum "${subdir}/realm.tar.gz" | awk '{print tolower($1)}')"
        digest="$(github_asset_sha256 "$REALM_REPO" "$tag" "$asset" || true)"
        if [[ "$digest" =~ ^[0-9a-f]{64}$ ]]; then
            if [ "$digest" != "$actual" ]; then
                warn "$(L 'SHA256 校验失败（')${asset}$(L '），尝试另一构建')"
                asset=""; continue
            fi
            success "$(L 'SHA256 校验通过（')${asset}$(L '）')"
        else
            warn "$(L '未取到官方 SHA256 摘要（')${asset}$(L '）')"
            if [ ! -t 0 ] || ! confirm "$(L '未能获取官方摘要，是否仍继续安装？')" n; then
                asset=""; continue
            fi
        fi

        tar -xzf "${subdir}/realm.tar.gz" --no-same-owner -C "$subdir" || { asset=""; continue; }
        bin="$(find "$subdir" -maxdepth 2 -type f -name realm ! -type l 2>/dev/null | head -1 || true)"
        [ -n "$bin" ] || { asset=""; continue; }
        verify_elf_binary "$bin" || { warn "$(L '下载到的二进制不是本机架构的 ELF 可执行文件，已中止')"; asset=""; continue; }
        chmod 755 "$bin" || { asset=""; continue; }
        if command -v timeout >/dev/null 2>&1; then
            if ! timeout 10 "$bin" --version >/dev/null 2>&1; then
                warn "$(L '下载的 realm 无法在本机运行，尝试另一构建')"
                asset=""; continue
            fi
        elif ! "$bin" --version >/dev/null 2>&1; then
            warn "$(L '下载的 realm 无法在本机运行，尝试另一构建')"
            asset=""; continue
        fi
        REALM_DL_BIN="$bin"
        return 0
    done
    warn "$(L '下载 Realm ')${tag}$(L ' 失败')"
    return 1
}

realm_fix_perms() {
    local f has_grp=0
    getent group adam-realm >/dev/null 2>&1 && has_grp=1
    if [ -d "$REALM_DIR" ] && [ ! -L "$REALM_DIR" ]; then
        if [ "$has_grp" -eq 1 ] && [ ! -f "${REALM_DIR}/run-as-root" ]; then
            chown -h root:adam-realm "$REALM_DIR" 2>/dev/null || true
            chmod 750 "$REALM_DIR" 2>/dev/null || true
        else
            chown -h root:root "$REALM_DIR" 2>/dev/null || true
            chmod 750 "$REALM_DIR" 2>/dev/null || true
        fi
    fi
    if [ -d "$REALM_CONF_D" ] && [ ! -L "$REALM_CONF_D" ]; then
        chown -h root:root "$REALM_CONF_D" 2>/dev/null || true
        chmod 750 "$REALM_CONF_D" 2>/dev/null || true
        for f in "${REALM_CONF_D}"/*.toml; do
            [ -f "$f" ] && [ ! -L "$f" ] || continue
            chown -h root:root "$f" 2>/dev/null || true
            chmod 640 "$f" 2>/dev/null || true
        done
    fi
    if [ -d "$REALM_RULE_DIR" ] && [ ! -L "$REALM_RULE_DIR" ]; then
        chown -h root:root "$REALM_RULE_DIR" 2>/dev/null || true
        chmod 700 "$REALM_RULE_DIR" 2>/dev/null || true
        for f in "${REALM_RULE_DIR}"/*.env; do
            [ -f "$f" ] && [ ! -L "$f" ] || continue
            chown -h root:root "$f" 2>/dev/null || true
            chmod 600 "$f" 2>/dev/null || true
        done
    fi
    if [ -f "$REALM_CONFIG_FILE" ] && [ ! -L "$REALM_CONFIG_FILE" ]; then
        if [ "$has_grp" -eq 1 ] && [ ! -f "${REALM_DIR}/run-as-root" ]; then
            chown -h root:adam-realm "$REALM_CONFIG_FILE" 2>/dev/null || true
            chmod 640 "$REALM_CONFIG_FILE" 2>/dev/null || true
        else
            chown -h root:root "$REALM_CONFIG_FILE" 2>/dev/null || true
            chmod 600 "$REALM_CONFIG_FILE" 2>/dev/null || true
        fi
    fi
    if [ -f "$REALM_VERSION_FILE" ] && [ ! -L "$REALM_VERSION_FILE" ]; then
        chown -h root:root "$REALM_VERSION_FILE" 2>/dev/null || true
        chmod 644 "$REALM_VERSION_FILE" 2>/dev/null || true
    fi
}

realm_write_base_config() {
    install -d -m 750 "$REALM_DIR" "$REALM_CONF_D"
    install -d -m 700 "$REALM_RULE_DIR"
    if [ ! -f "${REALM_CONF_D}/00-base.toml" ]; then
        cat > "${REALM_CONF_D}/00-base.toml" << 'BASEEOF'
[log]
level = "warn"
output = "stdout"

[dns]
mode = "ipv4_and_ipv6"
protocol = "tcp_and_udp"
min_ttl = 600
max_ttl = 3600
cache_size = 256

[network]
no_tcp = false
use_udp = true
tcp_timeout = 5
udp_timeout = 30
tcp_keepalive = 15
tcp_keepalive_probe = 3
BASEEOF
        chmod 640 "${REALM_CONF_D}/00-base.toml"
    fi
}

realm_write_service() {
    local run_user="adam-realm" run_group="adam-realm"
    if [ -f "${REALM_DIR}/run-as-root" ]; then
        # 曾因专用用户启动失败而回退 root：不再写回 User=（见 realm_reload_service）
        run_user=""; run_group=""
    elif ! ensure_system_user adam-realm adam-realm 2>/dev/null; then
        warn "$(L '创建 adam-realm 用户失败，改以 root 运行服务')"
        run_user=""; run_group=""
    fi
    write_service_unit "$REALM_SERVICE" "Adam Realm Port Forwarder" "https://github.com/${REALM_REPO}" "60" "$run_user" "$run_group" "${REALM_BIN} -c ${REALM_CONFIG_FILE}" "CAP_NET_BIND_SERVICE CAP_NET_RAW" "1048576" "always" "3" "ProtectSystem=full
ProtectHome=read-only" "StartLimitBurst=10"
    systemctl daemon-reload || true
}

# 校验 .env 文件内容是否可安全 source（委托全局 env_file_safe）
realm_env_file_safe() {
    env_file_safe "$1"
}

# 将单条 rules/<id>.env 渲染为 conf.d/rule-<id>.toml（停用时删除对应 .toml）
realm_render_rule() {
    local id="$1"
    local env_file="${REALM_RULE_DIR}/${id}.env"
    local toml_file="${REALM_CONF_D}/rule-${id}.toml"
    [ -f "$env_file" ] || { rm -f "$toml_file"; return 0; }
    (
        env_file_safe "$env_file" || exit 1
        # shellcheck disable=SC1090
        source "$env_file" 2>/dev/null || exit 1
        if [ "${RULE_ENABLED:-0}" != "1" ]; then
            rm -f "$toml_file"
            exit 0
        fi
        # 渲染是最后一道防线：端口/IP 非法、手改或导入的坏值直接跳过本规则
        validate_port "${RULE_LPORT:-}" || exit 1
        validate_port "${RULE_RPORT:-}" || exit 1
        is_safe_host "${RULE_RHOST:-}" || exit 1
        local _lip="${RULE_LIP:-}"
        if [[ "$_lip" == "["*"]" ]]; then
            _lip="${_lip#[}"; _lip="${_lip%]}"
            [[ "$_lip" == *:* ]] || exit 1
        elif [[ "$_lip" == *"["* || "$_lip" == *"]"* ]]; then
            exit 1
        fi
        is_ip "$_lip" 0 || exit 1
        # 换行/回车绝不能进 TOML（导入或手改的 env 可能带换行）
        case "${RULE_REMARK:-}${RULE_LTRANS:-}${RULE_RTRANS:-}${RULE_LIP:-}${RULE_RHOST:-}${RULE_THROUGH:-}${RULE_OUT_IF:-}${RULE_IN_IF:-}${RULE_EXTRA_REMOTES:-}${RULE_BALANCE:-}" in
            *$'\n'*|*$'\r'*) exit 1 ;;
        esac
        local tmpf
        tmpf="$(mktemp "${REALM_CONF_D}/.rule-${id}.XXXXXX")" || exit 1
        local no_tcp="false" use_udp="true"
        case "${RULE_PROTO:-both}" in
            tcp) no_tcp="false"; use_udp="false" ;;
            udp) no_tcp="true";  use_udp="true" ;;
            *)   no_tcp="false"; use_udp="true" ;;
        esac
        local lport_n=$((10#$RULE_LPORT)) rport_n=$((10#$RULE_RPORT)) laddr raddr
        laddr="$(format_host_for_url "$_lip"):${lport_n}"
        raddr="$(format_host_for_url "$RULE_RHOST"):${rport_n}"

        {
            echo "# id=${id} remark=$(toml_escape "${RULE_REMARK:-}")"
            echo "[[endpoints]]"
            echo "listen = \"$(toml_escape "$laddr")\""
            echo "remote = \"$(toml_escape "$raddr")\""
            if [ -n "${RULE_EXTRA_REMOTES:-}" ]; then
                local arr="" item ehost eport
                local -a extras=()
                IFS=',' read -r -a extras <<< "$RULE_EXTRA_REMOTES"
                for item in "${extras[@]}"; do
                    item="${item//[[:space:]]/}"
                    [ -n "$item" ] || continue
                    realm_split_host_port "$item" ehost eport || continue
                    arr="${arr:+${arr}, }\"$(toml_escape "$(format_host_for_url "$ehost"):${eport}")\""
                done
                [ -n "$arr" ] && echo "extra_remotes = [${arr}]"
                [ -n "$arr" ] && [ -n "${RULE_BALANCE:-}" ] && echo "balance = \"$(toml_escape "$RULE_BALANCE")\""
            fi
            [ -n "${RULE_THROUGH:-}" ] && echo "through = \"$(toml_escape "$RULE_THROUGH")\""
            [ -n "${RULE_OUT_IF:-}" ] && echo "interface = \"$(toml_escape "$RULE_OUT_IF")\""
            [ -n "${RULE_IN_IF:-}" ] && echo "listen_interface = \"$(toml_escape "$RULE_IN_IF")\""
            if [ "${RULE_PROTO:-both}" != "udp" ]; then
                [ -n "${RULE_LTRANS:-}" ] && echo "listen_transport = \"$(toml_escape "$RULE_LTRANS")\""
                [ -n "${RULE_RTRANS:-}" ] && echo "remote_transport = \"$(toml_escape "$RULE_RTRANS")\""
            fi
            local net="no_tcp = ${no_tcp}, use_udp = ${use_udp}"
            [ "${RULE_SEND_PROXY:-0}" = "1" ]   && net="${net}, send_proxy = true, send_proxy_version = 2"
            [ "${RULE_ACCEPT_PROXY:-0}" = "1" ] && net="${net}, accept_proxy = true"
            [ "${RULE_SEND_MPTCP:-0}" = "1" ]   && net="${net}, send_mptcp = true"
            [ "${RULE_ACCEPT_MPTCP:-0}" = "1" ] && net="${net}, accept_mptcp = true"
            echo "network = { ${net} }"
        } > "$tmpf" || { rm -f "$tmpf"; exit 1; }
        chmod 640 "$tmpf"
        mv -f "$tmpf" "$toml_file"
    )
}

realm_rebuild_all() {
    realm_write_base_config
    local f id rc=0
    while IFS= read -r f; do
        id="$(basename "$f" .env)"
        if ! realm_env_file_safe "$f"; then
            warn "$(L '规则文件内容非法，已跳过：')${id}"
            rm -f "${REALM_CONF_D}/rule-${id}.toml"
            rc=1
            continue
        fi
        if ! realm_render_rule "$id"; then
            warn "$(L '规则渲染失败，已跳过：')${id}"
            rm -f "${REALM_CONF_D}/rule-${id}.toml"
            rc=1
        fi
    done < <(realm_rule_files)
    # 删除无对应 .env 的残留 rule-*.toml（逐个渲染后再清理，不断档）
    local t
    for t in "${REALM_CONF_D}"/rule-*.toml; do
        [ -f "$t" ] || continue
        id="$(basename "$t" .toml)"
        id="${id#rule-}"
        [ -f "${REALM_RULE_DIR}/${id}.env" ] || rm -f "$t"
    done
    if [ "$rc" -ne 0 ]; then
        return 1
    fi
    # 合并为单个 /etc/adam-realm/config.toml：zhboner/realm 目录模式要求每个 .toml 都含 endpoints 字段，
    # 单独的 00-base.toml 会触发 missing field `endpoints` 崩溃；合并单文件同时避免目录读取顺序不确定。
    # 注意：00-base.toml 末尾是 [network] 表，无启用规则时必须在表头之前（文件顶部）写根级 endpoints = []。
    local tmpcfg ep_cnt=0
    for t in "${REALM_CONF_D}"/rule-*.toml; do
        [ -f "$t" ] && ep_cnt=$((ep_cnt + 1))
    done
    tmpcfg="$(mktemp "${REALM_DIR}/.config.toml.XXXXXX")" || return 1
    {
        if [ "$ep_cnt" -eq 0 ]; then
            printf 'endpoints = []\n\n'
        fi
        if [ -f "${REALM_CONF_D}/00-base.toml" ]; then
            # 剔除可能残留的空 endpoints = []，避免与后续 [[endpoints]] 产生 TOML 重复键冲突
            grep -vE '^[[:space:]]*endpoints[[:space:]]*=[[:space:]]*\[\][[:space:]]*$' "${REALM_CONF_D}/00-base.toml" || true
        fi
        for t in "${REALM_CONF_D}"/rule-*.toml; do
            [ -f "$t" ] || continue
            printf '\n'
            cat "$t"
        done
    } > "$tmpcfg" || { rm -f "$tmpcfg"; return 1; }
    # 若系统自带 Python 3.11+ tomllib，在覆盖生效配置前先做 TOML 语法与 endpoints 字段校验
    if command -v python3 >/dev/null 2>&1; then
        if ! python3 -c 'import sys
try: import tomllib
except ImportError: sys.exit(0)
with open(sys.argv[1], "rb") as fh: d = tomllib.load(fh)
assert isinstance(d.get("endpoints"), list), "missing endpoints"' "$tmpcfg" 2>/dev/null; then
            rm -f "$tmpcfg"
            warn "$(L '配置校验未通过：')${REALM_CONFIG_FILE}"
            return 1
        fi
    fi
    chmod 640 "$tmpcfg"
    mv -f "$tmpcfg" "$REALM_CONFIG_FILE"
    realm_fix_perms
}

# 有启用规则时 enable+启动；无规则时 disable+停止；是否 enable 由此处决定
realm_reload_service() {
    if ! realm_installed && [ ! -d "$REALM_DIR" ]; then
        info "$(L 'Realm 未安装，规则配置已保存，安装后生效')"
        return 0
    fi
    realm_rebuild_all || return 1
    if [ "$(realm_enabled_count)" -eq 0 ]; then
        systemctl disable --now adam-realm 2>/dev/null || true
        info "$(L '当前没有已启用的转发规则，adam-realm 已停止')"
        return 0
    fi
    if ! realm_installed; then
        info "$(L 'Realm 未安装，规则配置已保存，安装后生效')"
        return 0
    fi
    # 旧版服务文件若仍指向目录 -c conf.d，自动迁移为单文件 -c config.toml
    if [ ! -f "$REALM_SERVICE" ] || grep -q -- "-c ${REALM_CONF_D}" "$REALM_SERVICE" 2>/dev/null; then
        realm_write_service
    fi
    realm_fix_perms
    systemctl enable adam-realm >/dev/null 2>&1 || true
    if svc_restart_wait adam-realm 2 20 && realm_wait_healthy; then
        return 0
    fi
    # 专用用户启动失败或端口绑定失败（如特权端口/证书权限）时改以 root 重试一次
    if grep -q '^User=' "$REALM_SERVICE" 2>/dev/null; then
        local _svc_bak="${REALM_SERVICE}.rootbak"
        warn "$(L 'adam-realm 以专用用户启动失败，改以 root 重试')"
        cp -p "$REALM_SERVICE" "$_svc_bak" 2>/dev/null || true
        sed -i '/^User=/d; /^Group=/d' "$REALM_SERVICE" || { [ -f "$_svc_bak" ] && mv -f "$_svc_bak" "$REALM_SERVICE"; warn "$(L '改写服务文件失败')"; return 1; }
        systemctl daemon-reload || true
        touch "${REALM_DIR}/run-as-root" 2>/dev/null || true
        realm_fix_perms
        if svc_restart_wait adam-realm 2 20 && realm_wait_healthy; then
            rm -f "$_svc_bak"
            info "$(L '已记录 root 运行标记，下次安装不再写入专用用户：')${REALM_DIR}/run-as-root"
            return 0
        fi
        rm -f "${REALM_DIR}/run-as-root" 2>/dev/null || true
        if [ -f "$_svc_bak" ]; then mv -f "$_svc_bak" "$REALM_SERVICE"; fi
        systemctl daemon-reload || true
        realm_fix_perms
    fi
    warn "$(L 'adam-realm 启动失败，请查看日志：journalctl -u adam-realm -n 20 --no-pager')"
    return 1
}

_realm_repair_core() {
    local quiet="${1:-}" spec
    realm_installed || return 1
    realm_write_base_config
    realm_write_service
    realm_rebuild_all || return 1
    realm_fix_perms
    if ufw_active; then
        while IFS= read -r spec; do
            [ -n "$spec" ] && { ufw allow "$spec" >/dev/null 2>&1 || true; }
        done < <(realm_ports)
    fi
    reserved_ports_sync || true
    systemctl reset-failed adam-realm 2>/dev/null || true
    if [ "$(realm_enabled_count)" -gt 0 ]; then
        realm_reload_service || return 1
    else
        [ "$quiet" = "quiet" ] || info "$(L '当前无已启用的 Realm 规则，已完成权限与配置修复')"
    fi
    return 0
}

realm_repair() {
    step "$(L '修复 Realm（重建配置 / 权限收敛 / 同步防火墙并重启）')"
    divider
    if ! realm_installed; then
        warn "$(L '尚未安装 Realm，请先安装')"
        return 1
    fi
    maint_install_timers >/dev/null 2>&1 || true
    if _realm_repair_core; then
        success "$(L 'Realm 修复完成，状态正常')"
        return 0
    fi
    warn "$(L 'Realm 修复后仍未恢复正常，最近日志：')"
    journalctl -u adam-realm -n 25 --no-pager || true
    return 1
}

realm_install() {
    step "$(L '安装 / 更新 Realm')"
    divider
    preflight_install_check "Realm" "$REALM_BIN" "$REALM_DIR" || return 1
    apt_install curl tar ca-certificates python3 iproute2 || true
    local _t
    for _t in curl tar sha256sum ss; do
        command -v "$_t" >/dev/null 2>&1 || error "$(L '缺少必需工具：')${_t}$(L '，请先安装')"
    done
    info "$(L '正在查询 Realm 官方最新版本...')"
    local tag cur=""
    tag="$(realm_latest_tag)"
    [ -n "$tag" ] || error "$(L '无法获取 Realm 最新版本号，请检查网络')"
    [ -f "$REALM_VERSION_FILE" ] && cur="$(cat "$REALM_VERSION_FILE" 2>/dev/null || true)"
    info "$(L '最新版本:') ${tag}"
    [ -n "$cur" ] && info "$(L '当前版本:') ${cur}"
    if [ -n "$cur" ] && [ "${cur#v}" = "${tag#v}" ] && realm_installed; then
        if ! confirm "$(L '已是最新版本，仍要重新安装？')" n; then return 0; fi
    fi

    while ! realm_fetch_binary "$tag"; do
        confirm "$(L '下载失败，是否立即重试？')" y || error "$(L 'Realm 下载或校验失败')"
    done
    install -d -m 750 "$REALM_DIR" "$REALM_CONF_D" || error "$(L '创建 Realm 配置目录失败')"
    install -d -m 700 "$REALM_RULE_DIR" || error "$(L '创建 Realm 配置目录失败')"
    if [ -f "$REALM_BIN" ]; then cp "$REALM_BIN" "$REALM_BIN_BACKUP" 2>/dev/null || warn "$(L '备份旧二进制失败')"; fi
    install -m 755 "$REALM_DL_BIN" "$REALM_BIN" || error "$(L '安装 Realm 二进制失败')"
    realm_write_base_config
    realm_write_service
    realm_fix_perms

    if [ "$(realm_enabled_count)" -gt 0 ]; then
        if ! realm_reload_service; then
            if [ -f "$REALM_BIN_BACKUP" ]; then
                warn "$(L '新版本启动失败，自动回滚到旧二进制...')"
                install -m 755 "$REALM_BIN_BACKUP" "$REALM_BIN"
                [ -n "$cur" ] && echo "$cur" > "$REALM_VERSION_FILE"
                systemctl restart adam-realm 2>/dev/null || true
            else
                warn "$(L '首次安装启动失败，已删除新二进制')"
                rm -f "$REALM_BIN"
            fi
            error "$(L 'Realm 更新失败')"
        fi
    else
        realm_reload_service || true
    fi
    echo "$tag" > "$REALM_VERSION_FILE"
    realm_fix_perms
    maint_install_timers >/dev/null 2>&1 || true
    success "$(L 'Realm ')${tag}$(L ' 安装完成（')$(${REALM_BIN} --version 2>&1 | awk "NR==1" || true)$(L '）')"
}

realm_next_id() {
    local i=1 id
    while true; do
        id="$(printf 'r%02d' "$i")"
        [ ! -f "${REALM_RULE_DIR}/${id}.env" ] && { printf '%s' "$id"; return 0; }
        i=$((i + 1))
    done
}

# 构建 ws/tls/wss 隧道字符串（参考 xwPF 中转端/落地端配对；WS/WSS 默认采用 CSPRNG 拟真路径）
realm_prompt_transport() {
    local role_label="$1" is_server="$2" choice="" host="" path="" sni="" crt="" key="" def_path=""
    REALM_TRANS_RESULT=""
    echo "  ${role_label}$(L '传输隧道：')"
    echo "    1) $(L '标准透传（推荐，性能最高，适用于已加密协议）')"
    echo "    2) WS（WebSocket）"
    echo "    3) TLS"
    echo "    4) WSS（WebSocket + TLS）"
    read -rp "  $(L '选择 [1-4，默认 1]: ')" choice || { [ -n "$choice" ] || return 1; }
    case "${choice:-1}" in
        1) return 0 ;;
        2)
            def_path="$(csprng_url_path)"
            read -rp "    $(L '伪装 Host（如 cdn.example.com）: ')" host || { [ -n "$host" ] || return 1; }
            read -rp "    $(L 'WS Path（回车默认随机路径 ')${def_path}$(L '；对端须填写一致）: ')" path || { [ -n "$path" ] || return 1; }
            path="${path:-$def_path}"; [[ "$path" == /* ]] || path="/${path}"
            is_safe_host "$host" || { warn "$(L 'Host 不合法，回退标准透传')"; return 0; }
            realm_has_toml_special "$path" && { warn "$(L '路径含非法字符（\" 或 \），回退标准透传')"; return 0; }
            case "$path" in *';'*|*'='*) warn "$(L '路径含 ; 或 =，回退标准透传')"; return 0 ;; esac
            REALM_TRANS_RESULT="ws;host=${host};path=${path}"
            info "$(L '双端配对参数（请在另一端填写相同 Host 与 Path）：')Host=${host}  Path=${path}"
            ;;
        3)
            read -rp "    $(L 'TLS SNI / 域名（如 example.com）: ')" sni || { [ -n "$sni" ] || return 1; }
            is_safe_host "$sni" || { warn "$(L '域名不合法，回退标准透传')"; return 0; }
            if [ "$is_server" = "1" ]; then
                read -rp "    $(L '证书文件路径（回车使用 Realm 内置自签）: ')" crt || { [ -n "$crt" ] || return 1; }
                if [ -n "$crt" ]; then
                    if realm_has_toml_special "$crt"; then warn "$(L '路径含非法字符（\" 或 \），回退内置自签')"; REALM_TRANS_RESULT="tls;servername=${sni}"; return 0; fi
                    case "$crt" in *';'*|*'='*) warn "$(L '路径含 ; 或 =，回退内置自签')"; REALM_TRANS_RESULT="tls;servername=${sni}"; return 0 ;; esac
                    read -rp "    $(L '私钥文件路径: ')" key || { [ -n "$key" ] || return 1; }
                    if [ -f "$crt" ] && [ -n "$key" ] && [ -f "$key" ]; then
                        if realm_has_toml_special "$key"; then warn "$(L '路径含非法字符（\" 或 \），回退内置自签')"; REALM_TRANS_RESULT="tls;servername=${sni}"; return 0; fi
                        case "$key" in *';'*|*'='*) warn "$(L '路径含 ; 或 =，回退内置自签')"; REALM_TRANS_RESULT="tls;servername=${sni}"; return 0 ;; esac
                        REALM_TRANS_RESULT="tls;cert=${crt};key=${key}"
                    else
                        warn "$(L '证书或私钥文件不存在，回退内置自签')"
                        REALM_TRANS_RESULT="tls;servername=${sni}"
                    fi
                else
                    REALM_TRANS_RESULT="tls;servername=${sni}"
                fi
            else
                if confirm "$(L '目标证书由 CA 签发（可校验）？')" n; then
                    REALM_TRANS_RESULT="tls;sni=${sni}"
                else
                    REALM_TRANS_RESULT="tls;sni=${sni};insecure"
                fi
            fi
            ;;
        4)
            def_path="$(csprng_url_path)"
            read -rp "    $(L '伪装域名 Host/SNI（如 cdn.example.com）: ')" host || { [ -n "$host" ] || return 1; }
            read -rp "    $(L 'WS Path（回车默认随机路径 ')${def_path}$(L '；对端须填写一致）: ')" path || { [ -n "$path" ] || return 1; }
            path="${path:-$def_path}"; [[ "$path" == /* ]] || path="/${path}"
            is_safe_host "$host" || { warn "$(L '域名不合法，回退标准透传')"; return 0; }
            realm_has_toml_special "$path" && { warn "$(L '路径含非法字符（\" 或 \），回退标准透传')"; return 0; }
            case "$path" in *';'*|*'='*) warn "$(L '路径含 ; 或 =，回退标准透传')"; return 0 ;; esac
            if [ "$is_server" = "1" ]; then
                read -rp "    $(L '证书文件路径（回车使用 Realm 内置自签）: ')" crt || { [ -n "$crt" ] || return 1; }
                if [ -n "$crt" ]; then
                    if realm_has_toml_special "$crt"; then warn "$(L '路径含非法字符（\" 或 \），回退内置自签')"; REALM_TRANS_RESULT="ws;host=${host};path=${path};tls;servername=${host}"; return 0; fi
                    case "$crt" in *';'*|*'='*) warn "$(L '路径含 ; 或 =，回退内置自签')"; REALM_TRANS_RESULT="ws;host=${host};path=${path};tls;servername=${host}"; return 0 ;; esac
                    read -rp "    $(L '私钥文件路径: ')" key || { [ -n "$key" ] || return 1; }
                    if [ -f "$crt" ] && [ -n "$key" ] && [ -f "$key" ]; then
                        if realm_has_toml_special "$key"; then warn "$(L '路径含非法字符（\" 或 \），回退内置自签')"; REALM_TRANS_RESULT="ws;host=${host};path=${path};tls;servername=${host}"; return 0; fi
                        case "$key" in *';'*|*'='*) warn "$(L '路径含 ; 或 =，回退内置自签')"; REALM_TRANS_RESULT="ws;host=${host};path=${path};tls;servername=${host}"; return 0 ;; esac
                        REALM_TRANS_RESULT="ws;host=${host};path=${path};tls;cert=${crt};key=${key}"
                    else
                        warn "$(L '证书或私钥文件不存在，回退内置自签')"
                        REALM_TRANS_RESULT="ws;host=${host};path=${path};tls;servername=${host}"
                    fi
                else
                    REALM_TRANS_RESULT="ws;host=${host};path=${path};tls;servername=${host}"
                fi
            else
                if confirm "$(L '目标证书由 CA 签发（可校验）？')" n; then
                    REALM_TRANS_RESULT="ws;host=${host};path=${path};tls;sni=${host}"
                else
                    REALM_TRANS_RESULT="ws;host=${host};path=${path};tls;sni=${host};insecure"
                fi
            fi
            info "$(L '双端配对参数（请在另一端填写相同 Host 与 Path）：')Host=${host}  Path=${path}"
            ;;
    esac
    return 0
}

realm_add_rule() {
    realm_installed || { warn "$(L '尚未安装 Realm，请先安装')"; return 1; }
    step "$(L '添加 Realm 转发规则')"
    divider

    local id remark proto lip lport rhost rport proto_c def_lip occ
    local extra_remotes="" balance="" through="" out_if="" in_if=""
    local ltrans="" rtrans="" send_proxy=0 accept_proxy=0 send_mptcp=0 accept_mptcp=0

    while true; do
        read -rp "$(L '规则备注（可选，如 香港VPC落地）: ')" remark || { [ -n "$remark" ] || return 1; }
        if ! realm_has_toml_special "$remark"; then break; fi
        warn "$(L '备注含非法字符（\" 或 \），请去掉后重试')"
    done

    echo "$(L '转发协议：')"
    echo "  1) $(L 'TCP + UDP 双栈（默认）')"
    echo "  2) $(L '纯 TCP')"
    echo "  3) $(L '纯 UDP（自动跳过 WS/TLS 隧道选项）')"
    read -rp "$(L '选择 [1-3，默认 1]: ')" proto_c || { [ -n "$proto_c" ] || return 1; }
    case "${proto_c:-1}" in 2) proto="tcp" ;; 3) proto="udp" ;; *) proto="both" ;; esac

    def_lip="$(realm_default_listen_ip)"
    while true; do
        read -rp "$(L '本机监听 IP（回车默认 ')${def_lip}$(L '）: ')" lip || { [ -n "$lip" ] || return 1; }
        lip="${lip:-$def_lip}"
        local _lip_check="$lip"
        if [[ "$_lip_check" == "["*"]" ]]; then
            _lip_check="${_lip_check#[}"; _lip_check="${_lip_check%]}"
            [[ "$_lip_check" == *:* ]] || { warn "$(L '监听 IP 格式不合法')"; continue; }
        elif [[ "$_lip_check" == *"["* || "$_lip_check" == *"]"* ]]; then
            warn "$(L '监听 IP 格式不合法')"; continue
        fi
        if is_ip "$_lip_check" 0; then
            lip="$(format_host_for_url "$_lip_check")"
            break
        fi
        warn "$(L '监听 IP 格式不合法')"
    done

    while true; do
        read -rp "$(L '本机监听端口 (1-65535): ')" lport || { [ -n "$lport" ] || return 1; }
        if ! validate_port "$lport"; then warn "$(L '端口不合法')"; continue; fi
        lport=$((10#$lport))
        if realm_port_used "$lport" "$proto"; then
            warn "$(L '该端口已被本模块其他规则占用，请换一个') (${lport})"
            continue
        fi
        if command -v ss >/dev/null 2>&1; then
            occ=""
            [ "$proto" != "udp" ] && occ="$(check_port_occupied_by_other tcp "$lport" realm || true)"
            [ -z "$occ" ] && [ "$proto" != "tcp" ] && occ="$(check_port_occupied_by_other udp "$lport" realm || true)"
            if [ -n "$occ" ]; then
                warn "$(L '端口 ')${lport}$(L ' 已被其他进程占用：')"
                echo "$occ"
                confirm "$(L '仍要继续添加？')" n || continue
            fi
        fi
        break
    done

    while true; do
        read -rp "$(L '目标地址（域名、公网 IP 或同区免费内网 IP）: ')" rhost || { [ -n "$rhost" ] || return 1; }
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

    # 可选：负载均衡（单中转多出口）
    if confirm "$(L '配置多目标负载均衡（extra_remotes）？')" n; then
        read -rp "$(L '  额外目标列表（逗号分隔，格式 host:port,host2:port）: ')" extra_remotes || { [ -n "$extra_remotes" ] || return 1; }
        if [ -n "$extra_remotes" ]; then
            # 逐项校验 host:port，无效项剔除
            local _clean="" _item _ih _ip
            local -a _eitems=()
            IFS=',' read -r -a _eitems <<< "$extra_remotes"
            for _item in "${_eitems[@]}"; do
                _item="${_item//[[:space:]]/}"
                [ -n "$_item" ] || continue
                if ! realm_split_host_port "$_item" _ih _ip; then
                    warn "$(L '已剔除无效目标：')${_item}"
                    continue
                fi
                _clean="${_clean:+${_clean},}${_ih}:${_ip}"
            done
            extra_remotes="$_clean"
            if [ -z "$extra_remotes" ]; then
                warn "$(L '额外目标全部无效，已跳过负载均衡')"
            else
                echo "$(L '  负载策略：1) roundrobin（加权轮询）  2) iphash（源 IP 哈希）')"
                local lb_c lb_algo="roundrobin" lb_w=""
                read -rp "$(L '  选择 [1/2，默认 1]: ')" lb_c || { [ -n "$lb_c" ] || return 1; }
                [ "${lb_c:-1}" = "2" ] && lb_algo="iphash"
                read -rp "$(L '  各目标权重（逗号分隔，含主目标，如 2,1；回车全部等权 1）: ')" lb_w || { [ -n "$lb_w" ] || return 1; }
                local _cnt=1 _e
                local -a _arr=()
                IFS=',' read -r -a _arr <<< "$extra_remotes"
                for _e in "${_arr[@]}"; do [ -n "${_e//[[:space:]]/}" ] && _cnt=$((_cnt + 1)); done
                if [ -n "$lb_w" ]; then
                    # 权重数量须等于目标总数（主目标 + 额外目标）且全为正整数（拒绝空项与 0）
                    local _wc=0 _wok=1 _wi _wclean=""
                    local -a _warr=()
                    [[ "$lb_w" == *, ]] && _wok=0
                    IFS=',' read -r -a _warr <<< "$lb_w"
                    for _wi in "${_warr[@]}"; do
                        _wi="${_wi//[[:space:]]/}"
                        if [[ ! "$_wi" =~ ^[1-9][0-9]*$ ]]; then _wok=0; continue; fi
                        _wc=$((_wc + 1))
                        _wclean="${_wclean:+${_wclean}, }${_wi}"
                    done
                    if [ "$_wok" != "1" ] || [ "$_wc" -ne "$_cnt" ]; then
                        warn "$(L '权重数量与目标数不符或含非数字，已按等权生成')"
                        lb_w=""
                    else
                        lb_w="$_wclean"
                    fi
                fi
                if [ -z "$lb_w" ]; then
                    lb_w="$(printf '1, %.0s' $(seq 1 "$_cnt") | sed 's/, $//')"
                fi
                balance="${lb_algo}: ${lb_w}"
            fi
        fi
    fi

    # 可选：双端隧道（仅 TCP/双栈）
    if [ "$proto" != "udp" ] && confirm "$(L '配置 WS / TLS / WSS 双端加密隧道？')" n; then
        echo "$(L '  当前机器角色：1) 中转入口机（向外加密 remote_transport）  2) 落地出口机（入站解密 listen_transport）')"
        local trole
        read -rp "$(L '  选择 [1/2，默认 1]: ')" trole || { [ -n "$trole" ] || return 1; }
        if [ "${trole:-1}" = "2" ]; then
            realm_prompt_transport "$(L '入站解密')" 1 || return 1
            ltrans="$REALM_TRANS_RESULT"
        else
            realm_prompt_transport "$(L '出站加密')" 0 || return 1
            rtrans="$REALM_TRANS_RESULT"
        fi
    fi

    # 可选：多 IP / 多网卡 / Proxy Protocol / MPTCP
    if confirm "$(L '配置高级选项（指定出口 IP/网卡、Proxy Protocol、MPTCP）？')" n; then
        read -rp "$(L '  出站源 IP through（回车默认自动）: ')" through || { [ -n "$through" ] || return 1; }
        through="${through#[}"; through="${through%]}"
        if [ -n "$through" ] && ! is_ip "$through" 0; then warn "$(L '非合法 IP，已忽略')"; through=""; fi
        read -rp "$(L '  出站网卡 interface（如 eth1，回车默认自动）: ')" out_if || { [ -n "$out_if" ] || return 1; }
        if [ -n "$out_if" ] && [[ ! "$out_if" =~ ^[A-Za-z0-9_.-]+$ ]]; then warn "$(L '网卡名格式不合法，已忽略')"; out_if=""; fi
        read -rp "$(L '  入站网卡 listen_interface（如 eth0，回车默认自动）: ')" in_if || { [ -n "$in_if" ] || return 1; }
        if [ -n "$in_if" ] && [[ ! "$in_if" =~ ^[A-Za-z0-9_.-]+$ ]]; then warn "$(L '网卡名格式不合法，已忽略')"; in_if=""; fi
        if [ "$proto" != "udp" ]; then
            confirm "$(L '  向目标发送 Proxy Protocol v2（send_proxy）？')" n && send_proxy=1
            confirm "$(L '  接收来源 Proxy Protocol（accept_proxy）？')" n && accept_proxy=1
            confirm "$(L '  启用出站 MPTCP（send_mptcp）？')" n && send_mptcp=1
            confirm "$(L '  启用入站 MPTCP（accept_mptcp）？')" n && accept_mptcp=1
        fi
    fi

    install -d -m 750 "$REALM_DIR" "$REALM_CONF_D"
    install -d -m 700 "$REALM_RULE_DIR"
    id="$(realm_next_id)"
    local env_file="${REALM_RULE_DIR}/${id}.env"
    ( umask 077; cat > "$env_file" ) << RULEEOF
RULE_ID="${id}"
RULE_ENABLED="1"
RULE_REMARK="$(dq_escape "$remark")"
RULE_PROTO="${proto}"
RULE_LIP="${lip}"
RULE_LPORT="${lport}"
RULE_RHOST="${rhost}"
RULE_RPORT="${rport}"
RULE_EXTRA_REMOTES="$(dq_escape "$extra_remotes")"
RULE_BALANCE="$(dq_escape "$balance")"
RULE_THROUGH="${through}"
RULE_OUT_IF="${out_if}"
RULE_IN_IF="${in_if}"
RULE_LTRANS="$(dq_escape "$ltrans")"
RULE_RTRANS="$(dq_escape "$rtrans")"
RULE_SEND_PROXY="${send_proxy}"
RULE_ACCEPT_PROXY="${accept_proxy}"
RULE_SEND_MPTCP="${send_mptcp}"
RULE_ACCEPT_MPTCP="${accept_mptcp}"
RULEEOF
    chmod 600 "$env_file"

    if ! realm_render_rule "$id" || [ ! -f "${REALM_CONF_D}/rule-${id}.toml" ]; then
        rm -f "$env_file" "${REALM_CONF_D}/rule-${id}.toml"
        error "$(L '规则渲染失败，已中止')"
    fi
    if ! realm_reload_service; then
        rm -f "$env_file" "${REALM_CONF_D}/rule-${id}.toml"
        realm_reload_service >/dev/null 2>&1 || true
        error "$(L '新规则未能生效，已自动撤回（原有规则不受影响）')"
    fi

    local -a fw_specs=()
    [ "$proto" != "udp" ] && fw_specs+=("${lport}/tcp")
    [ "$proto" != "tcp" ] && fw_specs+=("${lport}/udp")
    fw_allow_for_service "${fw_specs[@]}"
    reserved_ports_sync || true
    success "$(L '规则 ')${id}$(L ' 已生效：')${lip}:${lport} -> ${rhost}:${rport}"
}

realm_list_rules() {
    step "$(L 'Realm 转发规则列表')"
    divider
    local f idx=0 tags status
    while IFS= read -r f; do
        idx=$((idx + 1))
        (
            env_file_safe "$f" || exit 0
            # shellcheck disable=SC1090
            source "$f" 2>/dev/null || exit 0
            tags=""
            [ "${RULE_PROTO:-both}" = "tcp" ] && tags="${tags}[$(L '纯TCP')]"
            [ "${RULE_PROTO:-both}" = "udp" ] && tags="${tags}[$(L '纯UDP')]"
            [ -n "${RULE_LTRANS:-}" ] && tags="${tags}[$(L '入站:')${RULE_LTRANS}]"
            [ -n "${RULE_RTRANS:-}" ] && tags="${tags}[$(L '出站:')${RULE_RTRANS}]"
            [ -n "${RULE_EXTRA_REMOTES:-}" ] && tags="${tags}[LB]"
            [ -n "${RULE_THROUGH:-}" ] && tags="${tags}[$(L '源IP:')${RULE_THROUGH}]"
            [ -n "${RULE_OUT_IF:-}" ] && tags="${tags}[$(L '出网卡:')${RULE_OUT_IF}]"
            if [ "${RULE_ENABLED:-0}" = "1" ]; then
                status="${GREEN}$(L '启用')${NC}"
            else
                status="${YELLOW}$(L '停用')${NC}"
            fi
            echo -e "  ${BOLD}${idx})${NC} [${RULE_ID}] ${status}  ${CYAN}${RULE_LIP}:${RULE_LPORT}${NC} -> ${GREEN}${RULE_RHOST}:${RULE_RPORT}${NC} ${tags}${RULE_REMARK:+  # ${RULE_REMARK}}"
        )
    done < <(realm_rule_files)
    if [ "$idx" -eq 0 ]; then
        info "$(L '暂无转发规则')"
    fi
}

realm_pick_rule_file() {
    local -a files=()
    local f choice
    while IFS= read -r f; do files+=("$f"); done < <(realm_rule_files)
    [ "${#files[@]}" -gt 0 ] || { info "$(L '暂无规则')"; return 1; }
    realm_list_rules
    echo ""
    read -rp "$(L '输入规则序号（回车取消）: ')" choice || { [ -n "$choice" ] || return 1; }
    [[ -n "$choice" && "$choice" =~ ^[0-9]+$ ]] || return 1
    choice=$((10#$choice))
    [ "$choice" -ge 1 ] && [ "$choice" -le "${#files[@]}" ] || { warn "$(L '序号无效')"; return 1; }
    PICKED_RULE_FILE="${files[$((choice - 1))]}"
    return 0
}

realm_toggle_rule() {
    realm_pick_rule_file || return 0
    local f="$PICKED_RULE_FILE" bak="${PICKED_RULE_FILE}.bak" cur next lport proto
    env_file_safe "$f" || { warn "$(L '规则文件内容非法，已跳过：')${f}"; return 1; }
    cur="$(grep -m1 '^RULE_ENABLED=' "$f" | cut -d'"' -f2 || echo 0)"
    lport="$(grep -m1 '^RULE_LPORT=' "$f" | cut -d'"' -f2 || true)"
    proto="$(grep -m1 '^RULE_PROTO=' "$f" | cut -d'"' -f2 || echo both)"
    if [ "$cur" = "1" ]; then next="0"; else next="1"; fi
    cp -f "$f" "$bak" || return 1
    if grep -q '^RULE_ENABLED=' "$f"; then
        sed -i "s|^RULE_ENABLED=.*|RULE_ENABLED=\"${next}\"|" "$f" || { mv -f "$bak" "$f"; warn "$(L '规则状态切换失败')"; return 1; }
    else
        printf '%s\n' "RULE_ENABLED=\"${next}\"" >> "$f"
    fi
    if ! realm_reload_service; then
        mv -f "$bak" "$f"
        realm_reload_service >/dev/null 2>&1 || true
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

realm_delete_rule() {
    realm_pick_rule_file || return 0
    local f="$PICKED_RULE_FILE" bak="${PICKED_RULE_FILE}.bak" old_port old_proto rid rlip rrhost rrport
    rid="$(grep -m1 '^RULE_ID=' "$f" | cut -d'"' -f2 || true)"
    rlip="$(grep -m1 '^RULE_LIP=' "$f" | cut -d'"' -f2 || true)"
    old_port="$(grep -m1 '^RULE_LPORT=' "$f" | cut -d'"' -f2 || true)"
    old_proto="$(grep -m1 '^RULE_PROTO=' "$f" | cut -d'"' -f2 || true)"
    rrhost="$(grep -m1 '^RULE_RHOST=' "$f" | cut -d'"' -f2 || true)"
    rrport="$(grep -m1 '^RULE_RPORT=' "$f" | cut -d'"' -f2 || true)"
    confirm "$(L '确认删除规则 [')${rid}] ${rlip}:${old_port} -> ${rrhost}:${rrport}$(L ']？')" n || return 0
    mv -f "$f" "$bak" || return 1
    if ! realm_reload_service; then
        mv -f "$bak" "$f"
        realm_reload_service >/dev/null 2>&1 || true
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
    success "$(L '已删除规则 ')${rid}"
    return 0
}

# TCP 目标连通性与延迟检测（类似 xwPF 链路检测，支持 IPv4/IPv6）
realm_test_rules() {
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
            if [ "${RULE_PROTO:-both}" = "udp" ]; then
                echo -e "  [${RULE_ID}] ${RULE_RHOST}:${RULE_RPORT}  $(L '跳过（纯 UDP 无法做 TCP 握手探测）')  ${RULE_REMARK}"
                exit 0
            fi
            res="$(probe_tcp_host_port "$RULE_RHOST" "$RULE_RPORT")"
            if [[ "$res" == OK* ]]; then
                echo -e "  [${RULE_ID}] ${RULE_RHOST}:${RULE_RPORT}  ${GREEN}${res}${NC}  ${RULE_REMARK}"
            else
                echo -e "  [${RULE_ID}] ${RULE_RHOST}:${RULE_RPORT}  ${RED}${res}${NC}  ${RULE_REMARK}"
            fi
            if [ -n "${RULE_EXTRA_REMOTES:-}" ]; then
                local _ex _eh _ep _eres
                local -a _exarr=()
                IFS=',' read -r -a _exarr <<< "$RULE_EXTRA_REMOTES"
                for _ex in "${_exarr[@]}"; do
                    _ex="${_ex//[[:space:]]/}"
                    [ -n "$_ex" ] || continue
                    realm_split_host_port "$_ex" _eh _ep || continue
                    _eres="$(probe_tcp_host_port "$_eh" "$_ep")"
                    if [[ "$_eres" == OK* ]]; then
                        echo -e "    └─ [LB] ${_eh}:${_ep}  ${GREEN}${_eres}${NC}"
                    else
                        echo -e "    └─ [LB] ${_eh}:${_ep}  ${RED}${_eres}${NC}"
                    fi
                done
            fi
        )
    done < <(realm_rule_files)
    if [ "$any" -eq 0 ]; then info "$(L '暂无可测试的规则')"; fi
    return 0
}

realm_export_rules() {
    [ -d "$REALM_DIR" ] || { warn "$(L '未找到 Realm 配置目录')"; return 1; }
    local out
    out="/root/adam-realm-$(date +%Y%m%d-%H%M%S).tgz"
    ( umask 077; tar -czf "$out" -C / etc/adam-realm 2>/dev/null ) || error "$(L '导出失败')"
    chmod 600 "$out"
    success "$(L '规则已导出至: ')${out}"
}

realm_import_rules() {
    realm_installed || { warn "$(L '尚未安装 Realm，请先安装')"; return 1; }
    local fpath members old_ports bakdir m
    read -rp "$(L '输入导出的 .tgz 备份文件路径: ')" fpath || { [ -n "$fpath" ] || return 1; }
    [ -f "$fpath" ] || error "$(L '找不到文件: ')${fpath}"
    tar -tzf "$fpath" >/dev/null 2>&1 || error "$(L '压缩包损坏或格式无效')"
    members="$(tar -tzf "$fpath" 2>/dev/null || true)"
    [ -n "$members" ] || error "$(L '备份为空或格式无效')"
    local _tv_list=""
    _tv_list="$(tar -tvzf "$fpath" 2>/dev/null || true)"
    if grep -qE '^[lhbcsp]' <<< "$_tv_list"; then
        error "$(L '备份文件包含符号链接或特殊设备文件，已拒绝导入')"
    fi
    # 成员校验：只允许 etc/adam-realm/**，.. 穿越即拒（与 do_restore 同款）
    while IFS= read -r m; do
        case "$m" in
            *".."*) error "$(L '备份文件包含非法路径，已中止'): $m" ;;
            etc/adam-realm|etc/adam-realm/*) : ;;
            *) error "$(L '备份文件包含非法路径，已中止'): $m" ;;
        esac
    done < <(printf '%s\n' "$members")
    old_ports="$(realm_ports 2>/dev/null | tr '\n' ' ' || true)"
    confirm "$(L '导入将覆盖 /etc/adam-realm 现有规则并重启服务，确认？')" n || return 0
    # 先备份现有配置：导入是"替换"而非"合并"，失败时可恢复
    bakdir="$(mktemp -d /tmp/adam-realm-import.XXXXXX)" || error "$(L '创建临时文件失败')"
    [ -d "$REALM_DIR" ] && cp -a "$REALM_DIR" "$bakdir/realm"
    rm -rf "${REALM_RULE_DIR}" "${REALM_CONF_D}"/rule-*.toml
    if ! tar -xzf "$fpath" --no-same-owner -C /; then
        warn "$(L '解包失败，已恢复原配置')"
        rm -rf "$REALM_DIR"
        [ -d "$bakdir/realm" ] && cp -a "$bakdir/realm" "$REALM_DIR"
        rm -rf "$bakdir"
        error "$(L '压缩包损坏或格式无效')"
    fi
    # 内容校验：外来 .env 不可直接 source，先逐个验
    local _ef _ok=1
    while IFS= read -r _ef; do
        realm_env_file_safe "$_ef" || { warn "$(L '规则文件内容非法，已恢复原配置'): ${_ef}"; _ok=0; break; }
    done < <(find "${REALM_RULE_DIR}" -maxdepth 1 -name '*.env' 2>/dev/null)
    if [ "$_ok" != "1" ]; then
        rm -rf "$REALM_DIR"
        [ -d "$bakdir/realm" ] && cp -a "$bakdir/realm" "$REALM_DIR"
        rm -rf "$bakdir"
        error "$(L '导入的规则文件内容非法，已恢复原配置')"
    fi
    # 跨机导入时保留本机的二进制版本记录与 root 运行标记，避免错判版本或服务权限不匹配
    if [ -f "$bakdir/realm/version.txt" ]; then cp -a "$bakdir/realm/version.txt" "$REALM_VERSION_FILE" 2>/dev/null || true; else rm -f "$REALM_VERSION_FILE"; fi
    if [ -f "$bakdir/realm/run-as-root" ]; then cp -a "$bakdir/realm/run-as-root" "${REALM_DIR}/run-as-root" 2>/dev/null || true; else rm -f "${REALM_DIR}/run-as-root"; fi
    realm_fix_perms
    if realm_reload_service; then
        rm -rf "$bakdir"
        fw_sync_managed
        [ -n "${old_ports// /}" ] && fw_prune_old_specs "$old_ports"
        reserved_ports_sync || true
        success "$(L '规则导入完成')"
    else
        warn "$(L '规则已导入，但服务重载失败，请检查日志')"
        rm -rf "$REALM_DIR"
        [ -d "$bakdir/realm" ] && cp -a "$bakdir/realm" "$REALM_DIR"
        rm -rf "$bakdir"
        realm_fix_perms
        realm_reload_service >/dev/null 2>&1 || true
        return 1
    fi
}

realm_uninstall_do() {
    local old_specs
    old_specs="$(realm_ports 2>/dev/null | tr '\n' ' ' || true)"
    systemctl disable --now adam-realm 2>/dev/null || true
    rm -f "$REALM_SERVICE" "$REALM_BIN" "$REALM_BIN_BACKUP"
    systemctl daemon-reload || true
    if confirm "$(L '同时删除规则配置目录') ${REALM_DIR}$(L '？')" n; then
        rm -rf "$REALM_DIR"
        userdel adam-realm >/dev/null 2>&1 || true
    else
        warn "$(L '已保留规则目录') ${REALM_DIR}"
    fi
    if [ -n "${old_specs// /}" ] && ufw_installed && confirm "$(L '同时删除防火墙中 Realm 端口的放行规则（')${old_specs}$(L '）？')" y; then
        local _rs
        while IFS= read -r _rs; do
            [ -n "$_rs" ] || continue
            fw_spec_has_ssh_port "$_rs" && continue
            port_used_by_other_services "$_rs" realm && continue
            fw_delete_spec "$_rs"
        done < <(printf '%s\n' "$old_specs" | tr ' ' '\n' | grep -v '^$')
    fi
    reserved_ports_sync || true
    success "$(L 'Realm 已卸载')"
}

realm_uninstall() {
    step "$(L '卸载 Realm')"
    divider
    confirm "$(L '确认卸载 Realm（含服务与二进制）？')" n || return 0
    realm_uninstall_do
}


# 端口是否已被本 Realm 模块已启用的同协议规则占用（可选 $3 排除指定规则 ID）
realm_port_used() {
    local want="$1" proto="${2:-both}" skip_id="${3:-}" f
    while IFS= read -r f; do
        (
            env_file_safe "$f" || exit 1
            # shellcheck disable=SC1090
            source "$f" 2>/dev/null || exit 1
            [ "${RULE_ENABLED:-0}" = "1" ] || exit 1
            [ -n "$skip_id" ] && [ "${RULE_ID:-}" = "$skip_id" ] && exit 1
            [ "${RULE_LPORT:-}" = "$want" ] || exit 1
            if [ "$proto" = "both" ] || [ "${RULE_PROTO:-both}" = "both" ] || [ "$proto" = "${RULE_PROTO:-both}" ]; then
                exit 0
            fi
            exit 1
        ) && return 0
    done < <(realm_rule_files)
    return 1
}

# Realm 定时自动更新（从 zhboner/realm 官方仓库拉取 + SHA256 digest 校验 + 失败自动回滚）
realm_autoupdate() {
    realm_installed || return 0
    local cur latest
    cur="$(cat "$REALM_VERSION_FILE" 2>/dev/null || true)"
    latest="$(realm_latest_tag)"
    if [ -z "$latest" ]; then
        echo "[Realm] $(L '未能获取官方版本信息，本次跳过；当前') ${cur:-$(L '未知')}"
        return 1
    fi
    if [ -n "$cur" ] && [ "${cur#v}" = "${latest#v}" ]; then
        echo "[Realm] $(L '已是最新:') ${cur}"
        return 0
    fi
    if [ -n "$cur" ] && version_ge "$cur" "$latest"; then
        echo "[Realm] $(L '已是最新:') ${cur}"
        return 0
    fi
    echo "[Realm] $(L '发现新版本:') ${cur:-$(L '未知')} -> ${latest}$(L '，开始更新')"
    if ! realm_fetch_binary "$latest"; then
        maint_log "[Realm] $(L '自动更新到') ${latest} $(L '失败，当前仍为') ${cur:-$(L '未知')}"
        return 1
    fi
    if [ -f "$REALM_BIN" ]; then cp -f "$REALM_BIN" "$REALM_BIN_BACKUP" 2>/dev/null || true; fi
    install -m 755 "$REALM_DL_BIN" "$REALM_BIN" || return 1
    if [ "$(realm_enabled_count)" -gt 0 ]; then
        if ! realm_reload_service; then
            if [ -f "$REALM_BIN_BACKUP" ]; then
                install -m 755 "$REALM_BIN_BACKUP" "$REALM_BIN"
                realm_reload_service >/dev/null 2>&1 || true
            fi
            maint_log "[Realm] $(L '自动更新到') ${latest} $(L '失败，当前仍为') ${cur:-$(L '未知')}"
            notify_send "Realm Auto-Rollback" "Auto-update to ${latest} failed; rolled back to ${cur:-previous}." || true
            return 1
        fi
    fi
    echo "$latest" > "$REALM_VERSION_FILE"
    realm_fix_perms
    maint_log "[Realm] $(L '已自动更新:') ${cur:-$(L '未知')} -> ${latest}"
    return 0
}

# 批量添加转发规则（支持端口段 10000-10020 或逗号列表 8080,8443；单次原子重载）
realm_add_batch_rules() {
    realm_installed || { warn "$(L '尚未安装 Realm，请先安装')"; return 1; }
    step "$(L '批量添加转发规则（端口段 / 多端口）')"
    divider

    local remark proto proto_c def_lip lip spec rhost rmode rport_fixed=""
    local -a ports=() added_files=() fw_specs=()
    local item a b p id env_file ok_cnt=0 skip_cnt=0

    read -rp "$(L '规则备注（可选，如 香港VPC落地）: ')" remark || { [ -n "$remark" ] || return 1; }
    if realm_has_toml_special "$remark"; then warn "$(L '备注含非法字符（\" 或 \），请去掉后重试')"; return 1; fi

    echo "$(L '转发协议：')"
    echo "  1) $(L 'TCP + UDP 双栈（默认）')"
    echo "  2) $(L '纯 TCP')"
    echo "  3) $(L '纯 UDP（自动跳过 WS/TLS 隧道选项）')"
    read -rp "$(L '选择 [1-3，默认 1]: ')" proto_c || { [ -n "$proto_c" ] || return 1; }
    case "${proto_c:-1}" in 2) proto="tcp" ;; 3) proto="udp" ;; *) proto="both" ;; esac

    def_lip="$(realm_default_listen_ip)"
    read -rp "$(L '本机监听 IP（回车默认 ')${def_lip}$(L '）: ')" lip || { [ -n "$lip" ] || return 1; }
    lip="${lip:-$def_lip}"
    local _lip_check="$lip"
    if [[ "$_lip_check" == "["*"]" ]]; then
        _lip_check="${_lip_check#[}"; _lip_check="${_lip_check%]}"
        [[ "$_lip_check" == *:* ]] || { warn "$(L '监听 IP 格式不合法')"; return 1; }
    elif [[ "$_lip_check" == *"["* || "$_lip_check" == *"]"* ]]; then
        warn "$(L '监听 IP 格式不合法')"; return 1
    fi
    is_ip "$_lip_check" 0 || { warn "$(L '监听 IP 格式不合法')"; return 1; }
    lip="$(format_host_for_url "$_lip_check")"

    read -rp "$(L '端口段或逗号列表（如 10000-10010 或 8080,8443,9000）: ')" spec || { [ -n "$spec" ] || return 1; }
    spec="${spec//[[:space:]]/}"
    [ -n "$spec" ] || { warn "$(L '输入不合法，未做任何修改')"; return 1; }
    local -a items=()
    IFS=',' read -r -a items <<< "$spec"
    for item in "${items[@]}"; do
        [ -n "$item" ] || continue
        if [[ "$item" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            a=$((10#${BASH_REMATCH[1]})); b=$((10#${BASH_REMATCH[2]}))
            if [ "$a" -lt 1 ] || [ "$b" -gt 65535 ] || [ "$a" -gt "$b" ]; then
                warn "$(L '端口超出范围:') ${item}"; return 1
            fi
            for ((p=a; p<=b; p++)); do
                ports+=("$p")
                if [ "${#ports[@]}" -gt 100 ]; then
                    warn "$(L '单次批量最多支持 100 个端口，请缩小范围')"; return 1
                fi
            done
        elif validate_port "$item"; then
            ports+=("$((10#$item))")
            if [ "${#ports[@]}" -gt 100 ]; then
                warn "$(L '单次批量最多支持 100 个端口，请缩小范围')"; return 1
            fi
        else
            warn "$(L '无法识别的端口写法:') ${item}"; return 1
        fi
    done
    [ "${#ports[@]}" -gt 0 ] || { warn "$(L '输入不合法，未做任何修改')"; return 1; }

    while true; do
        read -rp "$(L '目标地址（域名、公网 IP 或同区免费内网 IP）: ')" rhost || { [ -n "$rhost" ] || return 1; }
        rhost="${rhost//[[:space:]]/}"
        is_safe_host "$rhost" && break
        warn "$(L '目标地址格式不合法')"
    done

    echo "$(L '目标端口模式：1) 同端口一对一映射（推荐）  2) 全部指向同一个目标端口')"
    read -rp "$(L '  选择 [1/2，默认 1]: ')" rmode || { [ -n "$rmode" ] || return 1; }
    if [ "${rmode:-1}" = "2" ]; then
        while true; do
            read -rp "$(L '目标端口 (1-65535): ')" rport_fixed || { [ -n "$rport_fixed" ] || return 1; }
            validate_port "$rport_fixed" && { rport_fixed=$((10#$rport_fixed)); break; }
            warn "$(L '端口不合法')"
        done
    fi

    install -d -m 750 "$REALM_DIR" "$REALM_CONF_D"
    install -d -m 700 "$REALM_RULE_DIR"
    local rp occ
    for p in "${ports[@]}"; do
        if realm_port_used "$p" "$proto"; then
            warn "$(L '端口 ')${p} $(L '已被占用，请换一个')"
            skip_cnt=$((skip_cnt + 1))
            continue
        fi
        occ=""
        if command -v ss >/dev/null 2>&1; then
            [ "$proto" != "udp" ] && occ="$(check_port_occupied_by_other tcp "$p" realm || true)"
            [ -z "$occ" ] && [ "$proto" != "tcp" ] && occ="$(check_port_occupied_by_other udp "$p" realm || true)"
        fi
        if [ -n "$occ" ]; then
            warn "$(L '已跳过被其他进程占用的端口：')${p}"
            skip_cnt=$((skip_cnt + 1))
            continue
        fi
        rp="${rport_fixed:-$p}"
        id="$(realm_next_id)"
        env_file="${REALM_RULE_DIR}/${id}.env"
        ( umask 077; cat > "$env_file" ) << RULEEOF
RULE_ID="${id}"
RULE_ENABLED="1"
RULE_REMARK="$(dq_escape "${remark:+${remark}-}${p}")"
RULE_PROTO="${proto}"
RULE_LIP="${lip}"
RULE_LPORT="${p}"
RULE_RHOST="${rhost}"
RULE_RPORT="${rp}"
RULE_EXTRA_REMOTES=""
RULE_BALANCE=""
RULE_THROUGH=""
RULE_OUT_IF=""
RULE_IN_IF=""
RULE_LTRANS=""
RULE_RTRANS=""
RULE_SEND_PROXY="0"
RULE_ACCEPT_PROXY="0"
RULE_SEND_MPTCP="0"
RULE_ACCEPT_MPTCP="0"
RULEEOF
        chmod 600 "$env_file"
        added_files+=("$env_file")
        [ "$proto" != "udp" ] && fw_specs+=("${p}/tcp")
        [ "$proto" != "tcp" ] && fw_specs+=("${p}/udp")
        ok_cnt=$((ok_cnt + 1))
    done

    [ "$ok_cnt" -gt 0 ] || { warn "$(L '没有找到') (0)"; return 0; }

    if ! realm_reload_service; then
        for env_file in "${added_files[@]}"; do rm -f "$env_file"; done
        realm_reload_service >/dev/null 2>&1 || true
        error "$(L '新规则未能生效，已自动撤回（原有规则不受影响）')"
    fi

    [ "${#fw_specs[@]}" -gt 0 ] && fw_allow_for_service "${fw_specs[@]}"
    reserved_ports_sync || true
    success "$(L '批量添加完成：成功 ')${ok_cnt}$(L '，跳过 ')${skip_cnt}"
}

# 编辑已有转发规则（回车保持原值，失败自动恢复原配置）
realm_edit_rule() {
    realm_pick_rule_file || return 0
    local f="$PICKED_RULE_FILE" bak ans
    realm_env_file_safe "$f" || { warn "$(L '规则文件内容非法，已跳过：')${f}"; return 1; }
    # shellcheck disable=SC1090
    source "$f" || return 1
    local old_port="$RULE_LPORT" old_proto="$RULE_PROTO"
    local remark="$RULE_REMARK" proto="$RULE_PROTO" lip="$RULE_LIP" lport="$RULE_LPORT"
    local rhost="$RULE_RHOST" rport="$RULE_RPORT"
    local extra_remotes="${RULE_EXTRA_REMOTES:-}" balance="${RULE_BALANCE:-}"
    local through="${RULE_THROUGH:-}" out_if="${RULE_OUT_IF:-}" in_if="${RULE_IN_IF:-}"
    local ltrans="${RULE_LTRANS:-}" rtrans="${RULE_RTRANS:-}"
    local send_proxy="${RULE_SEND_PROXY:-0}" accept_proxy="${RULE_ACCEPT_PROXY:-0}"
    local send_mptcp="${RULE_SEND_MPTCP:-0}" accept_mptcp="${RULE_ACCEPT_MPTCP:-0}"

    step "$(L '编辑已有转发规则') [${RULE_ID}]"
    divider
    read -rp "$(L '规则备注（可选）: ') [${remark}] ($(L '回车保持')): " ans || { [ -n "$ans" ] || return 1; }
    if [ -n "$ans" ]; then
        if realm_has_toml_special "$ans"; then warn "$(L '备注含非法字符（\" 或 \），请去掉后重试')"; return 1; fi
        remark="$ans"
    fi

    echo "$(L '转发协议：') [$(L '当前:') ${proto}]"
    echo "  1) $(L 'TCP + UDP 双栈（默认）')  2) $(L '纯 TCP')  3) $(L '纯 UDP')"
    read -rp "$(L '选择') [1-3, $(L '回车保持')]: " ans || { [ -n "$ans" ] || return 1; }
    case "$ans" in 1) proto="both" ;; 2) proto="tcp" ;; 3) proto="udp" ;; *) : ;; esac

    read -rp "$(L '本机监听 IP（回车默认 ')${lip}$(L '）: ')" ans || { [ -n "$ans" ] || return 1; }
    if [ -n "$ans" ]; then
        local _lc="$ans"
        if [[ "$_lc" == "["*"]" ]]; then
            _lc="${_lc#[}"; _lc="${_lc%]}"
            [[ "$_lc" == *:* ]] || { warn "$(L '监听 IP 格式不合法')"; return 1; }
        elif [[ "$_lc" == *"["* || "$_lc" == *"]"* ]]; then
            warn "$(L '监听 IP 格式不合法')"; return 1
        fi
        is_ip "$_lc" 0 || { warn "$(L '监听 IP 格式不合法')"; return 1; }
        lip="$(format_host_for_url "$_lc")"
    fi

    read -rp "$(L '本机监听端口 (1-65535): ') [${lport}] ($(L '回车保持')): " ans || { [ -n "$ans" ] || return 1; }
    if [ -n "$ans" ]; then
        validate_port "$ans" || { warn "$(L '端口不合法')"; return 1; }
        lport=$((10#$ans))
    fi
    if [ "$lport" != "$old_port" ] || [ "$proto" != "$old_proto" ]; then
        if realm_port_used "$lport" "$proto" "$RULE_ID"; then
            warn "$(L '该端口已被本模块其他规则占用，请换一个') (${lport})"
            return 1
        fi
        if command -v ss >/dev/null 2>&1; then
            local occ=""
            [ "$proto" != "udp" ] && occ="$(check_port_occupied_by_other tcp "$lport" realm || true)"
            [ -z "$occ" ] && [ "$proto" != "tcp" ] && occ="$(check_port_occupied_by_other udp "$lport" realm || true)"
            if [ -n "$occ" ]; then
                warn "$(L '端口 ')${lport}$(L ' 已被其他进程占用：')"
                echo "$occ"
                confirm "$(L '仍要继续添加？')" n || return 1
            fi
        fi
    fi

    read -rp "$(L '目标地址（域名、公网 IP 或同区免费内网 IP）: ') [${rhost}] ($(L '回车保持')): " ans || { [ -n "$ans" ] || return 1; }
    if [ -n "$ans" ]; then
        ans="${ans//[[:space:]]/}"
        is_safe_host "$ans" || { warn "$(L '目标地址格式不合法')"; return 1; }
        rhost="$ans"
    fi

    read -rp "$(L '目标端口 (1-65535): ') [${rport}] ($(L '回车保持')): " ans || { [ -n "$ans" ] || return 1; }
    if [ -n "$ans" ]; then
        validate_port "$ans" || { warn "$(L '端口不合法')"; return 1; }
        rport=$((10#$ans))
    fi

    if confirm "$(L '配置多目标负载均衡（extra_remotes）？')" n; then
        read -rp "$(L '  额外目标列表（逗号分隔，格式 host:port,host2:port）: ') [${extra_remotes:-$(L '无')}]: " ans || { [ -n "$ans" ] || return 1; }
        if [ -z "$ans" ]; then
            extra_remotes=""; balance=""
        else
            local _clean="" _item _ih _ip _cnt=1
            local -a _eitems=()
            IFS=',' read -r -a _eitems <<< "$ans"
            for _item in "${_eitems[@]}"; do
                _item="${_item//[[:space:]]/}"
                [ -n "$_item" ] || continue
                if ! realm_split_host_port "$_item" _ih _ip; then
                    warn "$(L '已剔除无效目标：')${_item}"; continue
                fi
                _clean="${_clean:+${_clean},}${_ih}:${_ip}"; _cnt=$((_cnt + 1))
            done
            extra_remotes="$_clean"
            if [ -n "$extra_remotes" ]; then
                echo "$(L '  负载策略：1) roundrobin（加权轮询）  2) iphash（源 IP 哈希）')"
                local lb_c lb_algo="roundrobin" lb_w=""
                read -rp "$(L '  选择 [1/2，默认 1]: ')" lb_c || { [ -n "$lb_c" ] || return 1; }
                [ "${lb_c:-1}" = "2" ] && lb_algo="iphash"
                read -rp "$(L '  各目标权重（逗号分隔，含主目标，如 2,1；回车全部等权 1）: ')" lb_w || { [ -n "$lb_w" ] || return 1; }
                if [ -n "$lb_w" ]; then
                    local _wc=0 _wok=1 _wi _wclean=""
                    local -a _warr=()
                    [[ "$lb_w" == *, ]] && _wok=0
                    IFS=',' read -r -a _warr <<< "$lb_w"
                    for _wi in "${_warr[@]}"; do
                        _wi="${_wi//[[:space:]]/}"
                        if [[ ! "$_wi" =~ ^[1-9][0-9]*$ ]]; then _wok=0; continue; fi
                        _wc=$((_wc + 1))
                        _wclean="${_wclean:+${_wclean}, }${_wi}"
                    done
                    if [ "$_wok" != "1" ] || [ "$_wc" -ne "$_cnt" ]; then
                        warn "$(L '权重数量与目标数不符或含非数字，已按等权生成')"
                        lb_w=""
                    else
                        lb_w="$_wclean"
                    fi
                fi
                [ -n "$lb_w" ] || lb_w="$(printf '1, %.0s' $(seq 1 "$_cnt") | sed 's/, $//')"
                balance="${lb_algo}: ${lb_w}"
            else
                balance=""
            fi
        fi
    fi

    if [ "$proto" != "udp" ] && confirm "$(L '配置 WS / TLS / WSS 双端加密隧道？')" n; then
        echo "$(L '  当前机器角色：1) 中转入口机（向外加密 remote_transport）  2) 落地出口机（入站解密 listen_transport）')"
        local trole
        read -rp "$(L '  选择 [1/2，默认 1]: ')" trole || { [ -n "$trole" ] || return 1; }
        if [ "${trole:-1}" = "2" ]; then
            realm_prompt_transport "$(L '入站解密')" 1 || return 1
            ltrans="$REALM_TRANS_RESULT"; rtrans=""
        else
            realm_prompt_transport "$(L '出站加密')" 0 || return 1
            rtrans="$REALM_TRANS_RESULT"; ltrans=""
        fi
    elif [ "$proto" = "udp" ]; then
        ltrans=""; rtrans=""
    fi

    if confirm "$(L '配置高级选项（指定出口 IP/网卡、Proxy Protocol、MPTCP）？')" n; then
        read -rp "$(L '  出站源 IP through（回车默认自动）: ') [${through:-$(L '无')}]: " ans || { [ -n "$ans" ] || return 1; }
        ans="${ans#[}"; ans="${ans%]}"
        if [ -z "$ans" ]; then through=""
        elif is_ip "$ans" 0; then through="$ans"
        else warn "$(L '非合法 IP，已忽略')"; fi
        read -rp "$(L '  出站网卡 interface（如 eth1，回车默认自动）: ') [${out_if:-$(L '无')}]: " ans || { [ -n "$ans" ] || return 1; }
        if [ -z "$ans" ]; then out_if=""
        elif [[ "$ans" =~ ^[A-Za-z0-9_.-]+$ ]]; then out_if="$ans"
        else warn "$(L '网卡名格式不合法，已忽略')"; fi
        read -rp "$(L '  入站网卡 listen_interface（如 eth0，回车默认自动）: ') [${in_if:-$(L '无')}]: " ans || { [ -n "$ans" ] || return 1; }
        if [ -z "$ans" ]; then in_if=""
        elif [[ "$ans" =~ ^[A-Za-z0-9_.-]+$ ]]; then in_if="$ans"
        else warn "$(L '网卡名格式不合法，已忽略')"; fi
        if [ "$proto" != "udp" ]; then
            confirm "$(L '  向目标发送 Proxy Protocol v2（send_proxy）？')" "$([ "$send_proxy" = "1" ] && echo y || echo n)" && send_proxy=1 || send_proxy=0
            confirm "$(L '  接收来源 Proxy Protocol（accept_proxy）？')" "$([ "$accept_proxy" = "1" ] && echo y || echo n)" && accept_proxy=1 || accept_proxy=0
            confirm "$(L '  启用出站 MPTCP（send_mptcp）？')" "$([ "$send_mptcp" = "1" ] && echo y || echo n)" && send_mptcp=1 || send_mptcp=0
            confirm "$(L '  启用入站 MPTCP（accept_mptcp）？')" "$([ "$accept_mptcp" = "1" ] && echo y || echo n)" && accept_mptcp=1 || accept_mptcp=0
        else
            send_proxy=0; accept_proxy=0; send_mptcp=0; accept_mptcp=0
        fi
    fi

    bak="${f}.bak"
    cp -f "$f" "$bak" || return 1
    ( umask 077; cat > "$f" ) << RULEEOF
RULE_ID="${RULE_ID}"
RULE_ENABLED="${RULE_ENABLED}"
RULE_REMARK="$(dq_escape "$remark")"
RULE_PROTO="${proto}"
RULE_LIP="${lip}"
RULE_LPORT="${lport}"
RULE_RHOST="${rhost}"
RULE_RPORT="${rport}"
RULE_EXTRA_REMOTES="$(dq_escape "$extra_remotes")"
RULE_BALANCE="$(dq_escape "$balance")"
RULE_THROUGH="${through}"
RULE_OUT_IF="${out_if}"
RULE_IN_IF="${in_if}"
RULE_LTRANS="$(dq_escape "$ltrans")"
RULE_RTRANS="$(dq_escape "$rtrans")"
RULE_SEND_PROXY="${send_proxy}"
RULE_ACCEPT_PROXY="${accept_proxy}"
RULE_SEND_MPTCP="${send_mptcp}"
RULE_ACCEPT_MPTCP="${accept_mptcp}"
RULEEOF
    chmod 600 "$f"

    if ! realm_reload_service; then
        mv -f "$bak" "$f"
        realm_reload_service >/dev/null 2>&1 || true
        error "$(L '规则更新失败，已自动恢复原配置')"
    fi
    rm -f "$bak"

    if [ "${RULE_ENABLED:-1}" = "1" ]; then
        local -a fw_specs=()
        [ "$proto" != "udp" ] && fw_specs+=("${lport}/tcp")
        [ "$proto" != "tcp" ] && fw_specs+=("${lport}/udp")
        fw_allow_for_service "${fw_specs[@]}"
    fi
    if [ "$old_port" != "$lport" ] || [ "$old_proto" != "$proto" ]; then
        local old_specs=""
        [ "$old_proto" != "udp" ] && old_specs="${old_specs} ${old_port}/tcp"
        [ "$old_proto" != "tcp" ] && old_specs="${old_specs} ${old_port}/udp"
        fw_prune_old_specs "$old_specs"
    fi
    reserved_ports_sync || true
    success "$(L '规则已更新并生效：')${lip}:${lport} -> ${rhost}:${rport}"
}

realm_show_config() {
    step "$(L '查看完整有效配置（TOML）')"
    divider
    if [ -f "$REALM_CONFIG_FILE" ]; then
        echo -e "${CYAN}# === ${REALM_CONFIG_FILE} ===${NC}"
        cat "$REALM_CONFIG_FILE"
        [ "$(realm_enabled_count)" -eq 0 ] && info "$(L '暂无转发规则')"
        return 0
    fi
    if [ -f "${REALM_CONF_D}/00-base.toml" ]; then
        echo -e "${CYAN}# === 00-base.toml ===${NC}"
        cat "${REALM_CONF_D}/00-base.toml"
    fi
    info "$(L '暂无转发规则')"
}

realm_tune_global() {
    realm_write_base_config
    step "$(L '全局网络 / DNS 参数调优')"
    divider
    echo "  $(L 'DNS 解析策略: 1) ipv4_and_ipv6  2) ipv4_only  3) ipv6_only  4) ipv4_then_ipv6  5) ipv6_then_ipv4')"
    local ans dns_mode="ipv4_and_ipv6" tcp_to="5" udp_to="30" ka="15"
    read -rp "  $(L '选择 DNS 策略 [1-5，默认 1]: ')" ans || { [ -n "$ans" ] || return 1; }
    case "${ans:-1}" in
        2) dns_mode="ipv4_only" ;;
        3) dns_mode="ipv6_only" ;;
        4) dns_mode="ipv4_then_ipv6" ;;
        5) dns_mode="ipv6_then_ipv4" ;;
        *) dns_mode="ipv4_and_ipv6" ;;
    esac
    read -rp "  $(L 'TCP 连接超时 tcp_timeout（秒，默认 5）: ')" ans || { [ -n "$ans" ] || return 1; }
    [[ "${ans:-5}" =~ ^[1-9][0-9]*$ ]] && tcp_to="${ans:-5}"
    read -rp "  $(L 'UDP 会话超时 udp_timeout（秒，默认 30）: ')" ans || { [ -n "$ans" ] || return 1; }
    [[ "${ans:-30}" =~ ^[1-9][0-9]*$ ]] && udp_to="${ans:-30}"
    read -rp "  $(L 'TCP 保活间隔 tcp_keepalive（秒，默认 15）: ')" ans || { [ -n "$ans" ] || return 1; }
    [[ "${ans:-15}" =~ ^[1-9][0-9]*$ ]] && ka="${ans:-15}"

    local base_bak="${REALM_CONF_D}/00-base.toml.bak"
    [ -f "${REALM_CONF_D}/00-base.toml" ] && cp -f "${REALM_CONF_D}/00-base.toml" "$base_bak" || true
    cat > "${REALM_CONF_D}/00-base.toml" << BASEEOF
[log]
level = "warn"
output = "stdout"

[dns]
mode = "${dns_mode}"
protocol = "tcp_and_udp"
min_ttl = 600
max_ttl = 3600
cache_size = 256

[network]
no_tcp = false
use_udp = true
tcp_timeout = ${tcp_to}
udp_timeout = ${udp_to}
tcp_keepalive = ${ka}
tcp_keepalive_probe = 3
BASEEOF
    chmod 640 "${REALM_CONF_D}/00-base.toml" 2>/dev/null || true
    if ! realm_reload_service; then
        [ -f "$base_bak" ] && mv -f "$base_bak" "${REALM_CONF_D}/00-base.toml"
        realm_reload_service >/dev/null 2>&1 || true
        error "$(L '配置更新失败，已恢复原配置')"
    fi
    rm -f "$base_bak"
    success "$(L '配置已更新并重启')"
    return 0
}

realm_menu() {
    local choice
    while true; do
        clear 2>/dev/null || true
        maint_load
        echo -e "${BOLD}${CYAN}━━━ $(L 'Realm 端口转发管理') ━━━${NC}"
        echo -e "  $(L '当前状态:') $(realm_state_text)    $(L '自动更新:') $(maint_onoff "${MAINT_REALM_AUTO:-0}")"
        divider
        echo -e "  ${GREEN}1)${NC}  $(L '安装 / 更新 Realm')"
        echo -e "  ${GREEN}2)${NC}  $(L '添加转发规则（TCP/UDP/LB/隧道/多网卡）')"
        echo -e "  ${GREEN}3)${NC}  $(L '批量添加转发规则（端口段 / 多端口）')"
        echo -e "  ${GREEN}4)${NC}  $(L '查看转发规则列表')"
        echo -e "  ${GREEN}5)${NC}  $(L '编辑已有转发规则')"
        echo -e "  ${GREEN}6)${NC}  $(L '启用 / 停用单条规则')"
        echo -e "  ${GREEN}7)${NC}  $(L '删除转发规则')"
        echo -e "  ${GREEN}8)${NC}  $(L '测试目标连通性与延迟')"
        echo -e "  ${GREEN}9)${NC}  $(L '查看完整有效配置（TOML）')"
        echo -e "  ${GREEN}10)${NC} $(L '全局网络 / DNS 参数调优')"
        echo -e "  ${GREEN}11)${NC} $(L 'Realm 自动更新 开 / 关') [$(maint_onoff "${MAINT_REALM_AUTO:-0}")]"
        echo -e "  ${GREEN}12)${NC} $(L '重启服务 / 查看状态与日志')"
        echo -e "  ${GREEN}13)${NC} $(L '导出规则（迁移备份）')"
        echo -e "  ${GREEN}14)${NC} $(L '导入规则（从备份恢复）')"
        echo -e "  ${GREEN}15)${NC} $(L '修复 Realm（重建配置 / 权限收敛 / 同步防火墙并重启）')"
        echo -e "  ${GREEN}16)${NC} ${RED}$(L '卸载')${NC} Realm"
        echo -e "  ${GREEN}0)${NC}  $(L '返回主菜单')"
        divider
        read -rp "$(L '请选择') [0-16]: " choice || return 0
        case "$choice" in
            1)  run_action realm_install ;;
            2)  run_action realm_add_rule ;;
            3)  run_action realm_add_batch_rules ;;
            4)  run_action realm_list_rules ;;
            5)  run_action realm_edit_rule ;;
            6)  run_action realm_toggle_rule ;;
            7)  run_action realm_delete_rule ;;
            8)  run_action realm_test_rules ;;
            9)  run_action realm_show_config ;;
            10) run_action realm_tune_global ;;
            11) run_action maint_toggle MAINT_REALM_AUTO ;;
            12) run_action bash -c 'systemctl restart adam-realm 2>/dev/null || true; systemctl status adam-realm --no-pager || true; journalctl -u adam-realm -n 20 --no-pager || true' ;;
            13) run_action realm_export_rules ;;
            14) run_action realm_import_rules ;;
            15) run_action realm_repair ;;
            16) run_action realm_uninstall ;;
            0)  return 0 ;;
            *)  warn "$(L '无效选择')" ;;
        esac
        pause_return
    done
}

realm_cli() {
    local sub="${1:-menu}"
    [ "$#" -gt 0 ] && shift
    case "$sub" in
        menu)      realm_menu ;;
        install|update) realm_install ;;
        add)       realm_add_rule ;;
        batch)     realm_add_batch_rules ;;
        edit)      realm_edit_rule ;;
        list)      realm_list_rules ;;
        toggle)    realm_toggle_rule ;;
        delete)    realm_delete_rule ;;
        test)      realm_test_rules ;;
        config)    realm_show_config ;;
        tune)      realm_tune_global ;;
        auto)      maint_toggle MAINT_REALM_AUTO ;;
        repair)    realm_repair ;;
        restart)   realm_reload_service && success "$(L 'Realm 已重启')" ;;
        status)    systemctl status adam-realm --no-pager || true ;;
        logs)      journalctl -u adam-realm -f || true ;;
        export)    realm_export_rules ;;
        import)    realm_import_rules ;;
        uninstall) realm_uninstall ;;
        *) error "$(L '未知的 realm 子命令:') ${sub}$(L '（可用: install / add / batch / edit / list / toggle / delete / test / config / tune / auto / repair / restart / status / logs / export / import / uninstall）')" ;;
    esac
}

