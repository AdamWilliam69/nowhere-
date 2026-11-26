# ══════════════════════════════════════════════════════════════
#   一键域名反代模块（Caddy 多域名自动 HTTPS + Cloudflare Tunnel）
#   Caddy 配置：/etc/adam-caddy/Caddyfile + /etc/adam-caddy/sites/<id>.env / <id>.caddy
#   Cloudflare Tunnel：/etc/adam-cloudflared/tunnel.env（TUNNEL_TOKEN 600 权限，不进命令行参数）
# ══════════════════════════════════════════════════════════════

caddy_installed() { [ -x "$CADDY_BIN" ]; }
cf_tunnel_installed() { [ -x "$CF_TUNNEL_BIN" ]; }

caddy_load_state() {
    state_load "$CADDY_STATE_FILE" "CADDY_EMAIL="
    return 0
}

caddy_save_state() {
    state_save "$CADDY_STATE_FILE" "$CADDY_DIR" 750 CADDY_EMAIL
}

caddy_site_files() {
    local f
    [ -d "$CADDY_SITES_DIR" ] || return 0
    for f in "${CADDY_SITES_DIR}"/*.env; do
        [ -f "$f" ] && printf '%s\n' "$f"
    done
}

caddy_enabled_count() {
    local f n=0
    while IFS= read -r f; do
        grep -q '^SITE_ENABLED="1"$' "$f" 2>/dev/null && n=$((n + 1))
    done < <(caddy_site_files)
    printf '%s' "$n"
}

caddy_ports() {
    local f
    while IFS= read -r f; do
        (
            env_file_safe "$f" || exit 0
            # shellcheck disable=SC1090
            source "$f" 2>/dev/null || exit 0
            [ "${SITE_ENABLED:-0}" = "1" ] || exit 0
            if [ "${SITE_MODE:-https}" = "http" ]; then
                validate_port "${SITE_PORT:-80}" || exit 0
                echo "$((10#${SITE_PORT:-80}))/tcp"
            else
                echo "80/tcp"
                echo "443/tcp"
                echo "443/udp"
            fi
        )
    done < <(caddy_site_files) | sort -u
}

caddy_healthy() {
    [ "$(caddy_enabled_count)" -gt 0 ] || return 0
    caddy_installed || return 1
    systemctl is-active --quiet adam-caddy 2>/dev/null || return 1
    local spec
    while IFS= read -r spec; do
        [ -n "$spec" ] || continue
        if [[ "$spec" == */tcp ]]; then
            tcp_listening "${spec%/tcp}" || return 1
        fi
    done < <(caddy_ports)
    return 0
}

caddy_wait_healthy() {
    local i
    for i in 1 2 3 4 5; do
        caddy_healthy && return 0
        sleep 1
    done
    return 1
}

proxy_state_text() {
    local ctxt="" ttxt=""
    if caddy_installed; then
        local total=0 en=0 f cver
        while IFS= read -r f; do
            total=$((total + 1))
            grep -q '^SITE_ENABLED="1"$' "$f" 2>/dev/null && en=$((en + 1))
        done < <(caddy_site_files)
        cver="$("$CADDY_BIN" version 2>/dev/null | awk '{print $1}' || true)"
        ctxt="Caddy ${cver:-?} (${en}/${total} $(L '个站点') · $(svc_state adam-caddy))"
    fi
    if cf_tunnel_installed; then
        if systemctl is-active --quiet adam-cloudflared 2>/dev/null; then
            ttxt="CF-Tunnel ${GREEN}$(L '隧道已运行')${NC}"
        elif [ -f "$CF_TUNNEL_ENV" ]; then
            ttxt="CF-Tunnel $(L '已配置') · $(svc_state adam-cloudflared)"
        else
            ttxt="CF-Tunnel $(L '已安装')"
        fi
    fi
    if [ -n "$ctxt" ] && [ -n "$ttxt" ]; then
        printf '%s  |  %s' "$ctxt" "$ttxt"
    elif [ -n "$ctxt" ]; then
        printf '%s' "$ctxt"
    elif [ -n "$ttxt" ]; then
        printf '%s' "$ttxt"
    else
        printf '%s' "${YELLOW}$(L '未安装')${NC}"
    fi
}

caddy_latest_tag() {
    github_latest_tag "$CADDY_REPO"
}

caddy_fetch_binary() {
    local tag="$1" arch ver_num asset url sums_url expected_256="" expected_raw="" actual bin
    case "$(uname -m)" in
        x86_64|amd64)  arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        armv7l)        arch="armv7" ;;
        *) warn "$(L '不支持的架构:') $(uname -m)"; return 1 ;;
    esac
    ver_num="${tag#v}"
    asset="caddy_${ver_num}_linux_${arch}.tar.gz"
    url="https://github.com/${CADDY_REPO}/releases/download/${tag}/${asset}"
    sums_url="https://github.com/${CADDY_REPO}/releases/download/${tag}/caddy_${ver_num}_checksums.txt"

    CADDY_DL_BIN=""
    make_workdir || return 1
    local wd="$WORKDIR"
    if ! secure_curl -fL --retry 3 --connect-timeout 10 --max-time 300 -o "${wd}/${asset}" "$url"; then
        warn "$(L '下载失败:') ${url}"
        return 1
    fi
    expected_256="$(github_asset_sha256 "$CADDY_REPO" "$tag" "$asset" || true)"
    if [ -z "$expected_256" ] && secure_curl -fsSL --max-time 20 -o "${wd}/checksums.txt" "$sums_url" 2>/dev/null; then
        expected_raw="$(awk -v a="$asset" '$2 == a || $2 == "*"a {print tolower($1); exit}' "${wd}/checksums.txt" || true)"
    fi
    if [[ "$expected_256" =~ ^[0-9a-f]{64}$ ]]; then
        actual="$(sha256sum "${wd}/${asset}" | awk '{print tolower($1)}')"
        if [ "$expected_256" != "$actual" ]; then
            warn "$(L 'SHA256 校验失败（官方') ${expected_256}$(L '，实际') ${actual}$(L '），已中止')"
            return 1
        fi
        success "$(L 'SHA256 校验通过（')${asset}$(L '）')"
    elif [[ "$expected_raw" =~ ^[0-9a-f]{64}$ ]]; then
        actual="$(sha256sum "${wd}/${asset}" | awk '{print tolower($1)}')"
        if [ "$expected_raw" != "$actual" ]; then
            warn "$(L 'SHA256 校验失败（官方') ${expected_raw}$(L '，实际') ${actual}$(L '），已中止')"
            return 1
        fi
        success "$(L 'SHA256 校验通过（')${asset}$(L '）')"
    elif [[ "$expected_raw" =~ ^[0-9a-f]{128}$ ]]; then
        actual="$(sha512sum "${wd}/${asset}" | awk '{print tolower($1)}')"
        if [ "$expected_raw" != "$actual" ]; then
            warn "$(L 'SHA512 校验失败（官方') ${expected_raw}$(L '，实际') ${actual}$(L '），已中止')"
            return 1
        fi
        success "$(L 'SHA512 校验通过（')${asset}$(L '）')"
    else
        warn "$(L '未取到官方校验摘要（')${asset}$(L '）')"
        if [ ! -t 0 ] || ! confirm "$(L '未能获取官方摘要，是否仍继续安装？')" n; then
            return 1
        fi
    fi
    tar -xzf "${wd}/${asset}" --no-same-owner -C "$wd" || { warn "$(L '解压失败')"; return 1; }
    bin="$(find "$wd" -maxdepth 2 -type f -name caddy ! -type l 2>/dev/null | head -1 || true)"
    [ -n "$bin" ] || { warn "$(L '解压失败')"; return 1; }
    verify_elf_binary "$bin" || { warn "$(L '下载到的二进制不是本机架构的 ELF 可执行文件，已中止')"; return 1; }
    chmod 755 "$bin"
    if command -v timeout >/dev/null 2>&1; then
        timeout 10 "$bin" version >/dev/null 2>&1 || { warn "$(L '下载到的二进制无法在本机运行（架构或 libc 不匹配），已中止，现有安装未被改动')"; return 1; }
    else
        "$bin" version >/dev/null 2>&1 || { warn "$(L '下载到的二进制无法在本机运行（架构或 libc 不匹配），已中止，现有安装未被改动')"; return 1; }
    fi
    CADDY_DL_BIN="$bin"
    return 0
}

# 校验 Caddy reverse_proxy 上游地址（拒绝带路径后缀，避免 Caddy 报 upstream address cannot contain a path）
caddy_valid_upstream() {
    local u="$1"
    [ -n "$u" ] || return 1
    if [[ "$u" =~ ^https?://(\[[0-9A-Fa-f:]+\]|[A-Za-z0-9._-]+)(:([0-9]{1,5}))?$ ]]; then
        if [ -n "${BASH_REMATCH[3]:-}" ]; then
            validate_port "${BASH_REMATCH[3]}" || return 1
        fi
        return 0
    fi
    if [[ "$u" =~ ^(\[[0-9A-Fa-f:]+\]|[A-Za-z0-9._-]+):([0-9]{1,5})$ ]]; then
        validate_port "${BASH_REMATCH[2]}" && return 0
    fi
    return 1
}

# 检查 domain+mode+port 是否与已有站点冲突（可选 $4 排除自身 SITE_ID）
caddy_site_conflict() {
    local domain="$1" mode="$2" port="$3" skip_id="${4:-}" _sf
    while IFS= read -r _sf; do
        if (
            env_file_safe "$_sf" || exit 1
            # shellcheck disable=SC1090
            source "$_sf" 2>/dev/null || exit 1
            [ -n "$skip_id" ] && [ "${SITE_ID:-}" = "$skip_id" ] && exit 1
            [ "${SITE_DOMAIN:-}" = "$domain" ] || exit 1
            if [ "$mode" = "http" ] && [ "${SITE_MODE:-https}" = "http" ]; then
                [ "${SITE_PORT:-80}" = "$port" ] && exit 0
            elif [ "$mode" != "http" ] && [ "${SITE_MODE:-https}" != "http" ]; then
                exit 0
            fi
            exit 1
        ); then
            return 0
        fi
    done < <(caddy_site_files)
    return 1
}

caddy_fix_perms() {
    local f grp="root"
    if [ ! -f "${CADDY_DIR}/run-as-root" ] && getent group adam-caddy >/dev/null 2>&1; then
        grp="adam-caddy"
    fi
    if [ -d "$CADDY_DIR" ] && [ ! -L "$CADDY_DIR" ]; then
        chown -h "root:${grp}" "$CADDY_DIR" 2>/dev/null || true
        chmod 750 "$CADDY_DIR" 2>/dev/null || true
    fi
    if [ -d "$CADDY_SITES_DIR" ] && [ ! -L "$CADDY_SITES_DIR" ]; then
        chown -h "root:${grp}" "$CADDY_SITES_DIR" 2>/dev/null || true
        chmod 750 "$CADDY_SITES_DIR" 2>/dev/null || true
    fi
    if [ -f "$CADDY_STATE_FILE" ] && [ ! -L "$CADDY_STATE_FILE" ]; then
        chown -h root:root "$CADDY_STATE_FILE" 2>/dev/null || true
        chmod 600 "$CADDY_STATE_FILE" 2>/dev/null || true
    fi
    if [ -f "$CADDY_FILE" ] && [ ! -L "$CADDY_FILE" ]; then
        chown -h "root:${grp}" "$CADDY_FILE" 2>/dev/null || true
        chmod 640 "$CADDY_FILE" 2>/dev/null || true
    fi
    if [ -d "$CADDY_SITES_DIR" ] && [ ! -L "$CADDY_SITES_DIR" ]; then
        for f in "${CADDY_SITES_DIR}"/*.env; do
            [ -f "$f" ] && [ ! -L "$f" ] || continue
            chown -h root:root "$f" 2>/dev/null || true
            chmod 600 "$f" 2>/dev/null || true
        done
        for f in "${CADDY_SITES_DIR}"/*.caddy; do
            [ -f "$f" ] && [ ! -L "$f" ] || continue
            chown -h "root:${grp}" "$f" 2>/dev/null || true
            chmod 640 "$f" 2>/dev/null || true
        done
    fi
    if [ -d "$CADDY_DATA_DIR" ] && [ ! -L "$CADDY_DATA_DIR" ]; then
        if [ "$grp" = "adam-caddy" ] && id adam-caddy >/dev/null 2>&1; then
            find "$CADDY_DATA_DIR" ! -type l -exec chown -h adam-caddy:adam-caddy {} + 2>/dev/null || true
        else
            find "$CADDY_DATA_DIR" ! -type l -exec chown -h root:root {} + 2>/dev/null || true
        fi
        chmod 700 "$CADDY_DATA_DIR" 2>/dev/null || true
    fi
}

caddy_write_main_config() {
    install -d -m 750 "$CADDY_DIR" "$CADDY_SITES_DIR"
    [ -d "$CADDY_DATA_DIR" ] || install -d -m 700 "$CADDY_DATA_DIR"
    chmod 700 "$CADDY_DATA_DIR" 2>/dev/null || true
    caddy_load_state
    {
        printf '{\n'
        printf '    admin off\n'
        [ -n "${CADDY_EMAIL:-}" ] && printf '    email %s\n' "$CADDY_EMAIL"
        printf '}\n\n'
        printf 'import %s/*.caddy\n' "$CADDY_SITES_DIR"
    } > "$CADDY_FILE"
    chmod 640 "$CADDY_FILE"
}

caddy_write_service() {
    local run_user="adam-caddy" run_group="adam-caddy"
    if [ -f "${CADDY_DIR}/run-as-root" ]; then
        run_user=""; run_group=""
    elif ! ensure_system_user adam-caddy adam-caddy 2>/dev/null; then
        run_user=""; run_group=""
    else
        install -d -m 700 -o adam-caddy -g adam-caddy "$CADDY_DATA_DIR" 2>/dev/null || true
        find "$CADDY_DATA_DIR" ! -type l -exec chown -h adam-caddy:adam-caddy {} + 2>/dev/null || true
        chmod 700 "$CADDY_DATA_DIR" 2>/dev/null || true
    fi
    write_service_unit "$CADDY_SERVICE" "Adam Caddy Reverse Proxy" "https://caddyserver.com/docs/" "60" "$run_user" "$run_group" \
        "${CADDY_BIN} run --environ --config ${CADDY_FILE} --adapter caddyfile" \
        "CAP_NET_BIND_SERVICE" "1048576" "always" "3" \
        "Environment=XDG_DATA_HOME=${CADDY_DATA_DIR}
Environment=XDG_CONFIG_HOME=${CADDY_DATA_DIR}
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=${CADDY_DATA_DIR}" "StartLimitBurst=10"
    systemctl daemon-reload || true
}

caddy_render_site() {
    local id="$1"
    local env_file="${CADDY_SITES_DIR}/${id}.env"
    local caddy_file="${CADDY_SITES_DIR}/${id}.caddy"
    [ -f "$env_file" ] || { rm -f "$caddy_file"; return 0; }
    (
        env_file_safe "$env_file" || exit 1
        # shellcheck disable=SC1090
        source "$env_file" 2>/dev/null || exit 1
        if [ "${SITE_ENABLED:-0}" != "1" ]; then
            rm -f "$caddy_file"
            exit 0
        fi
        # 渲染前纵深校验，防止被篡改或导入的 .env 向 Caddyfile 注入任意指令
        local re_dom='^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$'
        [[ "${SITE_DOMAIN:-}" == *.* && "${SITE_DOMAIN:-}" =~ $re_dom ]] || exit 1
        caddy_valid_upstream "${SITE_UPSTREAM:-}" || exit 1
        case "${SITE_REMARK:-}" in *$'\n'*|*$'\r'*) exit 1 ;; esac
        local addr="" up="${SITE_UPSTREAM}"
        case "${SITE_MODE:-https}" in
            http)
                local sp="${SITE_PORT:-80}"
                validate_port "$sp" || exit 1
                sp=$((10#$sp))
                addr="http://${SITE_DOMAIN}:${sp}"
                ;;
            *)
                addr="${SITE_DOMAIN}"
                ;;
        esac
        local tmpf
        tmpf="$(mktemp "${CADDY_SITES_DIR}/.${id}.XXXXXX")" || exit 1
        {
            echo "# id=${id} mode=${SITE_MODE:-https} remark=${SITE_REMARK:-}"
            echo "${addr} {"
            echo "    encode zstd gzip"
            if [ "${SITE_MODE:-https}" = "remote" ]; then
                echo "    reverse_proxy ${up} {"
                echo "        header_up Host {upstream_hostport}"
                echo "        header_up X-Real-IP {remote_host}"
                if [ "${SITE_INSECURE:-0}" = "1" ]; then
                    echo "        transport http {"
                    echo "            tls_insecure_skip_verify"
                    echo "        }"
                fi
                echo "    }"
            else
                echo "    reverse_proxy ${up} {"
                echo "        flush_interval -1"
                echo "        header_up X-Real-IP {remote_host}"
                if [ "${SITE_INSECURE:-0}" = "1" ]; then
                    echo "        transport http {"
                    echo "            tls_insecure_skip_verify"
                    echo "        }"
                fi
                echo "    }"
            fi
            echo "}"
        } > "$tmpf" || { rm -f "$tmpf"; exit 1; }
        chmod 640 "$tmpf"
        mv -f "$tmpf" "$caddy_file"
    )
}

caddy_rebuild_all() {
    caddy_write_main_config || return 1
    local f id rc=0
    while IFS= read -r f; do
        id="$(basename "$f" .env)"
        if ! caddy_render_site "$id"; then
            warn "$(L '渲染站点配置失败:') ${id}"
            rm -f "${CADDY_SITES_DIR}/${id}.caddy"
            rc=1
        fi
    done < <(caddy_site_files)
    local c
    for c in "${CADDY_SITES_DIR}"/*.caddy; do
        [ -f "$c" ] || continue
        id="$(basename "$c" .caddy)"
        [ -f "${CADDY_SITES_DIR}/${id}.env" ] || rm -f "$c"
    done
    caddy_fix_perms
    return "$rc"
}

caddy_reload_service() {
    caddy_rebuild_all || return 1
    if [ "$(caddy_enabled_count)" -eq 0 ]; then
        systemctl disable --now adam-caddy 2>/dev/null || true
        return 0
    fi
    caddy_installed || return 0
    local out vtmp
    vtmp="$(mktemp -d /tmp/adam-caddy-val.XXXXXX 2>/dev/null || echo /tmp)"
    if ! out="$(XDG_DATA_HOME="$vtmp" XDG_CONFIG_HOME="$vtmp" "$CADDY_BIN" validate --config "$CADDY_FILE" --adapter caddyfile 2>&1)"; then
        [ "$vtmp" != "/tmp" ] && rm -rf "$vtmp"
        warn "$(L '配置校验未通过：')"
        printf '%s\n' "$out" | tail -n 8
        return 1
    fi
    [ "$vtmp" != "/tmp" ] && rm -rf "$vtmp"
    [ -f "$CADDY_SERVICE" ] || caddy_write_service
    caddy_fix_perms
    systemctl enable adam-caddy >/dev/null 2>&1 || true
    if svc_restart_wait adam-caddy 2 15 && caddy_wait_healthy; then
        return 0
    fi
    if grep -q '^User=' "$CADDY_SERVICE" 2>/dev/null; then
        local _svc_bak="${CADDY_SERVICE}.rootbak"
        cp -p "$CADDY_SERVICE" "$_svc_bak" 2>/dev/null || true
        sed -i '/^User=/d; /^Group=/d' "$CADDY_SERVICE" || { [ -f "$_svc_bak" ] && mv -f "$_svc_bak" "$CADDY_SERVICE"; return 1; }
        systemctl daemon-reload || true
        # 重试前先切 root 标记并调整 CADDY_DATA_DIR 归属，否则 CapabilityBoundingSet 限制下 UID 0 仍会 EACCES
        touch "${CADDY_DIR}/run-as-root" 2>/dev/null || true
        caddy_fix_perms
        if svc_restart_wait adam-caddy 2 15 && caddy_wait_healthy; then
            rm -f "$_svc_bak"
            return 0
        fi
        rm -f "${CADDY_DIR}/run-as-root" 2>/dev/null || true
        if [ -f "$_svc_bak" ]; then mv -f "$_svc_bak" "$CADDY_SERVICE"; fi
        systemctl daemon-reload || true
        caddy_fix_perms
    fi
    return 1
}

_caddy_repair_core() {
    local quiet="${1:-}" spec
    caddy_installed || return 1
    install -d -m 750 "$CADDY_DIR" "$CADDY_SITES_DIR"
    [ -d "$CADDY_DATA_DIR" ] || install -d -m 700 "$CADDY_DATA_DIR"
    caddy_write_service
    caddy_rebuild_all || return 1
    if ufw_active; then
        while IFS= read -r spec; do
            [ -n "$spec" ] && { ufw allow "$spec" >/dev/null 2>&1 || true; }
        done < <(caddy_ports)
    fi
    reserved_ports_sync || true
    systemctl reset-failed adam-caddy 2>/dev/null || true
    if [ "$(caddy_enabled_count)" -gt 0 ]; then
        caddy_reload_service || return 1
    else
        [ "$quiet" = "quiet" ] || info "$(L '当前无已启用的 Caddy 站点，已完成权限与配置修复')"
    fi
    return 0
}

caddy_repair() {
    step "$(L '修复 Caddy（重建配置 / 权限收敛 / 同步防火墙并重启）')"
    divider
    if ! caddy_installed; then
        warn "$(L '尚未安装 Caddy，请先安装')"
        return 1
    fi
    maint_install_timers >/dev/null 2>&1 || true
    if _caddy_repair_core; then
        success "$(L 'Caddy 修复完成，状态正常')"
        return 0
    fi
    warn "$(L 'Caddy 修复后仍未恢复正常，最近日志：')"
    journalctl -u adam-caddy -n 25 --no-pager || true
    return 1
}

caddy_install() {
    step "$(L '安装 / 更新 Caddy（官方仓库）')"
    divider
    preflight_install_check "Caddy" "$CADDY_BIN" "$CADDY_DIR" || return 1
    apt_install curl tar ca-certificates iproute2 || true
    info "$(L '正在查询 Caddy 官方最新版本...')"
    local tag cur=""
    tag="$(caddy_latest_tag)"
    [ -n "$tag" ] || error "$(L '无法获取 Caddy 最新版本号，请检查网络')"
    if caddy_installed; then cur="$("$CADDY_BIN" version 2>/dev/null | awk '{print $1}' || true)"; fi
    info "$(L '最新版本:') ${tag}"
    [ -n "$cur" ] && info "$(L '当前版本:') ${cur}"
    if [ -n "$cur" ] && [ "${cur#v}" = "${tag#v}" ]; then
        confirm "$(L '已是最新版本，仍要重新安装？')" n || return 0
    fi
    while ! caddy_fetch_binary "$tag"; do
        confirm "$(L '下载失败，是否立即重试？')" y || error "$(L '下载或校验失败，已中止')"
    done
    install -d -m 750 "$CADDY_DIR" "$CADDY_SITES_DIR"
    [ -d "$CADDY_DATA_DIR" ] || install -d -m 700 "$CADDY_DATA_DIR"
    if [ -f "$CADDY_BIN" ]; then cp -f "$CADDY_BIN" "$CADDY_BIN_BACKUP" 2>/dev/null || true; fi
    install -m 755 "$CADDY_DL_BIN" "$CADDY_BIN"
    caddy_load_state
    if [ -z "${CADDY_EMAIL:-}" ] && [ -t 0 ]; then
        local em=""
        read -rp "$(L 'ACME 邮箱（证书账户用）:') " em || true
        em="$(printf '%s' "$em" | tr -d ' \r\n')"
        if [[ "$em" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
            CADDY_EMAIL="$em"; caddy_save_state
        fi
    fi
    caddy_write_main_config
    caddy_write_service
    caddy_fix_perms
    if [ "$(caddy_enabled_count)" -gt 0 ]; then
        if ! caddy_reload_service; then
            if [ -f "$CADDY_BIN_BACKUP" ]; then
                install -m 755 "$CADDY_BIN_BACKUP" "$CADDY_BIN"
                caddy_reload_service >/dev/null 2>&1 || true
            fi
            error "$(L '更新失败')"
        fi
    fi
    maint_install_timers >/dev/null 2>&1 || true
    success "$(L 'Caddy 安装完成') (${tag})"
}

caddy_autoupdate() {
    caddy_installed || return 0
    local cur latest
    cur="$("$CADDY_BIN" version 2>/dev/null | awk '{print $1}' || true)"
    latest="$(caddy_latest_tag)"
    if [ -z "$latest" ]; then
        echo "[Caddy] $(L '未能获取官方版本信息，本次跳过；当前') ${cur:-$(L '未知')}"
        return 1
    fi
    if [ -n "$cur" ] && version_ge "$cur" "$latest"; then
        echo "[Caddy] $(L '已是最新:') ${cur}"
        return 0
    fi
    if ! caddy_fetch_binary "$latest"; then
        maint_log "[Caddy] $(L '自动更新到') ${latest} $(L '失败，当前仍为') ${cur:-$(L '未知')}"
        return 1
    fi
    cp -f "$CADDY_BIN" "$CADDY_BIN_BACKUP" 2>/dev/null || true
    install -m 755 "$CADDY_DL_BIN" "$CADDY_BIN"
    if [ "$(caddy_enabled_count)" -gt 0 ] && ! caddy_reload_service; then
        [ -f "$CADDY_BIN_BACKUP" ] && install -m 755 "$CADDY_BIN_BACKUP" "$CADDY_BIN"
        caddy_reload_service >/dev/null 2>&1 || true
        maint_log "[Caddy] $(L '自动更新到') ${latest} $(L '失败，当前仍为') ${cur:-$(L '未知')}"
        notify_send "Caddy Auto-Rollback" "Auto-update to ${latest} failed; rolled back to ${cur:-previous}." || true
        return 1
    fi
    maint_log "[Caddy] $(L '已自动更新:') ${cur:-$(L '未知')} -> ${latest}"
    return 0
}

caddy_next_id() {
    local i=1 id
    while true; do
        id="$(printf 's%02d' "$i")"
        [ ! -f "${CADDY_SITES_DIR}/${id}.env" ] && { printf '%s' "$id"; return 0; }
        i=$((i + 1))
    done
}

caddy_add_site() {
    caddy_installed || { warn "$(L '尚未安装 Caddy，请先安装')"; return 1; }
    step "$(L '添加域名反代站点（自动 HTTPS）')"
    divider

    local id domain upstream mode="https" port="443" insecure=0 remark="" ans
    local re_dom='^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$'

    while true; do
        read -rp "$(L '请输入域名（如: nhk.example.com）:') " domain || { [ -n "$domain" ] || return 1; }
        domain="$(printf '%s' "$domain" | tr -d ' \r\n')"
        domain="${domain,,}"
        if [[ "$domain" == *.* && "$domain" =~ $re_dom ]]; then break; fi
        warn "$(L '域名格式不正确')"
    done

    echo "$(L '反代模式：')"
    echo "  1) $(L '标准反代（本机/内网服务，自动 HTTPS + WebSocket/XHTTP 透传，推荐）')"
    echo "  2) $(L '反代远程站点（自动改写 Host 头，支持 HTTPS 上游）')"
    echo "  3) $(L 'HTTP 明文反代 / 自定义端口（适合套 Cloudflare CDN 灵活模式或非 443 端口）')"
    read -rp "$(L '选择 [1-3，默认 1]: ')" ans || { [ -n "$ans" ] || return 1; }
    case "${ans:-1}" in
        2) mode="remote" ;;
        3)
            mode="http"
            while true; do
                read -rp "$(L '本机监听端口 (1-65535): ') [default 80]: " port || { [ -n "$port" ] || return 1; }
                port="${port:-80}"
                validate_port "$port" && { port=$((10#$port)); break; }
                warn "$(L '端口不合法')"
            done
            ;;
        *) mode="https" ;;
    esac

    # 防重复域名+端口冲突（会导致 Caddy ambiguous site definition 校验失败）
    if caddy_site_conflict "$domain" "$mode" "$port"; then
        warn "$(L '该域名与端口组合已存在反代配置，请改用「编辑反代站点」')"
        return 1
    fi

    local occ="" occ80=""
    if [ "$mode" != "http" ]; then
        check_domain_dns "$domain" || true
        occ80="$(check_port_occupied_by_other tcp 80 caddy || true)"
        if [ -n "$occ80" ]; then
            warn "$(L '端口 ')80$(L ' 已被其他进程占用：')"
            echo "$occ80"
            confirm "$(L '仍要继续添加？')" n || return 0
        fi
        occ="$(check_port_occupied_by_other tcp 443 caddy || true)"
        if [ -n "$occ" ]; then
            warn "$(L '端口 ')443$(L ' 已被其他进程占用：')"
            echo "$occ"
            confirm "$(L '仍要继续添加？')" n || return 0
        fi
    else
        occ="$(check_port_occupied_by_other tcp "$port" caddy || true)"
        if [ -n "$occ" ]; then
            warn "$(L '端口 ')${port}$(L ' 已被其他进程占用：')"
            echo "$occ"
            confirm "$(L '仍要继续添加？')" n || return 0
        fi
    fi

    while true; do
        read -rp "$(L '上游目标地址（如 127.0.0.1:8080 或 https://example.com）: ')" upstream || { [ -n "$upstream" ] || return 1; }
        upstream="$(printf '%s' "$upstream" | tr -d ' \r\n')"
        upstream="${upstream%/}"
        if caddy_valid_upstream "$upstream"; then break; fi
        warn "$(L '目标地址格式不合法')"
    done
    if [[ "$upstream" == https://* ]]; then
        if confirm "$(L '跳过上游 TLS 证书校验（自签上游选 y）？')" n; then insecure=1; fi
    fi

    read -rp "$(L '规则备注（可选）: ')" remark || { [ -n "$remark" ] || return 1; }
    remark="${remark//\"/}"

    id="$(caddy_next_id)"
    local env_file="${CADDY_SITES_DIR}/${id}.env"
    install -d -m 750 "$CADDY_SITES_DIR"
    ( umask 077; cat > "$env_file" ) << SITEEOF
SITE_ID="${id}"
SITE_ENABLED="1"
SITE_DOMAIN="${domain}"
SITE_MODE="${mode}"
SITE_PORT="${port}"
SITE_UPSTREAM="${upstream}"
SITE_INSECURE="${insecure}"
SITE_REMARK="$(dq_escape "$remark")"
SITEEOF
    chmod 600 "$env_file"

    if ! caddy_reload_service; then
        rm -f "$env_file" "${CADDY_SITES_DIR}/${id}.caddy"
        caddy_reload_service >/dev/null 2>&1 || true
        error "$(L 'Caddy 配置校验失败，已自动撤回改动')"
    fi

    if [ "$mode" = "http" ]; then
        fw_allow_for_service "${port}/tcp"
    else
        fw_allow_for_service "80/tcp" "443/tcp" "443/udp"
    fi
    reserved_ports_sync || true
    success "$(L '反代站点已生效：')${domain} -> ${upstream}"
}

caddy_list_sites() {
    step "$(L '反代站点列表')"
    divider
    local f idx=0 st
    while IFS= read -r f; do
        idx=$((idx + 1))
        (
            env_file_safe "$f" || exit 0
            # shellcheck disable=SC1090
            source "$f" 2>/dev/null || exit 0
            if [ "${SITE_ENABLED:-0}" = "1" ]; then st="${GREEN}$(L '启用')${NC}"; else st="${YELLOW}$(L '停用')${NC}"; fi
            local pinfo=""
            [ "${SITE_MODE:-https}" = "http" ] && pinfo=":${SITE_PORT:-80} [HTTP]" || pinfo=" [HTTPS/${SITE_MODE}]"
            echo -e "  ${BOLD}${idx})${NC} [${SITE_ID}] ${st}  ${CYAN}${SITE_DOMAIN}${pinfo}${NC} -> ${GREEN}${SITE_UPSTREAM}${NC}${SITE_REMARK:+  # ${SITE_REMARK}}"
        )
    done < <(caddy_site_files)
    if [ "$idx" -eq 0 ]; then info "$(L '暂无反代站点')"; fi
    return 0
}

caddy_pick_site() {
    local -a files=()
    local f choice
    while IFS= read -r f; do files+=("$f"); done < <(caddy_site_files)
    [ "${#files[@]}" -gt 0 ] || { info "$(L '暂无反代站点')"; return 1; }
    caddy_list_sites
    echo ""
    read -rp "$(L '输入站点序号（回车取消）: ')" choice || { [ -n "$choice" ] || return 1; }
    [[ -n "$choice" && "$choice" =~ ^[0-9]+$ ]] || return 1
    choice=$((10#$choice))
    [ "$choice" -ge 1 ] && [ "$choice" -le "${#files[@]}" ] || { warn "$(L '序号无效')"; return 1; }
    PICKED_SITE_FILE="${files[$((choice - 1))]}"
    return 0
}

caddy_toggle_site() {
    caddy_pick_site || return 0
    local f="$PICKED_SITE_FILE" bak="${PICKED_SITE_FILE}.bak" cur next mode port
    env_file_safe "$f" || { warn "$(L '站点配置文件格式异常')"; return 1; }
    cur="$(grep -m1 '^SITE_ENABLED=' "$f" | cut -d'"' -f2 || echo 0)"
    mode="$(grep -m1 '^SITE_MODE=' "$f" | cut -d'"' -f2 || echo https)"
    port="$(grep -m1 '^SITE_PORT=' "$f" | cut -d'"' -f2 || echo 443)"
    if [ "$cur" = "1" ]; then next="0"; else next="1"; fi
    cp -f "$f" "$bak" || return 1
    sed -i "s|^SITE_ENABLED=.*|SITE_ENABLED=\"${next}\"|" "$f" || { mv -f "$bak" "$f"; return 1; }
    if ! caddy_reload_service; then
        mv -f "$bak" "$f"
        caddy_reload_service >/dev/null 2>&1 || true
        error "$(L 'Caddy 配置校验失败，已自动撤回改动')"
    fi
    rm -f "$bak"
    if [ "$next" = "1" ]; then
        if [ "$mode" = "http" ] && validate_port "$port"; then
            fw_allow_for_service "${port}/tcp"
        else
            fw_allow_for_service "80/tcp" "443/tcp" "443/udp"
        fi
    fi
    reserved_ports_sync || true
    success "$(L '站点状态已切换为：')$([ "$next" = "1" ] && echo "$(L '启用')" || echo "$(L '停用')")"
    return 0
}

caddy_edit_site() {
    caddy_pick_site || return 0
    local f="$PICKED_SITE_FILE" bak ans re_dom='^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$'
    env_file_safe "$f" || { warn "$(L '站点配置文件格式异常')"; return 1; }
    # shellcheck disable=SC1090
    source "$f" || return 1
    local old_port="${SITE_PORT:-443}"
    local domain="$SITE_DOMAIN" upstream="$SITE_UPSTREAM" mode="$SITE_MODE" port="${SITE_PORT:-443}" insecure="${SITE_INSECURE:-0}" remark="${SITE_REMARK:-}"
    read -rp "$(L '请输入域名（如: nhk.example.com）:') [${domain}] ($(L '回车保持')): " ans || { [ -n "$ans" ] || return 1; }
    if [ -n "$ans" ]; then
        ans="$(printf '%s' "$ans" | tr -d ' \r\n')"
        ans="${ans,,}"
        if [[ "$ans" == *.* && "$ans" =~ $re_dom ]]; then domain="$ans"; else warn "$(L '域名格式不正确')"; return 1; fi
    fi
    if [ "$mode" = "http" ]; then
        read -rp "$(L '本机监听端口 (1-65535): ') [${port}] ($(L '回车保持')): " ans || { [ -n "$ans" ] || return 1; }
        if [ -n "$ans" ]; then
            validate_port "$ans" || { warn "$(L '端口不合法')"; return 1; }
            port=$((10#$ans))
        fi
    fi
    if caddy_site_conflict "$domain" "$mode" "$port" "$SITE_ID"; then
        warn "$(L '该域名与端口组合已存在反代配置，请改用「编辑反代站点」')"
        return 1
    fi
    if [ "$mode" = "http" ] && [ "$port" != "$old_port" ]; then
        local occ=""
        occ="$(check_port_occupied_by_other tcp "$port" caddy || true)"
        if [ -n "$occ" ]; then
            warn "$(L '端口 ')${port}$(L ' 已被其他进程占用：')"
            echo "$occ"
            confirm "$(L '仍要继续添加？')" n || return 0
        fi
    fi
    read -rp "$(L '上游目标地址（如 127.0.0.1:8080 或 https://example.com）: ') [${upstream}] ($(L '回车保持')): " ans || { [ -n "$ans" ] || return 1; }
    if [ -n "$ans" ]; then
        ans="$(printf '%s' "$ans" | tr -d ' \r\n')"
        ans="${ans%/}"
        if caddy_valid_upstream "$ans"; then upstream="$ans"; else warn "$(L '目标地址格式不合法')"; return 1; fi
    fi
    if [[ "$upstream" == https://* ]]; then
        if confirm "$(L '跳过上游 TLS 证书校验（自签上游选 y）？')" "$([ "$insecure" = "1" ] && echo y || echo n)"; then insecure=1; else insecure=0; fi
    else
        insecure=0
    fi
    read -rp "$(L '规则备注（可选）: ') [${remark}] ($(L '回车保持')): " ans || { [ -n "$ans" ] || return 1; }
    [ -n "$ans" ] && remark="${ans//\"/}"
    bak="${f}.bak"
    cp -f "$f" "$bak"
    ( umask 077; cat > "$f" ) << SITEEOF
SITE_ID="${SITE_ID}"
SITE_ENABLED="${SITE_ENABLED}"
SITE_DOMAIN="${domain}"
SITE_MODE="${mode}"
SITE_PORT="${port}"
SITE_UPSTREAM="${upstream}"
SITE_INSECURE="${insecure}"
SITE_REMARK="$(dq_escape "$remark")"
SITEEOF
    chmod 600 "$f"
    if ! caddy_reload_service; then
        mv -f "$bak" "$f"
        caddy_reload_service >/dev/null 2>&1 || true
        error "$(L 'Caddy 配置校验失败，已自动撤回改动')"
    fi
    rm -f "$bak"
    if [ "$mode" = "http" ] && [ "$port" != "$old_port" ]; then
        if [ "${SITE_ENABLED:-0}" = "1" ]; then
            fw_allow_for_service "${port}/tcp"
        fi
        ufw_installed && validate_port "$old_port" && fw_prune_old_specs "${old_port}/tcp"
        reserved_ports_sync || true
    fi
    success "$(L '反代站点已生效：')${domain} -> ${upstream}"
    return 0
}

caddy_delete_site() {
    caddy_pick_site || return 0
    local f="$PICKED_SITE_FILE" bak="${PICKED_SITE_FILE}.bak" old_mode old_port
    env_file_safe "$f" || { warn "$(L '站点配置文件格式异常')"; return 1; }
    # shellcheck disable=SC1090
    source "$f" || return 1
    old_mode="${SITE_MODE:-https}"
    old_port="${SITE_PORT:-443}"
    confirm "$(L '确认删除反代站点 ')${SITE_DOMAIN}$(L '？')" n || return 0
    mv -f "$f" "$bak" || return 1
    rm -f "${CADDY_SITES_DIR}/${SITE_ID}.caddy"
    if ! caddy_reload_service; then
        mv -f "$bak" "$f"
        caddy_reload_service >/dev/null 2>&1 || true
        warn "$(L '服务重载失败，删除未生效，请检查日志')"
        return 1
    fi
    rm -f "$bak"
    if ufw_installed; then
        if [ "$old_mode" = "http" ] && validate_port "$old_port"; then
            fw_prune_old_specs "${old_port}/tcp"
        else
            fw_prune_old_specs "80/tcp 443/tcp 443/udp"
        fi
    fi
    reserved_ports_sync || true
    success "$(L '已删除反代站点 ')${SITE_DOMAIN}"
    return 0
}

caddy_show_config() {
    step "$(L '查看当前 Caddyfile 配置')"
    divider
    [ -f "$CADDY_FILE" ] && cat "$CADDY_FILE"
    local c
    for c in "${CADDY_SITES_DIR}"/*.caddy; do
        [ -f "$c" ] || continue
        echo ""
        echo -e "${CYAN}# === $(basename "$c") ===${NC}"
        cat "$c"
    done
}

caddy_uninstall_do() {
    if ! caddy_installed && [ ! -d "$CADDY_DIR" ] && [ ! -f "$CADDY_SERVICE" ]; then return 0; fi
    local old_specs
    old_specs="$(caddy_ports 2>/dev/null | tr '\n' ' ' || true)"
    systemctl disable --now adam-caddy 2>/dev/null || true
    rm -f "$CADDY_SERVICE" "$CADDY_BIN" "$CADDY_BIN_BACKUP"
    systemctl daemon-reload || true
    if confirm "$(L '同时删除配置目录') ${CADDY_DIR}$(L '？')" n; then
        rm -rf "$CADDY_DIR" "$CADDY_DATA_DIR"
        userdel adam-caddy >/dev/null 2>&1 || true
    fi
    if [ -n "${old_specs// /}" ] && ufw_installed && confirm "$(L '同时删除防火墙中 Caddy 端口的放行规则（')${old_specs}$(L '）？')" y; then
        local _cs
        while IFS= read -r _cs; do
            [ -n "$_cs" ] || continue
            fw_spec_has_ssh_port "$_cs" && continue
            port_used_by_other_services "$_cs" caddy && continue
            fw_delete_spec "$_cs"
        done < <(printf '%s\n' "$old_specs" | tr ' ' '\n' | grep -v '^$')
    fi
    reserved_ports_sync || true
    success "$(L 'Caddy 已卸载')"
}

caddy_uninstall() {
    step "$(L '卸载 Caddy')"
    divider
    confirm "$(L '确认卸载 Caddy（含服务与二进制）？')" n || return 0
    caddy_uninstall_do
}

# ── Cloudflare Tunnel (cloudflared) ─────────────────────────────

cf_tunnel_latest_tag() {
    github_latest_tag "$CF_TUNNEL_REPO"
}

cf_tunnel_fix_perms() {
    if [ -d "$CF_TUNNEL_DIR" ] && [ ! -L "$CF_TUNNEL_DIR" ]; then
        chown -h root:root "$CF_TUNNEL_DIR" 2>/dev/null || true
        chmod 700 "$CF_TUNNEL_DIR" 2>/dev/null || true
    fi
    if [ -f "$CF_TUNNEL_ENV" ] && [ ! -L "$CF_TUNNEL_ENV" ]; then
        chown -h root:root "$CF_TUNNEL_ENV" 2>/dev/null || true
        chmod 600 "$CF_TUNNEL_ENV" 2>/dev/null || true
    fi
}

cf_tunnel_write_service() {
    local run_user="adam-cloudflared" run_group="adam-cloudflared"
    if [ -f "${CF_TUNNEL_DIR}/run-as-root" ] || ! ensure_system_user adam-cloudflared adam-cloudflared 2>/dev/null; then
        run_user=""; run_group=""
    fi
    write_service_unit "$CF_TUNNEL_SERVICE" "Adam Cloudflare Tunnel" "https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/" "60" "$run_user" "$run_group" \
        "${CF_TUNNEL_BIN} --no-autoupdate tunnel run" "" "65536" "always" "5" \
        "EnvironmentFile=${CF_TUNNEL_ENV}
ProtectSystem=full
ProtectHome=read-only" "StartLimitBurst=10"
    systemctl daemon-reload || true
}

cf_tunnel_fetch_binary() {
    local tag="$1" arch asset url digest actual api_json
    case "$(uname -m)" in
        x86_64|amd64)  arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        armv7l)        arch="arm" ;;
        *) warn "$(L '不支持的架构:') $(uname -m)"; return 1 ;;
    esac
    asset="cloudflared-linux-${arch}"
    url="https://github.com/${CF_TUNNEL_REPO}/releases/download/${tag}/${asset}"
    CF_TUNNEL_DL_BIN=""
    make_workdir || return 1
    local wd="$WORKDIR"
    if ! secure_curl -fL --retry 3 --connect-timeout 10 --max-time 300 -o "${wd}/cloudflared" "$url"; then
        warn "$(L '下载失败:') ${url}"
        return 1
    fi
    actual="$(sha256sum "${wd}/cloudflared" | awk '{print tolower($1)}')"
    digest="$(github_asset_sha256 "$CF_TUNNEL_REPO" "$tag" "$asset" || true)"
    if [ -z "$digest" ]; then
        api_json="$(secure_curl -fsS --max-time 20 "https://api.github.com/repos/${CF_TUNNEL_REPO}/releases/tags/${tag}" 2>/dev/null || true)"
        if [ -n "$api_json" ]; then
            digest="$(printf '%s\n' "$api_json" | grep -oE "(^|[^A-Za-z0-9._-])${asset}[[:space:]:\`|]+([0-9a-fA-F]{64})" | grep -oE '[0-9a-fA-F]{64}' | head -1 | tr 'A-F' 'a-f' || true)"
        fi
    fi
    if [[ "$digest" =~ ^[0-9a-f]{64}$ ]]; then
        if [ "$digest" != "$actual" ]; then
            warn "$(L 'SHA256 校验失败（官方') ${digest}$(L '，实际') ${actual}$(L '），已中止')"
            return 1
        fi
        success "$(L 'SHA256 校验通过（')${asset}$(L '）')"
    else
        warn "$(L '未取到官方 SHA256 摘要（')${asset}$(L '）')"
        if [ ! -t 0 ] || ! confirm "$(L '未能获取官方摘要，是否仍继续安装？')" n; then
            return 1
        fi
    fi
    verify_elf_binary "${wd}/cloudflared" || { warn "$(L '下载到的二进制不是本机架构的 ELF 可执行文件，已中止')"; return 1; }
    chmod 755 "${wd}/cloudflared"
    if command -v timeout >/dev/null 2>&1; then
        timeout 10 "${wd}/cloudflared" --version >/dev/null 2>&1 || { warn "$(L '下载到的二进制无法在本机运行（架构或 libc 不匹配），已中止，现有安装未被改动')"; return 1; }
    else
        "${wd}/cloudflared" --version >/dev/null 2>&1 || { warn "$(L '下载到的二进制无法在本机运行（架构或 libc 不匹配），已中止，现有安装未被改动')"; return 1; }
    fi
    CF_TUNNEL_DL_BIN="${wd}/cloudflared"
    return 0
}

cf_tunnel_install() {
    step "$(L '安装 / 更新 cloudflared（官方仓库）')"
    divider
    preflight_install_check "Cloudflare Tunnel (cloudflared)" "$CF_TUNNEL_BIN" "$CF_TUNNEL_DIR" || return 1
    apt_install curl ca-certificates || true
    info "$(L '正在查询 cloudflared 官方最新版本...')"
    local tag cur=""
    tag="$(cf_tunnel_latest_tag)"
    [ -n "$tag" ] || error "$(L '无法获取 cloudflared 最新版本号，请检查网络')"
    if cf_tunnel_installed; then
        cur="$("$CF_TUNNEL_BIN" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
    fi
    info "$(L '最新版本:') ${tag}"
    [ -n "$cur" ] && info "$(L '当前版本:') ${cur}"
    if [ -n "$cur" ] && [ "${cur#v}" = "${tag#v}" ]; then
        confirm "$(L '已是最新版本，仍要重新安装？')" n || return 0
    fi
    while ! cf_tunnel_fetch_binary "$tag"; do
        confirm "$(L '下载失败，是否立即重试？')" y || error "$(L '下载或校验失败，已中止')"
    done
    [ -f "$CF_TUNNEL_BIN" ] && cp -f "$CF_TUNNEL_BIN" "$CF_TUNNEL_BIN_BACKUP" 2>/dev/null || true
    install -m 755 "$CF_TUNNEL_DL_BIN" "$CF_TUNNEL_BIN"
    cf_tunnel_fix_perms
    if [ -f "$CF_TUNNEL_SERVICE" ] && systemctl is-enabled --quiet adam-cloudflared 2>/dev/null; then
        if ! svc_restart_wait adam-cloudflared 3 15; then
            if [ -f "$CF_TUNNEL_BIN_BACKUP" ]; then
                install -m 755 "$CF_TUNNEL_BIN_BACKUP" "$CF_TUNNEL_BIN"
                systemctl restart adam-cloudflared 2>/dev/null || true
                warn "$(L '服务重启失败，已回滚到旧二进制')"
            fi
            error "$(L '更新失败')"
        fi
    fi
    success "$(L 'cloudflared 安装完成') (${tag})"
}

cf_tunnel_autoupdate() {
    cf_tunnel_installed || return 0
    local cur latest
    cur="$("$CF_TUNNEL_BIN" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
    latest="$(cf_tunnel_latest_tag)"
    if [ -z "$latest" ]; then
        echo "[CF-Tunnel] $(L '未能获取官方版本信息，本次跳过；当前') ${cur:-$(L '未知')}"
        return 1
    fi
    if [ -n "$cur" ] && version_ge "$cur" "$latest"; then
        echo "[CF-Tunnel] $(L '已是最新:') ${cur}"
        return 0
    fi
    if ! cf_tunnel_fetch_binary "$latest"; then
        maint_log "[CF-Tunnel] $(L '自动更新到') ${latest} $(L '失败，当前仍为') ${cur:-$(L '未知')}"
        return 1
    fi
    cp -f "$CF_TUNNEL_BIN" "$CF_TUNNEL_BIN_BACKUP" 2>/dev/null || true
    install -m 755 "$CF_TUNNEL_DL_BIN" "$CF_TUNNEL_BIN"
    cf_tunnel_fix_perms
    if [ -f "$CF_TUNNEL_SERVICE" ] && systemctl is-enabled --quiet adam-cloudflared 2>/dev/null; then
        if ! svc_restart_wait adam-cloudflared 3 15; then
            [ -f "$CF_TUNNEL_BIN_BACKUP" ] && install -m 755 "$CF_TUNNEL_BIN_BACKUP" "$CF_TUNNEL_BIN"
            systemctl restart adam-cloudflared 2>/dev/null || true
            maint_log "[CF-Tunnel] $(L '自动更新到') ${latest} $(L '失败，当前仍为') ${cur:-$(L '未知')}"
            notify_send "CF-Tunnel Auto-Rollback" "Auto-update to ${latest} failed; rolled back to ${cur:-previous}." || true
            return 1
        fi
    fi
    maint_log "[CF-Tunnel] $(L '已自动更新:') ${cur:-$(L '未知')} -> ${latest}"
    return 0
}

cf_tunnel_setup_token() {
    cf_tunnel_installed || cf_tunnel_install || return 1
    step "$(L '配置持久化隧道（粘贴 Zero Trust Token）')"
    divider
    local token=""
    read -rsp "$(L '粘贴 Cloudflare Zero Trust Tunnel Token（输入不回显）: ')" token || { [ -n "$token" ] || return 1; }; echo
    token="$(printf '%s' "$token" | tr -d '\r\n' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    # 兼容直接粘贴 Zero Trust 面板复制的整条命令（如 sudo cloudflared service install eyJ...）
    if [[ "$token" == *" "* ]]; then
        token="${token##* }"
        info "$(L '已自动提取 Cloudflare Tunnel Token')"
    fi
    token="${token//[[:space:]]/}"
    token="${token#\"}"; token="${token%\"}"
    token="${token#\'}"; token="${token%\'}"
    [ -n "$token" ] || { warn "$(L 'Token 不能为空')"; return 1; }
    install -d -m 700 "$CF_TUNNEL_DIR"
    local _env_bak=""
    if [ -f "$CF_TUNNEL_ENV" ]; then
        _env_bak="${CF_TUNNEL_ENV}.bak"
        ( umask 077; cp -f "$CF_TUNNEL_ENV" "$_env_bak" ) 2>/dev/null || _env_bak=""
    fi
    ( umask 077; printf 'TUNNEL_TOKEN="%s"\n' "$(dq_escape "$token")" > "$CF_TUNNEL_ENV" )
    cf_tunnel_fix_perms
    cf_tunnel_write_service
    systemctl enable adam-cloudflared >/dev/null 2>&1 || true
    if svc_restart_wait adam-cloudflared 3 20; then
        [ -n "$_env_bak" ] && rm -f "$_env_bak"
        maint_install_timers >/dev/null 2>&1 || true
        success "$(L 'Cloudflare Tunnel 持久化服务已启动')"
        return 0
    fi
    if grep -q '^User=' "$CF_TUNNEL_SERVICE" 2>/dev/null; then
        local _svc_bak="${CF_TUNNEL_SERVICE}.rootbak"
        cp -p "$CF_TUNNEL_SERVICE" "$_svc_bak" 2>/dev/null || true
        sed -i '/^User=/d; /^Group=/d' "$CF_TUNNEL_SERVICE" || { [ -f "$_svc_bak" ] && mv -f "$_svc_bak" "$CF_TUNNEL_SERVICE"; return 1; }
        systemctl daemon-reload || true
        if svc_restart_wait adam-cloudflared 3 20; then
            rm -f "$_svc_bak"
            [ -n "$_env_bak" ] && rm -f "$_env_bak"
            touch "${CF_TUNNEL_DIR}/run-as-root" 2>/dev/null || true
            maint_install_timers >/dev/null 2>&1 || true
            success "$(L 'Cloudflare Tunnel 持久化服务已启动')"
            return 0
        fi
        if [ -f "$_svc_bak" ]; then mv -f "$_svc_bak" "$CF_TUNNEL_SERVICE"; fi
        systemctl daemon-reload || true
    fi
    if [ -n "$_env_bak" ] && [ -f "$_env_bak" ]; then
        mv -f "$_env_bak" "$CF_TUNNEL_ENV"
        cf_tunnel_fix_perms
        systemctl restart adam-cloudflared >/dev/null 2>&1 || true
    fi
    warn "$(L 'Cloudflare Tunnel 启动失败，请查看日志：journalctl -u adam-cloudflared -n 20 --no-pager')"
    return 1
}

_cf_tunnel_repair_core() {
    local quiet="${1:-}"
    cf_tunnel_installed || return 1
    cf_tunnel_fix_perms
    if [ -f "$CF_TUNNEL_ENV" ] && grep -q '^TUNNEL_TOKEN=' "$CF_TUNNEL_ENV" 2>/dev/null; then
        cf_tunnel_write_service
        systemctl reset-failed adam-cloudflared 2>/dev/null || true
        systemctl enable adam-cloudflared >/dev/null 2>&1 || true
        if svc_restart_wait adam-cloudflared 3 15; then
            return 0
        fi
        if grep -q '^User=' "$CF_TUNNEL_SERVICE" 2>/dev/null; then
            local _svc_bak="${CF_TUNNEL_SERVICE}.rootbak"
            cp -p "$CF_TUNNEL_SERVICE" "$_svc_bak" 2>/dev/null || true
            sed -i '/^User=/d; /^Group=/d' "$CF_TUNNEL_SERVICE" || { [ -f "$_svc_bak" ] && mv -f "$_svc_bak" "$CF_TUNNEL_SERVICE"; return 1; }
            systemctl daemon-reload || true
            if svc_restart_wait adam-cloudflared 3 15; then
                rm -f "$_svc_bak"
                touch "${CF_TUNNEL_DIR}/run-as-root" 2>/dev/null || true
                return 0
            fi
            if [ -f "$_svc_bak" ]; then mv -f "$_svc_bak" "$CF_TUNNEL_SERVICE"; fi
            systemctl daemon-reload || true
        fi
        return 1
    fi
    [ "$quiet" = "quiet" ] || info "$(L '未检测到持久化 Tunnel Token，已完成权限收敛')"
    return 0
}

cf_tunnel_repair() {
    step "$(L '修复 Cloudflare Tunnel（权限收敛 / 重写服务单元并重启）')"
    divider
    if ! cf_tunnel_installed; then
        warn "$(L '尚未安装 cloudflared，请先安装')"
        return 1
    fi
    maint_install_timers >/dev/null 2>&1 || true
    if _cf_tunnel_repair_core; then
        success "$(L 'Cloudflare Tunnel 修复完成，状态正常')"
        return 0
    fi
    warn "$(L 'Cloudflare Tunnel 修复后仍未恢复正常，最近日志：')"
    journalctl -u adam-cloudflared -n 25 --no-pager || true
    return 1
}

cf_tunnel_quick() {
    cf_tunnel_installed || cf_tunnel_install || return 1
    step "$(L '启动临时快速隧道（trycloudflare.com，免配置）')"
    divider
    local port=""
    read -rp "$(L '输入本地服务端口（如 8080，将映射到 *.trycloudflare.com）: ')" port || { [ -n "$port" ] || return 1; }
    validate_port "$port" || { warn "$(L '端口不合法')"; return 1; }
    info "$(L '按 Ctrl+C 停止临时隧道 ...')"
    "$CF_TUNNEL_BIN" tunnel --url "http://127.0.0.1:$((10#$port))" || true
}

cf_tunnel_uninstall_do() {
    if ! cf_tunnel_installed && [ ! -d "$CF_TUNNEL_DIR" ] && [ ! -f "$CF_TUNNEL_SERVICE" ]; then return 0; fi
    systemctl disable --now adam-cloudflared 2>/dev/null || true
    rm -f "$CF_TUNNEL_SERVICE" "$CF_TUNNEL_BIN" "$CF_TUNNEL_BIN_BACKUP"
    systemctl daemon-reload || true
    if confirm "$(L '同时删除配置目录') ${CF_TUNNEL_DIR}$(L '？')" n; then
        rm -rf "$CF_TUNNEL_DIR"
        userdel adam-cloudflared >/dev/null 2>&1 || true
    fi
    success "$(L 'cloudflared 已卸载')"
}

cf_tunnel_uninstall() {
    step "$(L '停用 / 卸载 cloudflared')"
    divider
    confirm "$(L '确认卸载 cloudflared（含服务与二进制）？')" n || return 0
    cf_tunnel_uninstall_do
}

cf_tunnel_menu() {
    local choice
    while true; do
        clear 2>/dev/null || true
        maint_load
        echo -e "${BOLD}${CYAN}━━━ $(L 'Cloudflare Tunnel 管理（Zero Trust / 临时隧道）') ━━━${NC}"
        echo -e "  $(L '当前状态:') $([ -x "$CF_TUNNEL_BIN" ] && "$CF_TUNNEL_BIN" --version 2>/dev/null | head -1 || echo "$(L '未安装')") · $(svc_state adam-cloudflared)"
        divider
        echo -e "  ${GREEN}1)${NC} $(L '安装 / 更新 cloudflared（官方仓库）')"
        echo -e "  ${GREEN}2)${NC} $(L '配置持久化隧道（粘贴 Zero Trust Token）')"
        echo -e "  ${GREEN}3)${NC} $(L '启动临时快速隧道（trycloudflare.com，免配置）')"
        echo -e "  ${GREEN}4)${NC} $(L '查看隧道状态与日志')"
        echo -e "  ${GREEN}5)${NC} $(L '重启持久化隧道')"
        echo -e "  ${GREEN}6)${NC} $(L '修复 Cloudflare Tunnel（权限收敛 / 重写服务单元并重启）')"
        echo -e "  ${GREEN}7)${NC} $(L 'cloudflared 自动更新 开 / 关') [$(maint_onoff "${MAINT_CF_TUNNEL_AUTO:-0}")]"
        echo -e "  ${GREEN}8)${NC} ${RED}$(L '停用 / 卸载 cloudflared')${NC}"
        echo -e "  ${GREEN}0)${NC} $(L '返回')"
        divider
        read -rp "$(L '请选择') [0-8]: " choice || return 0
        case "$choice" in
            1) run_action cf_tunnel_install ;;
            2) run_action cf_tunnel_setup_token ;;
            3) run_action cf_tunnel_quick ;;
            4) run_action bash -c 'systemctl status adam-cloudflared --no-pager || true; journalctl -u adam-cloudflared -n 20 --no-pager || true' ;;
            5) run_action svc_restart_wait adam-cloudflared 2 15 ;;
            6) run_action cf_tunnel_repair ;;
            7) run_action maint_toggle MAINT_CF_TUNNEL_AUTO ;;
            8) run_action cf_tunnel_uninstall ;;
            0) return 0 ;;
            *) warn "$(L '无效选择')" ;;
        esac
        pause_return
    done
}

proxy_menu() {
    local choice
    while true; do
        clear 2>/dev/null || true
        maint_load
        echo -e "${BOLD}${CYAN}━━━ $(L '一键域名反代管理') ━━━${NC}"
        echo -e "  $(L '当前状态:') $(proxy_state_text)"
        divider
        echo -e "  ${BOLD}── Caddy $(L '域名反代') ──${NC}"
        echo -e "  ${GREEN}1)${NC}  $(L '安装 / 更新 Caddy（官方仓库）')"
        echo -e "  ${GREEN}2)${NC}  $(L '添加域名反代站点（自动 HTTPS）')"
        echo -e "  ${GREEN}3)${NC}  $(L '查看反代站点列表')"
        echo -e "  ${GREEN}4)${NC}  $(L '编辑反代站点')"
        echo -e "  ${GREEN}5)${NC}  $(L '启用 / 停用站点')"
        echo -e "  ${GREEN}6)${NC}  $(L '删除反代站点')"
        echo -e "  ${GREEN}7)${NC}  $(L '查看当前 Caddyfile 配置')"
        echo -e "  ${GREEN}8)${NC}  $(L 'Caddy 自动更新 开 / 关') [$(maint_onoff "${MAINT_CADDY_AUTO:-0}")]"
        echo -e "  ${GREEN}9)${NC}  $(L '重启 Caddy / 查看状态与日志')"
        echo -e "  ${GREEN}10)${NC} $(L '修复 Caddy（重建配置 / 权限收敛 / 同步防火墙并重启）')"
        echo -e "  ${GREEN}11)${NC} ${RED}$(L '卸载 Caddy')${NC}"
        echo -e "  ${BOLD}── Cloudflare Tunnel ──${NC}"
        echo -e "  ${GREEN}12)${NC} $(L 'Cloudflare Tunnel 管理（Zero Trust / 临时隧道）')"
        echo -e "  ${GREEN}0)${NC}  $(L '返回主菜单')"
        divider
        read -rp "$(L '请选择') [0-12]: " choice || return 0
        case "$choice" in
            1)  run_action caddy_install ;;
            2)  run_action caddy_add_site ;;
            3)  run_action caddy_list_sites ;;
            4)  run_action caddy_edit_site ;;
            5)  run_action caddy_toggle_site ;;
            6)  run_action caddy_delete_site ;;
            7)  run_action caddy_show_config ;;
            8)  run_action maint_toggle MAINT_CADDY_AUTO ;;
            9)  run_action bash -c 'systemctl restart adam-caddy 2>/dev/null || true; systemctl status adam-caddy --no-pager || true; journalctl -u adam-caddy -n 20 --no-pager || true' ;;
            10) run_action caddy_repair ;;
            11) run_action caddy_uninstall ;;
            12) cf_tunnel_menu ;;
            0)  return 0 ;;
            *)  warn "$(L '无效选择')" ;;
        esac
        pause_return
    done
}

proxy_cli() {
    local sub="${1:-menu}"
    [ "$#" -gt 0 ] && shift
    case "$sub" in
        menu)      proxy_menu ;;
        install|update) caddy_install ;;
        add)       caddy_add_site ;;
        list)      caddy_list_sites ;;
        edit)      caddy_edit_site ;;
        toggle)    caddy_toggle_site ;;
        delete)    caddy_delete_site ;;
        config)    caddy_show_config ;;
        auto)      maint_toggle MAINT_CADDY_AUTO ;;
        repair)    caddy_repair ;;
        restart)   caddy_reload_service && success "$(L '已重启')" ;;
        status)    systemctl status adam-caddy --no-pager || true ;;
        logs)      journalctl -u adam-caddy -f || true ;;
        uninstall) caddy_uninstall ;;
        tunnel)    cf_tunnel_cli "$@" ;;
        *) error "$(L '未知的 proxy 子命令:') ${sub}" ;;
    esac
}

cf_tunnel_cli() {
    local sub="${1:-menu}"
    [ "$#" -gt 0 ] && shift
    case "$sub" in
        menu)      cf_tunnel_menu ;;
        install|update) cf_tunnel_install ;;
        token)     cf_tunnel_setup_token ;;
        quick)     cf_tunnel_quick ;;
        auto)      maint_toggle MAINT_CF_TUNNEL_AUTO ;;
        repair)    cf_tunnel_repair ;;
        restart)   svc_restart_wait adam-cloudflared 2 15 ;;
        status)    systemctl status adam-cloudflared --no-pager || true ;;
        logs)      journalctl -u adam-cloudflared -f || true ;;
        uninstall) cf_tunnel_uninstall ;;
        *) error "$(L '未知的 tunnel 子命令:') ${sub}" ;;
    esac
}

