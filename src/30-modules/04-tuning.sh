# ══════════════════════════════════════════════════════════════
#   系统与网络调优
#     - TCP 调优：直接使用 Kylin010/tcpfit（按本机实测推导参数、可回滚）。本脚本只负责
#       拉取、校验、安装到 /usr/local/bin/tcpfit 并调用，调优逻辑由 tcpfit 自己维护；
#     - XanMod 内核、DNS、IPv4/IPv6 优先级、禁用 IPv6：功能参考 Eric86777/vps-tcp-tune，
#       实现为本脚本自有的精简版（每项都有备份与恢复）。
# ══════════════════════════════════════════════════════════════

# 拉取 tcpfit 到临时文件并校验；成功后路径写入 TCPFIT_TMP、版本写入 TCPFIT_REMOTE_VER
tcpfit_fetch() {
    local want got ts
    TCPFIT_TMP=""; TCPFIT_REMOTE_VER=""
    make_workdir || return 1
    local wd="$WORKDIR"
    ts="$(date +%s)"
    if ! secure_curl -fsSL --max-time 60 "${TCPFIT_RAW}/tcpfit.sh?t=${ts}" -o "$wd/tcpfit.sh"; then
        warn "$(L '下载 tcpfit 失败（')${TCPFIT_RAW}$(L '/tcpfit.sh），请检查到 GitHub 的网络')"
        return 1
    fi
    # 与 tcpfit 自己的安装脚本相同的三项自检：是脚本、有版本号、语法完整（防传输截断）
    if ! head -n 1 "$wd/tcpfit.sh" | grep -q '^#!' || ! grep -q '^VERSION=' "$wd/tcpfit.sh" || ! bash -n "$wd/tcpfit.sh" 2>/dev/null; then
        warn "$(L '下载到的 tcpfit 不完整或不是脚本（传输被截断或被网关拦截），已放弃')"
        return 1
    fi
    TCPFIT_REMOTE_VER="$(grep -m1 '^VERSION=' "$wd/tcpfit.sh" | cut -d'"' -f2 || true)"
    got="$(sha256sum "$wd/tcpfit.sh" | awk '{print tolower($1)}')"
    want="$(secure_curl -fsSL --max-time 20 "${TCPFIT_RAW}/SHA256SUMS?t=${ts}" 2>/dev/null | awk '$2 == "tcpfit.sh" || $2 == "*tcpfit.sh" {print tolower($1); exit}' || true)"
    if [ -z "$want" ]; then
        warn "$(L '取不到仓库里的 SHA256SUMS，无法核对校验值（SHA256:') ${got}$(L '）')"
        if [ ! -t 0 ] || [ "${ADAM_ASSUME_YES:-0}" = "1" ] || ! confirm "$(L '仍要继续？')" n; then
            return 1
        fi
    elif [ "$want" != "$got" ]; then
        warn "$(L 'SHA256 与仓库 SHA256SUMS 不一致（仓库') ${want}$(L '，实际') ${got}$(L '）')"
        warn "$(L '可能是作者刚更新、两个文件的缓存不同步，也可能是下载被篡改')"
        return 1
    else
        success "$(L 'SHA256 与仓库 SHA256SUMS 一致')"
    fi
    TCPFIT_TMP="$wd/tcpfit.sh"
    return 0
}

tcpfit_installed_version() {
    [ -x "$TCPFIT_BIN" ] || return 0
    grep -m1 '^VERSION=' "$TCPFIT_BIN" 2>/dev/null | cut -d'"' -f2 || true
}

tcpfit_install() {
    local cur prefix=""
    cur="$(tcpfit_installed_version)"
    [ -n "$cur" ] && prefix="$(L '当前已安装') ${cur}$(L '，')"
    info "$(L 'tcpfit 是第三方开源脚本（')${TCPFIT_RAW%/main}$(L '），将以 root 运行并修改 sysctl / qdisc 等网络参数')"
    info "$(L '它的改动只写在自己的文件里（/etc/sysctl.d/99-tcpfit.conf 等），可用 tcpfit rollback 整体回滚')"
    confirm "${prefix}$(L '从官方仓库拉取最新版并安装到') ${TCPFIT_BIN}$(L '？')" y || return 1
    tcpfit_fetch || return 1
    install -m 755 "$TCPFIT_TMP" "$TCPFIT_BIN"
    rm -f /usr/local/sbin/tcpfit.sh
    success "tcpfit ${TCPFIT_REMOTE_VER} $(L '已安装')"
    return 0
}

tcpfit_run() {   # tcpfit_run [子命令...]：没装先装
    if [ ! -x "$TCPFIT_BIN" ]; then
        tcpfit_install || return 1
    fi
    if [ "$#" -eq 0 ] && [ ! -t 0 ]; then
        warn "$(L 'tcpfit 的菜单需要在终端里运行，请直接执行: tcpfit')"
        return 1
    fi
    "$TCPFIT_BIN" "$@" || warn "$(L 'tcpfit 以非 0 状态退出（如果是你主动退出菜单可忽略）')"
    return 0
}

tcpfit_menu_entry() {
    step "$(L 'TCP 调优（tcpfit）')"
    divider
    echo "  $(L 'tcpfit 会按本机实测结果推导缓冲区、BBR/fq、限速器拐点与整形参数，而不是套固定值。')"
    echo "  $(L '进入后选「1 一键调优」即可；所有改动可用其菜单 7 或 tcpfit rollback 回滚。')"
    echo ""
    tcpfit_run
}

tcpfit_update() {
    if [ ! -x "$TCPFIT_BIN" ]; then tcpfit_install; return $?; fi
    info "$(L '当前 tcpfit 版本:') $(tcpfit_installed_version)"
    tcpfit_fetch || return 1
    if cmp -s "$TCPFIT_TMP" "$TCPFIT_BIN"; then
        success "$(L '已是仓库最新（')${TCPFIT_REMOTE_VER}$(L '）')"
        return 0
    fi
    confirm "$(L '仓库版本为') ${TCPFIT_REMOTE_VER}$(L '，更新？')" y || return 0
    install -m 755 "$TCPFIT_TMP" "$TCPFIT_BIN"
    success "$(L 'tcpfit 已更新到') ${TCPFIT_REMOTE_VER}"
    return 0
}

# ── XanMod 内核 ────────────────────────────────────────────────

# 本机 CPU 的 x86-64 psABI 等级（1-4），判定条件与 XanMod 官方的 check_x86-64_psabi.sh 一致
xanmod_cpu_level() {
    awk '
        /^flags/ {
            $0 = $0 " "
            lvl = 1
            if (/ cx16 / && / lahf_lm / && / popcnt / && / sse4_1 / && / sse4_2 / && / ssse3 /) lvl = 2
            if (lvl == 2 && / avx / && / avx2 / && / bmi1 / && / bmi2 / && / f16c / && / fma / && / abm / && / movbe / && / xsave /) lvl = 3
            if (lvl == 3 && / avx512f / && / avx512bw / && / avx512cd / && / avx512dq / && / avx512vl /) lvl = 4
            print lvl; found = 1; exit
        }
        END { if (!found) print 1 }' /proc/cpuinfo 2>/dev/null
}

xanmod_installed_pkgs() {
    dpkg-query -W -f='${Status} ${Package}\n' 'linux-*xanmod*' 2>/dev/null | awk '$1 == "install" && $3 == "installed" {print $4}' || true
}

xanmod_install() {
    step "$(L '安装 / 更新 XanMod 内核（内置 BBR v3）')"
    divider
    local arch virt id="" codename="" suite="" lvl pkg="" free_mb c keyring=/etc/apt/keyrings/xanmod-archive-keyring.gpg
    local -a cands=()
    arch="$(uname -m)"
    if [ "$arch" != "x86_64" ]; then
        warn "$(L 'XanMod 官方只提供 x86_64 构建，本机是') ${arch}"
        info "$(L 'ARM 机器的发行版内核自带 BBR + fq，直接用「1')) $(L 'TCP 调优」即可')"
        return 1
    fi
    virt="$(systemd-detect-virt 2>/dev/null || true)"
    case "$virt" in
        lxc|lxc-libvirt|openvz|docker|podman|systemd-nspawn|wsl)
            warn "$(L '当前是容器类虚拟化（')${virt}$(L '），与宿主机共用内核，无法更换内核')"
            return 1 ;;
    esac
    if [ -r /etc/os-release ]; then
        id="$( . /etc/os-release; printf '%s' "${ID:-}" )"
        codename="$( . /etc/os-release; printf '%s' "${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}" )"
    fi
    if [ "$id" != "debian" ] && [ "$id" != "ubuntu" ]; then
        warn "$(L '仅支持 Debian / Ubuntu（当前:') ${id:-$(L '未知')}$(L '）')"
        return 1
    fi
    if [ -z "$codename" ]; then warn "$(L '无法识别发行版代号，不能添加 XanMod 软件源')"; return 1; fi
    free_mb="$(df -Pm /boot 2>/dev/null | awk 'NR==2 {print $4}' || echo 0)"
    if [ "${free_mb:-0}" -lt 300 ]; then
        warn "$(L '/boot 可用空间只有') ${free_mb:-0} $(L 'MB（建议') ≥ $(L '300 MB），装新内核可能失败，请先清理旧内核')"
        confirm "$(L '仍要继续？')" n || return 1
    fi
    lvl="$(xanmod_cpu_level)"
    info "$(L 'CPU 指令集等级: x86-64-v')${lvl}    $(L '发行版:') ${id} ${codename}    $(L '当前内核:') $(uname -r)"
    if [ -n "$(xanmod_installed_pkgs)" ]; then info "$(L '已安装的 XanMod 包:') $(xanmod_installed_pkgs | tr '\n' ' ')"; fi
    warn "$(L '更换内核有风险：请确认服务商面板有 VNC / 救援模式，万一新内核起不来可以回到旧内核')"
    confirm "$(L '继续安装 / 更新 XanMod 内核？')" n || { info "$(L '已取消')"; return 0; }

    apt_install gnupg ca-certificates curl || { warn "$(L '依赖安装失败')"; return 1; }
    # 先探测 deb.xanmod.org 支持的 suite（优先统一 releases，兼容旧发行版 codename），避免把 404 软件源写进 apt
    if secure_curl -fsI --max-time 15 "https://deb.xanmod.org/dists/releases/InRelease" >/dev/null 2>&1 \
        || secure_curl -fsI --max-time 15 "https://deb.xanmod.org/dists/releases/Release" >/dev/null 2>&1; then
        suite="releases"
    elif secure_curl -fsI --max-time 15 "https://deb.xanmod.org/dists/${codename}/InRelease" >/dev/null 2>&1 \
        || secure_curl -fsI --max-time 15 "https://deb.xanmod.org/dists/${codename}/Release" >/dev/null 2>&1; then
        suite="$codename"
    else
        warn "$(L 'XanMod 官方仓库暂不提供当前系统代号（')${codename}$(L '）的软件包，已跳过写入软件源（避免污染 apt）')"
        return 1
    fi
    install -d -m 755 /etc/apt/keyrings
    make_workdir || return 1
    if ! secure_curl -fsSL --max-time 30 https://dl.xanmod.org/archive.key -o "$WORKDIR/xanmod.key" \
        || [ ! -s "$WORKDIR/xanmod.key" ] \
        || ! gpg --dearmor --yes -o "$keyring" < "$WORKDIR/xanmod.key" 2>/dev/null \
        || [ ! -s "$keyring" ]; then
        warn "$(L 'XanMod 仓库密钥下载或导入失败')"
        return 1
    fi
    chmod 644 "$keyring"
    echo "deb [arch=amd64 signed-by=${keyring}] https://deb.xanmod.org ${suite} main" > /etc/apt/sources.list.d/xanmod-release.list
    info "$(L '正在更新软件包列表 ...')"
    apt-get update -qq || warn "$(L 'apt-get update 部分失败，继续尝试')"
    APT_UPDATED=1
    # 官方主线目前提供 x64v2 / x64v3；v1 只有 LTS，v4 的 CPU 用 x64v3
    case "$lvl" in
        1) cands=(linux-xanmod-lts-x64v1) ;;
        2) cands=(linux-xanmod-x64v2 linux-xanmod-lts-x64v2) ;;
        *) cands=(linux-xanmod-x64v3 linux-xanmod-lts-x64v3) ;;
    esac
    for c in "${cands[@]}"; do
        if apt-cache show "$c" >/dev/null 2>&1; then pkg="$c"; break; fi
    done
    if [ -z "$pkg" ]; then
        warn "$(L '软件源里没有适合 x86-64-v')${lvl} $(L '的 XanMod 内核包（发行版') ${codename} $(L '可能不在 XanMod 支持列表里）')"
        rm -f /etc/apt/sources.list.d/xanmod-release.list
        return 1
    fi
    info "$(L '将安装:') ${pkg}"
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg"; then
        warn "$(L '内核包安装失败')"
        if [ -z "$(xanmod_installed_pkgs)" ]; then
            rm -f /etc/apt/sources.list.d/xanmod-release.list
            info "$(L '已清理失败的 XanMod 软件源配置')"
        fi
        return 1
    fi
    success "$(L 'XanMod 内核已安装:') ${pkg}"
    warn "$(L '需要重启才会切换到新内核。重启后可用本菜单「8')) $(L '查看当前状态」确认，再用「1')) $(L 'TCP 调优」启用 BBR')"
    info "$(L '软件源已保留（/etc/apt/sources.list.d/xanmod-release.list），之后 apt upgrade 或再次执行本项即可更新内核')"
    if confirm "$(L '现在重启？')" n; then
        info "$(L '3 秒后重启 ...')"
        sleep 3
        reboot
    fi
    return 0
}

xanmod_uninstall() {
    step "$(L '卸载 XanMod 内核')"
    divider
    local pkgs others
    pkgs="$(xanmod_installed_pkgs | tr '\n' ' ')"
    if [ -z "${pkgs// /}" ]; then info "$(L '没有检测到已安装的 XanMod 内核包')"; return 0; fi
    # 必须还有别的真实可启动内核镜像（排除 -dbg / -unsigned），否则卸完就起不来了
    others="$(dpkg-query -W -f='${Status} ${Package}\n' 'linux-image-*' 2>/dev/null | awk '$1 == "install" && $3 == "installed" && $4 !~ /xanmod|-dbg$|-unsigned/ {print $4}' | tr '\n' ' ' || true)"
    if [ -z "${others// /}" ]; then
        warn "$(L '系统里没有其他已安装的内核镜像，卸载 XanMod 后将无法启动，已拒绝')"
        info "$(L '请先安装发行版内核：Debian 用 apt install linux-image-amd64，Ubuntu 用 apt install linux-image-generic')"
        return 1
    fi
    info "$(L '将卸载:') ${pkgs}"
    info "$(L '保留的其他内核:') ${others}"
    confirm "$(L '确认卸载？（卸载后重启会回到发行版内核）')" n || { info "$(L '已取消')"; return 0; }
    # shellcheck disable=SC2086
    DEBIAN_FRONTEND=noninteractive apt-get purge -y $pkgs || { warn "$(L '卸载失败')"; return 1; }
    rm -f /etc/apt/sources.list.d/xanmod-release.list /etc/apt/keyrings/xanmod-archive-keyring.gpg
    if command -v update-grub >/dev/null 2>&1; then update-grub >/dev/null 2>&1 || true; fi
    success "$(L 'XanMod 内核已卸载，重启后生效')"
    return 0
}

# ── DNS ────────────────────────────────────────────────────────

resolved_active() { systemctl is-active --quiet systemd-resolved 2>/dev/null; }

dns_show() {
    info "$(L '当前 DNS：')"
    if resolved_active && command -v resolvectl >/dev/null 2>&1; then
        resolvectl status 2>/dev/null | grep -E 'Link [0-9]+|Global|DNS Servers|Current DNS Server|DNSOverTLS|DNS Domain|resolv.conf mode' | sed 's/^/  /' || true
    fi
    echo "  /etc/resolv.conf -> $(readlink -f /etc/resolv.conf 2>/dev/null || echo '?')"
    grep -E '^(nameserver|options)' /etc/resolv.conf 2>/dev/null | sed 's/^/    /' || true
    return 0
}

dns_locked_by_others() {
    local attr
    attr="$(lsattr /etc/resolv.conf 2>/dev/null | awk '{print $1}' || true)"
    [[ "$attr" == *i* ]]
}

# 设置系统 DNS。systemd-resolved 在运行时写它的 drop-in（官方支持的方式）；否则直接写 /etc/resolv.conf。
dns_set() {
    step "$(L '设置 DNS')"
    divider
    local ans choice servers="" dot="no" s v4 v6 iface rtmp
    dns_show
    echo ""
    if dns_locked_by_others; then
        warn "$(L '/etc/resolv.conf 被加了不可修改属性（chattr +i）—— 通常是 cnblock 的 DNS 黑洞在接管解析')"
        warn "$(L '此时改系统 DNS 会让它失效或互相打架，已中止。请先执行 cnblock close，或改它的上游 DNS')"
        return 1
    fi
    echo "  1) $(L 'Cloudflare + Google（1.1.1.1 / 8.8.8.8，含 IPv6）')"
    echo "  2) $(L 'Google + Cloudflare（8.8.8.8 / 1.1.1.1，含 IPv6）')"
    echo "  3) $(L 'Quad9 + Cloudflare（9.9.9.9 / 1.1.1.1，含 IPv6）')"
    echo "  4) $(L '自定义')"
    echo "  0) $(L '返回')"
    read -rp "$(L '请选择') [0-4]: " choice || { [ -n "$choice" ] || return 1; }
    case "$choice" in
        1) v4="1.1.1.1 8.8.8.8"; v6="2606:4700:4700::1111 2001:4860:4860::8888" ;;
        2) v4="8.8.8.8 1.1.1.1"; v6="2001:4860:4860::8888 2606:4700:4700::1111" ;;
        3) v4="9.9.9.9 1.1.1.1"; v6="2620:fe::fe 2606:4700:4700::1111" ;;
        4)
            while true; do
                read -rp "$(L '输入 DNS 服务器 IP（空格分隔，可混合 IPv4 / IPv6）:') " ans || { [ -n "$ans" ] || return 1; }
                [ "$ans" = "q" ] && return 0
                v4=""; v6=""; local _dns_bad=0
                while IFS= read -r s; do
                    [ -n "$s" ] || continue
                    if ! is_ip "$s"; then warn "$(L '不是合法 IP:') ${s}"; _dns_bad=1; break; fi
                    if [[ "$s" == *:* ]]; then v6="${v6:+$v6 }$s"; else v4="${v4:+$v4 }$s"; fi
                done < <(printf '%s\n' "$ans" | tr ' ' '\n' | grep -v '^$')
                [ "$_dns_bad" = "1" ] && continue
                if [ -z "$v4$v6" ]; then warn "$(L '没有输入任何服务器')"; continue; fi
                break
            done
            ;;
        *) return 0 ;;
    esac
    # 本机 IPv6 不可用时不写 IPv6 的 DNS，避免解析超时
    if snell_ipv6_ok && ip -6 route show default 2>/dev/null | awk 'NF{f=1} END{exit !f}'; then servers="${v4:+$v4 }${v6}"; else servers="${v4:-$v6}"; fi
    servers="${servers% }"

    if resolved_active; then
        if [ "$choice" != "4" ] && confirm "$(L '启用 DNS over TLS（opportunistic：上游支持就加密，不支持自动回退）？')" n; then dot="opportunistic"; fi
        install -d -m 755 /etc/systemd/resolved.conf.d
        cat > "$DNS_DROPIN" << DNSEOF
# $(L '由 Adam 管理脚本生成（系统与网络调优 -> DNS）。删除本文件并重启 systemd-resolved 即恢复。')
[Resolve]
DNS=${servers}
FallbackDNS=1.1.1.1 8.8.8.8
Domains=~.
DNSOverTLS=${dot}
DNSEOF
        systemctl restart systemd-resolved 2>/dev/null || true
        sleep 1
        # 网卡上由 DHCP / netplan 下发的 DNS 会与全局设置并存；这里把默认路由网卡的运行时 DNS 也对齐
        #（运行时设置，重启网络后由 DHCP 重新下发；要永久去掉需改 netplan / DHCP 配置）
        iface="$(ip route show default 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") {print $(i + 1); exit}}' || true)"
        if [ -n "$iface" ] && command -v resolvectl >/dev/null 2>&1; then
            # shellcheck disable=SC2086
            resolvectl dns "$iface" $servers 2>/dev/null || true
            resolvectl domain "$iface" '~.' 2>/dev/null || true
            resolvectl flush-caches 2>/dev/null || true
        fi
        success "$(L '已通过 systemd-resolved 设置 DNS:') ${servers}"
    else
        # 同时检查 -L，防止原 /etc/resolv.conf 为悬空符号链接（如指向已停用的 systemd-resolved stub）时二次设置覆盖原始备份
        if [ ! -e "$DNS_RESOLV_BACKUP" ] && [ ! -L "$DNS_RESOLV_BACKUP" ]; then
            install -d -m 755 "$MAINT_DIR"
            cp -P /etc/resolv.conf "$DNS_RESOLV_BACKUP" 2>/dev/null || true
        fi
        rtmp="$(mktemp /etc/.resolv.conf.XXXXXX)" || error "$(L '创建临时文件失败')"
        {
            echo "# $(L '由 Adam 管理脚本生成；原文件备份在') ${DNS_RESOLV_BACKUP}"
            while IFS= read -r s; do [ -n "$s" ] || continue; echo "nameserver $s"; done < <(printf '%s\n' "$servers" | tr ' ' '\n' | grep -v '^$')
            echo "options timeout:2 attempts:2"
        } > "$rtmp"
        chmod 644 "$rtmp"
        rm -f /etc/resolv.conf
        mv -f "$rtmp" /etc/resolv.conf
        success "$(L '已写入 /etc/resolv.conf:') ${servers}"
        warn "$(L '如果本机用 DHCP，续租或重启网络时该文件可能被改回（那种情况需在 DHCP / 网络配置里固定 DNS）')"
    fi
    echo ""
    if getent hosts www.cloudflare.com >/dev/null 2>&1; then success "$(L '解析测试通过')"; else warn "$(L '解析测试失败，请检查，或用「恢复 DNS」撤销')"; fi
    return 0
}

dns_restore() {
    local iface
    if [ -f "$DNS_DROPIN" ]; then
        rm -f "$DNS_DROPIN"
        iface="$(ip route show default 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") {print $(i + 1); exit}}' || true)"
        if [ -n "$iface" ] && command -v resolvectl >/dev/null 2>&1; then resolvectl revert "$iface" 2>/dev/null || true; fi
        systemctl restart systemd-resolved 2>/dev/null || true
        success "$(L '已移除本脚本的 systemd-resolved 配置，DNS 恢复为系统原设置')"
    elif [ -e "$DNS_RESOLV_BACKUP" ] || [ -L "$DNS_RESOLV_BACKUP" ]; then
        rm -f /etc/resolv.conf
        cp -P "$DNS_RESOLV_BACKUP" /etc/resolv.conf
        rm -f "$DNS_RESOLV_BACKUP"
        success "$(L '已从备份恢复 /etc/resolv.conf')"
    else
        info "$(L '没有本脚本做过的 DNS 改动可恢复')"
    fi
    return 0
}

dns_menu() {
    local ans=""
    echo "  1) $(L '查看当前 DNS    2')) $(L '设置 DNS    3')) $(L '恢复为修改前    0')) $(L '返回')"
    read -rp "$(L '请选择:') " ans || return 0
    case "$ans" in
        1) dns_show ;;
        2) dns_set ;;
        3) dns_restore ;;
        *) : ;;
    esac
    return 0
}

# ── IPv4 / IPv6 优先级（getaddrinfo 的地址选择顺序，不关闭任何协议栈） ──

ip_priority_current() {
    local p4 p6
    p4="$(awk '$1 == "precedence" && $2 == "::ffff:0:0/96" {print $3}' /etc/gai.conf 2>/dev/null | tail -n 1 || true)"
    p6="$(awk '$1 == "precedence" && $2 == "::/0" {print $3}' /etc/gai.conf 2>/dev/null | tail -n 1 || true)"
    [[ "$p6" =~ ^[0-9]+$ ]] || p6=40
    if [[ "$p4" =~ ^[0-9]+$ ]] && [ "$p4" -gt "$p6" ]; then printf "$(L 'IPv4 优先')"; else printf "$(L 'IPv6 优先（系统默认）')"; fi
}

ip_priority_set() {   # ip_priority_set ipv4|ipv6
    local which="$1" p4=100 p6=10
    if [ "$which" = "ipv6" ]; then p4=10; p6=100; fi
    install -d -m 755 "$MAINT_DIR"
    # 只在第一次改动前备份原始状态
    if [ ! -e "$GAI_BACKUP" ] && [ ! -e "${GAI_BACKUP}.absent" ]; then
        if [ -f /etc/gai.conf ]; then cp -p /etc/gai.conf "$GAI_BACKUP"; else : > "${GAI_BACKUP}.absent"; fi
    fi
    # 原地只改两条 precedence 行，保留文件里其他 label/scopev4/reload 等条目
    #（旧版整文件重写会丢掉发行版或用户原有的条目；兼容多空格/制表符及末尾无换行）
    [ -f /etc/gai.conf ] || : > /etc/gai.conf
    if [ -s /etc/gai.conf ] && [ -n "$(tail -c 1 /etc/gai.conf 2>/dev/null)" ]; then
        printf '\n' >> /etc/gai.conf
    fi
    if grep -qE '^[[:space:]]*precedence[[:space:]]+::ffff:0:0/96([[:space:]]|$)' /etc/gai.conf; then
        sed -i -E "s|^[[:space:]]*precedence[[:space:]]+::ffff:0:0/96([[:space:]].*)?$|precedence ::ffff:0:0/96  ${p4}|" /etc/gai.conf
    else
        echo "precedence ::ffff:0:0/96  ${p4}" >> /etc/gai.conf
    fi
    if grep -qE '^[[:space:]]*precedence[[:space:]]+::/0([[:space:]]|$)' /etc/gai.conf; then
        sed -i -E "s|^[[:space:]]*precedence[[:space:]]+::/0([[:space:]].*)?$|precedence ::/0           ${p6}|" /etc/gai.conf
    else
        echo "precedence ::/0           ${p6}" >> /etc/gai.conf
    fi
    if command -v resolvectl >/dev/null 2>&1; then resolvectl flush-caches 2>/dev/null || true; fi
    success "$(L '已设置为') $([ "$which" = "ipv6" ] && echo IPv6 || echo IPv4) $(L '优先（新启动的程序生效；已在运行的服务重启后生效）')"
    return 0
}

ip_priority_restore() {
    if [ -f "$GAI_BACKUP" ]; then
        cp -p "$GAI_BACKUP" /etc/gai.conf; rm -f "$GAI_BACKUP"
        success "$(L '已恢复原来的 /etc/gai.conf')"
    elif [ -e "${GAI_BACKUP}.absent" ]; then
        rm -f /etc/gai.conf "${GAI_BACKUP}.absent"
        success "$(L '已恢复（原系统没有 /etc/gai.conf，已删除）')"
    else
        info "$(L '没有本脚本做过的优先级改动可恢复')"
    fi
    return 0
}

ip_priority_menu() {
    local ans=""
    echo "  $(L '当前:') $(ip_priority_current)"
    echo "  1) $(L 'IPv4 优先    2')) $(L 'IPv6 优先    3')) $(L '恢复为修改前    0')) $(L '返回')"
    read -rp "$(L '请选择:') " ans || return 0
    case "$ans" in
        1) ip_priority_set ipv4 ;;
        2) ip_priority_set ipv6 ;;
        3) ip_priority_restore ;;
        *) : ;;
    esac
    return 0
}

# ── 禁用 / 恢复 IPv6 ───────────────────────────────────────────

ipv6_state_text() {
    local v
    v="$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo '?')"
    case "$v" in
        0) printf "$(L '已启用')" ;;
        1) if [ -f "$IPV6_DISABLE_FILE" ]; then printf "$(L '已禁用（永久）')"; else printf "$(L '已禁用（临时，重启恢复）')"; fi ;;
        *) printf "$(L '未知')" ;;
    esac
}

# IPv6 可用性变化后，让本脚本管理的服务换用合适的监听地址
services_adapt_ipv6() {
    local f changed=0 port psk mode pref xbak=""
    if [ -x "$SNELL_BIN" ] && [ -f "$SNELL_CONF" ]; then
        port="$(snell_port)"; psk="$(snell_conf_get psk 2>/dev/null || true)"
        mode="$(snell_conf_get mode 2>/dev/null || true)"; pref="$(snell_conf_get dns-ip-preference 2>/dev/null || true)"
        if [ -n "$port" ] && [ -n "$psk" ]; then
            snell_write_conf "$port" "$psk" "${mode:-default}" "${pref:-default}"
            systemctl try-restart snell >/dev/null 2>&1 || true
            local xp xconf
            while IFS= read -r xp; do
                xconf="${SNELL_PORTS_DIR}/${xp}.conf"
                snell_write_conf "$xp" "$(snell_conf_get psk "$xconf" 2>/dev/null || true)" \
                    "$(snell_conf_get mode "$xconf" 2>/dev/null || echo default)" \
                    "$(snell_conf_get dns-ip-preference "$xconf" 2>/dev/null || echo default)" "$xconf"
                systemctl try-restart "snell-port@${xp}" >/dev/null 2>&1 || true
            done < <(snell_extra_ports)
            info "$(L 'Snell 的监听地址已按当前 IPv6 状态调整')"
        fi
    fi
    if [ -d "$XRAY_CONF_D" ]; then
        for f in "$XRAY_CONF_D"/10-in-*.json; do
            [ -f "$f" ] || continue
            if ipv6_dualstack_ok; then
                if grep -q '"listen": "0.0.0.0"' "$f"; then
                    [ -n "$xbak" ] || { make_workdir || return 1; xbak="$WORKDIR/xray_in"; mkdir -p "$xbak"; }
                    cp -a "$f" "$xbak/" 2>/dev/null || true
                    sed -i 's/"listen": "0.0.0.0"/"listen": "::"/' "$f"; changed=1
                fi
            else
                if grep -q '"listen": "::"' "$f"; then
                    [ -n "$xbak" ] || { make_workdir || return 1; xbak="$WORKDIR/xray_in"; mkdir -p "$xbak"; }
                    cp -a "$f" "$xbak/" 2>/dev/null || true
                    sed -i 's/"listen": "::"/"listen": "0.0.0.0"/' "$f"; changed=1
                fi
            fi
        done
        if [ "$changed" = "1" ]; then
            xray_fix_perms
            # 改完先校验，不通过就恢复原文件、不重启（原先改完直接 try-restart 且总返回成功）
            if xray_test_conf >/dev/null 2>&1; then
                systemctl try-restart adam-xray >/dev/null 2>&1 || true
                info "$(L 'Xray 节点的监听地址已按当前 IPv6 状态调整')"
            else
                warn "$(L 'Xray 配置改动后校验失败，已恢复原文件')"
                [ -n "$xbak" ] && cp -a "$xbak"/*.json "$XRAY_CONF_D/" 2>/dev/null || true
                xray_fix_perms
            fi
        fi
    fi
    # 同步调整 Xray 转发规则的默认监听地址（带 .env 备份与失败自动回滚）
    if [ -d "$XRAY_FWD_DIR" ]; then
        local _fchg=0 _ff _fbak=""
        while IFS= read -r _ff; do
            if ipv6_dualstack_ok; then
                if grep -q '^FWD_LIP="0.0.0.0"$' "$_ff"; then
                    [ -n "$_fbak" ] || { make_workdir || return 1; _fbak="$WORKDIR/xray_fwd"; mkdir -p "$_fbak"; }
                    cp -a "$_ff" "$_fbak/" 2>/dev/null || true
                    sed -i 's/^FWD_LIP="0.0.0.0"$/FWD_LIP="::"/' "$_ff"; _fchg=1
                fi
            else
                if grep -q '^FWD_LIP="::"$' "$_ff"; then
                    [ -n "$_fbak" ] || { make_workdir || return 1; _fbak="$WORKDIR/xray_fwd"; mkdir -p "$_fbak"; }
                    cp -a "$_ff" "$_fbak/" 2>/dev/null || true
                    sed -i 's/^FWD_LIP="::"$/FWD_LIP="0.0.0.0"/' "$_ff"; _fchg=1
                fi
            fi
        done < <(xray_fwd_rule_files)
        if [ "$_fchg" = "1" ] && ! xray_fwd_rebuild >/dev/null 2>&1; then
            warn "$(L 'Xray 转发监听地址调整失败，已恢复原规则配置')"
            [ -n "$_fbak" ] && cp -a "$_fbak"/*.env "$XRAY_FWD_DIR/" 2>/dev/null || true
            xray_fwd_rebuild >/dev/null 2>&1 || true
        fi
    fi
    # 同步调整 Realm 规则的默认监听地址（带 .env 备份与失败自动回滚）
    if [ -d "$REALM_RULE_DIR" ]; then
        local _rchg=0 _rf _rbak=""
        while IFS= read -r _rf; do
            if ipv6_dualstack_ok; then
                if grep -q '^RULE_LIP="0.0.0.0"$' "$_rf"; then
                    [ -n "$_rbak" ] || { make_workdir || return 1; _rbak="$WORKDIR/realm_rules"; mkdir -p "$_rbak"; }
                    cp -a "$_rf" "$_rbak/" 2>/dev/null || true
                    sed -i 's/^RULE_LIP="0.0.0.0"$/RULE_LIP="[::]"/' "$_rf"; _rchg=1
                fi
            else
                if grep -qE '^RULE_LIP="(\[::\]|::)"$' "$_rf"; then
                    [ -n "$_rbak" ] || { make_workdir || return 1; _rbak="$WORKDIR/realm_rules"; mkdir -p "$_rbak"; }
                    cp -a "$_rf" "$_rbak/" 2>/dev/null || true
                    sed -i -E 's/^RULE_LIP="(\[::\]|::)"$/RULE_LIP="0.0.0.0"/' "$_rf"; _rchg=1
                fi
            fi
        done < <(realm_rule_files)
        if [ "$_rchg" = "1" ] && ! realm_reload_service >/dev/null 2>&1; then
            warn "$(L 'Realm 监听地址调整失败，已恢复原规则配置')"
            [ -n "$_rbak" ] && cp -a "$_rbak"/*.env "$REALM_RULE_DIR/" 2>/dev/null || true
            realm_reload_service >/dev/null 2>&1 || true
        fi
    fi
    return 0
}

ipv6_ssh_guard() {
    local peer="${SSH_CONNECTION%% *}"
    if [[ "$peer" == *:* ]]; then
        warn "$(L '你当前是通过 IPv6（')${peer}$(L '）登录的：禁用 IPv6 会立刻断开，且之后只能用 IPv4 登录')"
        confirm "$(L '确认本机有可用的 IPv4 登录方式并继续？')" n || return 1
    fi
    return 0
}

ipv6_disable() {   # ipv6_disable temp|perm
    local mode="$1"
    ipv6_ssh_guard || { info "$(L '已取消')"; return 0; }
    if [ "$mode" = "perm" ]; then
        confirm "$(L '永久禁用 IPv6（写入') ${IPV6_DISABLE_FILE}$(L '，重启后仍然生效）？')" n || { info "$(L '已取消')"; return 0; }
        cat > "$IPV6_DISABLE_FILE" << V6EOF
# $(L '由 Adam 管理脚本生成（系统与网络调优 -> 禁用 IPv6）。删除本文件并执行 sysctl --system 即恢复。')
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
V6EOF
    else
        confirm "$(L '临时禁用 IPv6（重启后自动恢复）？')" y || { info "$(L '已取消')"; return 0; }
    fi
    sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.lo.disable_ipv6=1 >/dev/null 2>&1 || true
    if [ "$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo 0)" = "1" ]; then
        success "IPv6 $(ipv6_state_text)"
        services_adapt_ipv6
    else
        warn "$(L '禁用失败（内核可能未编译 IPv6 或 sysctl 被限制）')"
        rm -f "$IPV6_DISABLE_FILE"
        return 1
    fi
    return 0
}

ipv6_enable() {
    rm -f "$IPV6_DISABLE_FILE"
    sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.lo.disable_ipv6=0 >/dev/null 2>&1 || true
    if [ "$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo 1)" = "0" ]; then
        success "$(L 'IPv6 已恢复启用（网卡的 IPv6 地址可能需要几秒，或重启网络 / 重启系统后才重新获取）')"
        services_adapt_ipv6
    else
        warn "$(L '恢复失败：可能有其他 sysctl 配置文件也禁用了 IPv6（grep -r disable_ipv6 /etc/sysctl.d /etc/sysctl.conf）')"
        return 1
    fi
    return 0
}

ipv6_menu() {
    local ans=""
    echo "  $(L '当前: IPv6') $(ipv6_state_text)"
    echo "  1) $(L '临时禁用（重启恢复）    2')) $(L '永久禁用    3')) $(L '恢复启用    0')) $(L '返回')"
    read -rp "$(L '请选择:') " ans || return 0
    case "$ans" in
        1) ipv6_disable temp ;;
        2) ipv6_disable perm ;;
        3) ipv6_enable ;;
        *) : ;;
    esac
    return 0
}

net_status() {
    step "$(L '当前系统与网络状态')"
    divider
    echo "  $(L '内核       :') $(uname -r)$([[ "$(uname -r)" == *xanmod* ]] && echo "（XanMod）")"
    echo "  $(L '拥塞控制   :') $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo '?')    $(L '可用:') $(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo '?')"
    echo "  $(L '默认队列   :') $(sysctl -n net.core.default_qdisc 2>/dev/null || echo '?')"
    echo "  IPv6       : $(ipv6_state_text)"
    echo "  $(L '地址优先级 :') $(ip_priority_current)"
    echo "  tcpfit     : $([ -x "$TCPFIT_BIN" ] && echo "$(L '已安装') $(tcpfit_installed_version)" || echo "$(L '未安装')")"
    echo "  $(L '保留端口   :') $(sysctl -n net.ipv4.ip_local_reserved_ports 2>/dev/null || echo '?')"
    echo ""
    dns_show
    return 0
}

tune_menu() {
    local choice
    while true; do
        clear 2>/dev/null || true
        echo -e "${BOLD}${CYAN}━━━ $(L '系统与网络调优') ━━━${NC}"
        echo -e "  $(L '内核:') $(uname -r)    $(L '拥塞控制:') $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo '?')    IPv6: $(ipv6_state_text)    $(ip_priority_current)"
        divider
        echo -e "  ${GREEN}1)${NC} ${GREEN}$(L 'TCP 调优')${NC}$(L '（tcpfit：按本机实测推导参数，可回滚）')"
        echo -e "  ${GREEN}2)${NC} $(L 'tcpfit 状态 / 回滚 / 更新')"
        echo -e "  ${GREEN}3)${NC} $(L '安装 / 更新 XanMod 内核（BBR v3，仅 x86_64）')"
        echo -e "  ${GREEN}4)${NC} ${RED}$(L '卸载')${NC} $(L 'XanMod 内核')"
        echo -e "  ${GREEN}5)${NC} $(L 'DNS 设置（查看 / 修改 / 恢复）')"
        echo -e "  ${GREEN}6)${NC} $(L 'IPv4 / IPv6 优先级')"
        echo -e "  ${GREEN}7)${NC} $(L '禁用 / 恢复 IPv6')"
        echo -e "  ${GREEN}8)${NC} $(L '查看当前状态')"
        echo -e "  ${GREEN}0)${NC} $(L '返回主菜单')"
        divider
        read -rp "$(L '请选择') [0-8]: " choice || return 0
        case "$choice" in
            1) run_action tcpfit_menu_entry ;;
            2) run_action tcpfit_sub_menu ;;
            3) run_action xanmod_install ;;
            4) run_action xanmod_uninstall ;;
            5) run_action dns_menu ;;
            6) run_action ip_priority_menu ;;
            7) run_action ipv6_menu ;;
            8) run_action net_status ;;
            0) return 0 ;;
            *) warn "$(L '无效选择')" ;;
        esac
        pause_return
    done
}

tcpfit_sub_menu() {
    local ans=""
    echo "  1) $(L '查看 tcpfit 状态    2')) $(L '回滚 tcpfit 的全部改动    3')) $(L '检查并更新 tcpfit    0')) $(L '返回')"
    read -rp "$(L '请选择:') " ans || return 0
    case "$ans" in
        1) tcpfit_run status ;;
        2) tcpfit_run rollback ;;
        3) tcpfit_update ;;
        *) : ;;
    esac
    return 0
}

tune_cli() {
    local sub="${1:-menu}"
    if [ "$#" -gt 0 ]; then shift; fi
    case "$sub" in
        menu)        tune_menu ;;
        tcp|tcpfit)  tcpfit_run "$@" ;;
        tcpfit-update) tcpfit_update ;;
        xanmod)      xanmod_install ;;
        xanmod-remove) xanmod_uninstall ;;
        dns)
            case "${1:-}" in
                show)    dns_show ;;
                set)     dns_set ;;
                restore) dns_restore ;;
                *)       dns_menu ;;
            esac ;;
        prefer)
            case "${1:-}" in
                ipv4|ipv6) ip_priority_set "$1" ;;
                restore)   ip_priority_restore ;;
                *)         ip_priority_menu ;;
            esac ;;
        ipv6)
            case "${1:-}" in
                off)      ipv6_disable perm ;;
                off-temp) ipv6_disable temp ;;
                on)       ipv6_enable ;;
                *)        ipv6_menu ;;
            esac ;;
        status)      net_status ;;
        *) error "$(L '未知的 tune 子命令:') ${sub}$(L '（可用: tcp') [$(L 'tcpfit 子命令')] / tcpfit-update / xanmod / xanmod-remove / dns [show|set|restore] / prefer [ipv4|ipv6|restore] / ipv6 [off|off-temp|on] $(L '/ status）')" ;;
    esac
}

do_update_script() {
    step "$(L '更新管理脚本')"
    divider
    maint_load
    local tmp remote_ver
    make_workdir || return 1
    tmp="$WORKDIR/manager.sh"
    info "$(L '当前版本:') ${SCRIPT_VERSION}$(L '，正在从') ${SCRIPT_URL} $(L '下载 ...')"
    # 与自动维护共用 script_fetch_remote（带 ?t= 缓存击穿 + 标识/语法完整性校验）
    if ! script_fetch_remote "$tmp"; then
        warn "$(L '下载失败或远端内容不完整，请检查网络或脚本地址（现有脚本未改动）')"
        return 1
    fi
    remote_ver="$REMOTE_SCRIPT_VERSION"
    info "$(L '远端版本:') ${remote_ver:-$(L '未知')}"
    if [ -f "$MANAGER_PATH" ] && cmp -s "$tmp" "$MANAGER_PATH"; then
        info "$(L '本地已是仓库最新版本')"
        return 0
    fi
    # 与自动维护一致：远端版本低于本地不降级（仓库里旧内容可能仍挂着旧版本号）
    if ! version_ge "$remote_ver" "$SCRIPT_VERSION"; then
        warn "$(L '仓库版本') ${remote_ver} $(L '低于本地') ${SCRIPT_VERSION}$(L '，不降级')"
        return 1
    fi
    if [ "${remote_ver#v}" = "${SCRIPT_VERSION#v}" ]; then
        if ! confirm "$(L '版本号相同，仍要用远端内容覆盖本地脚本？')" n; then
            info "$(L '已取消')"
            return 0
        fi
    fi
    if [ -f "$MANAGER_PATH" ]; then cp -f "$MANAGER_PATH" "${MANAGER_PATH}.bak"; fi
    install -m 755 "$tmp" "$MANAGER_PATH"
    success "$(L '管理脚本已更新到') ${remote_ver:-$(L '新版本')}$(L '（旧版备份在') ${MANAGER_PATH}$(L '.bak），重新运行 adam 生效')"
    return 0
}

# probe_tcp_host_port HOST PORT：TCP 握手探测，打印 OK <毫秒> 或 FAIL <原因>；恒返回 0，
# 调用方按输出前缀判断。IPv6 与域名解析走 python3；无 python3 时退到 /dev/tcp（仅 IPv4/域名）。
probe_tcp_host_port() {
    local host="$1" port="$2"
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import socket,sys,time
h,p = sys.argv[1].strip("[]"), int(sys.argv[2])
t0 = time.monotonic()
try:
    with socket.create_connection((h, p), timeout=3):
        print(f"OK {(time.monotonic()-t0)*1000:.1f}ms")
except Exception as e:
    print(f"FAIL {e}")' "$host" "$port" 2>/dev/null || echo "FAIL"
        return 0
    fi
    case "$host" in *:* ) echo "FAIL (need python3 for IPv6)"; return 0 ;; esac
    if timeout 3 bash -c 'exec 3<>/dev/tcp/"$0"/"$1"' "$host" "$port" 2>/dev/null; then
        echo "OK"
    else
        echo "FAIL timeout/refused"
    fi
    return 0
}

