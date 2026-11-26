L() {
    local k="${1:-}"
    if [ "${ADAM_LANG:-zh}" != "en" ] || [ -z "$k" ]; then printf '%s' "$k"; return 0; fi
    [ "$_I18N_INIT" = "1" ] || init_i18n_en
    printf '%s' "${I18N[$k]:-$k}"
}

set_lang_menu() {
    echo "  1) $(L '中文') (zh)"
    echo "  2) English (en)"
    read -rp "$(L '请选择') [1/2]: " _lang_choice
    case "$_lang_choice" in
        1) set_lang zh ;;
        2) set_lang en ;;
        *) warn "$(L '无效选择')" ;;
    esac
}

# 首次使用 / 安装开始时先选语言（双语提示，不依赖当前语言设置）
ask_lang_first_time() {
    [ -f "$LANG_FILE" ] && return 0
    [ -t 0 ] || return 0
    echo "  1) 中文 (zh)"
    echo "  2) English (en)"
    read -rp "请选择语言 / Choose language [1/2, default 1]: " _first_lang
    case "$_first_lang" in 2) set_lang en ;; *) set_lang zh ;; esac
}

# adam lang [zh|en]：切换界面语言并持久化；不带参数显示当前语言
set_lang() {
    local want="${1:-}"
    case "$want" in
        zh|en) : ;;
        "") info "$(L '当前语言：')${ADAM_LANG}$(L '（zh=中文 / en=English，切换：adam lang zh')|$(L 'en）')"; return 0 ;;
        *) warn "$(L '用法：adam lang zh')|$(L 'en（当前：')${ADAM_LANG}$(L '）')"; return 1 ;;
    esac
    mkdir -p "$(dirname "$LANG_FILE")"
    printf '%s\n' "$want" > "$LANG_FILE"
    ADAM_LANG="$want"
    [ "$ADAM_LANG" = "en" ] && init_i18n_en
    success "$(L '语言已切换为') ${want}$(L '（zh=中文 / en=English），下次打开菜单生效')"
}

load_lang
[ "$EUID" -ne 0 ] && error "$(L '请以 root 用户运行此脚本')"

ACTION="${1:-menu}"
if [ "$#" -gt 0 ]; then shift; fi
ACTION_ARGS=("$@")

# ── 脚本 v4.0 通用基础设施 ─────────────────────────────────────

# 临时目录统一登记，脚本（或菜单动作所在的子 shell）退出时清理
_CLEANUP_DIRS=()
_cleanup() {
    local d
    for d in "${_CLEANUP_DIRS[@]}"; do
        if [ -n "$d" ] && [ -d "$d" ]; then rm -rf "$d"; fi
    done
    return 0
}
trap _cleanup EXIT
trap '_cleanup; exit 143' TERM HUP

# 新建临时工作目录，路径写入全局 WORKDIR（不能用 $(...) 调用，否则登记会丢在子 shell 里）
make_workdir() {
    WORKDIR="$(mktemp -d /tmp/adam-work.XXXXXX 2>/dev/null || true)"
    [ -n "$WORKDIR" ] && [ -d "$WORKDIR" ] || { warn "$(L '创建临时工作目录失败')"; WORKDIR=""; return 1; }
    _CLEANUP_DIRS+=("$WORKDIR")
    return 0
}

# confirm "提示" [y|n]：第二个参数是回车时的默认值；设置 ADAM_ASSUME_YES=1 时非交互自动同意
confirm() {
    local prompt="$1" def="${2:-n}" ans=""
    if [ "${ADAM_ASSUME_YES:-0}" = "1" ]; then return 0; fi
    if [ "$def" = "y" ]; then
        read -rp "$(L "$prompt") [Y/n]: " ans || { [ -n "$ans" ] || return 1; }
        [[ ! "$ans" =~ ^[Nn]$ ]]
    else
        read -rp "$(L "$prompt") [y/N]: " ans || { [ -n "$ans" ] || return 1; }
        [[ "$ans" =~ ^[Yy]$ ]]
    fi
}

pause_return() {
    echo ""
    read -rp "$(L '按回车返回菜单...') " _ || true
}

# 在子 shell 中执行一个菜单动作：动作里的 error/exit、set -e 触发的中止、Ctrl+C
# 都只结束这一个动作，不会把整个菜单带走。
run_action() {
    set +e
    trap ':' INT
    ( trap _cleanup EXIT; trap - INT; _CLEANUP_DIRS=(); set -e; "$@" )
    trap - INT
    set -e
    return 0
}

# _pkg_mgr：返回当前系统可用的包管理器（apt / dnf / yum / apk）
_pkg_mgr() {
    if command -v apt-get >/dev/null 2>&1; then printf 'apt';
    elif command -v dnf >/dev/null 2>&1; then printf 'dnf';
    elif command -v yum >/dev/null 2>&1; then printf 'yum';
    elif command -v apk >/dev/null 2>&1; then printf 'apk';
    else printf ''; fi
}

# _pkg_map_name MGR DEB_PKG：将 Debian 风格包名映射到目标发行版包名
_pkg_map_name() {
    local mgr="$1" pkg="$2"
    case "${mgr}:${pkg}" in
        dnf:iproute2|yum:iproute2) printf 'iproute' ;;
        dnf:gnupg|yum:gnupg)       printf 'gnupg2' ;;
        dnf:dnsutils|yum:dnsutils) printf 'bind-utils' ;;
        apk:dnsutils)              printf 'bind-tools' ;;
        apk:gnupg)                 printf 'gnupg' ;;
        apk:qrencode)              printf 'libqrencode-tools' ;;
        *)                         printf '%s' "$pkg" ;;
    esac
}

pkg_installed() {
    local mgr p s
    mgr="$(_pkg_mgr)"
    p="$(_pkg_map_name "$mgr" "$1")"
    case "$mgr" in
        apt)
            s="$(dpkg-query -W -f='${Status}' "$p" 2>/dev/null || true)"
            [ "$s" = "install ok installed" ]
            ;;
        dnf|yum)
            rpm -q "$p" >/dev/null 2>&1
            ;;
        apk)
            apk info -e "$p" >/dev/null 2>&1
            ;;
        *)
            command -v "$1" >/dev/null 2>&1
            ;;
    esac
}

# 按需安装软件包（支持 Debian/Ubuntu apt、RHEL/Rocky/Fedora dnf/yum、Alpine apk）；已安装的跳过
APT_UPDATED=0
apt_install() {
    local mgr p mapped
    local -a need=()
    mgr="$(_pkg_mgr)"
    for p in "$@"; do
        if ! pkg_installed "$p"; then
            mapped="$(_pkg_map_name "$mgr" "$p")"
            need+=("$mapped")
        fi
    done
    if [ "${#need[@]}" -eq 0 ]; then return 0; fi
    case "$mgr" in
        apt)
            if [ "$APT_UPDATED" != "1" ]; then
                apt-get update -qq || warn "$(L 'apt-get update 失败，继续尝试安装')"
                APT_UPDATED=1
            fi
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${need[@]}"
            ;;
        dnf)
            dnf install -y -q "${need[@]}"
            ;;
        yum)
            yum install -y -q "${need[@]}"
            ;;
        apk)
            if [ "$APT_UPDATED" != "1" ]; then
                apk update -q || true
                APT_UPDATED=1
            fi
            apk add --no-cache -q "${need[@]}"
            ;;
        *)
            warn "$(L '未找到受支持的包管理器（apt/dnf/yum/apk），请手动安装:') ${need[*]}"
            return 1
            ;;
    esac
}

# 向导里的输入校验依赖 python3（IP 字面量校验、URL 编码、Release digest 解析），
# 旧版要到「安装系统依赖」那一步才装，精简镜像上会在此之前把合法输入误判为不合法。
ensure_prereqs() {
    local -a need=()
    command -v curl >/dev/null 2>&1 || need+=(curl)
    command -v python3 >/dev/null 2>&1 || need+=(python3)
    command -v openssl >/dev/null 2>&1 || need+=(openssl)
    if [ "${#need[@]}" -gt 0 ]; then
        info "$(L '先安装向导所需的基础工具:') ${need[*]}"
        apt_install "${need[@]}" || warn "$(L '基础工具安装失败，后续的输入校验可能不准确')"
    fi
    return 0
}

# version_ge A B：A >= B（只比较 X.Y.Z 数字部分；解析不了的按 0.0.0 处理）
version_ge() {
    local a="${1#v}" b="${2#v}" i x y an bn asuf bsuf
    local -a A=() B=()
    an="${a%%[^0-9.]*}"; bn="${b%%[^0-9.]*}"
    asuf="${a#$an}"; bsuf="${b#$bn}"
    IFS=. read -r -a A <<< "$an"
    IFS=. read -r -a B <<< "$bn"
    for i in 0 1 2; do
        x="${A[$i]:-0}"; y="${B[$i]:-0}"
        [[ "$x" =~ ^[0-9]+$ ]] || x=0
        [[ "$y" =~ ^[0-9]+$ ]] || y=0
        if (( 10#$x > 10#$y )); then return 0; fi
        if (( 10#$x < 10#$y )); then return 1; fi
    done
    # 数字部分相等：带预发布后缀（-rc/-beta/b3 等）的版本小于正式版；都有后缀时按自然序比（b10 > b2）
    if [ "$asuf" = "$bsuf" ]; then return 0; fi
    if [ -z "$asuf" ]; then return 0; fi
    if [ -z "$bsuf" ]; then return 1; fi
    local as_tag as_num bs_tag bs_num
    as_tag="${asuf%%[0-9]*}"; as_num="${asuf#"$as_tag"}"
    bs_tag="${bsuf%%[0-9]*}"; bs_num="${bsuf#"$bs_tag"}"
    if [ "$as_tag" = "$bs_tag" ] && [[ "$as_num" =~ ^[0-9]+$ ]] && [[ "$bs_num" =~ ^[0-9]+$ ]]; then
        (( 10#$as_num >= 10#$bs_num ))
        return $?
    fi
    [ "$(printf '%s\n%s\n' "$asuf" "$bsuf" | sort -V | tail -n 1)" = "$asuf" ]
}

