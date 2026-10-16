#!/bin/bash
set -e
set -o pipefail

# ══════════════════════════════════════════════════════════════
#   Adam Nowhere Portal 一键管理脚本（适配 Nowhere v3.0.0 / NW3）
#   已按 v3.0.0 官方文档 + 真实二进制实测重写，v1.5.x 旧配置不兼容：
#     - 协议已换 NW3（ALPN 固定 nw3），v1/v2 的 Portal/Vector 无法
#       与 v3 互通，升级必须 Portal、Vector、Anywhere 等对端一起升级
#     - 共享密钥必须是恰好 32 位小写十六进制字符（nowhere generate-key），
#       旧版任意字符串密钥（如 Base64）会被 v3 在启动时直接拒绝
#     - 已移除的参数：alpn（固定 nw3）/ net / log / pool / next / mux /
#       up / down / socks(Vector) —— v3 对未知参数是“忽略”而非报错，
#       所以旧 URL 拼进 v3 也不会生效，只会静默跑偏
#     - Portal 监听改用端点路径语法：portal://KEY@*:443（同端口双栈）、
#       portal://KEY@*/tcp:443（仅TLS）、portal://KEY@*/udp:443（仅QUIC）、
#       portal://KEY@*/tcp:2000/udp:2001（双端口）；空主机 :443 已非法，
#       通配监听必须写 *；地址族可用 tcp4/tcp6/udp4/udp6
#     - Portal 出口统一为 out=：direct（默认）/ egress / SOCKS5 地址，
#       旧 socks= 已改名；Vector 本地入口改用 in=（旧 socks= 会被拒：
#       实测报 "in parameter is required"）；Vector 不再有 pool
#     - Morph 默认开启（morph=1），关闭必须两端显式 morph=0 且一致
#     - 新增第三角色 Egress：Portal 配 out=egress + 远程机跑
#       egress://KEY@host/udp:port 主动回连，无需出口机开放入站端口
#     - 新增 CLI：nowhere generate-key / fingerprint / probe / status；
#       无参数运行只显示帮助（v1.6 的 TUI 已在 v3 移除）
#   快捷命令：adam(菜单) · zt(状态) · pz(配置) · cxpz(重新配置) · cq(重启)
#   支持 Debian / Ubuntu · x86_64 / aarch64
#   ── v2 升级（2026-10-16）：证书申请与自动续期重构 + 全面加固 ──
#     证书链路：新增 cert_is_valid（存在/剩余>30天/域名匹配/私钥匹配），有效则跳过、无效才重签；
#       新增 verify_issued_cert，签发后用 openssl 复核（防“有文件但不可用”）；
#       新增 check_domain_dns，HTTP-01 前做 DNS 预检；
#       新增 setup_certbot_renewal：deploy hook + 确保 certbot.timer 生效（缺失时 cron 兜底）+
#       可选 --dry-run 续期演练；新增 setup_acmesh_renewal 确认 acme.sh cron 就绪；
#       acme.sh 分支：安装失败显式报错、去掉 --issue --force（防 LE 频率限制）、校验签发结果；
#       「其他/手动」DNS 改为明确不支持并指引改选；新增菜单 16「检查证书状态 / 手动续期」。
#     通用加固：下载改用 mktemp 独立目录（防并发冲突、自动清理）；发布包 SHA256 机会性校验；
#       GitHub API 解析加 || true 适配 pipefail；gai.conf 追加防粘连；卸载时清理续期 hook。
# ══════════════════════════════════════════════════════════════

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

REPO="NodePassProject/Nowhere"
BIN_PATH="/usr/local/bin/nowhere"
BIN_BACKUP_PATH="/usr/local/bin/nowhere.previous"
CONFIG_DIR="/etc/nowhere"
CONFIG_FILE="${CONFIG_DIR}/nowhere.env"
VERSION_FILE="${CONFIG_DIR}/version.txt"
PREV_VERSION_FILE="${CONFIG_DIR}/version.previous.txt"
SERVICE_FILE="/etc/systemd/system/nowhere.service"
ACME_HOME="/root/.acme.sh"
MANAGER_PATH="/usr/local/bin/adam-nowhere-manager.sh"

DEFAULT_MORPH="1"
DEFAULT_VECTOR_SOCKS="127.0.0.1:1080"
DEFAULT_DIAL="auto"

info()    { echo -e "${BLUE}[信息]${NC} $1"; }
success() { echo -e "${GREEN}[成功]${NC} $1"; }
warn()    { echo -e "${YELLOW}[警告]${NC} $1"; }
error()   { echo -e "${RED}[错误]${NC} $1"; exit 1; }
step()    { echo -e "\n${BOLD}${CYAN}━━━ $1 ━━━${NC}"; }
divider() { echo -e "${CYAN}────────────────────────────────────────────────────────${NC}"; }

[ "$EUID" -ne 0 ] && error "请以 root 用户运行此脚本"

ACTION="${1:-menu}"

# ── 架构 / 二进制 ─────────────────────────────────────────────

detect_binary() {
    ARCH=$(uname -m)
    case $ARCH in
        x86_64|amd64)  ARCH_NAME="x86_64" ;;
        aarch64|arm64) ARCH_NAME="aarch64" ;;
        *)             error "不支持的架构: ${ARCH}" ;;
    esac
    LIBC="gnu"
    if command -v ldd >/dev/null 2>&1 && ldd --version 2>&1 | grep -qi musl; then
        LIBC="musl"
    fi
    BIN_NAME="nowhere-${ARCH_NAME}-unknown-linux-${LIBC}.tar.gz"
}

record_installed_version() {
    local tag="$1"
    install -d -m 700 "$CONFIG_DIR"
    echo "$tag" > "$VERSION_FILE"
}

read_installed_version() {
    [ -f "$VERSION_FILE" ] && cat "$VERSION_FILE" || echo "未知"
}

read_previous_version() {
    [ -f "$PREV_VERSION_FILE" ] && cat "$PREV_VERSION_FILE" || echo ""
}

# 取 tag 的主版本号，如 v3.0.0 -> 3；解析不了返回空
version_major() {
    echo "$1" | sed -n 's/^v\?\([0-9][0-9]*\)\..*/\1/p'
}

install_nowhere_version() {
    local target_tag="$1"
    detect_binary

    local major
    major="$(version_major "$target_tag")"
    if [ -n "$major" ] && [ "$major" -lt 3 ]; then
        warn "目标版本 ${target_tag} 属于 NW${major} 协议代，与本脚本生成的 v3(NW3) 配置/对端不互通"
        read -p "仍要安装该旧版本吗？[y/N]: " OLD_CONFIRM
        if [[ ! "$OLD_CONFIRM" =~ ^[Yy]$ ]]; then
            info "已取消"
            return 1
        fi
    fi

    local url="https://github.com/${REPO}/releases/download/${target_tag}/${BIN_NAME}"
    info "校验该版本是否发布了对应架构 (${ARCH_NAME}-${LIBC}) 的二进制..."
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -L "$url")
    if [ "$http_code" != "200" ]; then
        warn "版本 ${target_tag} 未找到对应架构的发布文件 (HTTP ${http_code})"
        return 1
    fi

    info "下载 ${target_tag} ..."
    local workdir binary_path
    workdir="$(mktemp -d /tmp/nowhere-dl.XXXXXX)"
    trap "rm -rf $workdir" RETURN
    curl -fL --retry 3 -o "$workdir/nowhere.tar.gz" "$url" || { warn "下载失败"; return 1; }
    verify_release_checksum "$target_tag" "$workdir" || { warn "校验失败，已中止安装"; return 1; }
    tar -xzf "$workdir/nowhere.tar.gz" -C "$workdir/" || { warn "解压失败"; return 1; }
    binary_path=$(find "$workdir" -type f -name nowhere | head -1)
    if [ -z "$binary_path" ]; then
        warn "解压后未找到 nowhere 二进制"
        return 1
    fi

    if [ -f "$BIN_PATH" ]; then
        cp "$BIN_PATH" "$BIN_BACKUP_PATH"
        read_installed_version > "$PREV_VERSION_FILE"
    fi

    systemctl stop nowhere 2>/dev/null || true
    install -m 755 "$binary_path" "$BIN_PATH"
    record_installed_version "$target_tag"
    systemctl start nowhere
    sleep 2

    if systemctl is-active --quiet nowhere; then
        success "已切换到 ${target_tag}: $(${BIN_PATH} --version 2>&1 | head -1)"
        return 0
    else
        warn "新版本启动失败，日志如下："
        journalctl -u nowhere -n 20 --no-pager
        return 1
    fi
}

# ── 通用小工具 ────────────────────────────────────────────────

urlencode() {
    local input="${1:-}"
    python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$input" 2>/dev/null \
        || echo -n "$input" | od -An -tx1 | tr ' ' % | tr -d '\n'
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
# 装好二进制后优先用官方 nowhere generate-key，两者格式一致
gen_key() {
    if [ -x "$BIN_PATH" ]; then
        local k
        k="$("$BIN_PATH" generate-key 2>/dev/null | tr -d ' \r\n' || true)"
        if is_valid_key "$k"; then
            printf '%s' "$k"
            return 0
        fi
    fi
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 16 | tr -d '\n'
    else
        od -An -tx1 -N16 /dev/urandom | tr -d ' \n'
    fi
}

detect_public_host() {
    local detected=""
    detected="$(curl -4fsS --max-time 4 https://api.ipify.org 2>/dev/null || true)"
    [[ -z "$detected" ]] && detected="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
    printf '%s' "$detected"
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
    [[ "$1" =~ ^[0-9]+$ ]] && [[ "$1" -ge 1 ]] && [[ "$1" -le 65535 ]]
}

validate_nonneg_int() {
    [[ "$1" =~ ^[0-9]+$ ]]
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
        [[ "$endpoint" != *:*:* ]] || return 1
        host="${endpoint%:*}"; port="${endpoint##*:}"
    fi
    [[ -n "$host" ]] || return 1
    validate_port "$port"
}

# 证书信任参数（Vector/Egress 共用）：
#   tls=2 真实证书：默认按端点主机名走系统 CA 校验；公网地址与证书域名不一致时补 sni=
#   tls=1 自签证书：必须 pin=证书 SHA-256 指纹（64 位小写 hex），否则校验必然失败
# 自签指纹取不到（服务未启动等）时返回 1，调用方应留空并提示稍后用菜单 5/8 重新生成
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
    local host
    if [[ -z "$LISTEN_HOST" || "$LISTEN_HOST" == "*" ]]; then
        host="*"
    else
        host="$(format_host_for_url "$LISTEN_HOST")"
    fi
    if [[ "$PORT_MODE" == "split" ]]; then
        printf '%s/tcp:%s/udp:%s' "$host" "$TCP_PORT" "$UDP_PORT"
    else
        case "$NET" in
            tcp) printf '%s/tcp:%s' "$host" "$PORT" ;;
            udp) printf '%s/udp:%s' "$host" "$PORT" ;;
            *)   printf '%s:%s' "$host" "$PORT" ;;
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
        query="${query}&crt=${CRT}&key=${KEY_PEM}"
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
    host="${PUBLIC_HOST:-}"
    [[ -z "$host" ]] && host="$(detect_public_host)"
    host_part="$(format_host_for_url "$host")"
    encoded_name="$(urlencode "Nowhere-${DOMAIN}")"
    base="nowhere://${SHARED_KEY}@${host_part}"

    UDP_LINK=""; TCP_LINK=""; IMPORT_UDP=""; IMPORT_TCP=""

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
build_vector_info() {
    VECTOR_URL=""
    [ "$GENERATE_VECTOR" != "1" ] && return 0

    local host host_part port carrier query
    host="${PUBLIC_HOST:-}"
    [[ -z "$host" ]] && host="$(detect_public_host)"
    if [[ -z "$host" ]]; then
        warn "未能确定公网地址，无法生成 Vector 连接串，可稍后通过菜单「5) 查看连接信息」重试"
        return 0
    fi
    host_part="$(format_host_for_url "$host")"
    carrier="$VECTOR_CARRIER"
    if [[ "$carrier" == "udp" ]]; then
        port="$(udp_port)"
    else
        port="$(tcp_port)"
        carrier="tcp"
    fi

    query="in=$(encode_socks "$VECTOR_SOCKS")&morph=${MORPH}"
    local trust_query
    if trust_query="$(append_trust_params "$query")"; then
        query="$trust_query"
    else
        warn "未能获取自签证书指纹，Vector 连接串暂缺 pin=（服务启动后可用菜单 5 重新生成）"
    fi
    VECTOR_URL="vector://${SHARED_KEY}@${host_part}/${carrier}:${port}?${query}"
}

# 远程 Egress 出口：egress://KEY@HOST/udp:PORT（仅 QUIC），在出口机上运行，无需其开放入站端口
build_egress_info() {
    EGRESS_URL=""
    [ "$GENERATE_EGRESS" != "1" ] && return 0

    local host host_part port query
    host="${PUBLIC_HOST:-}"
    [[ -z "$host" ]] && host="$(detect_public_host)"
    if [[ -z "$host" ]]; then
        warn "未能确定公网地址，无法生成 Egress 连接串，可稍后通过菜单「5) 查看连接信息」重试"
        return 0
    fi
    host_part="$(format_host_for_url "$host")"
    port="$(udp_port)"

    query="morph=${MORPH}"
    local trust_query
    if trust_query="$(append_trust_params "$query")"; then
        query="$trust_query"
    else
        warn "未能获取自签证书指纹，Egress 连接串暂缺 pin=（服务启动后可用菜单 5 重新生成）"
    fi
    EGRESS_URL="egress://${SHARED_KEY}@${host_part}/udp:${port}?${query}"
}

# 供 probe 使用的 Vector URL（不需要 in=）
build_probe_vector_url() {
    local host host_part port carrier query
    host="${PUBLIC_HOST:-}"
    [[ -z "$host" ]] && host="$(detect_public_host)"
    host_part="$(format_host_for_url "$host")"
    carrier="${VECTOR_CARRIER:-tcp}"
    if [[ "$carrier" == "udp" ]] && has_udp; then
        port="$(udp_port)"
    else
        carrier="tcp"
        port="$(tcp_port)"
    fi
    query="morph=${MORPH}"
    local trust_query
    if trust_query="$(append_trust_params "$query")"; then
        query="$trust_query"
    fi
    printf 'vector://%s@%s/%s:%s?%s' "$SHARED_KEY" "$host_part" "$carrier" "$port" "$query"
}

# 纯获取指纹（64 位小写 hex，无冒号），不打印不警告，供 pin= 拼接用
# 优先用官方 nowhere fingerprint（自动处理 Morph），回退 openssl s_client
get_tls_fingerprint() {
    [[ "$TLS_MODE" != "1" ]] && return 1
    if ! has_tcp; then
        # fingerprint 只能走 TCP/TLS：纯 UDP Portal 没有 TLS 监听，取不到指纹
        return 1
    fi
    local port
    port="$(tcp_port)"
    if [ -x "$BIN_PATH" ]; then
        local out fp
        out="$(timeout 8 "$BIN_PATH" fingerprint "nowhere://${SHARED_KEY}@127.0.0.1:${port}?morph=${MORPH}" 2>/dev/null || true)"
        fp="$(echo "$out" | grep -oE '[0-9a-f]{64}' | head -1 || true)"
        if [ -n "$fp" ]; then
            echo "$fp"
            return 0
        fi
    fi
    local sni="${PUBLIC_HOST:-localhost}"
    local fingerprint output
    for _ in 1 2 3 4 5; do
        output="$(timeout 8 openssl s_client -connect "127.0.0.1:${port}" \
            -servername "$sni" -showcerts </dev/null 2>/dev/null \
            | openssl x509 -noout -fingerprint -sha256 2>/dev/null || true)"
        fingerprint="${output#*=}"
        if [[ -n "$fingerprint" && "$fingerprint" != "$output" ]]; then
            echo "$fingerprint" | tr -d ':' | tr 'A-F' 'a-f'
            return 0
        fi
        sleep 1
    done
    return 1
}

print_tls_fingerprint() {
    if [[ "$TLS_MODE" != "1" ]]; then
        return 0
    fi
    if ! has_tcp; then
        warn "当前为纯 QUIC/UDP Portal，没有 TLS 监听，无法用 fingerprint 读取指纹"
        warn "自签模式下 Vector/Egress 的 pin 请从 Portal 启动日志的 'tls certificate fingerprint:' 一行获取"
        return 0
    fi
    echo
    info "正在获取自签证书 SHA-256 指纹..."
    local fingerprint
    fingerprint="$(get_tls_fingerprint || true)"
    if [ -n "$fingerprint" ]; then
        echo -e "  ${GREEN}${fingerprint}${NC}"
        warn "tls=1 证书只存在内存中，Nowhere 每次重启后指纹都会变化，pin= 需同步重新生成（菜单 5 或 pz 命令）"
    else
        warn "暂未获取到指纹，可稍后运行: journalctl -u nowhere -n 100 | grep fingerprint"
    fi
}

ensure_ipv4_preference() {
    local has_ipv6_addr=false
    if ip -6 addr show scope global 2>/dev/null | grep -q "inet6"; then
        has_ipv6_addr=true
    fi

    [ "$has_ipv6_addr" = false ] && return 0

    info "检测到本机配置了 IPv6 地址，测试实际是否能连通外网..."
    if curl -6 -fsS --max-time 5 https://www.cloudflare.com >/dev/null 2>&1; then
        success "IPv6 连通性正常，无需调整"
        return 0
    fi

    warn "IPv6 地址已配置，但实际无法连通外网（VPS常见问题：分配了地址却未正确路由）"
    warn "这会导致 curl/certbot 优先尝试 IPv6 而报错 'Network is unreachable'"

    if ! grep -q "^precedence ::ffff:0:0/96" /etc/gai.conf 2>/dev/null; then
        info "写入 /etc/gai.conf，让系统优先选用 IPv4（不关闭IPv6，只调整地址选择优先级）"
        [ -n "$(tail -c 1 /etc/gai.conf 2>/dev/null)" ] && echo >> /etc/gai.conf
        echo "precedence ::ffff:0:0/96  100" >> /etc/gai.conf
    fi

    if curl -fsS --max-time 5 https://acme-v02.api.letsencrypt.org/directory >/dev/null 2>&1; then
        success "已修正为 IPv4 优先，现在可以正常连接 Let's Encrypt"
    else
        warn "调整后仍无法连接，请检查 VPS 出网本身是否正常: ping -c 3 8.8.8.8"
    fi
}

install_shortcuts() {
    step "安装快捷命令"
    divider
    local self_path
    self_path="$(readlink -f "$0" 2>/dev/null || true)"

    if [ -z "$self_path" ] || [ ! -f "$self_path" ]; then
        warn "无法定位脚本自身文件路径（可能是通过管道 bash <(curl ...) 运行）"
        warn "这种一次性管道运行方式下，脚本内容来自匿名管道，读取一次即耗尽，无法复制自身"
        warn "快捷命令需要脚本先以文件形式保存到磁盘再运行，例如："
        warn "  curl -fsSL <脚本地址> -o ${MANAGER_PATH} && chmod +x ${MANAGER_PATH} && ${MANAGER_PATH}"
        return 1
    fi

    if [ "$self_path" != "$MANAGER_PATH" ]; then
        cp "$self_path" "$MANAGER_PATH"
    fi
    chmod +x "$MANAGER_PATH"

    cat > /usr/local/bin/adam << SHORTEOF
#!/bin/bash
exec "${MANAGER_PATH}" "\$@"
SHORTEOF
    chmod +x /usr/local/bin/adam

    cat > /usr/local/bin/zt << SHORTEOF
#!/bin/bash
exec "${MANAGER_PATH}" status
SHORTEOF
    chmod +x /usr/local/bin/zt

    cat > /usr/local/bin/pz << SHORTEOF
#!/bin/bash
exec "${MANAGER_PATH}" config
SHORTEOF
    chmod +x /usr/local/bin/pz

    cat > /usr/local/bin/cxpz << SHORTEOF
#!/bin/bash
exec "${MANAGER_PATH}" reconfig
SHORTEOF
    chmod +x /usr/local/bin/cxpz

    cat > /usr/local/bin/cq << SHORTEOF
#!/bin/bash
exec "${MANAGER_PATH}" restart
SHORTEOF
    chmod +x /usr/local/bin/cq

    success "快捷命令已安装完成"
    echo -e "  ${CYAN}adam${NC}   — 打开管理菜单"
    echo -e "  ${CYAN}zt${NC}     — 查看服务状态"
    echo -e "  ${CYAN}pz${NC}     — 查看节点/连接信息"
    echo -e "  ${CYAN}cxpz${NC}   — 重新修改配置"
    echo -e "  ${CYAN}cq${NC}     — 快速重启服务"
}

# ── 证书申请与自动续期（v2 新增/重构） ──────────────────────────

# 证书有效性：文件存在、私钥匹配、SAN/CN 含域名、剩余有效期 > 30 天
cert_is_valid() {
    local domain="$1" crt="$2" key="$3"
    [ -n "$domain" ] && [ -f "$crt" ] && [ -f "$key" ] || return 1
    openssl x509 -in "$crt" -noout -checkend 2592000 >/dev/null 2>&1 || return 1
    openssl x509 -in "$crt" -noout -pubkey 2>/dev/null | \
        cmp -s - <(openssl pkey -in "$key" -pubout 2>/dev/null) || return 1
    openssl x509 -in "$crt" -noout -ext subjectAltName 2>/dev/null | grep -q "DNS:${domain}" && return 0
    openssl x509 -in "$crt" -noout -subject 2>/dev/null | grep -q "CN *= *${domain}" && return 0
    return 1
}

# 证书剩余有效天数（整数）；取不到返回非 0
cert_expiry_days() {
    local crt="$1" end_s now_s
    end_s="$(date -d "$(openssl x509 -in "$crt" -noout -enddate 2>/dev/null | cut -d= -f2-)" +%s 2>/dev/null)" || return 1
    [ -n "$end_s" ] || return 1
    now_s="$(date +%s)"
    echo $(( (end_s - now_s) / 86400 ))
}

# 签发后校验：文件存在、未过期、私钥匹配、SAN 含域名
verify_issued_cert() {
    local domain="$1" crt="$2" key="$3" days
    [ -f "$crt" ] && [ -f "$key" ] || { warn "证书文件未生成：${crt}"; return 1; }
    openssl x509 -in "$crt" -noout -checkend 0 >/dev/null 2>&1 || { warn "证书已过期或无法解析"; return 1; }
    if ! openssl x509 -in "$crt" -noout -pubkey 2>/dev/null | \
            cmp -s - <(openssl pkey -in "$key" -pubout 2>/dev/null); then
        warn "证书与私钥不匹配"
        return 1
    fi
    if ! openssl x509 -in "$crt" -noout -ext subjectAltName 2>/dev/null | grep -q "DNS:${domain}"; then
        warn "证书 SAN 中不包含域名 ${domain}（可能签发了错误的域名）"
        openssl x509 -in "$crt" -noout -ext subjectAltName 2>/dev/null || true
        return 1
    fi
    days="$(cert_expiry_days "$crt" || echo "?")"
    success "证书校验通过：${domain}，剩余有效期约 ${days} 天"
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
        warn "域名 ${domain} 当前解析不到任何 A 记录（DNS 未生效或拼写错误），HTTP-01 很可能失败"
        return 1
    fi
    if [ -n "$myip" ] && [ "$resolved" != "$myip" ]; then
        warn "域名 ${domain} 解析到 ${resolved}，但本机公网 IP 疑似 ${myip}：两者不一致时 HTTP-01 会失败"
        warn "若刚修改 DNS，请确认已传播：dig +short ${domain}（或等待 10-30 分钟后重试）"
        return 1
    fi
    success "DNS 预检通过：${domain} -> ${resolved}"
    return 0
}

# 发布包 SHA256 机会性校验：仓库若提供校验文件则必校验通过，否则告警跳过（不阻断）
verify_release_checksum() {
    local tag="$1" workdir="$2" sumfile url entry
    for sumfile in "SHA256SUMS" "sha256sums.txt" "checksums.txt"; do
        url="https://github.com/${REPO}/releases/download/${tag}/${sumfile}"
        curl -fsSL --max-time 15 -o "${workdir}/${sumfile}" "$url" 2>/dev/null || continue
        entry="$(grep "nowhere-${ARCH_NAME}-unknown-linux-${LIBC}.tar.gz" "${workdir}/${sumfile}" | head -1 || true)"
        if [ -z "$entry" ]; then
            warn "校验文件 ${sumfile} 中没有本架构条目，跳过校验"
            return 0
        fi
        info "正在用 ${sumfile} 校验安装包..."
        if echo "$entry" | (cd "$workdir" && sha256sum -c - >/dev/null 2>&1); then
            success "SHA256 校验通过"
            return 0
        else
            warn "SHA256 校验失败：安装包可能被篡改或下载损坏"
            return 1
        fi
    done
    warn "该版本未提供可识别的校验文件，跳过校验（本次经 HTTPS 直连 GitHub 下载）"
    return 0
}

# certbot 续期链路：deploy hook + 确保 timer 生效（缺失时 cron 兜底）+ 可选 dry-run 演练
setup_certbot_renewal() {
    mkdir -p /etc/letsencrypt/renewal-hooks/deploy
    cat > /etc/letsencrypt/renewal-hooks/deploy/restart-nowhere.sh << 'HOOKEOF'
#!/bin/bash
# certbot 续期成功后自动重启 nowhere，使新证书生效
systemctl restart nowhere
HOOKEOF
    chmod +x /etc/letsencrypt/renewal-hooks/deploy/restart-nowhere.sh
    info "已安装续期 hook：证书更新后自动 restart nowhere"

    if systemctl list-unit-files 2>/dev/null | grep -q '^certbot\.timer'; then
        systemctl enable --now certbot.timer 2>/dev/null || warn "certbot.timer 启用失败，请手动执行：systemctl enable --now certbot.timer"
        if systemctl is-active --quiet certbot.timer 2>/dev/null; then
            success "自动续期已就绪：certbot.timer 运行中（每天两次检查续期）"
        else
            warn "certbot.timer 未在运行，自动续期可能不工作，请手动检查"
        fi
    else
        warn "未找到 certbot.timer，改用 cron 兜底（每天 3:00 / 15:00 检查续期）"
        (crontab -l 2>/dev/null | grep -v 'certbot renew' || true; \
         echo '0 3,15 * * * certbot renew --quiet --deploy-hook "systemctl restart nowhere"') | crontab -
        success "cron 续期任务已写入"
    fi

    echo ""
    read -p "是否立即做一次续期演练（certbot renew --dry-run，不消耗 LE 配额）？[Y/n]: " DRYRUN
    if [[ ! "${DRYRUN:-y}" =~ ^[Nn]$ ]]; then
        info "演练中（约需 30-90 秒）..."
        if certbot renew --dry-run 2>&1 | tail -5; then
            success "续期演练通过，自动续期链路可信"
        else
            warn "续期演练未通过：请根据上方报错排查（如 80 端口被占、DNS 凭证失效），否则证书到期后服务会中断"
        fi
    else
        warn "已跳过演练：建议 90 天内用菜单「16) 检查证书状态 / 手动续期」验证一次"
    fi
}

# acme.sh 续期链路：确认其自带的 cron 定时任务已就绪
setup_acmesh_renewal() {
    if crontab -l 2>/dev/null | grep -q 'acme.sh.*--cron'; then
        success "自动续期已就绪：acme.sh 的 cron 定时任务存在（每天检查，到期自动续签并执行 --reloadcmd 重启 nowhere）"
    else
        warn "未在 root 的 crontab 中找到 acme.sh 定时任务，自动续期可能不工作"
        warn "可手动补加：(crontab -l 2>/dev/null; echo '0 0 * * * \"${ACME_HOME}/acme.sh\" --cron --home \"${ACME_HOME}\"') | crontab -"
    fi
    info "当前该域名的证书状态："
    "${ACME_HOME}/acme.sh" --list 2>/dev/null | grep -E "Main_Domain|${DOMAIN}" || true
}

show_menu() {
    clear
    echo -e "${BOLD}${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║         Adam Nowhere Portal 一键管理脚本                     ║"
    echo "║         已适配 v3.0.0 / NW3 · Portal + Vector + Egress       ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "  ${BOLD}1)${NC} 安装 Nowhere（向导）"
    echo -e "  ${BOLD}2)${NC} 卸载 Nowhere"
    echo -e "  ${BOLD}3)${NC} 更新 Nowhere 二进制（更新到最新版）"
    echo -e "  ${BOLD}4)${NC} 重新配置（修改参数）"
    echo -e "  ${BOLD}5)${NC} 查看连接信息 / 导入链接"
    echo -e "  ${BOLD}6)${NC} 查看服务状态（含 nowhere status）"
    echo -e "  ${BOLD}7)${NC} 查看实时日志"
    echo -e "  ${BOLD}8)${NC} 查看自签证书指纹（tls=1）"
    echo -e "  ${BOLD}9)${NC} 重启服务"
    echo -e "  ${BOLD}10)${NC} 重装快捷命令（adam/zt/pz/cxpz/cq）"
    echo -e "  ${BOLD}11)${NC} 查看当前版本 / 检查更新"
    echo -e "  ${BOLD}12)${NC} 选择指定版本（版本切换/回退到历史版本）"
    echo -e "  ${BOLD}13)${NC} 快速回退到上一个版本"
    echo -e "  ${BOLD}14)${NC} 生成 v3 共享密钥（32 位十六进制）"
    echo -e "  ${BOLD}15)${NC} 连通性探测 probe（真实 TCP Flow 测试）"
    echo -e "  ${BOLD}16)${NC} 检查证书状态 / 手动续期"
    echo -e "  ${BOLD}0)${NC} 退出"
    divider
    if [ -x /usr/local/bin/adam ]; then
        echo -e "  ${YELLOW}提示：可直接输入${NC} ${CYAN}adam${NC} ${YELLOW}唤出此菜单，或用${NC} ${CYAN}zt${NC}/${CYAN}pz${NC}/${CYAN}cxpz${NC}/${CYAN}cq${NC} ${YELLOW}快捷执行${NC}"
        divider
    fi
    read -p "请选择操作 [0-16]: " MENU_CHOICE
}

do_install() {
    step "第 1 步：选择证书获取方式"
    divider
    echo -e "${BOLD}TLS 证书方式：${NC}"
    echo "  1) 自签证书 tls=1  - 无需域名，快速测试（Vector/Egress 必须用 pin= 锁定指纹，指纹随重启变化）"
    echo "  2) Let's Encrypt HTTP-01 - 需要开放 80 端口（自动续期）"
    echo "  3) Let's Encrypt DNS-01 通用 - 支持多种 DNS 服务商（自动续期）"
    echo "  4) Cloudflare DNS-01 - 需要 CF API Key（自动续期，推荐）"
    read -p "请选择 [1/2/3/4，默认4]: " CERT_CHOICE
    CERT_CHOICE=${CERT_CHOICE:-4}

    case $CERT_CHOICE in
        1) TLS_MODE=1; CERT_METHOD="self-signed" ;;
        2) TLS_MODE=2; CERT_METHOD="letsencrypt-http" ;;
        3) TLS_MODE=2; CERT_METHOD="letsencrypt-dns" ;;
        4) TLS_MODE=2; CERT_METHOD="cloudflare-dns" ;;
        *) TLS_MODE=2; CERT_METHOD="cloudflare-dns" ;;
    esac

    if [ "$TLS_MODE" = "1" ]; then
        warn "提醒（v3 官方说明）：Vector/Egress 默认校验系统 CA + 主机名，自签证书必须改用 pin= 指纹锁定"
        warn "自签证书仅建议测试用，生产环境请用真实域名 + CA 签发证书（选 2/3/4）"
    fi

    step "第 2 步：基础网络信息"
    divider

    if [ "$TLS_MODE" = "2" ]; then
        while true; do
            read -p "请输入域名（如: nhk.example.com）: " DOMAIN
            DOMAIN=$(echo "$DOMAIN" | tr -d ' \r\n')
            [[ -z "$DOMAIN" ]] && { echo -e "${RED}域名不能为空${NC}"; continue; }
            [[ "$DOMAIN" != *.* ]] && { echo -e "${RED}域名格式不正确${NC}"; continue; }
            break
        done
        PUBLIC_HOST="$DOMAIN"
    else
        info "自签模式无需域名，将自动探测公网 IP 作为客户端连接地址"
        DETECTED_IP="$(detect_public_host)"
        read -p "公网 IP/域名（用于 Anywhere/Vector/Egress 连接，回车使用探测值 ${DETECTED_IP}）: " PUBLIC_HOST
        PUBLIC_HOST=${PUBLIC_HOST:-$DETECTED_IP}
        DOMAIN="$PUBLIC_HOST"
    fi

    while true; do
        read -p "请输入邮箱（用于证书申请/找回）: " EMAIL
        EMAIL=$(echo "$EMAIL" | tr -d ' \r\n')
        [[ "$EMAIL" != *@*.* ]] && { echo -e "${RED}邮箱格式不正确${NC}"; continue; }
        break
    done

    if [ "$CERT_METHOD" = "cloudflare-dns" ]; then
        echo ""
        echo -e "${BOLD}Cloudflare 认证方式：${NC}"
        echo "  1) Global API Key"
        echo "  2) API Token"
        read -p "选择 [1/2，默认1]: " CF_AUTH_TYPE
        CF_AUTH_TYPE=${CF_AUTH_TYPE:-1}
        if [ "$CF_AUTH_TYPE" = "1" ]; then
            read -p "Cloudflare Email: " CF_EMAIL
            read -p "Cloudflare Global API Key: " CF_API_KEY
        else
            read -p "Cloudflare API Token: " CF_TOKEN
        fi
    elif [ "$CERT_METHOD" = "letsencrypt-dns" ]; then
        echo ""
        echo -e "${BOLD}DNS 服务商：${NC}"
        echo "  1) Cloudflare  2) DNSPod  3) 阿里云  4) 其他/手动"
        read -p "选择 [1-4，默认1]: " DNS_PROVIDER
        DNS_PROVIDER=${DNS_PROVIDER:-1}
        case $DNS_PROVIDER in
            1) read -p "Cloudflare Email: " CF_EMAIL
               read -p "Cloudflare API Key: " CF_API_KEY
               export CF_Email="${CF_EMAIL}" CF_Key="${CF_API_KEY}"
               DNS_API="dns_cf" ;;
            2) read -p "DNSPod ID: " DNSPOD_ID
               read -p "DNSPod Token: " DNSPOD_TOKEN
               export DP_Id="${DNSPOD_ID}" DP_Key="${DNSPOD_TOKEN}"
               DNS_API="dns_dp" ;;
            3) read -p "阿里云 AccessKey ID: " ALI_ID
               read -p "阿里云 AccessKey Secret: " ALI_SECRET
               export Ali_Key="${ALI_ID}" Ali_Secret="${ALI_SECRET}"
               DNS_API="dns_ali" ;;
            *) warn "「其他/手动」需要交互式完成 DNS TXT 验证，本脚本暂不接管，请改选 1-3"; DNS_API="unsupported" ;;
        esac
    fi

    step "第 3 步：监听参数"
    divider
    echo -e "${BOLD}端口模式（v3 端点路径语法）：${NC}"
    echo "  1) TLS 与 QUIC 共用同一端口，如 *:443（推荐）"
    echo "  2) TLS 与 QUIC 分开端口，如 */tcp:2000/udp:2001"
    read -p "选择 [1/2，默认1]: " PORT_MODE_CHOICE
    case ${PORT_MODE_CHOICE:-1} in
        2) PORT_MODE="split" ;;
        *) PORT_MODE="same" ;;
    esac

    if [ "$PORT_MODE" = "split" ]; then
        NET="mix"
        read -p "TLS/TCP 端口（回车默认2000）: " TCP_PORT
        TCP_PORT=${TCP_PORT:-2000}
        validate_port "$TCP_PORT" || { warn "端口不合法，重置为2000"; TCP_PORT=2000; }
        read -p "QUIC/UDP 端口（回车默认2001）: " UDP_PORT
        UDP_PORT=${UDP_PORT:-2001}
        validate_port "$UDP_PORT" || { warn "端口不合法，重置为2001"; UDP_PORT=2001; }
        if [ "$TCP_PORT" = "$UDP_PORT" ]; then
            warn "分端口模式下 TCP 与 UDP 端口不能相同，已将 UDP 端口改为 2001"
            UDP_PORT=2001
        fi
        PORT="$TCP_PORT"
    else
        read -p "监听端口（回车默认443）: " PORT
        PORT=${PORT:-443}
        validate_port "$PORT" || { warn "端口不合法，重置为443"; PORT=443; }
        TCP_PORT="$PORT"
        UDP_PORT="$PORT"

        echo ""
        echo -e "${BOLD}传输模式（决定端点路径，TCP 与 UDP 都能承载 TCP/UDP 业务流）：${NC}"
        echo "  1) mix - TLS/TCP + QUIC/UDP 双栈（HOST:PORT，推荐）"
        echo "  2) tcp - 仅 TLS/TCP（HOST/tcp:PORT）"
        echo "  3) udp - 仅 QUIC/UDP（HOST/udp:PORT）"
        read -p "选择 [1/2/3，默认1]: " NET_CHOICE
        case ${NET_CHOICE:-1} in
            1) NET="mix" ;; 2) NET="tcp" ;; 3) NET="udp" ;; *) NET="mix" ;;
        esac
    fi

    read -p "监听地址（回车= * 通配，全监听；也可填具体 IP）: " LISTEN_HOST
    LISTEN_HOST=${LISTEN_HOST:-}
    [[ "$LISTEN_HOST" == "*" ]] && LISTEN_HOST="*"

    step "第 4 步：协议与安全参数"
    divider

    # v3 密钥必须是恰好 32 位小写十六进制，旧任意字符串密钥会被直接拒绝
    while true; do
        read -p "共享密钥 Shared Key（回车自动生成 32 位十六进制）: " SHARED_KEY
        if [ -z "$SHARED_KEY" ]; then
            SHARED_KEY="$(gen_key)"
            info "已生成密钥: ${SHARED_KEY}"
            break
        fi
        if is_valid_key "$SHARED_KEY"; then
            break
        fi
        warn "该密钥不符合 v3 规范：必须是恰好 32 位小写十六进制字符（0-9a-f）"
        warn "旧版任意字符串/Base64 密钥在 v3 会被拒绝启动，请重新输入或直接回车自动生成"
    done

    echo ""
    echo -e "${BOLD}Morph 流量乱形${NC}（${YELLOW}v3 默认开启 morph=1；仅做流量形态混淆，不提供额外加密；两端必须一致，没有协商/回退${NC}）："
    read -p "是否开启 [Y/n]: " MORPH_CHOICE
    if [[ "$MORPH_CHOICE" =~ ^[Nn]$ ]]; then MORPH="0"; else MORPH="$DEFAULT_MORPH"; fi

    echo ""
    echo -e "${BOLD}Portal 出口 out=（Portal 固定出口，运行期间不可变）：${NC}"
    echo "  1) direct - Portal 直接访问目标（默认）"
    echo "  2) SOCKS5 上游 - 经一层 SOCKS5 代理出站（链式代理）"
    if has_udp; then
        echo "  3) egress - 远程 Egress 出口（目标解析/拨号在另一台主动回连的机器上，该机无需开放入站端口）"
        read -p "选择 [1/2/3，默认1]: " OUT_CHOICE
        case ${OUT_CHOICE:-1} in
            2) OUT_TYPE="socks" ;;
            3) OUT_TYPE="egress" ;;
            *) OUT_TYPE="direct" ;;
        esac
    else
        warn "当前为纯 TCP 模式，没有 QUIC 监听，out=egress 不可用（Egress 只能走 QUIC 注册）"
        read -p "选择 [1/2，默认1]: " OUT_CHOICE
        case ${OUT_CHOICE:-1} in
            2) OUT_TYPE="socks" ;;
            *) OUT_TYPE="direct" ;;
        esac
    fi

    SOCKS="none"
    if [ "$OUT_TYPE" = "socks" ]; then
        read -p "SOCKS5 地址，格式 host:port 或 user:pass@host:port: " SOCKS
        SOCKS=${SOCKS:-none}
        validate_socks "$SOCKS" || { warn "SOCKS5 格式不合法，已重置为 none 并改回 direct"; SOCKS="none"; OUT_TYPE="direct"; }
    fi

    DIAL_MODE="single"; DIAL="$DEFAULT_DIAL"; DIAL4="auto"; DIAL6="auto"
    if [ "$OUT_TYPE" = "egress" ]; then
        info "out=egress 时 Portal 不能再设置 dial/dial4/dial6（与官方约束一致），目标源地址请在 Egress 端配置"
    else
        echo ""
        read -p "出站源 IP dial（回车默认 auto；填 IP 会限定地址族，绑定失败不回退）: " DIAL
        DIAL=${DIAL:-$DEFAULT_DIAL}
        read -p "是否改用 dial4/dial6 分别绑定 IPv4/IPv6 源地址？[y/N]: " DIAL46_CHOICE
        if [[ "$DIAL46_CHOICE" =~ ^[Yy]$ ]]; then
            DIAL_MODE="dual"
            read -p "  dial4（IPv4 源地址，回车默认 auto）: " DIAL4
            DIAL4=${DIAL4:-auto}
            read -p "  dial6（IPv6 源地址，回车默认 auto）: " DIAL6
            DIAL6=${DIAL6:-auto}
            DIAL="auto"
        fi
    fi

    echo ""
    echo -e "${BOLD}限速设置（Portal/Vector/Egress 通用语义，0=不限速）：${NC}"
    read -p "上行限速 Mbps，Vector→目标（0=不限速）: " RATE
    RATE=${RATE:-0}
    validate_nonneg_int "$RATE" || { warn "输入不合法，重置为0"; RATE=0; }

    read -p "下行限速 Mbps，目标→Vector（0=不限速）: " ETAR
    ETAR=${ETAR:-0}
    validate_nonneg_int "$ETAR" || { warn "输入不合法，重置为0"; ETAR=0; }

    echo ""
    echo -e "${BOLD}本地 Vector 客户端连接信息${NC}（可选，在电脑/路由器上跑本地 SOCKS5 入口用 in=）："
    read -p "是否生成 Vector 连接信息？[Y/n]: " GEN_VECTOR
    GEN_VECTOR=${GEN_VECTOR:-y}
    if [[ "$GEN_VECTOR" =~ ^[Yy]$ ]]; then
        GENERATE_VECTOR="1"
        if has_tcp && has_udp; then
            echo "  Vector 载体（二选一，v3 一条连接只用一种载体）  1) tcp/TLS  2) udp/QUIC"
            read -p "  选择 [1/2，默认1]: " VCARRIER_CHOICE
            case ${VCARRIER_CHOICE:-1} in 2) VECTOR_CARRIER="udp" ;; *) VECTOR_CARRIER="tcp" ;; esac
        elif has_udp; then
            VECTOR_CARRIER="udp"
            info "  当前 Portal 仅 QUIC/UDP，Vector 载体自动选 udp"
        else
            VECTOR_CARRIER="tcp"
            info "  当前 Portal 仅 TLS/TCP，Vector 载体自动选 tcp"
        fi
        read -p "  本地 SOCKS5 监听 in=（回车默认 ${DEFAULT_VECTOR_SOCKS}，可带 user:pass@）: " VECTOR_SOCKS
        VECTOR_SOCKS=${VECTOR_SOCKS:-$DEFAULT_VECTOR_SOCKS}
    else
        GENERATE_VECTOR="0"
        VECTOR_CARRIER="tcp"; VECTOR_SOCKS="$DEFAULT_VECTOR_SOCKS"
    fi

    GENERATE_EGRESS="0"
    if [ "$OUT_TYPE" = "egress" ]; then
        echo ""
        echo -e "${BOLD}远程 Egress 出口机连接信息${NC}（在出口机上运行 egress:// 主动回连本 Portal）："
        read -p "是否生成 Egress 连接信息？[Y/n]: " GEN_EGRESS
        GEN_EGRESS=${GEN_EGRESS:-y}
        if [[ "$GEN_EGRESS" =~ ^[Yy]$ ]]; then
            GENERATE_EGRESS="1"
        fi
    fi

    echo ""
    divider
    echo -e "${BOLD}配置确认：${NC}"
    divider
    echo -e "  域名/主机     : ${GREEN}${DOMAIN}${NC}"
    echo -e "  公网地址      : ${GREEN}${PUBLIC_HOST}${NC}"
    echo -e "  邮箱          : ${GREEN}${EMAIL}${NC}"
    echo -e "  证书方式      : ${GREEN}${CERT_METHOD}${NC}"
    echo -e "  端口模式      : ${GREEN}${PORT_MODE}（TCP $(tcp_port) / UDP $(udp_port)）${NC}"
    echo -e "  监听地址      : ${GREEN}$([ -z "$LISTEN_HOST" ] && echo "*（通配）" || echo "$LISTEN_HOST")${NC}"
    echo -e "  传输模式      : ${GREEN}${NET}${NC}"
    echo -e "  Portal 端点   : ${GREEN}$(build_portal_endpoint)${NC}"
    echo -e "  共享密钥      : ${GREEN}$(mask_secret "$SHARED_KEY")（32 位十六进制）${NC}"
    echo -e "  Morph 乱形    : ${GREEN}$([ "$MORPH" = "1" ] && echo "开启 morph=1（默认）" || echo "关闭 morph=0")${NC}"
    echo -e "  Portal 出口   : ${GREEN}${OUT_TYPE}$([ "$OUT_TYPE" = "socks" ] && echo " ($(display_socks "$SOCKS"))")${NC}"
    if [ "$OUT_TYPE" != "egress" ]; then
        if [ "$DIAL_MODE" = "dual" ]; then
            echo -e "  出站源IP      : ${GREEN}dial4=${DIAL4} dial6=${DIAL6}${NC}"
        else
            echo -e "  出站源IP      : ${GREEN}dial=${DIAL}${NC}"
        fi
    fi
    echo -e "  上/下行限速   : ${GREEN}${RATE} / ${ETAR} Mbps${NC}"
    if [ "$GENERATE_VECTOR" = "1" ]; then
        echo -e "  Vector客户端  : ${GREEN}生成（carrier=${VECTOR_CARRIER} in=${VECTOR_SOCKS}）${NC}"
    fi
    if [ "$GENERATE_EGRESS" = "1" ]; then
        echo -e "  Egress出口机  : ${GREEN}生成（udp:$(udp_port)）${NC}"
    fi
    divider
    read -p "确认安装 [y/N]: " CONFIRM
    [[ ! "$CONFIRM" =~ ^[Yy]$ ]] && { info "已取消"; return; }

    CRT="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
    KEY_PEM="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"

    step "第 5 步：安装系统依赖"
    divider
    apt-get update -qq
    apt-get install -y -qq curl wget tar ufw socat openssl python3
    if [ "$TLS_MODE" = "2" ]; then
        apt-get install -y -qq certbot
        [ "$CERT_METHOD" = "cloudflare-dns" ] && apt-get install -y -qq python3-certbot-dns-cloudflare
    fi
    success "依赖安装完成"

    if [ "$TLS_MODE" = "2" ]; then
        ensure_ipv4_preference
        step "第 6 步：申请 TLS 证书"
        divider

        if [ "$CERT_METHOD" = "letsencrypt-http" ]; then
            # HTTP-01 前先做 DNS 预检：域名必须解析到本机，否则 certbot 必败
            check_domain_dns "$DOMAIN" || true
            if cert_is_valid "$DOMAIN" "$CRT" "$KEY_PEM"; then
                info "检测到有效证书（剩余 $(cert_expiry_days "$CRT") 天，域名匹配），跳过申请"
            else
                info "申请证书中（HTTP-01，需 80 端口）..."
                ufw allow 80/tcp 2>/dev/null || true
                certbot certonly \
                    --standalone \
                    --preferred-challenges http \
                    --non-interactive \
                    --agree-tos \
                    --email "${EMAIL}" \
                    -d "${DOMAIN}" \
                    --http-01-port 80 --http-01-address 0.0.0.0 || {
                    error "证书申请失败，请检查：1) 域名是否正确 2) 80 端口是否对外开放 3) 域名是否已指向本 VPS（见上方 DNS 预检结果）"
                }
                verify_issued_cert "$DOMAIN" "$CRT" "$KEY_PEM" || error "证书签发后校验未通过，请看上方告警"
                success "证书申请成功"
            fi
            setup_certbot_renewal

        elif [ "$CERT_METHOD" = "cloudflare-dns" ]; then
            mkdir -p /etc/cloudflare
            if [ "$CF_AUTH_TYPE" = "1" ]; then
                cat > /etc/cloudflare/credentials.ini << CFEOF
dns_cloudflare_email = ${CF_EMAIL}
dns_cloudflare_api_key = ${CF_API_KEY}
CFEOF
            else
                cat > /etc/cloudflare/credentials.ini << CFEOF
dns_cloudflare_api_token = ${CF_TOKEN}
CFEOF
            fi
            chmod 600 /etc/cloudflare/credentials.ini

            if cert_is_valid "$DOMAIN" "$CRT" "$KEY_PEM"; then
                info "检测到有效证书（剩余 $(cert_expiry_days "$CRT") 天，域名匹配），跳过申请"
            else
                info "申请证书中（Cloudflare DNS-01，约需 30-60 秒）..."
                certbot certonly \
                    --dns-cloudflare \
                    --dns-cloudflare-credentials /etc/cloudflare/credentials.ini \
                    --non-interactive \
                    --agree-tos \
                    --email "${EMAIL}" \
                    -d "${DOMAIN}" \
                    --dns-cloudflare-propagation-seconds 30 || {
                    error "证书申请失败，请检查：1) CF API Key/Token 是否正确 2) 域名是否在该 CF 账号下 3) Token 是否有 Zone:DNS:Edit 权限"
                }
                verify_issued_cert "$DOMAIN" "$CRT" "$KEY_PEM" || error "证书签发后校验未通过，请看上方告警"
                success "证书申请成功"
            fi
            setup_certbot_renewal

        elif [ "$CERT_METHOD" = "letsencrypt-dns" ]; then
            if [ "${DNS_API}" = "unsupported" ]; then
                error "您之前选择了「其他/手动」DNS 服务商：需先手动完成 DNS TXT 验证签发证书，本脚本无法一键接管。请重新运行并改选 Cloudflare（推荐）/ DNSPod / 阿里云"
            fi
            info "安装 acme.sh..."
            if ! curl -fsSL https://get.acme.sh | bash -s email="${EMAIL}"; then
                error "acme.sh 安装失败，请检查网络后重试"
            fi
            [ -x "${ACME_HOME}/acme.sh" ] || error "acme.sh 安装后仍找不到可执行文件（${ACME_HOME}/acme.sh）"
            . "${ACME_HOME}/acme.sh.env" 2>/dev/null || true

            if cert_is_valid "$DOMAIN" "$CRT" "$KEY_PEM"; then
                info "检测到有效证书（剩余 $(cert_expiry_days "$CRT") 天，域名匹配），跳过申请"
            else
                info "申请证书中（DNS-01: ${DNS_API}；不加 --force，避免重复签发触发 LE 频率限制）..."
                "${ACME_HOME}/acme.sh" --issue -d "${DOMAIN}" --dns "${DNS_API}" || {
                    error "证书签发失败：请检查 DNS API 凭证是否正确、域名 DNS 是否由所选服务商托管"
                }
                "${ACME_HOME}/acme.sh" --install-cert -d "${DOMAIN}" \
                    --key-file "${KEY_PEM}" \
                    --fullchain-file "${CRT}" \
                    --reloadcmd "systemctl restart nowhere" || {
                    error "证书安装（install-cert）失败"
                }
                verify_issued_cert "$DOMAIN" "$CRT" "$KEY_PEM" || error "证书签发后校验未通过，请看上方告警"
                success "证书申请成功"
            fi
            setup_acmesh_renewal
        fi

        info "证书路径: ${CRT}"
        info "私钥路径: ${KEY_PEM}"
    fi


    step "第 7 步：下载 Nowhere 二进制"
    divider
    detect_binary
    info "正在获取最新版本号..."
    LATEST=$(curl -s "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | cut -d'"' -f4 || true)
    [ -z "$LATEST" ] && error "无法获取版本号，请检查网络"
    LATEST_MAJOR="$(version_major "$LATEST")"
    if [ -n "$LATEST_MAJOR" ] && [ "$LATEST_MAJOR" -lt 3 ]; then
        error "当前最新版为 ${LATEST}，低于 v3.0.0，与本脚本的 NW3 配置不兼容，已中止（请检查仓库状态）"
    fi
    info "最新版本: ${LATEST} (${ARCH_NAME}-${LIBC})"
    local workdir_dl
    workdir_dl="$(mktemp -d /tmp/nowhere-dl.XXXXXX)"
    trap "rm -rf $workdir_dl" RETURN
    curl -fL --retry 3 --connect-timeout 10 \
        -o "$workdir_dl/nowhere.tar.gz" \
        "https://github.com/${REPO}/releases/download/${LATEST}/${BIN_NAME}" || error "下载失败"
    verify_release_checksum "$LATEST" "$workdir_dl" || error "安装包 SHA256 校验失败，已中止"
    tar -xzf "$workdir_dl/nowhere.tar.gz" -C "$workdir_dl/" || error "解压失败"
    BINARY_PATH=$(find "$workdir_dl" -type f -name nowhere -perm -u+x | head -1)
    [ -z "$BINARY_PATH" ] && BINARY_PATH=$(find "$workdir_dl" -type f -name nowhere | head -1)
    [ -z "$BINARY_PATH" ] && error "未找到 nowhere 二进制文件"
    install -m 755 "${BINARY_PATH}" "${BIN_PATH}"
    record_installed_version "$LATEST"
    success "Nowhere $(${BIN_PATH} --version 2>&1 | head -1) 安装完成"

    step "第 8 步：保存配置"
    divider
    install -d -m 700 "$CONFIG_DIR"
    NOWHERE_PORTAL="$(build_portal_url)"
    cat > "$CONFIG_FILE" << ENVEOF
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
OUT_TYPE_VALUE="${OUT_TYPE}"
SOCKS_VALUE="${SOCKS}"
DIAL_MODE_VALUE="${DIAL_MODE}"
DIAL_VALUE="${DIAL}"
DIAL4_VALUE="${DIAL4}"
DIAL6_VALUE="${DIAL6}"
RATE_VALUE="${RATE}"
ETAR_VALUE="${ETAR}"
MORPH_VALUE="${MORPH}"
GENERATE_VECTOR_VALUE="${GENERATE_VECTOR}"
VECTOR_CARRIER_VALUE="${VECTOR_CARRIER}"
VECTOR_SOCKS_VALUE="${VECTOR_SOCKS}"
GENERATE_EGRESS_VALUE="${GENERATE_EGRESS}"
ENVEOF
    chmod 600 "$CONFIG_FILE"
    success "配置已保存至 ${CONFIG_FILE}"

    step "第 9 步：安装前端口占用检测"
    divider
    EXISTING_PROC=""
    if command -v ss >/dev/null 2>&1; then
        if has_tcp; then
            EXISTING_PROC="$(ss -tlnp 2>/dev/null | grep -E ":$(tcp_port)\b" || true)"
        fi
        if [ -z "$EXISTING_PROC" ] && has_udp; then
            EXISTING_PROC="$(ss -ulnp 2>/dev/null | grep -E ":$(udp_port)\b" || true)"
        fi
    fi
    if [ -n "$EXISTING_PROC" ]; then
        warn "检测到目标端口已被其他进程占用："
        echo "$EXISTING_PROC"
        warn "如果这不是本次要替换的旧 Nowhere 实例，请先停止占用该端口的服务，否则新服务会反复崩溃重启，客户端表现为一直 timeout"
        read -p "仍要继续安装吗？[y/N]: " PORT_CONFIRM
        [[ ! "$PORT_CONFIRM" =~ ^[Yy]$ ]] && { info "已取消安装"; return; }
    else
        success "目标端口空闲，可以使用"
    fi

    step "第 10 步：配置防火墙（先于服务启动，避免中间态连不通）"
    divider
    ufw allow ssh 2>/dev/null || true
    if has_tcp; then ufw allow "$(tcp_port)/tcp" 2>/dev/null || true; fi
    if has_udp; then ufw allow "$(udp_port)/udp" 2>/dev/null || true; fi
    [ "$CERT_METHOD" = "letsencrypt-http" ] && ufw allow 80/tcp 2>/dev/null || true
    ufw --force enable
    success "防火墙已配置"

    step "第 11 步：创建并启动系统服务"
    divider
    # 注意：PrivateTmp 必须关闭。v3 的 nowhere status 靠系统临时目录下的
    # 受保护 IPC 注册表发现实例，PrivateTmp 会让服务与外部命令看到不同的 /tmp，
    # 导致 status 永远发现不到本服务（实测会报 namespace identity unavailable 一类问题时更难排查）
    cat > "$SERVICE_FILE" << SVCEOF
[Unit]
Description=Nowhere Portal
Documentation=https://github.com/${REPO}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=${CONFIG_FILE}
ExecStart=${BIN_PATH} \${NOWHERE_PORTAL}
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
NoNewPrivileges=true
PrivateTmp=false
ProtectSystem=full
ProtectHome=read-only
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
SVCEOF

    systemctl daemon-reload
    systemctl enable nowhere
    systemctl restart nowhere
    sleep 3

    LISTENING=""
    if command -v ss >/dev/null 2>&1; then
        LISTENING="$(ss -tlnp 2>/dev/null | grep nowhere || true)"
        [ -z "$LISTENING" ] && LISTENING="$(ss -ulnp 2>/dev/null | grep nowhere || true)"
    fi

    if systemctl is-active --quiet nowhere && [ -n "$LISTENING" ]; then
        success "服务启动成功，且已确认端口正在监听"
    elif systemctl is-active --quiet nowhere && [ -z "$LISTENING" ]; then
        warn "systemd 显示服务 active，但未检测到端口实际在监听"
        warn "常见原因：证书路径错误、端口被抢占、密钥格式不合 v3 规范（必须 32 位小写十六进制）"
        journalctl -u nowhere -n 30 --no-pager
        warn "服务处于不确定状态，建议排查后再连接客户端，否则会一直 timeout"
    else
        warn "服务未能启动，查看日志排查："
        journalctl -u nowhere -n 30 --no-pager
        error "安装中止"
    fi

    step "第 12 步：生成连接信息"
    divider
    build_client_links
    build_vector_info
    build_egress_info
    print_all_info

    step "第 13 步：安装快捷命令"
    divider
    install_shortcuts || true
}

print_all_info() {
    local udp_section="" tcp_section="" vector_section="" egress_section=""

    if [[ -n "$UDP_LINK" ]]; then
        udp_section="
【Anywhere 分享链接 —— QUIC/UDP（net=udp）】
链接：
${UDP_LINK}

一键导入深链（手机点击，需 Anywhere 已支持 NW3）：
${IMPORT_UDP}
"
    fi

    if [[ -n "$TCP_LINK" ]]; then
        tcp_section="
【Anywhere 分享链接 —— TLS/TCP（net=tcp，默认）】
链接：
${TCP_LINK}

一键导入深链（手机点击，需 Anywhere 已支持 NW3）：
${IMPORT_TCP}
"
    fi

    if [ "$GENERATE_VECTOR" = "1" ]; then
        if [[ -n "$VECTOR_URL" ]]; then
            vector_section="
【本地 Vector 客户端 —— 在电脑/路由器上跑本地 SOCKS5 入口】
载体: ${VECTOR_CARRIER}  本地监听 in=${VECTOR_SOCKS}
连接串：
${VECTOR_URL}

启动命令：
nowhere '${VECTOR_URL}'
$([ "$TLS_MODE" = "1" ] && echo "
※ 用的是 pin=证书指纹 锁定方式，Portal 每次重启该指纹都会变，重启后需要重新生成本连接串（菜单 5 或 pz 命令）")
"
        else
            vector_section="
【本地 Vector 客户端】
生成失败：未能获取到有效的连接参数，可稍后通过菜单「5) 查看连接信息」重试
"
        fi
    fi

    if [ "$GENERATE_EGRESS" = "1" ]; then
        if [[ -n "$EGRESS_URL" ]]; then
            egress_section="
【远程 Egress 出口机 —— 在出口机上运行，主动回连本 Portal，无需出口机开放入站端口】
连接串：
${EGRESS_URL}

出口机启动命令：
nowhere '${EGRESS_URL}'
※ 本 Portal 已固定 out=egress：Egress 离线时新连接会立即失败，不会回退直连；每台 Portal 只接受一个 Egress 注册
$([ "$TLS_MODE" = "1" ] && echo "※ 同 Vector，pin= 指纹随 Portal 重启变化，重启后需同步更新出口机连接串")
"
        else
            egress_section="
【远程 Egress 出口机】
生成失败：未能获取到有效的连接参数，可稍后通过菜单「5) 查看连接信息」重试
"
        fi
    fi

    cat > "${CONFIG_DIR}/config.txt" << CONFEOF
════════════════════════════════════════════════════════════════
  Nowhere Portal 连接信息（v3.0.0 / NW3）
  更新时间: $(date '+%Y-%m-%d %H:%M:%S')
════════════════════════════════════════════════════════════════

【服务端启动参数（Portal URL，用于 systemd ExecStart）】
${NOWHERE_PORTAL}
※ v3 的 alpn/net/log/pool/up/down/socks(Vector旧名) 等旧参数均已移除或改名，
  未知参数会被静默忽略，千万不要再往启动串里手动拼旧参数。

【客户端连接参数】
  域名/公网地址 : ${PUBLIC_HOST}
  TCP 端口      : $(tcp_port)
  UDP 端口      : $(udp_port)
  共享密钥      : ${SHARED_KEY}（32 位小写十六进制，两端必须完全一致）
  传输模式      : ${NET}（端口模式 ${PORT_MODE}）
  Morph 乱形    : $([ "$MORPH" = "1" ] && echo "开启 morph=1（v3 默认，客户端必须同步开启）" || echo "关闭 morph=0（客户端必须同步关闭）")
  TLS           : $([ "$TLS_MODE" = "1" ] && echo "自签证书(tls=1，靠 pin= 指纹锁定)" || echo "真实证书(tls=2，系统 CA + 主机名校验)")
  Portal 出口   : ${OUT_TYPE}
${udp_section}${tcp_section}${vector_section}${egress_section}
【Anywhere 手动填写】
  服务器 : ${PUBLIC_HOST}
  端口   : $(if has_tcp; then tcp_port; else udp_port; fi)
  密钥   : ${SHARED_KEY}
  TLS    : 开启
  ALPN   : nw3（v3 固定，不可改，App 内无需/无法填写 alpn 时忽略此项）
  Morph  : ${MORPH}（务必和服务端保持一致）

【防火墙提醒】
$(if has_tcp && has_udp; then echo "  需放行: TCP $(tcp_port) 和 UDP $(udp_port)"; elif has_tcp; then echo "  需放行: TCP $(tcp_port)"; else echo "  需放行: UDP $(udp_port)"; fi)
$([ "$TLS_MODE" = "1" ] && echo "
【TLS 提示】
  tls=1 为临时自签证书，每次重启指纹会变化，仅建议测试用
  v3 客户端默认校验系统 CA 与主机名，自签场景必须用 pin= 锁定指纹")

【版本兼容提醒】
  本配置为 NW3 协议：v1/v2 的 Portal/Vector 以及未支持 NW3 的
  Anywhere/第三方客户端无法与本服务端互通，升级需整条链路一起升。
  分享链接与 anywhere:// 深链格式已按 v3 文档更新，但能否导入成功
  取决于你手机上的 Anywhere 版本是否已支持 NW3，请以实测为准。
════════════════════════════════════════════════════════════════
CONFEOF
    chmod 600 "${CONFIG_DIR}/config.txt"

    echo ""
    echo -e "${BOLD}${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║              ✅  操作完成！                                  ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    cat "${CONFIG_DIR}/config.txt"
    echo ""
    if [[ -n "$IMPORT_UDP" ]]; then
        echo -e "${BOLD}✅ 最快导入方式（QUIC/UDP）：${NC}"
        echo -e "在手机浏览器打开，自动跳转 Anywhere 导入（需 Anywhere 支持 NW3）："
        echo -e "${CYAN}${IMPORT_UDP}${NC}"
    elif [[ -n "$IMPORT_TCP" ]]; then
        echo -e "${BOLD}✅ 最快导入方式（TLS/TCP）：${NC}"
        echo -e "在手机浏览器打开，自动跳转 Anywhere 导入（需 Anywhere 支持 NW3）："
        echo -e "${CYAN}${IMPORT_TCP}${NC}"
    fi
    echo ""
    print_tls_fingerprint
    echo ""
    echo -e "${BOLD}📋 常用命令：${NC}"
    echo -e "  状态 : ${CYAN}systemctl status nowhere${NC} / ${CYAN}nowhere status${NC}"
    echo -e "  日志 : ${CYAN}journalctl -u nowhere -f${NC}"
    echo -e "  配置 : ${CYAN}cat ${CONFIG_DIR}/config.txt${NC}"
    echo -e "  重启 : ${CYAN}systemctl restart nowhere${NC}"
    echo -e "  探测 : ${CYAN}${MANAGER_PATH} probe${NC}（真实 TCP Flow 连通性测试）"
    divider
}

load_saved_config() {
    [ ! -f "$CONFIG_FILE" ] && error "未找到配置文件，请先执行安装"
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
    # 兼容旧版（v1.5 脚本）配置文件：旧字段 ALPN/POOL/LOG/SOCKS含义已变，只做迁移提示不直接沿用
    OUT_TYPE="${OUT_TYPE_VALUE:-}"
    if [[ -z "$OUT_TYPE" ]]; then
        if [[ -n "${SOCKS_VALUE:-}" && "${SOCKS_VALUE}" != "none" ]]; then
            OUT_TYPE="socks"
            SOCKS="$SOCKS_VALUE"
            warn "检测到旧版配置：SOCKS5 已由 socks= 迁移为 Portal 的 out=，已自动沿用该地址"
        else
            OUT_TYPE="direct"
            SOCKS="none"
        fi
        warn "检测到旧版（NW1）配置文件。v3 还要求：密钥改为 32 位十六进制、删除 alpn/net/log/pool 参数，建议用菜单「4) 重新配置」按 v3 向导重装一次"
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
    GENERATE_VECTOR="${GENERATE_VECTOR_VALUE:-0}"
    # 旧配置里存的是 VECTOR_UP/VECTOR_DOWN 双向载体，v3 Vector 只有单载体：优先取上行值
    VECTOR_CARRIER="${VECTOR_CARRIER_VALUE:-${VECTOR_UP_VALUE:-tcp}}"
    VECTOR_SOCKS="${VECTOR_SOCKS_VALUE:-$DEFAULT_VECTOR_SOCKS}"
    GENERATE_EGRESS="${GENERATE_EGRESS_VALUE:-0}"
    NOWHERE_PORTAL="${NOWHERE_PORTAL:-$(build_portal_url)}"

    if ! is_valid_key "$SHARED_KEY"; then
        warn "当前保存的共享密钥不符合 v3 规范（必须是恰好 32 位小写十六进制字符）"
        warn "v3 会直接拒绝用该密钥启动。请用菜单「4) 重新配置」生成新密钥，并同步更新所有 Vector/Egress/Anywhere 对端"
    fi
}

do_uninstall() {
    step "卸载 Nowhere"
    divider
    read -p "确认卸载 [y/N]: " CONFIRM
    [[ ! "$CONFIRM" =~ ^[Yy]$ ]] && { info "已取消"; return; }
    systemctl disable --now nowhere 2>/dev/null || true
    rm -f "$SERVICE_FILE" "$BIN_PATH" "$BIN_BACKUP_PATH"
    rm -f /etc/letsencrypt/renewal-hooks/deploy/restart-nowhere.sh
    systemctl daemon-reload
    warn "已保留 ${CONFIG_DIR}（含密钥配置），如需彻底清除请手动: rm -rf ${CONFIG_DIR}"
    success "Nowhere 已卸载"
}

do_update() {
    step "更新 Nowhere 二进制（更新到最新版）"
    divider
    local current
    current="$(read_installed_version)"
    info "当前版本: ${current}"
    info "正在获取最新版本号..."
    local latest
    latest=$(curl -s "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | cut -d'"' -f4 || true)
    [ -z "$latest" ] && error "无法获取版本号"
    info "最新版本: ${latest}"

    if [ "$current" = "$latest" ]; then
        info "已经是最新版本，无需更新"
        return
    fi

    local cur_major latest_major
    cur_major="$(version_major "$current")"
    latest_major="$(version_major "$latest")"
    if [[ -n "$cur_major" && -n "$latest_major" && "$cur_major" != "$latest_major" ]]; then
        warn "这是跨协议代升级（NW${cur_major} -> NW${latest_major}）：新旧对端不互通，Vector/Egress/Anywhere 必须一起升级"
        warn "且 v3 的密钥格式、URL 参数与旧版不兼容，仅换二进制不重配大概率启动失败或连不上"
        read -p "确认跨代升级 [y/N]: " MAJOR_CONFIRM
        [[ ! "$MAJOR_CONFIRM" =~ ^[Yy]$ ]] && { info "已取消"; return; }
    fi

    install_nowhere_version "$latest" || error "更新失败"
    warn "若这是从 v1/v2 跨代升到 v3，请接着用菜单「4) 重新配置」按 v3 向导重建配置（新密钥 + 新 URL），再同步更新所有对端"
}

do_show_version() {
    step "版本信息"
    divider
    local current previous
    current="$(read_installed_version)"
    previous="$(read_previous_version)"

    if [ -x "$BIN_PATH" ]; then
        echo -e "  当前运行的二进制  : ${GREEN}$(${BIN_PATH} --version 2>&1 | head -1)${NC}"
    else
        warn "未检测到已安装的 Nowhere 二进制"
    fi
    echo -e "  记录的版本 tag    : ${GREEN}${current}${NC}"
    [ -n "$previous" ] && echo -e "  上一个版本 tag    : ${YELLOW}${previous}${NC}（可用「版本回退」快速切回）"

    echo ""
    info "正在查询 GitHub 最新版本..."
    local latest
    latest=$(curl -s "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | cut -d'"' -f4 || true)
    if [ -n "$latest" ]; then
        if [ "$current" = "$latest" ]; then
            success "已是最新版本 (${latest})"
        else
            warn "有新版本可用: ${latest}（当前 ${current}），可选菜单「更新」升级"
        fi
    else
        warn "无法查询最新版本，请检查网络"
    fi
}

do_select_version() {
    step "选择要安装的版本（支持回退到历史版本）"
    divider
    local current
    current="$(read_installed_version)"
    info "当前版本: ${current}"
    info "正在获取版本列表..."

    local tags=()
    while IFS= read -r line; do
        tags+=("$line")
    done < <(curl -s "https://api.github.com/repos/${REPO}/releases?per_page=20" | grep '"tag_name"' | cut -d'"' -f4)

    if [ "${#tags[@]}" -eq 0 ]; then
        error "未能获取版本列表，请检查网络"
    fi

    echo ""
    local i=1
    for t in "${tags[@]}"; do
        if [ "$t" = "$current" ]; then
            echo -e "  ${BOLD}${i})${NC} ${t}  ${GREEN}← 当前版本${NC}"
        else
            echo -e "  ${BOLD}${i})${NC} ${t}"
        fi
        i=$((i+1))
    done
    echo -e "  ${BOLD}0)${NC} 取消"
    divider
    read -p "选择要切换到的版本序号: " VER_CHOICE

    [[ "$VER_CHOICE" == "0" || -z "$VER_CHOICE" ]] && { info "已取消"; return; }
    if ! [[ "$VER_CHOICE" =~ ^[0-9]+$ ]] || [ "$VER_CHOICE" -lt 1 ] || [ "$VER_CHOICE" -gt "${#tags[@]}" ]; then
        warn "无效选择"
        return
    fi

    local target="${tags[$((VER_CHOICE-1))]}"
    if [ "$target" = "$current" ]; then
        info "已经是该版本，无需切换"
        return
    fi

    read -p "确认切换到 ${target} [y/N]: " CONFIRM
    [[ ! "$CONFIRM" =~ ^[Yy]$ ]] && { info "已取消"; return; }

    install_nowhere_version "$target" || error "切换失败，服务可能未正常启动，请检查日志"
}

do_rollback() {
    step "版本回退"
    divider
    if [ ! -f "$BIN_BACKUP_PATH" ]; then
        warn "没有可用于回退的本地备份版本"
        info "备份仅在执行过「更新」或「选择版本」之后才会生成"
        return
    fi

    local current previous
    current="$(read_installed_version)"
    previous="$(read_previous_version)"
    echo -e "  当前版本 : ${GREEN}${current}${NC}"
    echo -e "  回退目标 : ${YELLOW}${previous:-未知版本（本地备份二进制）}${NC}"
    divider
    read -p "确认回退 [y/N]: " CONFIRM
    [[ ! "$CONFIRM" =~ ^[Yy]$ ]] && { info "已取消"; return; }

    local tmp_bin="/tmp/nowhere.swap"
    cp "$BIN_PATH" "$tmp_bin"

    systemctl stop nowhere 2>/dev/null || true
    install -m 755 "$BIN_BACKUP_PATH" "$BIN_PATH"
    install -m 755 "$tmp_bin" "$BIN_BACKUP_PATH"
    rm -f "$tmp_bin"

    echo "$current" > "$PREV_VERSION_FILE"
    if [ -n "$previous" ]; then
        echo "$previous" > "$VERSION_FILE"
    else
        echo "未知(本地备份)" > "$VERSION_FILE"
    fi

    systemctl start nowhere
    sleep 2
    if systemctl is-active --quiet nowhere; then
        success "已回退到: $(${BIN_PATH} --version 2>&1 | head -1)"
    else
        warn "回退后服务启动失败，日志如下："
        journalctl -u nowhere -n 20 --no-pager
    fi
}

do_reconfig() {
    step "重新配置"
    divider
    warn "将重新走一遍安装向导并覆盖当前配置"
    warn "注意：v3 密钥与 URL 语法已变更，重新配置后务必把新的 Vector/Egress/Anywhere 连接信息同步到所有对端，旧链接无法继续使用"
    read -p "确认继续 [y/N]: " CONFIRM
    [[ ! "$CONFIRM" =~ ^[Yy]$ ]] && return
    do_install
}

do_show_config() {
    step "连接信息"
    divider
    if [ -f "$CONFIG_FILE" ]; then
        load_saved_config
        # 每次查看都按当前保存参数重新生成（含最新自签 pin），避免展示过期指纹的旧串
        NOWHERE_PORTAL="$(build_portal_url)"
        build_client_links
        build_vector_info
        build_egress_info
        print_all_info
    elif [ -f "${CONFIG_DIR}/config.txt" ]; then
        cat "${CONFIG_DIR}/config.txt"
    else
        warn "未找到配置，请先安装"
    fi
}

do_show_status() {
    step "服务状态"
    divider
    systemctl status nowhere --no-pager
    divider
    if [ -x "$BIN_PATH" ]; then
        info "Nowhere 本地实例快照（nowhere status，v3 内置遥测）："
        "$BIN_PATH" status 2>&1 || warn "nowhere status 未能读取到实例（服务未运行，或二进制版本低于 v2.1.2 无此命令）"
        divider
    fi
    info "最近日志（20行）："
    journalctl -u nowhere -n 20 --no-pager
}

do_show_logs() {
    step "实时日志（Ctrl+C 退出）"
    divider
    journalctl -u nowhere -f
}

do_fingerprint() {
    load_saved_config
    print_tls_fingerprint
}

do_restart() {
    systemctl restart nowhere
    sleep 1
    systemctl is-active --quiet nowhere && success "已重启" || error "重启失败"
    load_saved_config 2>/dev/null && print_tls_fingerprint
    if [[ "${TLS_MODE:-}" == "1" ]]; then
        warn "自签证书指纹已随本次重启变化，请用 pz/菜单 5 重新生成带新 pin= 的 Vector/Egress 连接串并同步到对端"
    fi
}

do_genkey() {
    step "生成 v3 共享密钥"
    divider
    local k
    k="$(gen_key)"
    if is_valid_key "$k"; then
        echo -e "  ${GREEN}${k}${NC}"
        info "格式：32 位小写十六进制（16 随机字节）。Portal、Vector、Egress、Anywhere 四端必须填完全相同的这串字符"
    else
        error "生成失败：openssl 与 nowhere 二进制均不可用"
    fi
}

do_probe() {
    step "连通性探测 probe（真实 TCP Flow，不发送业务数据）"
    divider
    [ -x "$BIN_PATH" ] || error "未找到 Nowhere 二进制，请先安装"
    load_saved_config
    is_valid_key "$SHARED_KEY" || error "当前密钥不符合 v3 规范，无法探测，请先用菜单 4 重新配置"
    local vector_url target
    vector_url="$(build_probe_vector_url)"
    read -p "目标地址 host:port（回车默认 example.com:443）: " target
    target=${target:-example.com:443}
    info "Vector: ${vector_url}"
    info "Target: ${target}"
    "$BIN_PATH" probe "$vector_url" "$target" || warn "探测未成功（Result 非 OK）。常见原因：Portal 出口不可达、Egress 离线、对端 Morph/pin/密钥不一致、目标本身不可达"
}

do_cert_status() {
    step "证书状态与续期"
    divider
    [ -f "$CONFIG_FILE" ] || error "未找到配置文件，请先执行安装"
    load_saved_config
    if [ "$TLS_MODE" != "2" ]; then
        info "当前为自签模式（tls=1），证书只存在内存中、无需续期"
        return
    fi
    echo -e "  域名       : ${GREEN}${DOMAIN}${NC}"
    echo -e "  证书路径   : ${GREEN}${CRT}${NC}"
    echo -e "  申请方式   : ${GREEN}${CERT_METHOD}${NC}"
    local days
    days="$(cert_expiry_days "$CRT" 2>/dev/null || echo "")"
    if [ -n "$days" ]; then
        if [ "$days" -lt 0 ]; then
            warn "证书已过期 $((-days)) 天！请立即手动续期"
        elif [ "$days" -le 30 ]; then
            warn "证书剩余 ${days} 天（30 天内到期），建议立即手动续期"
        else
            success "证书有效，剩余约 ${days} 天"
        fi
    else
        warn "无法读取证书有效期（文件缺失或损坏），建议重新签发"
    fi
    echo ""
    info "自动续期链路检查："
    case "$CERT_METHOD" in
        letsencrypt-http|cloudflare-dns)
            if systemctl is-active --quiet certbot.timer 2>/dev/null; then
                success "certbot.timer 运行中"
            elif crontab -l 2>/dev/null | grep -q 'certbot renew'; then
                success "cron 兜底续期任务存在"
            else
                warn "未发现有效的自动续期任务！"
            fi
            [ -x /etc/letsencrypt/renewal-hooks/deploy/restart-nowhere.sh ] \
                && success "续期 deploy hook 存在（续期后自动重启 nowhere）" \
                || warn "续期 deploy hook 缺失（续期后不会自动重启 nowhere）"
            ;;
        letsencrypt-dns)
            if crontab -l 2>/dev/null | grep -q 'acme.sh.*--cron'; then
                success "acme.sh cron 续期任务存在"
            else
                warn "未发现 acme.sh 自动续期任务！"
            fi
            ;;
    esac
    echo ""
    read -p "是否立即手动触发一次续期检查？（仅当证书满足续期条件时才会真的续签）[y/N]: " DO_RENEW
    if [[ "$DO_RENEW" =~ ^[Yy]$ ]]; then
        case "$CERT_METHOD" in
            letsencrypt-http|cloudflare-dns)
                certbot renew && systemctl restart nowhere && success "续期检查完成" \
                    || warn "续期失败，请看上方报错"
                ;;
            letsencrypt-dns)
                "${ACME_HOME}/acme.sh" --renew -d "${DOMAIN}" && success "续期检查完成（acme.sh 的 --reloadcmd 会自动重启 nowhere）" \
                    || warn "续期失败，请看上方报错"
                ;;
        esac
    fi
}

run_interactive_menu() {
    show_menu
    case $MENU_CHOICE in
        1) do_install ;;
        2) do_uninstall ;;
        3) do_update ;;
        4) do_reconfig ;;
        5) do_show_config ;;
        6) do_show_status ;;
        7) do_show_logs ;;
        8) do_fingerprint ;;
        9) do_restart ;;
        10) install_shortcuts ;;
        11) do_show_version ;;
        12) do_select_version ;;
        13) do_rollback ;;
        14) do_genkey ;;
        15) do_probe ;;
        16) do_cert_status ;;
        0) exit 0 ;;
        *) error "无效选择" ;;
    esac
}

case "$ACTION" in
    menu)       run_interactive_menu ;;
    install)    do_install ;;
    uninstall)  do_uninstall ;;
    update)     do_update ;;
    reconfig)   do_reconfig ;;
    config)     do_show_config ;;
    status)     do_show_status ;;
    logs)       do_show_logs ;;
    fingerprint) do_fingerprint ;;
    restart)    do_restart ;;
    shortcuts)  install_shortcuts ;;
    version)    do_show_version ;;
    select-version) do_select_version ;;
    rollback)   do_rollback ;;
    generate-key) do_genkey ;;
    probe)      do_probe ;;
    cert-status) do_cert_status ;;
    *) error "未知操作: ${ACTION}（可用: install/uninstall/update/reconfig/config/status/logs/fingerprint/restart/shortcuts/version/select-version/rollback/generate-key/probe/cert-status）" ;;
esac
