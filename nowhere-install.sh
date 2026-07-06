#!/bin/bash
set -e

# ══════════════════════════════════════════════════════════════
#   Adam Nowhere Portal 一键管理脚本
#   合并证书自动申请（install版）+ 完整协议参数（vps版）
#   快捷命令：adam(菜单) · zt(状态) · pz(配置) · cxpz(重新配置) · cq(重启)
#   支持 Debian / Ubuntu · x86_64 / aarch64
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
CONFIG_DIR="/etc/nowhere"
CONFIG_FILE="${CONFIG_DIR}/nowhere.env"
SERVICE_FILE="/etc/systemd/system/nowhere.service"
ACME_HOME="/root/.acme.sh"
MANAGER_PATH="/usr/local/bin/adam-nowhere-manager.sh"

DEFAULT_NET="mix"
DEFAULT_ALPN="now/1"
DEFAULT_LOG="info"
DEFAULT_POOL="5"
DEFAULT_SOCKS="none"
DEFAULT_DIAL="auto"

info()    { echo -e "${BLUE}[信息]${NC} $1"; }
success() { echo -e "${GREEN}[成功]${NC} $1"; }
warn()    { echo -e "${YELLOW}[警告]${NC} $1"; }
error()   { echo -e "${RED}[错误]${NC} $1"; exit 1; }
step()    { echo -e "\n${BOLD}${CYAN}━━━ $1 ━━━${NC}"; }
divider() { echo -e "${CYAN}────────────────────────────────────────────────────────${NC}"; }

[ "$EUID" -ne 0 ] && error "请以 root 用户运行此脚本"

# 支持命令行直接传参调用，例如: adam status / adam config
ACTION="${1:-menu}"

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

urlencode() {
    local input="${1:-}"
    python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$input" 2>/dev/null \
        || echo -n "$input" | od -An -tx1 | tr ' ' % | tr -d '\n'
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

random_token() {
    local bytes="${1:-24}"
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 "$bytes" | tr '+/' '-_' | tr -d '='
    else
        LC_ALL=C tr -dc 'A-Za-z0-9._~-' </dev/urandom | head -c $((bytes * 2))
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

build_portal_url() {
    # 服务端启动 URL（Portal），仅包含 Portal 真正接受的参数。
    # 明确不加入 pool —— 该参数是 Anywhere 客户端 TCP 导入链接专用，Portal 服务端不识别，
    # 加进去会被服务端忽略或报错，因此这里永远不拼接 pool。
    local encoded_key host_part query
    encoded_key="$(urlencode "$SHARED_KEY")"
    host_part="$(format_host_for_url "${LISTEN_HOST:-}")"
    query="tls=${TLS_MODE}"

    [[ -n "$SPEC" ]] && query="${query}&spec=$(urlencode "$SPEC")"
    [[ -n "$ALPN" && "$ALPN" != "$DEFAULT_ALPN" ]] && query="${query}&alpn=$(urlencode "$ALPN")"
    [[ "$NET" != "$DEFAULT_NET" ]] && query="${query}&net=${NET}"
    [[ -n "$DIAL" && "$DIAL" != "$DEFAULT_DIAL" ]] && query="${query}&dial=$(urlencode "$DIAL")"
    [[ -n "$SOCKS" && "$SOCKS" != "$DEFAULT_SOCKS" ]] && query="${query}&socks=$(urlencode "$SOCKS")"
    [[ -n "$RATE" && "$RATE" != "0" ]] && query="${query}&rate=${RATE}"
    [[ -n "$ETAR" && "$ETAR" != "0" ]] && query="${query}&etar=${ETAR}"
    if [[ "$TLS_MODE" == "2" ]]; then
        query="${query}&crt=$(urlencode "$CRT")&key=$(urlencode "$KEY_PEM")"
    fi
    [[ "$LOG" != "$DEFAULT_LOG" ]] && query="${query}&log=${LOG}"

    printf 'portal://%s@%s:%s?%s' "$encoded_key" "$host_part" "$PORT" "$query"
}

build_client_links() {
    local host host_part encoded_key encoded_name base query
    host="${PUBLIC_HOST:-}"
    [[ -z "$host" ]] && host="$(detect_public_host)"
    host_part="$(format_host_for_url "$host")"
    encoded_key="$(urlencode "$SHARED_KEY")"
    encoded_name="$(urlencode "Nowhere-${DOMAIN}")"
    base="nowhere://${encoded_key}@${host_part}:${PORT}"

    UDP_LINK=""
    TCP_LINK=""
    IMPORT_UDP=""
    IMPORT_TCP=""

    # 服务端 net=mix 时 UDP/TCP 均可用；net=udp 只生成 UDP 链接；net=tcp 只生成 TCP 链接
    # 这样客户端导入链接始终和服务端实际监听的协议匹配，不会生成连不通的链接
    if [[ "$NET" == "mix" || "$NET" == "udp" ]]; then
        query="net=udp"
        [[ -n "$SPEC" ]] && query="${query}&spec=$(urlencode "$SPEC")"
        [[ -n "$ALPN" && "$ALPN" != "$DEFAULT_ALPN" ]] && query="${query}&alpn=$(urlencode "$ALPN")"
        UDP_LINK="${base}?${query}#${encoded_name}"
        IMPORT_UDP="anywhere://add-proxy?link=$(urlencode "$UDP_LINK")"
    fi

    if [[ "$NET" == "mix" || "$NET" == "tcp" ]]; then
        # 注意：pool 仅是 Anywhere 客户端 TLS/TCP 导入链接的参数，
        # Portal（服务端）不接受该参数，因此绝不会出现在 build_portal_url() 生成的启动串里
        query="net=tcp&pool=${POOL:-$DEFAULT_POOL}"
        [[ -n "$SPEC" ]] && query="${query}&spec=$(urlencode "$SPEC")"
        [[ -n "$ALPN" && "$ALPN" != "$DEFAULT_ALPN" ]] && query="${query}&alpn=$(urlencode "$ALPN")"
        TCP_LINK="${base}?${query}#${encoded_name}"
        IMPORT_TCP="anywhere://add-proxy?link=$(urlencode "$TCP_LINK")"
    fi
}

print_tls_fingerprint() {
    if [[ "$TLS_MODE" != "1" ]]; then
        return 0
    fi
    echo
    info "正在获取自签证书 SHA-256 指纹..."
    local connect_host="127.0.0.1"
    local sni="${PUBLIC_HOST:-localhost}"
    local fingerprint output
    for _ in 1 2 3 4 5; do
        output="$(timeout 8 openssl s_client -connect "${connect_host}:${PORT}" \
            -servername "$sni" -showcerts </dev/null 2>/dev/null \
            | openssl x509 -noout -fingerprint -sha256 2>/dev/null || true)"
        fingerprint="${output#*=}"
        if [[ -n "$fingerprint" && "$fingerprint" != "$output" ]]; then
            echo -e "  ${GREEN}${fingerprint}${NC}"
            warn "tls=1 证书存在内存中，Nowhere 每次重启后指纹都会变化"
            return 0
        fi
        sleep 1
    done
    warn "暂未获取到指纹，可稍后运行: journalctl -u nowhere -n 100"
}

# ══════════════════════════════════════════════════════════════
#  快捷命令安装：adam(菜单入口) · zt(状态) · pz(配置) · cxpz(重新配置) · cq(重启)
# ══════════════════════════════════════════════════════════════

install_shortcuts() {
    step "安装快捷命令"
    divider
    local self_path
    self_path="$(readlink -f "$0" 2>/dev/null || true)"

    if [ -n "$self_path" ] && [ -f "$self_path" ]; then
        cp "$self_path" "$MANAGER_PATH"
        chmod +x "$MANAGER_PATH"
    else
        warn "无法定位脚本自身文件路径（可能是通过管道 bash <(curl ...) 运行）"
        warn "快捷命令需要脚本以文件形式保存后再运行，例如："
        warn "  wget -O nowhere-install.sh <脚本地址> && bash nowhere-install.sh"
        return 1
    fi

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

show_menu() {
    clear
    echo -e "${BOLD}${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║         Adam Nowhere Portal 一键管理脚本                     ║"
    echo "║         加密隧道协议 · TLS/TCP + QUIC/UDP                    ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "  ${BOLD}1)${NC} 安装 Nowhere（向导）"
    echo -e "  ${BOLD}2)${NC} 卸载 Nowhere"
    echo -e "  ${BOLD}3)${NC} 更新 Nowhere 二进制"
    echo -e "  ${BOLD}4)${NC} 重新配置（修改参数）"
    echo -e "  ${BOLD}5)${NC} 查看连接信息 / 导入链接"
    echo -e "  ${BOLD}6)${NC} 查看服务状态"
    echo -e "  ${BOLD}7)${NC} 查看实时日志"
    echo -e "  ${BOLD}8)${NC} 查看自签证书指纹（tls=1）"
    echo -e "  ${BOLD}9)${NC} 重启服务"
    echo -e "  ${BOLD}10)${NC} 重装快捷命令（adam/zt/pz/cxpz/cq）"
    echo -e "  ${BOLD}0)${NC} 退出"
    divider
    if [ -x /usr/local/bin/adam ]; then
        echo -e "  ${YELLOW}提示：可直接输入${NC} ${CYAN}adam${NC} ${YELLOW}唤出此菜单，或用${NC} ${CYAN}zt${NC}/${CYAN}pz${NC}/${CYAN}cxpz${NC}/${CYAN}cq${NC} ${YELLOW}快捷执行${NC}"
        divider
    fi
    read -p "请选择操作 [0-10]: " MENU_CHOICE
}

do_install() {
    step "第 1 步：选择证书获取方式"
    divider
    echo -e "${BOLD}TLS 证书方式：${NC}"
    echo "  1) 自签证书 tls=1  - 无需域名，快速测试（指纹会变化）"
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
        read -p "公网 IP/域名（用于 Anywhere 导入链接，回车使用探测值 ${DETECTED_IP}）: " PUBLIC_HOST
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
            *) warn "请手动配置 acme.sh DNS 环境变量"; DNS_API="dns_manual" ;;
        esac
    fi

    step "第 3 步：监听参数"
    divider
    read -p "监听端口（回车默认443）: " PORT
    PORT=${PORT:-443}
    validate_port "$PORT" || { warn "端口不合法，重置为443"; PORT=443; }

    read -p "监听地址（回车为空=IPv4/IPv6全监听，通常留空即可）: " LISTEN_HOST

    echo ""
    echo -e "${BOLD}传输模式：${NC}"
    echo "  1) mix - TLS/TCP + QUIC/UDP 双栈（推荐）"
    echo "  2) tcp - 仅 TLS/TCP"
    echo "  3) udp - 仅 QUIC/UDP"
    read -p "选择 [1/2/3，默认1]: " NET_CHOICE
    case ${NET_CHOICE:-1} in
        1) NET="mix" ;; 2) NET="tcp" ;; 3) NET="udp" ;; *) NET="mix" ;;
    esac

    step "第 4 步：协议与安全参数（完整）"
    divider

    read -p "共享密钥 Shared Key（回车自动生成）: " SHARED_KEY
    [ -z "$SHARED_KEY" ] && { SHARED_KEY="$(random_token 24)"; info "已生成密钥: ${SHARED_KEY}"; }

    read -p "Spec Seed 协议种子（回车自动生成）: " SPEC
    [ -z "$SPEC" ] && { SPEC="$(random_token 12)"; info "已生成 Spec: ${SPEC}"; }

    read -p "ALPN（回车默认 ${DEFAULT_ALPN}）: " ALPN
    ALPN=${ALPN:-$DEFAULT_ALPN}

    echo ""
    echo -e "${BOLD}限速设置：${NC}"
    read -p "上行限速 Mbps，客户端→目标（0=不限速）: " RATE
    RATE=${RATE:-0}
    validate_nonneg_int "$RATE" || { warn "输入不合法，重置为0"; RATE=0; }

    read -p "下行限速 Mbps，目标→客户端（0=不限速）: " ETAR
    ETAR=${ETAR:-0}
    validate_nonneg_int "$ETAR" || { warn "输入不合法，重置为0"; ETAR=0; }

    echo ""
    read -p "出站源 IP（回车默认 auto，即系统自动选择）: " DIAL
    DIAL=${DIAL:-$DEFAULT_DIAL}

    echo ""
    echo -e "${BOLD}SOCKS5 出站代理（可选，用于链式代理）：${NC}"
    read -p "格式 host:port 或 user:pass@host:port（回车跳过）: " SOCKS
    SOCKS=${SOCKS:-$DEFAULT_SOCKS}
    validate_socks "$SOCKS" || { warn "SOCKS5 格式不合法，已重置为 none"; SOCKS="none"; }

    echo ""
    echo -e "${BOLD}日志级别：${NC}"
    echo "  1) info  2) debug  3) warn  4) error  5) event  6) none"
    read -p "选择 [1-6，默认1]: " LOG_CHOICE
    case ${LOG_CHOICE:-1} in
        1) LOG="info" ;; 2) LOG="debug" ;; 3) LOG="warn" ;;
        4) LOG="error" ;; 5) LOG="event" ;; 6) LOG="none" ;; *) LOG="info" ;;
    esac

    if [[ "$NET" == "mix" || "$NET" == "tcp" ]]; then
        echo ""
        echo -e "${BOLD}Anywhere TCP Pool${NC}（${YELLOW}仅客户端 TLS/TCP 导入链接使用，Portal 服务端不接受此参数，不会写入启动命令${NC}）："
        read -p "连接池大小 0-9（回车默认 ${DEFAULT_POOL}）: " POOL
        POOL=${POOL:-$DEFAULT_POOL}
        [[ "$POOL" =~ ^[0-9]$ ]] || { warn "Pool 值不合法，重置为默认"; POOL=$DEFAULT_POOL; }
    else
        POOL="$DEFAULT_POOL"
        info "传输模式为 udp，不涉及 TCP 连接，跳过 Pool 设置"
    fi

    echo ""
    divider
    echo -e "${BOLD}配置确认：${NC}"
    divider
    echo -e "  域名/主机     : ${GREEN}${DOMAIN}${NC}"
    echo -e "  公网地址      : ${GREEN}${PUBLIC_HOST}${NC}"
    echo -e "  邮箱          : ${GREEN}${EMAIL}${NC}"
    echo -e "  证书方式      : ${GREEN}${CERT_METHOD}${NC}"
    echo -e "  监听端口      : ${GREEN}${PORT}${NC}"
    echo -e "  监听地址      : ${GREEN}$([ -z "$LISTEN_HOST" ] && echo "<空,全监听>" || echo "$LISTEN_HOST")${NC}"
    echo -e "  传输模式      : ${GREEN}${NET}${NC}"
    echo -e "  共享密钥      : ${GREEN}$(mask_secret "$SHARED_KEY")${NC}"
    echo -e "  Spec          : ${GREEN}$(mask_secret "$SPEC")${NC}"
    echo -e "  ALPN          : ${GREEN}${ALPN}${NC}"
    echo -e "  上/下行限速   : ${GREEN}${RATE} / ${ETAR} Mbps${NC}"
    echo -e "  出站源IP      : ${GREEN}${DIAL}${NC}"
    echo -e "  SOCKS5出站    : ${GREEN}$(display_socks "$SOCKS")${NC}"
    echo -e "  日志级别      : ${GREEN}${LOG}${NC}"
    if [[ "$NET" == "mix" || "$NET" == "tcp" ]]; then
        echo -e "  TCP Pool      : ${GREEN}${POOL}${NC}（仅客户端参数）"
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
        step "第 6 步：申请 TLS 证书"
        divider
        mkdir -p "/etc/letsencrypt/live/${DOMAIN}"

        if [ "$CERT_METHOD" = "letsencrypt-http" ]; then
            if [ -f "$CRT" ] && [ -f "$KEY_PEM" ]; then
                warn "证书已存在，跳过申请"
            else
                info "申请证书中（HTTP-01，需 80 端口）..."
                ufw allow 80/tcp 2>/dev/null || true
                certbot certonly --standalone --preferred-challenges http \
                    --non-interactive --agree-tos --email "${EMAIL}" \
                    -d "${DOMAIN}" --http-01-port 80 --http-01-address 0.0.0.0 || \
                    error "证书申请失败：请检查域名解析和80端口"
                success "证书申请成功"
            fi

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

            if [ -f "$CRT" ] && [ -f "$KEY_PEM" ]; then
                warn "证书已存在，跳过申请"
            else
                info "申请证书中（Cloudflare DNS-01，约需30-60秒）..."
                certbot certonly --dns-cloudflare \
                    --dns-cloudflare-credentials /etc/cloudflare/credentials.ini \
                    --non-interactive --agree-tos --email "${EMAIL}" \
                    -d "${DOMAIN}" --dns-cloudflare-propagation-seconds 30 || \
                    error "证书申请失败：请检查 CF API Key 和域名 DNS 是否在 Cloudflare 管理下"
                success "证书申请成功"
            fi

        elif [ "$CERT_METHOD" = "letsencrypt-dns" ]; then
            info "安装 acme.sh..."
            curl -s https://get.acme.sh | bash -s email="${EMAIL}" > /dev/null 2>&1
            . "${ACME_HOME}/acme.sh.env" 2>/dev/null || true

            if [ -f "$CRT" ] && [ -f "$KEY_PEM" ]; then
                warn "证书已存在，跳过申请"
            else
                info "申请证书中（DNS-01: ${DNS_API}）..."
                "${ACME_HOME}/acme.sh" --issue -d "${DOMAIN}" --dns "${DNS_API}" --force || \
                    error "证书申请失败：请检查 DNS API 凭据"
                "${ACME_HOME}/acme.sh" --install-cert -d "${DOMAIN}" \
                    --cert-file "${CRT}" --key-file "${KEY_PEM}" --fullchain-file "${CRT}" \
                    --reloadcmd "systemctl restart nowhere"
                success "证书申请成功"
            fi
        fi

        info "证书链: ${CRT}"
        info "私钥  : ${KEY_PEM}"

        mkdir -p /etc/letsencrypt/renewal-hooks/deploy
        cat > /etc/letsencrypt/renewal-hooks/deploy/restart-nowhere.sh << 'HOOKEOF'
#!/bin/bash
systemctl restart nowhere
HOOKEOF
        chmod +x /etc/letsencrypt/renewal-hooks/deploy/restart-nowhere.sh
    fi

    step "第 7 步：下载 Nowhere 二进制"
    divider
    detect_binary
    LATEST=$(curl -s "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)
    [ -z "$LATEST" ] && error "无法获取版本号，请检查网络"
    info "最新版本: ${LATEST} (${ARCH_NAME}-${LIBC})"
    curl -fL --retry 3 --connect-timeout 10 \
        -o /tmp/nowhere.tar.gz \
        "https://github.com/${REPO}/releases/download/${LATEST}/${BIN_NAME}" || error "下载失败"
    tar -xzf /tmp/nowhere.tar.gz -C /tmp/ || error "解压失败"
    BINARY_PATH=$(find /tmp -type f -name nowhere -perm -u+x | head -1)
    [ -z "$BINARY_PATH" ] && BINARY_PATH=$(find /tmp -type f -name nowhere | head -1)
    [ -z "$BINARY_PATH" ] && error "未找到 nowhere 二进制文件"
    install -m 755 "${BINARY_PATH}" "${BIN_PATH}"
    rm -f /tmp/nowhere.tar.gz /tmp/nowhere 2>/dev/null || true
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
PORT_VALUE="${PORT}"
SHARED_KEY_VALUE="${SHARED_KEY}"
SPEC_VALUE="${SPEC}"
NET_VALUE="${NET}"
ALPN_VALUE="${ALPN}"
TLS_MODE_VALUE="${TLS_MODE}"
CERT_METHOD_VALUE="${CERT_METHOD}"
CRT_VALUE="${CRT:-}"
KEY_PEM_VALUE="${KEY_PEM:-}"
RATE_VALUE="${RATE}"
ETAR_VALUE="${ETAR}"
DIAL_VALUE="${DIAL}"
SOCKS_VALUE="${SOCKS}"
LOG_VALUE="${LOG}"
POOL_VALUE="${POOL}"
ENVEOF
    chmod 600 "$CONFIG_FILE"
    success "配置已保存至 ${CONFIG_FILE}"

    step "第 9 步：创建系统服务"
    divider
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
PrivateTmp=true
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
    sleep 2
    systemctl is-active --quiet nowhere && success "服务启动成功" || {
        warn "服务未能启动，查看日志排查："
        journalctl -u nowhere -n 30 --no-pager
        error "安装中止"
    }

    step "第 10 步：配置防火墙"
    divider
    ufw allow ssh 2>/dev/null || true
    ufw allow "${PORT}/tcp" 2>/dev/null || true
    ufw allow "${PORT}/udp" 2>/dev/null || true
    [ "$CERT_METHOD" = "letsencrypt-http" ] && ufw allow 80/tcp 2>/dev/null || true
    ufw --force enable
    success "防火墙已配置（端口 ${PORT} TCP+UDP 已放行）"

    step "第 11 步：生成连接信息"
    divider
    build_client_links
    print_all_info

    step "第 12 步：安装快捷命令"
    divider
    install_shortcuts || true
}

print_all_info() {
    # 按服务端 net 模式，只拼接实际存在的链接段落，避免展示连不通的链接
    local udp_section="" tcp_section=""

    if [[ -n "$UDP_LINK" ]]; then
        udp_section="
【Anywhere App 导入 —— QUIC/UDP（推荐，延迟更低）】
链接：
${UDP_LINK}

一键导入深链（手机点击）：
${IMPORT_UDP}
"
    fi

    if [[ -n "$TCP_LINK" ]]; then
        tcp_section="
【Anywhere App 导入 —— TLS/TCP（兼容性更好，pool=${POOL}，仅客户端参数，Portal 服务端不接受）】
链接：
${TCP_LINK}

一键导入深链（手机点击）：
${IMPORT_TCP}
"
    fi

    cat > "${CONFIG_DIR}/config.txt" << CONFEOF
════════════════════════════════════════════════════════════════
  Nowhere Portal 连接信息
  更新时间: $(date '+%Y-%m-%d %H:%M:%S')
════════════════════════════════════════════════════════════════

【服务端启动参数（Portal URL，用于 systemd ExecStart）】
${NOWHERE_PORTAL}
※ 注意：pool 是 Anywhere 客户端 TCP 导入链接专用参数，Portal 服务端不识别该参数，
   因此上面这条服务端启动串里不会出现 pool，这是正常且预期的行为。

【客户端连接参数】
  域名/公网地址 : ${PUBLIC_HOST}
  端口          : ${PORT}
  共享密钥      : ${SHARED_KEY}
  Spec          : ${SPEC}
  ALPN          : ${ALPN}
  传输模式      : ${NET}
  TLS           : $([ "$TLS_MODE" = "1" ] && echo "自签证书(tls=1)" || echo "真实证书(tls=2)")
${udp_section}${tcp_section}
【Anywhere 手动填写】
  服务器 : ${PUBLIC_HOST}
  端口   : ${PORT}
  密钥   : ${SHARED_KEY}
  Spec   : ${SPEC}
  TLS    : 开启
  SNI    : ${DOMAIN}
  ALPN   : ${ALPN}
$([[ "$NET" == "mix" || "$NET" == "tcp" ]] && echo "  Pool   : ${POOL}（仅 TLS/TCP 方式导入时需要，服务端不使用）")

【防火墙提醒】
$(case "$NET" in
    tcp) echo "  需放行: TCP ${PORT}" ;;
    udp) echo "  需放行: UDP ${PORT}" ;;
    *)   echo "  需放行: TCP ${PORT} 和 UDP ${PORT}" ;;
esac)
$([ "$TLS_MODE" = "1" ] && echo "
【TLS 提示】
  tls=1 为临时自签证书，每次重启指纹会变化，仅建议测试用
  生产环境请使用 tls=2 + 真实域名证书")
$([ -n "$SOCKS" ] && [ "$SOCKS" != "none" ] && echo "
【SOCKS5 出站代理】
  $(display_socks "$SOCKS")")
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
        echo -e "${BOLD}✅ 最快导入方式（QUIC/UDP，推荐）：${NC}"
        echo -e "在手机浏览器打开，自动跳转 Anywhere 导入："
        echo -e "${CYAN}${IMPORT_UDP}${NC}"
    elif [[ -n "$IMPORT_TCP" ]]; then
        echo -e "${BOLD}✅ 最快导入方式（TLS/TCP）：${NC}"
        echo -e "在手机浏览器打开，自动跳转 Anywhere 导入："
        echo -e "${CYAN}${IMPORT_TCP}${NC}"
    fi
    echo ""
    print_tls_fingerprint
    echo ""
    echo -e "${BOLD}📋 常用命令：${NC}"
    echo -e "  状态 : ${CYAN}systemctl status nowhere${NC}"
    echo -e "  日志 : ${CYAN}journalctl -u nowhere -f${NC}"
    echo -e "  配置 : ${CYAN}cat ${CONFIG_DIR}/config.txt${NC}"
    echo -e "  重启 : ${CYAN}systemctl restart nowhere${NC}"
    divider
}

load_saved_config() {
    [ ! -f "$CONFIG_FILE" ] && error "未找到配置文件，请先执行安装"
    source "$CONFIG_FILE"
    DOMAIN="$DOMAIN_VALUE"
    PUBLIC_HOST="$PUBLIC_HOST_VALUE"
    LISTEN_HOST="$LISTEN_HOST_VALUE"
    PORT="$PORT_VALUE"
    SHARED_KEY="$SHARED_KEY_VALUE"
    SPEC="$SPEC_VALUE"
    NET="$NET_VALUE"
    ALPN="$ALPN_VALUE"
    TLS_MODE="$TLS_MODE_VALUE"
    CERT_METHOD="$CERT_METHOD_VALUE"
    CRT="$CRT_VALUE"
    KEY_PEM="$KEY_PEM_VALUE"
    RATE="$RATE_VALUE"
    ETAR="$ETAR_VALUE"
    DIAL="$DIAL_VALUE"
    SOCKS="$SOCKS_VALUE"
    LOG="$LOG_VALUE"
    POOL="$POOL_VALUE"
}

do_uninstall() {
    step "卸载 Nowhere"
    divider
    read -p "确认卸载 [y/N]: " CONFIRM
    [[ ! "$CONFIRM" =~ ^[Yy]$ ]] && { info "已取消"; return; }
    systemctl disable --now nowhere 2>/dev/null || true
    rm -f "$SERVICE_FILE" "$BIN_PATH"
    systemctl daemon-reload
    warn "已保留 ${CONFIG_DIR}（含密钥配置），如需彻底清除请手动: rm -rf ${CONFIG_DIR}"
    success "Nowhere 已卸载"
}

do_update() {
    step "更新 Nowhere 二进制"
    divider
    detect_binary
    LATEST=$(curl -s "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)
    [ -z "$LATEST" ] && error "无法获取版本号"
    info "最新版本: ${LATEST}"
    curl -fL --retry 3 -o /tmp/nowhere.tar.gz \
        "https://github.com/${REPO}/releases/download/${LATEST}/${BIN_NAME}" || error "下载失败"
    tar -xzf /tmp/nowhere.tar.gz -C /tmp/
    BINARY_PATH=$(find /tmp -type f -name nowhere | head -1)
    systemctl stop nowhere 2>/dev/null || true
    install -m 755 "${BINARY_PATH}" "${BIN_PATH}"
    rm -f /tmp/nowhere.tar.gz
    systemctl start nowhere
    sleep 2
    systemctl is-active --quiet nowhere && success "更新完成: $(${BIN_PATH} --version 2>&1 | head -1)" || error "启动失败"
}

do_reconfig() {
    step "重新配置"
    divider
    warn "将重新走一遍安装向导并覆盖当前配置"
    read -p "确认继续 [y/N]: " CONFIRM
    [[ ! "$CONFIRM" =~ ^[Yy]$ ]] && return
    do_install
}

do_show_config() {
    step "连接信息"
    divider
    if [ -f "${CONFIG_DIR}/config.txt" ]; then
        cat "${CONFIG_DIR}/config.txt"
    elif [ -f "$CONFIG_FILE" ]; then
        load_saved_config
        build_client_links
        print_all_info
    else
        warn "未找到配置，请先安装"
    fi
}

do_show_status() {
    step "服务状态"
    divider
    systemctl status nowhere --no-pager
    divider
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
        0) exit 0 ;;
        *) error "无效选择" ;;
    esac
}

# 支持两种调用方式：
#   1) bash nowhere-install.sh          → 打开交互菜单
#   2) bash nowhere-install.sh status   → 直接执行（配合 adam/zt/pz/cxpz/cq 快捷命令）
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
    *) error "未知操作: ${ACTION}（可用: install/uninstall/update/reconfig/config/status/logs/fingerprint/restart）" ;;
esac
