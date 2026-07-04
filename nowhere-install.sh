#!/bin/bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${BLUE}[信息]${NC} $1"; }
success() { echo -e "${GREEN}[成功]${NC} $1"; }
warn()    { echo -e "${YELLOW}[警告]${NC} $1"; }
error()   { echo -e "${RED}[错误]${NC} $1"; exit 1; }
step()    { echo -e "\n${BOLD}${CYAN}━━━ $1 ━━━${NC}"; }
divider() { echo -e "${CYAN}──────────────────────────────────────────────${NC}"; }

[ "$EUID" -ne 0 ] && error "请以 root 用户运行此脚本"

detect_binary() {
    ARCH=$(uname -m)
    if ldd /bin/ls 2>&1 | grep -qi musl; then
        LIBC="musl"
    else
        LIBC="gnu"
    fi
    case $ARCH in
        x86_64)  BIN_NAME="nowhere-x86_64-unknown-linux-${LIBC}.tar.gz" ;;
        aarch64) BIN_NAME="nowhere-aarch64-unknown-linux-${LIBC}.tar.gz" ;;
        *)       error "不支持的架构: ${ARCH}" ;;
    esac
}

# 生成 Anywhere 深链
generate_deeplink() {
    local portal_url="$1"
    # 使用 bash 内置方法进行 URL 编码
    python3 -c "
import urllib.parse
import sys
portal = '''${portal_url}'''
encoded = urllib.parse.quote(portal, safe='')
print('anywhere://add-proxy?link=' + encoded)
" 2>/dev/null || echo "anywhere://add-proxy?link=$(echo -n "${portal_url}" | od -An -tx1 | tr ' ' % | tr -d '\n')"
}

show_menu() {
    clear
    echo -e "${BOLD}${CYAN}"
    echo "╔══════════════════════════════════════════════════╗"
    echo "║         Nowhere Portal 一键管理脚本              ║"
    echo "║         加密隧道协议 · TLS/TCP + QUIC/UDP        ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "  ${BOLD}1)${NC} 安装 Nowhere"
    echo -e "  ${BOLD}2)${NC} 卸载 Nowhere"
    echo -e "  ${BOLD}3)${NC} 更新 Nowhere"
    echo -e "  ${BOLD}4)${NC} 查看连接信息"
    echo -e "  ${BOLD}5)${NC} 查看服务状态"
    echo -e "  ${BOLD}0)${NC} 退出"
    divider
    read -p "请选择操作 [0-5]: " MENU_CHOICE
}

do_install() {
    step "第 1 步：选择证书方式"
    divider
    echo -e "${BOLD}TLS 证书获取方式：${NC}"
    echo "  1) 自签证书 - 无需域名，快速测试（tls=1）"
    echo "  2) Let's Encrypt HTTP-01 - 需要开放 80 端口（自动续期）"
    echo "  3) Let's Encrypt DNS-01 通用 - 支持任意 DNS 服务商（自动续期）"
    echo "  4) Cloudflare DNS-01 - 需要 CF API Key（自动续期）"
    read -p "请选择 [1/2/3/4，默认2]: " CERT_CHOICE
    CERT_CHOICE=${CERT_CHOICE:-2}

    case $CERT_CHOICE in
        1) TLS_MODE=1; CERT_METHOD="self-signed" ;;
        2) TLS_MODE=2; CERT_METHOD="letsencrypt-http" ;;
        3) TLS_MODE=2; CERT_METHOD="letsencrypt-dns" ;;
        4) TLS_MODE=2; CERT_METHOD="cloudflare-dns" ;;
        *) TLS_MODE=2; CERT_METHOD="letsencrypt-http" ;;
    esac

    step "第 2 步：收集配置信息"
    divider
    echo -e "${YELLOW}请依次输入以下信息${NC}\n"

    # 域名
    if [ "$TLS_MODE" = "2" ]; then
        while true; do
            read -p "请输入你的域名（例如: node.example.com）: " DOMAIN
            DOMAIN=$(echo "$DOMAIN" | tr -d ' \r\n')
            [[ -z "$DOMAIN" ]] && { echo -e "${RED}[提示] 域名不能为空！${NC}"; continue; }
            [[ "$DOMAIN" != *.* ]] && { echo -e "${RED}[提示] 域名格式不正确！${NC}"; continue; }
            break
        done
    else
        DOMAIN="localhost"
    fi

    # 邮箱
    while true; do
        read -p "请输入邮箱（用于证书申请/恢复）: " EMAIL
        EMAIL=$(echo "$EMAIL" | tr -d ' \r\n')
        [[ -z "$EMAIL" ]] && { echo -e "${RED}[提示] 邮箱不能为空！${NC}"; continue; }
        [[ "$EMAIL" != *@*.* ]] && { echo -e "${RED}[提示] 邮箱格式不正确！${NC}"; continue; }
        break
    done

    # ── DNS 验证方式 ──────────────────────────────
    if [ "$CERT_METHOD" = "letsencrypt-dns" ]; then
        echo ""
        echo -e "${BOLD}DNS 服务商：${NC}"
        echo "  1) Cloudflare"
        echo "  2) DNSPod（腾讯）"
        echo "  3) Aliyun（阿里云）"
        echo "  4) 其他/手动配置"
        read -p "请选择 [1/2/3/4，默认1]: " DNS_PROVIDER
        DNS_PROVIDER=${DNS_PROVIDER:-1}
        
        case $DNS_PROVIDER in
            1)
                read -p "请输入 Cloudflare Email: " CF_EMAIL
                read -p "请输入 Cloudflare Global API Key: " CF_API_KEY
                export CF_Email="${CF_EMAIL}"
                export CF_Key="${CF_API_KEY}"
                DNS_API="dns_cf"
                ;;
            2)
                read -p "请输入 DNSPod ID: " DNSPOD_ID
                read -p "请输入 DNSPod Token: " DNSPOD_TOKEN
                export DP_Id="${DNSPOD_ID}"
                export DP_Key="${DNSPOD_TOKEN}"
                DNS_API="dns_dp"
                ;;
            3)
                read -p "请输入阿里云 AccessKey ID: " ALIYU_ID
                read -p "请输入阿里云 AccessKey Secret: " ALIYU_SECRET
                export Ali_Key="${ALIYU_ID}"
                export Ali_Secret="${ALIYU_SECRET}"
                DNS_API="dns_ali"
                ;;
            *)
                warn "请手动配置 DNS 环境变量，参考 acme.sh 文档"
                DNS_API="dns_manual"
                ;;
        esac
    elif [ "$CERT_METHOD" = "cloudflare-dns" ]; then
        echo ""
        echo -e "${BOLD}Cloudflare 认证方式：${NC}"
        echo "  1) Global API Key"
        echo "  2) API Token"
        read -p "请选择 [1/2，默认1]: " CF_AUTH_TYPE
        CF_AUTH_TYPE=${CF_AUTH_TYPE:-1}
        if [ "$CF_AUTH_TYPE" = "1" ]; then
            while true; do
                read -p "请输入 Cloudflare Global API Key: " CF_API_KEY
                CF_API_KEY=$(echo "$CF_API_KEY" | tr -d ' \r\n')
                [ -n "$CF_API_KEY" ] && break
                echo -e "${RED}[提示] API Key 不能为空！${NC}"
            done
        else
            while true; do
                read -p "请输入 Cloudflare API Token: " CF_TOKEN
                CF_TOKEN=$(echo "$CF_TOKEN" | tr -d ' \r\n')
                [ -n "$CF_TOKEN" ] && break
                echo -e "${RED}[提示] API Token 不能为空！${NC}"
            done
        fi
    fi

    # 端口
    echo ""
    read -p "请输入监听端口（直接回车默认443）: " PORT
    PORT=$(echo "$PORT" | tr -d ' \r\n')
    PORT=${PORT:-443}
    if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
        warn "端口不合法，已重置为 443"
        PORT=443
    fi

    # 传输模式
    echo ""
    echo -e "${BOLD}传输模式：${NC}"
    echo "  1) mix - TLS/TCP + QUIC/UDP 双栈（推荐）"
    echo "  2) tcp - 仅 TLS/TCP"
    echo "  3) udp - 仅 QUIC/UDP"
    read -p "请选择 [1/2/3，默认1]: " NET_CHOICE
    case ${NET_CHOICE:-1} in
        1) NET="mix" ;;
        2) NET="tcp" ;;
        3) NET="udp" ;;
        *) NET="mix" ;;
    esac

    # 日志级别
    echo ""
    read -p "请输入日志级别 [info/debug/none，默认info]: " LOG
    LOG=${LOG:-info}

    # 速率限制
    echo ""
    read -p "请输入速率限制 MB/s（直接回车不限速）: " RATE_LIMIT
    RATE_LIMIT=$(echo "$RATE_LIMIT" | tr -d ' \r\n')

    # 密钥和 Spec
    echo ""
    read -p "请输入共享密钥（直接回车随机生成）: " SHARED_KEY
    SHARED_KEY=$(echo "$SHARED_KEY" | tr -d ' \r\n')
    if [ -z "$SHARED_KEY" ]; then
        SHARED_KEY=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 32)
        info "已随机生成密钥: ${SHARED_KEY}"
    fi

    read -p "请输入 Spec（直接回车随机生成）: " SPEC
    SPEC=$(echo "$SPEC" | tr -d ' \r\n')
    if [ -z "$SPEC" ]; then
        SPEC=$(tr -dc 'a-z0-9' < /dev/urandom | head -c 16)
        info "已随机生成 Spec: ${SPEC}"
    fi

    # 确认
    echo ""
    divider
    echo -e "${BOLD}请确认以下配置信息：${NC}"
    divider
    echo -e "  域名          : ${GREEN}${DOMAIN}${NC}"
    echo -e "  邮箱          : ${GREEN}${EMAIL}${NC}"
    echo -e "  端口          : ${GREEN}${PORT}${NC}"
    echo -e "  证书方式      : ${GREEN}${CERT_METHOD}${NC}"
    echo -e "  传输模式      : ${GREEN}${NET}${NC}"
    echo -e "  日志级别      : ${GREEN}${LOG}${NC}"
    echo -e "  共享密钥      : ${GREEN}${SHARED_KEY}${NC}"
    echo -e "  Spec          : ${GREEN}${SPEC}${NC}"
    divider
    echo ""
    read -p "确认无误，开始安装？[y/N]: " CONFIRM
    [[ ! "$CONFIRM" =~ ^[Yy]$ ]] && { info "已取消安装"; return; }

    CRT="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
    KEY_PEM="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
    ACME_HOME="/root/.acme.sh"

    # 构建启动参数
    EXTRA_PARAMS="tls=${TLS_MODE}&net=${NET}&log=${LOG}&spec=${SPEC}"
    if [ "$TLS_MODE" = "2" ]; then
        EXTRA_PARAMS="${EXTRA_PARAMS}&crt=${CRT}&key=${KEY_PEM}"
    fi
    if [ -n "$RATE_LIMIT" ]; then
        EXTRA_PARAMS="${EXTRA_PARAMS}&rate=${RATE_LIMIT}m"
    fi

    # ── 安装依赖 ──────────────────────────────────
    step "第 3 步：安装系统依赖"
    divider
    apt-get update -qq
    apt-get install -y -qq curl wget tar ufw socat openssl python3
    success "系统依赖安装完成"

    # ── 申请证书 ──────────────────────────────────
    if [ "$TLS_MODE" = "2" ]; then
        if [ "$CERT_METHOD" = "letsencrypt-http" ]; then
            step "第 4 步：申请 Let's Encrypt 证书（HTTP-01）"
            divider
            info "安装 acme.sh..."
            curl -s https://get.acme.sh | bash -s email="${EMAIL}" > /dev/null 2>&1 || true
            . "${ACME_HOME}/acme.sh.env" 2>/dev/null || true
            
            if [ -f "$CRT" ]; then
                warn "证书已存在，跳过申请"
            else
                info "正在申请证书（需要 80 端口开放）..."
                ufw allow 80/tcp 2>/dev/null || true
                "${ACME_HOME}/acme.sh" --issue -d "${DOMAIN}" --standalone --force
                "${ACME_HOME}/acme.sh" --install-cert -d "${DOMAIN}" \
                    --cert-file "${CRT}" \
                    --key-file "${KEY_PEM}" \
                    --fullchain-file "${CRT}"
                success "证书申请成功"
            fi
            
            # 自动续期钩子
            "${ACME_HOME}/acme.sh" --install-cert -d "${DOMAIN}" \
                --cert-file "${CRT}" \
                --key-file "${KEY_PEM}" \
                --fullchain-file "${CRT}" \
                --reloadcmd "systemctl restart nowhere" 2>/dev/null || true

        elif [ "$CERT_METHOD" = "letsencrypt-dns" ]; then
            step "第 4 步：申请 Let's Encrypt 证书（DNS-01）"
            divider
            info "安装 acme.sh..."
            curl -s https://get.acme.sh | bash -s email="${EMAIL}" > /dev/null 2>&1 || true
            . "${ACME_HOME}/acme.sh.env" 2>/dev/null || true
            
            if [ -f "$CRT" ]; then
                warn "证书已存在，跳过申请"
            else
                info "正在申请证书..."
                "${ACME_HOME}/acme.sh" --issue -d "${DOMAIN}" --dns "${DNS_API}" --force
                "${ACME_HOME}/acme.sh" --install-cert -d "${DOMAIN}" \
                    --cert-file "${CRT}" \
                    --key-file "${KEY_PEM}" \
                    --fullchain-file "${CRT}"
                success "证书申请成功"
            fi
            
            # 自动续期钩子
            "${ACME_HOME}/acme.sh" --install-cert -d "${DOMAIN}" \
                --cert-file "${CRT}" \
                --key-file "${KEY_PEM}" \
                --fullchain-file "${CRT}" \
                --reloadcmd "systemctl restart nowhere" 2>/dev/null || true

        elif [ "$CERT_METHOD" = "cloudflare-dns" ]; then
            step "第 4 步：申请 Let's Encrypt 证书（Cloudflare DNS-01）"
            divider
            mkdir -p /etc/cloudflare
            if [ "$CF_AUTH_TYPE" = "1" ]; then
                cat > /etc/cloudflare/credentials.ini << CFEOF
dns_cloudflare_email = ${CF_EMAIL:-}
dns_cloudflare_api_key = ${CF_API_KEY}
CFEOF
            else
                cat > /etc/cloudflare/credentials.ini << CFEOF
dns_cloudflare_api_token = ${CF_TOKEN}
CFEOF
            fi
            chmod 600 /etc/cloudflare/credentials.ini
            success "Cloudflare 凭据已写入"
            
            apt-get install -y -qq certbot python3-certbot-dns-cloudflare
            if [ -f "$CRT" ]; then
                warn "证书已存在，跳过申请"
            else
                info "正在申请证书..."
                certbot certonly \
                    --dns-cloudflare \
                    --dns-cloudflare-credentials /etc/cloudflare/credentials.ini \
                    --non-interactive \
                    --agree-tos \
                    --email "${EMAIL}" \
                    -d "${DOMAIN}" \
                    --dns-cloudflare-propagation-seconds 30
                success "证书申请成功"
            fi
        fi

        info "证书路径: ${CRT}"
        info "私钥路径: ${KEY_PEM}"

        # 证书续期钩子（certbot）
        mkdir -p /etc/letsencrypt/renewal-hooks/deploy
        cat > /etc/letsencrypt/renewal-hooks/deploy/restart-nowhere.sh << 'HOOKEOF'
#!/bin/bash
systemctl restart nowhere
HOOKEOF
        chmod +x /etc/letsencrypt/renewal-hooks/deploy/restart-nowhere.sh
    fi

    # ── 下载 Nowhere ──────────────────────────────
    step "第 5 步：下载 Nowhere"
    divider
    detect_binary
    info "正在获取最新版本号..."
    LATEST=$(curl -s https://api.github.com/repos/NodePassProject/Nowhere/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
    [ -z "$LATEST" ] && error "无法获取版本号，请检查网络"
    info "最新版本: ${LATEST}"
    info "正在下载..."
    wget --show-progress -q \
        "https://github.com/NodePassProject/Nowhere/releases/download/${LATEST}/${BIN_NAME}" \
        -O /tmp/nowhere.tar.gz
    tar -xzf /tmp/nowhere.tar.gz -C /tmp/
    BINARY_PATH=$(find /tmp -name "nowhere" -type f | head -1)
    cp "${BINARY_PATH}" /usr/local/bin/nowhere
    chmod +x /usr/local/bin/nowhere
    rm -f /tmp/nowhere.tar.gz /tmp/nowhere 2>/dev/null || true
    success "Nowhere 安装完成"

    # ── systemd 服务 ──────────────────────────────
    step "第 6 步：创建系统服务"
    divider
    cat > /etc/systemd/system/nowhere.service << SVCEOF
[Unit]
Description=Nowhere Portal
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/nowhere 'portal://${SHARED_KEY}@:${PORT}?${EXTRA_PARAMS}'
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
SVCEOF

    systemctl daemon-reload
    systemctl enable nowhere
    systemctl start nowhere
    sleep 2
    systemctl is-active --quiet nowhere && success "服务启动成功" || error "服务启动失败"

    # ── 防火墙 ──────────────────────────────────
    step "第 7 步：配置防火墙"
    divider
    ufw allow ssh 2>/dev/null || true
    ufw allow ${PORT}/tcp
    ufw allow ${PORT}/udp
    [ "$CERT_METHOD" = "letsencrypt-http" ] && ufw allow 80/tcp 2>/dev/null || true
    ufw --force enable
    success "防火墙已配置"

    # ── 保存配置并生成深链 ────────────────────────
    mkdir -p /etc/nowhere
    PORTAL_URL="portal://${SHARED_KEY}@${DOMAIN}:${PORT}?${EXTRA_PARAMS}"
    
    # 生成深链
    ANYWHERE_LINK=$(generate_deeplink "${PORTAL_URL}")

    cat > /etc/nowhere/config.txt << CONFEOF
═══════════════════════════════════════════════════════════════
  Nowhere Portal 配置信息
  安装时间: $(date '+%Y-%m-%d %H:%M:%S')
═══════════════════════════════════════════════════════════════
  服务器    : ${DOMAIN}
  端口      : ${PORT}
  密钥      : ${SHARED_KEY}
  Spec      : ${SPEC}
  证书方式  : ${CERT_METHOD}
  传输模式  : ${NET}

  Portal URL:
  ${PORTAL_URL}

  Anywhere 深链（手机点击直接导入）:
  ${ANYWHERE_LINK}

  Anywhere 手动配置:
    服务器 : ${DOMAIN}
    端口   : ${PORT}
    密钥   : ${SHARED_KEY}
    Spec   : ${SPEC}
    TLS    : 开启
    SNI    : ${DOMAIN}
    ALPN   : now/1
═══════════════════════════════════════════════════════════════
CONFEOF
    chmod 600 /etc/nowhere/config.txt

    echo ""
    echo -e "${BOLD}${GREEN}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║              ✅  安装完成！                              ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    divider
    cat /etc/nowhere/config.txt
    divider
    echo ""
    echo -e "${BOLD}✅ 导入 Anywhere 的最快方式：${NC}"
    echo -e "在手机浏览器或 Anywhere App 中打开此链接："
    echo -e "${CYAN}${ANYWHERE_LINK}${NC}"
    echo ""
    echo -e "${BOLD}常用命令：${NC}"
    echo -e "  查看状态  : ${CYAN}systemctl status nowhere${NC}"
    echo -e "  查看日志  : ${CYAN}journalctl -u nowhere -f${NC}"
    echo -e "  查看配置  : ${CYAN}cat /etc/nowhere/config.txt${NC}"
    divider
}

do_uninstall() {
    step "卸载 Nowhere"
    divider
    read -p "确认卸载？[y/N]: " CONFIRM
    [[ ! "$CONFIRM" =~ ^[Yy]$ ]] && { info "已取消"; return; }
    systemctl stop nowhere 2>/dev/null || true
    systemctl disable nowhere 2>/dev/null || true
    rm -f /etc/systemd/system/nowhere.service
    systemctl daemon-reload
    rm -f /usr/local/bin/nowhere
    rm -rf /etc/nowhere
    success "已卸载"
}

do_update() {
    step "更新 Nowhere"
    divider
    detect_binary
    LATEST=$(curl -s https://api.github.com/repos/NodePassProject/Nowhere/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
    [ -z "$LATEST" ] && error "无法获取版本号"
    info "最新版本: ${LATEST}"
    wget --show-progress -q \
        "https://github.com/NodePassProject/Nowhere/releases/download/${LATEST}/${BIN_NAME}" \
        -O /tmp/nowhere.tar.gz
    tar -xzf /tmp/nowhere.tar.gz -C /tmp/
    BINARY_PATH=$(find /tmp -name "nowhere" -type f | head -1)
    systemctl stop nowhere 2>/dev/null || true
    cp "${BINARY_PATH}" /usr/local/bin/nowhere
    chmod +x /usr/local/bin/nowhere
    rm -f /tmp/nowhere.tar.gz
    systemctl start nowhere
    sleep 2
    systemctl is-active --quiet nowhere && success "更新完成" || error "启动失败"
}

do_show_config() {
    step "连接信息"
    divider
    [ -f /etc/nowhere/config.txt ] && cat /etc/nowhere/config.txt || warn "未找到配置"
}

do_show_status() {
    step "服务状态"
    divider
    systemctl status nowhere --no-pager
    echo ""
    divider
    info "最近日志（最后20行）："
    journalctl -u nowhere -n 20 --no-pager
}

show_menu
case $MENU_CHOICE in
    1) do_install ;;
    2) do_uninstall ;;
    3) do_update ;;
    4) do_show_config ;;
    5) do_show_status ;;
    0) exit 0 ;;
    *) error "无效选择" ;;
esac
