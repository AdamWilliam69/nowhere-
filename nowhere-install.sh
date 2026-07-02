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

if [ "$EUID" -ne 0 ]; then
    error "请以 root 用户运行此脚本"
fi

clear
echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║         Nowhere Portal 一键安装脚本              ║"
echo "║         加密隧道协议 · TLS/TCP + QUIC/UDP        ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

step "第 1 步：收集配置信息"
divider
echo -e "${YELLOW}请依次输入以下信息（直接回车使用默认值）${NC}\n"

# 1. 验证域名格式循环
while true; do
    read -p "请输入你的域名（例如: node.example.com）: " DOMAIN
    DOMAIN=$(echo "$DOMAIN" | tr -d ' \r\n') # 去除空格和回车
    if [[ -z "$DOMAIN" ]]; then
        echo -e "${RED}[提示] 域名不能为空，请重新输入！${NC}"
    elif [[ "$DOMAIN" != *.* ]]; then
        echo -e "${RED}[提示] 域名格式不正确，请检查后重新输入！${NC}"
    else
        break
    fi
done

# 2. 验证邮箱格式循环 (兼容性更好的原生匹配)
while true; do
    read -p "请输入邮箱（用于证书申请）: " EMAIL
    EMAIL=$(echo "$EMAIL" | tr -d ' \r\n') # 去除可能误复制的空格和回车
    
    if [[ -z "$EMAIL" ]]; then
        echo -e "${RED}[提示] 邮箱不能为空，请重新输入！${NC}"
    elif [[ "$EMAIL" != *@*.* ]]; then
        echo -e "${RED}[提示] 邮箱格式不正确 (必须包含 @ 和 .)，请重新输入！${NC}"
    elif [[ "$EMAIL" == .* ]]; then
        echo -e "${RED}[提示] 邮箱不能以点 (.) 开头，请重新输入合法的邮箱！${NC}"
    elif [[ "${EMAIL%%@*}" == *. ]]; then
        echo -e "${RED}[提示] 邮箱前缀 (@前面) 不能以点 (.) 结尾，请重新输入合法的邮箱！${NC}"
    else
        break
    fi
done

echo ""
echo -e "${BOLD}Cloudflare 认证方式：${NC}"
echo "  1) Global API Key（推荐）"
echo "  2) API Token"
read -p "请选择 [1/2，默认1]: " CF_AUTH_TYPE
CF_AUTH_TYPE=${CF_AUTH_TYPE:-1}

if [ "$CF_AUTH_TYPE" = "1" ]; then
    while true; do
        read -p "请输入 Cloudflare Global API Key: " CF_API_KEY
        CF_API_KEY=$(echo "$CF_API_KEY" | tr -d ' \r\n')
        if [ -n "$CF_API_KEY" ]; then break; else echo -e "${RED}[提示] API Key 不能为空！${NC}"; fi
    done
else
    while true; do
        read -p "请输入 Cloudflare API Token: " CF_TOKEN
        CF_TOKEN=$(echo "$CF_TOKEN" | tr -d ' \r\n')
        if [ -n "$CF_TOKEN" ]; then break; else echo -e "${RED}[提示] API Token 不能为空！${NC}"; fi
    done
fi

echo ""
read -p "请输入监听端口（直接回车默认443）: " PORT
PORT=$(echo "$PORT" | tr -d ' \r\n')
PORT=${PORT:-443}
if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
    echo -e "${YELLOW}[警告] 端口不合法，已自动重置为默认值 443${NC}"
    PORT=443
fi

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

echo ""
divider
echo -e "${BOLD}请确认以下配置信息：${NC}"
divider
echo -e "  域名       : ${GREEN}${DOMAIN}${NC}"
echo -e "  邮箱       : ${GREEN}${EMAIL}${NC}"
echo -e "  端口       : ${GREEN}${PORT}${NC}"
echo -e "  传输模式   : ${GREEN}${NET}${NC}"
echo -e "  共享密钥   : ${GREEN}${SHARED_KEY}${NC}"
echo -e "  Spec       : ${GREEN}${SPEC}${NC}"
divider
echo ""
read -p "确认无误，开始安装？[y/N]: " CONFIRM
[[ ! "$CONFIRM" =~ ^[Yy]$ ]] && { info "已取消安装"; exit 0; }

CRT="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
KEY_PEM="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"

step "第 2 步：安装系统依赖"
divider
apt-get update -qq
apt-get install -y -qq curl wget tar ufw certbot python3-certbot-dns-cloudflare
success "系统依赖安装完成"

step "第 3 步：配置 Cloudflare 凭据"
divider
mkdir -p /etc/cloudflare
if [ "$CF_AUTH_TYPE" = "1" ]; then
cat > /etc/cloudflare/credentials.ini << CFEOF
dns_cloudflare_email = ${EMAIL}
dns_cloudflare_api_key = ${CF_API_KEY}
CFEOF
else
cat > /etc/cloudflare/credentials.ini << CFEOF
dns_cloudflare_api_token = ${CF_TOKEN}
CFEOF
fi
chmod 600 /etc/cloudflare/credentials.ini
success "Cloudflare 凭据已写入"

step "第 4 步：申请 TLS 证书"
divider
if [ -f "$CRT" ]; then
    warn "证书已存在，跳过申请"
else
    info "正在通过 DNS-01 验证申请证书，请稍候..."
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
info "证书路径: ${CRT}"
info "私钥路径: ${KEY_PEM}"

step "第 5 步：下载 Nowhere"
divider
info "正在获取最新版本号..."
LATEST=$(curl -s https://api.github.com/repos/NodePassProject/Nowhere/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
info "最新版本: ${LATEST}"

ARCH=$(uname -m)
case $ARCH in
    x86_64)  BIN="nowhere-x86_64-unknown-linux-gnu.tar.gz" ;;
    aarch64) BIN="nowhere-aarch64-unknown-linux-gnu.tar.gz" ;;
    *)       error "不支持的架构: ${ARCH}" ;;
esac

info "正在下载 ${BIN}..."
wget --show-progress -q \
     "https://github.com/NodePassProject/Nowhere/releases/download/${LATEST}/${BIN}" \
     -O /tmp/nowhere.tar.gz

info "正在解压..."
tar -xzf /tmp/nowhere.tar.gz -C /tmp/
BINARY_PATH=$(find /tmp -name "nowhere" -type f | head -1)
cp "${BINARY_PATH}" /usr/local/bin/nowhere
chmod +x /usr/local/bin/nowhere
rm -f /tmp/nowhere.tar.gz
success "Nowhere 安装完成: $(nowhere --version 2>&1 | head -1)"

step "第 6 步：创建系统服务"
divider
cat > /etc/systemd/system/nowhere.service << SVCEOF
[Unit]
Description=Nowhere Portal
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/nowhere 'portal://${SHARED_KEY}@:${PORT}?spec=${SPEC}&tls=2&net=${NET}&crt=${CRT}&key=${KEY_PEM}&log=info'
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

if systemctl is-active --quiet nowhere; then
    success "Nowhere 服务启动成功"
else
    error "服务启动失败，请运行: journalctl -u nowhere -n 30 --no-pager"
fi

step "第 7 步：配置防火墙"
divider
ufw allow ssh comment 'SSH' 2>/dev/null || true
ufw allow ${PORT}/tcp comment 'Nowhere TCP'
ufw allow ${PORT}/udp comment 'Nowhere UDP'
ufw --force enable
success "防火墙规则已配置"

step "第 8 步：配置证书自动续期"
divider
mkdir -p /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/restart-nowhere.sh << 'HOOKEOF'
#!/bin/bash
systemctl restart nowhere
HOOKEOF
chmod +x /etc/letsencrypt/renewal-hooks/deploy/restart-nowhere.sh
success "证书续期钩子已配置（90天自动续期后重启服务）"

mkdir -p /etc/nowhere
cat > /etc/nowhere/config.txt << CONFEOF
═══════════════════════════════════════════════
Nowhere Portal 配置信息
安装时间: $(date '+%Y-%m-%d %H:%M:%S')
═══════════════════════════════════════════════
服务器地址 : ${DOMAIN}
端口       : ${PORT}
共享密钥   : ${SHARED_KEY}
Spec       : ${SPEC}
TLS 模式   : tls=2（真实证书）
传输模式   : ${NET}

Portal URL:
portal://${SHARED_KEY}@${DOMAIN}:${PORT}?spec=${SPEC}&tls=2&net=${NET}

客户端填写（Anywhere App）:
服务器 : ${DOMAIN}
端口   : ${PORT}
密钥   : ${SHARED_KEY}
Spec   : ${SPEC}
TLS    : 开启
SNI    : ${DOMAIN}
ALPN   : now/1
═══════════════════════════════════════════════
CONFEOF
chmod 600 /etc/nowhere/config.txt

echo ""
echo -e "${BOLD}${GREEN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║              ✅  安装完成！                      ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"
divider
echo -e "${BOLD}客户端连接信息（Anywhere App）：${NC}"
divider
echo -e "  服务器地址 : ${GREEN}${DOMAIN}${NC}"
echo -e "  端口       : ${GREEN}${PORT}${NC}"
echo -e "  共享密钥   : ${GREEN}${SHARED_KEY}${NC}"
echo -e "  Spec       : ${GREEN}${SPEC}${NC}"
echo -e "  TLS        : ${GREEN}开启${NC}"
echo -e "  SNI        : ${GREEN}${DOMAIN}${NC}"
echo -e "  ALPN       : ${GREEN}now/1${NC}"
divider
echo -e "${BOLD}Portal URL：${NC}"
echo -e "  ${CYAN}portal://${SHARED_KEY}@${DOMAIN}:${PORT}?spec=${SPEC}&tls=2&net=${NET}${NC}"
divider
echo -e "${YELLOW}配置已保存至: /etc/nowhere/config.txt${NC}"
echo ""
echo -e "${BOLD}常用命令：${NC}"
echo -e "  查看状态 : ${CYAN}systemctl status nowhere${NC}"
echo -e "  查看日志 : ${CYAN}journalctl -u nowhere -f${NC}"
echo -e "  重启服务 : ${CYAN}systemctl restart nowhere${NC}"
echo -e "  查看配置 : ${CYAN}cat /etc/nowhere/config.txt${NC}"
echo -e "  证书续期 : ${CYAN}certbot renew${NC}"
divider
echo ""
