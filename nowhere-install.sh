#!/bin/bash
set -e
set -o pipefail

# ══════════════════════════════════════════════════════════════
#   Adam Nowhere Portal 一键管理脚本（适配 Nowhere v3.3.0 / NW3 · 集成 Snell v6 / 防火墙 / Fail2ban）
#   已按 v3.1.0 官方文档 + 真实二进制实测重写（协议线仍为 NW3，配置与 v3.0.x 兼容），v1.5.x 旧配置不兼容：
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
#   子命令：adam snell ... · adam fw ... · adam f2b ... · adam update-script（adam help 查看全部）
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
#   ── 脚本 v3 修订（2026-10-23，跟随 Nowhere v3.0.1）──
#     - 跟随 v3.0.1：新增 NOW_MORPH_TCP_PRELUDE 策略选择（默认 fade，v3.0.0 为 full8；
#       该设置只影响本机发起端、接收端通吃、不进分享链接，无需迁移密钥/URL）；
#     - 下载校验改为强制：优先用 GitHub Release API 的资产 sha256 digest 比对，
#       修复旧逻辑按校验文件名 sha256sum -c 而下载文件名为 nowhere.tar.gz、永远对不上的问题；
#     - 更新/切换版本启动失败时自动用本地备份二进制回滚，不再把服务留在宕机状态；
#     - 补齐地址族载体 tcp4/tcp6/udp4/udp6（旧版头部声称支持但向导从未提供）；
#     - Egress 连接串可带 dial=/rate=/etar=，Vector 连接串补 rate=/etar=；
#     - 安全：密钥/API Token/含密码项改 read -s 不回显、全部 read 加 -r；probe 输出打码密钥；
#       rate/etar 增加官方上限 2147483647 校验，dial 增加 IP 字面量校验；
#       防火墙启用前先放行实际 SSH 端口（防自定义 SSH 端口被 ufw 锁死）；env 写出对 SOCKS 凭证转义；
#     - 体验：重装前自动备份旧配置目录；连接信息可输出二维码（qrencode）；tls=2 也可查看证书指纹；
#       卸载时可一并清理快捷命令；GitHub API 调用统一加超时。
#   ── 脚本 v3.1 修订（2026-10-26，跟随 Nowhere v3.1.0，协议线仍为 NW3）──
#     - 版本文案：头部/菜单/连接信息由 v3.0.1 更新为 v3.1.0；v3.1.0 官方升级说明为“无需迁移，
#       URL/密钥/证书继续有效，3.0.x 与 3.1.0 可混跑”，NOW_MORPH_TCP_PRELUDE 仍为 fade 默认，
#       故旧配置无需重建，菜单 3 更新二进制即可升到 v3.1.0；
#     - v3.1.0 过渡警告：3.1.0 仍接受传统 Morph Prelude，但官方说明该兼容为过渡行为，
#       未来版本将强制 Authenticated Prelude，届时旧 3.0.x 对端会断连，故对端也应尽早同升；
#     - Egress：Portal 生成的 egress:// 补 dial4/dial6 双栈绑定（与 Portal dial 互斥规则一致：
#       dial 与 dial4/dial6 二选一，只影响 Egress 到目标的出站源地址，不影响回连 Portal 的 QUIC）；
#       新增菜单 17「本机安装为 Egress 服务」，可在出口机上直接装成 systemd 服务，无需手动跑连接串；
#     - 指纹兜底：get_tls_fingerprint 在纯 UDP（无 TCP 监听）或 TCP 探测失败时，改从当前
#       nowhere 主进程（systemctl MainPID）的 journalctl 启动日志提取指纹，兼容无冒号与冒号分隔
#       两种打印形式；取不到时仍返回失败，不伪造、不取旧进程的过期指纹（MainPID 优先，-u 兜底取最后一条）；
#     - crt=/key= 编码：build_portal_url 改用 encode_path（保留 /，只编码空格/&/#/% 等会切断 URL
#       的字符），默认 Let's Encrypt 路径输出与旧版完全一致，特殊路径不再被 & 截断；
#     - Vector 紧凑语法说明：官方端点表规定 HOST:PORT 对 Vector 只代表 TLS（对 Egress 只代表 QUIC），
#       故本脚本继续显式写 /tcp: 或 /udp:，不把 udp 载体误写成紧凑形；同端口双栈 Portal 用紧凑形
#       的 Vector 等价于 tcp 载体，已在注释中说明，不做破坏性改动；
#     - 管道安装自救：install_shortcuts 在 bash <(curl ...) 等无法定位自身文件时，
#       改从 SCRIPT_URL 重新下载一份到管理脚本路径再建快捷命令，并校验下载内容；前提是新版
#       已先推送到该 raw 地址，否则下载到的仍是旧版（此时会打印警告）。这使简短安装命令可用，
#       但交互向导仍必须用 bash <(...) 而不能用 curl | bash（后者会把脚本本身当作 read 的输入）。
#   ── 脚本 v4.0 修订（2026-11-16，跟随 Nowhere v3.3.0，协议线仍为 NW3）──
#     跟随上游 v3.2.0 / v3.3.0：
#     - Egress 统一载体（v3.3.0）：egress:// 可走 QUIC/UDP 或 TLS/TCP（TLS Hydra 连接池），纯 TCP 的
#       Portal 也能用 out=egress；同一 Portal 可同时接多台 Egress（旧文案"只接受一个 Egress"已过时，
#       BUSY 现在表示 TLS 待命容量已满）；没有可用 Egress 时新 Flow 在 NOW_FLOW_SETUP_TIMEOUT 内等待而非立即失败；
#       菜单 17 可直接粘贴 Portal 生成的 egress:// 连接串，并可选 TLS 载体；
#     - 新增 NOW_MORPH_UDP_PRELUDE（v3.3.0）。Prelude 策略只对发起端（Vector/Egress）生效，Portal 不使用，
#       故不再写进 Portal 的 unit，改为写进 Egress 的 unit 与生成的 Vector/Egress 启动命令（旧版 Egress 服务反而没设）；
#     - v3.2.0 起 Portal 强制 Authenticated Prelude：升级跨过 v3.2.0 时提示对端需 ≥ v3.1.0；
#     - 记录本机角色（portal/egress），pz/zt/cq/指纹/probe/证书等命令不再把 Egress 机当 Portal 处理。
#     修复：
#     - 主菜单改为循环，动作在子 shell 执行：失败、error、Ctrl+C 只结束当前动作并回到菜单；
#     - zt/菜单 6 在服务停止时因 set -e 提前退出、看不到后面的日志；
#     - python3 未安装时（向导在装依赖之前就做输入校验）dial 等合法输入被误判；Release digest 解析用了
#       Python 3.9+ 的 removeprefix，旧系统上校验被静默跳过；
#     - acme.sh（DNS-01 通用）分支：证书目录不存在导致 install-cert 失败、默认 CA 实为 ZeroSSL 而非文案所说的
#       Let's Encrypt（现显式 --server letsencrypt），证书改放 /etc/nowhere/certs 不再混入 certbot 的 live 目录；
#     - 证书域名匹配由子串 grep 改为逐项精确比对（支持通配符证书、不再误匹配前缀相同的域名）；
#     - 自签模式不再强制填写邮箱；域名/地址输入增加字符集校验（这些值会写入被 source 的配置文件）；
#     - 安装时不再无条件 ufw --force enable：已启用则只加规则，未启用先列出未放行的监听端口再询问；
#       重新配置换端口后清理旧端口的放行规则；卸载可一并清理放行规则、Cloudflare 凭证、续期 cron；
#     - GitHub API 被限流时改用 releases/latest 跳转取版本号；下载/校验/解压逻辑由三份合并为一处并增加试运行；
#       更新二进制改为替换后一次 restart；管理脚本副本改用 install 覆盖（不原地改写运行中的脚本）；
#     - Morph 开启时跳过必然失败的 openssl s_client 指纹兜底（最长白等约 45 秒）。
#     新增：
#     - 菜单 18 Snell v6：从 Surge 官方发布页取最新版本一键安装，systemd 定时器每日检查并自动升级
#       （仅 v6 系列内、默认只跟正式版、失败自动回滚）；
#     - 菜单 19 防火墙（ufw）、菜单 20 Fail2ban：菜单结构参考 3x-ui，均可用 adam fw / adam f2b 子命令操作；
#     - 菜单 21 / adam update-script：更新本管理脚本。
#   ── 脚本 v4.1 修订（2026-11-16）──
#     - Snell：默认改为 beta 通道，跟随官方最新测试版（b / rc），正式版发布后自动转正式版；版本发现在
#       发布页之外增加按官方版本演进顺序的下载站探测（多轮、并行），发布页取不到也能自动发现新版本；
#       新增健康检查与一键修复；服务单元改为 Restart=always 且不限启动次数；监听端口加入内核保留端口。
#     - 菜单 22 Xray（SS2022 / VLESS）：REALITY Vision、XHTTP REALITY、XHTTP 过 CDN（TLS 或明文回源）、
#       VLESS Encryption（ML-KEM-768 / X25519）；独立目录与服务（adam-xray），多节点、分享链接；
#       默认跟随 XTLS/Xray-core 最新发布（含预发布），官方 .dgst 校验，新内核先校验现有配置再替换，失败回滚。
#     - 菜单 23 系统与网络调优：TCP 调优调用 Kylin010/tcpfit（拉取 + 校验 + 安装后运行）；XanMod 内核
#       安装 / 卸载；DNS 设置；IPv4 / IPv6 优先级；临时 / 永久禁用 IPv6（均可恢复）。
#     - 菜单 24 自动维护：每 5 分钟保活巡检（服务退出或端口不监听时重启）；每日任务依次做
#       管理脚本从仓库自更新、Snell / Xray 跟随官方更新、证书同步、可选每日重启。原 adam-snell-update 定时器并入。
# ══════════════════════════════════════════════════════════════

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'
if [ ! -t 1 ]; then
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; NC=''
fi

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
SCRIPT_VERSION="4.1"   # 本管理脚本自身的修订版本（与 Nowhere 版本号相互独立）
TARGET_NW_VERSION="v3.3.0"   # 本脚本文案与向导所对照的 Nowhere 版本
MORPH_TCP_PRELUDE="fade"  # NOW_MORPH_TCP_PRELUDE：fade(v3.0.1起默认，v3.1.0不变)/full8/low7，仅影响本机发起的 Morph TCP 连接
TCP_FAMILY=""             # 监听地址族限制：""/4/6 -> tcp/tcp4/tcp6
UDP_FAMILY=""             # 同上 -> udp/udp4/udp6
EGRESS_DIAL="auto"        # Egress 端目标出站源地址（在出口机上生效）
EGRESS_DIAL_MODE="single"   # Egress dial 模式：single 用 dial=，dual 用 dial4=/dial6=，二选一
EGRESS_DIAL4="auto"       # Egress 端 IPv4 目标出站源地址
EGRESS_DIAL6="auto"       # Egress 端 IPv6 目标出站源地址
SCRIPT_URL="https://raw.githubusercontent.com/AdamWilliam69/nowhere-/main/nowhere-install.sh"
EGRESS_CONFIG_FILE="${CONFIG_DIR}/egress.env"
EGRESS_CONFIG_TXT="${CONFIG_DIR}/egress-config.txt"
ROLE_FILE="${CONFIG_DIR}/role"   # 本机 nowhere.service 的角色：portal / egress
MORPH_UDP_PRELUDE="fade"  # NOW_MORPH_UDP_PRELUDE（v3.3.0 新增）：fade/full8/low7，仅 Morph QUIC 发起端使用
EGRESS_CARRIER="udp"      # 生成 egress:// 时使用的回连载体：udp(QUIC) / tcp(TLS，v3.3.0 起)

# Snell（Surge 官方）
SNELL_MAJOR="6"
SNELL_BIN="/usr/local/bin/snell-server"
SNELL_BIN_BACKUP="/usr/local/bin/snell-server.previous"
SNELL_DIR="/etc/snell"
SNELL_CONF="${SNELL_DIR}/snell-server.conf"
SNELL_VERSION_FILE="${SNELL_DIR}/version.txt"
SNELL_STATE_FILE="${SNELL_DIR}/adam-snell.env"
SNELL_SERVICE="/etc/systemd/system/snell.service"
SNELL_DL_BASE="https://dl.nssurge.com/snell"
SNELL_KB_URLS=(
    "https://kb.nssurge.com/surge-knowledge-base/release-notes/snell.md"
    "https://kb.nssurge.com/surge-knowledge-base/release-notes/snell"
)

SNELL_BASELINE_VERSION="v6.0.0"   # 未安装且发布页取不到时的探测起点（之后的版本靠探测自动发现）

# Xray（独立于官方安装脚本与 3x-ui）
XRAY_REPO="XTLS/Xray-core"
XRAY_DIR="/opt/adam-xray"
XRAY_BIN="${XRAY_DIR}/xray"
XRAY_CONF_DIR="/etc/adam-xray"
XRAY_CONF_D="${XRAY_CONF_DIR}/conf.d"
XRAY_NODE_DIR="${XRAY_CONF_DIR}/nodes"
XRAY_CERT_DIR="${XRAY_CONF_DIR}/certs"
XRAY_STATE_FILE="${XRAY_CONF_DIR}/adam-xray.env"
XRAY_SERVICE="/etc/systemd/system/adam-xray.service"

# 自动维护（保活 / 自动更新）
MAINT_DIR="/etc/adam"
MAINT_ENV="${MAINT_DIR}/maintain.env"
MAINT_LOG="/var/log/adam-maintain.log"
MAINT_LOCK="/run/adam-maintain.lock"
RESERVED_PORTS_FILE="/etc/sysctl.d/99-adam-reserved-ports.conf"

# 系统与网络调优
TCPFIT_RAW="https://raw.githubusercontent.com/Kylin010/tcpfit/main"
TCPFIT_BIN="/usr/local/bin/tcpfit"
DNS_DROPIN="/etc/systemd/resolved.conf.d/90-adam-dns.conf"
DNS_RESOLV_BACKUP="${MAINT_DIR}/resolv.conf.orig"
GAI_BACKUP="${MAINT_DIR}/gai.conf.orig"
IPV6_DISABLE_FILE="/etc/sysctl.d/99-adam-disable-ipv6.conf"

# Fail2ban
F2B_JAIL="sshd"
F2B_JAIL_FILE="/etc/fail2ban/jail.d/adam-sshd.local"
F2B_LOG="/var/log/fail2ban.log"

info()    { echo -e "${BLUE}[信息]${NC} $1"; }
success() { echo -e "${GREEN}[成功]${NC} $1"; }
warn()    { echo -e "${YELLOW}[警告]${NC} $1"; }
error()   { echo -e "${RED}[错误]${NC} $1"; exit 1; }
step()    { echo -e "\n${BOLD}${CYAN}━━━ $1 ━━━${NC}"; }
divider() { echo -e "${CYAN}────────────────────────────────────────────────────────${NC}"; }

[ "$EUID" -ne 0 ] && error "请以 root 用户运行此脚本"

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

# 新建临时工作目录，路径写入全局 WORKDIR（不能用 $(...) 调用，否则登记会丢在子 shell 里）
make_workdir() {
    WORKDIR="$(mktemp -d /tmp/adam-work.XXXXXX)"
    _CLEANUP_DIRS+=("$WORKDIR")
}

# confirm "提示" [y|n]：第二个参数是回车时的默认值
confirm() {
    local prompt="$1" def="${2:-n}" ans=""
    if [ "$def" = "y" ]; then
        read -rp "${prompt} [Y/n]: " ans || true
        [[ ! "$ans" =~ ^[Nn]$ ]]
    else
        read -rp "${prompt} [y/N]: " ans || true
        [[ "$ans" =~ ^[Yy]$ ]]
    fi
}

pause_return() {
    echo ""
    read -rp "按回车返回菜单..." _ || true
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

pkg_installed() {
    local s
    s="$(dpkg-query -W -f='${Status}' "$1" 2>/dev/null || true)"
    [ "$s" = "install ok installed" ]
}

# 按需安装软件包：已安装的跳过，一次运行内只 apt-get update 一次
APT_UPDATED=0
apt_install() {
    local p
    local -a need=()
    for p in "$@"; do
        if ! pkg_installed "$p"; then need+=("$p"); fi
    done
    if [ "${#need[@]}" -eq 0 ]; then return 0; fi
    if ! command -v apt-get >/dev/null 2>&1; then
        warn "未找到 apt-get（本脚本仅支持 Debian/Ubuntu），请手动安装: ${need[*]}"
        return 1
    fi
    if [ "$APT_UPDATED" != "1" ]; then
        apt-get update -qq || warn "apt-get update 失败，继续尝试安装"
        APT_UPDATED=1
    fi
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${need[@]}"
}

# 向导里的输入校验依赖 python3（IP 字面量校验、URL 编码、Release digest 解析），
# 旧版要到「安装系统依赖」那一步才装，精简镜像上会在此之前把合法输入误判为不合法。
ensure_prereqs() {
    local -a need=()
    command -v curl >/dev/null 2>&1 || need+=(curl)
    command -v python3 >/dev/null 2>&1 || need+=(python3)
    command -v openssl >/dev/null 2>&1 || need+=(openssl)
    if [ "${#need[@]}" -gt 0 ]; then
        info "先安装向导所需的基础工具: ${need[*]}"
        apt_install "${need[@]}" || warn "基础工具安装失败，后续的输入校验可能不准确"
    fi
    return 0
}

# version_ge A B：A >= B（只比较 X.Y.Z 数字部分；解析不了的按 0.0.0 处理）
version_ge() {
    local a="${1#v}" b="${2#v}" i x y
    local -a A=() B=()
    IFS=. read -r -a A <<< "${a%%[^0-9.]*}"
    IFS=. read -r -a B <<< "${b%%[^0-9.]*}"
    for i in 0 1 2; do
        x="${A[$i]:-0}"; y="${B[$i]:-0}"
        [[ "$x" =~ ^[0-9]+$ ]] || x=0
        [[ "$y" =~ ^[0-9]+$ ]] || y=0
        if (( 10#$x > 10#$y )); then return 0; fi
        if (( 10#$x < 10#$y )); then return 1; fi
    done
    return 0
}

# 本机 nowhere.service 当前扮演的角色：portal / egress / none
current_role() {
    local r=""
    if [ -f "$ROLE_FILE" ]; then r="$(tr -d ' \r\n' < "$ROLE_FILE" 2>/dev/null || true)"; fi
    case "$r" in portal|egress) printf '%s' "$r"; return 0 ;; esac
    if [ -f "$SERVICE_FILE" ] && grep -q 'NOWHERE_EGRESS' "$SERVICE_FILE" 2>/dev/null; then
        printf 'egress'
    elif [ -f "$CONFIG_FILE" ]; then
        printf 'portal'
    else
        printf 'none'
    fi
    return 0
}

# 最新 Release tag：先问 GitHub API；被限流（共享出口 IP 很常见，未认证 60 次/小时）
# 时改为解析 releases/latest 的跳转地址，不依赖 API。
get_latest_tag() {
    local tag=""
    tag="$(curl -fsS --max-time 20 "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
        | grep -m1 '"tag_name"' | cut -d'"' -f4 || true)"
    if [ -z "$tag" ]; then
        tag="$(curl -fsSI --max-time 20 "https://github.com/${REPO}/releases/latest" 2>/dev/null \
            | tr -d '\r' | awk 'tolower($1)=="location:" {print $2}' | sed -n 's#.*/tag/##p' | tail -1 || true)"
    fi
    printf '%s' "$tag"
}

# 下载 + 校验 + 解压 + 试运行指定 tag 的二进制；成功后路径写入全局 DL_BINARY。
# 旧版把这段逻辑在三个函数里各抄了一遍，这里收敛成一处。
fetch_nowhere_release() {
    local tag="$1" url
    detect_binary
    DL_BINARY=""
    make_workdir
    local workdir="$WORKDIR"
    url="https://github.com/${REPO}/releases/download/${tag}/${BIN_NAME}"
    if ! curl -fL --retry 3 --connect-timeout 10 -o "$workdir/nowhere.tar.gz" "$url"; then
        warn "下载失败（该版本可能没有 ${ARCH_NAME}-${LIBC} 的发布文件）: ${url}"
        return 1
    fi
    verify_release_checksum "$tag" "$workdir" || { warn "安装包 SHA256 校验失败，已中止"; return 1; }
    tar -xzf "$workdir/nowhere.tar.gz" -C "$workdir/" || { warn "解压失败"; return 1; }
    DL_BINARY="$(find "$workdir" -type f -name nowhere | head -1)"
    if [ -z "$DL_BINARY" ]; then warn "解压后未找到 nowhere 二进制"; return 1; fi
    chmod 755 "$DL_BINARY"
    if ! "$DL_BINARY" --version >/dev/null 2>&1; then
        warn "下载到的二进制无法在本机运行（架构或 libc 不匹配），已中止，现有安装未被改动"
        return 1
    fi
    return 0
}

# 升级跨过关键版本时的互通提醒（依据官方 v3.2.0 / v3.3.0 文档）
print_upgrade_notes() {
    local from="$1" to="$2"
    if version_ge "$to" "v3.2.0" && ! version_ge "$from" "v3.2.0"; then
        warn "v3.2.0 起 Portal 强制 Authenticated Prelude、不再有回退：仍停留在 v3.0.x 的 Vector/Egress/Anywhere 在 morph=1 的 TLS/TCP 载体上会被静默拒绝"
        warn "请把所有对端升级到 ≥ v3.1.0（建议与本机同版本）；QUIC 载体与 morph=0 不受这条影响"
    fi
    if version_ge "$to" "v3.3.0" && ! version_ge "$from" "v3.3.0"; then
        info "v3.3.0 新增：Egress 可走 TLS/TCP（egress://KEY@HOST/tcp:PORT）、多台 Egress 可同时注册、NOW_MORPH_UDP_PRELUDE、握手超时默认按共享密钥派生（3–30s）"
        info "现有 URL / 密钥 / 证书无需迁移；要用 TLS 载体的 Egress，出口机也需 ≥ v3.3.0"
    fi
    return 0
}

# SSH 实际监听端口（空格分隔）：当前会话端口 + sshd 生效配置 + 实际监听，取并集
detect_ssh_ports() {
    local ports="" p
    p="$(echo "${SSH_CONNECTION:-}" | awk '{print $4}')"
    if [[ "$p" =~ ^[0-9]+$ ]]; then ports="$p"; fi
    if command -v sshd >/dev/null 2>&1; then
        ports="${ports} $(sshd -T 2>/dev/null | awk '/^port /{print $2}' | tr '\n' ' ' || true)"
    fi
    if command -v ss >/dev/null 2>&1; then
        ports="${ports} $(ss -tlnp 2>/dev/null | awk '/"sshd"/ {n=split($4,a,":"); print a[n]}' | tr '\n' ' ' || true)"
    fi
    # shellcheck disable=SC2086
    ports="$(printf '%s\n' $ports | awk '/^[0-9]+$/ && $1>=1 && $1<=65535' | sort -un | tr '\n' ' ' || true)"
    ports="${ports% }"
    printf '%s' "${ports:-22}"
}

# is_ip ADDR [1=允许 CIDR]
is_ip() {
    local v="${1:-}" cidr="${2:-0}"
    [ -n "$v" ] || return 1
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import ipaddress,sys
v = sys.argv[1]
try:
    if sys.argv[2] == "1" and "/" in v:
        ipaddress.ip_network(v, strict=False)
    else:
        ipaddress.ip_address(v)
except Exception:
    sys.exit(1)' "$v" "$cidr" 2>/dev/null
        return $?
    fi
    local re4='^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$' re6='^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$'
    if [[ "$v" =~ $re4 ]]; then return 0; fi
    if [[ "$v" == *:* ]] && [[ "$v" =~ $re6 ]]; then return 0; fi
    return 1
}

# 主机名 / IP（可带方括号的 IPv6）字符集校验：这些值会写进被 source 的配置文件
is_safe_host() {
    local re='^[][A-Za-z0-9.:_-]+$'
    [[ -n "${1:-}" && "$1" =~ $re ]]
}

svc_state() {
    if systemctl is-active --quiet "$1" 2>/dev/null; then
        printf '%s' "${GREEN}运行中${NC}"
    else
        printf '%s' "${RED}未运行${NC}"
    fi
}

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
        read -rp "仍要安装该旧版本吗？[y/N]: " OLD_CONFIRM
        if [[ ! "$OLD_CONFIRM" =~ ^[Yy]$ ]]; then
            info "已取消"
            return 1
        fi
    fi
    if [ -n "$major" ] && [ "$major" -gt 3 ]; then
        warn "目标版本 ${target_tag} 属于新的协议代（NW${major}），本脚本只适配 NW3：URL 语法、密钥格式、对端兼容性都可能已变化"
        read -rp "仍要安装吗？[y/N]: " NEW_CONFIRM
        if [[ ! "$NEW_CONFIRM" =~ ^[Yy]$ ]]; then
            info "已取消"
            return 1
        fi
    fi

    info "下载并校验 ${target_tag} (${ARCH_NAME}-${LIBC}) ..."
    fetch_nowhere_release "$target_tag" || return 1

    local cur_tag
    cur_tag="$(read_installed_version)"
    install -d -m 700 "$CONFIG_DIR"
    if [ -f "$BIN_PATH" ]; then
        cp "$BIN_PATH" "$BIN_BACKUP_PATH"
        echo "$cur_tag" > "$PREV_VERSION_FILE"
    fi

    # install 会先删除旧文件再写入新文件，运行中的进程不受影响；随后一次 restart 完成切换，
    # 比旧版的 stop -> 替换 -> start 少一段停机窗口
    install -m 755 "$DL_BINARY" "$BIN_PATH"
    record_installed_version "$target_tag"

    if [ ! -f "$SERVICE_FILE" ]; then
        success "二进制已更新到 ${target_tag}（未检测到 nowhere.service，未启动服务）"
        return 0
    fi

    systemctl restart nowhere 2>/dev/null || true
    sleep 2

    if systemctl is-active --quiet nowhere; then
        success "已切换到 ${target_tag}: $(${BIN_PATH} --version 2>&1 | head -1)"
        print_upgrade_notes "$cur_tag" "$target_tag"
        return 0
    fi

    warn "新版本启动失败，日志如下："
    journalctl -u nowhere -n 20 --no-pager || true
    # 启动失败自动用本地备份二进制回滚，不把服务留在宕机状态
    if [ -f "$BIN_BACKUP_PATH" ]; then
        warn "正在自动回滚到备份二进制${cur_tag:+（${cur_tag}）}..."
        install -m 755 "$BIN_BACKUP_PATH" "$BIN_PATH"
        [ -n "$cur_tag" ] && record_installed_version "$cur_tag"
        systemctl restart nowhere 2>/dev/null || true
        sleep 2
        if systemctl is-active --quiet nowhere; then
            success "已自动回滚，服务恢复运行: $(${BIN_PATH} --version 2>&1 | head -1)"
        else
            warn "回滚后服务仍未启动，请立即查看日志: journalctl -u nowhere -n 50 --no-pager"
        fi
    fi
    return 1
}

# ── 通用小工具 ────────────────────────────────────────────────

urlencode() {
    local input="${1:-}"
    python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$input" 2>/dev/null \
        || echo -n "$input" | od -An -tx1 | tr ' ' % | tr -d '\n'
}

# 编码文件路径（crt=/key= 的值）：保留 / 不编码，只编码空格、&、#、% 等会切断 URL 查询串
# 的字符。默认 Let's Encrypt 路径不含这些字符，输出与旧版逐字相同；特殊路径不再被 & 截断。
# 注意：不能用 urlencode（safe=""）把 / 编成 %2F，那会改变路径原意。
encode_path() {
    local input="${1:-}"
    python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe="/"))' "$input" 2>/dev/null \
        || printf '%s' "$input"
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
    local detected="" u
    for u in https://api.ipify.org https://ipv4.icanhazip.com https://ifconfig.me/ip; do
        detected="$(curl -4fsS --max-time 4 "$u" 2>/dev/null | tr -d ' \r\n' || true)"
        if [[ "$detected" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then break; fi
        detected=""
    done
    if [ -z "$detected" ]; then
        # 纯 IPv6 机器：旧版只查 IPv4，取不到就退回 hostname -I 的第一个地址（可能是内网地址）
        detected="$(curl -6fsS --max-time 4 https://api64.ipify.org 2>/dev/null | tr -d ' \r\n' || true)"
        [[ "$detected" =~ ^[0-9A-Fa-f:]+$ ]] || detected=""
    fi
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

# rate/etar 官方取值范围 0..=2147483647（Mbps），超出会被 v3 在启动时直接拒绝
validate_rate() {
    [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -le 2147483647 ]
}

# dial/dial4/dial6 只接受 IP 字面量或 auto；fam: any/4/6，IPv6 时拒绝 IPv4-mapped 地址
validate_ip_or_auto() {
    local v="${1:-}" fam="${2:-any}"
    [ "$v" = "auto" ] && return 0
    [ -n "$v" ] || return 1
    python3 -c 'import ipaddress,sys
try: ip = ipaddress.ip_address(sys.argv[1])
except Exception: sys.exit(1)
fam = sys.argv[2]
if fam == "4" and ip.version != 4: sys.exit(1)
if fam == "6" and (ip.version != 6 or ip.ipv4_mapped is not None): sys.exit(1)
sys.exit(0)' "$v" "$fam" 2>/dev/null
}

# 把值安全地写进双引号 env 行：转义 \ " $ `，避免 source 配置文件时被展开/截断
dq_escape() {
    local v="$1"
    v="${v//\\/\\\\}"
    v="${v//\"/\\\"}"
    v="${v//$/\\$}"
    v="${v//\`/\\\`}"
    printf '%s' "$v"
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
    local host tcp_seg udp_seg
    if [[ -z "$LISTEN_HOST" || "$LISTEN_HOST" == "*" ]]; then
        host="*"
    else
        host="$(format_host_for_url "$LISTEN_HOST")"
    fi
    tcp_seg="tcp${TCP_FAMILY:-}"
    udp_seg="udp${UDP_FAMILY:-}"
    if [[ "$PORT_MODE" == "split" ]]; then
        printf '%s/%s:%s/%s:%s' "$host" "$tcp_seg" "$TCP_PORT" "$udp_seg" "$UDP_PORT"
    else
        case "$NET" in
            tcp) printf '%s/%s:%s' "$host" "$tcp_seg" "$PORT" ;;
            udp) printf '%s/%s:%s' "$host" "$udp_seg" "$PORT" ;;
            *)   # 同端口双栈：地址族受限时不能用紧凑形 HOST:PORT，必须写显式载体路径
                 if [[ -n "${TCP_FAMILY:-}" || -n "${UDP_FAMILY:-}" ]]; then
                     printf '%s/%s:%s/%s:%s' "$host" "$tcp_seg" "$PORT" "$udp_seg" "$PORT"
                 else
                     printf '%s:%s' "$host" "$PORT"
                 fi ;;
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
        query="${query}&crt=$(encode_path "$CRT")&key=$(encode_path "$KEY_PEM")"
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
# 注意：官方端点表规定 HOST:PORT 紧凑形对 Vector 只代表 TLS（对 Egress 只代表 QUIC），
# 不是“双栈自动选”，所以这里不把 udp 载体写成紧凑形；同端口双栈 Portal 的紧凑形 Vector
# 等价于 tcp 载体，显式写法与之一致且更明确。
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
        carrier="udp${UDP_FAMILY:-}"
    else
        port="$(tcp_port)"
        carrier="tcp${TCP_FAMILY:-}"
    fi

    query="in=$(encode_socks "$VECTOR_SOCKS")&morph=${MORPH}"
    [[ -n "$RATE" && "$RATE" != "0" ]] && query="${query}&rate=${RATE}"
    [[ -n "$ETAR" && "$ETAR" != "0" ]] && query="${query}&etar=${ETAR}"
    local trust_query
    if trust_query="$(append_trust_params "$query")"; then
        query="$trust_query"
    else
        warn "未能获取自签证书指纹，Vector 连接串暂缺 pin=（服务启动后可用菜单 5 重新生成）"
    fi
    VECTOR_URL="vector://${SHARED_KEY}@${host_part}/${carrier}:${port}?${query}"
}

# 远程 Egress 出口：egress://KEY@HOST/udp:PORT 或 /tcp:PORT，在出口机上运行，无需其开放入站端口。
# v3.3.0 起 Egress 可走 QUIC 或 TLS（一个连接串只选一种载体）；紧凑形 HOST:PORT 对 Egress 代表 QUIC，
# 这里始终写显式载体路径。
build_egress_info() {
    EGRESS_URL=""
    [ "$GENERATE_EGRESS" != "1" ] && return 0

    local host host_part port query carrier
    host="${PUBLIC_HOST:-}"
    [[ -z "$host" ]] && host="$(detect_public_host)"
    if [[ -z "$host" ]]; then
        warn "未能确定公网地址，无法生成 Egress 连接串，可稍后通过菜单「5) 查看连接信息」重试"
        return 0
    fi
    host_part="$(format_host_for_url "$host")"
    if [[ "${EGRESS_CARRIER:-udp}" == "tcp" ]] && has_tcp; then
        port="$(tcp_port)"; carrier="tcp${TCP_FAMILY:-}"
    elif has_udp; then
        port="$(udp_port)"; carrier="udp${UDP_FAMILY:-}"
    else
        port="$(tcp_port)"; carrier="tcp${TCP_FAMILY:-}"
    fi

    query="morph=${MORPH}"
    # dial 与 dial4/dial6 互斥（官方配置表）：dual 时只出 dial4/dial6，single 时只出 dial
    if [[ "${EGRESS_DIAL_MODE:-single}" == "dual" ]]; then
        [[ -n "${EGRESS_DIAL4:-}" && "$EGRESS_DIAL4" != "auto" ]] && query="${query}&dial4=$(urlencode "$EGRESS_DIAL4")"
        [[ -n "${EGRESS_DIAL6:-}" && "$EGRESS_DIAL6" != "auto" ]] && query="${query}&dial6=$(urlencode "$EGRESS_DIAL6")"
    elif [[ -n "${EGRESS_DIAL:-}" && "$EGRESS_DIAL" != "auto" ]]; then
        query="${query}&dial=$(urlencode "$EGRESS_DIAL")"
    fi
    [[ -n "$RATE" && "$RATE" != "0" ]] && query="${query}&rate=${RATE}"
    [[ -n "$ETAR" && "$ETAR" != "0" ]] && query="${query}&etar=${ETAR}"
    local trust_query
    if trust_query="$(append_trust_params "$query")"; then
        query="$trust_query"
    else
        warn "未能获取自签证书指纹，Egress 连接串暂缺 pin=（服务启动后可用菜单 5 重新生成）"
    fi
    EGRESS_URL="egress://${SHARED_KEY}@${host_part}/${carrier}:${port}?${query}"
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
        carrier="udp${UDP_FAMILY:-}"
    else
        carrier="tcp${TCP_FAMILY:-}"
        port="$(tcp_port)"
    fi
    query="morph=${MORPH}"
    local trust_query
    if trust_query="$(append_trust_params "$query")"; then
        query="$trust_query"
    fi
    printf 'vector://%s@%s/%s:%s?%s' "$SHARED_KEY" "$host_part" "$carrier" "$port" "$query"
}

# 从当前 nowhere 服务的启动日志提取指纹（供纯 UDP / TCP 探测失败时兜底）。
# 关键点：优先用 systemctl 的 MainPID 过滤，只取当前进程的日志，避免取到上一次重启
# （tls=1 指纹每次重启都会变）的过期指纹；MainPID 取不到时才用 -u 取最后一条。
# 日志里指纹可能是不带冒号的 64 位 hex，也可能是 AA:BB:... 冒号分隔形，两种都兼容，
# 统一输出为不带冒号的小写 hex。取不到返回 1，不输出、不伪造。
get_fingerprint_from_journal() {
    local log fp
    local main_pid
    main_pid="$(systemctl show -p MainPID --value nowhere 2>/dev/null | tr -d ' \r\n' || true)"
    if [[ "$main_pid" =~ ^[0-9]+$ ]] && [ "$main_pid" != "0" ]; then
        log="$(journalctl -u nowhere _PID="$main_pid" --no-pager 2>/dev/null || true)"
        fp="$(printf '%s' "$log" | grep -i 'fingerprint' | grep -oE '[0-9a-fA-F]{64}' | tail -1 | tr 'A-F' 'a-f' || true)"
        if [ -z "$fp" ]; then
            fp="$(printf '%s' "$log" | grep -i 'fingerprint' | grep -oE '([0-9a-fA-F]{2}:){31}[0-9a-fA-F]{2}' | tail -1 | tr -d ':' | tr 'A-F' 'a-f' || true)"
        fi
        if [ -n "$fp" ]; then
            printf '%s' "$fp"
            return 0
        fi
    fi
    log="$(journalctl -u nowhere -n 500 --no-pager 2>/dev/null || true)"
    fp="$(printf '%s' "$log" | grep -i 'fingerprint' | grep -oE '[0-9a-fA-F]{64}' | tail -1 | tr 'A-F' 'a-f' || true)"
    if [ -z "$fp" ]; then
        fp="$(printf '%s' "$log" | grep -i 'fingerprint' | grep -oE '([0-9a-fA-F]{2}:){31}[0-9a-fA-F]{2}' | tail -1 | tr -d ':' | tr 'A-F' 'a-f' || true)"
    fi
    if [ -n "$fp" ]; then
        printf '%s' "$fp"
        return 0
    fi
    return 1
}

# 纯获取指纹（64 位小写 hex，无冒号），不打印不警告，供 pin= 拼接用
# 顺序：官方 nowhere fingerprint（自动处理 Morph）-> 启动日志兜底 -> openssl s_client
# 纯 UDP 时没有 TCP/TLS 监听，第一步和第三步都不可用，只剩日志兜底。
get_tls_fingerprint() {
    [[ "$TLS_MODE" != "1" ]] && return 1
    local jfp
    if ! has_tcp; then
        jfp="$(get_fingerprint_from_journal 2>/dev/null || true)"
        if [ -n "$jfp" ]; then
            printf '%s' "$jfp"
            return 0
        fi
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
    jfp="$(get_fingerprint_from_journal 2>/dev/null || true)"
    if [ -n "$jfp" ]; then
        printf '%s' "$jfp"
        return 0
    fi
    # Morph 开启时 TLS 包在 Morph 信封里，openssl s_client 不可能握手成功，
    # 旧版会在这里白等 5 轮（最长约 45 秒）再失败
    if [ "${MORPH:-1}" = "1" ]; then return 1; fi
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
    if [[ "$TLS_MODE" == "2" ]]; then
        # tls=2：直接对证书文件算指纹（需要 pin= 的对端在证书续期后要同步更新）
        if [[ -n "${CRT:-}" && -f "$CRT" ]]; then
            local fp2
            fp2="$(openssl x509 -in "$CRT" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f' || true)"
            if [ -n "$fp2" ]; then
                echo
                info "当前 tls=2 证书 SHA-256 指纹（续期后会变化）："
                echo -e "  ${GREEN}${fp2}${NC}"
            fi
        fi
        return 0
    fi
    if [[ "$TLS_MODE" != "1" ]]; then
        return 0
    fi
    if ! has_tcp; then
        # 纯 QUIC/UDP：先走日志兜底，能取到就直接打印，取不到再提示手动查日志
        local journal_fp
        journal_fp="$(get_tls_fingerprint 2>/dev/null || true)"
        if [ -n "$journal_fp" ]; then
            echo
            info "已从当前服务启动日志读取到自签证书 SHA-256 指纹："
            echo -e "  ${GREEN}${journal_fp}${NC}"
            warn "tls=1 证书只存在内存中，Nowhere 每次重启后指纹都会变化，pin= 需同步重新生成（菜单 5 或 pz 命令）"
        else
            warn "当前为纯 QUIC/UDP Portal，没有 TLS 监听，且启动日志中未找到指纹"
            warn "自签模式下 Vector/Egress 的 pin 请从 Portal 启动日志含 fingerprint 的一行获取"
        fi
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

# 确保管理脚本副本存在于 MANAGER_PATH（快捷命令和 Snell 自动更新定时器都依赖它）。
# 一律"先写临时文件再 install 覆盖"：install 会换一个新 inode，另一个会话里正在运行的
# 旧副本不会被原地改写而执行错乱（旧版用 cp / curl -o 直接覆盖，存在这个问题）。
ensure_manager_copy() {
    local self_path tmp
    self_path="$(readlink -f "$0" 2>/dev/null || true)"

    if [ -z "$self_path" ] || [ ! -f "$self_path" ] || ! grep -q "Adam Nowhere" "$self_path" 2>/dev/null; then
        # 管道/进程替换运行：$0 指向 /dev/fd/63、bash 或匿名管道，无法直接复制自身。
        # 但这不等于装不了：从 SCRIPT_URL 重新下载一份到管理脚本路径即可。
        # 前提：新版必须已先推送到该 raw 地址；否则下载到的是旧版，下面会打印警告。
        info "通过管道/进程替换运行，无法直接复制自身，正在从脚本地址重新下载一份..."
        local dl_ok=0
        tmp="$(mktemp /tmp/adam-manager.XXXXXX)"
        if command -v curl >/dev/null 2>&1; then
            curl -fsSL --max-time 30 "$SCRIPT_URL" -o "$tmp" 2>/dev/null && dl_ok=1
        elif command -v wget >/dev/null 2>&1; then
            wget -qO "$tmp" "$SCRIPT_URL" 2>/dev/null && dl_ok=1
        fi
        if [ "$dl_ok" != "1" ] || [ ! -s "$tmp" ] || ! grep -q "Adam Nowhere" "$tmp" 2>/dev/null || ! bash -n "$tmp" 2>/dev/null; then
            rm -f "$tmp"
            warn "重新下载脚本失败，管理脚本副本无法安装"
            warn "请改用文件方式运行：curl -fsSL ${SCRIPT_URL} -o ${MANAGER_PATH} && chmod +x ${MANAGER_PATH} && ${MANAGER_PATH}"
            return 1
        fi
        install -m 755 "$tmp" "$MANAGER_PATH"
        rm -f "$tmp"
        self_path="$MANAGER_PATH"
        local remote_ver
        remote_ver="$(grep -m1 '^SCRIPT_VERSION=' "$MANAGER_PATH" 2>/dev/null | cut -d'"' -f2 || true)"
        if [ -n "${SCRIPT_VERSION:-}" ] && [ -n "$remote_ver" ] && [ "$remote_ver" != "$SCRIPT_VERSION" ]; then
            warn "注意：下载到的脚本版本为 ${remote_ver}，与当前运行的 ${SCRIPT_VERSION} 不一致（可能新版尚未推送到 ${SCRIPT_URL}），管理命令将指向下载到的版本"
        fi
    fi

    if [ "$self_path" != "$MANAGER_PATH" ]; then
        install -m 755 "$self_path" "$MANAGER_PATH"
    fi
    chmod +x "$MANAGER_PATH"
    return 0
}

install_shortcuts() {
    step "安装快捷命令"
    divider
    if ! ensure_manager_copy; then
        warn "快捷命令无法安装"
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

# ── 证书申请与自动续期（v2 新增/重构） ──────────────────────────

# 证书是否覆盖指定域名：逐个 SAN 精确比对，并支持一级通配符（*.example.com）。
# 旧版用 grep "DNS:${domain}" 做子串匹配：会把 example.com.evil.org 之类前缀相同的名字当成匹配，
# 也识别不了通配符证书。
cert_covers_domain() {
    local crt="$1" domain="$2" sans name wild
    sans="$(openssl x509 -in "$crt" -noout -ext subjectAltName 2>/dev/null | tr ',' '\n' | sed -n 's/^[[:space:]]*DNS://p' || true)"
    wild="*.${domain#*.}"
    while IFS= read -r name; do
        [ -n "$name" ] || continue
        if [ "$name" = "$domain" ] || [ "$name" = "$wild" ]; then return 0; fi
    done <<< "$sans"
    return 1
}

# 证书有效性：文件存在、私钥匹配、SAN/CN 含域名、剩余有效期 > 30 天
cert_is_valid() {
    local domain="$1" crt="$2" key="$3"
    [ -n "$domain" ] && [ -f "$crt" ] && [ -f "$key" ] || return 1
    openssl x509 -in "$crt" -noout -checkend 2592000 >/dev/null 2>&1 || return 1
    openssl x509 -in "$crt" -noout -pubkey 2>/dev/null | \
        cmp -s - <(openssl pkey -in "$key" -pubout 2>/dev/null) || return 1
    cert_covers_domain "$crt" "$domain" && return 0
    local cn
    cn="$(openssl x509 -in "$crt" -noout -subject 2>/dev/null | sed -n 's/.*CN *= *\([^,\/]*\).*/\1/p' || true)"
    [ "$cn" = "$domain" ] && return 0
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
    if ! cert_covers_domain "$crt" "$domain"; then
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

# 发布包 SHA256 校验（v3 修订：改为“能取到官方校验值就必须通过”）：
# 1) 首选 GitHub Release API 返回的资产 digest（sha256:...，官方发布即带，所有版本可查）；
# 2) 兜底仓库校验文件——旧实现用 sha256sum -c 按校验文件里的原名找文件，
#    而下载到本地的文件名是 nowhere.tar.gz，永远对不上（且上游根本未提供校验文件，旧逻辑恒跳过）；
#    新实现提取哈希字段与本地实算值直接比对，不依赖文件名；
# 3) 两者都取不到时才告警跳过。
verify_release_checksum() {
    local tag="$1" workdir="$2"
    local tarball="${workdir}/nowhere.tar.gz"
    [ -f "$tarball" ] || { warn "校验时找不到已下载的安装包"; return 1; }
    local actual
    actual="$(sha256sum "$tarball" | awk '{print $1}')"

    local digest="" api_json=""
    api_json="$(curl -fsS --max-time 20 "https://api.github.com/repos/${REPO}/releases/tags/${tag}" 2>/dev/null || true)"
    if [ -n "$api_json" ] && command -v python3 >/dev/null 2>&1; then
        # 注意：不用 str.removeprefix（Python 3.9+），旧系统上会抛异常并被吞掉，等于静默跳过校验
        digest="$(printf '%s' "$api_json" | BIN_NAME="$BIN_NAME" python3 -c 'import json,os,sys
try: data = json.load(sys.stdin)
except Exception: sys.exit(0)
for a in data.get("assets", []):
    if a.get("name") == os.environ.get("BIN_NAME"):
        print((a.get("digest") or "").replace("sha256:", ""))
        break' 2>/dev/null || true)"
    fi
    if [ -z "$digest" ] && [ -n "$api_json" ]; then
        # 没有 python3 时的兜底：资产对象里 name 之后的第一个 digest 字段
        digest="$(printf '%s\n' "$api_json" | grep -A 60 "\"name\": *\"${BIN_NAME}\"" | grep -m1 '"digest"' | grep -oE '[0-9a-f]{64}' | head -n 1 || true)"
    fi
    if [ -n "$digest" ]; then
        if [ "$digest" = "$actual" ]; then
            success "SHA256 校验通过（GitHub 官方资产 digest）"
            return 0
        fi
        warn "SHA256 校验失败：官方 digest=${digest}，本地实算=${actual}，安装包可能被篡改或下载损坏"
        return 1
    fi

    local sumfile url expected
    for sumfile in "SHA256SUMS" "sha256sums.txt" "checksums.txt"; do
        url="https://github.com/${REPO}/releases/download/${tag}/${sumfile}"
        curl -fsSL --max-time 15 -o "${workdir}/${sumfile}" "$url" 2>/dev/null || continue
        expected="$(grep "${BIN_NAME}" "${workdir}/${sumfile}" 2>/dev/null | head -1 | awk '{print $1}' || true)"
        [ -n "$expected" ] || continue
        if [ "$expected" = "$actual" ]; then
            success "SHA256 校验通过（${sumfile}）"
            return 0
        fi
        warn "SHA256 校验失败（${sumfile}）：期望 ${expected}，实算 ${actual}"
        return 1
    done
    warn "无法取得官方校验值（API digest 与校验文件均不可用），跳过校验（本次经 HTTPS 直连 GitHub 下载）"
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
    read -rp "是否立即做一次续期演练（certbot renew --dry-run，不消耗 LE 配额）？[Y/n]: " DRYRUN
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

menu_status_summary() {
    local role nw
    role="$(current_role)"
    case "$role" in portal) role="Portal" ;; egress) role="Egress" ;; *) role="" ;; esac
    if [ -x "$BIN_PATH" ]; then
        nw="$(read_installed_version)${role:+ · ${role}} · $(svc_state nowhere)"
    else
        nw="${YELLOW}未安装${NC}"
    fi
    echo -e "  Nowhere : ${nw}"
    echo -e "  Snell   : $(snell_state_text)"
    echo -e "  Xray    : $(xray_state_text)"
    echo -e "  防火墙  : $(fw_state_text)      Fail2ban : $(f2b_state_text)      保活巡检 : $(maint_timer_state adam-watchdog.timer)"
}

show_menu() {
    clear 2>/dev/null || true
    echo -e "${BOLD}${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║         Adam Nowhere Portal 一键管理脚本                     ║"
    echo "║   Nowhere ${TARGET_NW_VERSION} · Snell v${SNELL_MAJOR} · Xray · 防火墙 · Fail2ban · 调优║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "  管理脚本版本: ${SCRIPT_VERSION}"
    menu_status_summary
    divider
    echo -e "  ${BOLD}── Nowhere ──${NC}"
    echo -e "  ${BOLD}1)${NC} 安装 Nowhere Portal（向导）"
    echo -e "  ${BOLD}2)${NC} 卸载 Nowhere"
    echo -e "  ${BOLD}3)${NC} 更新 Nowhere 二进制（更新到最新版）"
    echo -e "  ${BOLD}4)${NC} 重新配置（修改参数）"
    echo -e "  ${BOLD}5)${NC} 查看连接信息 / 导入链接"
    echo -e "  ${BOLD}6)${NC} 查看服务状态（含 nowhere status）"
    echo -e "  ${BOLD}7)${NC} 查看实时日志"
    echo -e "  ${BOLD}8)${NC} 查看证书指纹（tls=1 自签 / tls=2 文件证书）"
    echo -e "  ${BOLD}9)${NC} 重启服务"
    echo -e "  ${BOLD}10)${NC} 重装快捷命令（adam/zt/pz/cxpz/cq）"
    echo -e "  ${BOLD}11)${NC} 查看当前版本 / 检查更新"
    echo -e "  ${BOLD}12)${NC} 选择指定版本（版本切换/回退到历史版本）"
    echo -e "  ${BOLD}13)${NC} 快速回退到上一个版本"
    echo -e "  ${BOLD}14)${NC} 生成 v3 共享密钥（32 位十六进制）"
    echo -e "  ${BOLD}15)${NC} 连通性探测 probe（真实 TCP Flow 测试）"
    echo -e "  ${BOLD}16)${NC} 检查证书状态 / 手动续期"
    echo -e "  ${BOLD}17)${NC} 本机安装为 Egress 服务（出口机用，QUIC 或 TLS 载体）"
    echo -e "  ${BOLD}── 扩展功能 ──${NC}"
    echo -e "  ${BOLD}18)${NC} Snell v${SNELL_MAJOR} 管理（安装 / 跟随测试版更新 / 健康检查 / 配置）"
    echo -e "  ${BOLD}19)${NC} 防火墙管理（ufw：安装 / 放行与删除端口 / 启停）"
    echo -e "  ${BOLD}20)${NC} Fail2ban 管理（封禁时长 / 被封 IP / 启停）"
    echo -e "  ${BOLD}21)${NC} 更新本管理脚本"
    echo -e "  ${BOLD}22)${NC} Xray 管理（SS2022 / VLESS：REALITY Vision、XHTTP REALITY、XHTTP CDN、VLESS Encryption）"
    echo -e "  ${BOLD}23)${NC} 系统与网络调优（TCP 调优 tcpfit / XanMod 内核 / DNS / IPv4·IPv6 优先级 / 禁用 IPv6）"
    echo -e "  ${BOLD}24)${NC} 自动维护（保活巡检 / 脚本与内核自动更新）"
    echo -e "  ${BOLD}0)${NC} 退出"
    divider
    if [ -x /usr/local/bin/adam ]; then
        echo -e "  ${YELLOW}提示：可直接输入${NC} ${CYAN}adam${NC} ${YELLOW}唤出此菜单，或用${NC} ${CYAN}zt${NC}/${CYAN}pz${NC}/${CYAN}cxpz${NC}/${CYAN}cq${NC} ${YELLOW}快捷执行；${NC}${CYAN}adam help${NC} ${YELLOW}查看全部子命令${NC}"
        divider
    fi
    read -rp "请选择操作 [0-24]: " MENU_CHOICE
}

do_install() {
    local OLD_NW_PORTS=""
    OLD_NW_PORTS="$(nowhere_ports 2>/dev/null || true)"
    if [ "$(current_role)" = "egress" ]; then
        warn "本机当前是 Egress 角色：继续安装会把 nowhere.service 换成 Portal"
        read -rp "确认继续 [y/N]: " ROLE_CONFIRM
        [[ ! "$ROLE_CONFIRM" =~ ^[Yy]$ ]] && { info "已取消"; return; }
    fi
    ensure_prereqs

    step "第 1 步：选择证书获取方式"
    divider
    echo -e "${BOLD}TLS 证书方式：${NC}"
    echo "  1) 自签证书 tls=1  - 无需域名，快速测试（Vector/Egress 必须用 pin= 锁定指纹，指纹随重启变化）"
    echo "  2) Let's Encrypt HTTP-01 - 需要开放 80 端口（自动续期）"
    echo "  3) Let's Encrypt DNS-01 通用 - 支持多种 DNS 服务商（自动续期）"
    echo "  4) Cloudflare DNS-01 - 需要 CF API Key（自动续期，推荐）"
    read -rp "请选择 [1/2/3/4，默认4]: " CERT_CHOICE
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
            read -rp "请输入域名（如: nhk.example.com）: " DOMAIN
            DOMAIN=$(echo "$DOMAIN" | tr -d ' \r\n')
            [[ -z "$DOMAIN" ]] && { echo -e "${RED}域名不能为空${NC}"; continue; }
            [[ "$DOMAIN" != *.* ]] && { echo -e "${RED}域名格式不正确${NC}"; continue; }
            [[ ! "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] && { echo -e "${RED}域名只能包含字母、数字、点和连字符${NC}"; continue; }
            break
        done
        PUBLIC_HOST="$DOMAIN"
    else
        info "自签模式无需域名，将自动探测公网 IP 作为客户端连接地址"
        DETECTED_IP="$(detect_public_host)"
        while true; do
            read -rp "公网 IP/域名（用于 Anywhere/Vector/Egress 连接，回车使用探测值 ${DETECTED_IP:-未探测到，请手动输入}）: " PUBLIC_HOST
            PUBLIC_HOST=${PUBLIC_HOST:-$DETECTED_IP}
            PUBLIC_HOST=$(echo "$PUBLIC_HOST" | tr -d ' \r\n')
            is_safe_host "$PUBLIC_HOST" && break
            echo -e "${RED}地址不能为空，且只能包含字母、数字和 . : - _ [ ]${NC}"
        done
        DOMAIN="$PUBLIC_HOST"
    fi

    # 邮箱只用于 ACME 账户：自签模式不申请证书，不再强制填写
    EMAIL=""
    if [ "$TLS_MODE" = "2" ]; then
        while true; do
            read -rp "请输入邮箱（用于证书申请/找回）: " EMAIL
            EMAIL=$(echo "$EMAIL" | tr -d ' \r\n')
            [[ ! "$EMAIL" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] && { echo -e "${RED}邮箱格式不正确${NC}"; continue; }
            break
        done
    fi

    if [ "$CERT_METHOD" = "cloudflare-dns" ]; then
        echo ""
        echo -e "${BOLD}Cloudflare 认证方式：${NC}"
        echo "  1) Global API Key"
        echo "  2) API Token"
        read -rp "选择 [1/2，默认1]: " CF_AUTH_TYPE
        CF_AUTH_TYPE=${CF_AUTH_TYPE:-1}
        if [ "$CF_AUTH_TYPE" = "1" ]; then
            read -rp "Cloudflare Email: " CF_EMAIL
            read -rsp "Cloudflare Global API Key（输入不回显）: " CF_API_KEY; echo
        else
            read -rsp "Cloudflare API Token（输入不回显）: " CF_TOKEN; echo
        fi
    elif [ "$CERT_METHOD" = "letsencrypt-dns" ]; then
        echo ""
        echo -e "${BOLD}DNS 服务商：${NC}"
        echo "  1) Cloudflare  2) DNSPod  3) 阿里云  4) 其他/手动"
        read -rp "选择 [1-4，默认1]: " DNS_PROVIDER
        DNS_PROVIDER=${DNS_PROVIDER:-1}
        case $DNS_PROVIDER in
            1) read -rp "Cloudflare Email: " CF_EMAIL
               read -rsp "Cloudflare API Key（输入不回显）: " CF_API_KEY; echo
               export CF_Email="${CF_EMAIL}" CF_Key="${CF_API_KEY}"
               DNS_API="dns_cf" ;;
            2) read -rp "DNSPod ID: " DNSPOD_ID
               read -rsp "DNSPod Token（输入不回显）: " DNSPOD_TOKEN; echo
               export DP_Id="${DNSPOD_ID}" DP_Key="${DNSPOD_TOKEN}"
               DNS_API="dns_dp" ;;
            3) read -rp "阿里云 AccessKey ID: " ALI_ID
               read -rsp "阿里云 AccessKey Secret（输入不回显）: " ALI_SECRET; echo
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
    read -rp "选择 [1/2，默认1]: " PORT_MODE_CHOICE
    case ${PORT_MODE_CHOICE:-1} in
        2) PORT_MODE="split" ;;
        *) PORT_MODE="same" ;;
    esac

    if [ "$PORT_MODE" = "split" ]; then
        NET="mix"
        read -rp "TLS/TCP 端口（回车默认2000）: " TCP_PORT
        TCP_PORT=${TCP_PORT:-2000}
        validate_port "$TCP_PORT" || { warn "端口不合法，重置为2000"; TCP_PORT=2000; }
        read -rp "QUIC/UDP 端口（回车默认2001）: " UDP_PORT
        UDP_PORT=${UDP_PORT:-2001}
        validate_port "$UDP_PORT" || { warn "端口不合法，重置为2001"; UDP_PORT=2001; }
        if [ "$TCP_PORT" = "$UDP_PORT" ]; then
            warn "分端口模式下 TCP 与 UDP 端口不能相同，已将 UDP 端口改为 2001"
            UDP_PORT=2001
        fi
        PORT="$TCP_PORT"
    else
        read -rp "监听端口（回车默认443）: " PORT
        PORT=${PORT:-443}
        validate_port "$PORT" || { warn "端口不合法，重置为443"; PORT=443; }
        TCP_PORT="$PORT"
        UDP_PORT="$PORT"

        echo ""
        echo -e "${BOLD}传输模式（决定端点路径，TCP 与 UDP 都能承载 TCP/UDP 业务流）：${NC}"
        echo "  1) mix - TLS/TCP + QUIC/UDP 双栈（HOST:PORT，推荐）"
        echo "  2) tcp - 仅 TLS/TCP（HOST/tcp:PORT）"
        echo "  3) udp - 仅 QUIC/UDP（HOST/udp:PORT）"
        read -rp "选择 [1/2/3，默认1]: " NET_CHOICE
        case ${NET_CHOICE:-1} in
            1) NET="mix" ;; 2) NET="tcp" ;; 3) NET="udp" ;; *) NET="mix" ;;
        esac
    fi

    TCP_FAMILY=""; UDP_FAMILY=""
    read -rp "是否限制监听地址族？（默认不限；IPv6 未真正开通的 VPS 可选仅 IPv4）[y/N]: " FAM_CHOICE
    if [[ "$FAM_CHOICE" =~ ^[Yy]$ ]]; then
        if has_tcp; then
            read -rp "  TCP 地址族 [4=仅IPv4 / 6=仅IPv6 / 回车=不限]: " TCP_FAMILY_IN
            case "$TCP_FAMILY_IN" in 4) TCP_FAMILY="4" ;; 6) TCP_FAMILY="6" ;; *) TCP_FAMILY="" ;; esac
        fi
        if has_udp; then
            read -rp "  UDP 地址族 [4=仅IPv4 / 6=仅IPv6 / 回车=不限]: " UDP_FAMILY_IN
            case "$UDP_FAMILY_IN" in 4) UDP_FAMILY="4" ;; 6) UDP_FAMILY="6" ;; *) UDP_FAMILY="" ;; esac
        fi
    fi

    read -rp "监听地址（回车= * 通配，全监听；也可填具体 IP）: " LISTEN_HOST
    LISTEN_HOST=${LISTEN_HOST:-}
    LISTEN_HOST=$(echo "$LISTEN_HOST" | tr -d ' \r\n')
    if [[ -n "$LISTEN_HOST" && "$LISTEN_HOST" != "*" ]] && ! is_safe_host "$LISTEN_HOST"; then
        warn "监听地址格式不合法，已改为 * 通配"
        LISTEN_HOST=""
    fi

    step "第 4 步：协议与安全参数"
    divider

    # v3 密钥必须是恰好 32 位小写十六进制，旧任意字符串密钥会被直接拒绝
    while true; do
        read -rsp "共享密钥 Shared Key（输入不回显，回车自动生成 32 位十六进制）: " SHARED_KEY; echo
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
    read -rp "是否开启 [Y/n]: " MORPH_CHOICE
    if [[ "$MORPH_CHOICE" =~ ^[Nn]$ ]]; then MORPH="0"; else MORPH="$DEFAULT_MORPH"; fi

    MORPH_TCP_PRELUDE="fade"; MORPH_UDP_PRELUDE="fade"
    if [ "$MORPH" = "1" ]; then
        echo ""
        echo -e "${BOLD}Morph Prelude 策略${NC}（${YELLOW}NOW_MORPH_TCP_PRELUDE / NOW_MORPH_UDP_PRELUDE，后者为 v3.3.0 新增。只对发起端（Vector / Egress）生效，Portal 自身不使用；这里的选择会写进下方生成的 Vector / Egress 启动命令。接收端三种通吃、两端无需一致、不进分享链接${NC}）："
        echo "  1) fade  - ASCII→低7位→全8位渐变（默认，推荐）"
        echo "  2) full8 - 全程全 8 位随机"
        echo "  3) low7  - 全程低 7 位随机"
        read -rp "选择 [1/2/3，默认1]: " PRELUDE_CHOICE
        case ${PRELUDE_CHOICE:-1} in
            2) MORPH_TCP_PRELUDE="full8" ;;
            3) MORPH_TCP_PRELUDE="low7" ;;
            *) MORPH_TCP_PRELUDE="fade" ;;
        esac
        MORPH_UDP_PRELUDE="$MORPH_TCP_PRELUDE"
    fi

    echo ""
    echo -e "${BOLD}Portal 出口 out=（Portal 固定出口，运行期间不可变）：${NC}"
    echo "  1) direct - Portal 直接访问目标（默认）"
    echo "  2) SOCKS5 上游 - 经一层 SOCKS5 代理出站（链式代理）"
    # v3.3.0 起 out=egress 接受任意已启用的 TLS 或 QUIC 监听上的 Egress 注册，纯 TCP 的 Portal 也可用
    echo "  3) egress - 远程 Egress 出口（目标解析/拨号在另一台主动回连的机器上，该机无需开放入站端口；可同时接多台）"
    read -rp "选择 [1/2/3，默认1]: " OUT_CHOICE
    case ${OUT_CHOICE:-1} in
        2) OUT_TYPE="socks" ;;
        3) OUT_TYPE="egress" ;;
        *) OUT_TYPE="direct" ;;
    esac

    SOCKS="none"
    if [ "$OUT_TYPE" = "socks" ]; then
        read -rsp "SOCKS5 地址，格式 user:pass@host:port（输入不回显）: " SOCKS; echo
        SOCKS=${SOCKS:-none}
        validate_socks "$SOCKS" || { warn "SOCKS5 格式不合法，已重置为 none 并改回 direct"; SOCKS="none"; OUT_TYPE="direct"; }
    fi

    DIAL_MODE="single"; DIAL="$DEFAULT_DIAL"; DIAL4="auto"; DIAL6="auto"
    if [ "$OUT_TYPE" = "egress" ]; then
        info "out=egress 时 Portal 不能再设置 dial/dial4/dial6（与官方约束一致），目标源地址请在 Egress 端配置"
    else
        echo ""
        read -rp "出站源 IP dial（回车默认 auto；填 IP 会限定地址族，绑定失败不回退）: " DIAL
        DIAL=${DIAL:-$DEFAULT_DIAL}
        validate_ip_or_auto "$DIAL" any || { warn "dial 不是合法 IP 字面量，已重置为 auto"; DIAL="auto"; }
        read -rp "是否改用 dial4/dial6 分别绑定 IPv4/IPv6 源地址？[y/N]: " DIAL46_CHOICE
        if [[ "$DIAL46_CHOICE" =~ ^[Yy]$ ]]; then
            DIAL_MODE="dual"
            read -rp "  dial4（IPv4 源地址，回车默认 auto）: " DIAL4
            DIAL4=${DIAL4:-auto}
            read -rp "  dial6（IPv6 源地址，回车默认 auto）: " DIAL6
            DIAL6=${DIAL6:-auto}
            validate_ip_or_auto "$DIAL4" 4 || { warn "dial4 不是合法 IPv4 字面量，已重置为 auto"; DIAL4="auto"; }
            validate_ip_or_auto "$DIAL6" 6 || { warn "dial6 不是合法 IPv6 字面量（IPv4-mapped 地址不被 v3 接受），已重置为 auto"; DIAL6="auto"; }
            DIAL="auto"
        fi
    fi

    echo ""
    echo -e "${BOLD}限速设置（Portal/Vector/Egress 通用语义，0=不限速）：${NC}"
    read -rp "上行限速 Mbps，Vector→目标（0=不限速）: " RATE
    RATE=${RATE:-0}
    validate_rate "$RATE" || { warn "输入不合法（须为 0..2147483647 的整数），重置为0"; RATE=0; }

    read -rp "下行限速 Mbps，目标→Vector（0=不限速）: " ETAR
    ETAR=${ETAR:-0}
    validate_rate "$ETAR" || { warn "输入不合法（须为 0..2147483647 的整数），重置为0"; ETAR=0; }

    echo ""
    echo -e "${BOLD}本地 Vector 客户端连接信息${NC}（可选，在电脑/路由器上跑本地 SOCKS5 入口用 in=）："
    read -rp "是否生成 Vector 连接信息？[Y/n]: " GEN_VECTOR
    GEN_VECTOR=${GEN_VECTOR:-y}
    if [[ "$GEN_VECTOR" =~ ^[Yy]$ ]]; then
        GENERATE_VECTOR="1"
        if has_tcp && has_udp; then
            echo "  Vector 载体（二选一，v3 一条连接只用一种载体）  1) tcp/TLS  2) udp/QUIC"
            read -rp "  选择 [1/2，默认1]: " VCARRIER_CHOICE
            case ${VCARRIER_CHOICE:-1} in 2) VECTOR_CARRIER="udp" ;; *) VECTOR_CARRIER="tcp" ;; esac
        elif has_udp; then
            VECTOR_CARRIER="udp"
            info "  当前 Portal 仅 QUIC/UDP，Vector 载体自动选 udp"
        else
            VECTOR_CARRIER="tcp"
            info "  当前 Portal 仅 TLS/TCP，Vector 载体自动选 tcp"
        fi
        read -rp "  本地 SOCKS5 监听 in=（回车默认 ${DEFAULT_VECTOR_SOCKS}，可带 user:pass@）: " VECTOR_SOCKS
        VECTOR_SOCKS=${VECTOR_SOCKS:-$DEFAULT_VECTOR_SOCKS}
    else
        GENERATE_VECTOR="0"
        VECTOR_CARRIER="tcp"; VECTOR_SOCKS="$DEFAULT_VECTOR_SOCKS"
    fi

    GENERATE_EGRESS="0"
    EGRESS_DIAL_MODE="single"; EGRESS_DIAL4="auto"; EGRESS_DIAL6="auto"
    if has_udp; then EGRESS_CARRIER="udp"; else EGRESS_CARRIER="tcp"; fi
    if [ "$OUT_TYPE" = "egress" ]; then
        echo ""
        echo -e "${BOLD}远程 Egress 出口机连接信息${NC}（在出口机上运行 egress:// 主动回连本 Portal）："
        read -rp "是否生成 Egress 连接信息？[Y/n]: " GEN_EGRESS
        GEN_EGRESS=${GEN_EGRESS:-y}
        if [[ "$GEN_EGRESS" =~ ^[Yy]$ ]]; then
            GENERATE_EGRESS="1"
            if has_tcp && has_udp; then
                echo "  Egress 回连载体（v3.3.0 起两种都可用；一个连接串只选一种，多台出口机可以混用）"
                echo "    1) udp / QUIC - 一条连接承载多条 Flow（推荐）"
                echo "    2) tcp / TLS  - 每条 Flow 独占一条 TLS 连接，出口机自动维护预建连接池；UDP 被限制的网络选这个（出口机需 ≥ v3.3.0）"
                read -rp "  选择 [1/2，默认1]: " ECARRIER_CHOICE
                case ${ECARRIER_CHOICE:-1} in 2) EGRESS_CARRIER="tcp" ;; *) EGRESS_CARRIER="udp" ;; esac
            elif has_udp; then
                EGRESS_CARRIER="udp"
            else
                EGRESS_CARRIER="tcp"
                info "  当前 Portal 仅 TLS/TCP，Egress 载体自动选 tcp（出口机需 ≥ v3.3.0）"
            fi
            read -rp "  Egress 端出站源 IP dial（在出口机上绑定目标连接源地址，回车默认 auto）: " EGRESS_DIAL
            EGRESS_DIAL=${EGRESS_DIAL:-auto}
            validate_ip_or_auto "$EGRESS_DIAL" any || { warn "Egress dial 不是合法 IP 字面量，已重置为 auto"; EGRESS_DIAL="auto"; }
            read -rp "  是否改用 dial4/dial6 分别绑定 IPv4/IPv6 目标出站源地址？[y/N]: " EGRESS_DIAL46_CHOICE
            if [[ "$EGRESS_DIAL46_CHOICE" =~ ^[Yy]$ ]]; then
                EGRESS_DIAL_MODE="dual"
                read -rp "    dial4（IPv4 源地址，回车默认 auto）: " EGRESS_DIAL4
                EGRESS_DIAL4=${EGRESS_DIAL4:-auto}
                read -rp "    dial6（IPv6 源地址，回车默认 auto）: " EGRESS_DIAL6
                EGRESS_DIAL6=${EGRESS_DIAL6:-auto}
                validate_ip_or_auto "$EGRESS_DIAL4" 4 || { warn "Egress dial4 不是合法 IPv4 字面量，已重置为 auto"; EGRESS_DIAL4="auto"; }
                validate_ip_or_auto "$EGRESS_DIAL6" 6 || { warn "Egress dial6 不是合法 IPv6 字面量（IPv4-mapped 地址不被 v3 接受），已重置为 auto"; EGRESS_DIAL6="auto"; }
                EGRESS_DIAL="auto"
            fi
        fi
    fi

    echo ""
    divider
    echo -e "${BOLD}配置确认：${NC}"
    divider
    echo -e "  域名/主机     : ${GREEN}${DOMAIN}${NC}"
    echo -e "  公网地址      : ${GREEN}${PUBLIC_HOST}${NC}"
    echo -e "  邮箱          : ${GREEN}${EMAIL:-（自签模式不需要）}${NC}"
    echo -e "  证书方式      : ${GREEN}${CERT_METHOD}${NC}"
    echo -e "  端口模式      : ${GREEN}${PORT_MODE}（TCP $(tcp_port) / UDP $(udp_port)）${NC}"
    echo -e "  监听地址      : ${GREEN}$([ -z "$LISTEN_HOST" ] && echo "*（通配）" || echo "$LISTEN_HOST")${NC}"
    echo -e "  传输模式      : ${GREEN}${NET}${NC}"
    echo -e "  Portal 端点   : ${GREEN}$(build_portal_endpoint)${NC}"
    echo -e "  共享密钥      : ${GREEN}$(mask_secret "$SHARED_KEY")（32 位十六进制）${NC}"
    echo -e "  Morph 乱形    : ${GREEN}$([ "$MORPH" = "1" ] && echo "开启 morph=1（默认）" || echo "关闭 morph=0")${NC}"
    [ "$MORPH" = "1" ] && echo -e "  Prelude 策略  : ${GREEN}${MORPH_TCP_PRELUDE}（写入生成的 Vector / Egress 启动命令，Portal 自身不使用）${NC}"
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
        if [ "$EGRESS_DIAL_MODE" = "dual" ]; then
            echo -e "  Egress出口机  : ${GREEN}生成（载体 ${EGRESS_CARRIER}，dial4=${EGRESS_DIAL4} dial6=${EGRESS_DIAL6}）${NC}"
        else
            echo -e "  Egress出口机  : ${GREEN}生成（载体 ${EGRESS_CARRIER}，dial=${EGRESS_DIAL}）${NC}"
        fi
    fi
    divider
    read -rp "确认安装 [y/N]: " CONFIRM
    [[ ! "$CONFIRM" =~ ^[Yy]$ ]] && { info "已取消"; return; }

    if [ "$CERT_METHOD" = "letsencrypt-dns" ]; then
        # acme.sh 签发的证书放到本脚本自己的目录：旧版写进 certbot 的 /etc/letsencrypt/live/<域名>/，
        # 该目录由 certbot 管理且此时并不存在，install-cert 会因目录缺失而失败
        CRT="${CONFIG_DIR}/certs/${DOMAIN}/fullchain.pem"
        KEY_PEM="${CONFIG_DIR}/certs/${DOMAIN}/privkey.pem"
    else
        CRT="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
        KEY_PEM="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
    fi

    if [ -f "$CONFIG_FILE" ]; then
        local backup_dir="${CONFIG_DIR}.bak.$(date +%Y%m%d-%H%M%S)"
        if cp -a "$CONFIG_DIR" "$backup_dir"; then
            info "检测到已有配置，已备份到 ${backup_dir}（本次安装中途失败时可手动恢复）"
            # 备份里有密钥，只保留最近 3 份，避免每次重新配置都多留一份
            ls -1d "${CONFIG_DIR}".bak.* 2>/dev/null | sort -r | tail -n +4 | xargs -r rm -rf || true
        fi
    fi

    step "第 5 步：安装系统依赖"
    divider
    apt-get update -qq
    apt-get install -y -qq curl wget tar ufw socat openssl python3 qrencode iproute2 ca-certificates
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
                # acme.sh 的默认 CA 是 ZeroSSL；菜单写的是 Let's Encrypt，这里显式指定以保持一致
                "${ACME_HOME}/acme.sh" --issue --server letsencrypt -d "${DOMAIN}" --dns "${DNS_API}" || {
                    error "证书签发失败：请检查 DNS API 凭证是否正确、域名 DNS 是否由所选服务商托管"
                }
                install -d -m 700 "$(dirname "$CRT")"
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
    LATEST="$(get_latest_tag)"
    [ -z "$LATEST" ] && error "无法获取版本号（GitHub API 与 releases/latest 跳转均失败），请检查网络"
    LATEST_MAJOR="$(version_major "$LATEST")"
    if [ -n "$LATEST_MAJOR" ] && [ "$LATEST_MAJOR" -lt 3 ]; then
        error "当前最新版为 ${LATEST}，低于 v3.0.0，与本脚本的 NW3 配置不兼容，已中止（请检查仓库状态）"
    fi
    if [ -n "$LATEST_MAJOR" ] && [ "$LATEST_MAJOR" -gt 3 ]; then
        warn "当前最新版为 ${LATEST}，已进入新的协议代（NW${LATEST_MAJOR}）；本脚本的向导按 NW3 生成配置，可能无法直接使用"
        read -rp "仍要继续安装该版本吗？[y/N]: " NEWMAJOR_CONFIRM
        [[ ! "$NEWMAJOR_CONFIRM" =~ ^[Yy]$ ]] && { info "已取消"; return; }
    fi
    info "最新版本: ${LATEST} (${ARCH_NAME}-${LIBC})"
    fetch_nowhere_release "$LATEST" || error "下载或校验失败，已中止"
    install -m 755 "$DL_BINARY" "${BIN_PATH}"
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
SOCKS_VALUE="$(dq_escape "$SOCKS")"
DIAL_MODE_VALUE="${DIAL_MODE}"
DIAL_VALUE="${DIAL}"
DIAL4_VALUE="${DIAL4}"
DIAL6_VALUE="${DIAL6}"
RATE_VALUE="${RATE}"
ETAR_VALUE="${ETAR}"
MORPH_VALUE="${MORPH}"
MORPH_TCP_PRELUDE_VALUE="${MORPH_TCP_PRELUDE}"
TCP_FAMILY_VALUE="${TCP_FAMILY}"
UDP_FAMILY_VALUE="${UDP_FAMILY}"
EGRESS_DIAL_VALUE="${EGRESS_DIAL}"
EGRESS_DIAL_MODE_VALUE="${EGRESS_DIAL_MODE}"
EGRESS_DIAL4_VALUE="${EGRESS_DIAL4}"
EGRESS_DIAL6_VALUE="${EGRESS_DIAL6}"
EGRESS_CARRIER_VALUE="${EGRESS_CARRIER}"
MORPH_UDP_PRELUDE_VALUE="${MORPH_UDP_PRELUDE}"
GENERATE_VECTOR_VALUE="${GENERATE_VECTOR}"
VECTOR_CARRIER_VALUE="${VECTOR_CARRIER}"
VECTOR_SOCKS_VALUE="$(dq_escape "$VECTOR_SOCKS")"
GENERATE_EGRESS_VALUE="${GENERATE_EGRESS}"
ENVEOF
    chmod 600 "$CONFIG_FILE"
    echo "portal" > "$ROLE_FILE"
    success "配置已保存至 ${CONFIG_FILE}"

    step "第 9 步：安装前端口占用检测"
    divider
    EXISTING_PROC=""
    if command -v ss >/dev/null 2>&1; then
        if has_tcp; then
            EXISTING_PROC="$(ss -tlnp 2>/dev/null | grep -E ":$(tcp_port)\b" | grep -v '"nowhere"' || true)"
        fi
        if [ -z "$EXISTING_PROC" ] && has_udp; then
            EXISTING_PROC="$(ss -ulnp 2>/dev/null | grep -E ":$(udp_port)\b" | grep -v '"nowhere"' || true)"
        fi
    fi
    if [ -n "$EXISTING_PROC" ]; then
        warn "检测到目标端口已被其他进程占用："
        echo "$EXISTING_PROC"
        warn "请先停止占用该端口的服务（旧的 Nowhere 实例已自动排除在外），否则新服务会反复崩溃重启，客户端表现为一直 timeout"
        read -rp "仍要继续安装吗？[y/N]: " PORT_CONFIRM
        [[ ! "$PORT_CONFIRM" =~ ^[Yy]$ ]] && { info "已取消安装"; return; }
    else
        success "目标端口空闲，可以使用"
    fi

    step "第 10 步：配置防火墙（先于服务启动，避免中间态连不通）"
    divider
    # 旧版在这里无条件 ufw --force enable：如果机器上还跑着别的服务（Snell、面板、其他代理），
    # 它们没放行的端口会被一起挡掉。现在：ufw 已启用就只加规则；未启用则先列出未放行的监听端口再询问。
    local -a NW_FW_SPECS=()
    if has_tcp; then NW_FW_SPECS+=("$(tcp_port)/tcp"); fi
    if has_udp; then NW_FW_SPECS+=("$(udp_port)/udp"); fi
    if [ "$CERT_METHOD" = "letsencrypt-http" ]; then NW_FW_SPECS+=("80/tcp"); fi
    fw_allow_for_service "${NW_FW_SPECS[@]}"
    if [ -n "$OLD_NW_PORTS" ]; then fw_prune_old_specs "$OLD_NW_PORTS"; fi

    step "第 11 步：创建并启动系统服务"
    divider
    # 注意：PrivateTmp 必须关闭。v3 的 nowhere status 靠系统临时目录下的
    # 受保护 IPC 注册表发现实例，PrivateTmp 会让服务与外部命令看到不同的 /tmp，
    # 导致 status 永远发现不到本服务（实测会报 namespace identity unavailable 一类问题时更难排查）
    # NOW_MORPH_*_PRELUDE 不再写进 Portal 的 unit：官方文档明确 Portal 不使用这两个变量（只有发起端使用）
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
NOW_MORPH_TCP_PRELUDE=${MORPH_TCP_PRELUDE} NOW_MORPH_UDP_PRELUDE=${MORPH_UDP_PRELUDE} nowhere '${VECTOR_URL}'
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
回连载体: ${EGRESS_CARRIER}
连接串：
${EGRESS_URL}

出口机启动命令（或在出口机上运行本脚本菜单 17，直接粘贴上面的连接串装成 systemd 服务）：
NOW_MORPH_TCP_PRELUDE=${MORPH_TCP_PRELUDE} NOW_MORPH_UDP_PRELUDE=${MORPH_UDP_PRELUDE} nowhere '${EGRESS_URL}'
※ 本 Portal 已固定 out=egress：没有可用的 Egress 时，新连接会在 Flow 建立超时（NOW_FLOW_SETUP_TIMEOUT，默认 20s）内等待注册，超时即失败，不会回退直连
※ v3.3.0 起同一 Portal 可同时接受多台 Egress（TLS / QUIC 可混用，Portal 按先进先出轮转，不保证均衡）；使用 tcp 载体的出口机需 ≥ v3.3.0
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
  Nowhere Portal 连接信息（${TARGET_NW_VERSION} / NW3）
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
  Prelude 策略  : ${MORPH_TCP_PRELUDE}（NOW_MORPH_TCP_PRELUDE / NOW_MORPH_UDP_PRELUDE，只在发起端 Vector / Egress 上设置，Portal 不使用；接收端通吃、两端无需一致）
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
  v3.2.0 起 Portal 强制 Authenticated Prelude：morph=1 且走 TLS/TCP 的对端
  （Vector / Egress / Anywhere）必须 ≥ v3.1.0，更旧的版本会被静默拒绝。
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
    if command -v qrencode >/dev/null 2>&1; then
        if [[ -n "$UDP_LINK" ]]; then
            echo ""
            echo -e "${BOLD}📱 扫码导入 Anywhere（QUIC/UDP）：${NC}"
            qrencode -t ANSIUTF8 "$UDP_LINK" || true
        fi
        if [[ -n "$TCP_LINK" ]]; then
            echo ""
            echo -e "${BOLD}📱 扫码导入 Anywhere（TLS/TCP）：${NC}"
            qrencode -t ANSIUTF8 "$TCP_LINK" || true
        fi
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
    MORPH_TCP_PRELUDE="${MORPH_TCP_PRELUDE_VALUE:-fade}"
    case "$MORPH_TCP_PRELUDE" in fade|full8|low7) : ;; *) MORPH_TCP_PRELUDE="fade" ;; esac
    TCP_FAMILY="${TCP_FAMILY_VALUE:-}"
    UDP_FAMILY="${UDP_FAMILY_VALUE:-}"
    EGRESS_DIAL="${EGRESS_DIAL_VALUE:-auto}"
    EGRESS_DIAL_MODE="${EGRESS_DIAL_MODE_VALUE:-single}"
    case "$EGRESS_DIAL_MODE" in single|dual) : ;; *) EGRESS_DIAL_MODE="single" ;; esac
    EGRESS_DIAL4="${EGRESS_DIAL4_VALUE:-auto}"
    EGRESS_DIAL6="${EGRESS_DIAL6_VALUE:-auto}"
    EGRESS_CARRIER="${EGRESS_CARRIER_VALUE:-udp}"
    case "$EGRESS_CARRIER" in tcp|udp) : ;; *) EGRESS_CARRIER="udp" ;; esac
    MORPH_UDP_PRELUDE="${MORPH_UDP_PRELUDE_VALUE:-$MORPH_TCP_PRELUDE}"
    case "$MORPH_UDP_PRELUDE" in fade|full8|low7) : ;; *) MORPH_UDP_PRELUDE="fade" ;; esac
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

# 只下载并安装二进制，不触碰任何服务（供本机 Egress 安装用：服务文件尚未生成时，
# 不能复用 install_nowhere_version，那个函数会在装完后直接重启 nowhere）。
install_nowhere_binary_only() {
    info "正在获取最新版本号..."
    local latest latest_major
    latest="$(get_latest_tag)"
    [ -z "$latest" ] && { warn "无法获取版本号，请检查网络"; return 1; }
    latest_major="$(version_major "$latest")"
    if [ -n "$latest_major" ] && [ "$latest_major" -lt 3 ]; then
        warn "当前最新版为 ${latest}，低于 v3.0.0，与 NW3 配置不兼容，已中止"
        return 1
    fi
    detect_binary
    info "最新版本: ${latest} (${ARCH_NAME}-${LIBC})"
    fetch_nowhere_release "$latest" || return 1
    install -d -m 700 "$CONFIG_DIR"
    if [ -f "$BIN_PATH" ]; then
        cp "$BIN_PATH" "$BIN_BACKUP_PATH"
        read_installed_version > "$PREV_VERSION_FILE"
    fi
    install -m 755 "$DL_BINARY" "$BIN_PATH"
    record_installed_version "$latest"
    success "Nowhere $(${BIN_PATH} --version 2>&1 | head -1) 安装完成"
    return 0
}

# 解析 egress:// 连接串（Portal 端菜单 5 / pz 生成的那一串）。
# 结果写入 PE_KEY / PE_HOST / PE_PORT / PE_CARRIER / PE_FAMILY / PE_MORPH。
# 同时限制字符集：这串内容会原样写进 systemd 的 EnvironmentFile。
parse_egress_url() {
    local u="$1" rest query=""
    local re_path='^(.+)/(tcp|udp)([46]?):([0-9]+)$' re_compact='^(.+):([0-9]+)$'
    local re_host='^[][A-Za-z0-9.:_-]+$' re_query='^[A-Za-z0-9=&%._:~-]+$'
    PE_KEY=""; PE_HOST=""; PE_PORT=""; PE_CARRIER=""; PE_FAMILY=""; PE_MORPH="1"
    [[ "$u" == egress://*@* ]] || return 1
    rest="${u#egress://}"
    PE_KEY="${rest%%@*}"
    is_valid_key "$PE_KEY" || return 1
    rest="${rest#*@}"
    if [[ "$rest" == *\?* ]]; then query="${rest#*\?}"; rest="${rest%%\?*}"; fi
    if [[ "$rest" =~ $re_path ]]; then
        PE_HOST="${BASH_REMATCH[1]}"; PE_CARRIER="${BASH_REMATCH[2]}"
        PE_FAMILY="${BASH_REMATCH[3]}"; PE_PORT="${BASH_REMATCH[4]}"
    elif [[ "$rest" =~ $re_compact ]]; then
        # 官方端点表：HOST:PORT 紧凑形对 Egress 代表 QUIC
        PE_HOST="${BASH_REMATCH[1]}"; PE_CARRIER="udp"; PE_PORT="${BASH_REMATCH[2]}"
    else
        return 1
    fi
    validate_port "$PE_PORT" || return 1
    [[ "$PE_HOST" =~ $re_host ]] || return 1
    if [ -n "$query" ]; then
        [[ "$query" =~ $re_query ]] || return 1
        if [[ "&${query}&" == *"&morph=0&"* ]]; then PE_MORPH="0"; fi
    fi
    return 0
}

# 本机安装为 Egress 服务（在出口机上运行，主动回连 Portal）。
# v3.3.0 起 Egress 可选 QUIC/UDP 或 TLS/TCP 载体，同一 Portal 可同时接多台 Egress。
# 注意：这会覆盖本机现有的 nowhere.service（同一服务名），一台机器同一时间只能是
# Portal 或 Egress 其中一种角色；Egress 配置单独存在 egress.env，不读写 Portal 的 nowhere.env，
# 角色记录在 ${CONFIG_DIR}/role，状态/配置/重启等命令据此区分。
do_install_egress_service() {
    step "本机安装为 Egress 服务"
    divider
    warn "本机将作为出口机（Egress），主动回连 Portal；这会覆盖本机现有的 nowhere.service"
    warn "Portal 侧必须已设 out=egress，并放行所选载体的端口（QUIC = UDP 端口，TLS = TCP 端口）"
    if [ "$(current_role)" = "portal" ]; then
        warn "检测到本机当前是 Portal 角色：继续会把本机切换为 Egress（Portal 配置文件保留，但服务被替换）"
    fi
    read -rp "确认继续 [y/N]: " EG_CONFIRM
    [[ ! "$EG_CONFIRM" =~ ^[Yy]$ ]] && { info "已取消"; return; }
    local old_portal_specs=""
    old_portal_specs="$(nowhere_ports 2>/dev/null || true)"
    ensure_prereqs

    local eg_host="" eg_port="" eg_key="" eg_morph="1" eg_sni="" eg_pin="" eg_carrier="udp" eg_family=""
    local eg_dial_mode eg_dial eg_dial4 eg_dial6 eg_rate eg_etar eg_prelude="fade"
    local eg_url="" eg_query eg_host_part eg_paste=""

    echo ""
    info "可以直接粘贴 Portal 端（菜单 5 / pz）生成的 egress:// 连接串，跳过逐项填写"
    read -rsp "粘贴 egress:// 连接串（输入不回显，回车 = 逐项填写）: " eg_paste; echo
    eg_paste="$(printf '%s' "$eg_paste" | tr -d ' \r\n')"
    if [ -n "$eg_paste" ]; then
        if parse_egress_url "$eg_paste"; then
            eg_url="$eg_paste"; eg_key="$PE_KEY"; eg_host="$PE_HOST"; eg_port="$PE_PORT"
            eg_carrier="$PE_CARRIER"; eg_family="$PE_FAMILY"; eg_morph="$PE_MORPH"
            success "连接串解析通过：${eg_host} ${eg_carrier}${eg_family}:${eg_port}，morph=${eg_morph}"
        else
            warn "连接串格式不合法（应为 egress://32位hex密钥@主机/udp|tcp:端口?参数），改为逐项填写"
        fi
    fi

    if [ -z "$eg_url" ]; then
        while true; do
            read -rp "Portal 公网地址（域名或 IP，Egress 回连用）: " eg_host
            eg_host=$(echo "$eg_host" | tr -d ' \r\n')
            if is_safe_host "$eg_host"; then break; fi
            warn "地址不能为空，且只能包含字母、数字和 . : - _ [ ]"
        done
        echo ""
        echo "回连载体（须与 Portal 已开放的监听对应；v3.3.0 起两种都可用）："
        echo "  1) udp / QUIC（默认）- 一条连接承载多条 Flow"
        echo "  2) tcp / TLS        - 每条 Flow 独占一条 TLS 连接，自动维护预建连接池（Hydra）；UDP 被限制的网络选这个"
        read -rp "选择 [1/2，默认1]: " EG_CARRIER_CHOICE
        case ${EG_CARRIER_CHOICE:-1} in 2) eg_carrier="tcp" ;; *) eg_carrier="udp" ;; esac
        read -rp "Portal 的 ${eg_carrier^^} 端口（回车默认 443）: " eg_port
        eg_port=${eg_port:-443}
        validate_port "$eg_port" || { warn "端口不合法，重置为 443"; eg_port=443; }
        read -rp "地址族（回车=不限；4=仅 IPv4；6=仅 IPv6）: " eg_family
        case "$eg_family" in 4|6) : ;; *) eg_family="" ;; esac
        while true; do
            read -rsp "共享密钥（必须与 Portal 完全一致，32 位小写十六进制，输入不回显）: " eg_key; echo
            if is_valid_key "$eg_key"; then
                break
            fi
            warn "密钥不符合 v3 规范：必须是恰好 32 位小写十六进制字符，不能回车自动生成（必须与 Portal 一致）"
        done
        read -rp "Morph 是否开启（须与 Portal 一致）[Y/n]: " eg_morph
        if [[ "$eg_morph" =~ ^[Nn]$ ]]; then eg_morph="0"; else eg_morph="1"; fi
        echo ""
        echo "Portal 证书信任方式："
        echo "  1) tls=2 真实证书：走系统 CA + 主机名校验（默认）"
        echo "  2) tls=1 自签证书：必须用 pin= 锁定 Portal 证书指纹（指纹随 Portal 重启变化）"
        read -rp "选择 [1/2，默认1]: " EG_TLS_CHOICE
        case ${EG_TLS_CHOICE:-1} in
            2)
                while true; do
                    read -rsp "Portal 自签证书指纹 pin（64 位 hex，可从 Portal 机菜单 8 查看，输入不回显，回车=暂不填）: " eg_pin; echo
                    eg_pin=$(echo "$eg_pin" | tr -d ' \r\n' | tr 'A-F' 'a-f')
                    if [ -z "$eg_pin" ]; then
                        warn "未填 pin：自签证书走系统 CA 校验必然失败，服务会反复重连"
                        read -rp "仍要继续（稍后需手动改 egress.env 补 pin）？[y/N]: " EG_PIN_CONFIRM
                        [[ ! "$EG_PIN_CONFIRM" =~ ^[Yy]$ ]] && { info "已取消"; return; }
                        break
                    fi
                    if [[ "$eg_pin" =~ ^[0-9a-f]{64}$ ]]; then
                        break
                    fi
                    warn "pin 必须是 64 位小写十六进制字符"
                done
                ;;
            *)
                read -rp "  SNI（证书域名与回连地址不一致时填，回车=用回连地址）: " eg_sni
                eg_sni=$(echo "$eg_sni" | tr -d ' \r\n')
                if [ -n "$eg_sni" ] && ! is_safe_host "$eg_sni"; then warn "SNI 格式不合法，已忽略"; eg_sni=""; fi
                ;;
        esac
        eg_dial_mode="single"; eg_dial="auto"; eg_dial4="auto"; eg_dial6="auto"
        echo ""
        read -rp "Egress 到目标的出站源 IP dial（回车默认 auto，只影响目标连接，不影响回连 Portal）: " eg_dial
        eg_dial=${eg_dial:-auto}
        validate_ip_or_auto "$eg_dial" any || { warn "dial 不是合法 IP 字面量，已重置为 auto"; eg_dial="auto"; }
        read -rp "是否改用 dial4/dial6 分别绑定 IPv4/IPv6 目标出站源地址？[y/N]: " EG_DIAL46
        if [[ "$EG_DIAL46" =~ ^[Yy]$ ]]; then
            eg_dial_mode="dual"
            read -rp "  dial4（IPv4 源地址，回车默认 auto）: " eg_dial4
            eg_dial4=${eg_dial4:-auto}
            read -rp "  dial6（IPv6 源地址，回车默认 auto）: " eg_dial6
            eg_dial6=${eg_dial6:-auto}
            validate_ip_or_auto "$eg_dial4" 4 || { warn "dial4 不是合法 IPv4 字面量，已重置为 auto"; eg_dial4="auto"; }
            validate_ip_or_auto "$eg_dial6" 6 || { warn "dial6 不是合法 IPv6 字面量，已重置为 auto"; eg_dial6="auto"; }
            eg_dial="auto"
        fi
        read -rp "上行限速 Mbps（0=不限速）: " eg_rate
        eg_rate=${eg_rate:-0}
        validate_rate "$eg_rate" || { warn "输入不合法，重置为 0"; eg_rate=0; }
        read -rp "下行限速 Mbps（0=不限速）: " eg_etar
        eg_etar=${eg_etar:-0}
        validate_rate "$eg_etar" || { warn "输入不合法，重置为 0"; eg_etar=0; }
        eg_host_part="$(format_host_for_url "$eg_host")"
        eg_query="morph=${eg_morph}"
        if [ "$eg_dial_mode" = "dual" ]; then
            [[ "$eg_dial4" != "auto" ]] && eg_query="${eg_query}&dial4=$(urlencode "$eg_dial4")"
            [[ "$eg_dial6" != "auto" ]] && eg_query="${eg_query}&dial6=$(urlencode "$eg_dial6")"
        elif [ "$eg_dial" != "auto" ]; then
            eg_query="${eg_query}&dial=$(urlencode "$eg_dial")"
        fi
        [[ "$eg_rate" != "0" ]] && eg_query="${eg_query}&rate=${eg_rate}"
        [[ "$eg_etar" != "0" ]] && eg_query="${eg_query}&etar=${eg_etar}"
        [[ -n "$eg_sni" ]] && eg_query="${eg_query}&sni=$(urlencode "$eg_sni")"
        [[ -n "$eg_pin" ]] && eg_query="${eg_query}&pin=${eg_pin}"
        eg_url="egress://${eg_key}@${eg_host_part}/${eg_carrier}${eg_family}:${eg_port}?${eg_query}"
    fi

    if [ "$eg_morph" = "1" ]; then
        echo ""
        echo -e "${BOLD}Morph Prelude 策略${NC}（Egress 是发起端，这个设置在本机生效；Portal 三种都收，两端无需一致）："
        echo "  1) fade（默认）  2) full8  3) low7"
        read -rp "选择 [1/2/3，默认1]: " EG_PRELUDE_CHOICE
        case ${EG_PRELUDE_CHOICE:-1} in 2) eg_prelude="full8" ;; 3) eg_prelude="low7" ;; *) eg_prelude="fade" ;; esac
    fi

    echo ""
    divider
    echo -e "  Portal 地址 : ${GREEN}${eg_host}:${eg_port} (${eg_carrier}${eg_family})${NC}"
    echo -e "  共享密钥    : ${GREEN}$(mask_secret "$eg_key")${NC}"
    echo -e "  Morph       : ${GREEN}${eg_morph}$([ "$eg_morph" = "1" ] && echo "（Prelude ${eg_prelude}）")${NC}"
    echo -e "  Egress URL  : ${GREEN}${eg_url/$eg_key/$(mask_secret "$eg_key")}${NC}"
    divider
    read -rp "确认安装为 Egress 服务 [y/N]: " EG_CONFIRM2
    [[ ! "$EG_CONFIRM2" =~ ^[Yy]$ ]] && { info "已取消"; return; }
    step "安装系统依赖"
    divider
    apt_install curl tar ca-certificates python3 || warn "部分依赖安装失败，继续尝试"
    local need_download=1 have_ver=""
    if [ -x "$BIN_PATH" ]; then
        have_ver="$(${BIN_PATH} --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
        if [ "$eg_carrier" = "tcp" ] && ! version_ge "${have_ver:-0}" "3.3.0"; then
            warn "TLS 载体的 Egress 需要 Nowhere ≥ v3.3.0，本机现有二进制为 ${have_ver:-未知}，将下载最新版"
        else
            read -rp "已检测到 nowhere 二进制（${have_ver:-未知版本}），是否跳过下载直接使用？[Y/n]: " EG_REUSE
            if [[ ! "${EG_REUSE:-y}" =~ ^[Nn]$ ]]; then
                need_download=0
                info "复用现有二进制: $(${BIN_PATH} --version 2>&1 | head -1)"
            fi
        fi
    fi
    if [ "$need_download" = "1" ]; then
        install_nowhere_binary_only || { warn "二进制下载失败，安装中止"; return; }
    fi
    step "保存 Egress 配置并创建 systemd 服务"
    divider
    install -d -m 700 "$CONFIG_DIR"
    cat > "$EGRESS_CONFIG_FILE" << EGENVEOF
NOWHERE_EGRESS="${eg_url}"
EGRESS_PORTAL_HOST="${eg_host}"
EGRESS_PORTAL_PORT="${eg_port}"
EGRESS_CARRIER="${eg_carrier}"
EGRESS_MORPH="${eg_morph}"
EGENVEOF
    chmod 600 "$EGRESS_CONFIG_FILE"
    cat > "$SERVICE_FILE" << EGSEOF
[Unit]
Description=Nowhere Egress
Documentation=https://github.com/${REPO}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=${EGRESS_CONFIG_FILE}
Environment=NOW_MORPH_TCP_PRELUDE=${eg_prelude}
Environment=NOW_MORPH_UDP_PRELUDE=${eg_prelude}
ExecStart=${BIN_PATH} \${NOWHERE_EGRESS}
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
NoNewPrivileges=true
PrivateTmp=false
ProtectSystem=full
ProtectHome=read-only

[Install]
WantedBy=multi-user.target
EGSEOF
    echo "egress" > "$ROLE_FILE"
    systemctl daemon-reload
    systemctl enable nowhere
    systemctl restart nowhere || true
    sleep 3
    if systemctl is-active --quiet nowhere; then
        success "Egress 服务已启动（注册结果请看日志：ACCEPTED 为成功；BUSY 表示 Portal 的待命注册容量已满（主要出现在 TLS 载体），本机会自动重试）"
    else
        warn "Egress 服务未能启动，日志如下："
        journalctl -u nowhere -n 30 --no-pager || true
        warn "安装中止：请按日志排查（常见：密钥 / pin / 端口 / Portal 未设 out=egress / 载体与 Portal 监听不对应）"
        return
    fi
    cat > "$EGRESS_CONFIG_TXT" << EGCONFEOF
════════════════════════════════════════════════════════════════
  Nowhere Egress 连接信息（${TARGET_NW_VERSION} / NW3）
  更新时间: $(date '+%Y-%m-%d %H:%M:%S')
════════════════════════════════════════════════════════════════

【出口机启动参数（Egress URL，用于 systemd ExecStart）】
${eg_url}

【说明】
  Portal 地址 : ${eg_host}:${eg_port} (${eg_carrier}${eg_family})
  Morph       : ${eg_morph}（须与 Portal 一致）$([ "$eg_morph" = "1" ] && echo "，Prelude 策略 ${eg_prelude}")
  本机角色    : Egress（主动回连 Portal，无需本机开放入站端口）
  v3.3.0 起同一 Portal 可同时接受多台 Egress（TLS / QUIC 可混用，Portal 按先进先出轮转，不保证均衡）。
  TLS 载体下每条 Flow 独占一条连接，本机会自动预建待命连接；BUSY 表示 Portal 的待命容量已满。
  tls=1 时 pin 随 Portal 重启变化，Portal 重启后需在本机更新 egress.env 里的 pin 并重启服务。
════════════════════════════════════════════════════════════════
EGCONFEOF
    chmod 600 "$EGRESS_CONFIG_TXT"
    cat "$EGRESS_CONFIG_TXT"
    if [ -n "$old_portal_specs" ] && ufw_installed; then
        echo ""
        if confirm "本机不再是 Portal：删除防火墙里原 Portal 端口的放行规则（$(echo $old_portal_specs)）？" y; then
            local ops
            for ops in $old_portal_specs; do
                if [ "$ops" = "80/tcp" ]; then continue; fi
                fw_delete_spec "$ops"
            done
        fi
    fi
    echo ""
    info "常用命令：systemctl status nowhere / journalctl -u nowhere -f / ${MANAGER_PATH} status"
    install_shortcuts || true
}

do_uninstall() {
    step "卸载 Nowhere"
    divider
    read -rp "确认卸载 [y/N]: " CONFIRM
    [[ ! "$CONFIRM" =~ ^[Yy]$ ]] && { info "已取消"; return; }
    local old_specs s cron_now
    old_specs="$(nowhere_ports 2>/dev/null || true)"
    systemctl disable --now nowhere 2>/dev/null || true
    rm -f "$SERVICE_FILE" "$BIN_PATH" "$BIN_BACKUP_PATH" "$ROLE_FILE"
    rm -f /etc/letsencrypt/renewal-hooks/deploy/restart-nowhere.sh
    cron_now="$(crontab -l 2>/dev/null || true)"
    if [[ "$cron_now" == *"certbot renew"*"restart nowhere"* ]]; then
        printf '%s\n' "$cron_now" | grep -v 'certbot renew.*restart nowhere' | crontab - || true
        info "已移除 certbot 续期的 cron 兜底任务"
    fi
    if [ -n "$old_specs" ] && ufw_installed; then
        if confirm "同时删除防火墙里 Nowhere 端口的放行规则（$(echo $old_specs)）？" y; then
            for s in $old_specs; do
                if [ "$s" = "80/tcp" ]; then continue; fi
                fw_delete_spec "$s"
            done
        fi
    fi
    if [ -f /etc/cloudflare/credentials.ini ]; then
        if confirm "删除保存的 Cloudflare API 凭证（/etc/cloudflare/credentials.ini）？" n; then
            rm -f /etc/cloudflare/credentials.ini
            info "已删除 Cloudflare 凭证"
        fi
    fi
    read -rp "是否同时删除快捷命令 adam/zt/pz/cxpz/cq？[y/N]: " RM_SHORTCUTS
    if [[ "$RM_SHORTCUTS" =~ ^[Yy]$ ]]; then
        if [ -x "$SNELL_BIN" ] || ufw_installed || f2b_installed; then
            warn "删除后 Snell / 防火墙 / Fail2ban 的管理入口需改用 ${MANAGER_PATH} 直接运行（Snell 自动更新不受影响）"
        fi
        rm -f /usr/local/bin/adam /usr/local/bin/zt /usr/local/bin/pz /usr/local/bin/cxpz /usr/local/bin/cq
        info "快捷命令已删除（管理脚本副本 ${MANAGER_PATH} 已保留，如需清除请手动删除）"
    fi
    systemctl daemon-reload
    warn "已保留 ${CONFIG_DIR}（含密钥配置与证书文件），如需彻底清除请手动: rm -rf ${CONFIG_DIR}"
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
    latest="$(get_latest_tag)"
    [ -z "$latest" ] && error "无法获取版本号（GitHub API 与 releases/latest 跳转均失败），请检查网络"
    info "最新版本: ${latest}"

    if [ "$current" = "$latest" ]; then
        info "已经是最新版本，无需更新"
        return
    fi

    local cur_major latest_major cross_major=0
    cur_major="$(version_major "$current")"
    latest_major="$(version_major "$latest")"
    if [[ -n "$cur_major" && -n "$latest_major" && "$cur_major" != "$latest_major" ]]; then
        cross_major=1
        warn "这是跨协议代升级（NW${cur_major} -> NW${latest_major}）：新旧对端不互通，Vector/Egress/Anywhere 必须一起升级"
        warn "且不同协议代的密钥格式、URL 参数可能不兼容，仅换二进制不重配大概率启动失败或连不上"
        read -rp "确认跨代升级 [y/N]: " MAJOR_CONFIRM
        [[ ! "$MAJOR_CONFIRM" =~ ^[Yy]$ ]] && { info "已取消"; return; }
    elif [ "$(current_role)" = "portal" ] && version_ge "$latest" "v3.2.0" && ! version_ge "$current" "v3.2.0"; then
        warn "本次升级会跨过 v3.2.0：此后 Portal 只接受带认证的 Morph TCP Prelude，仍在 v3.0.x 的 Vector/Egress/Anywhere（morph=1 + TLS/TCP）会连不上"
        warn "稳妥做法：先把对端升级到 ≥ v3.1.0，再升级本机 Portal"
        read -rp "对端已就绪，继续升级 [y/N]: " PRELUDE_CONFIRM
        [[ ! "$PRELUDE_CONFIRM" =~ ^[Yy]$ ]] && { info "已取消"; return; }
    fi

    install_nowhere_version "$latest" || error "更新失败"
    if [ "$cross_major" = "1" ]; then
        warn "跨代升级后请接着用菜单「4) 重新配置」按新版向导重建配置（新密钥 + 新 URL），再同步更新所有对端"
    fi
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
    echo -e "  本机角色          : ${GREEN}$(current_role)${NC}"
    echo -e "  管理脚本版本      : ${GREEN}${SCRIPT_VERSION}${NC}（适配 Nowhere ${TARGET_NW_VERSION}）"

    echo ""
    info "正在查询 GitHub 最新版本..."
    local latest
    latest="$(get_latest_tag)"
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
    done < <(curl -s --max-time 20 "https://api.github.com/repos/${REPO}/releases?per_page=20" | grep '"tag_name"' | cut -d'"' -f4)

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
    read -rp "选择要切换到的版本序号: " VER_CHOICE

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

    read -rp "确认切换到 ${target} [y/N]: " CONFIRM
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
    read -rp "确认回退 [y/N]: " CONFIRM
    [[ ! "$CONFIRM" =~ ^[Yy]$ ]] && { info "已取消"; return; }

    local tmp_bin
    tmp_bin="$(mktemp /tmp/nowhere.swap.XXXXXX)"
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

    systemctl start nowhere 2>/dev/null || true
    sleep 2
    if systemctl is-active --quiet nowhere; then
        success "已回退到: $(${BIN_PATH} --version 2>&1 | head -1)"
    else
        warn "回退后服务启动失败，日志如下："
        journalctl -u nowhere -n 20 --no-pager || true
    fi
}

do_reconfig() {
    step "重新配置"
    divider
    warn "将重新走一遍安装向导并覆盖当前配置"
    warn "注意：v3 密钥与 URL 语法已变更，重新配置后务必把新的 Vector/Egress/Anywhere 连接信息同步到所有对端，旧链接无法继续使用"
    read -rp "确认继续 [y/N]: " CONFIRM
    [[ ! "$CONFIRM" =~ ^[Yy]$ ]] && return
    do_install
}

do_show_config() {
    step "连接信息"
    divider
    if [ "$(current_role)" = "egress" ]; then
        if [ -f "$EGRESS_CONFIG_TXT" ]; then
            cat "$EGRESS_CONFIG_TXT"
        else
            warn "本机为 Egress 角色，但未找到 ${EGRESS_CONFIG_TXT}，请用菜单 17 重新安装"
        fi
        return 0
    fi
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
    # systemctl status 在服务停止时返回非 0：旧版在 set -e 下会在这里直接退出，
    # 恰好是服务挂了、最需要看后面日志的时候
    systemctl status nowhere --no-pager || true
    divider
    if [ -x "$BIN_PATH" ]; then
        info "Nowhere 本地实例快照（nowhere status，v3 内置遥测）："
        "$BIN_PATH" status 2>&1 || warn "nowhere status 未能读取到实例（服务未运行，或二进制版本低于 v2.1.2 无此命令）"
        divider
    fi
    info "最近日志（20行）："
    journalctl -u nowhere -n 20 --no-pager || true
}

do_show_logs() {
    step "实时日志（Ctrl+C 退出）"
    divider
    journalctl -u nowhere -f || true
}

do_fingerprint() {
    if [ "$(current_role)" = "egress" ]; then
        info "本机是 Egress 角色，没有监听证书；Portal 的证书指纹请在 Portal 机上查看"
        return 0
    fi
    load_saved_config
    print_tls_fingerprint
}

do_restart() {
    systemctl restart nowhere || true
    sleep 1
    if systemctl is-active --quiet nowhere; then
        success "已重启"
    else
        journalctl -u nowhere -n 15 --no-pager || true
        error "重启失败，请按上方日志排查"
    fi
    if [ "$(current_role)" = "egress" ] || [ ! -f "$CONFIG_FILE" ]; then
        return 0
    fi
    load_saved_config
    print_tls_fingerprint
    if [[ "${TLS_MODE:-}" == "1" ]]; then
        warn "自签证书指纹已随本次重启变化，请用 pz/菜单 5 重新生成带新 pin= 的 Vector/Egress 连接串并同步到对端"
    fi
    return 0
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
    if [ "$(current_role)" = "egress" ]; then
        info "本机是 Egress 角色：probe 需要以 Vector 身份连接 Portal，请在 Portal 机或客户端机上执行"
        return 0
    fi
    load_saved_config
    is_valid_key "$SHARED_KEY" || error "当前密钥不符合 v3 规范，无法探测，请先用菜单 4 重新配置"
    local vector_url target
    vector_url="$(build_probe_vector_url)"
    read -rp "目标地址 host:port（回车默认 example.com:443）: " target
    target=${target:-example.com:443}
    info "Vector: ${vector_url/$SHARED_KEY/$(mask_secret "$SHARED_KEY")}"
    info "Target: ${target}"
    export NOW_MORPH_TCP_PRELUDE="${MORPH_TCP_PRELUDE:-fade}"
    export NOW_MORPH_UDP_PRELUDE="${MORPH_UDP_PRELUDE:-fade}"
    "$BIN_PATH" probe "$vector_url" "$target" || warn "探测未成功（Result 非 OK）。常见原因：Portal 出口不可达、没有可用的 Egress（会等到 Flow 建立超时）、对端 Morph/pin/密钥不一致、目标本身不可达"
}

do_cert_status() {
    step "证书状态与续期"
    divider
    if [ "$(current_role)" = "egress" ]; then
        info "本机是 Egress 角色，不持有监听证书，无需续期"
        return 0
    fi
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
    read -rp "是否立即手动触发一次续期检查？（仅当证书满足续期条件时才会真的续签）[y/N]: " DO_RENEW
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
        warn "尚未安装 ufw，请先在防火墙菜单执行「1) 安装防火墙」（或 adam fw install）"
        return 1
    fi
    return 0
}

fw_state_text() {
    if ! ufw_installed; then
        printf '%s' "${YELLOW}未安装${NC}"
    elif ufw_active; then
        printf '%s' "${GREEN}已启用${NC}"
    else
        printf '%s' "${RED}未启用${NC}"
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

# 本脚本管理的全部服务端口（Nowhere + Snell），每行一个 ufw 规格
managed_ports() {
    local sp
    nowhere_ports
    sp="$(snell_port)"
    if [ -n "$sp" ]; then echo "${sp}/tcp"; fi
    xray_ports
    return 0
}

fw_allow_ssh() {
    local p
    for p in $(detect_ssh_ports); do
        ufw allow "${p}/tcp" >/dev/null 2>&1 || true
    done
    return 0
}

fw_sync_managed() {
    local spec n=0
    while IFS= read -r spec; do
        [ -n "$spec" ] || continue
        if ufw allow "$spec" >/dev/null 2>&1; then
            info "已放行本脚本服务端口: ${spec}"
            n=$((n + 1))
        fi
    done < <(managed_ports)
    if [ "$n" -eq 0 ]; then
        info "当前没有由本脚本管理的服务端口需要放行（Nowhere / Snell / Xray 均未安装）"
    fi
    return 0
}

# fw_is_allowed PORT PROTO：是否已有覆盖该端口的 allow 规则（防火墙未启用时也能查）
fw_is_allowed() {
    local port="$1" proto="$2" added
    added="$(LC_ALL=C ufw show added 2>/dev/null || true)"
    printf '%s\n' "$added" | awk -v p="$port" -v pr="$proto" '
        $1 == "ufw" && $2 == "allow" {
            split($3, a, "/"); rng = a[1]; rp = a[2]
            if (rp != "" && rp != pr) next
            n = split(rng, b, ":")
            if (n == 1 && b[1] == p) f = 1
            if (n == 2 && p + 0 >= b[1] + 0 && p + 0 <= b[2] + 0) f = 1
        }
        END { exit !f }'
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
            if (host ~ /^127\./ || host == "[::1]" || host ~ /^\[?fe80/) next
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
                warn "以下端口正在对外监听，但还没有在防火墙里放行（启用后外部将无法访问）："
                shown=1
            fi
            echo -e "    ${YELLOW}${spec}${NC}  ${proc}"
        fi
    done < <(fw_listening_ports)
    if [ "$shown" -eq 1 ]; then
        info "需要对外提供服务的端口，请用「3) 放行端口」添加后再启用"
    fi
    return 0
}

fw_warn_conflicts() {
    local rules=""
    if command -v iptables >/dev/null 2>&1; then
        rules="$(iptables -S INPUT 2>/dev/null || true)"
        if [[ "$rules" == *"-j FWIN"* ]]; then
            warn "检测到 cnblock 的端口防火墙链 FWIN 已挂在 INPUT 上：两套入站防火墙会叠加（两边都放行才通），建议只保留一套（cnblock fw off，或不启用 ufw）"
        fi
    fi
    if systemctl is-active --quiet firewalld 2>/dev/null; then
        warn "检测到 firewalld 正在运行，与 ufw 同时启用会互相覆盖规则，请只保留一个"
    fi
    if command -v docker >/dev/null 2>&1; then
        info "提示：Docker 用 -p 发布的端口走 FORWARD 链，不受 ufw 入站规则限制"
    fi
    return 0
}

fw_enable() {
    fw_require || return 1
    if ufw_active; then
        info "防火墙已是启用状态"
        return 0
    fi
    fw_warn_conflicts
    info "启用前先放行 SSH 端口（$(detect_ssh_ports)），避免把自己锁在外面"
    fw_allow_ssh
    fw_sync_managed
    fw_show_unallowed_listening
    echo ""
    if ! confirm "确认启用防火墙？（默认拒绝所有入站，仅放行已添加的端口）" y; then
        info "已取消，防火墙保持未启用"
        return 0
    fi
    ufw --force enable >/dev/null 2>&1 || true
    if ufw_active; then
        success "防火墙已启用（开机自动生效）"
    else
        warn "启用失败，请查看: ufw status verbose"
        return 1
    fi
    return 0
}

fw_disable() {
    fw_require || return 1
    if ! ufw_active; then
        info "防火墙当前未启用"
        return 0
    fi
    warn "停用后所有端口不再受 ufw 过滤（已添加的规则会保留，可随时重新启用）"
    if ! confirm "确认停用防火墙？" n; then
        info "已取消"
        return 0
    fi
    ufw disable >/dev/null 2>&1 || true
    success "防火墙已停用"
    return 0
}

fw_install() {
    step "安装防火墙（ufw）"
    divider
    if ufw_installed; then
        info "ufw 已安装"
    else
        info "正在安装 ufw ..."
        apt_install ufw || { warn "ufw 安装失败，请检查 apt 源/网络"; return 1; }
        success "ufw 安装完成"
    fi
    if ufw_active; then
        success "防火墙已处于启用状态，补齐 SSH 与本脚本服务端口的放行规则"
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
            warn "无法识别的端口写法: ${item}"
            return 1
        fi
        a="${BASH_REMATCH[1]}"; b="${BASH_REMATCH[3]}"; proto="${BASH_REMATCH[5]}"
        a=$((10#$a))
        if [ "$a" -lt 1 ] || [ "$a" -gt 65535 ]; then warn "端口超出范围: ${item}"; return 1; fi
        if [ -n "$b" ]; then
            b=$((10#$b))
            if [ "$b" -lt 1 ] || [ "$b" -gt 65535 ]; then warn "端口超出范围: ${item}"; return 1; fi
            if [ "$a" -ge "$b" ]; then warn "端口范围的起点必须小于终点: ${item}"; return 1; fi
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
        echo "输入要放行的端口：逗号分隔，支持范围与协议后缀"
        echo "  例：80,443,2053    400-500    443/tcp,51820/udp   （不写协议 = TCP 和 UDP 都放行）"
        read -rp "端口: " input
    fi
    if ! fw_parse_specs "$input"; then
        warn "输入不合法，未做任何修改"
        return 1
    fi
    for spec in "${FW_SPECS[@]}"; do
        if ufw allow "$spec" >/dev/null 2>&1; then
            success "已放行 ${spec}"
        else
            warn "放行失败: ${spec}"
        fi
    done
    if ! ufw_active; then
        warn "注意：防火墙当前未启用，规则已保存，启用后才生效"
    fi
    return 0
}

# 删除一条放行规则；不带协议时把 端口 / 端口/tcp / 端口/udp 三种写法都清掉
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
        success "已删除放行规则: ${spec}"
    else
        info "没有找到 ${spec} 的放行规则"
    fi
    return 0
}

fw_delete_by_number() {
    local nums n line rule_port listing
    local sshp=" $(detect_ssh_ports) "
    if ! ufw_active; then
        warn "防火墙未启用时 ufw 不显示规则编号，请改用「按端口」删除"
        return 1
    fi
    read -rp "输入要删除的规则编号（逗号分隔，如 3,5）: " nums
    nums="${nums//[[:space:]]/}"
    if [[ ! "$nums" =~ ^[0-9]+(,[0-9]+)*$ ]]; then
        warn "输入不合法，未做任何修改"
        return 1
    fi
    listing="$(LC_ALL=C ufw status numbered 2>/dev/null || true)"
    for n in $(printf '%s\n' "$nums" | tr ',' '\n' | sort -rnu); do
        line="$(printf '%s\n' "$listing" | grep -E "^\[ *${n}\]" || true)"
        if [ -z "$line" ]; then
            warn "编号 ${n} 不存在，已跳过"
            continue
        fi
        rule_port="$(printf '%s' "$line" | sed -E 's/^\[ *[0-9]+\] *//' | awk '{print $1}' | cut -d/ -f1)"
        if [[ "$sshp" == *" ${rule_port} "* && "$line" == *"ALLOW"* ]]; then
            warn "规则 [${n}] 是 SSH 端口的放行规则: ${line#*] }"
            if ! confirm "删除后可能无法再通过 SSH 登录，确认删除？" n; then
                info "已跳过 [${n}]"
                continue
            fi
        fi
        if ufw --force delete "$n" >/dev/null 2>&1; then
            success "已删除规则 [${n}] ${line#*] }"
        else
            warn "删除规则 [${n}] 失败"
        fi
    done
    return 0
}

fw_delete_ports() {
    fw_require || return 1
    local input="${1:-}" choice="" spec p
    local sshp=" $(detect_ssh_ports) "
    if [ -n "$input" ]; then
        choice=2
    else
        echo "当前规则："
        ufw status numbered 2>/dev/null || true
        echo ""
        echo "删除方式："
        echo "  1) 按规则编号（上表方括号里的数字）"
        echo "  2) 按端口"
        read -rp "请选择 [1/2]: " choice
    fi
    case "$choice" in
        1) fw_delete_by_number ;;
        2)
            if [ -z "$input" ]; then
                read -rp "输入要删除的端口（写法同放行，如 80,443 或 400-500）: " input
            fi
            if ! fw_parse_specs "$input"; then
                warn "输入不合法，未做任何修改"
                return 1
            fi
            for spec in "${FW_SPECS[@]}"; do
                p="${spec%%/*}"
                if [[ "$sshp" == *" ${p} "* ]]; then
                    warn "${p} 是当前的 SSH 端口"
                    if ! confirm "删除后可能无法再通过 SSH 登录，确认删除？" n; then
                        info "已跳过 ${spec}"
                        continue
                    fi
                fi
                fw_delete_spec "$spec"
            done
            ;;
        *) warn "无效选择"; return 1 ;;
    esac
    return 0
}

fw_list() {
    fw_require || return 1
    if ufw_active; then
        ufw status numbered 2>/dev/null || true
    else
        warn "防火墙未启用，以下是已保存、启用后才生效的规则："
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
        warn "未安装 ufw，已跳过防火墙配置（可用主菜单「防火墙管理」安装）；请确认云厂商安全组已放行: $*"
        return 0
    fi
    fw_allow_ssh
    for spec in "$@"; do
        ufw allow "$spec" >/dev/null 2>&1 || warn "放行失败: ${spec}"
    done
    if ufw_active; then
        success "防火墙已放行: $*"
        return 0
    fi
    info "ufw 当前未启用，已预先保存放行规则: $*"
    fw_warn_conflicts
    fw_sync_managed >/dev/null
    fw_show_unallowed_listening
    if confirm "是否现在启用防火墙？（默认拒绝入站，仅放行已添加的端口）" y; then
        ufw --force enable >/dev/null 2>&1 || true
        if ufw_active; then success "防火墙已启用"; else warn "启用失败，请查看: ufw status verbose"; fi
    else
        warn "已跳过启用防火墙，请确认云厂商安全组 / 其他防火墙已放行: $*"
    fi
    return 0
}

# 重新配置换了端口后，清掉旧端口的放行规则（SSH、80、仍在使用的端口不动）
fw_prune_old_specs() {
    local old="$1" spec keep
    local sshp=" $(detect_ssh_ports) "
    ufw_installed || return 0
    keep=" $(managed_ports | tr '\n' ' ') "
    for spec in $old; do
        [ "$spec" = "80/tcp" ] && continue
        [[ "$keep" == *" ${spec} "* ]] && continue
        [[ "$sshp" == *" ${spec%%/*} "* ]] && continue
        info "端口已变更，清理旧的放行规则: ${spec}"
        fw_delete_spec "$spec"
    done
    return 0
}

fw_menu() {
    local choice
    while true; do
        clear 2>/dev/null || true
        echo -e "${BOLD}${CYAN}━━━ 防火墙管理（ufw） ━━━${NC}"
        echo -e "  当前状态: $(fw_state_text)    SSH 端口: $(detect_ssh_ports)"
        divider
        echo -e "  ${GREEN}1)${NC} ${GREEN}安装${NC}防火墙（自动放行 SSH 与本脚本服务端口）"
        echo -e "  ${GREEN}2)${NC} 端口列表（带编号）"
        echo -e "  ${GREEN}3)${NC} ${GREEN}放行${NC}端口（TCP / UDP）"
        echo -e "  ${GREEN}4)${NC} ${RED}删除${NC}已放行的端口"
        echo -e "  ${GREEN}5)${NC} ${GREEN}启用${NC}防火墙"
        echo -e "  ${GREEN}6)${NC} ${RED}停用${NC}防火墙"
        echo -e "  ${GREEN}7)${NC} 防火墙状态（详细）"
        echo -e "  ${GREEN}8)${NC} 一键放行本脚本服务端口（SSH / Nowhere / Snell / Xray）"
        echo -e "  ${GREEN}0)${NC} 返回主菜单"
        divider
        read -rp "请选择 [0-8]: " choice
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
            *) warn "无效选择" ;;
        esac
        pause_return
    done
}

fw_sync_cmd() {
    fw_require || return 1
    fw_allow_ssh
    info "已确认 SSH 端口放行: $(detect_ssh_ports)"
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
            [ -n "${1:-}" ] || error "用法: adam fw allow <端口[,端口...]>，如 adam fw allow 443/tcp,8000-8100"
            fw_open_ports "$1" ;;
        deny|delete|close)
            [ -n "${1:-}" ] || error "用法: adam fw deny <端口[,端口...]>"
            fw_delete_ports "$1" ;;
        sync)            fw_sync_cmd ;;
        *) error "未知的 fw 子命令: ${sub}（可用: install / list / status / on / off / allow <端口> / deny <端口> / sync）" ;;
    esac
}

# ══════════════════════════════════════════════════════════════
#   Fail2ban 管理 —— 菜单结构参考 3x-ui 的 IP Limit Management
#   3x-ui 的 jail 针对 Xray 的 IP 数量限制；这里没有 Xray，防护对象是 SSH 爆破。
#   配置只写在 jail.d/adam-sshd.local 一个文件里，不碰 jail.conf / jail.local。
# ══════════════════════════════════════════════════════════════

f2b_installed() { command -v fail2ban-client >/dev/null 2>&1; }
f2b_running()   { systemctl is-active --quiet fail2ban 2>/dev/null; }

f2b_require() {
    if ! f2b_installed; then
        warn "尚未安装 Fail2ban，请先执行「1) 安装 Fail2ban」（或 adam f2b install）"
        return 1
    fi
    return 0
}

f2b_require_running() {
    f2b_require || return 1
    if ! f2b_running; then
        warn "Fail2ban 服务未运行，请先执行「10) 启用」或「9) 重启」"
        return 1
    fi
    return 0
}

f2b_state_text() {
    local n=""
    if ! f2b_installed; then
        printf '%s' "${YELLOW}未安装${NC}"
    elif f2b_running; then
        n="$(fail2ban-client status "$F2B_JAIL" 2>/dev/null | sed -n 's/.*Currently banned:[[:space:]]*//p' || true)"
        printf '%s' "${GREEN}运行中${NC}${n:+（当前封禁 ${n} 个）}"
    else
        printf '%s' "${RED}已停止${NC}"
    fi
}

# f2b_get KEY [DEFAULT]：读取本脚本 jail 文件里的当前值
f2b_get() {
    local key="$1" def="${2:-}" v=""
    if [ -f "$F2B_JAIL_FILE" ]; then
        v="$(awk -v k="$key" '
            /^[ \t]*#/ { next }
            {
                i = index($0, "="); if (i == 0) next
                kk = substr($0, 1, i - 1); gsub(/[ \t]/, "", kk)
                if (kk == k) { v = substr($0, i + 1); gsub(/^[ \t]+|[ \t\r]+$/, "", v); print v; exit }
            }' "$F2B_JAIL_FILE" 2>/dev/null || true)"
    fi
    printf '%s' "${v:-$def}"
}

# 没有 /var/log/auth.log 的系统（Debian 12+ 默认不装 rsyslog）只能读 systemd journal
f2b_pick_backend() {
    if [ -s /var/log/auth.log ]; then printf 'auto'; else printf 'systemd'; fi
}

f2b_pick_banaction() {
    if command -v iptables >/dev/null 2>&1; then
        printf 'iptables-multiport'
    elif [ -f /etc/fail2ban/action.d/nftables-multiport.conf ]; then
        printf 'nftables-multiport'
    else
        printf 'nftables[type=multiport]'
    fi
}

# f2b_write_jail BANTIME FINDTIME MAXRETRY IGNOREIP [BACKEND]
f2b_write_jail() {
    local bantime="$1" findtime="$2" maxretry="$3" ignoreip="$4" backend="${5:-}"
    local ports banaction
    if [ -z "$backend" ]; then backend="$(f2b_pick_backend)"; fi
    ports="$(detect_ssh_ports | tr ' ' ',')"
    banaction="$(f2b_pick_banaction)"
    install -d -m 755 /etc/fail2ban/jail.d
    cat > "$F2B_JAIL_FILE" << F2BEOF
# 由 Adam 管理脚本生成（adam -> Fail2ban 管理）。请通过菜单修改，手动改动会在下次调整时被覆盖。
# 用 jail.d/*.local：读取顺序在 jail.conf、jail.d/*.conf、jail.local 之后，同名项以这里为准。
[sshd]
enabled = true
port = ${ports}
backend = ${backend}
banaction = ${banaction}
bantime = ${bantime}
findtime = ${findtime}
maxretry = ${maxretry}
ignoreip = ${ignoreip}
F2BEOF
    chmod 644 "$F2B_JAIL_FILE"
}

f2b_rewrite_keep() {
    f2b_write_jail "$(f2b_get bantime 30m)" "$(f2b_get findtime 10m)" "$(f2b_get maxretry 5)" \
        "$(f2b_get ignoreip '127.0.0.1/8 ::1')" "${1:-$(f2b_get backend '')}"
}

# 重启并确认 sshd jail 真的起来了（服务 active 不等于 jail 已加载）
f2b_apply() {
    local i
    systemctl enable fail2ban >/dev/null 2>&1 || true
    systemctl restart fail2ban >/dev/null 2>&1 || true
    for i in 1 2 3 4 5 6 7 8 9 10; do
        if fail2ban-client ping >/dev/null 2>&1 && fail2ban-client status "$F2B_JAIL" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

f2b_diagnose_and_fix() {
    local log backend
    log="$( { journalctl -u fail2ban -n 40 --no-pager 2>/dev/null; fail2ban-client -t 2>&1; } || true)"
    backend="$(f2b_get backend auto)"
    if [[ "$log" == *"asynchat"* || "$log" == *"asyncore"* ]]; then
        warn "fail2ban 与当前 Python 版本不兼容（缺 asynchat/asyncore，常见于 Ubuntu 24.04 的初版软件包），尝试升级 fail2ban ..."
        apt-get update -qq || true
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --only-upgrade fail2ban || true
        if f2b_apply; then return 0; fi
    fi
    if [ "$backend" != "systemd" ]; then
        warn "按日志文件方式启动失败（常见原因：系统没有 /var/log/auth.log），改用 systemd journal 后端重试 ..."
        apt_install python3-systemd || true
        f2b_rewrite_keep systemd
        if f2b_apply; then return 0; fi
    fi
    warn "Fail2ban 仍未能正常启动，最近日志："
    journalctl -u fail2ban -n 15 --no-pager 2>/dev/null || true
    fail2ban-client -t 2>&1 | tail -n 5 || true
    return 1
}

f2b_show_settings() {
    echo -e "  防护端口 : ${GREEN}$(f2b_get port ssh)${NC}"
    echo -e "  封禁时长 : ${GREEN}$(f2b_get bantime 30m)${NC}（-1 表示永久）"
    echo -e "  触发条件 : ${GREEN}$(f2b_get findtime 10m)${NC} 内失败 ${GREEN}$(f2b_get maxretry 5)${NC} 次"
    echo -e "  白名单   : ${GREEN}$(f2b_get ignoreip '127.0.0.1/8 ::1')${NC}"
    echo -e "  日志后端 : ${GREEN}$(f2b_get backend auto)${NC}    封禁动作: ${GREEN}$(f2b_get banaction -)${NC}"
}

f2b_install() {
    step "安装 Fail2ban 并启用 SSH 防护"
    divider
    local backend ignoreip myip
    local -a pkgs=(fail2ban)
    backend="$(f2b_pick_backend)"
    if [ "$backend" = "systemd" ]; then pkgs+=(python3-systemd); fi
    if ! command -v iptables >/dev/null 2>&1 && ! command -v nft >/dev/null 2>&1; then pkgs+=(nftables); fi
    info "正在安装: ${pkgs[*]}"
    apt_install "${pkgs[@]}" || { warn "安装失败，请检查 apt 源/网络"; return 1; }

    # 消除 fail2ban 1.x 的 allowipv6 未设置告警（仅当发行版配置里有这一行时才改）
    sed -i 's/^#allowipv6 = auto/allowipv6 = auto/' /etc/fail2ban/fail2ban.conf 2>/dev/null || true

    ignoreip="$(f2b_get ignoreip '127.0.0.1/8 ::1')"
    myip="${SSH_CONNECTION%% *}"
    if [ -n "$myip" ] && is_ip "$myip" && [[ " $ignoreip " != *" $myip "* ]]; then
        if confirm "把你当前的登录 IP（${myip}）加入白名单，避免输错密码把自己封掉？" y; then
            ignoreip="${ignoreip} ${myip}"
        fi
    fi
    f2b_write_jail "$(f2b_get bantime 30m)" "$(f2b_get findtime 10m)" "$(f2b_get maxretry 5)" "$ignoreip" "$backend"
    if f2b_apply || f2b_diagnose_and_fix; then
        success "Fail2ban 已启动，SSH 防护生效"
        f2b_show_settings
        return 0
    fi
    return 1
}

f2b_require_managed() {
    f2b_require || return 1
    if [ ! -f "$F2B_JAIL_FILE" ]; then
        warn "未找到本脚本的 SSH 防护配置，请先执行「1) 安装 Fail2ban」生成"
        return 1
    fi
    return 0
}

f2b_set_bantime() {
    f2b_require_managed || return 1
    local v="${1:-}" re='^[1-9][0-9]*[smhdw]$'
    if [ -z "$v" ]; then
        echo "当前封禁时长: $(f2b_get bantime 30m)"
        read -rp "新的封禁时长（纯数字=分钟；也可写 10m / 1h / 1d / 1w；-1=永久）[默认 30]: " v
        v="${v:-30}"
    fi
    v="${v//[[:space:]]/}"
    if [[ "$v" =~ ^[1-9][0-9]*$ ]]; then
        v="${v}m"
    elif [[ "$v" =~ $re || "$v" == "-1" ]]; then
        :
    else
        warn "格式不合法: ${v}（示例：30 / 10m / 1h / 1d / -1）"
        return 1
    fi
    f2b_write_jail "$v" "$(f2b_get findtime 10m)" "$(f2b_get maxretry 5)" "$(f2b_get ignoreip '127.0.0.1/8 ::1')" "$(f2b_get backend '')"
    if f2b_apply || f2b_diagnose_and_fix; then
        success "封禁时长已改为 ${v}（对之后的新封禁生效）"
        return 0
    fi
    return 1
}

f2b_tune() {
    f2b_require_managed || return 1
    local mr ft re='^[1-9][0-9]*[smhdw]?$'
    echo "当前触发条件: $(f2b_get findtime 10m) 内失败 $(f2b_get maxretry 5) 次"
    read -rp "最大失败次数 maxretry [回车保持 $(f2b_get maxretry 5)]: " mr
    mr="${mr:-$(f2b_get maxretry 5)}"
    if [[ ! "$mr" =~ ^[1-9][0-9]*$ ]]; then warn "maxretry 必须是正整数"; return 1; fi
    read -rp "统计窗口 findtime（如 10m / 1h，纯数字=分钟）[回车保持 $(f2b_get findtime 10m)]: " ft
    ft="${ft:-$(f2b_get findtime 10m)}"
    ft="${ft//[[:space:]]/}"
    if [[ ! "$ft" =~ $re ]]; then warn "findtime 格式不合法"; return 1; fi
    if [[ "$ft" =~ ^[0-9]+$ ]]; then ft="${ft}m"; fi
    f2b_write_jail "$(f2b_get bantime 30m)" "$ft" "$mr" "$(f2b_get ignoreip '127.0.0.1/8 ::1')" "$(f2b_get backend '')"
    if f2b_apply || f2b_diagnose_and_fix; then
        success "触发条件已改为: ${ft} 内失败 ${mr} 次"
        return 0
    fi
    return 1
}

f2b_unban_all() {
    f2b_require_running || return 1
    if ! confirm "确认解封当前所有被封禁的 IP？" y; then
        info "已取消"
        return 0
    fi
    if fail2ban-client unban --all >/dev/null 2>&1; then
        success "已解封所有 IP"
    else
        warn "解封失败，请查看: fail2ban-client status ${F2B_JAIL}"
        return 1
    fi
    return 0
}

f2b_banned() {
    f2b_require_running || return 1
    local jails j out cur total ips
    jails="$(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' | tr -d ',' || true)"
    if [ -z "$jails" ]; then
        echo "  （没有启用的 jail）"
        return 0
    fi
    for j in $jails; do
        out="$(fail2ban-client status "$j" 2>/dev/null || true)"
        cur="$(printf '%s\n' "$out" | sed -n 's/.*Currently banned:[[:space:]]*//p')"
        total="$(printf '%s\n' "$out" | sed -n 's/.*Total banned:[[:space:]]*//p')"
        ips="$(printf '%s\n' "$out" | sed -n 's/.*Banned IP list:[[:space:]]*//p')"
        echo -e "  ${BOLD}[${j}]${NC} 当前封禁 ${cur:-0} 个，累计 ${total:-0} 次"
        if [ -n "$ips" ]; then echo "    ${ips}"; fi
    done
    return 0
}

f2b_banlog() {
    f2b_require || return 1
    local out=""
    info "最近的封禁 / 解封记录："
    if [ -f "$F2B_LOG" ]; then
        out="$(grep -E '\] (Ban|Unban|Restore Ban) ' "$F2B_LOG" 2>/dev/null | tail -n 20 || true)"
    else
        out="$(journalctl -u fail2ban --no-pager -n 2000 2>/dev/null | grep -E '\] (Ban|Unban|Restore Ban) ' | tail -n 20 || true)"
    fi
    if [ -n "$out" ]; then printf '%s\n' "$out"; else echo "  （暂无记录）"; fi
    echo ""
    info "当前封禁列表："
    f2b_banned || true
    return 0
}

f2b_ban_ip() {
    f2b_require_running || return 1
    local ip="${1:-}" myip="${SSH_CONNECTION%% *}"
    if [ -z "$ip" ]; then read -rp "输入要封禁的 IP 地址: " ip; fi
    ip="${ip//[[:space:]]/}"
    if ! is_ip "$ip"; then warn "IP 地址格式不合法: ${ip}"; return 1; fi
    if [ -n "$myip" ] && [ "$ip" = "$myip" ]; then
        warn "这是你当前登录所用的 IP，封禁后会立刻断开且无法重连，已拒绝"
        return 1
    fi
    if fail2ban-client set "$F2B_JAIL" banip "$ip" >/dev/null 2>&1; then
        success "已封禁 ${ip}（时长 $(f2b_get bantime 30m)）"
    else
        warn "封禁失败（jail ${F2B_JAIL} 是否已启用？）"
        return 1
    fi
    return 0
}

f2b_unban_ip() {
    f2b_require_running || return 1
    local ip="${1:-}"
    if [ -z "$ip" ]; then read -rp "输入要解封的 IP 地址: " ip; fi
    ip="${ip//[[:space:]]/}"
    if ! is_ip "$ip"; then warn "IP 地址格式不合法: ${ip}"; return 1; fi
    if fail2ban-client unban "$ip" >/dev/null 2>&1 || fail2ban-client set "$F2B_JAIL" unbanip "$ip" >/dev/null 2>&1; then
        success "已解封 ${ip}"
    else
        warn "解封失败（该 IP 可能本来就没有被封）"
        return 1
    fi
    return 0
}

f2b_live_log() {
    f2b_require || return 1
    info "实时日志（Ctrl+C 返回）"
    if [ -f "$F2B_LOG" ]; then
        tail -n 20 -f "$F2B_LOG" || true
    else
        journalctl -u fail2ban -n 20 -f || true
    fi
    return 0
}

f2b_status() {
    f2b_require || return 1
    systemctl status fail2ban --no-pager 2>/dev/null | head -n 12 || true
    divider
    if [ -f "$F2B_JAIL_FILE" ]; then
        f2b_show_settings
        divider
    fi
    if f2b_running; then f2b_banned || true; fi
    return 0
}

f2b_restart() {
    f2b_require || return 1
    if f2b_apply; then
        success "Fail2ban 已重启"
    elif [ -f "$F2B_JAIL_FILE" ]; then
        f2b_diagnose_and_fix || return 1
        success "Fail2ban 已重启"
    else
        systemctl is-active --quiet fail2ban || { warn "重启失败: journalctl -u fail2ban -n 30"; return 1; }
        success "Fail2ban 已重启"
    fi
    return 0
}

f2b_on() {
    f2b_require || return 1
    systemctl enable --now fail2ban >/dev/null 2>&1 || true
    sleep 1
    if f2b_running; then
        success "Fail2ban 已启用（开机自启）"
    else
        warn "启动失败: journalctl -u fail2ban -n 30 --no-pager"
        return 1
    fi
    return 0
}

f2b_off() {
    f2b_require || return 1
    systemctl disable --now fail2ban >/dev/null 2>&1 || true
    success "Fail2ban 已停用（现有封禁随服务停止而解除，配置保留）"
    return 0
}

f2b_whitelist() {
    f2b_require_managed || return 1
    local cur choice ip new="" w
    cur="$(f2b_get ignoreip '127.0.0.1/8 ::1')"
    echo "当前白名单（这些来源永远不会被封）: ${cur}"
    echo "  1) 添加 IP / 网段    2) 移除 IP / 网段    0) 返回"
    read -rp "请选择: " choice
    case "$choice" in
        1)
            read -rp "输入要加入白名单的 IP 或 CIDR 网段: " ip
            ip="${ip//[[:space:]]/}"
            if ! is_ip "$ip" 1; then warn "格式不合法: ${ip}"; return 1; fi
            if [[ " $cur " == *" $ip "* ]]; then info "已在白名单中"; return 0; fi
            new="${cur} ${ip}"
            ;;
        2)
            read -rp "输入要移除的 IP 或网段: " ip
            ip="${ip//[[:space:]]/}"
            for w in $cur; do
                if [ "$w" != "$ip" ]; then new="${new:+$new }$w"; fi
            done
            if [ "$new" = "$cur" ]; then info "白名单里没有 ${ip}"; return 0; fi
            if [ -z "$new" ]; then new="127.0.0.1/8 ::1"; fi
            ;;
        *) return 0 ;;
    esac
    f2b_write_jail "$(f2b_get bantime 30m)" "$(f2b_get findtime 10m)" "$(f2b_get maxretry 5)" "$new" "$(f2b_get backend '')"
    if f2b_apply || f2b_diagnose_and_fix; then
        success "白名单已更新: ${new}"
        return 0
    fi
    return 1
}

f2b_uninstall() {
    f2b_require || return 1
    local choice
    echo -e "  ${GREEN}1)${NC} 只移除本脚本的 SSH 防护配置（保留 Fail2ban 及其他 jail）"
    echo -e "  ${GREEN}2)${NC} 卸载 Fail2ban（保留 /etc/fail2ban 下你自己的其他配置）"
    echo -e "  ${GREEN}0)${NC} 返回"
    read -rp "请选择: " choice
    case "$choice" in
        1)
            rm -f "$F2B_JAIL_FILE"
            systemctl restart fail2ban >/dev/null 2>&1 || true
            success "已移除本脚本的 SSH 防护配置"
            ;;
        2)
            if ! confirm "确认卸载 Fail2ban？" n; then info "已取消"; return 0; fi
            systemctl disable --now fail2ban >/dev/null 2>&1 || true
            rm -f "$F2B_JAIL_FILE"
            DEBIAN_FRONTEND=noninteractive apt-get remove -y -qq fail2ban || warn "apt-get remove 失败，请手动处理"
            success "Fail2ban 已卸载"
            ;;
        *) return 0 ;;
    esac
    return 0
}

f2b_menu() {
    local choice
    while true; do
        clear 2>/dev/null || true
        echo -e "${BOLD}${CYAN}━━━ Fail2ban 管理（SSH 防爆破） ━━━${NC}"
        echo -e "  当前状态: $(f2b_state_text)    封禁时长: $(f2b_get bantime '-')"
        divider
        echo -e "  ${GREEN}1)${NC}  ${GREEN}安装${NC} Fail2ban 并启用 SSH 防护"
        echo -e "  ${GREEN}2)${NC}  修改封禁时长"
        echo -e "  ${GREEN}3)${NC}  解封所有 IP"
        echo -e "  ${GREEN}4)${NC}  封禁日志 / 查看被封 IP"
        echo -e "  ${GREEN}5)${NC}  手动封禁一个 IP"
        echo -e "  ${GREEN}6)${NC}  手动解封一个 IP"
        echo -e "  ${GREEN}7)${NC}  实时日志"
        echo -e "  ${GREEN}8)${NC}  服务状态"
        echo -e "  ${GREEN}9)${NC}  重启服务"
        echo -e "  ${GREEN}10)${NC} ${GREEN}启用${NC} Fail2ban（开机自启）"
        echo -e "  ${GREEN}11)${NC} ${RED}停用${NC} Fail2ban"
        echo -e "  ${GREEN}12)${NC} 修改触发条件（失败次数 / 统计窗口）"
        echo -e "  ${GREEN}13)${NC} 白名单管理"
        echo -e "  ${GREEN}14)${NC} ${RED}卸载${NC}"
        echo -e "  ${GREEN}0)${NC}  返回主菜单"
        divider
        read -rp "请选择 [0-14]: " choice
        case "$choice" in
            1)  run_action f2b_install ;;
            2)  run_action f2b_set_bantime ;;
            3)  run_action f2b_unban_all ;;
            4)  run_action f2b_banlog ;;
            5)  run_action f2b_ban_ip ;;
            6)  run_action f2b_unban_ip ;;
            7)  run_action f2b_live_log ;;
            8)  run_action f2b_status ;;
            9)  run_action f2b_restart ;;
            10) run_action f2b_on ;;
            11) run_action f2b_off ;;
            12) run_action f2b_tune ;;
            13) run_action f2b_whitelist ;;
            14) run_action f2b_uninstall ;;
            0)  return 0 ;;
            *)  warn "无效选择" ;;
        esac
        pause_return
    done
}

f2b_cli() {
    local sub="${1:-menu}"
    if [ "$#" -gt 0 ]; then shift; fi
    case "$sub" in
        menu)         f2b_menu ;;
        install)      f2b_install ;;
        status)       f2b_status ;;
        banned|list)  f2b_banned ;;
        log|logs)     f2b_banlog ;;
        bantime)      f2b_set_bantime "${1:-}" ;;
        ban)
            [ -n "${1:-}" ] || error "用法: adam f2b ban <IP>"
            f2b_ban_ip "$1" ;;
        unban)
            [ -n "${1:-}" ] || error "用法: adam f2b unban <IP>"
            f2b_unban_ip "$1" ;;
        unban-all)    f2b_unban_all ;;
        on|enable)    f2b_on ;;
        off|disable)  f2b_off ;;
        restart)      f2b_restart ;;
        uninstall)    f2b_uninstall ;;
        *) error "未知的 f2b 子命令: ${sub}（可用: install / status / banned / log / bantime <时长> / ban <IP> / unban <IP> / unban-all / on / off / restart / uninstall）" ;;
    esac
}

# ══════════════════════════════════════════════════════════════
#   自动维护：保活（watchdog）/ 每日自动更新 / 端口保留
#   设计参考 Eric86777/vps-tcp-tune 的 Snell 稳定性方案：
#     - 服务单元 Restart=always 且不设启动次数上限（进程崩溃由 systemd 立即拉起）；
#     - 监听端口写入 net.ipv4.ip_local_reserved_ports，避免被本机出站连接当临时端口占走，
#       导致服务重启后绑定失败；
#     - 定时巡检：单元在运行但端口没监听 / 单元已退出时自动重启（systemd 管不到"进程活着但不监听"）；
#     - 每日任务：管理脚本自更新 → Snell / Xray 跟随官方发布更新 → 可选的每日定时重启。
#   参考脚本用 cron + 包装脚本，这里统一用 systemd timer（开机补跑、日志进 journal）。
# ══════════════════════════════════════════════════════════════

maint_load() {
    MAINT_WATCHDOG="1"; MAINT_SCRIPT_AUTO="0"; MAINT_DAILY_RESTART="0"; MAINT_SCRIPT_ASKED="0"
    if [ -f "$MAINT_ENV" ]; then
        # shellcheck disable=SC1090
        source "$MAINT_ENV" 2>/dev/null || true
    fi
    return 0
}

maint_save() {
    install -d -m 755 "$MAINT_DIR"
    cat > "$MAINT_ENV" << MAINTEOF
MAINT_WATCHDOG="${MAINT_WATCHDOG}"
MAINT_SCRIPT_AUTO="${MAINT_SCRIPT_AUTO}"
MAINT_DAILY_RESTART="${MAINT_DAILY_RESTART}"
MAINT_SCRIPT_ASKED="${MAINT_SCRIPT_ASKED}"
MAINTEOF
    chmod 600 "$MAINT_ENV"
}

# 事件日志：保活重启、自动更新结果。超过约 200KB 时只留最后 400 行
maint_log() {
    local msg="$*" size=0
    echo "$msg"
    install -d -m 755 "$(dirname "$MAINT_LOG")" 2>/dev/null || true
    printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$msg" >> "$MAINT_LOG" 2>/dev/null || true
    size="$(stat -c %s "$MAINT_LOG" 2>/dev/null || echo 0)"
    if [ "${size:-0}" -gt 204800 ]; then
        tail -n 400 "$MAINT_LOG" > "${MAINT_LOG}.tmp" 2>/dev/null && mv -f "${MAINT_LOG}.tmp" "$MAINT_LOG"
    fi
    return 0
}

# 把本脚本管理的监听端口（≥1024 的）写入内核保留端口：持久化文件只含本脚本的端口；
# 运行时取"当前值 ∪ 本脚本端口"，只增不减，不动其他程序保留的端口。
reserved_ports_sync() {
    local csv cur new
    csv="$(managed_ports | awk -F/ '$1 ~ /^[0-9]+$/ && $1 >= 1024 {print $1}' | sort -un | paste -sd, - || true)"
    if [ -z "$csv" ]; then
        rm -f "$RESERVED_PORTS_FILE"
        return 0
    fi
    cat > "$RESERVED_PORTS_FILE" << RSVEOF
# 由 Adam 管理脚本维护：Snell / Xray / Nowhere 的监听端口，避免被本机出站连接当作临时端口占用
net.ipv4.ip_local_reserved_ports = ${csv}
RSVEOF
    if cur="$(sysctl -n net.ipv4.ip_local_reserved_ports 2>/dev/null)"; then
        # shellcheck disable=SC2086
        new="$(printf '%s\n' ${cur//,/ } ${csv//,/ } | awk 'NF && !s[$0]++' | paste -sd, - || true)"
        if [ -n "$new" ]; then sysctl -w "net.ipv4.ip_local_reserved_ports=${new}" >/dev/null 2>&1 || true; fi
    fi
    return 0
}

reserved_port_ok() {
    local port="$1" cur
    cur="$(sysctl -n net.ipv4.ip_local_reserved_ports 2>/dev/null || true)"
    printf '%s\n' "${cur//,/ }" | tr ' ' '\n' | awk -v p="$port" '
        { n = split($0, a, "-"); if (n == 1 && a[1] == p) f = 1; if (n == 2 && p + 0 >= a[1] + 0 && p + 0 <= a[2] + 0) f = 1 }
        END { exit !f }'
}

# TCP 端口是否有进程在监听
tcp_listening() {
    local port="$1" out
    command -v ss >/dev/null 2>&1 || return 0
    out="$(ss -tln 2>/dev/null || true)"
    printf '%s\n' "$out" | awk -v p=":${port}" '
        { n = length($4); if (n >= length(p) && substr($4, n - length(p) + 1) == p) f = 1 }
        END { exit !f }'
}

# TCP 端口是否被"名字不含 $2"的进程占用
tcp_port_conflict() {
    local p="$1" own="${2:-__none__}" out
    command -v ss >/dev/null 2>&1 || return 1
    out="$(ss -tlnp 2>/dev/null | awk -v p=":${p}" '{ n = length($4); if (n >= length(p) && substr($4, n - length(p) + 1) == p) print }' || true)"
    [ -n "$out" ] || return 1
    if [[ "$out" == *"\"${own}\""* ]]; then return 1; fi
    return 0
}

# 安装 Snell / Xray 时问一次：是否让管理脚本每天自动从仓库拉取更新（之后可在「自动维护」里改）
maint_ask_script_auto() {
    maint_load
    if [ "$MAINT_SCRIPT_ASKED" = "1" ]; then return 0; fi
    if confirm "让本管理脚本每天自动从仓库拉取更新？（地址: ${SCRIPT_URL}；下载后校验完整性，版本不低于本地才替换）" y; then
        MAINT_SCRIPT_AUTO="1"
    else
        MAINT_SCRIPT_AUTO="0"
    fi
    MAINT_SCRIPT_ASKED="1"
    maint_save
    return 0
}

maint_unit_installed() { [ -f "/etc/systemd/system/$1.service" ]; }

maint_unit_healthy() {
    case "$1" in
        snell)     snell_healthy ;;
        adam-xray) xray_healthy ;;
        *)         systemctl is-active --quiet "$1" 2>/dev/null ;;
    esac
}

maint_install_timers() {
    if ! ensure_manager_copy >/dev/null 2>&1; then
        warn "管理脚本未能安装到 ${MANAGER_PATH}，无法启用定时任务"
        return 1
    fi
    maint_load
    cat > /etc/systemd/system/adam-watchdog.service << WDSVC
[Unit]
Description=Adam manager: keep Snell / Xray / Nowhere alive
After=network-online.target

[Service]
Type=oneshot
ExecStart=${MANAGER_PATH} watchdog
WDSVC
    cat > /etc/systemd/system/adam-watchdog.timer << WDTMR
[Unit]
Description=Adam manager: service watchdog (every 5 minutes)

[Timer]
OnBootSec=3min
OnUnitActiveSec=5min
AccuracySec=30s

[Install]
WantedBy=timers.target
WDTMR
    cat > /etc/systemd/system/adam-maintain.service << MTSVC
[Unit]
Description=Adam manager: daily self-update and upstream updates (Snell / Xray)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${MANAGER_PATH} maintain
TimeoutStartSec=30min
MTSVC
    cat > /etc/systemd/system/adam-maintain.timer << MTTMR
[Unit]
Description=Adam manager: daily maintenance

[Timer]
OnCalendar=*-*-* 04:00:00
RandomizedDelaySec=2h
Persistent=true

[Install]
WantedBy=timers.target
MTTMR
    # 旧版（脚本 v4.0）只管 Snell 的定时器，功能已并入 adam-maintain
    systemctl disable --now adam-snell-update.timer >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/adam-snell-update.timer /etc/systemd/system/adam-snell-update.service
    systemctl daemon-reload
    systemctl enable --now adam-maintain.timer >/dev/null 2>&1 || warn "adam-maintain.timer 启用失败"
    if [ "$MAINT_WATCHDOG" = "1" ]; then
        systemctl enable --now adam-watchdog.timer >/dev/null 2>&1 || warn "adam-watchdog.timer 启用失败"
    else
        systemctl disable --now adam-watchdog.timer >/dev/null 2>&1 || true
    fi
    [ -f "$MAINT_ENV" ] || maint_save
    return 0
}

maint_remove_timers() {
    systemctl disable --now adam-watchdog.timer adam-maintain.timer >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/adam-watchdog.timer /etc/systemd/system/adam-watchdog.service \
          /etc/systemd/system/adam-maintain.timer /etc/systemd/system/adam-maintain.service
    systemctl daemon-reload
    return 0
}

maint_lock() {   # maint_lock [等待秒数]：拿不到锁返回 1
    command -v flock >/dev/null 2>&1 || return 0
    exec 9> "$MAINT_LOCK" || return 0
    flock -w "${1:-0}" 9
}

# 定时器每 5 分钟调用：全程不提问
maint_watchdog() {
    local unit
    maint_load
    [ "$MAINT_WATCHDOG" = "1" ] || return 0
    # 正在更新 / 安装时不插手，下一轮再看
    maint_lock 0 || return 0
    for unit in snell adam-xray nowhere; do
        maint_unit_installed "$unit" || continue
        # 只管"设为开机自启"的服务：手动 disable 掉的不会被拉起
        systemctl is-enabled --quiet "$unit" 2>/dev/null || continue
        if maint_unit_healthy "$unit"; then continue; fi
        maint_log "[保活] ${unit} 状态异常（未运行或端口未监听），正在重启"
        systemctl reset-failed "$unit" >/dev/null 2>&1 || true
        systemctl restart "$unit" >/dev/null 2>&1 || true
        sleep 3
        if maint_unit_healthy "$unit"; then
            maint_log "[保活] ${unit} 已恢复"
        else
            maint_log "[保活] ${unit} 重启后仍异常，请查看: journalctl -u ${unit} -n 50 --no-pager"
        fi
    done
    return 0
}

# 取远端脚本到 $1 并做完整性检查；远端版本写入 REMOTE_SCRIPT_VERSION
script_fetch_remote() {
    local dst="$1"
    REMOTE_SCRIPT_VERSION=""
    curl -fsSL --max-time 60 "${SCRIPT_URL}?t=$(date +%s)" -o "$dst" 2>/dev/null \
        || curl -fsSL --max-time 60 "$SCRIPT_URL" -o "$dst" 2>/dev/null || return 1
    # 截断的文件前半段往往是好的：除了标识和语法，还要求结尾的命令分发段在
    grep -q "Adam Nowhere" "$dst" 2>/dev/null || return 1
    grep -q '^case "\$ACTION" in' "$dst" 2>/dev/null || return 1
    bash -n "$dst" 2>/dev/null || return 1
    REMOTE_SCRIPT_VERSION="$(grep -m1 '^SCRIPT_VERSION=' "$dst" | cut -d'"' -f2 || true)"
    [ -n "$REMOTE_SCRIPT_VERSION" ]
}

# 自动更新管理脚本（不提问）：远端内容与本地不同、且远端版本号不低于本地时才替换。
# 返回 0 = 已更新；1 = 无需更新或失败
script_self_update_auto() {
    local tmp
    make_workdir
    tmp="$WORKDIR/manager.sh"
    if ! script_fetch_remote "$tmp"; then
        maint_log "[脚本] 未能从 ${SCRIPT_URL} 取得完整脚本，本次跳过"
        return 1
    fi
    if [ -f "$MANAGER_PATH" ] && cmp -s "$tmp" "$MANAGER_PATH"; then
        echo "[脚本] 已是仓库最新（${SCRIPT_VERSION}）"
        return 1
    fi
    if ! version_ge "$REMOTE_SCRIPT_VERSION" "$SCRIPT_VERSION"; then
        maint_log "[脚本] 仓库版本 ${REMOTE_SCRIPT_VERSION} 低于本地 ${SCRIPT_VERSION}，不降级"
        return 1
    fi
    if [ -f "$MANAGER_PATH" ]; then cp -f "$MANAGER_PATH" "${MANAGER_PATH}.bak"; fi
    install -m 755 "$tmp" "$MANAGER_PATH"
    maint_log "[脚本] 已从仓库更新: ${SCRIPT_VERSION} -> ${REMOTE_SCRIPT_VERSION}（旧版备份 ${MANAGER_PATH}.bak）"
    return 0
}

# 定时器每日调用：全程不提问
maint_daily() {
    local unit
    maint_load
    maint_lock 300 || { echo "另一个维护任务仍在运行，本次跳过"; return 0; }
    if [ "$MAINT_SCRIPT_AUTO" = "1" ] && [ "${ADAM_REEXEC:-0}" != "1" ]; then
        if script_self_update_auto; then
            # 换成新脚本继续跑后面的步骤，让新逻辑当天就生效
            exec 9>&- || true
            ADAM_REEXEC=1 exec "$MANAGER_PATH" maintain
        fi
    fi
    snell_load_state
    if [ -x "$SNELL_BIN" ] && [ "$SNELL_AUTO_UPDATE" = "1" ]; then
        snell_autoupdate || true
    fi
    xray_load_state
    if [ -x "$XRAY_BIN" ] && [ "$XRAY_AUTO_UPDATE" = "1" ]; then
        xray_autoupdate || true
    fi
    if [ -x "$XRAY_BIN" ]; then xray_sync_certs || true; fi
    reserved_ports_sync || true
    if [ "$MAINT_DAILY_RESTART" = "1" ]; then
        for unit in snell adam-xray; do
            if systemctl is-active --quiet "$unit" 2>/dev/null; then
                systemctl restart "$unit" >/dev/null 2>&1 || true
                maint_log "[每日重启] ${unit} 已重启"
            fi
        done
    fi
    return 0
}

maint_timer_state() {
    if systemctl is-active --quiet "$1" 2>/dev/null; then
        printf '%s' "${GREEN}运行中${NC}"
    else
        printf '%s' "${YELLOW}未启用${NC}"
    fi
}

maint_onoff() { if [ "$1" = "1" ]; then printf '%s' "${GREEN}开${NC}"; else printf '%s' "${YELLOW}关${NC}"; fi; }

maint_toggle() {   # maint_toggle 变量名
    local name="$1" cur
    maint_load
    cur="${!name}"
    if [ "$cur" = "1" ]; then printf -v "$name" '%s' "0"; else printf -v "$name" '%s' "1"; fi
    maint_save
    maint_install_timers || return 1
    success "已切换，当前: $([ "${!name}" = "1" ] && echo 开 || echo 关)"
    return 0
}

maint_toggle_snell() {
    snell_require || return 1
    snell_load_state
    if [ "$SNELL_AUTO_UPDATE" = "1" ]; then snell_disable_autoupdate; else snell_enable_autoupdate; fi
}

maint_toggle_xray() {
    xray_require || return 1
    xray_load_state
    if [ "$XRAY_AUTO_UPDATE" = "1" ]; then XRAY_AUTO_UPDATE="0"; else XRAY_AUTO_UPDATE="1"; fi
    xray_save_state
    if [ "$XRAY_AUTO_UPDATE" = "1" ]; then maint_install_timers || return 1; fi
    success "Xray 自动更新: $([ "$XRAY_AUTO_UPDATE" = "1" ] && echo "开（${XRAY_CHANNEL} 通道）" || echo 关)"
    return 0
}

maint_run_now() {
    info "立即执行一次每日维护（脚本自更新 / Snell / Xray 更新检查）..."
    maint_daily
    echo ""
    info "立即执行一次保活巡检..."
    exec 9>&- 2>/dev/null || true
    maint_watchdog
    success "执行完毕"
    return 0
}

maint_show_log() {
    info "最近的维护事件（${MAINT_LOG}）："
    if [ -s "$MAINT_LOG" ]; then tail -n 30 "$MAINT_LOG"; else echo "  （暂无记录）"; fi
    echo ""
    info "最近一次每日任务输出："
    journalctl -u adam-maintain --no-pager -n 20 -o cat 2>/dev/null || true
    return 0
}

maint_menu() {
    local choice
    while true; do
        clear 2>/dev/null || true
        maint_load; snell_load_state; xray_load_state
        echo -e "${BOLD}${CYAN}━━━ 自动维护（保活 / 自动更新） ━━━${NC}"
        echo -e "  保活巡检定时器: $(maint_timer_state adam-watchdog.timer)    每日维护定时器: $(maint_timer_state adam-maintain.timer)"
        divider
        echo -e "  ${GREEN}1)${NC} 保活巡检（每 5 分钟；服务未运行或端口未监听时自动重启）  [$(maint_onoff "$MAINT_WATCHDOG")]"
        echo -e "  ${GREEN}2)${NC} 管理脚本自动从仓库拉取更新（每日）                      [$(maint_onoff "$MAINT_SCRIPT_AUTO")]"
        echo -e "  ${GREEN}3)${NC} Snell 跟随官方发布自动更新（${SNELL_CHANNEL} 通道）                  [$(maint_onoff "$SNELL_AUTO_UPDATE")]"
        echo -e "  ${GREEN}4)${NC} Xray 跟随官方发布自动更新（${XRAY_CHANNEL} 通道）              [$(maint_onoff "$XRAY_AUTO_UPDATE")]"
        echo -e "  ${GREEN}5)${NC} 每日定时重启 Snell / Xray（随每日维护执行）              [$(maint_onoff "$MAINT_DAILY_RESTART")]"
        echo -e "  ${GREEN}6)${NC} 立即执行一次维护与巡检"
        echo -e "  ${GREEN}7)${NC} 查看维护记录"
        echo -e "  ${GREEN}8)${NC} 重装定时器（修复）"
        echo -e "  ${GREEN}9)${NC} ${RED}移除${NC}全部定时器"
        echo -e "  ${GREEN}0)${NC} 返回主菜单"
        divider
        read -rp "请选择 [0-9]: " choice
        case "$choice" in
            1) run_action maint_toggle MAINT_WATCHDOG ;;
            2) run_action maint_toggle MAINT_SCRIPT_AUTO ;;
            3) run_action maint_toggle_snell ;;
            4) run_action maint_toggle_xray ;;
            5) run_action maint_toggle MAINT_DAILY_RESTART ;;
            6) run_action maint_run_now ;;
            7) run_action maint_show_log ;;
            8) run_action maint_install_timers ;;
            9) run_action maint_remove_timers ;;
            0) return 0 ;;
            *) warn "无效选择" ;;
        esac
        pause_return
    done
}

# ══════════════════════════════════════════════════════════════
#   Snell Server（Surge 官方）—— v6 一键安装 + 跟随官方发布自动更新
#   版本来源：Surge 知识库的 Snell 发布页（官方没有版本查询 API，只能解析该页的下载链接），
#   并对 dl.nssurge.com 做"下一个版本号"探测作为补充；二进制只从 dl.nssurge.com 下载。
#   官方未提供校验值，这里做的是：HTTPS + zip 完整性 + ELF 检查 + 试运行 + 启动失败自动回滚。
#   路径与社区常见脚本一致（/etc/snell/snell-server.conf、snell.service），已有安装可直接接管。
# ══════════════════════════════════════════════════════════════

snell_arch() {
    case "$(uname -m)" in
        x86_64|amd64)  printf 'amd64' ;;
        aarch64|arm64) printf 'aarch64' ;;
        i386|i686)     printf 'i386' ;;
        armv7l)        printf 'armv7l' ;;
        *) warn "Snell 官方未提供该架构的二进制: $(uname -m)"; return 1 ;;
    esac
}

# v6.0.0 / v6.0.0rc2 / v6.0.0b3 -> 定宽可比较的键；同一 X.Y.Z 下 正式版 > rc > b
snell_ver_key() {
    local v="${1#v}" stage=2 stagenum=0
    local re='^([0-9]+)\.([0-9]+)\.([0-9]+)(([a-z]+)([0-9]*))?$'
    [[ "$v" =~ $re ]] || return 1
    if [ -n "${BASH_REMATCH[5]}" ]; then
        case "${BASH_REMATCH[5]}" in rc) stage=1 ;; *) stage=0 ;; esac
        stagenum="${BASH_REMATCH[6]:-0}"
    fi
    printf '%05d%05d%05d%d%05d' "$((10#${BASH_REMATCH[1]}))" "$((10#${BASH_REMATCH[2]}))" \
        "$((10#${BASH_REMATCH[3]}))" "$stage" "$((10#${stagenum}))"
}

snell_ver_gt() {
    local a b
    a="$(snell_ver_key "$1")" || return 1
    b="$(snell_ver_key "$2")" || return 0
    [[ "$a" > "$b" ]]
}

snell_is_prerelease() { local v="${1#v}"; [[ "$v" =~ [a-z] ]]; }

snell_ver_major() { local v="${1#v}"; printf '%s' "${v%%.*}"; }

snell_conf_get() {
    [ -f "$SNELL_CONF" ] || return 1
    awk -v k="$1" '
        /^[ \t]*[#;\[]/ { next }
        {
            i = index($0, "="); if (i == 0) next
            kk = substr($0, 1, i - 1); gsub(/[ \t]/, "", kk)
            if (kk == k) { v = substr($0, i + 1); gsub(/^[ \t]+|[ \t\r]+$/, "", v); print v; found = 1; exit }
        }
        END { exit !found }' "$SNELL_CONF"
}

# 监听端口：取 listen 的第一个端点
snell_port() {
    local l=""
    l="$(snell_conf_get listen 2>/dev/null || true)"
    l="${l%%,*}"; l="${l##*:}"; l="${l//[[:space:]]/}"
    if [[ "$l" =~ ^[0-9]+$ ]] && [ "$l" -ge 1 ] && [ "$l" -le 65535 ]; then printf '%s' "$l"; fi
    return 0
}

snell_installed_version() {
    local v=""
    # 二进制不在就不算已安装（卸载时保留配置目录的情况下，旧的版本记录不应被当成当前版本）
    if [ ! -x "$SNELL_BIN" ]; then return 0; fi
    if [ -f "$SNELL_VERSION_FILE" ]; then v="$(tr -d ' \r\n' < "$SNELL_VERSION_FILE" 2>/dev/null || true)"; fi
    if [ -z "$v" ] && [ -x "$SNELL_BIN" ]; then
        v="$(timeout 5 "$SNELL_BIN" -v 2>&1 < /dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+[a-z0-9]*' | head -n 1 || true)"
        if [ -n "$v" ] && [ -d "$SNELL_DIR" ]; then echo "$v" > "$SNELL_VERSION_FILE" 2>/dev/null || true; fi
    fi
    printf '%s' "$v"
}

snell_require() {
    if [ ! -x "$SNELL_BIN" ] || [ ! -f "$SNELL_CONF" ]; then
        warn "Snell 尚未安装，请先执行「1) 安装 Snell」（或 adam snell install）"
        return 1
    fi
    return 0
}

snell_load_state() {
    SNELL_CHANNEL="beta"; SNELL_AUTO_UPDATE="0"; SNELL_PUBLIC_HOST=""; SNELL_NODE_NAME=""
    if [ -f "$SNELL_STATE_FILE" ]; then
        # shellcheck disable=SC1090
        source "$SNELL_STATE_FILE" 2>/dev/null || true
    fi
    case "$SNELL_CHANNEL" in stable|beta) : ;; *) SNELL_CHANNEL="beta" ;; esac
    return 0
}

snell_save_state() {
    install -d -m 750 "$SNELL_DIR"
    cat > "$SNELL_STATE_FILE" << SNSTEOF
SNELL_CHANNEL="${SNELL_CHANNEL}"
SNELL_AUTO_UPDATE="${SNELL_AUTO_UPDATE}"
SNELL_PUBLIC_HOST="${SNELL_PUBLIC_HOST}"
SNELL_NODE_NAME="${SNELL_NODE_NAME}"
SNSTEOF
    chmod 600 "$SNELL_STATE_FILE"
}

# 官方发布页上列出的、对应本机架构的全部版本号（每行一个）
snell_remote_versions() {
    local arch="$1" url body found=""
    for url in "${SNELL_KB_URLS[@]}"; do
        body="$(curl -fsSL --max-time 20 -A 'Mozilla/5.0 (adam-manager)' "$url" 2>/dev/null || true)"
        [ -n "$body" ] || continue
        found="$(printf '%s' "$body" \
            | grep -oE "snell-server-v[0-9]+\.[0-9]+\.[0-9]+[a-z0-9]*-linux-${arch}\.zip" \
            | sed -E 's/^snell-server-(v[^-]+)-linux-.*$/\1/' | sort -u || true)"
        if [ -n "$found" ]; then
            printf '%s\n' "$found"
            return 0
        fi
    done
    return 1
}

# 官方没有版本清单接口（下载目录不可列），发布页也可能取不到或滞后。
# 这里按官方的版本演进顺序（X.Y.Zb1..bN → X.Y.Zrc（裸 rc 即 rc1）→ rc2.. → X.Y.Z 正式版 → 补丁 / 下一个次版本）
# 从给定版本往后生成候选版本号，逐个到下载站探测是否存在。思路来自 Eric86777/vps-tcp-tune。
snell_probe_candidates() {
    local cur="${1#v}" maj min pat n i
    local re_b='^([0-9]+)\.([0-9]+)\.([0-9]+)b([0-9]+)$' re_rc='^([0-9]+)\.([0-9]+)\.([0-9]+)rc([0-9]*)$' re_s='^([0-9]+)\.([0-9]+)\.([0-9]+)$'
    if [[ "$cur" =~ $re_b ]]; then
        maj=$((10#${BASH_REMATCH[1]})); min=$((10#${BASH_REMATCH[2]})); pat=$((10#${BASH_REMATCH[3]})); n=$((10#${BASH_REMATCH[4]}))
        for i in 1 2 3 4 5 6 7 8; do echo "v${maj}.${min}.${pat}b$((n + i))"; done
        echo "v${maj}.${min}.${pat}rc"
        for i in 2 3 4 5; do echo "v${maj}.${min}.${pat}rc${i}"; done
        for i in 0 1 2 3; do echo "v${maj}.${min}.$((pat + i))"; done
    elif [[ "$cur" =~ $re_rc ]]; then
        maj=$((10#${BASH_REMATCH[1]})); min=$((10#${BASH_REMATCH[2]})); pat=$((10#${BASH_REMATCH[3]}))
        n="${BASH_REMATCH[4]}"; n=$((10#${n:-1}))
        for i in 1 2 3 4; do echo "v${maj}.${min}.${pat}rc$((n + i))"; done
        for i in 0 1 2 3; do echo "v${maj}.${min}.$((pat + i))"; done
    elif [[ "$cur" =~ $re_s ]]; then
        maj=$((10#${BASH_REMATCH[1]})); min=$((10#${BASH_REMATCH[2]})); pat=$((10#${BASH_REMATCH[3]}))
        # 正式版之后：下一个补丁的测试版与正式版
        echo "v${maj}.${min}.$((pat + 1))b1"; echo "v${maj}.${min}.$((pat + 1))rc"
        for i in 1 2 3 4; do echo "v${maj}.${min}.$((pat + i))"; done
    else
        return 0
    fi
    # 下一个次版本、下一个大版本的起点（大版本只用于提示，不会自动跨过去）
    echo "v${maj}.$((min + 1)).0b1"; echo "v${maj}.$((min + 1)).0rc"; echo "v${maj}.$((min + 1)).0"
    echo "v$((maj + 1)).0.0b1"; echo "v$((maj + 1)).0.0rc"; echo "v$((maj + 1)).0.0"
    return 0
}

snell_dl_exists() {   # snell_dl_exists ARCH VERSION
    curl -fsI --max-time 8 "${SNELL_DL_BASE}/snell-server-${2}-linux-${1}.zip" >/dev/null 2>&1
}

# 并行探测一批候选，输出其中存在的版本
snell_probe_batch() {
    local arch="$1" tmp c
    shift
    tmp="$(mktemp /tmp/adam-snell-probe.XXXXXX)" || return 0
    for c in "$@"; do
        ( if snell_dl_exists "$arch" "$c"; then echo "$c" >> "$tmp"; fi ) &
    done
    wait
    cat "$tmp" 2>/dev/null || true
    rm -f "$tmp"
    return 0
}

# 从 cur 出发往后探测，找到更新的就以它为新起点再探，最多 4 轮（能跨过多次发布）
snell_probe_next() {
    local arch="$1" base="$2" round found v best
    local -a cands=()
    for round in 1 2 3 4; do
        cands=()
        while IFS= read -r v; do [ -n "$v" ] && cands+=("$v"); done < <(snell_probe_candidates "$base")
        [ "${#cands[@]}" -gt 0 ] || break
        found="$(snell_probe_batch "$arch" "${cands[@]}")"
        [ -n "$found" ] || break
        printf '%s\n' "$found"
        best="$base"
        for v in $found; do
            # 只沿着同一大版本继续追
            if [ "$(snell_ver_major "$v")" = "$(snell_ver_major "$base")" ] && snell_ver_gt "$v" "$best"; then best="$v"; fi
        done
        [ "$best" != "$base" ] || break
        base="$best"
    done
    return 0
}

# snell_query_latest ARCH CHANNEL CURRENT
# 结果写入：SNELL_LATEST（按通道与大版本策略可升级到的最高版本）、SNELL_LATEST_PRE（该大版本
# 最新的测试版）、SNELL_NEWER_MAJOR（更高大版本，仅提示）、SNELL_SOURCE_OK（是否取到任何版本信息）
snell_query_latest() {
    local arch="$1" channel="$2" current="$3" all="" v major
    SNELL_LATEST=""; SNELL_LATEST_PRE=""; SNELL_NEWER_MAJOR=""; SNELL_SOURCE_OK=0
    local probe_base="$current"
    all="$(snell_remote_versions "$arch" || true)"
    if [ -z "$probe_base" ] || ! snell_ver_key "$probe_base" >/dev/null 2>&1 \
        || [ "$(snell_ver_major "$probe_base")" != "$SNELL_MAJOR" ]; then
        # 没装过（或装的不是 v6）：从脚本内置的已知版本起步，它本身也作为候选
        probe_base="$SNELL_BASELINE_VERSION"
        if snell_dl_exists "$arch" "$probe_base"; then all="${all}"$'\n'"${probe_base}"; fi
    fi
    all="${all}"$'\n'"$(snell_probe_next "$arch" "$probe_base" || true)"
    for v in $all; do
        snell_ver_key "$v" >/dev/null 2>&1 || continue
        SNELL_SOURCE_OK=1
        major="$(snell_ver_major "$v")"
        if [ "$major" -gt "$SNELL_MAJOR" ]; then
            if [ -z "$SNELL_NEWER_MAJOR" ] || snell_ver_gt "$v" "$SNELL_NEWER_MAJOR"; then SNELL_NEWER_MAJOR="$v"; fi
            continue
        fi
        [ "$major" -eq "$SNELL_MAJOR" ] || continue
        if snell_is_prerelease "$v"; then
            if [ -z "$SNELL_LATEST_PRE" ] || snell_ver_gt "$v" "$SNELL_LATEST_PRE"; then SNELL_LATEST_PRE="$v"; fi
            [ "$channel" = "beta" ] || continue
        fi
        if [ -z "$SNELL_LATEST" ] || snell_ver_gt "$v" "$SNELL_LATEST"; then SNELL_LATEST="$v"; fi
    done
    # 已安装的版本比能查到的都新（发布页滞后、探测窗口里也没有更新的）时，它自己就是"最新"，
    # 避免把更旧的版本报成"官方最新"
    if [ "$SNELL_SOURCE_OK" = "1" ] && [ -n "$current" ] && snell_ver_key "$current" >/dev/null 2>&1 \
        && [ "$(snell_ver_major "$current")" = "$SNELL_MAJOR" ]; then
        if [ -z "$SNELL_LATEST" ] || snell_ver_gt "$current" "$SNELL_LATEST"; then SNELL_LATEST="$current"; fi
    fi
    return 0
}

# 下载并检查指定版本；成功后二进制路径写入 SNELL_DL_BIN
snell_fetch() {
    local ver="$1" arch="$2" url magic out
    SNELL_DL_BIN=""
    make_workdir
    local wd="$WORKDIR"
    url="${SNELL_DL_BASE}/snell-server-${ver}-linux-${arch}.zip"
    if ! curl -fL --retry 3 --connect-timeout 10 --max-time 300 -o "$wd/snell.zip" "$url"; then
        warn "下载失败: ${url}"
        return 1
    fi
    if ! unzip -tq "$wd/snell.zip" >/dev/null 2>&1; then
        warn "下载到的压缩包不完整或已损坏"
        return 1
    fi
    unzip -oq "$wd/snell.zip" snell-server -d "$wd" || { warn "压缩包里没有 snell-server"; return 1; }
    magic="$(head -c 4 "$wd/snell-server" | od -An -tx1 | tr -d ' \n' || true)"
    if [ "$magic" != "7f454c46" ]; then
        warn "解压出的 snell-server 不是 Linux 可执行文件"
        return 1
    fi
    chmod 755 "$wd/snell-server"
    out="$(cd "$wd" && timeout 5 ./snell-server -v 2>&1 < /dev/null || true)"
    if [[ "$out" == *"not found"* || "$out" == *"cannot execute"* || "$out" == *"No such file"* || "$out" == *"GLIBC"* ]]; then
        warn "新二进制无法在本机运行（缺少依赖库或架构不符）: ${out}"
        return 1
    fi
    SNELL_DL_BIN="$wd/snell-server"
    info "SHA256: $(sha256sum "$SNELL_DL_BIN" | awk '{print $1}')（官方未公布校验值，仅供留档比对）"
    return 0
}

snell_apply_binary() {
    local ver="$1"
    if [ -f "$SNELL_BIN" ]; then cp -f "$SNELL_BIN" "$SNELL_BIN_BACKUP"; fi
    install -m 755 "$SNELL_DL_BIN" "$SNELL_BIN"
    install -d -m 750 "$SNELL_DIR"
    echo "$ver" > "$SNELL_VERSION_FILE"
    chmod 644 "$SNELL_VERSION_FILE"
    snell_fix_perms
}

snell_fix_perms() {
    if getent group snell >/dev/null 2>&1; then
        chown root:snell "$SNELL_DIR" 2>/dev/null || true
        chmod 750 "$SNELL_DIR" 2>/dev/null || true
        if [ -f "$SNELL_CONF" ]; then
            chown root:snell "$SNELL_CONF" 2>/dev/null || true
            chmod 640 "$SNELL_CONF" 2>/dev/null || true
        fi
    fi
    return 0
}

snell_healthy() {
    local port out
    systemctl is-active --quiet snell 2>/dev/null || return 1
    port="$(snell_port)"
    [ -n "$port" ] || return 0
    command -v ss >/dev/null 2>&1 || return 0
    out="$(ss -tln 2>/dev/null || true)"
    printf '%s\n' "$out" | awk -v p=":${port}" '
        { n = length($4); if (n >= length(p) && substr($4, n - length(p) + 1) == p) f = 1 }
        END { exit !f }'
}

snell_rollback_binary() {
    local prev="${1:-}"
    if [ ! -f "$SNELL_BIN_BACKUP" ]; then
        warn "没有可回滚的备份二进制"
        return 1
    fi
    warn "正在回滚到旧版本${prev:+（${prev}）} ..."
    install -m 755 "$SNELL_BIN_BACKUP" "$SNELL_BIN"
    if [ -n "$prev" ]; then echo "$prev" > "$SNELL_VERSION_FILE"; fi
    systemctl restart snell 2>/dev/null || true
    sleep 2
    if snell_healthy; then
        success "已回滚，服务恢复运行"
    else
        warn "回滚后服务仍未启动，请查看: journalctl -u snell -n 50 --no-pager"
    fi
    return 0
}

# 升级到指定版本（不提问，供手动更新与定时自动更新共用）；启动失败自动回滚
snell_upgrade_to() {
    local ver="$1" arch prev
    arch="$(snell_arch)" || return 1
    prev="$(snell_installed_version)"
    snell_fetch "$ver" "$arch" || return 1
    snell_apply_binary "$ver"
    if [ ! -f "$SNELL_SERVICE" ]; then
        success "Snell 二进制已更新到 ${ver}（未检测到 snell.service，未启动服务）"
        return 0
    fi
    systemctl restart snell 2>/dev/null || true
    sleep 2
    if snell_healthy; then
        success "Snell 已更新: ${prev:-未知} → ${ver}"
        return 0
    fi
    warn "新版本启动失败，最近日志："
    journalctl -u snell -n 15 --no-pager 2>/dev/null || true
    snell_rollback_binary "$prev" || true
    return 1
}

snell_ensure_user() {
    getent group snell >/dev/null 2>&1 || groupadd --system snell 2>/dev/null || true
    if ! id snell >/dev/null 2>&1; then
        useradd --system --gid snell --no-create-home --shell /usr/sbin/nologin snell 2>/dev/null \
            || { warn "创建 snell 系统用户失败"; return 1; }
    fi
    return 0
}

snell_ipv6_ok() {
    [ -r /proc/sys/net/ipv6/conf/all/disable_ipv6 ] || return 1
    [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo 1)" = "0" ]
}

# snell_write_conf PORT PSK MODE DNS_PREF
snell_write_conf() {
    local port="$1" psk="$2" mode="$3" pref="$4" listen tmp
    if snell_ipv6_ok; then
        listen="0.0.0.0:${port},[::]:${port}"
    else
        listen="0.0.0.0:${port}"
    fi
    install -d -m 750 "$SNELL_DIR"
    tmp="$(mktemp "${SNELL_DIR}/.conf.XXXXXX")"
    cat > "$tmp" << SNCONFEOF
[snell-server]
mode = ${mode}
listen = ${listen}
psk = ${psk}
dns-ip-preference = ${pref}
SNCONFEOF
    chmod 640 "$tmp"
    mv -f "$tmp" "$SNELL_CONF"
    snell_fix_perms
}

snell_write_service() {
    cat > "$SNELL_SERVICE" << SNSVCEOF
[Unit]
Description=Snell Proxy Service
Documentation=https://kb.nssurge.com/surge-knowledge-base/release-notes/snell
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=snell
Group=snell
ExecStart=${SNELL_BIN} -l info -c ${SNELL_CONF}
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW
LimitNOFILE=65536
Restart=always
RestartSec=3
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
SyslogIdentifier=snell-server

[Install]
WantedBy=multi-user.target
SNSVCEOF
}

snell_gen_psk() {
    local s=""
    if command -v openssl >/dev/null 2>&1; then
        s="$(openssl rand -base64 64 2>/dev/null | tr -dc 'A-Za-z0-9' | cut -c1-32 || true)"
    fi
    if [ "${#s}" -lt 32 ]; then
        s="$(head -c 512 /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9' | cut -c1-32 || true)"
    fi
    printf '%s' "$s"
}

# 端口是否被 snell-server 以外的进程占用
snell_port_conflict() {
    local p="$1" out
    command -v ss >/dev/null 2>&1 || return 1
    out="$(ss -tlnp 2>/dev/null | awk -v p=":${p}" '{ n = length($4); if (n >= length(p) && substr($4, n - length(p) + 1) == p) print }' || true)"
    [ -n "$out" ] || return 1
    if [[ "$out" == *"snell-server"* ]]; then return 1; fi
    return 0
}

random_free_port() {
    local p=0 i
    for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
        p=$(( (RANDOM * 32768 + RANDOM) % 40000 + 20000 ))
        if ! snell_port_conflict "$p"; then break; fi
    done
    printf '%s' "$p"
}

snell_client_line() {
    local host port psk mode major name
    port="$(snell_port)"
    psk="$(snell_conf_get psk 2>/dev/null || true)"
    mode="$(snell_conf_get mode 2>/dev/null || true)"
    mode="${mode:-default}"
    snell_load_state
    host="${SNELL_PUBLIC_HOST:-$(detect_public_host)}"
    name="${SNELL_NODE_NAME:-Snell-v${SNELL_MAJOR}}"
    major="$(snell_ver_major "$(snell_installed_version)")"
    [[ "$major" =~ ^[0-9]+$ ]] || major="$SNELL_MAJOR"
    printf '%s = snell, %s, %s, psk=%s, version=%s, mode=%s, reuse=true' "$name" "$host" "$port" "$psk" "$major" "$mode"
}

snell_show_config() {
    snell_require || return 1
    step "Snell 配置"
    divider
    snell_load_state
    echo -e "  版本     : ${GREEN}$(snell_installed_version)${NC}"
    echo -e "  配置文件 : ${GREEN}${SNELL_CONF}${NC}"
    echo -e "  监听     : ${GREEN}$(snell_conf_get listen 2>/dev/null || echo '?')${NC}"
    echo -e "  PSK      : ${GREEN}$(snell_conf_get psk 2>/dev/null || echo '?')${NC}"
    echo -e "  mode     : ${GREEN}$(snell_conf_get mode 2>/dev/null || echo 'default')${NC}"
    echo -e "  DNS 偏好 : ${GREEN}$(snell_conf_get dns-ip-preference 2>/dev/null || echo 'default')${NC}"
    echo -e "  自动更新 : ${GREEN}$([ "$SNELL_AUTO_UPDATE" = "1" ] && echo "开启（${SNELL_CHANNEL} 通道）" || echo "关闭")${NC}"
    echo ""
    echo -e "${BOLD}Surge 节点配置（粘贴到 [Proxy] 段）：${NC}"
    echo -e "${GREEN}$(snell_client_line)${NC}"
    echo ""
    echo "  说明："
    echo "  · mode 必须与服务端一致（官方要求），否则无法连通"
    echo "  · v6 的协议特征由 PSK 派生：更换 PSK 等于更换一套流量特征，客户端需同步修改"
    echo "  · v6 已移除 QUIC Proxy Mode，UDP 走 UDP over TCP，防火墙只需放行 TCP $(snell_port)；官方建议客户端屏蔽 QUIC 让应用回落到 HTTP/2"
    echo "  · 需要支持 Snell v6 的 Surge 版本；官方未说明 v6 服务端兼容 v4/v5 客户端，第三方客户端是否支持请以其文档为准"
    return 0
}

snell_enable_autoupdate() {
    snell_load_state
    SNELL_AUTO_UPDATE="1"
    snell_save_state
    maint_install_timers || return 1
    success "已开启 Snell 自动更新：每日维护任务（凌晨 4–6 点）检查官方发布，${SNELL_CHANNEL} 通道有 v${SNELL_MAJOR} 新版本即自动升级，启动失败自动回滚"
    info "查看记录: adam maintain-log    或 journalctl -u adam-maintain --no-pager -n 30"
    return 0
}

snell_disable_autoupdate() {
    snell_load_state
    SNELL_AUTO_UPDATE="0"
    if [ -d "$SNELL_DIR" ]; then snell_save_state; fi
    success "已关闭 Snell 自动更新（保活巡检不受影响）"
    return 0
}

snell_toggle_autoupdate() {
    snell_require || return 1
    snell_load_state
    if [ "$SNELL_AUTO_UPDATE" = "1" ]; then
        info "自动更新当前为：开启（${SNELL_CHANNEL} 通道）"
        echo "  1) 关闭自动更新"
        echo "  2) 切换通道（当前 ${SNELL_CHANNEL}；beta=跟随最新测试版 b/rc 及正式版，stable=只跟正式版）"
        echo "  0) 返回"
        local c
        read -rp "请选择: " c
        case "$c" in
            1) snell_disable_autoupdate ;;
            2)
                if [ "$SNELL_CHANNEL" = "stable" ]; then SNELL_CHANNEL="beta"; else SNELL_CHANNEL="stable"; fi
                snell_save_state
                success "已切换到 ${SNELL_CHANNEL} 通道"
                ;;
            *) : ;;
        esac
    else
        info "自动更新当前为：关闭"
        if confirm "开启自动更新？" y; then snell_enable_autoupdate; fi
    fi
    return 0
}

# 定时器调用：全程不提问，输出进 journal
snell_autoupdate() {
    local arch current
    if [ ! -x "$SNELL_BIN" ]; then
        echo "Snell 未安装，跳过"
        return 0
    fi
    arch="$(snell_arch)" || return 1
    snell_load_state
    current="$(snell_installed_version)"
    if [ "$(snell_ver_major "$current")" != "$SNELL_MAJOR" ]; then
        echo "当前安装的是 ${current:-未知版本}，不是 v${SNELL_MAJOR} 系列，自动更新不跨大版本，跳过"
        return 0
    fi
    snell_query_latest "$arch" "$SNELL_CHANNEL" "$current"
    if [ -n "$SNELL_NEWER_MAJOR" ]; then
        echo "提示：官方已发布更高大版本 ${SNELL_NEWER_MAJOR}，需要客户端同步升级，不会自动跨大版本"
    fi
    if [ -z "$SNELL_LATEST" ]; then
        if [ "$SNELL_SOURCE_OK" = "1" ]; then
            echo "官方暂无可用于 ${SNELL_CHANNEL} 通道的 v${SNELL_MAJOR} 版本，当前 ${current}"
            return 0
        fi
        echo "未能获取官方版本信息（网络问题或发布页结构变化），本次跳过；当前 ${current}"
        return 1
    fi
    if ! snell_ver_gt "$SNELL_LATEST" "$current"; then
        echo "已是最新: ${current}（${SNELL_CHANNEL} 通道）"
        return 0
    fi
    echo "发现新版本: ${current} → ${SNELL_LATEST}，开始更新"
    if snell_upgrade_to "$SNELL_LATEST"; then
        maint_log "[Snell] 已自动更新: ${current} -> ${SNELL_LATEST}"
        return 0
    fi
    maint_log "[Snell] 自动更新到 ${SNELL_LATEST} 失败，当前仍为 $(snell_installed_version)"
    return 1
}

snell_update() {
    snell_require || return 1
    step "检查 Snell 更新"
    divider
    local arch current
    arch="$(snell_arch)" || return 1
    snell_load_state
    current="$(snell_installed_version)"
    info "当前版本: ${current:-未知}（${SNELL_CHANNEL} 通道）"
    info "正在查询 Surge 官方发布页 ..."
    snell_query_latest "$arch" "$SNELL_CHANNEL" "$current"
    if [ -n "$SNELL_NEWER_MAJOR" ]; then
        warn "官方已发布更高大版本 ${SNELL_NEWER_MAJOR}：跨大版本需要客户端同步升级、配置格式也可能变化，本脚本不自动处理"
    fi
    if [ -z "$SNELL_LATEST" ]; then
        if [ "$SNELL_SOURCE_OK" = "1" ] && [ -n "$SNELL_LATEST_PRE" ]; then
            info "正式版通道暂无 v${SNELL_MAJOR} 版本；测试版最新为 ${SNELL_LATEST_PRE}（可在「自动更新」里切到 beta 通道）"
        else
            warn "未能获取官方版本信息（${SNELL_KB_URLS[0]} 不可达或页面结构变化）"
        fi
        return 1
    fi
    info "官方最新: ${SNELL_LATEST}"
    if [ -n "$current" ] && ! snell_ver_gt "$SNELL_LATEST" "$current"; then
        success "已经是最新版本"
        return 0
    fi
    if ! confirm "升级到 ${SNELL_LATEST}？（服务会重启，约 2 秒中断；启动失败自动回滚）" y; then
        info "已取消"
        return 0
    fi
    snell_upgrade_to "$SNELL_LATEST"
}

snell_install() {
    step "安装 Snell Server（Surge 官方，v${SNELL_MAJOR}）"
    divider
    local arch current latest port="" psk="" mode="default" pref="default" host name keep=0 ans old_port def_port
    local hostre='^[][A-Za-z0-9.:_-]+$' namere='^[A-Za-z0-9._-]+$' pskre='^[A-Za-z0-9_-]{12,255}$'
    arch="$(snell_arch)" || return 1
    apt_install curl unzip ca-certificates iproute2 || { warn "依赖安装失败，请检查 apt 源/网络"; return 1; }
    snell_load_state
    current="$(snell_installed_version)"
    old_port="$(snell_port)"

    echo -e "${BOLD}版本通道：${NC}"
    echo "  1) beta   - 跟随官方最新测试版（b / rc），正式版发布后自动转到正式版（默认）"
    echo "  2) stable - 只安装和跟随正式版"
    read -rp "选择 [1/2，默认 $([ "$SNELL_CHANNEL" = "stable" ] && echo 2 || echo 1)]: " ans
    case "${ans:-}" in
        1) SNELL_CHANNEL="beta" ;;
        2) SNELL_CHANNEL="stable" ;;
        *) : ;;
    esac
    info "正在查询官方最新版本（发布页 + 下载站探测，约几秒）..."
    snell_query_latest "$arch" "$SNELL_CHANNEL" "$current"
    latest="$SNELL_LATEST"
    if [ -z "$latest" ] && [ -n "$SNELL_LATEST_PRE" ]; then
        warn "官方目前只有 v${SNELL_MAJOR} 的测试版（${SNELL_LATEST_PRE}），还没有正式版"
        if confirm "安装测试版 ${SNELL_LATEST_PRE}？（之后的自动更新也会跟随测试通道）" y; then
            SNELL_CHANNEL="beta"
            latest="$SNELL_LATEST_PRE"
        else
            info "已取消"
            return 0
        fi
    fi
    if [ -z "$latest" ]; then
        warn "未能从官方发布页取得 v${SNELL_MAJOR} 的版本信息（${SNELL_KB_URLS[0]} 不可达，或该架构 ${arch} 没有 v${SNELL_MAJOR} 版本）"
        read -rp "可手动输入版本号继续（如 v6.0.0，回车取消）: " latest
        latest="${latest//[[:space:]]/}"
        if [ -z "$latest" ]; then info "已取消"; return 0; fi
        [[ "$latest" == v* ]] || latest="v${latest}"
        if ! snell_ver_key "$latest" >/dev/null 2>&1; then warn "版本号格式不合法"; return 1; fi
    fi
    # 发布页偶尔滞后：本机已装的版本比发布页列出的还新时，重装不降级
    if [ -n "$current" ] && [ "$(snell_ver_major "$current")" = "$SNELL_MAJOR" ] && snell_ver_gt "$current" "$latest"; then
        info "本机已安装的 ${current} 比发布页列出的 ${latest} 更新，按 ${current} 重装"
        latest="$current"
    fi
    info "将安装: ${latest}（linux-${arch}）"
    if [ -n "$SNELL_NEWER_MAJOR" ]; then
        info "提示：官方已有更高大版本 ${SNELL_NEWER_MAJOR}，本脚本按 v${SNELL_MAJOR} 的配置格式管理，不自动跨大版本"
    fi

    if [ -f "$SNELL_CONF" ] && [ -n "$old_port" ] && [ -n "$(snell_conf_get psk 2>/dev/null || true)" ]; then
        info "检测到已有 Snell 配置（端口 ${old_port}）"
        if confirm "保留现有端口和 PSK？（选 n 重新配置）" y; then keep=1; fi
    fi

    if [ "$keep" = "1" ]; then
        port="$old_port"
        psk="$(snell_conf_get psk 2>/dev/null || true)"
        mode="$(snell_conf_get mode 2>/dev/null || true)"; mode="${mode:-default}"
        pref="$(snell_conf_get dns-ip-preference 2>/dev/null || true)"; pref="${pref:-default}"
        case "$mode" in default|unshaped|unsafe-raw) : ;; *) mode="default" ;; esac
        case "$pref" in default|prefer-ipv4|prefer-ipv6|ipv4-only|ipv6-only) : ;; *) pref="default" ;; esac
    else
        def_port="$(random_free_port)"
        while true; do
            read -rp "监听端口（回车使用随机端口 ${def_port}）: " port
            port="${port:-$def_port}"
            if [[ ! "$port" =~ ^[0-9]+$ ]] || [ "$((10#$port))" -lt 1 ] || [ "$((10#$port))" -gt 65535 ]; then
                warn "端口不合法（1-65535）"
                continue
            fi
            port=$((10#$port))
            if snell_port_conflict "$port"; then
                warn "TCP 端口 ${port} 已被其他进程占用，请换一个"
                continue
            fi
            break
        done
        while true; do
            read -rp "PSK（回车自动生成 32 位随机串；自定义需 12-255 位，仅限字母、数字、- 和 _）: " psk
            if [ -z "$psk" ]; then
                psk="$(snell_gen_psk)"
                if [ "${#psk}" -ne 32 ]; then warn "随机 PSK 生成失败"; return 1; fi
                info "已生成 PSK: ${psk}"
                break
            fi
            if [[ "$psk" =~ $pskre ]]; then break; fi
            warn "PSK 不符合要求"
        done
        echo ""
        echo -e "${BOLD}mode（服务端与客户端必须一致）：${NC}"
        echo "  1) default    - 流量整形混淆 + AES 加密（推荐）"
        echo "  2) unshaped   - 仅 AES 加密、不做混淆，吞吐约高 10%（官方说明：相当于 Snell v3）"
        echo "  3) unsafe-raw - 不加密、不混淆，明文转发（只适合可信内网 / 专线）"
        read -rp "选择 [1/2/3，默认1]: " ans
        case "${ans:-1}" in
            2) mode="unshaped" ;;
            3)
                warn "unsafe-raw 下所有流量明文传输，公网使用等于裸奔"
                if confirm "确认使用 unsafe-raw？" n; then mode="unsafe-raw"; else mode="default"; fi
                ;;
            *) mode="default" ;;
        esac
        echo ""
        echo -e "${BOLD}出站 DNS 地址族偏好 dns-ip-preference：${NC}"
        echo "  1) default  2) prefer-ipv4  3) prefer-ipv6  4) ipv4-only  5) ipv6-only"
        read -rp "选择 [1-5，默认1]: " ans
        case "${ans:-1}" in
            2) pref="prefer-ipv4" ;; 3) pref="prefer-ipv6" ;; 4) pref="ipv4-only" ;; 5) pref="ipv6-only" ;; *) pref="default" ;;
        esac
    fi

    host="${SNELL_PUBLIC_HOST:-$(detect_public_host)}"
    while true; do
        read -rp "客户端连接用的公网地址（回车使用 ${host:-未探测到，请手动输入}）: " ans
        ans="${ans:-$host}"
        if [[ -n "$ans" && "$ans" =~ $hostre ]]; then host="$ans"; break; fi
        warn "地址不能为空，且只能包含字母、数字和 . : - _ [ ]"
    done
    name="${SNELL_NODE_NAME:-Snell-v${SNELL_MAJOR}}"
    read -rp "节点名称（回车使用 ${name}）: " ans
    if [ -n "$ans" ]; then
        if [[ "$ans" =~ $namere ]]; then name="$ans"; else warn "名称只能包含字母、数字和 . _ -，已使用默认值"; fi
    fi

    snell_ensure_user || return 1
    info "下载 ${latest} ..."
    snell_fetch "$latest" "$arch" || return 1
    snell_apply_binary "$latest"
    snell_write_conf "$port" "$psk" "$mode" "$pref"
    snell_write_service
    systemctl daemon-reload
    systemctl enable snell >/dev/null 2>&1 || true
    systemctl restart snell 2>/dev/null || true
    sleep 2
    if snell_healthy; then
        success "Snell ${latest} 已启动并监听 TCP ${port}"
    else
        warn "Snell 未能正常启动，最近日志："
        journalctl -u snell -n 20 --no-pager 2>/dev/null || true
        return 1
    fi

    SNELL_PUBLIC_HOST="$host"; SNELL_NODE_NAME="$name"
    snell_save_state

    fw_allow_for_service "${port}/tcp"
    if [ -n "$old_port" ] && [ "$old_port" != "$port" ]; then fw_prune_old_specs "${old_port}/tcp"; fi

    echo ""
    reserved_ports_sync || true
    if [ "$SNELL_AUTO_UPDATE" = "1" ]; then
        snell_enable_autoupdate || true
    elif confirm "开启自动更新？（每天检查一次官方发布，${SNELL_CHANNEL} 通道有 v${SNELL_MAJOR} 新版本就自动升级，失败自动回滚）" y; then
        snell_enable_autoupdate || true
    fi
    # 保活巡检默认随安装启用（可在主菜单「自动维护」里关闭）
    maint_ask_script_auto
    maint_install_timers || true
    if snell_is_prerelease "$latest"; then
        warn "当前安装的是测试版 ${latest}：客户端需使用支持该版本的 Surge 测试渠道，协议在正式版前仍可能变动，两端要同步"
    fi
    ensure_manager_copy >/dev/null 2>&1 || true
    snell_show_config
    return 0
}

snell_reconfig() {
    snell_require || return 1
    local port psk mode pref old_port choice ans bak
    local pskre='^[A-Za-z0-9_-]{12,255}$'
    port="$(snell_port)"; old_port="$port"
    psk="$(snell_conf_get psk 2>/dev/null || true)"
    mode="$(snell_conf_get mode 2>/dev/null || true)"; mode="${mode:-default}"
    pref="$(snell_conf_get dns-ip-preference 2>/dev/null || true)"; pref="${pref:-default}"
    echo "当前：端口 ${port} · mode ${mode} · DNS 偏好 ${pref}"
    echo "  1) 修改端口"
    echo "  2) 重新生成 PSK（同时更换一套流量特征）"
    echo "  3) 自定义 PSK"
    echo "  4) 修改 mode"
    echo "  5) 修改 DNS 地址族偏好"
    echo "  6) 修改节点名称 / 公网地址（只影响生成的 Surge 配置行）"
    echo "  0) 返回"
    read -rp "请选择: " choice
    case "$choice" in
        1)
            read -rp "新的监听端口: " ans
            if [[ ! "$ans" =~ ^[0-9]+$ ]] || [ "$((10#$ans))" -lt 1 ] || [ "$((10#$ans))" -gt 65535 ]; then warn "端口不合法"; return 1; fi
            ans=$((10#$ans))
            if snell_port_conflict "$ans"; then warn "TCP 端口 ${ans} 已被其他进程占用"; return 1; fi
            port="$ans"
            ;;
        2)
            psk="$(snell_gen_psk)"
            if [ "${#psk}" -ne 32 ]; then warn "随机 PSK 生成失败"; return 1; fi
            ;;
        3)
            read -rp "新的 PSK（12-255 位，仅限字母、数字、- 和 _）: " ans
            if [[ ! "$ans" =~ $pskre ]]; then warn "PSK 不符合要求"; return 1; fi
            psk="$ans"
            ;;
        4)
            echo "  1) default  2) unshaped  3) unsafe-raw（明文，仅可信内网）"
            read -rp "选择: " ans
            case "$ans" in
                1) mode="default" ;; 2) mode="unshaped" ;;
                3) if confirm "unsafe-raw 为明文传输，确认？" n; then mode="unsafe-raw"; else return 0; fi ;;
                *) warn "无效选择"; return 1 ;;
            esac
            ;;
        5)
            echo "  1) default  2) prefer-ipv4  3) prefer-ipv6  4) ipv4-only  5) ipv6-only"
            read -rp "选择: " ans
            case "$ans" in
                1) pref="default" ;; 2) pref="prefer-ipv4" ;; 3) pref="prefer-ipv6" ;; 4) pref="ipv4-only" ;; 5) pref="ipv6-only" ;;
                *) warn "无效选择"; return 1 ;;
            esac
            ;;
        6)
            local hostre='^[][A-Za-z0-9.:_-]+$' namere='^[A-Za-z0-9._-]+$'
            snell_load_state
            read -rp "公网地址（回车保持 ${SNELL_PUBLIC_HOST:-未设置}）: " ans
            if [ -n "$ans" ]; then
                if [[ "$ans" =~ $hostre ]]; then SNELL_PUBLIC_HOST="$ans"; else warn "地址格式不合法，未修改"; fi
            fi
            read -rp "节点名称（回车保持 ${SNELL_NODE_NAME:-Snell-v${SNELL_MAJOR}}）: " ans
            if [ -n "$ans" ]; then
                if [[ "$ans" =~ $namere ]]; then SNELL_NODE_NAME="$ans"; else warn "名称格式不合法，未修改"; fi
            fi
            snell_save_state
            snell_show_config
            return 0
            ;;
        *) return 0 ;;
    esac

    bak="${SNELL_CONF}.bak"
    cp -f "$SNELL_CONF" "$bak"
    snell_write_conf "$port" "$psk" "$mode" "$pref"
    systemctl restart snell 2>/dev/null || true
    sleep 2
    if ! snell_healthy; then
        warn "新配置启动失败，已恢复原配置。日志："
        journalctl -u snell -n 15 --no-pager 2>/dev/null || true
        mv -f "$bak" "$SNELL_CONF"
        snell_fix_perms
        systemctl restart snell 2>/dev/null || true
        return 1
    fi
    rm -f "$bak"
    success "配置已更新并重启"
    if [ "$port" != "$old_port" ]; then
        fw_allow_for_service "${port}/tcp"
        fw_prune_old_specs "${old_port}/tcp"
        reserved_ports_sync || true
    fi
    warn "客户端需要同步修改，新的配置行如下"
    snell_show_config
    return 0
}

snell_status() {
    snell_require || return 1
    systemctl status snell --no-pager 2>/dev/null | head -n 12 || true
    divider
    snell_load_state
    echo -e "  版本     : $(snell_installed_version)"
    echo -e "  监听     : $(snell_conf_get listen 2>/dev/null || echo '?')"
    echo -e "  自动更新 : $([ "$SNELL_AUTO_UPDATE" = "1" ] && echo "开启（${SNELL_CHANNEL} 通道）" || echo "关闭")"
    echo "  最近的维护记录："
    if [ -s "$MAINT_LOG" ]; then grep -E 'Snell|snell' "$MAINT_LOG" 2>/dev/null | tail -n 5 || true; else echo "    （暂无）"; fi
    return 0
}

# 健康检查（只检测，不改动）。返回 0 = 全部正常
snell_health_check() {
    snell_require || return 1
    local problems=0 port active enabled restarts arch cur out
    step "Snell 健康检查"
    divider
    port="$(snell_port)"
    cur="$(snell_installed_version)"
    active="$(systemctl is-active snell 2>/dev/null || true)"
    enabled="$(systemctl is-enabled snell 2>/dev/null || true)"
    restarts="$(systemctl show snell -p NRestarts --value 2>/dev/null || true)"
    hc_line() {   # hc_line 0|1|2 文本   0=正常 1=异常 2=提示
        case "$1" in
            0) echo -e "  ${GREEN}✓${NC} $2" ;;
            1) echo -e "  ${RED}✗${NC} $2"; problems=$((problems + 1)) ;;
            *) echo -e "  ${YELLOW}!${NC} $2" ;;
        esac
    }
    if [ "$active" = "active" ]; then hc_line 0 "服务运行中（systemd 自动重启次数: ${restarts:-0}）"; else hc_line 1 "服务未运行（状态: ${active:-unknown}）"; fi
    if [ "$enabled" = "enabled" ]; then hc_line 0 "已设为开机自启"; else hc_line 1 "未设为开机自启（状态: ${enabled:-unknown}）"; fi
    if [ -n "$port" ]; then
        if tcp_listening "$port"; then hc_line 0 "TCP ${port} 正在监听"; else hc_line 1 "TCP ${port} 没有在监听"; fi
        if [ "$port" -ge 1024 ]; then
            if reserved_port_ok "$port"; then hc_line 0 "端口 ${port} 已加入内核保留端口"; else hc_line 1 "端口 ${port} 未加入内核保留端口（可能被出站连接占用导致重启后绑定失败）"; fi
        fi
        if ufw_active; then
            if fw_is_allowed "$port" tcp; then hc_line 0 "防火墙已放行 ${port}/tcp"; else hc_line 1 "防火墙未放行 ${port}/tcp"; fi
        else
            hc_line 2 "ufw 未启用（如有云厂商安全组，请确认已放行 ${port}/tcp）"
        fi
    else
        hc_line 1 "配置文件里读不到监听端口"
    fi
    out="$(timeout 5 "$SNELL_BIN" -v 2>&1 < /dev/null || true)"
    if [[ "$out" == *"not found"* || "$out" == *"cannot execute"* || "$out" == *"GLIBC"* ]]; then
        hc_line 1 "二进制无法运行: ${out}"
    else
        hc_line 0 "二进制可运行（${cur:-版本未知}）"
    fi
    if grep -q '^Restart=always' "$SNELL_SERVICE" 2>/dev/null; then hc_line 0 "服务单元已启用崩溃自动拉起"; else hc_line 1 "服务单元未启用 Restart=always（旧版单元）"; fi
    maint_load
    if [ "$MAINT_WATCHDOG" = "1" ] && systemctl is-active --quiet adam-watchdog.timer 2>/dev/null; then
        hc_line 0 "保活巡检定时器运行中（每 5 分钟）"
    else
        hc_line 1 "保活巡检定时器未运行"
    fi
    snell_load_state
    if [ "$SNELL_AUTO_UPDATE" = "1" ]; then
        if systemctl is-active --quiet adam-maintain.timer 2>/dev/null; then
            hc_line 0 "自动更新已开启（${SNELL_CHANNEL} 通道）"
        else
            hc_line 1 "自动更新已开启，但每日维护定时器未运行"
        fi
    else
        hc_line 2 "自动更新未开启"
    fi
    arch="$(snell_arch 2>/dev/null || true)"
    if [ -n "$arch" ] && [ -n "$cur" ]; then
        if snell_dl_exists "$arch" "$cur"; then
            snell_query_latest "$arch" "$SNELL_CHANNEL" "$cur"
            if [ -n "$SNELL_LATEST" ] && snell_ver_gt "$SNELL_LATEST" "$cur"; then
                hc_line 2 "官方有新版本 ${SNELL_LATEST}（当前 ${cur}），可用「检查并更新」升级"
            else
                hc_line 0 "已是 ${SNELL_CHANNEL} 通道最新版本"
            fi
            if [ -n "$SNELL_NEWER_MAJOR" ]; then hc_line 2 "官方已有更高大版本 ${SNELL_NEWER_MAJOR}（不自动跨大版本）"; fi
        else
            hc_line 2 "暂时连不上官方下载站，无法判断是否有新版本"
        fi
    fi
    divider
    if [ "$problems" -eq 0 ]; then
        success "健康检查通过"
        return 0
    fi
    warn "发现 ${problems} 项问题，可用「一键修复」处理"
    return 1
}

# 一键修复：补齐服务单元 / 权限 / 保留端口 / 防火墙 / 定时器，然后重启并复查
snell_repair() {
    snell_require || return 1
    local port
    step "Snell 一键修复"
    divider
    port="$(snell_port)"
    snell_ensure_user || return 1
    snell_write_service
    snell_fix_perms
    systemctl daemon-reload
    systemctl reset-failed snell >/dev/null 2>&1 || true
    systemctl enable snell >/dev/null 2>&1 || true
    reserved_ports_sync || true
    if [ -n "$port" ] && ufw_active; then ufw allow "${port}/tcp" >/dev/null 2>&1 || true; fi
    maint_install_timers || true
    systemctl restart snell 2>/dev/null || true
    sleep 2
    if snell_healthy; then
        success "修复完成，服务运行正常"
    else
        warn "修复后服务仍未正常监听，最近日志："
        journalctl -u snell -n 20 --no-pager 2>/dev/null || true
        return 1
    fi
    return 0
}

snell_logs() {
    snell_require || return 1
    info "实时日志（Ctrl+C 返回）"
    journalctl -u snell -n 30 -f || true
    return 0
}

snell_restart() {
    snell_require || return 1
    systemctl restart snell 2>/dev/null || true
    sleep 2
    if snell_healthy; then
        success "Snell 已重启"
    else
        warn "重启后未检测到服务正常监听："
        journalctl -u snell -n 15 --no-pager 2>/dev/null || true
        return 1
    fi
    return 0
}

snell_uninstall() {
    if [ ! -x "$SNELL_BIN" ] && [ ! -f "$SNELL_SERVICE" ]; then
        info "未检测到 Snell 安装"
        return 0
    fi
    local port
    port="$(snell_port)"
    if ! confirm "确认卸载 Snell？" n; then info "已取消"; return 0; fi
    systemctl disable --now snell >/dev/null 2>&1 || true
    rm -f "$SNELL_SERVICE" "$SNELL_BIN" "$SNELL_BIN_BACKUP" "$SNELL_VERSION_FILE"
    systemctl daemon-reload
    if [ -n "$port" ] && ufw_installed; then
        if confirm "同时删除防火墙里 Snell 端口（${port}/tcp）的放行规则？" y; then
            # 配置还在时 managed_ports 仍会包含该端口，这里直接删
            fw_delete_spec "${port}/tcp"
        fi
    fi
    if confirm "同时删除配置目录 ${SNELL_DIR}（含 PSK）？" n; then
        rm -rf "$SNELL_DIR"
        userdel snell >/dev/null 2>&1 || true
    else
        info "已保留 ${SNELL_DIR}，重装时可直接沿用端口和 PSK"
    fi
    reserved_ports_sync || true
    success "Snell 已卸载"
    return 0
}

snell_state_text() {
    local v
    if [ ! -x "$SNELL_BIN" ]; then
        printf '%s' "${YELLOW}未安装${NC}"
        return 0
    fi
    v=""
    if [ -f "$SNELL_VERSION_FILE" ]; then v="$(tr -d ' \r\n' < "$SNELL_VERSION_FILE" 2>/dev/null || true)"; fi
    printf '%s' "${v:-版本未知} · $(svc_state snell)"
}

snell_menu() {
    local choice
    while true; do
        clear 2>/dev/null || true
        snell_load_state
        echo -e "${BOLD}${CYAN}━━━ Snell Server 管理（Surge 官方，v${SNELL_MAJOR}） ━━━${NC}"
        echo -e "  当前状态: $(snell_state_text)    通道: ${SNELL_CHANNEL}    自动更新: $(maint_onoff "$SNELL_AUTO_UPDATE")"
        divider
        echo -e "  ${GREEN}1)${NC}  ${GREEN}安装${NC} / 重装 Snell（自动获取官方最新版，默认跟随测试版）"
        echo -e "  ${GREEN}2)${NC}  检查并更新到官方最新版"
        echo -e "  ${GREEN}3)${NC}  查看配置 / Surge 节点配置行"
        echo -e "  ${GREEN}4)${NC}  修改配置（端口 / PSK / mode / DNS 偏好 / 节点名）"
        echo -e "  ${GREEN}5)${NC}  自动更新 开 / 关 / 切换通道（beta ⇄ stable）"
        echo -e "  ${GREEN}6)${NC}  健康检查（只检测）"
        echo -e "  ${GREEN}7)${NC}  一键修复（单元 / 保留端口 / 防火墙 / 保活定时器）"
        echo -e "  ${GREEN}8)${NC}  服务状态"
        echo -e "  ${GREEN}9)${NC}  实时日志"
        echo -e "  ${GREEN}10)${NC} 重启服务"
        echo -e "  ${GREEN}11)${NC} ${RED}卸载${NC} Snell"
        echo -e "  ${GREEN}0)${NC}  返回主菜单"
        divider
        read -rp "请选择 [0-11]: " choice
        case "$choice" in
            1)  run_action snell_install ;;
            2)  run_action snell_update ;;
            3)  run_action snell_show_config ;;
            4)  run_action snell_reconfig ;;
            5)  run_action snell_toggle_autoupdate ;;
            6)  run_action snell_health_check ;;
            7)  run_action snell_repair ;;
            8)  run_action snell_status ;;
            9)  run_action snell_logs ;;
            10) run_action snell_restart ;;
            11) run_action snell_uninstall ;;
            0)  return 0 ;;
            *)  warn "无效选择" ;;
        esac
        pause_return
    done
}

snell_cli() {
    local sub="${1:-menu}"
    if [ "$#" -gt 0 ]; then shift; fi
    case "$sub" in
        menu)        snell_menu ;;
        install)     snell_install ;;
        update|check) snell_update ;;
        config|info) snell_show_config ;;
        reconfig)    snell_reconfig ;;
        status)      snell_status ;;
        logs)        snell_logs ;;
        restart)     snell_restart ;;
        health)      snell_health_check ;;
        repair)      snell_repair ;;
        auto)
            case "${1:-}" in
                on)  snell_require && snell_enable_autoupdate ;;
                off) snell_disable_autoupdate ;;
                *)   snell_toggle_autoupdate ;;
            esac ;;
        uninstall)   snell_uninstall ;;
        *) error "未知的 snell 子命令: ${sub}（可用: install / update / config / reconfig / status / health / repair / logs / restart / auto [on|off] / uninstall）" ;;
    esac
}

# ══════════════════════════════════════════════════════════════
#   Xray（SS / VLESS）—— 多节点管理，跟随 XTLS/Xray-core 官方发布（默认含预发布版）
#   节点类型参考 3x-ui 的入站设计：
#     VLESS + REALITY + Vision、VLESS + XHTTP + REALITY、VLESS + XHTTP + TLS/明文（过 CDN）、
#     VLESS Encryption（xray vlessenc，ML-KEM-768 / X25519）+ XHTTP、Shadowsocks 2022。
#   与其他安装完全隔离：独立目录 /opt/adam-xray、/etc/adam-xray，独立服务 adam-xray.service，
#   不碰官方安装脚本的 /usr/local/bin/xray 与 3x-ui 自带的 xray。
#   配置用 Xray 的多文件模式（-confdir）：00-base.json + 每个节点一个 JSON，增删节点只动一个文件，
#   不需要 jq；每次改动先用 xray run -test 校验，校验不过就撤回。
# ══════════════════════════════════════════════════════════════

xray_asset_name() {
    case "$(uname -m)" in
        x86_64|amd64)  printf 'Xray-linux-64.zip' ;;
        aarch64|arm64) printf 'Xray-linux-arm64-v8a.zip' ;;
        i386|i686)     printf 'Xray-linux-32.zip' ;;
        armv7l)        printf 'Xray-linux-arm32-v7a.zip' ;;
        *) warn "Xray 模块暂不支持该架构: $(uname -m)"; return 1 ;;
    esac
}

xray_require() {
    if [ ! -x "$XRAY_BIN" ]; then
        warn "Xray 尚未安装，请先执行「1) 安装 Xray」（或 adam xray install）"
        return 1
    fi
    return 0
}

xray_installed_version() {
    local v=""
    [ -x "$XRAY_BIN" ] || return 0
    v="$("$XRAY_BIN" version 2>/dev/null | awk 'NR==1 {print $2}' || true)"
    if [[ "$v" =~ ^[0-9]+(\.[0-9]+){1,3}$ ]]; then printf 'v%s' "$v"; fi
    return 0
}

xray_load_state() {
    XRAY_CHANNEL="prerelease"; XRAY_AUTO_UPDATE="0"; XRAY_PUBLIC_HOST=""; XRAY_PIN_VERSION=""
    if [ -f "$XRAY_STATE_FILE" ]; then
        # shellcheck disable=SC1090
        source "$XRAY_STATE_FILE" 2>/dev/null || true
    fi
    case "$XRAY_CHANNEL" in prerelease|stable|pin) : ;; *) XRAY_CHANNEL="prerelease" ;; esac
    return 0
}

xray_save_state() {
    install -d -m 750 "$XRAY_CONF_DIR"
    cat > "$XRAY_STATE_FILE" << XRSTEOF
XRAY_CHANNEL="${XRAY_CHANNEL}"
XRAY_AUTO_UPDATE="${XRAY_AUTO_UPDATE}"
XRAY_PUBLIC_HOST="${XRAY_PUBLIC_HOST}"
XRAY_PIN_VERSION="${XRAY_PIN_VERSION}"
XRSTEOF
    chmod 600 "$XRAY_STATE_FILE"
}

# a 是否高于 b（vX.Y.Z）
xray_ver_gt() {
    local a="${1#v}" b="${2#v}"
    [ -n "$a" ] && [ -n "$b" ] && [ "$a" != "$b" ] \
        && [ "$(printf '%s\n%s\n' "$a" "$b" | sort -V | tail -n 1)" = "$a" ]
}

# 官方发布列表，每行 "tag 预发布标记(1/0/?)"。先用 API（带预发布标记），
# API 被限流时退到 releases.atom（不依赖 API，但拿不到预发布标记）。
xray_list_releases() {
    local json out=""
    json="$(curl -fsS --max-time 20 "https://api.github.com/repos/${XRAY_REPO}/releases?per_page=30" 2>/dev/null || true)"
    if [ -n "$json" ] && command -v python3 >/dev/null 2>&1; then
        out="$(printf '%s' "$json" | python3 -c 'import json,sys
try: data = json.load(sys.stdin)
except Exception: sys.exit(0)
if isinstance(data, list):
    for r in data:
        if isinstance(r, dict) and not r.get("draft") and r.get("tag_name"):
            print(r["tag_name"], 1 if r.get("prerelease") else 0)' 2>/dev/null || true)"
    fi
    if [ -z "$out" ]; then
        out="$(curl -fsSL --max-time 20 "https://github.com/${XRAY_REPO}/releases.atom" 2>/dev/null \
            | grep -oE 'releases/tag/v[0-9]+(\.[0-9]+){1,3}' | sed 's#.*/##' | awk '!s[$0]++ {print $0, "?"}' || true)"
    fi
    if [ -n "$out" ]; then printf '%s\n' "$out"; fi
    return 0
}

# xray_query_latest CHANNEL：结果写入 XRAY_LATEST（按通道）、XRAY_LATEST_ANY（含预发布的最高版本）、
# XRAY_LATEST_IS_PRE（1/0/?）、XRAY_SOURCE_OK
xray_query_latest() {
    local channel="$1" tag flag re='^v[0-9]+(\.[0-9]+){1,3}$'
    XRAY_LATEST=""; XRAY_LATEST_ANY=""; XRAY_LATEST_IS_PRE="?"; XRAY_SOURCE_OK=0
    while read -r tag flag; do
        [[ "$tag" =~ $re ]] || continue
        XRAY_SOURCE_OK=1
        if [ -z "$XRAY_LATEST_ANY" ] || xray_ver_gt "$tag" "$XRAY_LATEST_ANY"; then XRAY_LATEST_ANY="$tag"; fi
        if [ "$channel" = "stable" ] && [ "$flag" != "0" ]; then continue; fi
        if [ -z "$XRAY_LATEST" ] || xray_ver_gt "$tag" "$XRAY_LATEST"; then
            XRAY_LATEST="$tag"; XRAY_LATEST_IS_PRE="$flag"
        fi
    done < <(xray_list_releases)
    return 0
}

# 下载 + SHA256 校验（官方 .dgst）+ 解压 + 试运行；成功后目录写入 XRAY_DL_DIR
xray_fetch() {
    local ver="$1" asset base want got
    asset="$(xray_asset_name)" || return 1
    XRAY_DL_DIR=""
    make_workdir
    local wd="$WORKDIR"
    base="https://github.com/${XRAY_REPO}/releases/download/${ver}"
    if ! curl -fL --retry 3 --connect-timeout 10 --max-time 300 -o "$wd/xray.zip" "${base}/${asset}"; then
        warn "下载失败: ${base}/${asset}"
        return 1
    fi
    if ! curl -fsSL --retry 2 --max-time 30 -o "$wd/xray.dgst" "${base}/${asset}.dgst"; then
        warn "未能下载官方校验文件 ${asset}.dgst，为安全起见中止"
        return 1
    fi
    want="$(grep -iE '^SHA(2-)?256' "$wd/xray.dgst" | awk '{print $NF}' | head -n 1 || true)"
    got="$(sha256sum "$wd/xray.zip" | awk '{print $1}')"
    if [ -z "$want" ] || [ "$want" != "$got" ]; then
        warn "SHA256 校验失败（官方 ${want:-未知}，实际 ${got}），已中止"
        return 1
    fi
    success "SHA256 校验通过（官方 .dgst）"
    unzip -tq "$wd/xray.zip" >/dev/null 2>&1 || { warn "压缩包损坏"; return 1; }
    mkdir -p "$wd/x"
    unzip -oq "$wd/xray.zip" -d "$wd/x" || { warn "解压失败"; return 1; }
    [ -f "$wd/x/xray" ] || { warn "压缩包里没有 xray 二进制"; return 1; }
    chmod 755 "$wd/x/xray"
    if ! "$wd/x/xray" version >/dev/null 2>&1; then
        warn "下载到的 xray 无法在本机运行（架构不符？）"
        return 1
    fi
    XRAY_DL_DIR="$wd/x"
    return 0
}

xray_ensure_user() {
    getent group adam-xray >/dev/null 2>&1 || groupadd --system adam-xray 2>/dev/null || true
    if ! id adam-xray >/dev/null 2>&1; then
        useradd --system --gid adam-xray --no-create-home --shell /usr/sbin/nologin adam-xray 2>/dev/null \
            || { warn "创建 adam-xray 系统用户失败"; return 1; }
    fi
    return 0
}

xray_fix_perms() {
    install -d -m 750 "$XRAY_CONF_DIR" "$XRAY_CONF_D" "$XRAY_CERT_DIR"
    install -d -m 700 "$XRAY_NODE_DIR"
    if getent group adam-xray >/dev/null 2>&1; then
        chown root:adam-xray "$XRAY_CONF_DIR" "$XRAY_CONF_D" 2>/dev/null || true
        chown -R root:adam-xray "$XRAY_CERT_DIR" 2>/dev/null || true
        find "$XRAY_CONF_D" -type f -name '*.json' -exec chown root:adam-xray {} + -exec chmod 640 {} + 2>/dev/null || true
        find "$XRAY_CERT_DIR" -type f -exec chmod 640 {} + 2>/dev/null || true
        find "$XRAY_CERT_DIR" -type d -exec chmod 750 {} + 2>/dev/null || true
    fi
    return 0
}

xray_apply_binary() {
    install -d -m 755 "$XRAY_DIR"
    if [ -f "$XRAY_BIN" ]; then cp -f "$XRAY_BIN" "${XRAY_BIN}.previous"; fi
    install -m 755 "$XRAY_DL_DIR/xray" "$XRAY_BIN"
    local f
    for f in geoip.dat geosite.dat; do
        if [ -f "$XRAY_DL_DIR/$f" ]; then install -m 644 "$XRAY_DL_DIR/$f" "$XRAY_DIR/$f"; fi
    done
    return 0
}

xray_write_base() {
    install -d -m 750 "$XRAY_CONF_D"
    cat > "${XRAY_CONF_D}/00-base.json" << 'XRBASE'
{
  "log": { "loglevel": "warning" },
  "outbounds": [
    { "tag": "direct", "protocol": "freedom" },
    { "tag": "block", "protocol": "blackhole" }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      { "type": "field", "ip": ["geoip:private"], "outboundTag": "block" }
    ]
  }
}
XRBASE
}

xray_write_service() {
    cat > "$XRAY_SERVICE" << XRSVC
[Unit]
Description=Xray Service (managed by adam)
Documentation=https://github.com/${XRAY_REPO}
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=adam-xray
Group=adam-xray
Environment=XRAY_LOCATION_ASSET=${XRAY_DIR}
ExecStart=${XRAY_BIN} run -confdir ${XRAY_CONF_D}
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
LimitNOFILE=1048576
Restart=always
RestartSec=3
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
SyslogIdentifier=adam-xray

[Install]
WantedBy=multi-user.target
XRSVC
}

# xray_test_conf [二进制路径]：校验整套配置
xray_test_conf() {
    local bin="${1:-$XRAY_BIN}"
    XRAY_LOCATION_ASSET="$XRAY_DIR" "$bin" run -test -confdir "$XRAY_CONF_D" 2>&1
}

xray_node_tags() {
    local f
    [ -d "$XRAY_NODE_DIR" ] || return 0
    for f in "$XRAY_NODE_DIR"/*.env; do
        [ -f "$f" ] || continue
        basename "$f" .env
    done
    return 0
}

xray_node_count() { xray_node_tags | grep -c . || true; }

# 读取节点元数据到 N_* 变量（调用方应在子 shell 或 local 环境里用）
xray_node_load() {
    N_TAG=""; N_TYPE=""; N_PORT=""; N_UUID=""; N_SNI=""; N_PBK=""; N_SID=""; N_PATH=""; N_ENC="none"
    N_DOMAIN=""; N_CPORT=""; N_CSEC=""; N_METHOD=""; N_PASS=""; N_NAME=""; N_CERT_SRC=""; N_KEY_SRC=""; N_ORIGIN=""
    [ -f "${XRAY_NODE_DIR}/$1.env" ] || return 1
    # shellcheck disable=SC1090
    source "${XRAY_NODE_DIR}/$1.env" 2>/dev/null || return 1
    return 0
}

# 全部节点的端口，每行一个 ufw 规格（SS 同时需要 UDP）
xray_ports() {
    local tag
    [ -d "$XRAY_NODE_DIR" ] || return 0
    for tag in $(xray_node_tags); do
        (
            xray_node_load "$tag" || exit 0
            [[ "$N_PORT" =~ ^[0-9]+$ ]] || exit 0
            echo "${N_PORT}/tcp"
            if [ "$N_TYPE" = "ss2022" ]; then echo "${N_PORT}/udp"; fi
        )
    done
    return 0
}

xray_healthy() {
    local spec
    systemctl is-active --quiet adam-xray 2>/dev/null || return 1
    while IFS= read -r spec; do
        [[ "$spec" == */tcp ]] || continue
        tcp_listening "${spec%/tcp}" || return 1
    done < <(xray_ports)
    return 0
}

# 校验配置并（重）启动；没有节点时停止服务
xray_reload() {
    local out
    xray_fix_perms
    if [ "$(xray_node_count)" -eq 0 ]; then
        systemctl disable --now adam-xray >/dev/null 2>&1 || true
        info "当前没有节点，Xray 服务已停止"
        return 0
    fi
    if ! out="$(xray_test_conf)"; then
        warn "配置校验未通过："
        printf '%s\n' "$out" | tail -n 8
        return 1
    fi
    systemctl daemon-reload
    systemctl enable adam-xray >/dev/null 2>&1 || true
    systemctl restart adam-xray 2>/dev/null || true
    sleep 2
    if xray_healthy; then return 0; fi
    warn "Xray 未能正常启动，最近日志："
    journalctl -u adam-xray -n 15 --no-pager 2>/dev/null || true
    return 1
}

xray_gen_uuid() {
    local u=""
    u="$("$XRAY_BIN" uuid 2>/dev/null | head -n 1 || true)"
    if [[ ! "$u" =~ ^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$ ]]; then
        u="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || true)"
    fi
    printf '%s' "$u"
}

# 生成 REALITY 密钥对，写入 XK_PRIV / XK_PUB。兼容新旧两种输出：
#   新: "PrivateKey: ..." / "Password (PublicKey): ..."     旧: "Private key: ..." / "Public key: ..."
xray_gen_x25519() {
    local out re='^[A-Za-z0-9_-]{43}$'
    XK_PRIV=""; XK_PUB=""
    out="$("$XRAY_BIN" x25519 2>/dev/null || true)"
    XK_PRIV="$(printf '%s\n' "$out" | awk -F':[[:space:]]*' '{l=tolower($1); gsub(/[[:space:]]/,"",l); if (l=="privatekey") {print $NF; exit}}')"
    XK_PUB="$(printf '%s\n' "$out" | awk -F':[[:space:]]*' '{l=tolower($1); gsub(/[[:space:]]/,"",l); if (l=="publickey" || l=="password" || l=="password(publickey)") {print $NF; exit}}')"
    [[ "$XK_PRIV" =~ $re && "$XK_PUB" =~ $re ]]
}

# 生成 VLESS Encryption 配置对，写入 VE_DEC（服务端 decryption）/ VE_ENC（客户端 encryption）
# $1 = pq（ML-KEM-768 认证，抗量子）或 x25519
xray_gen_vlessenc() {
    local want="$1" out label re='^mlkem768x25519plus\.[a-z]+\.[0-9a-z-]+\.[A-Za-z0-9_.-]+$'
    VE_DEC=""; VE_ENC=""
    if [ "$want" = "pq" ]; then label="ML-KEM-768"; else label="X25519"; fi
    out="$("$XRAY_BIN" vlessenc 2>/dev/null || true)"
    VE_DEC="$(printf '%s\n' "$out" | awk -v l="$label" '
        /^Authentication:/ { on = (index($0, l) > 0) }
        on && /"decryption"/ { s = $0; sub(/^[^:]*:[[:space:]]*"/, "", s); sub(/".*$/, "", s); print s; exit }')"
    VE_ENC="$(printf '%s\n' "$out" | awk -v l="$label" '
        /^Authentication:/ { on = (index($0, l) > 0) }
        on && /"encryption"/ { s = $0; sub(/^[^:]*:[[:space:]]*"/, "", s); sub(/".*$/, "", s); print s; exit }')"
    [[ "$VE_DEC" =~ $re && "$VE_ENC" =~ $re ]]
}

xray_listen_addr() { if snell_ipv6_ok; then printf '::'; else printf '0.0.0.0'; fi; }

# 询问端口：$1 默认值，结果写入 XP_PORT
xray_ask_port() {
    local def="$1" p
    while true; do
        read -rp "监听端口（回车使用 ${def}）: " p
        p="${p:-$def}"
        if [[ ! "$p" =~ ^[0-9]+$ ]] || [ "$((10#$p))" -lt 1 ] || [ "$((10#$p))" -gt 65535 ]; then
            warn "端口不合法（1-65535）"
            continue
        fi
        p=$((10#$p))
        if tcp_port_conflict "$p" "__none__" || xray_port_used "$p"; then
            warn "TCP 端口 ${p} 已被占用，请换一个"
            continue
        fi
        XP_PORT="$p"
        return 0
    done
}

# 端口是否已被本模块的某个节点使用（服务没在运行时 ss 查不到）
xray_port_used() {
    local want="$1" spec
    while IFS= read -r spec; do
        if [ "${spec%/*}" = "$want" ]; then return 0; fi
    done < <(xray_ports)
    return 1
}

xray_default_port() {   # 首选端口空闲就用它，否则给一个随机空闲端口
    local want="$1"
    if ! tcp_port_conflict "$want" "__none__"; then printf '%s' "$want"; else random_free_port; fi
}

# 询问 REALITY 伪装站点，结果写入 XR_SNI
xray_ask_sni() {
    local ans re='^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$'
    echo "REALITY 伪装站点（需是境外、支持 TLS 1.3 + HTTP/2 的站点；握手会转发到它的 443 端口）："
    echo "  1) www.microsoft.com   2) www.apple.com   3) www.amazon.com   4) 自定义"
    read -rp "选择 [1-4，默认1]: " ans
    case "${ans:-1}" in
        2) XR_SNI="www.apple.com" ;;
        3) XR_SNI="www.amazon.com" ;;
        4)
            while true; do
                read -rp "输入域名（不带 https:// 和端口）: " ans
                ans="$(printf '%s' "$ans" | tr -d ' \r\n')"
                if [[ "$ans" == *.* && "$ans" =~ $re ]]; then XR_SNI="$ans"; break; fi
                warn "域名格式不正确"
            done
            ;;
        *) XR_SNI="www.microsoft.com" ;;
    esac
    # 尽力检查：从本机能否与该站点完成 TLS 1.3 + h2 握手（失败只提醒，不拦截）
    if command -v openssl >/dev/null 2>&1; then
        ans="$(timeout 8 openssl s_client -connect "${XR_SNI}:443" -servername "$XR_SNI" -tls1_3 -alpn h2 < /dev/null 2>/dev/null || true)"
        if [[ "$ans" == *"TLSv1.3"* && "$ans" == *"ALPN protocol: h2"* ]]; then
            success "${XR_SNI} 支持 TLS 1.3 + HTTP/2，可用"
        else
            warn "从本机未能确认 ${XR_SNI} 支持 TLS 1.3 + HTTP/2（也可能只是本机到它的网络不通），如连不上请换一个站点"
        fi
    fi
    return 0
}

# 询问是否叠加 VLESS Encryption，结果写入 VE_DEC / VE_ENC（不叠加时为 none）
xray_ask_vlessenc() {
    local def="$1" ans
    VE_DEC="none"; VE_ENC="none"
    if [ "$def" != "force" ]; then
        confirm "叠加 VLESS Encryption（抗量子密钥交换的应用层加密；客户端需较新的 Xray 内核）？" n || return 0
    fi
    echo "  认证方式：1) ML-KEM-768（抗量子，默认）  2) X25519（密钥更短）"
    read -rp "  选择 [1/2，默认1]: " ans
    if [ "${ans:-1}" = "2" ]; then ans="x25519"; else ans="pq"; fi
    if ! xray_gen_vlessenc "$ans"; then
        warn "xray vlessenc 生成失败（当前内核版本可能不支持 VLESS Encryption）"
        VE_DEC="none"; VE_ENC="none"
        return 1
    fi
    return 0
}

# 写节点配置 + 元数据，校验并重启；失败则撤回。参数：tag、入站 JSON（不含外层）、元数据文本
xray_commit_node() {
    local tag="$1" inbound="$2" meta="$3"
    local conf="${XRAY_CONF_D}/10-in-${tag}.json" env="${XRAY_NODE_DIR}/${tag}.env"
    install -d -m 700 "$XRAY_NODE_DIR"
    printf '{\n  "inbounds": [\n%s\n  ]\n}\n' "$inbound" > "$conf"
    printf '%s\n' "$meta" > "$env"
    chmod 600 "$env"
    if xray_reload; then return 0; fi
    warn "新节点未能生效，已撤回本次改动"
    rm -f "$conf" "$env"
    rm -rf "${XRAY_CERT_DIR:?}/${tag}"
    xray_reload >/dev/null 2>&1 || true
    return 1
}

XRAY_SNIFF='"sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": true }'

xray_add_vision() {
    local port uuid sid tag listen name
    xray_ask_port "$(xray_default_port 443)"; port="$XP_PORT"
    xray_ask_sni
    xray_gen_x25519 || { warn "REALITY 密钥生成失败"; return 1; }
    uuid="$(xray_gen_uuid)"; sid="$(openssl rand -hex 8)"; listen="$(xray_listen_addr)"
    tag="vision-${port}"; name="VLESS-Vision-${port}"
    xray_commit_node "$tag" "    {
      \"tag\": \"${tag}\", \"listen\": \"${listen}\", \"port\": ${port}, \"protocol\": \"vless\",
      \"settings\": { \"clients\": [ { \"id\": \"${uuid}\", \"flow\": \"xtls-rprx-vision\" } ], \"decryption\": \"none\" },
      \"streamSettings\": {
        \"network\": \"tcp\", \"security\": \"reality\",
        \"realitySettings\": { \"show\": false, \"target\": \"${XR_SNI}:443\", \"xver\": 0, \"serverNames\": [\"${XR_SNI}\"], \"privateKey\": \"${XK_PRIV}\", \"shortIds\": [\"${sid}\"] }
      },
      ${XRAY_SNIFF}
    }" "N_TAG=\"${tag}\"
N_TYPE=\"vision\"
N_PORT=\"${port}\"
N_UUID=\"${uuid}\"
N_SNI=\"${XR_SNI}\"
N_PBK=\"${XK_PUB}\"
N_SID=\"${sid}\"
N_NAME=\"${name}\"" || return 1
    XRAY_NEW_TAG="$tag"
}

xray_add_xhttp_reality() {
    local port uuid sid tag listen name path
    xray_ask_port "$(xray_default_port 8443)"; port="$XP_PORT"
    xray_ask_sni
    xray_gen_x25519 || { warn "REALITY 密钥生成失败"; return 1; }
    xray_ask_vlessenc ask || true
    uuid="$(xray_gen_uuid)"; sid="$(openssl rand -hex 8)"; listen="$(xray_listen_addr)"
    path="/$(openssl rand -hex 6)"
    tag="xhttp-reality-${port}"; name="VLESS-XHTTP-REALITY-${port}"
    xray_commit_node "$tag" "    {
      \"tag\": \"${tag}\", \"listen\": \"${listen}\", \"port\": ${port}, \"protocol\": \"vless\",
      \"settings\": { \"clients\": [ { \"id\": \"${uuid}\" } ], \"decryption\": \"${VE_DEC}\" },
      \"streamSettings\": {
        \"network\": \"xhttp\", \"security\": \"reality\",
        \"xhttpSettings\": { \"path\": \"${path}\", \"mode\": \"auto\" },
        \"realitySettings\": { \"show\": false, \"target\": \"${XR_SNI}:443\", \"xver\": 0, \"serverNames\": [\"${XR_SNI}\"], \"privateKey\": \"${XK_PRIV}\", \"shortIds\": [\"${sid}\"] }
      },
      ${XRAY_SNIFF}
    }" "N_TAG=\"${tag}\"
N_TYPE=\"xhttp-reality\"
N_PORT=\"${port}\"
N_UUID=\"${uuid}\"
N_SNI=\"${XR_SNI}\"
N_PBK=\"${XK_PUB}\"
N_SID=\"${sid}\"
N_PATH=\"${path}\"
N_ENC=\"${VE_ENC}\"
N_NAME=\"${name}\"" || return 1
    XRAY_NEW_TAG="$tag"
}

# 把证书复制到节点目录（Xray 以非 root 运行，读不了 /etc/letsencrypt 下 root 专属的私钥）
xray_install_cert() {
    local tag="$1" crt="$2" key="$3" dir="${XRAY_CERT_DIR}/$1"
    install -d -m 750 "$dir"
    install -m 640 "$crt" "$dir/fullchain.pem" || return 1
    install -m 640 "$key" "$dir/privkey.pem" || return 1
    return 0
}

# 每日维护时调用：外部证书续期后把新文件同步进来并重启
xray_sync_certs() {
    local tag changed=0
    for tag in $(xray_node_tags); do
        (
            xray_node_load "$tag" || exit 1
            [ -n "$N_CERT_SRC" ] && [ -f "$N_CERT_SRC" ] && [ -f "$N_KEY_SRC" ] || exit 1
            cmp -s "$N_CERT_SRC" "${XRAY_CERT_DIR}/${tag}/fullchain.pem" && exit 1
            xray_install_cert "$tag" "$N_CERT_SRC" "$N_KEY_SRC"
        ) && changed=1
    done
    if [ "$changed" = "1" ]; then
        xray_fix_perms
        systemctl restart adam-xray >/dev/null 2>&1 || true
        maint_log "[Xray] 检测到证书已续期，已同步并重启"
    fi
    return 0
}

xray_add_xhttp_cdn() {
    local port uuid tag listen name path domain ans origin="tls" crt="" key="" src_crt="" src_key="" cport="443" tls_block=""
    local re='^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$' dir
    echo "本节点用于套 CDN（如 Cloudflare）：客户端连 CDN 的域名，CDN 再回源到本机。"
    while true; do
        read -rp "已接入 CDN 的域名（如 cdn.example.com）: " domain
        domain="$(printf '%s' "$domain" | tr -d ' \r\n')"
        if [[ "$domain" == *.* && "$domain" =~ $re ]]; then break; fi
        warn "域名格式不正确"
    done
    echo "CDN 回源方式："
    echo "  1) TLS 回源 + 自签证书（默认；Cloudflare 的 SSL/TLS 模式选「完全 Full」，不是「完全(严格)」）"
    echo "  2) TLS 回源 + 已有证书文件（「完全(严格)」可用；证书续期后每日维护会自动同步）"
    echo "  3) 明文 HTTP 回源（Cloudflare 选「灵活 Flexible」；回源端口须是 80/8080/8880/2052/2082/2086/2095 之一）"
    read -rp "选择 [1/2/3，默认1]: " ans
    case "${ans:-1}" in
        2)
            read -rp "证书文件路径（fullchain.pem）: " src_crt
            read -rp "私钥文件路径（privkey.pem）: " src_key
            if [ ! -f "$src_crt" ] || [ ! -f "$src_key" ]; then warn "证书或私钥文件不存在"; return 1; fi
            if ! cert_covers_domain "$src_crt" "$domain"; then
                warn "该证书的域名列表里没有 ${domain}"
                confirm "仍要使用？" n || return 1
            fi
            ;;
        3) origin="plain" ;;
        *) : ;;
    esac
    if [ "$origin" = "plain" ]; then
        xray_ask_port "$(xray_default_port 8080)"
    else
        echo "  提示：Cloudflare 回源 HTTPS 只支持 443/2053/2083/2087/2096/8443 这几个端口"
        xray_ask_port "$(xray_default_port 2053)"
    fi
    port="$XP_PORT"
    read -rp "客户端连接 CDN 的端口（回车默认 443）: " ans
    if [[ "${ans:-443}" =~ ^[0-9]+$ ]]; then cport="${ans:-443}"; fi
    xray_ask_vlessenc ask || true
    uuid="$(xray_gen_uuid)"; listen="$(xray_listen_addr)"; path="/$(openssl rand -hex 6)"
    tag="xhttp-cdn-${port}"; name="VLESS-XHTTP-CDN-${port}"
    if [ "$origin" = "tls" ]; then
        dir="${XRAY_CERT_DIR}/${tag}"
        if [ -n "$src_crt" ]; then
            xray_install_cert "$tag" "$src_crt" "$src_key" || { warn "证书复制失败"; return 1; }
        else
            install -d -m 750 "$dir"
            openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
                -subj "/CN=${domain}" -addext "subjectAltName=DNS:${domain}" \
                -keyout "$dir/privkey.pem" -out "$dir/fullchain.pem" >/dev/null 2>&1 \
                || { warn "自签证书生成失败"; return 1; }
        fi
        crt="$dir/fullchain.pem"; key="$dir/privkey.pem"
        tls_block="\"security\": \"tls\",
        \"tlsSettings\": { \"alpn\": [\"h2\", \"http/1.1\"], \"certificates\": [ { \"certificateFile\": \"${crt}\", \"keyFile\": \"${key}\" } ] },"
    else
        tls_block="\"security\": \"none\","
    fi
    xray_commit_node "$tag" "    {
      \"tag\": \"${tag}\", \"listen\": \"${listen}\", \"port\": ${port}, \"protocol\": \"vless\",
      \"settings\": { \"clients\": [ { \"id\": \"${uuid}\" } ], \"decryption\": \"${VE_DEC}\" },
      \"streamSettings\": {
        \"network\": \"xhttp\", ${tls_block}
        \"xhttpSettings\": { \"path\": \"${path}\", \"mode\": \"auto\" }
      },
      ${XRAY_SNIFF}
    }" "N_TAG=\"${tag}\"
N_TYPE=\"xhttp-cdn\"
N_PORT=\"${port}\"
N_UUID=\"${uuid}\"
N_PATH=\"${path}\"
N_ENC=\"${VE_ENC}\"
N_DOMAIN=\"${domain}\"
N_CPORT=\"${cport}\"
N_ORIGIN=\"${origin}\"
N_CERT_SRC=\"${src_crt}\"
N_KEY_SRC=\"${src_key}\"
N_NAME=\"${name}\"" || return 1
    XRAY_NEW_TAG="$tag"
    info "记得在 CDN 侧：把 ${domain} 的回源端口指到 ${port}（Cloudflare 可用 Origin Rules），并开启 gRPC / HTTP/2 回源以获得更好的 XHTTP 表现"
}

xray_add_venc() {
    local port uuid tag listen name path
    echo "VLESS Encryption + XHTTP：不套 TLS / REALITY，由 VLESS 自身的加密保护（适合直连，或明文回源的 CDN 之后）。"
    xray_ask_port "$(xray_default_port 8880)"; port="$XP_PORT"
    xray_ask_vlessenc force || return 1
    uuid="$(xray_gen_uuid)"; listen="$(xray_listen_addr)"; path="/$(openssl rand -hex 6)"
    tag="venc-${port}"; name="VLESS-ENC-XHTTP-${port}"
    xray_commit_node "$tag" "    {
      \"tag\": \"${tag}\", \"listen\": \"${listen}\", \"port\": ${port}, \"protocol\": \"vless\",
      \"settings\": { \"clients\": [ { \"id\": \"${uuid}\" } ], \"decryption\": \"${VE_DEC}\" },
      \"streamSettings\": {
        \"network\": \"xhttp\", \"security\": \"none\",
        \"xhttpSettings\": { \"path\": \"${path}\", \"mode\": \"auto\" }
      },
      ${XRAY_SNIFF}
    }" "N_TAG=\"${tag}\"
N_TYPE=\"venc\"
N_PORT=\"${port}\"
N_UUID=\"${uuid}\"
N_PATH=\"${path}\"
N_ENC=\"${VE_ENC}\"
N_NAME=\"${name}\"" || return 1
    XRAY_NEW_TAG="$tag"
}

xray_add_ss() {
    local port tag listen name method="2022-blake3-aes-128-gcm" bytes=16 pass ans
    echo "Shadowsocks 2022 加密方式："
    echo "  1) 2022-blake3-aes-128-gcm（默认）  2) 2022-blake3-aes-256-gcm  3) 2022-blake3-chacha20-poly1305"
    read -rp "选择 [1/2/3，默认1]: " ans
    case "${ans:-1}" in
        2) method="2022-blake3-aes-256-gcm"; bytes=32 ;;
        3) method="2022-blake3-chacha20-poly1305"; bytes=32 ;;
        *) : ;;
    esac
    xray_ask_port "$(random_free_port)"; port="$XP_PORT"
    pass="$(openssl rand -base64 "$bytes" | tr -d '\n')"
    listen="$(xray_listen_addr)"
    tag="ss-${port}"; name="SS2022-${port}"
    xray_commit_node "$tag" "    {
      \"tag\": \"${tag}\", \"listen\": \"${listen}\", \"port\": ${port}, \"protocol\": \"shadowsocks\",
      \"settings\": { \"method\": \"${method}\", \"password\": \"${pass}\", \"network\": \"tcp,udp\" },
      ${XRAY_SNIFF}
    }" "N_TAG=\"${tag}\"
N_TYPE=\"ss2022\"
N_PORT=\"${port}\"
N_METHOD=\"${method}\"
N_PASS=\"${pass}\"
N_NAME=\"${name}\"" || return 1
    XRAY_NEW_TAG="$tag"
}

# 输出某节点的分享链接
xray_node_link() {
    local tag="$1" host="$2" h pathenc ui
    (
        xray_node_load "$tag" || exit 1
        h="$(format_host_for_url "$host")"
        pathenc="${N_PATH//\//%2F}"
        case "$N_TYPE" in
            vision)
                echo "vless://${N_UUID}@${h}:${N_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${N_SNI}&fp=chrome&pbk=${N_PBK}&sid=${N_SID}&type=tcp&headerType=none&support-x25519mlkem768=true#${N_NAME}" ;;
            xhttp-reality)
                echo "vless://${N_UUID}@${h}:${N_PORT}?encryption=${N_ENC}&security=reality&sni=${N_SNI}&fp=chrome&pbk=${N_PBK}&sid=${N_SID}&type=xhttp&path=${pathenc}&mode=auto&support-x25519mlkem768=true#${N_NAME}" ;;
            xhttp-cdn)
                echo "vless://${N_UUID}@${N_DOMAIN}:${N_CPORT}?encryption=${N_ENC}&security=tls&sni=${N_DOMAIN}&fp=chrome&alpn=h2&type=xhttp&host=${N_DOMAIN}&path=${pathenc}&mode=auto#${N_NAME}" ;;
            venc)
                echo "vless://${N_UUID}@${h}:${N_PORT}?encryption=${N_ENC}&security=none&type=xhttp&path=${pathenc}&mode=auto#${N_NAME}" ;;
            ss2022)
                ui="$(printf '%s' "${N_METHOD}:${N_PASS}" | base64 | tr -d '\n=' | tr '+/' '-_')"
                echo "ss://${ui}@${h}:${N_PORT}#${N_NAME}" ;;
            *) exit 1 ;;
        esac
    )
}

xray_type_label() {
    case "$1" in
        vision)        printf 'VLESS + REALITY + Vision' ;;
        xhttp-reality) printf 'VLESS + XHTTP + REALITY' ;;
        xhttp-cdn)     printf 'VLESS + XHTTP（CDN）' ;;
        venc)          printf 'VLESS Encryption + XHTTP' ;;
        ss2022)        printf 'Shadowsocks 2022' ;;
        *)             printf '%s' "$1" ;;
    esac
}

xray_show_node() {
    local tag="$1" host link
    xray_load_state
    host="${XRAY_PUBLIC_HOST:-$(detect_public_host)}"
    (
        xray_node_load "$tag" || { warn "找不到节点 ${tag}"; exit 1; }
        echo -e "${BOLD}[${tag}] $(xray_type_label "$N_TYPE")${NC}"
        echo "  端口: ${N_PORT}"
        case "$N_TYPE" in
            vision|xhttp-reality) echo "  伪装站点: ${N_SNI}    公钥(pbk): ${N_PBK}    shortId: ${N_SID}" ;;
        esac
        case "$N_TYPE" in
            xhttp-reality|xhttp-cdn|venc) echo "  XHTTP 路径: ${N_PATH}    VLESS Encryption: $([ "$N_ENC" = "none" ] && echo 未启用 || echo 已启用)" ;;
        esac
        if [ "$N_TYPE" = "xhttp-cdn" ]; then
            echo "  CDN 域名: ${N_DOMAIN}（客户端端口 ${N_CPORT}）   回源: $([ "$N_ORIGIN" = "plain" ] && echo "明文 HTTP" || echo "TLS") → 本机 ${N_PORT}"
        fi
        if [ "$N_TYPE" = "ss2022" ]; then echo "  加密: ${N_METHOD}    密码: ${N_PASS}"; fi
    ) || return 1
    link="$(xray_node_link "$tag" "$host" || true)"
    echo -e "  分享链接:\n  ${GREEN}${link}${NC}"
    if command -v qrencode >/dev/null 2>&1 && [ -n "$link" ] && [ -t 1 ]; then
        qrencode -t ANSIUTF8 -m 1 "$link" 2>/dev/null || true
    fi
    return 0
}

xray_list_nodes() {
    xray_require || return 1
    local tag n=0 st
    step "Xray 节点列表"
    divider
    for tag in $(xray_node_tags); do
        n=$((n + 1))
        (
            xray_node_load "$tag" || exit 0
            if tcp_listening "$N_PORT"; then st="${GREEN}监听中${NC}"; else st="${RED}未监听${NC}"; fi
            echo -e "  ${BOLD}${n})${NC} ${tag}    $(xray_type_label "$N_TYPE")    端口 ${N_PORT}    ${st}"
        )
    done
    if [ "$n" -eq 0 ]; then echo "  （还没有节点，用「2) 添加节点」创建）"; fi
    return 0
}

# 让用户选一个节点，结果写入 XRAY_PICK
xray_pick_node() {
    local -a tags=()
    local tag ans
    XRAY_PICK=""
    while IFS= read -r tag; do [ -n "$tag" ] && tags+=("$tag"); done < <(xray_node_tags)
    if [ "${#tags[@]}" -eq 0 ]; then warn "还没有节点"; return 1; fi
    xray_list_nodes
    read -rp "输入序号（回车取消）: " ans
    [ -n "$ans" ] || return 1
    if [[ ! "$ans" =~ ^[0-9]+$ ]] || [ "$ans" -lt 1 ] || [ "$ans" -gt "${#tags[@]}" ]; then warn "序号无效"; return 1; fi
    XRAY_PICK="${tags[$((ans - 1))]}"
    return 0
}

xray_show_links() {
    xray_require || return 1
    local tag n=0
    step "Xray 节点配置与分享链接"
    divider
    for tag in $(xray_node_tags); do
        n=$((n + 1))
        xray_show_node "$tag" || true
        echo ""
    done
    if [ "$n" -eq 0 ]; then echo "  （还没有节点）"; return 0; fi
    echo "  说明："
    echo "  · REALITY 节点：较新的 Xray 服务端（社区反馈自 v26.9.8 起）要求客户端握手带 X25519MLKEM768，"
    echo "    旧客户端会表现为超时 / reality verification failed；请使用新版 Xray 内核客户端，mihomo 内核需较新版本"
    echo "    并重新导入本链接（链接已带 support-x25519mlkem768=true，不认识该参数的客户端会忽略它）"
    echo "  · CDN 节点：连不通时把客户端的 XHTTP mode 从 auto 改成 packet-up 再试"
    echo "  · VLESS Encryption 的 encryption= 参数很长，属正常现象；客户端内核需支持该特性"
    return 0
}

xray_add_node() {
    xray_require || return 1
    local ans old_specs
    step "添加 Xray 节点"
    divider
    echo -e "  ${GREEN}1)${NC} VLESS + REALITY + Vision（TCP 直连，最常用）"
    echo -e "  ${GREEN}2)${NC} VLESS + XHTTP + REALITY（直连，可叠加 VLESS Encryption）"
    echo -e "  ${GREEN}3)${NC} VLESS + XHTTP + TLS / 明文回源（套 CDN，需要域名）"
    echo -e "  ${GREEN}4)${NC} VLESS Encryption + XHTTP（ML-KEM-768 抗量子，不依赖 TLS）"
    echo -e "  ${GREEN}5)${NC} Shadowsocks 2022（TCP + UDP）"
    echo -e "  ${GREEN}0)${NC} 返回"
    read -rp "请选择 [0-5]: " ans
    XRAY_NEW_TAG=""
    case "$ans" in
        1) xray_add_vision || return 1 ;;
        2) xray_add_xhttp_reality || return 1 ;;
        3) xray_add_xhttp_cdn || return 1 ;;
        4) xray_add_venc || return 1 ;;
        5) xray_add_ss || return 1 ;;
        *) return 0 ;;
    esac
    success "节点 ${XRAY_NEW_TAG} 已添加并生效"
    # shellcheck disable=SC2046
    fw_allow_for_service $( (xray_node_load "$XRAY_NEW_TAG" && { echo "${N_PORT}/tcp"; [ "$N_TYPE" = "ss2022" ] && echo "${N_PORT}/udp"; }) || true)
    reserved_ports_sync || true
    echo ""
    xray_show_node "$XRAY_NEW_TAG"
    return 0
}

xray_delete_node() {
    xray_require || return 1
    local tag specs
    xray_pick_node || return 0
    tag="$XRAY_PICK"
    confirm "确认删除节点 ${tag}？" n || { info "已取消"; return 0; }
    specs="$( (xray_node_load "$tag" && { echo "${N_PORT}/tcp"; [ "$N_TYPE" = "ss2022" ] && echo "${N_PORT}/udp"; }) || true)"
    rm -f "${XRAY_CONF_D}/10-in-${tag}.json" "${XRAY_NODE_DIR}/${tag}.env"
    rm -rf "${XRAY_CERT_DIR:?}/${tag}"
    xray_reload || true
    # shellcheck disable=SC2086
    if [ -n "$specs" ]; then fw_prune_old_specs "$(echo $specs)"; fi
    reserved_ports_sync || true
    success "节点 ${tag} 已删除"
    return 0
}

xray_compat_notice() {
    echo -e "${YELLOW}  跟随最新版本前请了解：${NC}"
    echo "  · Xray 官方近期的发布基本都标记为 Pre-release，「最新预发布版」通常就是官方最新一版"
    echo "  · 较新版本的 REALITY 服务端要求客户端握手带 X25519MLKEM768（社区反馈自 v26.9.8 起）："
    echo "    新版 Xray 内核客户端可连；mihomo 内核需较新版本并重新导入链接；部分客户端（如当时的 sing-box）连不上"
    echo "  · 预发布版偶有不兼容改动：自动更新会先用新内核校验现有配置，校验不过就不换；启动失败会自动回滚"
    echo "  · 如果你的客户端跟不上，可选「指定版本」固定在一个旧版本（如 v26.3.27）"
}

xray_choose_channel() {
    local ans re='^v?[0-9]+(\.[0-9]+){1,3}$'
    echo -e "${BOLD}版本通道：${NC}"
    echo "  1) prerelease - 跟随官方最新版（含预发布，默认）"
    echo "  2) stable     - 只跟官方标记为正式版的发布（官方近期没有这样的发布时会提示）"
    echo "  3) pin        - 指定一个版本并固定，不自动更新"
    xray_compat_notice
    read -rp "选择 [1/2/3，默认1]: " ans
    case "${ans:-1}" in
        2) XRAY_CHANNEL="stable"; XRAY_PIN_VERSION="" ;;
        3)
            read -rp "输入版本号（如 v26.3.27）: " ans
            ans="$(printf '%s' "$ans" | tr -d ' \r\n')"
            if [[ ! "$ans" =~ $re ]]; then warn "版本号格式不正确"; return 1; fi
            XRAY_CHANNEL="pin"; XRAY_PIN_VERSION="v${ans#v}"
            ;;
        *) XRAY_CHANNEL="prerelease"; XRAY_PIN_VERSION="" ;;
    esac
    return 0
}

# 按当前通道得出目标版本，写入 XRAY_TARGET；取不到返回 1
xray_resolve_target() {
    XRAY_TARGET=""
    if [ "$XRAY_CHANNEL" = "pin" ]; then
        XRAY_TARGET="$XRAY_PIN_VERSION"
    else
        xray_query_latest "$XRAY_CHANNEL"
        XRAY_TARGET="$XRAY_LATEST"
    fi
    if [ -n "$XRAY_TARGET" ]; then return 0; fi
    return 1
}

xray_install() {
    step "安装 Xray（SS / VLESS）"
    divider
    local host ans hostre='^[][A-Za-z0-9.:_-]+$'
    xray_asset_name >/dev/null || return 1
    apt_install curl unzip openssl ca-certificates iproute2 python3 || { warn "依赖安装失败，请检查 apt 源/网络"; return 1; }
    if systemctl is-active --quiet xray 2>/dev/null || systemctl is-active --quiet x-ui 2>/dev/null; then
        info "检测到本机还有其他 Xray（官方脚本安装的 xray.service 或 3x-ui）：本模块完全独立，互不影响，只需注意端口不要重复"
    fi
    xray_load_state
    if [ -x "$XRAY_BIN" ]; then
        info "已安装 $(xray_installed_version)，将按所选通道重装 / 切换版本（节点配置保留）"
    fi
    xray_choose_channel || return 1
    info "正在查询官方发布 ..."
    if ! xray_resolve_target; then
        if [ "$XRAY_CHANNEL" = "stable" ] && [ -n "${XRAY_LATEST_ANY:-}" ]; then
            warn "没有找到标记为正式版的发布（最新为 ${XRAY_LATEST_ANY}：官方标记为预发布，或当前取不到标记信息）"
            confirm "改为跟随最新预发布版 ${XRAY_LATEST_ANY}？" y || return 0
            XRAY_CHANNEL="prerelease"; XRAY_TARGET="$XRAY_LATEST_ANY"
        else
            warn "未能获取 Xray 官方发布信息（GitHub 不可达或被限流），请稍后重试，或选「指定版本」"
            return 1
        fi
    fi
    info "将安装: ${XRAY_TARGET}（$(xray_asset_name)）"
    xray_fetch "$XRAY_TARGET" || return 1
    xray_ensure_user || return 1
    xray_apply_binary
    [ -f "${XRAY_CONF_D}/00-base.json" ] || xray_write_base
    xray_write_service
    xray_fix_perms
    systemctl daemon-reload

    host="${XRAY_PUBLIC_HOST:-$(detect_public_host)}"
    while true; do
        read -rp "生成分享链接用的公网地址（回车使用 ${host:-未探测到，请手动输入}）: " ans
        ans="${ans:-$host}"
        if [[ -n "$ans" && "$ans" =~ $hostre ]]; then host="$ans"; break; fi
        warn "地址不能为空，且只能包含字母、数字和 . : - _ [ ]"
    done
    XRAY_PUBLIC_HOST="$host"
    if [ "$XRAY_CHANNEL" = "pin" ]; then
        XRAY_AUTO_UPDATE="0"
    elif confirm "开启自动更新？（每日检查官方发布；先用新内核校验配置，失败不换，启动失败自动回滚）" y; then
        XRAY_AUTO_UPDATE="1"
    else
        XRAY_AUTO_UPDATE="0"
    fi
    xray_save_state
    maint_ask_script_auto
    maint_install_timers || true
    success "Xray $(xray_installed_version) 安装完成"
    if [ "$(xray_node_count)" -gt 0 ]; then
        if xray_reload; then success "现有节点已随新内核重启"; else warn "现有节点在该版本下未能启动，请查看日志或换一个版本"; fi
        return 0
    fi
    echo ""
    if confirm "现在添加第一个节点？" y; then xray_add_node; fi
    return 0
}

# 升级到指定版本（不提问）：新内核先校验现有配置，再替换；启动失败回滚
xray_upgrade_to() {
    local ver="$1" prev out
    prev="$(xray_installed_version)"
    xray_fetch "$ver" || return 1
    if [ "$(xray_node_count)" -gt 0 ]; then
        if ! out="$(XRAY_LOCATION_ASSET="$XRAY_DL_DIR" "$XRAY_DL_DIR/xray" run -test -confdir "$XRAY_CONF_D" 2>&1)"; then
            maint_log "[Xray] ${ver} 无法通过现有配置的校验，保持 ${prev} 不变（上游可能有不兼容改动）"
            printf '%s\n' "$out" | tail -n 5
            return 1
        fi
    fi
    xray_apply_binary
    if [ "$(xray_node_count)" -eq 0 ]; then
        maint_log "[Xray] 已更新: ${prev:-未知} -> ${ver}"
        return 0
    fi
    systemctl restart adam-xray 2>/dev/null || true
    sleep 2
    if xray_healthy; then
        maint_log "[Xray] 已更新: ${prev:-未知} -> ${ver}"
        return 0
    fi
    maint_log "[Xray] ${ver} 启动失败，回滚到 ${prev:-旧版本}"
    journalctl -u adam-xray -n 10 --no-pager 2>/dev/null || true
    if [ -f "${XRAY_BIN}.previous" ]; then
        install -m 755 "${XRAY_BIN}.previous" "$XRAY_BIN"
        systemctl restart adam-xray 2>/dev/null || true
        sleep 2
        if xray_healthy; then maint_log "[Xray] 已回滚，服务恢复运行"; else maint_log "[Xray] 回滚后仍未启动: journalctl -u adam-xray -n 50"; fi
    fi
    return 1
}

# 每日维护调用：全程不提问
xray_autoupdate() {
    local cur
    [ -x "$XRAY_BIN" ] || return 0
    xray_load_state
    if [ "$XRAY_CHANNEL" = "pin" ]; then
        echo "[Xray] 已固定在 ${XRAY_PIN_VERSION}，不自动更新"
        return 0
    fi
    cur="$(xray_installed_version)"
    xray_query_latest "$XRAY_CHANNEL"
    if [ -z "$XRAY_LATEST" ]; then
        if [ "$XRAY_SOURCE_OK" = "1" ]; then
            echo "[Xray] ${XRAY_CHANNEL} 通道暂无可用发布，当前 ${cur}"
            return 0
        fi
        echo "[Xray] 未能获取官方发布信息，本次跳过；当前 ${cur}"
        return 1
    fi
    if [ -n "$cur" ] && ! xray_ver_gt "$XRAY_LATEST" "$cur"; then
        echo "[Xray] 已是最新: ${cur}（${XRAY_CHANNEL} 通道）"
        return 0
    fi
    echo "[Xray] 发现新版本: ${cur:-未知} -> ${XRAY_LATEST}，开始更新"
    xray_upgrade_to "$XRAY_LATEST"
}

xray_update() {
    xray_require || return 1
    local cur
    step "检查 Xray 更新"
    divider
    xray_load_state
    cur="$(xray_installed_version)"
    info "当前版本: ${cur:-未知}（${XRAY_CHANNEL} 通道）"
    if [ "$XRAY_CHANNEL" = "pin" ]; then
        info "已固定在 ${XRAY_PIN_VERSION}。要换版本或恢复跟随最新，请用「1) 安装 / 重装」重新选择通道"
        return 0
    fi
    info "正在查询官方发布 ..."
    xray_query_latest "$XRAY_CHANNEL"
    if [ -z "$XRAY_LATEST" ]; then
        warn "未能获取 ${XRAY_CHANNEL} 通道的版本信息（GitHub 不可达 / 被限流，或该通道暂无发布）"
        return 1
    fi
    info "官方最新: ${XRAY_LATEST}$([ "$XRAY_LATEST_IS_PRE" = "1" ] && echo "（预发布）")"
    if [ -n "$cur" ] && ! xray_ver_gt "$XRAY_LATEST" "$cur"; then
        success "已经是最新版本"
        return 0
    fi
    xray_compat_notice
    confirm "升级到 ${XRAY_LATEST}？" y || { info "已取消"; return 0; }
    if xray_upgrade_to "$XRAY_LATEST"; then success "升级完成: $(xray_installed_version)"; else return 1; fi
    return 0
}

xray_health_check() {
    xray_require || return 1
    local problems=0 tag active enabled restarts out cur days
    step "Xray 健康检查"
    divider
    hc_line() {
        case "$1" in
            0) echo -e "  ${GREEN}✓${NC} $2" ;;
            1) echo -e "  ${RED}✗${NC} $2"; problems=$((problems + 1)) ;;
            *) echo -e "  ${YELLOW}!${NC} $2" ;;
        esac
    }
    cur="$(xray_installed_version)"
    hc_line 0 "内核版本 ${cur:-未知}"
    if [ "$(xray_node_count)" -eq 0 ]; then
        hc_line 2 "还没有节点，服务不会启动"
        return 0
    fi
    active="$(systemctl is-active adam-xray 2>/dev/null || true)"
    enabled="$(systemctl is-enabled adam-xray 2>/dev/null || true)"
    restarts="$(systemctl show adam-xray -p NRestarts --value 2>/dev/null || true)"
    if [ "$active" = "active" ]; then hc_line 0 "服务运行中（systemd 自动重启次数: ${restarts:-0}）"; else hc_line 1 "服务未运行（状态: ${active:-unknown}）"; fi
    if [ "$enabled" = "enabled" ]; then hc_line 0 "已设为开机自启"; else hc_line 1 "未设为开机自启"; fi
    if out="$(xray_test_conf)"; then hc_line 0 "配置校验通过"; else hc_line 1 "配置校验失败: $(printf '%s\n' "$out" | tail -n 1)"; fi
    for tag in $(xray_node_tags); do
        xray_node_load "$tag" || continue
        if tcp_listening "$N_PORT"; then hc_line 0 "[${tag}] TCP ${N_PORT} 正在监听"; else hc_line 1 "[${tag}] TCP ${N_PORT} 没有在监听"; fi
        if [ "$N_PORT" -ge 1024 ] && ! reserved_port_ok "$N_PORT"; then hc_line 1 "[${tag}] 端口 ${N_PORT} 未加入内核保留端口"; fi
        if ufw_active && ! fw_is_allowed "$N_PORT" tcp; then hc_line 1 "[${tag}] 防火墙未放行 ${N_PORT}/tcp"; fi
        if [ "$N_TYPE" = "xhttp-cdn" ] && [ "$N_ORIGIN" != "plain" ] && [ -f "${XRAY_CERT_DIR}/${tag}/fullchain.pem" ]; then
            days="$(cert_expiry_days "${XRAY_CERT_DIR}/${tag}/fullchain.pem" 2>/dev/null || echo "")"
            if [[ "$days" =~ ^-?[0-9]+$ ]]; then
                if [ "$days" -lt 15 ]; then hc_line 1 "[${tag}] 回源证书剩余 ${days} 天"; else hc_line 0 "[${tag}] 回源证书剩余 ${days} 天"; fi
            fi
        fi
    done
    maint_load
    if [ "$MAINT_WATCHDOG" = "1" ] && systemctl is-active --quiet adam-watchdog.timer 2>/dev/null; then
        hc_line 0 "保活巡检定时器运行中（每 5 分钟）"
    else
        hc_line 1 "保活巡检定时器未运行"
    fi
    xray_load_state
    if [ "$XRAY_CHANNEL" = "pin" ]; then
        hc_line 2 "版本已固定在 ${XRAY_PIN_VERSION}，不自动更新"
    else
        if [ "$XRAY_AUTO_UPDATE" = "1" ]; then hc_line 0 "自动更新已开启（${XRAY_CHANNEL} 通道）"; else hc_line 2 "自动更新未开启"; fi
        xray_query_latest "$XRAY_CHANNEL"
        if [ -z "$XRAY_LATEST" ]; then
            hc_line 2 "暂时取不到官方发布信息，无法判断是否有新版本"
        elif [ -n "$cur" ] && xray_ver_gt "$XRAY_LATEST" "$cur"; then
            hc_line 2 "官方有新版本 ${XRAY_LATEST}（当前 ${cur}）"
        else
            hc_line 0 "已是 ${XRAY_CHANNEL} 通道最新版本"
        fi
    fi
    divider
    if [ "$problems" -eq 0 ]; then success "健康检查通过"; return 0; fi
    warn "发现 ${problems} 项问题，可用「一键修复」处理"
    return 1
}

xray_repair() {
    xray_require || return 1
    local spec
    step "Xray 一键修复"
    divider
    xray_ensure_user || return 1
    [ -f "${XRAY_CONF_D}/00-base.json" ] || xray_write_base
    xray_write_service
    xray_fix_perms
    systemctl daemon-reload
    systemctl reset-failed adam-xray >/dev/null 2>&1 || true
    reserved_ports_sync || true
    if ufw_active; then
        while IFS= read -r spec; do [ -n "$spec" ] && ufw allow "$spec" >/dev/null 2>&1; done < <(xray_ports)
    fi
    maint_install_timers || true
    if xray_reload; then success "修复完成"; else return 1; fi
    return 0
}

xray_status() {
    xray_require || return 1
    systemctl status adam-xray --no-pager 2>/dev/null | head -n 12 || true
    divider
    xray_load_state
    echo "  内核版本 : $(xray_installed_version)"
    echo "  版本通道 : ${XRAY_CHANNEL}$([ "$XRAY_CHANNEL" = "pin" ] && echo "（${XRAY_PIN_VERSION}）")    自动更新: $([ "$XRAY_AUTO_UPDATE" = "1" ] && echo 开 || echo 关)"
    echo "  节点数量 : $(xray_node_count)"
    return 0
}

xray_logs() {
    xray_require || return 1
    info "实时日志（Ctrl+C 返回）"
    journalctl -u adam-xray -n 30 -f || true
    return 0
}

xray_restart() {
    xray_require || return 1
    if xray_reload; then success "Xray 已重启"; else return 1; fi
    return 0
}

xray_set_host() {
    xray_require || return 1
    local ans hostre='^[][A-Za-z0-9.:_-]+$'
    xray_load_state
    read -rp "分享链接用的公网地址（当前 ${XRAY_PUBLIC_HOST:-未设置}）: " ans
    if [[ -n "$ans" && "$ans" =~ $hostre ]]; then
        XRAY_PUBLIC_HOST="$ans"; xray_save_state; success "已更新"
    else
        warn "未修改（为空或格式不合法）"
    fi
    return 0
}

xray_uninstall() {
    if [ ! -x "$XRAY_BIN" ] && [ ! -f "$XRAY_SERVICE" ]; then info "未检测到本模块安装的 Xray"; return 0; fi
    local specs
    confirm "确认卸载 Xray（本模块安装的 adam-xray）？" n || { info "已取消"; return 0; }
    specs="$(xray_ports | tr '\n' ' ')"
    systemctl disable --now adam-xray >/dev/null 2>&1 || true
    rm -f "$XRAY_SERVICE"
    rm -rf "$XRAY_DIR"
    systemctl daemon-reload
    if confirm "同时删除全部节点配置 ${XRAY_CONF_DIR}（含密钥）？" n; then
        rm -rf "$XRAY_CONF_DIR"
        userdel adam-xray >/dev/null 2>&1 || true
        if [ -n "${specs// /}" ] && ufw_installed; then
            if confirm "同时删除防火墙里这些节点端口的放行规则（${specs}）？" y; then fw_prune_old_specs "$specs"; fi
        fi
    else
        info "已保留 ${XRAY_CONF_DIR}，重装后节点可直接恢复"
    fi
    reserved_ports_sync || true
    success "Xray 已卸载"
    return 0
}

xray_state_text() {
    local v
    if [ ! -x "$XRAY_BIN" ]; then printf '%s' "${YELLOW}未安装${NC}"; return 0; fi
    v="$(xray_installed_version)"
    if [ "$(xray_node_count)" -eq 0 ]; then
        printf '%s' "${v:-版本未知} · ${YELLOW}无节点${NC}"
    else
        printf '%s' "${v:-版本未知} · $(xray_node_count) 个节点 · $(svc_state adam-xray)"
    fi
}

xray_menu() {
    local choice
    while true; do
        clear 2>/dev/null || true
        xray_load_state
        echo -e "${BOLD}${CYAN}━━━ Xray 管理（SS / VLESS） ━━━${NC}"
        echo -e "  当前状态: $(xray_state_text)    通道: ${XRAY_CHANNEL}    自动更新: $(maint_onoff "$XRAY_AUTO_UPDATE")"
        divider
        echo -e "  ${GREEN}1)${NC}  ${GREEN}安装${NC} / 重装 Xray 内核（选择通道：最新预发布 / 正式版 / 指定版本）"
        echo -e "  ${GREEN}2)${NC}  ${GREEN}添加节点${NC}（REALITY Vision / XHTTP REALITY / XHTTP CDN / VLESS Encryption / SS2022）"
        echo -e "  ${GREEN}3)${NC}  节点列表"
        echo -e "  ${GREEN}4)${NC}  查看节点配置 / 分享链接"
        echo -e "  ${GREEN}5)${NC}  ${RED}删除节点${NC}"
        echo -e "  ${GREEN}6)${NC}  检查并更新内核"
        echo -e "  ${GREEN}7)${NC}  自动更新 开 / 关"
        echo -e "  ${GREEN}8)${NC}  健康检查（只检测）"
        echo -e "  ${GREEN}9)${NC}  一键修复"
        echo -e "  ${GREEN}10)${NC} 服务状态"
        echo -e "  ${GREEN}11)${NC} 实时日志"
        echo -e "  ${GREEN}12)${NC} 重启服务"
        echo -e "  ${GREEN}13)${NC} 修改分享链接用的公网地址"
        echo -e "  ${GREEN}14)${NC} ${RED}卸载${NC} Xray"
        echo -e "  ${GREEN}0)${NC}  返回主菜单"
        divider
        read -rp "请选择 [0-14]: " choice
        case "$choice" in
            1)  run_action xray_install ;;
            2)  run_action xray_add_node ;;
            3)  run_action xray_list_nodes ;;
            4)  run_action xray_show_links ;;
            5)  run_action xray_delete_node ;;
            6)  run_action xray_update ;;
            7)  run_action maint_toggle_xray ;;
            8)  run_action xray_health_check ;;
            9)  run_action xray_repair ;;
            10) run_action xray_status ;;
            11) run_action xray_logs ;;
            12) run_action xray_restart ;;
            13) run_action xray_set_host ;;
            14) run_action xray_uninstall ;;
            0)  return 0 ;;
            *)  warn "无效选择" ;;
        esac
        pause_return
    done
}

xray_cli() {
    local sub="${1:-menu}"
    if [ "$#" -gt 0 ]; then shift; fi
    case "$sub" in
        menu)         xray_menu ;;
        install)      xray_install ;;
        add)          xray_add_node ;;
        list)         xray_list_nodes ;;
        links|config) xray_show_links ;;
        delete|del)   xray_delete_node ;;
        update)       xray_update ;;
        health)       xray_health_check ;;
        repair)       xray_repair ;;
        status)       xray_status ;;
        logs)         xray_logs ;;
        restart)      xray_restart ;;
        uninstall)    xray_uninstall ;;
        *) error "未知的 xray 子命令: ${sub}（可用: install / add / list / links / delete / update / health / repair / status / logs / restart / uninstall）" ;;
    esac
}

# ══════════════════════════════════════════════════════════════
#   系统与网络调优
#     - TCP 调优：直接使用 Kylin010/tcpfit（按本机实测推导参数、可回滚）。本脚本只负责
#       拉取、校验、安装到 /usr/local/bin/tcpfit 并调用，调优逻辑由 tcpfit 自己维护；
#     - XanMod 内核、DNS、IPv4/IPv6 优先级、禁用 IPv6：功能参考 Eric86777/vps-tcp-tune，
#       实现为本脚本自有的精简版（每项都有备份与恢复）。
# ══════════════════════════════════════════════════════════════

# 拉取 tcpfit 到临时文件并校验；成功后路径写入 TCPFIT_TMP、版本写入 TCPFIT_REMOTE_VER
tcpfit_fetch() {
    local want got
    TCPFIT_TMP=""; TCPFIT_REMOTE_VER=""
    make_workdir
    local wd="$WORKDIR"
    if ! curl -fsSL --max-time 60 "${TCPFIT_RAW}/tcpfit.sh" -o "$wd/tcpfit.sh"; then
        warn "下载 tcpfit 失败（${TCPFIT_RAW}/tcpfit.sh），请检查到 GitHub 的网络"
        return 1
    fi
    # 与 tcpfit 自己的安装脚本相同的三项自检：是脚本、有版本号、语法完整（防传输截断）
    if ! head -n 1 "$wd/tcpfit.sh" | grep -q '^#!' || ! grep -q '^VERSION=' "$wd/tcpfit.sh" || ! bash -n "$wd/tcpfit.sh" 2>/dev/null; then
        warn "下载到的 tcpfit 不完整或不是脚本（传输被截断或被网关拦截），已放弃"
        return 1
    fi
    TCPFIT_REMOTE_VER="$(grep -m1 '^VERSION=' "$wd/tcpfit.sh" | cut -d'"' -f2 || true)"
    got="$(sha256sum "$wd/tcpfit.sh" | awk '{print $1}')"
    want="$(curl -fsSL --max-time 20 "${TCPFIT_RAW}/SHA256SUMS" 2>/dev/null | awk '$2 == "tcpfit.sh" {print $1}' | head -n 1 || true)"
    if [ -z "$want" ]; then
        warn "取不到仓库里的 SHA256SUMS，无法核对校验值（SHA256: ${got}）"
        confirm "仍要继续？" n || return 1
    elif [ "$want" != "$got" ]; then
        warn "SHA256 与仓库 SHA256SUMS 不一致（仓库 ${want}，实际 ${got}）"
        warn "可能是作者刚更新、两个文件的缓存不同步，也可能是下载被篡改"
        confirm "仍要继续？" n || return 1
    else
        success "SHA256 与仓库 SHA256SUMS 一致"
    fi
    TCPFIT_TMP="$wd/tcpfit.sh"
    return 0
}

tcpfit_installed_version() {
    [ -x "$TCPFIT_BIN" ] || return 0
    grep -m1 '^VERSION=' "$TCPFIT_BIN" 2>/dev/null | cut -d'"' -f2 || true
}

tcpfit_install() {
    local cur
    cur="$(tcpfit_installed_version)"
    info "tcpfit 是第三方开源脚本（${TCPFIT_RAW%/main}），将以 root 运行并修改 sysctl / qdisc 等网络参数"
    info "它的改动只写在自己的文件里（/etc/sysctl.d/99-tcpfit.conf 等），可用 tcpfit rollback 整体回滚"
    confirm "${cur:+当前已安装 ${cur}，}从官方仓库拉取最新版并安装到 ${TCPFIT_BIN}？" y || return 1
    tcpfit_fetch || return 1
    install -m 755 "$TCPFIT_TMP" "$TCPFIT_BIN"
    rm -f /usr/local/sbin/tcpfit.sh
    success "tcpfit ${TCPFIT_REMOTE_VER} 已安装"
    return 0
}

tcpfit_run() {   # tcpfit_run [子命令...]：没装先装
    if [ ! -x "$TCPFIT_BIN" ]; then
        tcpfit_install || return 1
    fi
    if [ "$#" -eq 0 ] && [ ! -t 0 ]; then
        warn "tcpfit 的菜单需要在终端里运行，请直接执行: tcpfit"
        return 1
    fi
    "$TCPFIT_BIN" "$@" || warn "tcpfit 以非 0 状态退出（如果是你主动退出菜单可忽略）"
    return 0
}

tcpfit_menu_entry() {
    step "TCP 调优（tcpfit）"
    divider
    echo "  tcpfit 会按本机实测结果推导缓冲区、BBR/fq、限速器拐点与整形参数，而不是套固定值。"
    echo "  进入后选「1 一键调优」即可；所有改动可用其菜单 7 或 tcpfit rollback 回滚。"
    echo ""
    tcpfit_run
}

tcpfit_update() {
    if [ ! -x "$TCPFIT_BIN" ]; then tcpfit_install; return $?; fi
    info "当前 tcpfit 版本: $(tcpfit_installed_version)"
    tcpfit_fetch || return 1
    if cmp -s "$TCPFIT_TMP" "$TCPFIT_BIN"; then
        success "已是仓库最新（${TCPFIT_REMOTE_VER}）"
        return 0
    fi
    confirm "仓库版本为 ${TCPFIT_REMOTE_VER}，更新？" y || return 0
    install -m 755 "$TCPFIT_TMP" "$TCPFIT_BIN"
    success "tcpfit 已更新到 ${TCPFIT_REMOTE_VER}"
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
    step "安装 / 更新 XanMod 内核（内置 BBR v3）"
    divider
    local arch virt id="" codename="" lvl pkg="" free_mb c keyring=/etc/apt/keyrings/xanmod-archive-keyring.gpg
    local -a cands=()
    arch="$(uname -m)"
    if [ "$arch" != "x86_64" ]; then
        warn "XanMod 官方只提供 x86_64 构建，本机是 ${arch}"
        info "ARM 机器的发行版内核自带 BBR + fq，直接用「1) TCP 调优」即可"
        return 1
    fi
    virt="$(systemd-detect-virt 2>/dev/null || true)"
    case "$virt" in
        lxc|lxc-libvirt|openvz|docker|podman|systemd-nspawn|wsl)
            warn "当前是容器类虚拟化（${virt}），与宿主机共用内核，无法更换内核"
            return 1 ;;
    esac
    if [ -r /etc/os-release ]; then
        id="$( . /etc/os-release; printf '%s' "${ID:-}" )"
        codename="$( . /etc/os-release; printf '%s' "${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}" )"
    fi
    if [ "$id" != "debian" ] && [ "$id" != "ubuntu" ]; then
        warn "仅支持 Debian / Ubuntu（当前: ${id:-未知}）"
        return 1
    fi
    if [ -z "$codename" ]; then warn "无法识别发行版代号，不能添加 XanMod 软件源"; return 1; fi
    free_mb="$(df -Pm /boot 2>/dev/null | awk 'NR==2 {print $4}' || echo 0)"
    if [ "${free_mb:-0}" -lt 300 ]; then
        warn "/boot 可用空间只有 ${free_mb:-0} MB（建议 ≥ 300 MB），装新内核可能失败，请先清理旧内核"
        confirm "仍要继续？" n || return 1
    fi
    lvl="$(xanmod_cpu_level)"
    info "CPU 指令集等级: x86-64-v${lvl}    发行版: ${id} ${codename}    当前内核: $(uname -r)"
    if [ -n "$(xanmod_installed_pkgs)" ]; then info "已安装的 XanMod 包: $(xanmod_installed_pkgs | tr '\n' ' ')"; fi
    warn "更换内核有风险：请确认服务商面板有 VNC / 救援模式，万一新内核起不来可以回到旧内核"
    confirm "继续安装 / 更新 XanMod 内核？" n || { info "已取消"; return 0; }

    apt_install gnupg ca-certificates curl || { warn "依赖安装失败"; return 1; }
    install -d -m 755 /etc/apt/keyrings
    make_workdir
    if ! curl -fsSL --max-time 30 https://dl.xanmod.org/archive.key -o "$WORKDIR/xanmod.key" \
        || ! gpg --dearmor --yes -o "$keyring" < "$WORKDIR/xanmod.key" 2>/dev/null; then
        warn "XanMod 仓库密钥下载或导入失败"
        return 1
    fi
    chmod 644 "$keyring"
    echo "deb [signed-by=${keyring}] http://deb.xanmod.org ${codename} main" > /etc/apt/sources.list.d/xanmod-release.list
    info "正在更新软件包列表 ..."
    apt-get update -qq || warn "apt-get update 部分失败，继续尝试"
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
        warn "软件源里没有适合 x86-64-v${lvl} 的 XanMod 内核包（发行版 ${codename} 可能不在 XanMod 支持列表里）"
        rm -f /etc/apt/sources.list.d/xanmod-release.list
        return 1
    fi
    info "将安装: ${pkg}"
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg"; then
        warn "内核包安装失败"
        return 1
    fi
    success "XanMod 内核已安装: ${pkg}"
    warn "需要重启才会切换到新内核。重启后可用本菜单「8) 查看当前状态」确认，再用「1) TCP 调优」启用 BBR"
    info "软件源已保留（/etc/apt/sources.list.d/xanmod-release.list），之后 apt upgrade 或再次执行本项即可更新内核"
    if confirm "现在重启？" n; then
        info "3 秒后重启 ..."
        sleep 3
        reboot
    fi
    return 0
}

xanmod_uninstall() {
    step "卸载 XanMod 内核"
    divider
    local pkgs others
    pkgs="$(xanmod_installed_pkgs | tr '\n' ' ')"
    if [ -z "${pkgs// /}" ]; then info "没有检测到已安装的 XanMod 内核包"; return 0; fi
    # 必须还有别的内核可以启动，否则卸完就起不来了
    others="$(dpkg-query -W -f='${Status} ${Package}\n' 'linux-image-*' 2>/dev/null | awk '$1 == "install" && $3 == "installed" && $4 !~ /xanmod/ {print $4}' | tr '\n' ' ' || true)"
    if [ -z "${others// /}" ]; then
        warn "系统里没有其他已安装的内核镜像，卸载 XanMod 后将无法启动，已拒绝"
        info "请先安装发行版内核：Debian 用 apt install linux-image-amd64，Ubuntu 用 apt install linux-image-generic"
        return 1
    fi
    info "将卸载: ${pkgs}"
    info "保留的其他内核: ${others}"
    confirm "确认卸载？（卸载后重启会回到发行版内核）" n || { info "已取消"; return 0; }
    # shellcheck disable=SC2086
    DEBIAN_FRONTEND=noninteractive apt-get purge -y $pkgs || { warn "卸载失败"; return 1; }
    rm -f /etc/apt/sources.list.d/xanmod-release.list /etc/apt/keyrings/xanmod-archive-keyring.gpg
    if command -v update-grub >/dev/null 2>&1; then update-grub >/dev/null 2>&1 || true; fi
    success "XanMod 内核已卸载，重启后生效"
    return 0
}

# ── DNS ────────────────────────────────────────────────────────

resolved_active() { systemctl is-active --quiet systemd-resolved 2>/dev/null; }

dns_show() {
    info "当前 DNS："
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
    step "设置 DNS"
    divider
    local ans choice servers="" dot="no" s v4 v6 iface
    dns_show
    echo ""
    if dns_locked_by_others; then
        warn "/etc/resolv.conf 被加了不可修改属性（chattr +i）—— 通常是 cnblock 的 DNS 黑洞在接管解析"
        warn "此时改系统 DNS 会让它失效或互相打架，已中止。请先执行 cnblock close，或改它的上游 DNS"
        return 1
    fi
    echo "  1) Cloudflare + Google（1.1.1.1 / 8.8.8.8，含 IPv6）"
    echo "  2) Google + Cloudflare（8.8.8.8 / 1.1.1.1，含 IPv6）"
    echo "  3) Quad9 + Cloudflare（9.9.9.9 / 1.1.1.1，含 IPv6）"
    echo "  4) 自定义"
    echo "  0) 返回"
    read -rp "请选择 [0-4]: " choice
    case "$choice" in
        1) v4="1.1.1.1 8.8.8.8"; v6="2606:4700:4700::1111 2001:4860:4860::8888" ;;
        2) v4="8.8.8.8 1.1.1.1"; v6="2001:4860:4860::8888 2606:4700:4700::1111" ;;
        3) v4="9.9.9.9 1.1.1.1"; v6="2620:fe::fe 2606:4700:4700::1111" ;;
        4)
            read -rp "输入 DNS 服务器 IP（空格分隔，可混合 IPv4 / IPv6）: " ans
            v4=""; v6=""
            for s in $ans; do
                if ! is_ip "$s"; then warn "不是合法 IP: ${s}"; return 1; fi
                if [[ "$s" == *:* ]]; then v6="${v6:+$v6 }$s"; else v4="${v4:+$v4 }$s"; fi
            done
            if [ -z "$v4$v6" ]; then warn "没有输入任何服务器"; return 1; fi
            ;;
        *) return 0 ;;
    esac
    # 本机 IPv6 不可用时不写 IPv6 的 DNS，避免解析超时
    if snell_ipv6_ok && ip -6 route show default 2>/dev/null | grep -q .; then servers="${v4:+$v4 }${v6}"; else servers="${v4:-$v6}"; fi
    servers="${servers% }"

    if resolved_active; then
        if [ "$choice" != "4" ] && confirm "启用 DNS over TLS（opportunistic：上游支持就加密，不支持自动回退）？" n; then dot="opportunistic"; fi
        install -d -m 755 /etc/systemd/resolved.conf.d
        cat > "$DNS_DROPIN" << DNSEOF
# 由 Adam 管理脚本生成（系统与网络调优 -> DNS）。删除本文件并重启 systemd-resolved 即恢复。
[Resolve]
DNS=${servers}
FallbackDNS=
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
        success "已通过 systemd-resolved 设置 DNS: ${servers}"
    else
        if [ ! -e "$DNS_RESOLV_BACKUP" ]; then
            install -d -m 755 "$MAINT_DIR"
            cp -P /etc/resolv.conf "$DNS_RESOLV_BACKUP" 2>/dev/null || true
        fi
        rm -f /etc/resolv.conf
        {
            echo "# 由 Adam 管理脚本生成；原文件备份在 ${DNS_RESOLV_BACKUP}"
            for s in $servers; do echo "nameserver $s"; done
            echo "options timeout:2 attempts:2"
        } > /etc/resolv.conf
        success "已写入 /etc/resolv.conf: ${servers}"
        warn "如果本机用 DHCP，续租或重启网络时该文件可能被改回（那种情况需在 DHCP / 网络配置里固定 DNS）"
    fi
    echo ""
    if getent hosts www.cloudflare.com >/dev/null 2>&1; then success "解析测试通过"; else warn "解析测试失败，请检查，或用「恢复 DNS」撤销"; fi
    return 0
}

dns_restore() {
    local iface
    if [ -f "$DNS_DROPIN" ]; then
        rm -f "$DNS_DROPIN"
        iface="$(ip route show default 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") {print $(i + 1); exit}}' || true)"
        if [ -n "$iface" ] && command -v resolvectl >/dev/null 2>&1; then resolvectl revert "$iface" 2>/dev/null || true; fi
        systemctl restart systemd-resolved 2>/dev/null || true
        success "已移除本脚本的 systemd-resolved 配置，DNS 恢复为系统原设置"
    elif [ -e "$DNS_RESOLV_BACKUP" ] || [ -L "$DNS_RESOLV_BACKUP" ]; then
        rm -f /etc/resolv.conf
        cp -P "$DNS_RESOLV_BACKUP" /etc/resolv.conf
        rm -f "$DNS_RESOLV_BACKUP"
        success "已从备份恢复 /etc/resolv.conf"
    else
        info "没有本脚本做过的 DNS 改动可恢复"
    fi
    return 0
}

dns_menu() {
    local ans
    echo "  1) 查看当前 DNS    2) 设置 DNS    3) 恢复为修改前    0) 返回"
    read -rp "请选择: " ans
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
    local p4
    p4="$(awk '$1 == "precedence" && $2 == "::ffff:0:0/96" {print $3}' /etc/gai.conf 2>/dev/null | tail -n 1 || true)"
    if [[ "$p4" =~ ^[0-9]+$ ]] && [ "$p4" -ge 50 ]; then printf 'IPv4 优先'; else printf 'IPv6 优先（系统默认）'; fi
}

ip_priority_set() {   # ip_priority_set ipv4|ipv6
    local which="$1" p4=100 p6=10
    if [ "$which" = "ipv6" ]; then p4=10; p6=100; fi
    install -d -m 755 "$MAINT_DIR"
    # 只在第一次改动前备份原始状态
    if [ ! -e "$GAI_BACKUP" ] && [ ! -e "${GAI_BACKUP}.absent" ]; then
        if [ -f /etc/gai.conf ]; then cp -p /etc/gai.conf "$GAI_BACKUP"; else : > "${GAI_BACKUP}.absent"; fi
    fi
    cat > /etc/gai.conf << GAIEOF
# 由 Adam 管理脚本生成（系统与网络调优 -> IPv4/IPv6 优先级）。原文件备份: ${GAI_BACKUP}
# 只影响"域名同时有 A 和 AAAA 记录时先连哪个"，不关闭 IPv4 或 IPv6。
precedence ::1/128        50
precedence ::ffff:0:0/96  ${p4}
precedence ::/0           ${p6}
precedence 2002::/16      30
precedence fe80::/10      1
precedence fec0::/10      1
precedence fc00::/7       1
GAIEOF
    if command -v resolvectl >/dev/null 2>&1; then resolvectl flush-caches 2>/dev/null || true; fi
    success "已设置为 $([ "$which" = "ipv6" ] && echo IPv6 || echo IPv4) 优先（新启动的程序生效；已在运行的服务重启后生效）"
    return 0
}

ip_priority_restore() {
    if [ -f "$GAI_BACKUP" ]; then
        cp -p "$GAI_BACKUP" /etc/gai.conf; rm -f "$GAI_BACKUP"
        success "已恢复原来的 /etc/gai.conf"
    elif [ -e "${GAI_BACKUP}.absent" ]; then
        rm -f /etc/gai.conf "${GAI_BACKUP}.absent"
        success "已恢复（原系统没有 /etc/gai.conf，已删除）"
    else
        info "没有本脚本做过的优先级改动可恢复"
    fi
    return 0
}

ip_priority_menu() {
    local ans
    echo "  当前: $(ip_priority_current)"
    echo "  1) IPv4 优先    2) IPv6 优先    3) 恢复为修改前    0) 返回"
    read -rp "请选择: " ans
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
        0) printf '已启用' ;;
        1) if [ -f "$IPV6_DISABLE_FILE" ]; then printf '已禁用（永久）'; else printf '已禁用（临时，重启恢复）'; fi ;;
        *) printf '未知' ;;
    esac
}

# IPv6 可用性变化后，让本脚本管理的服务换用合适的监听地址
services_adapt_ipv6() {
    local f changed=0 port psk mode pref
    if [ -x "$SNELL_BIN" ] && [ -f "$SNELL_CONF" ]; then
        port="$(snell_port)"; psk="$(snell_conf_get psk 2>/dev/null || true)"
        mode="$(snell_conf_get mode 2>/dev/null || true)"; pref="$(snell_conf_get dns-ip-preference 2>/dev/null || true)"
        if [ -n "$port" ] && [ -n "$psk" ]; then
            snell_write_conf "$port" "$psk" "${mode:-default}" "${pref:-default}"
            systemctl try-restart snell >/dev/null 2>&1 || true
            info "Snell 的监听地址已按当前 IPv6 状态调整"
        fi
    fi
    if [ -d "$XRAY_CONF_D" ]; then
        for f in "$XRAY_CONF_D"/10-in-*.json; do
            [ -f "$f" ] || continue
            if snell_ipv6_ok; then
                if grep -q '"listen": "0.0.0.0"' "$f"; then sed -i 's/"listen": "0.0.0.0"/"listen": "::"/' "$f"; changed=1; fi
            else
                if grep -q '"listen": "::"' "$f"; then sed -i 's/"listen": "::"/"listen": "0.0.0.0"/' "$f"; changed=1; fi
            fi
        done
        if [ "$changed" = "1" ]; then
            systemctl try-restart adam-xray >/dev/null 2>&1 || true
            info "Xray 节点的监听地址已按当前 IPv6 状态调整"
        fi
    fi
    return 0
}

ipv6_ssh_guard() {
    local peer="${SSH_CONNECTION%% *}"
    if [[ "$peer" == *:* ]]; then
        warn "你当前是通过 IPv6（${peer}）登录的：禁用 IPv6 会立刻断开，且之后只能用 IPv4 登录"
        confirm "确认本机有可用的 IPv4 登录方式并继续？" n || return 1
    fi
    return 0
}

ipv6_disable() {   # ipv6_disable temp|perm
    local mode="$1"
    ipv6_ssh_guard || { info "已取消"; return 0; }
    if [ "$mode" = "perm" ]; then
        confirm "永久禁用 IPv6（写入 ${IPV6_DISABLE_FILE}，重启后仍然生效）？" n || { info "已取消"; return 0; }
        cat > "$IPV6_DISABLE_FILE" << V6EOF
# 由 Adam 管理脚本生成（系统与网络调优 -> 禁用 IPv6）。删除本文件并执行 sysctl --system 即恢复。
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
V6EOF
    else
        confirm "临时禁用 IPv6（重启后自动恢复）？" y || { info "已取消"; return 0; }
    fi
    sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.lo.disable_ipv6=1 >/dev/null 2>&1 || true
    if [ "$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo 0)" = "1" ]; then
        success "IPv6 $(ipv6_state_text)"
        services_adapt_ipv6
    else
        warn "禁用失败（内核可能未编译 IPv6 或 sysctl 被限制）"
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
        success "IPv6 已恢复启用（网卡的 IPv6 地址可能需要几秒，或重启网络 / 重启系统后才重新获取）"
        services_adapt_ipv6
    else
        warn "恢复失败：可能有其他 sysctl 配置文件也禁用了 IPv6（grep -r disable_ipv6 /etc/sysctl.d /etc/sysctl.conf）"
        return 1
    fi
    return 0
}

ipv6_menu() {
    local ans
    echo "  当前: IPv6 $(ipv6_state_text)"
    echo "  1) 临时禁用（重启恢复）    2) 永久禁用    3) 恢复启用    0) 返回"
    read -rp "请选择: " ans
    case "$ans" in
        1) ipv6_disable temp ;;
        2) ipv6_disable perm ;;
        3) ipv6_enable ;;
        *) : ;;
    esac
    return 0
}

net_status() {
    step "当前系统与网络状态"
    divider
    echo "  内核       : $(uname -r)$([[ "$(uname -r)" == *xanmod* ]] && echo "（XanMod）")"
    echo "  拥塞控制   : $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo '?')    可用: $(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo '?')"
    echo "  默认队列   : $(sysctl -n net.core.default_qdisc 2>/dev/null || echo '?')"
    echo "  IPv6       : $(ipv6_state_text)"
    echo "  地址优先级 : $(ip_priority_current)"
    echo "  tcpfit     : $([ -x "$TCPFIT_BIN" ] && echo "已安装 $(tcpfit_installed_version)" || echo 未安装)"
    echo "  保留端口   : $(sysctl -n net.ipv4.ip_local_reserved_ports 2>/dev/null || echo '?')"
    echo ""
    dns_show
    return 0
}

tune_menu() {
    local choice
    while true; do
        clear 2>/dev/null || true
        echo -e "${BOLD}${CYAN}━━━ 系统与网络调优 ━━━${NC}"
        echo -e "  内核: $(uname -r)    拥塞控制: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo '?')    IPv6: $(ipv6_state_text)    $(ip_priority_current)"
        divider
        echo -e "  ${GREEN}1)${NC} ${GREEN}TCP 调优${NC}（tcpfit：按本机实测推导参数，可回滚）"
        echo -e "  ${GREEN}2)${NC} tcpfit 状态 / 回滚 / 更新"
        echo -e "  ${GREEN}3)${NC} 安装 / 更新 XanMod 内核（BBR v3，仅 x86_64）"
        echo -e "  ${GREEN}4)${NC} ${RED}卸载${NC} XanMod 内核"
        echo -e "  ${GREEN}5)${NC} DNS 设置（查看 / 修改 / 恢复）"
        echo -e "  ${GREEN}6)${NC} IPv4 / IPv6 优先级"
        echo -e "  ${GREEN}7)${NC} 禁用 / 恢复 IPv6"
        echo -e "  ${GREEN}8)${NC} 查看当前状态"
        echo -e "  ${GREEN}0)${NC} 返回主菜单"
        divider
        read -rp "请选择 [0-8]: " choice
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
            *) warn "无效选择" ;;
        esac
        pause_return
    done
}

tcpfit_sub_menu() {
    local ans
    echo "  1) 查看 tcpfit 状态    2) 回滚 tcpfit 的全部改动    3) 检查并更新 tcpfit    0) 返回"
    read -rp "请选择: " ans
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
        *) error "未知的 tune 子命令: ${sub}（可用: tcp [tcpfit 子命令] / tcpfit-update / xanmod / xanmod-remove / dns [show|set|restore] / prefer [ipv4|ipv6|restore] / ipv6 [off|off-temp|on] / status）" ;;
    esac
}

do_update_script() {
    step "更新管理脚本"
    divider
    local tmp remote_ver
    make_workdir
    tmp="$WORKDIR/manager.sh"
    info "当前版本: ${SCRIPT_VERSION}，正在从 ${SCRIPT_URL} 下载 ..."
    if ! curl -fsSL --max-time 30 "$SCRIPT_URL" -o "$tmp"; then
        warn "下载失败，请检查网络或脚本地址"
        return 1
    fi
    if ! grep -q "Adam Nowhere" "$tmp" 2>/dev/null || ! grep -q '^case "\$ACTION" in' "$tmp" 2>/dev/null || ! bash -n "$tmp" 2>/dev/null; then
        warn "下载到的内容不是本脚本、不完整或存在语法错误，已放弃更新（现有脚本未改动）"
        return 1
    fi
    remote_ver="$(grep -m1 '^SCRIPT_VERSION=' "$tmp" | cut -d'"' -f2 || true)"
    info "远端版本: ${remote_ver:-未知}"
    if [ "$remote_ver" = "$SCRIPT_VERSION" ]; then
        if ! confirm "版本号相同，仍要用远端内容覆盖本地脚本？" n; then
            info "已取消"
            return 0
        fi
    fi
    if [ -f "$MANAGER_PATH" ]; then cp -f "$MANAGER_PATH" "${MANAGER_PATH}.bak"; fi
    install -m 755 "$tmp" "$MANAGER_PATH"
    success "管理脚本已更新到 ${remote_ver:-新版本}（旧版备份在 ${MANAGER_PATH}.bak），重新运行 adam 生效"
    return 0
}

usage() {
    cat << USAGEEOF
用法: adam [命令]          （不带参数 = 打开菜单）

Nowhere:
  install | uninstall | update | reconfig | config | status | logs | restart
  fingerprint | version | select-version | rollback | generate-key | probe
  cert-status | install-egress | shortcuts

Snell v${SNELL_MAJOR}:
  snell                      打开 Snell 菜单
  snell install | update | config | reconfig | status | health | repair | logs | restart | uninstall
  snell auto on|off          开/关 跟随官方发布的自动更新（默认 beta 通道：跟随最新测试版）

Xray (SS / VLESS):
  xray                       打开 Xray 菜单
  xray install | add | list | links | delete | update | health | repair | status | logs | restart | uninstall

系统与网络调优:
  tune                       打开调优菜单
  tune tcp [tcpfit 子命令]   运行 tcpfit（不带子命令 = 它的菜单），如 adam tune tcp status
  tune xanmod | xanmod-remove
  tune dns [show|set|restore] | prefer [ipv4|ipv6|restore] | ipv6 [off|off-temp|on] | status

自动维护:
  auto                       打开自动维护菜单（保活巡检 / 自动更新开关）
  maintain | watchdog        立即执行一次每日维护 / 保活巡检（定时器调用的就是这两个）
  maintain-log               查看维护记录

防火墙 (ufw):
  fw                         打开防火墙菜单
  fw install | list | status | on | off | sync
  fw allow <端口>            例: adam fw allow 443/tcp,8000-8100    （不写协议 = TCP+UDP）
  fw deny  <端口>            删除放行规则

Fail2ban:
  f2b                        打开 Fail2ban 菜单
  f2b install | status | banned | log | on | off | restart | uninstall
  f2b bantime <时长>         例: adam f2b bantime 1h   （纯数字 = 分钟，-1 = 永久）
  f2b ban <IP> | unban <IP> | unban-all

其他:
  update-script              更新本管理脚本
USAGEEOF
}

run_interactive_menu() {
    while true; do
        show_menu
        case "$MENU_CHOICE" in
            1)  run_action do_install ;;
            2)  run_action do_uninstall ;;
            3)  run_action do_update ;;
            4)  run_action do_reconfig ;;
            5)  run_action do_show_config ;;
            6)  run_action do_show_status ;;
            7)  run_action do_show_logs ;;
            8)  run_action do_fingerprint ;;
            9)  run_action do_restart ;;
            10) run_action install_shortcuts ;;
            11) run_action do_show_version ;;
            12) run_action do_select_version ;;
            13) run_action do_rollback ;;
            14) run_action do_genkey ;;
            15) run_action do_probe ;;
            16) run_action do_cert_status ;;
            17) run_action do_install_egress_service ;;
            18) snell_menu; continue ;;
            19) fw_menu; continue ;;
            20) f2b_menu; continue ;;
            21) run_action do_update_script ;;
            22) xray_menu; continue ;;
            23) tune_menu; continue ;;
            24) maint_menu; continue ;;
            0)  exit 0 ;;
            *)  warn "无效选择" ;;
        esac
        pause_return
    done
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
    install-egress) do_install_egress_service ;;
    snell)      snell_cli "${ACTION_ARGS[@]}" ;;
    snell-autoupdate) snell_autoupdate ;;
    fw|firewall) fw_cli "${ACTION_ARGS[@]}" ;;
    f2b|fail2ban) f2b_cli "${ACTION_ARGS[@]}" ;;
    update-script) do_update_script ;;
    xray)       xray_cli "${ACTION_ARGS[@]}" ;;
    tune)       tune_cli "${ACTION_ARGS[@]}" ;;
    auto|maint) maint_menu ;;
    watchdog)   maint_watchdog ;;
    maintain)   maint_daily ;;
    maintain-log) maint_show_log ;;
    help|-h|--help) usage ;;
    *) usage; error "未知操作: ${ACTION}" ;;
esac
