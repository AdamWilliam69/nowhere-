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
        *) warn "$(L 'Xray 模块暂不支持该架构:') $(uname -m)"; return 1 ;;
    esac
}

xray_require() {
    if [ ! -x "$XRAY_BIN" ]; then
        warn "$(L 'Xray 尚未安装，请先执行「1')) $(L '安装 Xray」（或 adam xray install）')"
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
    state_load "$XRAY_STATE_FILE" "XRAY_CHANNEL=prerelease XRAY_AUTO_UPDATE=0 XRAY_PUBLIC_HOST= XRAY_PIN_VERSION= XRAY_CN_BLOCK=1" XRAY_CHANNEL "prerelease stable pin"
    return 0
}

xray_save_state() {
    : "${XRAY_CN_BLOCK:=1}"
    state_save "$XRAY_STATE_FILE" "$XRAY_CONF_DIR" 750 XRAY_CHANNEL XRAY_AUTO_UPDATE XRAY_PUBLIC_HOST XRAY_PIN_VERSION XRAY_CN_BLOCK
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
    json="$(secure_curl -fsS --max-time 20 "https://api.github.com/repos/${XRAY_REPO}/releases?per_page=30" 2>/dev/null || true)"
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
        out="$(secure_curl -fsSL --max-time 20 "https://github.com/${XRAY_REPO}/releases.atom" 2>/dev/null \
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
        # flag="?" 来自 atom 兜底（GitHub API 被限流时取不到预发布标记）：stable 通道只跳过
        # 已知预发布（flag=1），未知标记的按最新发布继续并在下面警告，免得限流时 stable 全灭
        if [ "$channel" = "stable" ] && [ "$flag" = "1" ]; then continue; fi
        if [ -z "$XRAY_LATEST" ] || xray_ver_gt "$tag" "$XRAY_LATEST"; then
            XRAY_LATEST="$tag"; XRAY_LATEST_IS_PRE="$flag"
        fi
    done < <(xray_list_releases)
    if [ "$channel" = "stable" ] && [ -n "$XRAY_LATEST" ] && [ "$XRAY_LATEST_IS_PRE" = "?" ]; then
        warn "$(L 'GitHub API 被限流，取不到预发布标记；stable 通道暂按最新发布继续，请稍后确认是否为正式版')"
    fi
    return 0
}

# 下载 + SHA256 校验（官方 .dgst）+ 解压 + 试运行；成功后目录写入 XRAY_DL_DIR
xray_fetch() {
    local ver="$1" asset base want got gh_digest
    asset="$(xray_asset_name)" || return 1
    XRAY_DL_DIR=""
    make_workdir || return 1
    local wd="$WORKDIR"
    base="https://github.com/${XRAY_REPO}/releases/download/${ver}"
    # v8.6：全部经 secure_curl（仅 https + TLS ≥ 1.2，重定向也不允许降级到 http）
    if ! secure_curl -fL --retry 3 --connect-timeout 10 --max-time 300 -o "$wd/xray.zip" "${base}/${asset}"; then
        warn "$(L '下载失败:') ${base}/${asset}"
        return 1
    fi
    if ! secure_curl -fsSL --retry 2 --max-time 30 -o "$wd/xray.dgst" "${base}/${asset}.dgst"; then
        warn "$(L '未能下载官方校验文件') ${asset}$(L '.dgst，为安全起见中止')"
        return 1
    fi
    want="$(grep -iE '^SHA(2-)?256' "$wd/xray.dgst" | awk '{print tolower($NF)}' | head -n 1 || true)"
    got="$(sha256sum "$wd/xray.zip" | awk '{print $1}')"
    if [[ ! "$want" =~ ^[0-9a-f]{64}$ ]] || [ "$want" != "$got" ]; then
        warn "$(L 'SHA256 校验失败（官方') ${want:-$(L '未知')}$(L '，实际') ${got}$(L '），已中止')"
        return 1
    fi
    # v8.6：再与 GitHub 服务端计算的资产 digest 交叉核对（取不到时不阻断，.dgst 已强校验）
    gh_digest="$(github_asset_sha256 "$XRAY_REPO" "$ver" "$asset" 2>/dev/null || true)"
    if [ -n "$gh_digest" ] && [ "$gh_digest" != "$got" ]; then
        warn "$(L 'GitHub 资产 digest 与 .dgst 不一致，疑似被篡改，已中止')"
        return 1
    fi
    success "$(L 'SHA256 校验通过（官方 .dgst）')"
    unzip -tq "$wd/xray.zip" >/dev/null 2>&1 || { warn "$(L '压缩包损坏')"; return 1; }
    mkdir -p "$wd/x"
    unzip -oq "$wd/xray.zip" -d "$wd/x" || { warn "$(L '解压失败')"; return 1; }
    [ -f "$wd/x/xray" ] && [ ! -L "$wd/x/xray" ] || { warn "$(L '压缩包里没有 xray 二进制')"; return 1; }
    if ! verify_elf_binary "$wd/x/xray"; then
        warn "$(L '下载到的 xray 不是本机架构的 ELF 可执行文件，已中止')"
        return 1
    fi
    chmod 755 "$wd/x/xray"
    if ! timeout 10 "$wd/x/xray" version >/dev/null 2>&1; then
        warn "$(L '下载到的 xray 无法在本机运行（架构不符？）')"
        return 1
    fi
    XRAY_DL_DIR="$wd/x"
    return 0
}

xray_ensure_user() {
    ensure_system_user adam-xray || { warn "$(L '创建 adam-xray 系统用户失败')"; return 1; }
    return 0
}

# v8.6（BUG-11）：无论 adam-xray 组是否存在都强制收敛权限；chown 用 -h 不跟随符号链接
xray_fix_perms() {
    local grp="root"
    getent group adam-xray >/dev/null 2>&1 && grp="adam-xray"
    install -d -m 750 "$XRAY_CONF_DIR" "$XRAY_CONF_D" "$XRAY_CERT_DIR"
    install -d -m 700 "$XRAY_NODE_DIR"
    chmod 750 "$XRAY_CONF_DIR" "$XRAY_CONF_D" "$XRAY_CERT_DIR" 2>/dev/null || true
    chmod 700 "$XRAY_NODE_DIR" 2>/dev/null || true
    chown -h "root:${grp}" "$XRAY_CONF_DIR" "$XRAY_CONF_D" "$XRAY_CERT_DIR" 2>/dev/null || true
    chown -h root:root "$XRAY_NODE_DIR" 2>/dev/null || true
    find "$XRAY_CONF_D" -maxdepth 1 -type f -name '*.json' -exec chown -h "root:${grp}" {} + -exec chmod 640 {} + 2>/dev/null || true
    find "$XRAY_CERT_DIR" -mindepth 1 ! -type l -exec chown -h "root:${grp}" {} + 2>/dev/null || true
    find "$XRAY_CERT_DIR" -mindepth 1 -type d -exec chmod 750 {} + 2>/dev/null || true
    find "$XRAY_CERT_DIR" -mindepth 1 -type f -exec chmod 640 {} + 2>/dev/null || true
    find "$XRAY_NODE_DIR" -maxdepth 1 -type f -name '*.env' -exec chown -h root:root {} + -exec chmod 600 {} + 2>/dev/null || true
    if [ -d "$XRAY_FWD_DIR" ] && [ ! -L "$XRAY_FWD_DIR" ]; then
        chown -h root:root "$XRAY_FWD_DIR" 2>/dev/null || true
        chmod 700 "$XRAY_FWD_DIR" 2>/dev/null || true
        find "$XRAY_FWD_DIR" -maxdepth 1 -type f -name '*.env' -exec chown -h root:root {} + -exec chmod 600 {} + 2>/dev/null || true
    fi
    if [ -f "$XRAY_STATE_FILE" ] && [ ! -L "$XRAY_STATE_FILE" ]; then
        chown -h root:root "$XRAY_STATE_FILE" 2>/dev/null || true
        chmod 600 "$XRAY_STATE_FILE" 2>/dev/null || true
    fi
    if [ -d "$XRAY_DIR" ] && [ ! -L "$XRAY_DIR" ]; then
        chown -h root:root "$XRAY_DIR" 2>/dev/null || true
        chmod 755 "$XRAY_DIR" 2>/dev/null || true
        [ -f "$XRAY_BIN" ] && [ ! -L "$XRAY_BIN" ] && { chown -h root:root "$XRAY_BIN" 2>/dev/null || true; chmod 755 "$XRAY_BIN" 2>/dev/null || true; }
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

# 确保 geoip.dat / geosite.dat 在位（大陆拦截规则依赖它们）；缺失时从官方 release 下载
# v8.6（BUG-03）：v2fly/domain-list-community 的发布资产名是 dlc.dat（旧版拉 geosite.dat 必 404）；
# 每个文件都配合官方 .sha256sum 强校验，下载到独立临时目录，校验通过后原子替换，失败不留 .tmp 残片
xray_ensure_geo_data() {
    local missing=0 f url want got size wd tmp attempt ok
    for f in geoip.dat geosite.dat; do
        [ -s "$XRAY_DIR/$f" ] || missing=1
    done
    [ "$missing" = "0" ] && return 0
    install -d -m 755 "$XRAY_DIR"
    wd="$(mktemp -d "${TMPDIR:-/tmp}/adam-geo.XXXXXX" 2>/dev/null)" || { warn "$(L '无法创建临时目录')"; return 1; }
    for f in geoip.dat geosite.dat; do
        [ -s "$XRAY_DIR/$f" ] && continue
        case "$f" in
            geoip.dat) url="https://github.com/v2fly/geoip/releases/latest/download/geoip.dat" ;;
            geosite.dat) url="https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat" ;;
        esac
        tmp="${wd}/${f}"
        ok=0
        # latest 每天都可能发新版：数据与校验文件可能跨版本取到，校验不符时整体重试一次
        for attempt in 1 2; do
            rm -f "$tmp" "${tmp}.sha256sum"
            secure_curl -fsSL --retry 2 --connect-timeout 10 --max-time 120 -o "$tmp" "$url" 2>/dev/null || continue
            secure_curl -fsSL --retry 2 --connect-timeout 10 --max-time 30 -o "${tmp}.sha256sum" "${url}.sha256sum" 2>/dev/null || continue
            want="$(awk 'NR==1 {print tolower($1)}' "${tmp}.sha256sum" 2>/dev/null || true)"
            got="$(sha256sum "$tmp" 2>/dev/null | awk '{print $1}')"
            size="$(wc -c < "$tmp" 2>/dev/null || echo 0)"
            size=$((size + 0))
            if [[ "$want" =~ ^[0-9a-f]{64}$ ]] && [ "$want" = "$got" ] && [ "$size" -gt 10240 ]; then
                ok=1
                break
            fi
            [ "$attempt" = "1" ] && sleep 2
        done
        if [ "$ok" != "1" ]; then
            rm -rf "$wd"
            warn "$(L '下载 geo 数据失败或 SHA256 校验不通过：')${f}$(L '，大陆拦截暂不可用')"
            return 1
        fi
        if ! install -m 644 "$tmp" "$XRAY_DIR/.${f}.new" || ! mv -f "$XRAY_DIR/.${f}.new" "$XRAY_DIR/$f"; then
            rm -f "$XRAY_DIR/.${f}.new"
            rm -rf "$wd"
            warn "$(L '下载 geo 数据失败：')${f}$(L '，大陆拦截暂不可用')"
            return 1
        fi
    done
    rm -rf "$wd"
    rm -f "$XRAY_DIR/geoip.dat.tmp" "$XRAY_DIR/geosite.dat.tmp" 2>/dev/null || true
    success "$(L 'geo 数据已就位（官方 .sha256sum 校验通过）')"
    return 0
}

# 大陆流量拦截开关（geoip:cn / geosite:cn → block）：xray cnblock [on|off]，不带参数=切换
xray_cnblock() {
    xray_require || return 1
    local want="${1:-}"
    xray_load_state
    case "$want" in
        on) XRAY_CN_BLOCK="1" ;;
        off) XRAY_CN_BLOCK="0" ;;
        "") [ "${XRAY_CN_BLOCK:-1}" = "1" ] && XRAY_CN_BLOCK="0" || XRAY_CN_BLOCK="1" ;;
        *) warn "$(L '用法：xray cnblock on|off')"; return 1 ;;
    esac
    if [ "$XRAY_CN_BLOCK" = "1" ]; then
        if ! xray_ensure_geo_data; then
            warn "$(L 'geo 数据缺失，大陆拦截未开启')"
            XRAY_CN_BLOCK="0"
            xray_save_state
            xray_write_base
            return 1
        fi
    fi
    xray_save_state
    xray_write_base
    if xray_reload; then
        success "$(L '大陆流量拦截（geoip:cn / geosite:cn → 拦截）：')$([ "$XRAY_CN_BLOCK" = "1" ] && echo "$(L '开')" || echo "$(L '关')")"
    else
        warn "$(L '配置重载失败，拦截状态未生效，请查看日志')"
        return 1
    fi
    return 0
}

xray_write_base() {
    install -d -m 750 "$XRAY_CONF_D"
    local fwd_rule="" fwd_tags="" f fid fen cn_rules=""
    while IFS= read -r f; do
        fen="$(xray_fwd_env_get "$f" FWD_ENABLED)"
        [ "$fen" = "1" ] || continue
        fid="$(xray_fwd_env_get "$f" FWD_ID)"
        [ -n "$fid" ] || continue
        fwd_tags="${fwd_tags:+${fwd_tags}, }\"fwd-${fid}\""
    done < <(xray_fwd_rule_files)
    # 端口转发入站（dokodemo-door）最高优先级直连，避免转发到 VPC 内网 IP（geoip:private）或国内中转被黑洞拦截
    if [ -n "$fwd_tags" ]; then
        fwd_rule="      { \"type\": \"field\", \"inboundTag\": [${fwd_tags}], \"outboundTag\": \"direct\" },
"
    fi
    if [ "${XRAY_CN_BLOCK:-1}" = "1" ] && [ -f "${XRAY_DIR}/geoip.dat" ] && [ -f "${XRAY_DIR}/geosite.dat" ]; then
        cn_rules=",
      { \"type\": \"field\", \"ip\": [\"geoip:cn\"], \"outboundTag\": \"block\" },
      { \"type\": \"field\", \"domain\": [\"geosite:cn\"], \"outboundTag\": \"block\" }"
    fi
    cat > "${XRAY_CONF_D}/00-base.json" << XRBASE
{
  "log": { "loglevel": "warning" },
  "outbounds": [
    { "tag": "direct", "protocol": "freedom" },
    { "tag": "block", "protocol": "blackhole" }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
${fwd_rule}      { "type": "field", "ip": ["geoip:private"], "outboundTag": "block" }${cn_rules}
    ]
  }
}
XRBASE
}

xray_write_service() {
    write_service_unit "$XRAY_SERVICE" "Xray Service (managed by adam)" "https://github.com/${XRAY_REPO}" "0" "adam-xray" "adam-xray" "${XRAY_BIN} run -confdir ${XRAY_CONF_D}" "CAP_NET_BIND_SERVICE" "1048576" "always" "3" "Environment=XRAY_LOCATION_ASSET=${XRAY_DIR}
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
SyslogIdentifier=adam-xray"
}

# xray_test_conf [二进制路径]：校验整套配置
# shellcheck disable=SC2120
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
# v8.6：source 前先过 env_file_safe（拒绝 $ / ` / 未转义引号等可执行内容），并补齐 N_SIDS / N_SPX / N_FP / N_PQV / N_XPAD 默认值
# shellcheck disable=SC2034
xray_node_load() {
    N_TAG=""; N_TYPE=""; N_PORT=""; N_UUID=""; N_SNI=""; N_PBK=""; N_SID=""; N_PATH=""; N_ENC="none"
    N_DOMAIN=""; N_CPORT=""; N_CSEC=""; N_METHOD=""; N_PASS=""; N_NAME=""; N_CERT_SRC=""; N_KEY_SRC=""; N_ORIGIN=""
    N_SIDS=""; N_SPX=""; N_FP="chrome"; N_PQV=""; N_XPAD=""
    local f="${XRAY_NODE_DIR}/$1.env"
    [ -f "$f" ] && [ ! -L "$f" ] || return 1
    env_file_safe "$f" || return 1
    # shellcheck disable=SC1090
    source "$f" 2>/dev/null || return 1
    [ -n "$N_FP" ] || N_FP="chrome"
    return 0
}

# 全部节点的端口，每行一个 ufw 规格（SS 同时需要 UDP）
xray_ports() {
    local tag
    if [ -d "$XRAY_NODE_DIR" ]; then
        local -a _ntags=()
        while IFS= read -r tag; do [ -n "$tag" ] && _ntags+=("$tag"); done < <(xray_node_tags)
        for tag in "${_ntags[@]}"; do
            (
                xray_node_load "$tag" || exit 0
                [[ "$N_PORT" =~ ^[0-9]+$ ]] || exit 0
                echo "${N_PORT}/tcp"
                if [ "$N_TYPE" = "ss2022" ]; then echo "${N_PORT}/udp"; fi
            )
        done
    fi
    xray_fwd_ports
    return 0
}

xray_healthy() {
    local spec
    systemctl is-active --quiet adam-xray 2>/dev/null || return 1
    while IFS= read -r spec; do
        if [[ "$spec" == */tcp ]]; then
            tcp_listening "${spec%/tcp}" || return 1
        elif [[ "$spec" == */udp ]]; then
            udp_listening "${spec%/udp}" || return 1
        fi
    done < <(xray_ports)
    return 0
}

# 校验配置并（重）启动；没有节点且无转发规则时停止服务
xray_reload() {
    local out
    xray_fix_perms
    if [ "$(xray_node_count)" -eq 0 ] && [ "$(xray_fwd_enabled_count)" -eq 0 ]; then
        systemctl disable --now adam-xray >/dev/null 2>&1 || true
        info "$(L '当前没有节点与转发规则，Xray 服务已停止')"
        return 0
    fi
    if ! out="$(xray_test_conf)"; then
        warn "$(L '配置校验未通过：')"
        printf '%s\n' "$out" | tail -n 8
        return 1
    fi
    systemctl daemon-reload
    systemctl enable adam-xray >/dev/null 2>&1 || true
    systemctl restart adam-xray 2>/dev/null || true
    sleep 2
    if xray_healthy; then return 0; fi
    warn "$(L 'Xray 未能正常启动，最近日志：')"
    journalctl -u adam-xray -n 15 --no-pager 2>/dev/null || true
    return 1
}

xray_gen_uuid() {
    local u="" h v re='^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
    u="$("$XRAY_BIN" uuid 2>/dev/null | head -n 1 || true)"
    if [[ ! "$u" =~ $re ]]; then
        u="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || true)"
    fi
    # v8.6：再兜底用 CSPRNG 拼 RFC 4122 v4 UUID（容器/精简内核可能没有 /proc/sys/kernel/random/uuid）
    if [[ ! "$u" =~ $re ]]; then
        h="$(csprng_hex 16 2>/dev/null || true)"
        if [[ "$h" =~ ^[0-9a-f]{32}$ ]]; then
            v=$(( (16#${h:16:1} & 3) | 8 ))
            u="${h:0:8}-${h:8:4}-4${h:13:3}-$(printf '%x' "$v")${h:17:3}-${h:20:12}"
        fi
    fi
    printf '%s' "$u"
}

# 生成 REALITY 密钥对，写入 XK_PRIV / XK_PUB。兼容新旧两种输出：
#   新: "PrivateKey: ..." / "Password (PublicKey): ..."     旧: "Private key: ..." / "Public key: ..."
xray_gen_x25519() {
    local out re='^[A-Za-z0-9_-]{43}$'
    XK_PRIV=""; XK_PUB=""
    out="$("$XRAY_BIN" x25519 2>/dev/null || true)"
    XK_PRIV="$(printf '%s\n' "$out" | awk -F':[[:space:]]*' '{l=tolower($1); gsub(/[[:space:]]/,"",l); if (l=="privatekey") {v=$NF; gsub(/[[:space:]\r]+$/,"",v); print v; exit}}')"
    XK_PUB="$(printf '%s\n' "$out" | awk -F':[[:space:]]*' '{l=tolower($1); gsub(/[[:space:]]/,"",l); if (l=="publickey" || l=="password" || l=="password(publickey)") {v=$NF; gsub(/[[:space:]\r]+$/,"",v); print v; exit}}')"
    [[ "$XK_PRIV" =~ $re && "$XK_PUB" =~ $re ]]
}

# 生成 REALITY ML-DSA-65 后量子签名密钥对，写入 XM_SEED / XM_VERIFY；旧版 Xray 不支持 mldsa65 时静默返回 1
xray_gen_mldsa65() {
    local out re='^[A-Za-z0-9_-]{32,}$'
    XM_SEED=""; XM_VERIFY=""
    [ -x "$XRAY_BIN" ] || return 1
    out="$("$XRAY_BIN" mldsa65 2>/dev/null || true)"
    [ -n "$out" ] || return 1
    XM_SEED="$(printf '%s\n' "$out" | awk -F':[[:space:]]*' '{l=tolower($1); gsub(/[[:space:]]/,"",l); if (l=="seed") {v=$NF; gsub(/[[:space:]\r]+$/,"",v); print v; exit}}')"
    XM_VERIFY="$(printf '%s\n' "$out" | awk -F':[[:space:]]*' '{l=tolower($1); gsub(/[[:space:]]/,"",l); if (l=="verify") {v=$NF; gsub(/[[:space:]\r]+$/,"",v); print v; exit}}')"
    [[ "$XM_SEED" =~ $re && "$XM_VERIFY" =~ $re ]]
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

xray_listen_addr() { if ipv6_dualstack_ok; then printf '::'; else printf '0.0.0.0'; fi; }

# 询问端口：$1 默认值，结果写入 XP_PORT
# write_service_unit FILE DESC DOC STARTLIMIT USER GROUP EXEC CAPS NOFILE RESTART RESTARTSEC SVC_EXTRA：
# 五处 systemd unit 写出共用同一模板（原子写 mktemp+mv + 进程沙箱加固；M13 / v8.6）
write_service_unit() {
    local file="$1" desc="$2" doc="$3" startlimit="$4" user="$5" group="$6" execline="$7" caps="$8" nofile="$9" restart="${10}" restartsec="${11}" svc_extra="${12:-}" unit_extra="${13:-}"
    local tmp
    tmp="$(mktemp "$(dirname "$file")/.unit.XXXXXX")" || return 1
    {
        printf '[Unit]\nDescription=%s\n' "$desc"
        [ -n "$doc" ] && printf 'Documentation=%s\n' "$doc"
        printf 'After=network-online.target\nWants=network-online.target\n'
        [ -n "$startlimit" ] && printf 'StartLimitIntervalSec=%s\n' "$startlimit"
        [ -n "$unit_extra" ] && printf '%s\n' "$unit_extra"
        printf '\n[Service]\nType=simple\n'
        [ -n "$user" ] && printf 'User=%s\nGroup=%s\n' "$user" "$group"
        printf 'ExecStart=%s\n' "$execline"
        if [ -n "$caps" ]; then printf 'AmbientCapabilities=%s\nCapabilityBoundingSet=%s\n' "$caps" "$caps"; fi
        printf 'LimitNOFILE=%s\nRestart=%s\nRestartSec=%s\n' "$nofile" "$restart" "$restartsec"
        printf 'NoNewPrivileges=true\nPrivateDevices=true\nProtectKernelTunables=true\nProtectKernelModules=true\nProtectControlGroups=true\nRestrictNamespaces=true\nLockPersonality=true\nRestrictSUIDSGID=true\n'
        [ -n "$svc_extra" ] && printf '%s\n' "$svc_extra"
        printf '\n[Install]\nWantedBy=multi-user.target\n'
    } > "$tmp" || { rm -f "$tmp"; return 1; }
    mv -f "$tmp" "$file"
}

# ask_free_port DEFAULT [TAKEN_FN] [CONFLICT_FN] RESULT_VAR：问一个空闲端口；EOF 返回 1（M15）
ask_free_port() {
    local def="$1" taken_fn="${2:-}" conflict_fn="${3:-}" result_var="$4" p
    while true; do
        read -rp "$(L '监听端口（回车使用') ${def}$(L '）:') " p || { [ -n "$p" ] || return 1; }
        p="${p:-$def}"
        if [[ ! "$p" =~ ^[0-9]+$ ]] || [ "$((10#$p))" -lt 1 ] || [ "$((10#$p))" -gt 65535 ]; then
            warn "$(L '端口不合法（1-65535）')"
            continue
        fi
        p=$((10#$p))
        if [ -n "$taken_fn" ] && "$taken_fn" "$p"; then
            warn "$(L 'TCP 端口') ${p} $(L '已被占用，请换一个')"
            continue
        fi
        if [ -n "$conflict_fn" ] && "$conflict_fn" "$p"; then
            warn "$(L 'TCP 端口') ${p} $(L '已被占用，请换一个')"
            continue
        fi
        printf -v "$result_var" '%s' "$p"
        return 0
    done
}

# xray_port_conflict_any PORT：任一进程占用即冲突（供 ask_free_port 作 conflict_fn）
xray_port_conflict_any() { tcp_port_conflict "$1" "__none__"; }

# snell_port_taken_new PORT：snell_install 用，允许沿用旧主端口（SNELL_ASK_OLD_PORT）
snell_port_taken_new() { [ "$1" = "${SNELL_ASK_OLD_PORT:-}" ] && return 1; snell_port_taken "$1"; }

# xray_new_node_begin DEFAULT_PORT TAG_PREFIX NAME_PREFIX：问端口 + 生成 uuid/sid/listen/path/xpad/tag/name，结果写入 XN_*（M12）
# v8.6：REALITY 生成 2–3 条互不相同的变长 shortId（8–16 位偶数 hex，首条作分享链接主 sid）；
#       spiderX 与 XHTTP 路径均为拟真多段无扩展名 API 路径（CSPRNG），并生成随机 xPaddingBytes 抗包长指纹
xray_new_node_begin() {
    local def="$1" prefix="$2" name_prefix="$3" cnt i=0 tries=0 sid sids_str="" sids_json="" xp_lo xp_hi
    xray_ask_port "$(xray_default_port "$def")" || return 1
    XN_PORT="$XP_PORT"
    XN_UUID="$(xray_gen_uuid)"
    XN_LISTEN="$(xray_listen_addr)"
    cnt="$(csprng_int 2 3 2>/dev/null || echo 2)"
    while [ "$i" -lt "$cnt" ] && [ "$tries" -lt 20 ]; do
        tries=$((tries + 1))
        sid="$(csprng_short_id 2>/dev/null || true)"
        [[ "$sid" =~ ^([0-9a-f]{2}){4,8}$ ]] || continue
        case ",${sids_str}," in *",${sid},"*) continue ;; esac
        sids_str="${sids_str:+${sids_str},}${sid}"
        sids_json="${sids_json:+${sids_json}, }\"${sid}\""
        i=$((i + 1))
    done
    XN_SID="${sids_str%%,*}"
    XN_SIDS_STR="$sids_str"
    XN_SIDS_JSON="[${sids_json}]"
    XN_SPX="$(csprng_url_path 2>/dev/null || true)"
    XN_PATH="$(csprng_url_path 2>/dev/null || true)"
    xp_lo="$(csprng_int 100 350 2>/dev/null || echo 150)"
    xp_hi="$(csprng_int 600 1200 2>/dev/null || echo 900)"
    XN_XPAD="${xp_lo}-${xp_hi}"
    if [[ ! "$XN_UUID" =~ ^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$ ]] || [ "$i" -lt 2 ] \
        || [[ "$XN_PATH" != /* ]] || [ "${#XN_PATH}" -lt 8 ] || [[ "$XN_SPX" != /* ]]; then
        warn "$(L '生成随机密钥/UUID 失败，请检查 openssl 与 Xray 二进制')"
        return 1
    fi
    XN_TAG="${prefix}-${XN_PORT}"
    XN_NAME="${name_prefix}-${XN_PORT}"
    return 0
}

xray_ask_port() {
    ask_free_port "$1" xray_port_used xray_port_conflict_any XP_PORT
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
    if ! xray_port_used "$want" && ! tcp_port_conflict "$want" "__none__" && ! port_used_by_other_services "${want}/tcp" ""; then
        printf '%s' "$want"
    else
        random_free_port
    fi
}

# 询问 REALITY 伪装站点，结果写入 XR_SNI
# v8.6：
#   * 去掉 www.microsoft.com / www.apple.com 默认项：Xray-core 会对含 apple/icloud/microsoft 及 .cn/.ru/.ir 的
#     serverNames 打印“易被封 IP”警告，且这些站点在国内多有境内节点/被重点关注；
#   * 候选池为境外、非 Cloudflare、TLS 1.3 + HTTP/2 的大站，默认 CSPRNG 洗牌抽取 5 个并发/依次实测
#     （TLS 1.3 + ALPN h2 + 证书链校验通过），按握手 RTT 择优选择延迟最低的目标。
XRAY_SNI_POOL="www.amazon.com aws.amazon.com www.nvidia.com developer.nvidia.com www.intel.com www.cisco.com www.oracle.com www.mozilla.org www.logitech.com www.asus.com www.ibm.com www.dell.com"

# xray_probe_reality_target DOMAIN：0=本机可与其完成 TLS 1.3 + h2 且证书校验通过（写入 XR_RTT_MS）；1=不通过；2=无 openssl
xray_probe_reality_target() {
    local d="$1" out fam t0 t1
    local -a fam_args=()
    XR_RTT_MS=99999
    command -v openssl >/dev/null 2>&1 || return 2
    for fam in any 4; do
        if [ "$fam" = "4" ]; then fam_args=(-4); else fam_args=(); fi
        t0="$(date +%s%3N 2>/dev/null || echo 0)"
        out="$(timeout 8 openssl s_client "${fam_args[@]}" -connect "${d}:443" -servername "$d" -tls1_3 -alpn h2 < /dev/null 2>/dev/null || true)"
        t1="$(date +%s%3N 2>/dev/null || echo 0)"
        if [[ "$out" == *"TLSv1.3"* && "$out" == *"ALPN protocol: h2"* && "$out" == *"Verify return code: 0 (ok)"* ]]; then
            if [[ "$t0" =~ ^[0-9]+$ && "$t1" =~ ^[0-9]+$ ]] && [ "$t1" -ge "$t0" ]; then
                XR_RTT_MS=$((t1 - t0))
            else
                XR_RTT_MS=0
            fi
            return 0
        fi
    done
    return 1
}

xray_ask_sni() {
    local ans re='^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$' d i j tmp n rc best_rtt best_sni
    local -a pool=()
    read -r -a pool <<< "$XRAY_SNI_POOL"
    n="${#pool[@]}"
    echo "$(L 'REALITY 伪装站点（需是境外、支持 TLS 1.3 + HTTP/2 的站点；握手会转发到它的 443 端口）：')"
    echo "  1) $(L '从候选池随机抽取并实测择优（推荐，默认）')"
    echo "  2) $(L '从候选池手动选择')"
    echo "  3) $(L '自定义')"
    read -rp "$(L '选择') [$(L '1-3，默认1')]: " ans || { [ -n "$ans" ] || return 1; }
    case "${ans:-1}" in
        2)
            i=1
            for d in "${pool[@]}"; do
                printf '  %2d) %s\n' "$i" "$d"
                i=$((i + 1))
            done
            while true; do
                read -rp "$(L '选择') [1-${n}]: " ans || { [ -n "$ans" ] || return 1; }
                if [[ "$ans" =~ ^[0-9]+$ ]] && [ "$((10#$ans))" -ge 1 ] && [ "$((10#$ans))" -le "$n" ]; then
                    XR_SNI="${pool[$((10#$ans - 1))]}"
                    break
                fi
                warn "$(L '输入无效')"
            done
            ;;
        3)
            while true; do
                read -rp "$(L '输入域名（不带 https:// 和端口）:') " ans || { [ -n "$ans" ] || return 1; }
                ans="$(printf '%s' "$ans" | tr -d ' \r\n')"
                ans="${ans,,}"
                if [[ "$ans" == *.* && "$ans" =~ $re ]]; then
                    if [[ "$ans" =~ (apple|icloud|microsoft) ]] || [[ "$ans" =~ \.(cn|ru|ir)$ ]]; then
                        warn "$(L '该域名含 apple/icloud/microsoft 或属 .cn/.ru/.ir：Xray 会提示易被封 IP，不建议作 REALITY 伪装站点')"
                        confirm "$(L '仍要使用？')" n || continue
                    fi
                    XR_SNI="$ans"
                    break
                fi
                warn "$(L '域名格式不正确')"
            done
            ;;
        *)
            # CSPRNG Fisher-Yates 洗牌，实测最多 5 个并按握手 RTT 择优选择延迟最低的目标
            for ((i = n - 1; i > 0; i--)); do
                j="$(csprng_int 0 "$i" 2>/dev/null || echo "$i")"
                tmp="${pool[$i]}"; pool[$i]="${pool[$j]}"; pool[$j]="$tmp"
            done
            XR_SNI=""
            best_sni=""
            best_rtt=999999
            if command -v openssl >/dev/null 2>&1; then
                info "$(L '正在实测候选伪装站点（TLS 1.3 + HTTP/2 + 延迟择优）...')"
                for ((i = 0; i < n && i < 5; i++)); do
                    XR_RTT_MS=0
                    if xray_probe_reality_target "${pool[$i]}"; then
                        [[ "${XR_RTT_MS:-}" =~ ^[0-9]+$ ]] || XR_RTT_MS=99999
                        echo "  ${pool[$i]}: OK (${XR_RTT_MS}ms)"
                        if [ "$XR_RTT_MS" -lt "$best_rtt" ]; then
                            best_rtt="$XR_RTT_MS"
                            best_sni="${pool[$i]}"
                        fi
                    else
                        echo "  ${pool[$i]}: $(L '不通过，换下一个')"
                    fi
                done
                XR_SNI="$best_sni"
            fi
            if [ -n "$XR_SNI" ]; then
                success "$(L '已选定最低延迟伪装站点:') ${XR_SNI} (${best_rtt}ms, TLS 1.3 + HTTP/2)"
                return 0
            fi
            XR_SNI="${pool[0]}"
            warn "$(L '候选站点均未通过本机实测（可能是本机出网受限），暂用') ${XR_SNI}$(L '，如连不上请换一个站点')"
            return 0
            ;;
    esac
    # 尽力检查：从本机能否与该站点完成 TLS 1.3 + h2 握手（失败只提醒，不拦截）
    rc=0
    xray_probe_reality_target "$XR_SNI" || rc=$?
    if [ "$rc" = "0" ]; then
        success "${XR_SNI} $(L '支持 TLS 1.3 + HTTP/2，可用')"
    elif [ "$rc" = "1" ]; then
        warn "$(L '从本机未能确认') ${XR_SNI} $(L '支持 TLS 1.3 + HTTP/2（也可能只是本机到它的网络不通），如连不上请换一个站点')"
    fi
    return 0
}

# xray_pick_fp MODE（reality|tls）：选择客户端 uTLS 指纹（分享链接 fp=），结果写入 XR_FP
# v8.6：REALITY 服务端（Xray ≥ v26.9.8）拒绝过时/不带 X25519MLKEM768 混合密钥交换的 ClientHello，
#       edge / ios（以及旧 randomized）会被当成普通访客转发到伪装站（客户端报 received real certificate），
#       因此 REALITY 默认只在 chrome / firefox / safari 中加权随机；直连 TLS / CDN 节点不受此限。
xray_pick_fp() {
    local mode="${1:-tls}" ans r
    XR_FP="chrome"
    echo "$(L '客户端 uTLS 指纹（写入分享链接 fp=，模拟主流浏览器 ClientHello）：')"
    if [ "$mode" = "reality" ]; then
        echo "  1) $(L '按主流占比随机（chrome 60% / firefox 25% / safari 15%，默认）')"
    else
        echo "  1) $(L '按主流占比随机（chrome 45% / safari 20% / firefox 15% / edge 10% / ios 10%，默认）')"
    fi
    echo "  2) chrome   3) firefox   4) safari   5) edge   6) ios   7) randomized"
    read -rp "$(L '选择') [$(L '1-7，默认1')]: " ans || { [ -n "$ans" ] || return 1; }
    case "${ans:-1}" in
        2) XR_FP="chrome" ;;
        3) XR_FP="firefox" ;;
        4) XR_FP="safari" ;;
        5) XR_FP="edge" ;;
        6) XR_FP="ios" ;;
        7) XR_FP="randomized" ;;
        *)
            r="$(csprng_int 1 100 2>/dev/null || echo 1)"
            if [ "$mode" = "reality" ]; then
                if [ "$r" -le 60 ]; then XR_FP="chrome"; elif [ "$r" -le 85 ]; then XR_FP="firefox"; else XR_FP="safari"; fi
            else
                if [ "$r" -le 45 ]; then XR_FP="chrome"
                elif [ "$r" -le 65 ]; then XR_FP="safari"
                elif [ "$r" -le 80 ]; then XR_FP="firefox"
                elif [ "$r" -le 90 ]; then XR_FP="edge"
                else XR_FP="ios"; fi
            fi
            ;;
    esac
    if [ "$mode" = "reality" ]; then
        case "$XR_FP" in
            edge|ios)
                warn "$(L 'Xray ≥ v26.9.8 的 REALITY 服务端会拒绝不带 X25519MLKEM768 的 ClientHello，') ${XR_FP} $(L '指纹必然握手失败')"
                confirm "$(L '仍要使用该指纹？（否则改用 chrome）')" n || XR_FP="chrome"
                ;;
            randomized)
                warn "$(L 'randomized 需较新的 Xray 客户端（只从带 X25519MLKEM768 的指纹中随机），旧客户端可能偶发握手失败')"
                ;;
        esac
        [ "$XR_FP" = "chrome" ] || info "$(L '提示：Mihomo / Clash Meta 客户端连 REALITY 只有 chrome 指纹可用，用这类客户端请改 fp=chrome')"
    fi
    info "$(L '已选 uTLS 指纹:') ${XR_FP}"
    return 0
}

# 询问是否叠加 VLESS Encryption，结果写入 VE_DEC / VE_ENC（不叠加时为 none）
xray_ask_vlessenc() {
    local def="$1" ans
    VE_DEC="none"; VE_ENC="none"
    if [ "$def" != "force" ]; then
        confirm "$(L '叠加 VLESS Encryption（抗量子密钥交换的应用层加密；客户端需较新的 Xray 内核）？')" n || return 0
    fi
    echo "  $(L '认证方式：1')) $(L 'ML-KEM-768（抗量子，默认）  2')) $(L 'X25519（密钥更短）')"
    read -rp "  $(L '选择') [$(L '1/2，默认1')]: " ans || { [ -n "$ans" ] || return 1; }
    if [ "${ans:-1}" = "2" ]; then ans="x25519"; else ans="pq"; fi
    if ! xray_gen_vlessenc "$ans"; then
        warn "$(L 'xray vlessenc 生成失败（当前内核版本可能不支持 VLESS Encryption）')"
        VE_DEC="none"; VE_ENC="none"
        return 1
    fi
    return 0
}

# 写节点配置 + 元数据，校验并重启；失败则撤回。参数：tag、入站 JSON（不含外层）、元数据文本
xray_commit_node() {
    local tag="$1" inbound="$2" meta="$3"
    local conf="${XRAY_CONF_D}/10-in-${tag}.json" env="${XRAY_NODE_DIR}/${tag}.env"
    install -d -m 750 "$XRAY_CONF_D"
    install -d -m 700 "$XRAY_NODE_DIR"
    local _xc_tmp_conf="" _xc_tmp_env=""
    _xc_tmp_conf="$(mktemp "${XRAY_CONF_D}/.10-in-${tag}.XXXXXX")" || return 1
    _xc_tmp_env="$(mktemp "${XRAY_NODE_DIR}/.env.XXXXXX")" || { rm -f "$_xc_tmp_conf"; return 1; }
    printf '{\n  "inbounds": [\n%s\n  ]\n}\n' "$inbound" > "$_xc_tmp_conf" || { rm -f "$_xc_tmp_conf" "$_xc_tmp_env"; return 1; }
    printf '%s\n' "$meta" > "$_xc_tmp_env" || { rm -f "$_xc_tmp_conf" "$_xc_tmp_env"; return 1; }
    chmod 600 "$_xc_tmp_env"
    mv -f "$_xc_tmp_conf" "$conf" || { rm -f "$_xc_tmp_conf" "$_xc_tmp_env"; return 1; }
    mv -f "$_xc_tmp_env" "$env" || { rm -f "$_xc_tmp_conf" "$_xc_tmp_env"; return 1; }
    chmod 600 "$env"
    if xray_reload; then return 0; fi
    warn "$(L '新节点未能生效，已撤回本次改动')"
    rm -f "$conf" "$env"
    case "$tag" in
        ''|*[!A-Za-z0-9._-]*) warn "$(L '节点 tag 不合法，已跳过证书目录清理')" ;;
        *) rm -rf "${XRAY_CERT_DIR:?}/${tag}" ;;
    esac
    xray_reload >/dev/null 2>&1 || true
    return 1
}

XRAY_SNIFF='"sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": true }'

xray_add_vision() {
    local port uuid sid tag listen name pq_json="" pqv=""
    xray_new_node_begin 443 vision VLESS-Vision || return 1
    port="$XN_PORT"; uuid="$XN_UUID"; sid="$XN_SID"; listen="$XN_LISTEN"; tag="$XN_TAG"; name="$XN_NAME"
    xray_ask_sni || return 1
    xray_pick_fp reality || return 1
    xray_gen_x25519 || { warn "$(L 'REALITY 密钥生成失败')"; return 1; }
    if xray_gen_mldsa65; then
        pq_json=", \"mldsa65Seed\": \"${XM_SEED}\""
        pqv="$XM_VERIFY"
    fi
    # v8.6：多条变长 shortIds + maxTimeDiff 60s（拒绝时钟偏差过大的重放握手）+ 可选 ML-DSA-65 后量子签名
    xray_commit_node "$tag" "    {
      \"tag\": \"${tag}\", \"listen\": \"${listen}\", \"port\": ${port}, \"protocol\": \"vless\",
      \"settings\": { \"clients\": [ { \"id\": \"${uuid}\", \"flow\": \"xtls-rprx-vision\" } ], \"decryption\": \"none\" },
      \"streamSettings\": {
        \"network\": \"tcp\", \"security\": \"reality\",
        \"realitySettings\": { \"show\": false, \"target\": \"${XR_SNI}:443\", \"xver\": 0, \"serverNames\": $(xray_reality_snis_json "${XR_SNI}"), \"privateKey\": \"${XK_PRIV}\", \"shortIds\": ${XN_SIDS_JSON}, \"maxTimeDiff\": 60000${pq_json} }
      },
      ${XRAY_SNIFF}
    }" "N_TAG=\"${tag}\"
N_TYPE=\"vision\"
N_PORT=\"${port}\"
N_UUID=\"${uuid}\"
N_SNI=\"${XR_SNI}\"
N_PBK=\"${XK_PUB}\"
N_SID=\"${sid}\"
N_SIDS=\"${XN_SIDS_STR}\"
N_SPX=\"${XN_SPX}\"
N_FP=\"${XR_FP}\"
N_PQV=\"${pqv}\"
N_NAME=\"${name}\"" || return 1
    XRAY_NEW_TAG="$tag"
    local _ntp_rc=0
    check_ntp_sync || _ntp_rc=$?
    if [ "$_ntp_rc" = "1" ]; then
        warn "$(L '检测到系统时钟未 NTP 同步！REALITY maxTimeDiff 仅容忍 ±60 秒偏差，建议运行 timedatectl set-ntp true 或 adam xray repair')"
    fi
}

xray_add_xhttp_reality() {
    local port uuid sid tag listen name path xpad pq_json="" pqv=""
    xray_new_node_begin 8443 xhttp-reality VLESS-XHTTP-REALITY || return 1
    port="$XN_PORT"; uuid="$XN_UUID"; sid="$XN_SID"; listen="$XN_LISTEN"; path="$XN_PATH"; xpad="$XN_XPAD"; tag="$XN_TAG"; name="$XN_NAME"
    xray_ask_sni || return 1
    xray_pick_fp reality || return 1
    xray_gen_x25519 || { warn "$(L 'REALITY 密钥生成失败')"; return 1; }
    if xray_gen_mldsa65; then
        pq_json=", \"mldsa65Seed\": \"${XM_SEED}\""
        pqv="$XM_VERIFY"
    fi
    # v8.6：用户选择叠加 VLESS Encryption 但生成失败时中止，不再静默降级为 none
    xray_ask_vlessenc ask || return 1
    xray_commit_node "$tag" "    {
      \"tag\": \"${tag}\", \"listen\": \"${listen}\", \"port\": ${port}, \"protocol\": \"vless\",
      \"settings\": { \"clients\": [ { \"id\": \"${uuid}\" } ], \"decryption\": \"${VE_DEC}\" },
      \"streamSettings\": {
        \"network\": \"xhttp\", \"security\": \"reality\",
        \"xhttpSettings\": { \"path\": \"${path}\", \"mode\": \"auto\", \"extra\": { \"xPaddingBytes\": \"${xpad}\" } },
        \"realitySettings\": { \"show\": false, \"target\": \"${XR_SNI}:443\", \"xver\": 0, \"serverNames\": $(xray_reality_snis_json "${XR_SNI}"), \"privateKey\": \"${XK_PRIV}\", \"shortIds\": ${XN_SIDS_JSON}, \"maxTimeDiff\": 60000${pq_json} }
      },
      ${XRAY_SNIFF}
    }" "N_TAG=\"${tag}\"
N_TYPE=\"xhttp-reality\"
N_PORT=\"${port}\"
N_UUID=\"${uuid}\"
N_SNI=\"${XR_SNI}\"
N_PBK=\"${XK_PUB}\"
N_SID=\"${sid}\"
N_SIDS=\"${XN_SIDS_STR}\"
N_SPX=\"${XN_SPX}\"
N_FP=\"${XR_FP}\"
N_PQV=\"${pqv}\"
N_PATH=\"${path}\"
N_XPAD=\"${xpad}\"
N_ENC=\"${VE_ENC}\"
N_NAME=\"${name}\"" || return 1
    XRAY_NEW_TAG="$tag"
    local _ntp_rc=0
    check_ntp_sync || _ntp_rc=$?
    if [ "$_ntp_rc" = "1" ]; then
        warn "$(L '检测到系统时钟未 NTP 同步！REALITY maxTimeDiff 仅容忍 ±60 秒偏差，建议运行 timedatectl set-ntp true 或 adam xray repair')"
    fi
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
# v8.6：CDN TLS 回源自签证书（有效期 365–730 天随机）缺失或剩余 < 30 天时自动轮换
xray_sync_certs() {
    local tag changed=0
    local -a _ntags=()
    while IFS= read -r tag; do [ -n "$tag" ] && _ntags+=("$tag"); done < <(xray_node_tags)
    for tag in "${_ntags[@]}"; do
        (
            xray_node_load "$tag" || exit 1
            if [ -z "$N_CERT_SRC" ]; then
                [ "$N_TYPE" = "xhttp-cdn" ] && [ "${N_ORIGIN:-tls}" != "plain" ] && [ -n "$N_DOMAIN" ] || exit 1
                _days=""
                [ -s "${XRAY_CERT_DIR}/${tag}/fullchain.pem" ] && _days="$(cert_expiry_days "${XRAY_CERT_DIR}/${tag}/fullchain.pem" 2>/dev/null || true)"
                if [[ "$_days" =~ ^-?[0-9]+$ ]] && [ "$_days" -ge 30 ] && [ -s "${XRAY_CERT_DIR}/${tag}/privkey.pem" ]; then exit 1; fi
                xray_gen_self_signed_cert "$N_DOMAIN" "${XRAY_CERT_DIR}/${tag}" || { warn "[Xray] $(L '自签证书生成失败'): $tag"; exit 1; }
                maint_log "[Xray] $(L '自签回源证书已轮换'): $tag"
                exit 0
            fi
            [ -f "$N_CERT_SRC" ] && [ -f "$N_KEY_SRC" ] || exit 1
            cmp -s "$N_CERT_SRC" "${XRAY_CERT_DIR}/${tag}/fullchain.pem" && cmp -s "$N_KEY_SRC" "${XRAY_CERT_DIR}/${tag}/privkey.pem" && exit 1
            xray_install_cert "$tag" "$N_CERT_SRC" "$N_KEY_SRC" || { warn "[Xray] $(L '证书同步失败'): $tag"; exit 1; }
        ) && changed=1
    done
    if [ "$changed" = "1" ]; then
        xray_fix_perms
        systemctl restart adam-xray >/dev/null 2>&1 || true
        maint_log "[Xray] $(L '检测到证书已续期，已同步并重启')"
    fi
    return 0
}

# certbot 自动续期只负责“续签”，新证书的同步与重启由每日维护的 xray_sync_certs 负责
xray_ensure_certbot_timer() {
    if systemctl list-unit-files certbot.timer 2>/dev/null | awk '/^certbot\.timer/{f=1} END{exit !f}'; then
        systemctl enable --now certbot.timer 2>/dev/null || warn "$(L 'certbot.timer 启用失败，自动续期可能不工作')"
        return 0
    fi
    # 共用 certbot_renewal_cron_ensure：deploy hook 文件不在位时保留 Portal 的 deploy-hook cron 行（v10 保护）
    certbot_renewal_cron_ensure 2>/dev/null || true
    return 0
}

# 为域名申请/复用证书并复制到节点证书目录；成功时设置 XRAY_OBT_CRT/XRAY_OBT_KEY（源路径）
xray_obtain_cert() {
    local domain="$1" tag="$2" email="$3"
    local le_crt="/etc/letsencrypt/live/${domain}/fullchain.pem"
    local le_key="/etc/letsencrypt/live/${domain}/privkey.pem"
    local ans src_crt="" src_key="" occ80=""
    if cert_is_valid "$domain" "$le_crt" "$le_key"; then
        info "$(L '检测到该域名已有有效证书，直接复用')"
        xray_install_cert "$tag" "$le_crt" "$le_key" || { warn "$(L '证书复制失败')"; return 1; }
        XRAY_OBT_CRT="$le_crt"; XRAY_OBT_KEY="$le_key"
        xray_ensure_certbot_timer
        return 0
    fi
    while true; do
        echo "$(L '证书申请方式：')"
        echo "  1) $(L 'HTTP-01（域名解析到本机 + 开放 80 端口，自动续期）')"
        echo "  2) $(L 'Cloudflare DNS-01（需要 CF API Key/Token，自动续期，80 端口可不开）')"
        echo "  3) $(L '已有证书文件（fullchain.pem + privkey.pem）')"
        echo "  0) $(L '取消')"
        read -rp "$(L '选择') [$(L '1/2/3，默认1')]: " ans || return 1
        case "${ans:-1}" in
            0|q) return 1 ;;
            3)
                check_domain_dns "$domain" || true
                read -rp "$(L '证书文件路径（fullchain.pem）:') " src_crt || return 1
                read -rp "$(L '私钥文件路径（privkey.pem）:') " src_key || return 1
                if [ ! -f "$src_crt" ] || [ ! -f "$src_key" ]; then
                    warn "$(L '证书或私钥文件不存在')"
                    confirm "$(L '证书获取失败，是否重试或更换证书方式？')" y && continue || return 1
                fi
                if ! cert_covers_domain "$src_crt" "$domain"; then
                    warn "$(L '该证书的域名列表里没有') ${domain}"
                    confirm "$(L '仍要使用？')" n || { confirm "$(L '证书获取失败，是否重试或更换证书方式？')" y && continue || return 1; }
                fi
                xray_install_cert "$tag" "$src_crt" "$src_key" || { warn "$(L '证书复制失败')"; return 1; }
                XRAY_OBT_CRT="$src_crt"; XRAY_OBT_KEY="$src_key"
                return 0
                ;;
            2)
                check_domain_dns "$domain" || true
                apt_install certbot || { warn "$(L 'certbot 安装失败')"; return 1; }
                apt_install python3-certbot-dns-cloudflare || { warn "$(L 'certbot Cloudflare 插件安装失败')"; return 1; }
                if [ -s /etc/cloudflare/credentials.ini ] && confirm "$(L '检测到已有 Cloudflare 凭证文件（/etc/cloudflare/credentials.ini），是否直接复用？')" y; then
                    :
                else
                    prompt_cloudflare_creds || { confirm "$(L '证书获取失败，是否重试或更换证书方式？')" y && continue || return 1; }
                    write_cloudflare_creds
                fi
                info "$(L '证书申请中（Cloudflare DNS-01，约需 30-60 秒）...')"
                if certbot certonly --dns-cloudflare --dns-cloudflare-credentials /etc/cloudflare/credentials.ini \
                    --non-interactive --agree-tos --email "$email" -d "$domain" \
                    --dns-cloudflare-propagation-seconds 30 \
                    && verify_issued_cert "$domain" "$le_crt" "$le_key"; then
                    success "$(L '证书申请成功')"
                    xray_ensure_certbot_timer
                    xray_install_cert "$tag" "$le_crt" "$le_key" || { warn "$(L '证书复制失败')"; return 1; }
                    XRAY_OBT_CRT="$le_crt"; XRAY_OBT_KEY="$le_key"
                    return 0
                fi
                warn "$(L '证书申请失败：检查 CF 凭证与域名归属')"
                confirm "$(L '证书获取失败，是否重试或更换证书方式？')" y && continue || return 1
                ;;
            *)
                if ! check_domain_dns "$domain"; then
                    confirm "$(L '域名解析未通过，HTTP-01 很可能失败，仍要继续申请？')" n || continue
                fi
                occ80="$(check_port_occupied_by_other tcp 80 __none__ || true)"
                if [ -n "$occ80" ]; then
                    warn "$(L '当前 80 端口已被占用，HTTP-01 签发可能失败：')"
                    echo "$occ80"
                    confirm "$(L '仍要继续？')" n || continue
                fi
                apt_install certbot || { warn "$(L 'certbot 安装失败')"; return 1; }
                info "$(L '证书申请中（HTTP-01，需 80 端口）...')"
                ufw allow 80/tcp 2>/dev/null || true
                if certbot certonly --standalone --preferred-challenges http --non-interactive \
                    --agree-tos --email "$email" -d "$domain" \
                    --http-01-port 80 --http-01-address 0.0.0.0 \
                    && verify_issued_cert "$domain" "$le_crt" "$le_key"; then
                    success "$(L '证书申请成功')"
                    xray_ensure_certbot_timer
                    xray_install_cert "$tag" "$le_crt" "$le_key" || { warn "$(L '证书复制失败')"; return 1; }
                    XRAY_OBT_CRT="$le_crt"; XRAY_OBT_KEY="$le_key"
                    return 0
                fi
                warn "$(L '证书申请失败：检查域名解析与 80 端口')"
                confirm "$(L '证书获取失败，是否重试或更换证书方式？')" y && continue || return 1
                ;;
        esac
    done
}

# VLESS + XHTTP + TLS（直连域名证书）：TLS 只验证 SNI=域名，server 地址用域名或本机 IP 均可
xray_add_xhttp_tls() {
    local port uuid tag listen name path xpad domain email re='^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$'
    echo "$(L '直连域名证书节点：客户端连域名或本机 IP 均可（SNI 始终为域名，证书只验证域名）')"
    while true; do
        read -rp "$(L '域名（须已解析到本机，证书将签发给它）:') " domain || { [ -n "$domain" ] || return 1; }
        domain="$(printf '%s' "$domain" | tr -d ' \r\n')"
        domain="${domain,,}"
        if [[ "$domain" == *.* && "$domain" =~ $re ]] && is_safe_host "$domain"; then break; fi
        warn "$(L '域名格式不正确')"
    done
    while true; do
        read -rp "$(L 'ACME 邮箱（证书账户用）:') " email || { [ -n "$email" ] || return 1; }
        email="$(printf '%s' "$email" | tr -d ' \r\n')"
        [ -n "$email" ] && break
        warn "$(L '邮箱不能为空')"
    done
    xray_new_node_begin 443 xhttp-tls VLESS-XHTTP-TLS || return 1
    port="$XN_PORT"; uuid="$XN_UUID"; listen="$XN_LISTEN"; path="$XN_PATH"; xpad="$XN_XPAD"; tag="$XN_TAG"; name="$XN_NAME"
    # v8.6：直连 TLS 节点同样随机化客户端 uTLS 指纹（非 REALITY，可用 edge/ios）
    xray_pick_fp tls || return 1
    local fp="$XR_FP"
    # v8.6：用户选择叠加 VLESS Encryption 但生成失败时中止，不再静默降级为 none
    xray_ask_vlessenc ask || return 1
    XRAY_OBT_CRT=""; XRAY_OBT_KEY=""
    xray_obtain_cert "$domain" "$tag" "$email" || return 1
    local crt="${XRAY_CERT_DIR}/${tag}/fullchain.pem" key="${XRAY_CERT_DIR}/${tag}/privkey.pem"
    local esc_crt esc_key
    esc_crt="$(dq_escape "$XRAY_OBT_CRT")"; esc_key="$(dq_escape "$XRAY_OBT_KEY")"
    xray_commit_node "$tag" "    {
      \"tag\": \"${tag}\", \"listen\": \"${listen}\", \"port\": ${port}, \"protocol\": \"vless\",
      \"settings\": { \"clients\": [ { \"id\": \"${uuid}\" } ], \"decryption\": \"${VE_DEC}\" },
      \"streamSettings\": {
        \"network\": \"xhttp\", \"security\": \"tls\",
        \"tlsSettings\": { \"serverName\": \"${domain}\", \"alpn\": [\"h2\", \"http/1.1\"], \"certificates\": [ { \"certificateFile\": \"${crt}\", \"keyFile\": \"${key}\" } ] },
        \"xhttpSettings\": { \"path\": \"${path}\", \"mode\": \"auto\", \"extra\": { \"xPaddingBytes\": \"${xpad}\" } }
      },
      ${XRAY_SNIFF}
    }" "N_TAG=\"${tag}\"
N_TYPE=\"xhttp-tls\"
N_PORT=\"${port}\"
N_UUID=\"${uuid}\"
N_DOMAIN=\"${domain}\"
N_PATH=\"${path}\"
N_XPAD=\"${xpad}\"
N_ENC=\"${VE_ENC}\"
N_CERT_SRC=\"${esc_crt}\"
N_KEY_SRC=\"${esc_key}\"
N_FP=\"${fp}\"
N_NAME=\"${name}\"" || return 1
    XRAY_NEW_TAG="$tag"
    info "$(L '同一节点两种连法：域名或本机 IP（SNI 始终为域名），用 Xray 菜单 13 切换分享链接地址')"
}

# 当前分享链接地址是域名时输出它（IP 则输出空）
xray_host_domain() {
    local h="${XRAY_PUBLIC_HOST:-}"
    if [ -z "$h" ]; then
        xray_load_state
        h="${XRAY_PUBLIC_HOST:-}"
    fi
    if [ -z "$h" ]; then h="$(detect_public_host || true)"; fi
    if [[ "$h" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ "$h" == *:* ]]; then return 1; fi
    if [[ "$h" == *.* && "$h" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]; then printf '%s' "$h"; return 0; fi
    return 1
}

# REALITY serverNames：伪装站点 + 当前域名地址（若是域名；域名作 server 地址时客户端握手用的 SNI 就是它）
xray_reality_snis_json() {
    local sni="$1" dom
    dom="$(xray_host_domain || true)"
    if [ -n "$dom" ] && [ "$dom" != "$sni" ]; then
        printf '["%s", "%s"]' "$sni" "$dom"
    else
        printf '["%s"]' "$sni"
    fi
}

# 把全部 REALITY 节点的 serverNames 同步为 [伪装站点, 当前域名地址?]；原子写 + 失败自动回滚
xray_sync_reality_snis() {
    local tag conf rc changed=0 dom bak_dir=""
    xray_load_state
    dom="$(xray_host_domain || true)"
    command -v python3 >/dev/null 2>&1 || { warn "$(L '未找到 python3，无法同步 REALITY 域名')"; return 1; }
    local -a _ntags=() _baks=()
    while IFS= read -r tag; do [ -n "$tag" ] && _ntags+=("$tag"); done < <(xray_node_tags)
    for tag in "${_ntags[@]}"; do
        xray_node_load "$tag" || continue
        case "$N_TYPE" in vision|xhttp-reality) ;; *) continue ;; esac
        conf="${XRAY_CONF_D}/10-in-${tag}.json"
        [ -f "$conf" ] || continue
        if [ -z "$bak_dir" ]; then
            bak_dir="$(mktemp -d /tmp/adam-xray-sni.XXXXXX 2>/dev/null || true)"
        fi
        [ -n "$bak_dir" ] && cp -a "$conf" "${bak_dir}/$(basename "$conf")" 2>/dev/null && _baks+=("$conf")
        rc=0
        python3 - "$conf" "$N_SNI" "$dom" <<'PYEOF' || rc=$?
import json, os, sys, tempfile
conf, sni, dom = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(conf, "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception as e:
    print("json load failed: %s" % e, file=sys.stderr)
    sys.exit(1)
snis = [sni]
if dom and dom != sni:
    snis.append(dom)
changed = False
for ib in data.get("inbounds", []):
    rs = ib.get("streamSettings", {}).get("realitySettings")
    if rs is not None and rs.get("serverNames") != snis:
        rs["serverNames"] = snis
        changed = True
if not changed:
    sys.exit(0)
dname = os.path.dirname(conf) or "."
fd, tpath = tempfile.mkstemp(prefix=".sni-", dir=dname)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as tf:
        json.dump(data, tf, indent=2)
        tf.write("\n")
    os.chmod(tpath, 0o640)
    os.replace(tpath, conf)
except Exception as e:
    try:
        os.unlink(tpath)
    except OSError:
        pass
    print("json write failed: %s" % e, file=sys.stderr)
    sys.exit(1)
sys.exit(2)
PYEOF
        case "$rc" in
            2) changed=1 ;;
            0) : ;;
            *) warn "$(L '同步 REALITY 域名失败：')${tag}" ;;
        esac
    done
    if [ "$changed" = "1" ]; then
        xray_fix_perms
        if ! xray_reload; then
            if [ -n "$bak_dir" ]; then
                for conf in "${_baks[@]}"; do
                    [ -f "${bak_dir}/$(basename "$conf")" ] && cp -a "${bak_dir}/$(basename "$conf")" "$conf" 2>/dev/null || true
                done
                xray_fix_perms
                xray_reload >/dev/null 2>&1 || true
                rm -rf "$bak_dir"
            fi
            return 1
        fi
        info "$(L '已同步 REALITY serverNames（域名地址可用）')"
    fi
    [ -n "$bak_dir" ] && rm -rf "$bak_dir"
    return 0
}

# 生成抗指纹 CDN 回源 ECDSA P-256 自签证书：RFC 5280 正整数 16 字节随机序列号 + 365~730 天随机有效期
xray_gen_self_signed_cert() {
    local domain="$1" dir="$2" days first_nibble rest_hex serial
    install -d -m 750 "$dir"
    days="$(csprng_int 365 730)"
    first_nibble="$(csprng_int 1 7)"
    rest_hex="$(csprng_hex 16)"
    rest_hex="${rest_hex:1:31}"
    serial="0x${first_nibble}${rest_hex}"
    (
        umask 077
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
            -days "$days" -set_serial "$serial" -sha256 \
            -subj "/CN=${domain}" -addext "subjectAltName=DNS:${domain}" \
            -keyout "${dir}/privkey.pem.tmp" -out "${dir}/fullchain.pem.tmp" >/dev/null 2>&1
    ) || { rm -f "${dir}/privkey.pem.tmp" "${dir}/fullchain.pem.tmp"; return 1; }
    chmod 640 "${dir}/privkey.pem.tmp" "${dir}/fullchain.pem.tmp" 2>/dev/null || true
    mv -f "${dir}/privkey.pem.tmp" "${dir}/privkey.pem"
    mv -f "${dir}/fullchain.pem.tmp" "${dir}/fullchain.pem"
    return 0
}

xray_add_xhttp_cdn() {
    local port uuid tag listen name path xpad domain ans origin="tls" crt="" key="" src_crt="" src_key="" cport="443" tls_block="" fp="chrome"
    local re='^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$' dir
    echo "$(L '本节点用于套 CDN（如 Cloudflare）：客户端连 CDN 的域名，CDN 再回源到本机。')"
    while true; do
        read -rp "$(L '已接入 CDN 的域名（如 cdn.example.com）:') " domain || { [ -n "$domain" ] || return 1; }
        domain="$(printf '%s' "$domain" | tr -d ' \r\n')"
        domain="${domain,,}"
        if [[ "$domain" == *.* && "$domain" =~ $re ]]; then break; fi
        warn "$(L '域名格式不正确')"
    done
    echo "$(L 'CDN 回源方式：')"
    echo "  1) $(L 'TLS 回源 + 自签证书（默认；Cloudflare 的 SSL/TLS 模式选「完全 Full」，不是「完全')($(L '严格'))$(L '」）')"
    echo "  2) $(L 'TLS 回源 + 已有证书文件（「完全')($(L '严格'))$(L '」可用；证书续期后每日维护会自动同步）')"
    echo "  3) $(L '明文 HTTP 回源（Cloudflare 选「灵活 Flexible」；回源端口须是 80/8080/8880/2052/2082/2086/2095 之一）')"
    read -rp "$(L '选择') [$(L '1/2/3，默认1')]: " ans || { [ -n "$ans" ] || return 1; }
    case "${ans:-1}" in
        2)
            read -rp "$(L '证书文件路径（fullchain.pem）:') " src_crt || { [ -n "$src_crt" ] || return 1; }
            read -rp "$(L '私钥文件路径（privkey.pem）:') " src_key || { [ -n "$src_key" ] || return 1; }
            if [ ! -f "$src_crt" ] || [ ! -f "$src_key" ]; then warn "$(L '证书或私钥文件不存在')"; return 1; fi
            if ! cert_covers_domain "$src_crt" "$domain"; then
                warn "$(L '该证书的域名列表里没有') ${domain}"
                confirm "$(L '仍要使用？')" n || return 1
            fi
            ;;
        3) origin="plain" ;;
        *) : ;;
    esac
    if [ "$origin" = "plain" ]; then
        xray_new_node_begin 8080 xhttp-cdn VLESS-XHTTP-CDN || return 1
    else
        echo "  $(L '提示：Cloudflare 回源 HTTPS 只支持 443/2053/2083/2087/2096/8443 这几个端口')"
        xray_new_node_begin 2053 xhttp-cdn VLESS-XHTTP-CDN || return 1
    fi
    port="$XN_PORT"; uuid="$XN_UUID"; listen="$XN_LISTEN"; path="$XN_PATH"; xpad="$XN_XPAD"; tag="$XN_TAG"; name="$XN_NAME"
    read -rp "$(L '客户端连接 CDN 的端口（回车默认 443）:') " ans || { [ -n "$ans" ] || return 1; }
    if [[ "${ans:-443}" =~ ^[0-9]+$ ]] && [ "$((10#${ans:-443}))" -ge 1 ] && [ "$((10#${ans:-443}))" -le 65535 ]; then
        cport="${ans:-443}"
    else
        warn "$(L '端口不合法（1-65535），已用默认 443')"
    fi
    xray_pick_fp tls || return 1
    fp="$XR_FP"
    xray_ask_vlessenc ask || return 1

    if [ "$origin" = "tls" ]; then
        dir="${XRAY_CERT_DIR}/${tag}"
        if [ -n "$src_crt" ]; then
            xray_install_cert "$tag" "$src_crt" "$src_key" || { warn "$(L '证书复制失败')"; return 1; }
        else
            xray_gen_self_signed_cert "$domain" "$dir" || { warn "$(L '自签证书生成失败')"; return 1; }
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
        \"xhttpSettings\": { \"path\": \"${path}\", \"mode\": \"auto\", \"extra\": { \"xPaddingBytes\": \"${xpad}\" } }
      },
      ${XRAY_SNIFF}
    }" "N_TAG=\"${tag}\"
N_TYPE=\"xhttp-cdn\"
N_PORT=\"${port}\"
N_UUID=\"${uuid}\"
N_PATH=\"${path}\"
N_XPAD=\"${xpad}\"
N_ENC=\"${VE_ENC}\"
N_FP=\"${fp}\"
N_DOMAIN=\"${domain}\"
N_CPORT=\"${cport}\"
N_ORIGIN=\"${origin}\"
N_CERT_SRC=\"$(dq_escape "$src_crt")\"
N_KEY_SRC=\"$(dq_escape "$src_key")\"
N_NAME=\"${name}\"" || return 1
    XRAY_NEW_TAG="$tag"
    info "$(L '记得在 CDN 侧：把') ${domain} $(L '的回源端口指到') ${port}$(L '（Cloudflare 可用 Origin Rules），并开启 gRPC / HTTP/2 回源以获得更好的 XHTTP 表现')"
}

xray_add_venc() {
    local port uuid tag listen name path xpad
    echo "$(L 'VLESS Encryption + XHTTP：不套 TLS / REALITY，由 VLESS 自身的加密保护（适合直连，或明文回源的 CDN 之后）。')"
    xray_new_node_begin 8880 venc VLESS-ENC-XHTTP || return 1
    port="$XN_PORT"; uuid="$XN_UUID"; listen="$XN_LISTEN"; path="$XN_PATH"; xpad="$XN_XPAD"; tag="$XN_TAG"; name="$XN_NAME"
    xray_ask_vlessenc force || return 1
    xray_commit_node "$tag" "    {
      \"tag\": \"${tag}\", \"listen\": \"${listen}\", \"port\": ${port}, \"protocol\": \"vless\",
      \"settings\": { \"clients\": [ { \"id\": \"${uuid}\" } ], \"decryption\": \"${VE_DEC}\" },
      \"streamSettings\": {
        \"network\": \"xhttp\", \"security\": \"none\",
        \"xhttpSettings\": { \"path\": \"${path}\", \"mode\": \"auto\", \"extra\": { \"xPaddingBytes\": \"${xpad}\" } }
      },
      ${XRAY_SNIFF}
    }" "N_TAG=\"${tag}\"
N_TYPE=\"venc\"
N_PORT=\"${port}\"
N_UUID=\"${uuid}\"
N_PATH=\"${path}\"
N_XPAD=\"${xpad}\"
N_ENC=\"${VE_ENC}\"
N_NAME=\"${name}\"" || return 1
    XRAY_NEW_TAG="$tag"
}

xray_add_ss() {
    local port tag listen name method="2022-blake3-aes-128-gcm" bytes=16 pass ans
    echo "$(L 'Shadowsocks 2022 加密方式：')"
    echo "  1) $(L '2022-blake3-aes-128-gcm（默认）  2')) 2022-blake3-aes-256-gcm  3) 2022-blake3-chacha20-poly1305"
    read -rp "$(L '选择') [$(L '1/2/3，默认1')]: " ans || { [ -n "$ans" ] || return 1; }
    case "${ans:-1}" in
        2) method="2022-blake3-aes-256-gcm"; bytes=32 ;;
        3) method="2022-blake3-chacha20-poly1305"; bytes=32 ;;
        *) : ;;
    esac
    while true; do
        xray_new_node_begin "$(random_free_port)" ss SS2022 || return 1
        if udp_listening "$XN_PORT"; then
            warn "$(L 'UDP 端口已被占用，请换一个') (${XN_PORT})"
            continue
        fi
        break
    done
    port="$XN_PORT"; listen="$XN_LISTEN"; tag="$XN_TAG"; name="$XN_NAME"
    pass="$(csprng_base64 "$bytes" || true)"
    if [ -z "$pass" ]; then warn "$(L '生成随机密钥/UUID 失败，请检查 openssl 与 Xray 二进制')"; return 1; fi
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

# URI 组件百分号编码（保留 A-Za-z0-9._~-）
xray_urlencode() {
    local s="$1" i c out="" hex
    local LC_ALL=C
    for ((i=0; i<${#s}; i++)); do
        c="${s:i:1}"
        case "$c" in
            [A-Za-z0-9._~-]) out+="$c" ;;
            *) printf -v hex '%%%02X' "'$c"; out+="$hex" ;;
        esac
    done
    printf '%s' "$out"
}

# 输出某节点的分享链接
xray_node_link() {
    local tag="$1" host="$2" h pathenc spxenc spx_q="" pqv_q="" extra_q="" enc_q name_enc fp ui
    (
        xray_node_load "$tag" || exit 1
        h="$(format_host_for_url "$host")"
        pathenc="$(xray_urlencode "${N_PATH:-}")"
        enc_q="$(xray_urlencode "${N_ENC:-none}")"
        name_enc="$(xray_urlencode "${N_NAME:-$tag}")"
        fp="${N_FP:-chrome}"
        if [ -n "${N_SPX:-}" ]; then
            spxenc="$(xray_urlencode "$N_SPX")"
            spx_q="&spx=${spxenc}"
        fi
        if [ -n "${N_PQV:-}" ]; then
            pqv_q="&pqv=$(xray_urlencode "$N_PQV")"
        fi
        if [ -n "${N_XPAD:-}" ]; then
            extra_q="&extra=$(xray_urlencode "{\"xPaddingBytes\":\"${N_XPAD}\"}")"
        fi
        case "$N_TYPE" in
            vision)
                echo "vless://${N_UUID}@${h}:${N_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${N_SNI}&fp=${fp}&pbk=${N_PBK}&sid=${N_SID}${spx_q}${pqv_q}&type=tcp&headerType=none&support-x25519mlkem768=true#${name_enc}" ;;
            xhttp-reality)
                echo "vless://${N_UUID}@${h}:${N_PORT}?encryption=${enc_q}&security=reality&sni=${N_SNI}&fp=${fp}&pbk=${N_PBK}&sid=${N_SID}${spx_q}${pqv_q}&type=xhttp&path=${pathenc}&mode=auto${extra_q}&support-x25519mlkem768=true#${name_enc}" ;;
            xhttp-cdn)
                echo "vless://${N_UUID}@${N_DOMAIN}:${N_CPORT}?encryption=${enc_q}&security=tls&sni=${N_DOMAIN}&fp=${fp}&alpn=h2&type=xhttp&host=${N_DOMAIN}&path=${pathenc}&mode=packet-up${extra_q}#${name_enc}" ;;
            xhttp-tls)
                echo "vless://${N_UUID}@${h}:${N_PORT}?encryption=${enc_q}&security=tls&sni=${N_DOMAIN}&fp=${fp}&alpn=h2&type=xhttp&host=${N_DOMAIN}&path=${pathenc}&mode=auto${extra_q}#${name_enc}" ;;
            venc)
                echo "vless://${N_UUID}@${h}:${N_PORT}?encryption=${enc_q}&security=none&type=xhttp&path=${pathenc}&mode=auto${extra_q}#${name_enc}" ;;
            ss2022)
                ui="$(printf '%s' "${N_METHOD}:${N_PASS}" | base64 | tr -d '\n=' | tr '+/' '-_')"
                echo "ss://${ui}@${h}:${N_PORT}#${name_enc}" ;;
            *) exit 1 ;;
        esac
    )
}

xray_type_label() {
    case "$1" in
        vision)        printf 'VLESS + REALITY + Vision' ;;
        xhttp-reality) printf 'VLESS + XHTTP + REALITY' ;;
        xhttp-cdn)     printf 'VLESS + XHTTP（CDN）' ;;
        xhttp-tls)     printf 'VLESS + XHTTP + TLS（直连域名证书）' ;;
        venc)          printf 'VLESS Encryption + XHTTP' ;;
        ss2022)        printf 'Shadowsocks 2022' ;;
        *)             printf '%s' "$1" ;;
    esac
}

xray_show_node() {
    local tag="$1" host link alt_host alt_link
    xray_load_state
    host="${XRAY_PUBLIC_HOST:-$(detect_public_host)}"
    (
        xray_node_load "$tag" || { warn "$(L '找不到节点') ${tag}"; exit 1; }
        echo -e "${BOLD}[${tag}] $(xray_type_label "$N_TYPE")${NC}"
        echo "  $(L '端口:') ${N_PORT}"
        case "$N_TYPE" in
            vision|xhttp-reality)
                echo "  $(L '伪装站点:') ${N_SNI}    uTLS(fp): ${N_FP:-chrome}    $(L '公钥')(pbk): ${N_PBK}"
                echo "  shortIds: ${N_SIDS:-$N_SID}${N_SPX:+    spiderX: ${N_SPX}}${N_PQV:+    ML-DSA-65(pqv): ${N_PQV}}"
                ;;
            xhttp-cdn|xhttp-tls)
                echo "  uTLS(fp): ${N_FP:-chrome}"
                ;;
        esac
        case "$N_TYPE" in
            xhttp-reality|xhttp-cdn|venc|xhttp-tls) echo "  $(L 'XHTTP 路径:') ${N_PATH}${N_XPAD:+    xPaddingBytes: ${N_XPAD}}    VLESS Encryption: $([ "$N_ENC" = "none" ] && echo "$(L '未启用')" || echo "$(L '已启用')")" ;;
        esac
        if [ "$N_TYPE" = "xhttp-cdn" ]; then
            echo "  $(L 'CDN 域名:') ${N_DOMAIN}$(L '（客户端端口') ${N_CPORT}$(L '）   回源:') $([ "$N_ORIGIN" = "plain" ] && echo "$(L '明文 HTTP')" || echo "TLS") → $(L '本机') ${N_PORT}"
        fi
        if [ "$N_TYPE" = "xhttp-tls" ]; then
            echo "  $(L '域名:') ${N_DOMAIN}    $(L '证书剩余约') $([ -f "${XRAY_CERT_DIR}/${tag}/fullchain.pem" ] && cert_expiry_days "${XRAY_CERT_DIR}/${tag}/fullchain.pem" 2>/dev/null || echo '?') $(L '天')"
        fi
        if [ "$N_TYPE" = "ss2022" ]; then echo "  $(L '加密:') ${N_METHOD}    $(L '密码:') ${N_PASS}"; fi
    ) || return 1
    if [ -z "$host" ]; then
        warn "$(L '未能确定公网地址，分享链接暂不可用，请用 Xray 菜单 13 设置公网地址')"
        return 0
    fi
    link="$(xray_node_link "$tag" "$host" || true)"
    echo -e "  $(L '分享链接:')\n  ${GREEN}${link}${NC}"
    xray_node_load "$tag" 2>/dev/null || true
    if [ "${N_TYPE:-}" = "xhttp-tls" ] && [ -n "${N_DOMAIN:-}" ]; then
        alt_host=""
        if [ "$host" = "$N_DOMAIN" ]; then alt_host="$(detect_public_host)"; else alt_host="$N_DOMAIN"; fi
        if [ -n "$alt_host" ] && [ "$alt_host" != "$host" ]; then
            alt_link="$(xray_node_link "$tag" "$alt_host" || true)"
            if [ -n "$alt_link" ]; then
                echo -e "  $(L '备用链接（另一地址，SNI 仍为域名）:')\n  ${GREEN}${alt_link}${NC}"
            fi
        fi
    fi
    if command -v qrencode >/dev/null 2>&1 && [ -n "$link" ] && [ -t 1 ]; then
        qrencode -t ANSIUTF8 -m 1 "$link" 2>/dev/null || true
    fi
    return 0
}

xray_list_nodes() {
    xray_require || return 1
    local tag n=0 st
    step "$(L 'Xray 节点列表')"
    divider
    local -a _ntags=()
    while IFS= read -r tag; do [ -n "$tag" ] && _ntags+=("$tag"); done < <(xray_node_tags)
    for tag in "${_ntags[@]}"; do
        n=$((n + 1))
        (
            xray_node_load "$tag" || exit 0
            if [ "$N_TYPE" = "ss2022" ]; then
                if tcp_listening "$N_PORT" && udp_listening "$N_PORT"; then
                    st="${GREEN}$(L '监听中')${NC}"
                else
                    st="${RED}$(L '未监听')${NC}"
                fi
            else
                if tcp_listening "$N_PORT"; then st="${GREEN}$(L '监听中')${NC}"; else st="${RED}$(L '未监听')${NC}"; fi
            fi
            echo -e "  ${BOLD}${n})${NC} ${tag}    $(xray_type_label "$N_TYPE")    $(L '端口') ${N_PORT}    ${st}"
        )
    done
    if [ "$n" -eq 0 ]; then echo "  $(L '（还没有节点，用「2')) $(L '添加节点」创建）')"; fi
    return 0
}

# 让用户选一个节点，结果写入 XRAY_PICK
xray_pick_node() {
    local -a tags=()
    local tag ans
    XRAY_PICK=""
    while IFS= read -r tag; do [ -n "$tag" ] && tags+=("$tag"); done < <(xray_node_tags)
    if [ "${#tags[@]}" -eq 0 ]; then warn "$(L '还没有节点')"; return 1; fi
    xray_list_nodes
    read -rp "$(L '输入序号（回车取消）:') " ans || { [ -n "$ans" ] || return 1; }
    [ -n "$ans" ] || return 1
    if [[ ! "$ans" =~ ^[0-9]+$ ]] || [ "$ans" -lt 1 ] || [ "$ans" -gt "${#tags[@]}" ]; then warn "$(L '序号无效')"; return 1; fi
    XRAY_PICK="${tags[$((ans - 1))]}"
    return 0
}

xray_show_links() {
    xray_require || return 1
    local tag n=0
    step "$(L 'Xray 节点配置与分享链接')"
    divider
    local -a _ntags=()
    while IFS= read -r tag; do [ -n "$tag" ] && _ntags+=("$tag"); done < <(xray_node_tags)
    for tag in "${_ntags[@]}"; do
        n=$((n + 1))
        xray_show_node "$tag" || true
        echo ""
    done
    if [ "$n" -eq 0 ]; then echo "  $(L '（还没有节点）')"; return 0; fi
    echo "  $(L '说明：')"
    echo "  $(L '· REALITY 节点：较新的 Xray 服务端（社区反馈自 v26.9.8 起）要求客户端握手带 X25519MLKEM768，')"
    echo "    $(L '旧客户端会表现为超时 / reality verification failed；请使用新版 Xray 内核客户端，mihomo 内核需较新版本')"
    echo "    $(L '并重新导入本链接（链接已带 support-x25519mlkem768=true，不认识该参数的客户端会忽略它）')"
    echo "  $(L '· CDN 节点：连不通时把客户端的 XHTTP mode 从 auto 改成 packet-up 再试')"
    echo "  $(L '· VLESS Encryption 的 encryption= 参数很长，属正常现象；客户端内核需支持该特性')"
    return 0
}

xray_add_node() {
    xray_require || return 1
    local ans
    step "$(L '添加 Xray 节点')"
    divider
    echo -e "  ${GREEN}1)${NC} $(L 'VLESS + REALITY + Vision（TCP 直连，最常用）')"
    echo -e "  ${GREEN}2)${NC} $(L 'VLESS + XHTTP + REALITY（直连，可叠加 VLESS Encryption）')"
    echo -e "  ${GREEN}3)${NC} $(L 'VLESS + XHTTP + TLS / 明文回源（套 CDN，需要域名）')"
    echo -e "  ${GREEN}4)${NC} $(L 'VLESS Encryption + XHTTP（ML-KEM-768 抗量子，不依赖 TLS）')"
    echo -e "  ${GREEN}5)${NC} $(L 'Shadowsocks 2022（TCP + UDP）')"
    echo -e "  ${GREEN}6)${NC} $(L 'VLESS + XHTTP + TLS（直连域名证书，证书自动申请，IP 照常用）')"
    echo -e "  ${GREEN}0)${NC} $(L '返回')"
    read -rp "$(L '请选择') [0-6]: " ans || { [ -n "$ans" ] || return 1; }
    XRAY_NEW_TAG=""
    case "$ans" in
        1) xray_add_vision || return 1 ;;
        2) xray_add_xhttp_reality || return 1 ;;
        3) xray_add_xhttp_cdn || return 1 ;;
        4) xray_add_venc || return 1 ;;
        5) xray_add_ss || return 1 ;;
        6) xray_add_xhttp_tls || return 1 ;;
        *) return 0 ;;
    esac
    success "$(L '节点') ${XRAY_NEW_TAG} $(L '已添加并生效')"
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
    confirm "$(L '确认删除节点') ${tag}$(L '？')" n || { info "$(L '已取消')"; return 0; }
    specs="$( (xray_node_load "$tag" && { echo "${N_PORT}/tcp"; [ "$N_TYPE" = "ss2022" ] && echo "${N_PORT}/udp"; }) || true)"
    case "$tag" in ''|*[!A-Za-z0-9._-]*) warn "$(L '节点 tag 不合法，已中止删除')"; return 1 ;; esac
    rm -f "${XRAY_CONF_D}/10-in-${tag}.json" "${XRAY_NODE_DIR}/${tag}.env"
    rm -rf "${XRAY_CERT_DIR:?}/${tag}"
    xray_reload || true
    # shellcheck disable=SC2086
    if [ -n "$specs" ]; then fw_prune_old_specs "$(echo $specs)"; fi
    reserved_ports_sync || true
    success "$(L '节点') ${tag} $(L '已删除')"
    return 0
}

xray_compat_notice() {
    echo -e "${YELLOW}  $(L '跟随最新版本前请了解：')${NC}"
    echo "  $(L '· Xray 官方近期的发布基本都标记为 Pre-release，「最新预发布版」通常就是官方最新一版')"
    echo "  $(L '· 较新版本的 REALITY 服务端要求客户端握手带 X25519MLKEM768（社区反馈自 v26.9.8 起）：')"
    echo "    $(L '新版 Xray 内核客户端可连；mihomo 内核需较新版本并重新导入链接；部分客户端（如当时的 sing-box）连不上')"
    echo "  $(L '· 预发布版偶有不兼容改动：自动更新会先用新内核校验现有配置，校验不过就不换；启动失败会自动回滚')"
    echo "  $(L '· 如果你的客户端跟不上，可选「指定版本」固定在一个旧版本（如 v26.3.27）')"
}

xray_choose_channel() {
    local ans re='^v?[0-9]+(\.[0-9]+){1,3}$'
    echo -e "${BOLD}$(L '版本通道：')${NC}"
    echo "  1) $(L 'prerelease - 跟随官方最新版（含预发布，默认）')"
    echo "  2) $(L 'stable     - 只跟官方标记为正式版的发布（官方近期没有这样的发布时会提示）')"
    echo "  3) $(L 'pin        - 指定一个版本并固定，不自动更新')"
    xray_compat_notice
    read -rp "$(L '选择') [$(L '1/2/3，默认1')]: " ans || { [ -n "$ans" ] || return 1; }
    case "${ans:-1}" in
        2) XRAY_CHANNEL="stable"; XRAY_PIN_VERSION="" ;;
        3)
            while true; do
                read -rp "$(L '输入版本号（如 v26.3.27）:') " ans || { [ -n "$ans" ] || return 1; }
                ans="$(printf '%s' "$ans" | tr -d ' \r\n')"
                [ -z "$ans" ] || [ "$ans" = "q" ] && return 1
                if [[ "$ans" =~ $re ]]; then XRAY_CHANNEL="pin"; XRAY_PIN_VERSION="v${ans#v}"; break; fi
                warn "$(L '版本号格式不正确')"
            done
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
    step "$(L '安装 Xray（SS / VLESS）')"
    divider
    local host ans out hostre='^[][A-Za-z0-9.:_-]+$'
    xray_asset_name >/dev/null || return 1
    preflight_install_check "Xray-core" "$XRAY_BIN" "$XRAY_CONF_DIR" || return 1
    apt_install curl unzip openssl ca-certificates iproute2 python3 || { warn "$(L '依赖安装失败，请检查 apt 源/网络')"; return 1; }
    if systemctl is-active --quiet xray 2>/dev/null || systemctl is-active --quiet x-ui 2>/dev/null; then
        info "$(L '检测到本机还有其他 Xray（官方脚本安装的 xray.service 或 3x-ui）：本模块完全独立，互不影响，只需注意端口不要重复')"
    fi
    xray_load_state
    if [ -x "$XRAY_BIN" ]; then
        info "$(L '已安装') $(xray_installed_version)$(L '，将按所选通道重装 / 切换版本（节点配置保留）')"
    fi
    xray_choose_channel || return 1
    info "$(L '正在查询官方发布 ...')"
    if ! xray_resolve_target; then
        if [ "$XRAY_CHANNEL" = "stable" ] && [ -n "${XRAY_LATEST_ANY:-}" ]; then
            warn "$(L '没有找到标记为正式版的发布（最新为') ${XRAY_LATEST_ANY}$(L '：官方标记为预发布，或当前取不到标记信息）')"
            confirm "$(L '改为跟随最新预发布版') ${XRAY_LATEST_ANY}$(L '？')" y || return 0
            XRAY_CHANNEL="prerelease"; XRAY_TARGET="$XRAY_LATEST_ANY"
        else
            warn "$(L '未能获取 Xray 官方发布信息（GitHub 不可达或被限流），请稍后重试，或选「指定版本」')"
            return 1
        fi
    fi
    info "$(L '将安装:') ${XRAY_TARGET}$(L '（')$(xray_asset_name)$(L '）')"
    while ! xray_fetch "$XRAY_TARGET"; do
        confirm "$(L '下载失败，是否立即重试？')" y || return 1
    done
    # 有现成节点或转发规则时先用新内核校验现有配置（与 xray_upgrade_to 一致），不通过不替换
    if [ -x "$XRAY_BIN" ] && { [ "$(xray_node_count)" -gt 0 ] || [ "$(xray_fwd_enabled_count)" -gt 0 ]; }; then
        if ! out="$(XRAY_LOCATION_ASSET="$XRAY_DIR" "$XRAY_DL_DIR/xray" run -test -confdir "$XRAY_CONF_D" 2>&1)"; then
            warn "$(L '新内核未通过现有配置校验，保持当前版本不变（上游可能有不兼容改动）')"
            printf '%s\n' "$out" | tail -n 5
            return 1
        fi
    fi
    xray_ensure_user || return 1
    xray_apply_binary
    if [ "${XRAY_CN_BLOCK:-1}" = "1" ] && ! xray_ensure_geo_data; then
        warn "$(L 'geo 数据缺失：本次安装先不开启大陆拦截，稍后用 Xray 菜单 15 再开')"
        XRAY_CN_BLOCK="0"
    fi
    # 每次重装都按当前 XRAY_CN_BLOCK 重写（geo 数据缺失时上面已把 CN_BLOCK 置 0），
    # 否则旧文件与当前开关状态会脱节（菜单显示关、实际仍拦截，或反过来）
    xray_write_base
    xray_write_service
    xray_fix_perms
    systemctl daemon-reload

    host="${XRAY_PUBLIC_HOST:-$(detect_public_host)}"
    while true; do
        read -rp "$(L '生成分享链接用的公网地址（回车使用') ${host:-$(L '未探测到，请手动输入')}$(L '）:') " ans || { [ -n "$ans" ] || return 1; }
        ans="${ans:-$host}"
        if [[ -z "$ans" || ! "$ans" =~ $hostre ]]; then
            warn "$(L '地址不能为空，且只能包含字母、数字和 . : - _') [ ]"
            continue
        fi
        if check_public_host "$ans"; then host="$ans"; break; fi
        if confirm "$(L '仍要使用这个地址？')" n; then host="$ans"; break; fi
    done
    XRAY_PUBLIC_HOST="$host"
    if [ "$XRAY_CHANNEL" = "pin" ]; then
        XRAY_AUTO_UPDATE="0"
    elif confirm "$(L '开启自动更新？（每日检查官方发布；先用新内核校验配置，失败不换，启动失败自动回滚）')" y; then
        XRAY_AUTO_UPDATE="1"
    else
        XRAY_AUTO_UPDATE="0"
    fi
    xray_save_state
    maint_ask_script_auto
    maint_install_timers || true
    success "Xray $(xray_installed_version) $(L '安装完成')"
    if [ "$(xray_node_count)" -gt 0 ] || [ "$(xray_fwd_enabled_count)" -gt 0 ]; then
        if xray_reload; then
            success "$(L '现有节点已随新内核重启')"
        elif [ -f "${XRAY_BIN}.previous" ]; then
            warn "$(L '现有节点在该版本下未能启动，正在回滚到旧内核')"
            if install -m 755 "${XRAY_BIN}.previous" "$XRAY_BIN" && xray_reload; then
                success "$(L '已回滚到旧内核并重启')"
            else
                warn "$(L '回滚后仍未启动，请查看日志：journalctl -u adam-xray -n 50')"
            fi
        else
            warn "$(L '现有节点在该版本下未能启动，请查看日志或换一个版本')"
        fi
        return 0
    fi
    echo ""
    if confirm "$(L '现在添加第一个节点？')" y; then xray_add_node; fi
    return 0
}

# 升级到指定版本（不提问）：新内核先校验现有配置，再替换；启动失败回滚
xray_upgrade_to() {
    local ver="$1" prev out
    prev="$(xray_installed_version)"
    xray_fetch "$ver" || return 1
    if [ "$(xray_node_count)" -gt 0 ] || [ "$(xray_fwd_enabled_count)" -gt 0 ]; then
        if ! out="$(XRAY_LOCATION_ASSET="$XRAY_DIR" "$XRAY_DL_DIR/xray" run -test -confdir "$XRAY_CONF_D" 2>&1)"; then
            maint_log "[Xray] ${ver} $(L '无法通过现有配置的校验，保持') ${prev} $(L '不变（上游可能有不兼容改动）')"
            printf '%s\n' "$out" | tail -n 5
            return 1
        fi
    fi
    xray_apply_binary
    if [ "$(xray_node_count)" -eq 0 ] && [ "$(xray_fwd_enabled_count)" -eq 0 ]; then
        maint_log "[Xray] $(L '已更新:') ${prev:-$(L '未知')} -> ${ver}"
        return 0
    fi
    if svc_restart_wait adam-xray 2 10 && xray_healthy; then
        maint_log "[Xray] $(L '已更新:') ${prev:-$(L '未知')} -> ${ver}"
        return 0
    fi
    maint_log "[Xray] ${ver} $(L '启动失败，回滚到') ${prev:-$(L '旧版本')}"
    if [ -f "${XRAY_BIN}.previous" ]; then
        install -m 755 "${XRAY_BIN}.previous" "$XRAY_BIN"
        if svc_restart_wait adam-xray 2 10 && xray_healthy; then
            maint_log "[Xray] $(L '已回滚，服务恢复运行')"
            notify_send "Xray Auto-Rollback" "Upgrade to ${ver} failed; rolled back to ${prev:-previous} and recovered." || true
        else
            maint_log "[Xray] $(L '回滚后仍未启动: journalctl -u adam-xray -n 50')"
            notify_send "Xray Rollback Alert" "Upgrade to ${ver} failed and adam-xray is STILL DOWN after rollback." || true
        fi
    fi
    return 1
}

# 每日维护调用：全程不提问
xray_autoupdate() {
    local cur
    [ -x "$XRAY_BIN" ] || return 0
    xray_load_state
    if [ "$XRAY_CHANNEL" = "pin" ]; then
        echo "[Xray] $(L '已固定在') ${XRAY_PIN_VERSION}$(L '，不自动更新')"
        return 0
    fi
    cur="$(xray_installed_version)"
    xray_query_latest "$XRAY_CHANNEL"
    local _auc_rc=0
    # Xray 采用 CalVer（v26→v27），不按主版本号拦截跨年更新；安全由新内核 run -test 预检与失败自动回滚保障
    autoupdate_check "$cur" "$XRAY_LATEST" "" "$XRAY_SOURCE_OK" xray_ver_gt || _auc_rc=$?
    case "$_auc_rc" in
        0) ;;
        1) return 0 ;;
        *) return 1 ;;
    esac
    echo "[Xray] $(L '发现新版本:') ${cur:-$(L '未知')} -> ${XRAY_LATEST}$(L '，开始更新')"
    xray_upgrade_to "$XRAY_LATEST"
}

xray_update() {
    xray_require || return 1
    maint_lock_manual || return 1
    local cur
    step "$(L '检查 Xray 更新')"
    divider
    xray_load_state
    cur="$(xray_installed_version)"
    info "$(L '当前版本:') ${cur:-$(L '未知')}$(L '（')${XRAY_CHANNEL} $(L '通道）')"
    if [ "$XRAY_CHANNEL" = "pin" ]; then
        info "$(L '已固定在') ${XRAY_PIN_VERSION}$(L '。要换版本或恢复跟随最新，请用「1')) $(L '安装 / 重装」重新选择通道')"
        return 0
    fi
    info "$(L '正在查询官方发布 ...')"
    xray_query_latest "$XRAY_CHANNEL"
    if [ -z "$XRAY_LATEST" ]; then
        warn "$(L '未能获取') ${XRAY_CHANNEL} $(L '通道的版本信息（GitHub 不可达 / 被限流，或该通道暂无发布）')"
        return 1
    fi
    info "$(L '官方最新:') ${XRAY_LATEST}$([ "$XRAY_LATEST_IS_PRE" = "1" ] && echo "（$(L '预发布')）")"
    if [ -n "$cur" ] && ! xray_ver_gt "$XRAY_LATEST" "$cur"; then
        success "$(L '已经是最新版本')"
        return 0
    fi
    if [ -n "$(version_major "$cur")" ] && [ "$(version_major "$XRAY_LATEST")" != "$(version_major "$cur")" ]; then
        confirm "$(L '检测到跨大版本升级，确认继续吗？')" n || { info "$(L '已取消')"; return 0; }
    fi
    xray_compat_notice
    confirm "$(L '升级到') ${XRAY_LATEST}$(L '？')" y || { info "$(L '已取消')"; return 0; }
    if xray_upgrade_to "$XRAY_LATEST"; then success "$(L '升级完成:') $(xray_installed_version)"; else return 1; fi
    return 0
}

xray_health_check() {
    xray_require || return 1
    local tag out cur days cert_lbl has_reality=0 ntp_rc=0
    HC_PROBLEMS=0
    step "$(L 'Xray 健康检查')"
    divider
    cur="$(xray_installed_version)"
    hc_line 0 "$(L '内核版本') ${cur:-$(L '未知')}"
    if [ "$(xray_node_count)" -eq 0 ] && [ "$(xray_fwd_enabled_count)" -eq 0 ]; then
        hc_line 2 "$(L '还没有节点，服务不会启动')"
        return 0
    fi
    health_check_common adam-xray
    if out="$(xray_test_conf)"; then hc_line 0 "$(L '配置校验通过')"; else hc_line 1 "$(L '配置校验失败:') $(printf '%s\n' "$out" | tail -n 1)"; fi
    local -a _ntags=()
    while IFS= read -r tag; do [ -n "$tag" ] && _ntags+=("$tag"); done < <(xray_node_tags)
    for tag in "${_ntags[@]}"; do
        xray_node_load "$tag" || continue
        case "$N_TYPE" in vision|xhttp-reality) has_reality=1 ;; esac
        if tcp_listening "$N_PORT"; then hc_line 0 "[${tag}] TCP ${N_PORT} $(L '正在监听')"; else hc_line 1 "[${tag}] TCP ${N_PORT} $(L '没有在监听')"; fi
        if [ "$N_TYPE" = "ss2022" ]; then
            if udp_listening "$N_PORT"; then hc_line 0 "[${tag}] UDP ${N_PORT} $(L '正在监听')"; else hc_line 1 "[${tag}] UDP ${N_PORT} $(L '没有在监听')"; fi
            if ufw_active && ! fw_is_allowed "$N_PORT" udp; then hc_line 1 "[${tag}] $(L '防火墙未放行') ${N_PORT}/udp"; fi
        fi
        if [[ "$N_PORT" =~ ^[0-9]+$ ]] && [ "$N_PORT" -ge 1024 ] && ! reserved_port_ok "$N_PORT"; then hc_line 1 "[${tag}] $(L '端口') ${N_PORT} $(L '未加入内核保留端口')"; fi
        if ufw_active && ! fw_is_allowed "$N_PORT" tcp; then hc_line 1 "[${tag}] $(L '防火墙未放行') ${N_PORT}/tcp"; fi
        cert_lbl=""
        if [ "$N_TYPE" = "xhttp-tls" ]; then cert_lbl="$(L '证书剩余')";
        elif [ "$N_TYPE" = "xhttp-cdn" ] && [ "$N_ORIGIN" != "plain" ]; then cert_lbl="$(L '回源证书剩余')"; fi
        if [ -n "$cert_lbl" ] && [ -f "${XRAY_CERT_DIR}/${tag}/fullchain.pem" ]; then
            days="$(cert_expiry_days "${XRAY_CERT_DIR}/${tag}/fullchain.pem" 2>/dev/null || echo "")"
            if [[ "$days" =~ ^-?[0-9]+$ ]]; then
                if [ "$days" -lt 15 ]; then hc_line 1 "[${tag}] ${cert_lbl} ${days} $(L '天')"; else hc_line 0 "[${tag}] ${cert_lbl} ${days} $(L '天')"; fi
            fi
        fi
    done
    if [ "$has_reality" = "1" ]; then
        check_ntp_sync || ntp_rc=$?
        case "$ntp_rc" in
            0) hc_line 0 "$(L '系统时钟 NTP 同步正常（保障 REALITY maxTimeDiff: 60s）')" ;;
            1) hc_line 1 "$(L '系统时钟未 NTP 同步！REALITY 握手容差仅 ±60s，请开启 NTP')" ;;
        esac
    fi
    # 转发规则：TCP/UDP 监听与防火墙
    local _ftag
    while IFS= read -r _ftag; do
        [ -n "$_ftag" ] || continue
        xray_fwd_load "$_ftag" || continue
        [ "${FWD_ENABLED:-0}" = "1" ] || continue
        if ! validate_port "$FWD_LPORT"; then hc_line 1 "[fwd-${FWD_ID}] $(L '端口不合法')"; continue; fi
        if [ "${FWD_PROTO:-both}" != "udp" ]; then
            if tcp_listening "$FWD_LPORT"; then hc_line 0 "[fwd-${FWD_ID}] TCP ${FWD_LPORT} $(L '正在监听')"; else hc_line 1 "[fwd-${FWD_ID}] TCP ${FWD_LPORT} $(L '没有在监听')"; fi
            if ufw_active && ! fw_is_allowed "$FWD_LPORT" tcp; then hc_line 1 "[fwd-${FWD_ID}] $(L '防火墙未放行') ${FWD_LPORT}/tcp"; fi
        fi
        if [ "${FWD_PROTO:-both}" != "tcp" ]; then
            if udp_listening "$FWD_LPORT"; then hc_line 0 "[fwd-${FWD_ID}] UDP ${FWD_LPORT} $(L '正在监听')"; else hc_line 1 "[fwd-${FWD_ID}] UDP ${FWD_LPORT} $(L '没有在监听')"; fi
            if ufw_active && ! fw_is_allowed "$FWD_LPORT" udp; then hc_line 1 "[fwd-${FWD_ID}] $(L '防火墙未放行') ${FWD_LPORT}/udp"; fi
        fi
    done < <(xray_fwd_tags)
    maint_load
    if [ "$MAINT_WATCHDOG" = "1" ] && systemctl is-active --quiet adam-watchdog.timer 2>/dev/null; then
        hc_line 0 "$(L '保活巡检定时器运行中（每 5 分钟）')"
    elif [ "$MAINT_WATCHDOG" != "1" ]; then
        hc_line 2 "$(L '保活巡检未开启')"
    else
        hc_line 1 "$(L '保活巡检定时器未运行')"
    fi
    xray_load_state
    if [ "$XRAY_CHANNEL" = "pin" ]; then
        hc_line 2 "$(L '版本已固定在') ${XRAY_PIN_VERSION}$(L '，不自动更新')"
    else
        if [ "$XRAY_AUTO_UPDATE" = "1" ]; then
            if systemctl is-active --quiet adam-maintain.timer 2>/dev/null; then
                hc_line 0 "$(L '自动更新已开启（')${XRAY_CHANNEL} $(L '通道）')"
            else
                hc_line 1 "$(L '自动更新已开启，但每日维护定时器未运行')"
            fi
        else hc_line 2 "$(L '自动更新未开启')"; fi
        xray_query_latest "$XRAY_CHANNEL"
        if [ -z "$XRAY_LATEST" ]; then
            hc_line 2 "$(L '暂时取不到官方发布信息，无法判断是否有新版本')"
        elif [ -n "$cur" ] && xray_ver_gt "$XRAY_LATEST" "$cur"; then
            hc_line 2 "$(L '官方有新版本') ${XRAY_LATEST}$(L '（当前') ${cur}$(L '）')"
        else
            hc_line 0 "$(L '已是') ${XRAY_CHANNEL} $(L '通道最新版本')"
        fi
    fi
    divider
    if [ "$HC_PROBLEMS" -eq 0 ]; then success "$(L '健康检查通过')"; return 0; fi
    warn "$(L '发现') ${HC_PROBLEMS} $(L '项问题，可用「一键修复」处理')"
    return 1
}

_xray_repair_core() {
    local quiet="${1:-}" spec tag days ntp_rc=0
    [ -x "$XRAY_BIN" ] || return 1
    xray_ensure_user || return 1
    xray_load_state
    check_ntp_sync || ntp_rc=$?
    if [ "$ntp_rc" = "1" ]; then fix_ntp_sync || true; fi
    if [ "${XRAY_CN_BLOCK:-1}" = "1" ]; then
        xray_ensure_geo_data >/dev/null 2>&1 || true
    fi
    # 同步外部证书 + 自动轮换缺失或即将过期（<15 天）的 CDN 自签证书
    local -a _rtags=()
    while IFS= read -r tag; do [ -n "$tag" ] && _rtags+=("$tag"); done < <(xray_node_tags)
    for tag in "${_rtags[@]}"; do
        (
            xray_node_load "$tag" || exit 0
            if [ -n "${N_CERT_SRC:-}" ] && [ -f "$N_CERT_SRC" ] && [ -f "$N_KEY_SRC" ]; then
                xray_install_cert "$tag" "$N_CERT_SRC" "$N_KEY_SRC" 2>/dev/null || true
            elif [ "${N_TYPE:-}" = "xhttp-cdn" ] && [ "${N_ORIGIN:-tls}" != "plain" ] && [ -z "${N_CERT_SRC:-}" ] && [ -n "${N_DOMAIN:-}" ]; then
                if [ ! -f "${XRAY_CERT_DIR}/${tag}/fullchain.pem" ] || [ ! -f "${XRAY_CERT_DIR}/${tag}/privkey.pem" ]; then
                    xray_gen_self_signed_cert "$N_DOMAIN" "${XRAY_CERT_DIR}/${tag}" 2>/dev/null || true
                else
                    days="$(cert_expiry_days "${XRAY_CERT_DIR}/${tag}/fullchain.pem" 2>/dev/null || echo 999)"
                    if [[ "$days" =~ ^-?[0-9]+$ ]] && [ "$days" -lt 15 ]; then
                        xray_gen_self_signed_cert "$N_DOMAIN" "${XRAY_CERT_DIR}/${tag}" 2>/dev/null || true
                    fi
                fi
            fi
        ) || true
    done
    # 重建转发配置（不触发中间 reload）与 00-base.json
    if [ -d "$XRAY_FWD_DIR" ]; then
        local _ftmp _first=1 _cnt=0 _ff _frag
        install -d -m 750 "$XRAY_CONF_D" 2>/dev/null || true
        _ftmp="$(mktemp "${XRAY_CONF_D}/.20-forward.XXXXXX" 2>/dev/null || true)"
        if [ -n "$_ftmp" ]; then
            {
                printf '%s\n' '{' '  "inbounds": ['
                while IFS= read -r _ff; do
                    _frag="$(xray_fwd_rule_json "$_ff")"
                    [ -n "$_frag" ] || continue
                    if [ "$_first" = "1" ]; then _first=0; else printf '%s\n' ','; fi
                    printf '%s' "    ${_frag}"
                    _cnt=$((_cnt + 1))
                done < <(xray_fwd_rule_files)
                printf '\n%s\n' '  ]' '}'
            } > "$_ftmp" 2>/dev/null || true
            if [ "$_cnt" -eq 0 ]; then
                rm -f "$_ftmp" "$XRAY_FWD_JSON"
            else
                chmod 640 "$_ftmp" 2>/dev/null || true
                mv -f "$_ftmp" "$XRAY_FWD_JSON" 2>/dev/null || rm -f "$_ftmp"
            fi
        fi
    fi
    xray_write_base
    xray_write_service
    xray_fix_perms
    systemctl daemon-reload
    systemctl reset-failed adam-xray >/dev/null 2>&1 || true
    reserved_ports_sync || true
    if ufw_active; then
        while IFS= read -r spec; do
            if [ -n "$spec" ]; then
                ufw allow "$spec" >/dev/null 2>&1 || true
            fi
        done < <(xray_ports)
    fi
    xray_sync_reality_snis >/dev/null 2>&1 || true
    if [ "$quiet" = "quiet" ]; then
        xray_reload >/dev/null 2>&1 || return 1
    else
        xray_reload || return 1
    fi
    return 0
}

xray_repair() {
    xray_require || return 1
    step "$(L 'Xray 一键修复')"
    divider
    maint_install_timers || true
    if _xray_repair_core; then
        success "$(L '修复完成')"
        return 0
    fi
    return 1
}

# 将当前内存中的 N_* 元数据原子写回 ${XRAY_NODE_DIR}/${tag}.env（0600 权限）
xray_node_save() {
    local tag="$1"
    state_save "${XRAY_NODE_DIR}/${tag}.env" "$XRAY_NODE_DIR" 700 \
        N_TAG N_TYPE N_PORT N_UUID N_SNI N_PBK N_SID N_SIDS N_SPX N_FP N_PQV \
        N_PATH N_XPAD N_ENC N_DOMAIN N_CPORT N_CSEC N_METHOD N_PASS N_NAME \
        N_CERT_SRC N_KEY_SRC N_ORIGIN
}

# xray_edit_node [tag]：原地热轮换/编辑 Xray 节点（换 SNI / 轮换 shortIds+spiderX / 换 uTLS fp / 换端口 / 轮换 XHTTP 路径与填充），原子更新并失败自动回滚
xray_edit_node() {
    xray_require || return 1
    local tag="${1:-}" conf envf bak_conf bak_env choice old_port new_port need_reload=0 dom=""
    if [ -z "$tag" ]; then
        xray_pick_node || return 0
        tag="$XRAY_PICK"
    fi
    conf="${XRAY_CONF_D}/10-in-${tag}.json"
    envf="${XRAY_NODE_DIR}/${tag}.env"
    [ -f "$conf" ] && [ -f "$envf" ] || { warn "$(L '找不到节点') ${tag}"; return 1; }
    xray_node_load "$tag" || { warn "$(L '节点元数据损坏或未通过安全检查') ${tag}"; return 1; }
    command -v python3 >/dev/null 2>&1 || { warn "$(L '未找到 python3，无法编辑节点 JSON')"; return 1; }

    step "$(L '热更新 / 编辑 Xray 节点') [${tag}]"
    divider
    echo "  $(L '类型:') $(xray_type_label "$N_TYPE")    $(L '端口:') ${N_PORT}    uTLS(fp): ${N_FP:-chrome}"
    case "$N_TYPE" in
        vision|xhttp-reality) echo "  SNI: ${N_SNI}    shortIds: ${N_SIDS:-$N_SID}    spiderX: ${N_SPX:-/}" ;;
    esac
    case "$N_TYPE" in
        xhttp-reality|xhttp-cdn|xhttp-tls|venc) echo "  $(L 'XHTTP 路径:') ${N_PATH}    xPaddingBytes: ${N_XPAD:-default}" ;;
    esac
    divider
    echo "  1) $(L '更换 REALITY 伪装站点 (SNI)')"
    echo "  2) $(L '一键轮换 REALITY shortIds + spiderX')"
    echo "  3) $(L '更换客户端 uTLS 指纹 (fp)')"
    echo "  4) $(L '修改监听端口')"
    echo "  5) $(L '一键轮换 XHTTP 路径 + xPaddingBytes')"
    echo "  6) $(L '生成 / 轮换 REALITY ML-DSA-65 后量子签名')"
    echo "  0) $(L '取消')"
    read -rp "$(L '请选择') [0-6]: " choice || return 0

    make_workdir || return 1
    bak_conf="${WORKDIR}/in.json.bak"
    bak_env="${WORKDIR}/node.env.bak"
    cp -a "$conf" "$bak_conf"
    cp -a "$envf" "$bak_env"
    old_port="$N_PORT"
    new_port="$N_PORT"

    case "$choice" in
        0|"") info "$(L '已取消')"; return 0 ;;
        1)
            case "$N_TYPE" in vision|xhttp-reality) ;; *) warn "$(L '仅 REALITY 节点支持更换 SNI')"; return 1 ;; esac
            xray_ask_sni || return 1
            dom="$(xray_host_domain || true)"
            python3 - "$conf" "$XR_SNI" "$dom" << 'PY' || { warn "$(L '更新节点 JSON 失败')"; return 1; }
import json, os, sys, tempfile
conf, sni, dom = sys.argv[1], sys.argv[2], sys.argv[3]
with open(conf, "r", encoding="utf-8") as f:
    data = json.load(f)
snis = [sni] + ([dom] if dom and dom != sni else [])
for ib in data.get("inbounds", []):
    rs = ib.get("streamSettings", {}).get("realitySettings")
    if rs is not None:
        rs["target"] = f"{sni}:443"
        rs["serverNames"] = snis
fd, tmp = tempfile.mkstemp(prefix=".edit-", dir=os.path.dirname(conf) or ".")
with os.fdopen(fd, "w", encoding="utf-8") as tf:
    json.dump(data, tf, indent=2); tf.write("\n")
os.chmod(tmp, 0o640); os.replace(tmp, conf)
PY
            N_SNI="$XR_SNI"
            need_reload=1
            ;;
        2)
            case "$N_TYPE" in vision|xhttp-reality) ;; *) warn "$(L '仅 REALITY 节点支持轮换 shortIds')"; return 1 ;; esac
            local cnt i=0 tries=0 sid sids_str="" new_spx
            cnt="$(csprng_int 2 3 2>/dev/null || echo 2)"
            while [ "$i" -lt "$cnt" ] && [ "$tries" -lt 20 ]; do
                tries=$((tries + 1))
                sid="$(csprng_short_id 2>/dev/null || true)"
                [[ "$sid" =~ ^([0-9a-f]{2}){4,8}$ ]] || continue
                case ",${sids_str}," in *",${sid},"*) continue ;; esac
                sids_str="${sids_str:+${sids_str},}${sid}"
                i=$((i + 1))
            done
            new_spx="$(csprng_url_path 2>/dev/null || true)"
            [ "$i" -ge 2 ] && [[ "$new_spx" == /* ]] || { warn "$(L '生成随机参数失败')"; return 1; }
            python3 - "$conf" "$sids_str" << 'PY' || { warn "$(L '更新节点 JSON 失败')"; return 1; }
import json, os, sys, tempfile
conf, sids_csv = sys.argv[1], sys.argv[2]
sids = [s for s in sids_csv.split(",") if s]
with open(conf, "r", encoding="utf-8") as f:
    data = json.load(f)
for ib in data.get("inbounds", []):
    rs = ib.get("streamSettings", {}).get("realitySettings")
    if rs is not None:
        rs["shortIds"] = sids
fd, tmp = tempfile.mkstemp(prefix=".edit-", dir=os.path.dirname(conf) or ".")
with os.fdopen(fd, "w", encoding="utf-8") as tf:
    json.dump(data, tf, indent=2); tf.write("\n")
os.chmod(tmp, 0o640); os.replace(tmp, conf)
PY
            N_SID="${sids_str%%,*}"
            N_SIDS="$sids_str"
            N_SPX="$new_spx"
            need_reload=1
            ;;
        3)
            case "$N_TYPE" in
                vision|xhttp-reality) xray_pick_fp reality || return 1 ;;
                xhttp-tls|xhttp-cdn)  xray_pick_fp tls || return 1 ;;
                *) warn "$(L '该节点类型不使用 uTLS 指纹')"; return 1 ;;
            esac
            N_FP="$XR_FP"
            need_reload=0
            ;;
        4)
            while true; do
                xray_ask_port "$(random_free_port)" || return 1
                new_port="$XP_PORT"
                if [ "$N_TYPE" = "ss2022" ] && udp_listening "$new_port"; then
                    warn "$(L 'UDP 端口已被占用，请换一个') (${new_port})"
                    continue
                fi
                break
            done
            python3 - "$conf" "$new_port" << 'PY' || { warn "$(L '更新节点 JSON 失败')"; return 1; }
import json, os, sys, tempfile
conf, port = sys.argv[1], int(sys.argv[2])
with open(conf, "r", encoding="utf-8") as f:
    data = json.load(f)
for ib in data.get("inbounds", []):
    ib["port"] = port
fd, tmp = tempfile.mkstemp(prefix=".edit-", dir=os.path.dirname(conf) or ".")
with os.fdopen(fd, "w", encoding="utf-8") as tf:
    json.dump(data, tf, indent=2); tf.write("\n")
os.chmod(tmp, 0o640); os.replace(tmp, conf)
PY
            N_PORT="$new_port"
            need_reload=1
            ;;
        5)
            case "$N_TYPE" in xhttp-reality|xhttp-cdn|xhttp-tls|venc) ;; *) warn "$(L '仅 XHTTP 节点支持轮换路径与填充')"; return 1 ;; esac
            local new_path xp_lo xp_hi new_xpad
            new_path="$(csprng_url_path 2>/dev/null || true)"
            xp_lo="$(csprng_int 100 350 2>/dev/null || echo 150)"
            xp_hi="$(csprng_int 600 1200 2>/dev/null || echo 900)"
            new_xpad="${xp_lo}-${xp_hi}"
            [[ "$new_path" == /* ]] || { warn "$(L '生成随机参数失败')"; return 1; }
            python3 - "$conf" "$new_path" "$new_xpad" << 'PY' || { warn "$(L '更新节点 JSON 失败')"; return 1; }
import json, os, sys, tempfile
conf, path, xpad = sys.argv[1], sys.argv[2], sys.argv[3]
with open(conf, "r", encoding="utf-8") as f:
    data = json.load(f)
for ib in data.get("inbounds", []):
    xs = ib.get("streamSettings", {}).get("xhttpSettings")
    if xs is not None:
        xs["path"] = path
        ex = xs.get("extra") if isinstance(xs.get("extra"), dict) else {}
        ex["xPaddingBytes"] = xpad
        xs["extra"] = ex
fd, tmp = tempfile.mkstemp(prefix=".edit-", dir=os.path.dirname(conf) or ".")
with os.fdopen(fd, "w", encoding="utf-8") as tf:
    json.dump(data, tf, indent=2); tf.write("\n")
os.chmod(tmp, 0o640); os.replace(tmp, conf)
PY
            N_PATH="$new_path"
            N_XPAD="$new_xpad"
            need_reload=1
            ;;
        6)
            case "$N_TYPE" in vision|xhttp-reality) ;; *) warn "$(L '仅 REALITY 节点支持 ML-DSA-65 后量子签名')"; return 1 ;; esac
            xray_gen_mldsa65 || { warn "$(L '当前 Xray 内核不支持 mldsa65，请先升级内核')"; return 1; }
            python3 - "$conf" "$XM_SEED" << 'PY' || { warn "$(L '更新节点 JSON 失败')"; return 1; }
import json, os, sys, tempfile
conf, seed = sys.argv[1], sys.argv[2]
with open(conf, "r", encoding="utf-8") as f:
    data = json.load(f)
for ib in data.get("inbounds", []):
    rs = ib.get("streamSettings", {}).get("realitySettings")
    if rs is not None:
        rs["mldsa65Seed"] = seed
fd, tmp = tempfile.mkstemp(prefix=".edit-", dir=os.path.dirname(conf) or ".")
with os.fdopen(fd, "w", encoding="utf-8") as tf:
    json.dump(data, tf, indent=2); tf.write("\n")
os.chmod(tmp, 0o640); os.replace(tmp, conf)
PY
            N_PQV="$XM_VERIFY"
            need_reload=1
            ;;
        *) warn "$(L '无效选择')"; return 1 ;;
    esac

    xray_node_save "$tag" || { cp -a "$bak_conf" "$conf"; cp -a "$bak_env" "$envf"; return 1; }
    if [ "$need_reload" = "1" ]; then
        if [ "$new_port" != "$old_port" ] && ufw_active; then
            ufw allow "${new_port}/tcp" >/dev/null 2>&1 || true
            [ "$N_TYPE" = "ss2022" ] && ufw allow "${new_port}/udp" >/dev/null 2>&1 || true
        fi
        if ! xray_reload; then
            warn "$(L '重载失败，正在自动回滚节点配置...')"
            cp -a "$bak_conf" "$conf"
            cp -a "$bak_env" "$envf"
            xray_fix_perms
            xray_reload >/dev/null 2>&1 || true
            return 1
        fi
        if [ "$new_port" != "$old_port" ]; then
            reserved_ports_sync || true
            if ufw_active; then
                ! port_used_by_other_services "${old_port}/tcp" "" && ufw delete allow "${old_port}/tcp" >/dev/null 2>&1 || true
                if [ "$N_TYPE" = "ss2022" ]; then
                    ! port_used_by_other_services "${old_port}/udp" "" && ufw delete allow "${old_port}/udp" >/dev/null 2>&1 || true
                fi
            fi
        fi
    fi
    success "$(L '节点已热更新，请重新导入下方最新分享链接：')"
    xray_show_node "$tag"
    return 0
}

xray_status() {
    xray_require || return 1
    systemctl status adam-xray --no-pager 2>/dev/null | head -n 12 || true
    divider
    xray_load_state
    echo "  $(L '内核版本 :') $(xray_installed_version)"
    echo "  $(L '版本通道 :') ${XRAY_CHANNEL}$([ "$XRAY_CHANNEL" = "pin" ] && echo "（${XRAY_PIN_VERSION}）")    $(L '自动更新:') $([ "$XRAY_AUTO_UPDATE" = "1" ] && echo "$(L '开')" || echo "$(L '关')")"
    echo "  $(L '节点数量 :') $(xray_node_count)"
    return 0
}

xray_logs() {
    xray_require || return 1
    info "$(L '实时日志（Ctrl+C 返回）')"
    journalctl -u adam-xray -n 30 -f || true
    return 0
}

xray_restart() {
    xray_require || return 1
    if xray_reload; then success "$(L 'Xray 已重启')"; else return 1; fi
    return 0
}

xray_set_host() {
    xray_require || return 1
    local ans hostre='^[][A-Za-z0-9.:_-]+$'
    xray_load_state
    read -rp "$(L '分享链接用的公网地址（当前') ${XRAY_PUBLIC_HOST:-$(L '未设置')}$(L '）:') " ans || { [ -n "$ans" ] || return 1; }
    if [[ -z "$ans" || ! "$ans" =~ $hostre ]]; then
        warn "$(L '未修改（为空或格式不合法）')"
        return 0
    fi
    if check_public_host "$ans" || confirm "$(L '仍要使用这个地址？')" n; then
        XRAY_PUBLIC_HOST="$ans"; xray_save_state; success "$(L '已更新')"
        xray_sync_reality_snis || true
    else
        warn "$(L '未修改')"
    fi
    return 0
}

xray_uninstall() {
    if [ ! -x "$XRAY_BIN" ] && [ ! -f "$XRAY_SERVICE" ]; then info "$(L '未检测到本模块安装的 Xray')"; return 0; fi
    local specs _xray_had_80=0 _rm_fw=0
    confirm "$(L '确认卸载 Xray（本模块安装的 adam-xray）？')" n || { info "$(L '已取消')"; return 0; }
    specs="$(xray_ports | tr '\n' ' ')"
    xray_needs_port80 2>/dev/null && _xray_had_80=1
    systemctl disable --now adam-xray >/dev/null 2>&1 || true
    rm -f "$XRAY_SERVICE"
    rm -rf "$XRAY_DIR"
    systemctl daemon-reload
    if [ -n "${specs// /}" ] && ufw_installed; then
        if confirm "$(L '同时删除防火墙里这些节点端口的放行规则（')${specs}$(L '）？')" y; then
            _rm_fw=1
            fw_prune_old_specs "$specs"
        fi
    fi
    if confirm "$(L '同时删除全部节点配置') ${XRAY_CONF_DIR}$(L '（含密钥）？')" n; then
        rm -rf "$XRAY_CONF_DIR"
        userdel adam-xray >/dev/null 2>&1 || true
        # 节点已全删：域名证书流程留下的凭证与续期任务一并清理（保留配置时不动，节点重装后仍需续期）
        if [ -f /etc/cloudflare/credentials.ini ]; then
            if [ -f "$CONFIG_FILE" ] && grep -q 'CERT_METHOD_VALUE="cloudflare-dns"' "$CONFIG_FILE" 2>/dev/null; then
                warn "$(L 'Cloudflare 凭证仍被 Nowhere 使用（域名证书续期），未删除')"
            elif confirm "$(L '删除保存的 Cloudflare API 凭证（/etc/cloudflare/credentials.ini）？')" n; then
                rm -f /etc/cloudflare/credentials.ini
                info "$(L '已删除 Cloudflare 凭证')"
            fi
        fi
        # 仅在 Nowhere 未依赖 certbot 续期时才移除 certbot renew --quiet 兜底 cron
        if [ ! -x /etc/letsencrypt/renewal-hooks/deploy/restart-nowhere.sh ] && crontab -l 2>/dev/null | awk '/certbot renew --quiet$/{f=1} END{exit !f}'; then
            (crontab -l 2>/dev/null | grep -v 'certbot renew --quiet$' || true) | crontab - 2>/dev/null || true
            info "$(L '已移除 Xray 的 certbot 续期 cron 任务')"
        fi
        # v8.6（R2-BUG-06）：仅当 Xray 确实使用过 HTTP-01（80 端口）且未与其他服务共用时才收回 80/tcp
        if [ "$_xray_had_80" = "1" ] && [ "$_rm_fw" = "1" ] && ufw_installed && ! port_used_by_other_services "80/tcp" xray; then
            ufw delete allow 80/tcp >/dev/null 2>&1 || true
        fi
    else
        info "$(L '已保留') ${XRAY_CONF_DIR}$(L '，重装后节点可直接恢复')"
    fi
    reserved_ports_sync || true
    success "$(L 'Xray 已卸载')"
    return 0
}

xray_state_text() {
    local v fwd
    if [ ! -x "$XRAY_BIN" ]; then printf '%s' "${YELLOW}$(L '未安装')${NC}"; return 0; fi
    v="$(xray_installed_version)"
    fwd="$(xray_fwd_enabled_count)"
    if [ "$(xray_node_count)" -eq 0 ] && [ "$fwd" -eq 0 ]; then
        printf '%s' "${v:-$(L '版本未知')} · ${YELLOW}$(L '无节点')${NC}"
    else
        local fwd_txt=""
        [ "$fwd" -gt 0 ] && fwd_txt=" · ${fwd} $(L '条转发规则')"
        printf '%s' "${v:-$(L '版本未知')} · $(xray_node_count) $(L '个节点')${fwd_txt} · $(svc_state adam-xray)"
    fi
}

xray_menu() {
    local choice
    while true; do
        clear 2>/dev/null || true
        xray_load_state
        echo -e "${BOLD}${CYAN}━━━ $(L 'Xray 管理（SS / VLESS）') ━━━${NC}"
        echo -e "  $(L '当前状态:') $(xray_state_text)    $(L '通道:') ${XRAY_CHANNEL}    $(L '自动更新:') $(maint_onoff "$XRAY_AUTO_UPDATE")    $(L '大陆拦截:') $([ "${XRAY_CN_BLOCK:-1}" = "1" ] && echo "$(L '开')" || echo "$(L '关')")"
        divider
        echo -e "  ${GREEN}1)${NC}  ${GREEN}$(L '安装')${NC} $(L '/ 重装 Xray 内核（选择通道：最新预发布 / 正式版 / 指定版本）')"
        echo -e "  ${GREEN}2)${NC}  ${GREEN}$(L '添加节点')${NC}$(L '（REALITY Vision / XHTTP REALITY / XHTTP CDN / XHTTP TLS / VLESS Encryption / SS2022）')"
        echo -e "  ${GREEN}3)${NC}  $(L '节点列表')"
        echo -e "  ${GREEN}4)${NC}  $(L '查看节点配置 / 分享链接')"
        echo -e "  ${GREEN}5)${NC}  ${RED}$(L '删除节点')${NC}"
        echo -e "  ${GREEN}6)${NC}  $(L '检查并更新内核')"
        echo -e "  ${GREEN}7)${NC}  $(L '自动更新 开 / 关')"
        echo -e "  ${GREEN}8)${NC}  $(L '健康检查（只检测）')"
        echo -e "  ${GREEN}9)${NC}  $(L '一键修复')"
        echo -e "  ${GREEN}10)${NC} $(L '服务状态')"
        echo -e "  ${GREEN}11)${NC} $(L '实时日志')"
        echo -e "  ${GREEN}12)${NC} $(L '重启服务')"
        echo -e "  ${GREEN}13)${NC} $(L '修改分享链接用的公网地址')"
        echo -e "  ${GREEN}14)${NC} ${RED}$(L '卸载')${NC} Xray"
        echo -e "  ${GREEN}15)${NC} $(L '大陆流量拦截（geoip:cn / geosite:cn → 拦截）开 / 关')"
        echo -e "  ${GREEN}16)${NC} $(L '端口转发（dokodemo-door）')"
        echo -e "  ${GREEN}17)${NC} $(L '编辑 / 热轮换节点（换 SNI / 轮换 shortId / 换指纹 / 换端口）')"
        echo -e "  ${GREEN}0)${NC}  $(L '返回主菜单')"
        divider
        read -rp "$(L '请选择') [0-17]: " choice || return 0
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
            15) run_action xray_cnblock ;;
            16) run_action xray_fwd_menu ;;
            17) run_action xray_edit_node ;;
            0)  return 0 ;;
            *)  warn "$(L '无效选择')" ;;
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
        edit)         xray_edit_node "${1:-}" ;;
        list)         xray_list_nodes ;;
        links|config) xray_show_links ;;
        delete|del)   xray_delete_node ;;
        update)       xray_update ;;
        health)       xray_health_check ;;
        repair)       xray_repair ;;
        status)       xray_status ;;
        logs)         xray_logs ;;
        restart)      xray_restart ;;
        cnblock)      xray_cnblock "$@" ;;
        fwd)          xray_fwd_cli "$@" ;;
        uninstall)    xray_uninstall ;;
        *) error "$(L '未知的 xray 子命令:') ${sub}$(L '（可用: install / add / edit / list / links / delete / update / health / repair / status / logs / restart / cnblock / fwd / uninstall）')" ;;
    esac
}

