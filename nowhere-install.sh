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
#   ── 脚本 v4.3 修订（2026-11-17）──
#     - Snell 支持多端口：Snell 菜单 12 新增端口配置（每个端口独立 PSK / mode，由 snell-port@端口 实例承载）、
#       菜单 13 删除任意一个端口配置（删主端口时由一个附加端口接替为主配置；只剩一份时等同卸载）。
#       附加端口同样纳入防火墙放行、内核保留端口、保活巡检、健康检查、版本升级与回滚。
#   ── 脚本 v4.4 修订（2026-11-17，跟随 Nowhere v3.3.0，协议线仍为 NW3）──
#     回归修复：
#     - 补回 NOW_HANDSHAKE_TIMEOUT（v3.3 脚本已有、v4.3 丢失）：v3.3.0 起未设置时
#       超时从 Shared Key 派生（3–30s，换密钥会变），现向导默认显式 10s，写进 Portal
#       unit、Vector/Egress 启动命令、probe 导出、Egress 安装 unit（egress.env）与旧配置恢复，
#       格式校验 validate_duration（正数+单位，如 10s/500ms/1m/1h，非法重置 10s）。
#     tls=1 证书保持（tls=1 证书只在内存、无文件可续期，指纹每次重启都变）：
#     - 新增 save_current_pin：重启/查看连接信息/保活拉起后，把当前指纹写进
#       /etc/nowhere/tls-pin.txt（600 权限，含更新时间），不再只口头提醒；
#       config.txt 仍每次按最新 pin 重新生成；tls=2 走系统 CA 校验，不靠 pin，不受影响。
#     - Nowhere 菜单新增 17「tls=1 升级为真实证书 (tls=2)」：HTTP-01 / Cloudflare
#       DNS-01 两路复用现有 certbot 校验与续期链路，成功后原地改写配置与 unit 并重启、
#       重新生成连接信息；通用 DNS-01（acme.sh）仍走菜单 3 重新配置。
#     保活与维护：
#     - 保活新增 nowhere_healthy：Egress 只看 active；Portal 要求 active 且全部已配
#       载体端口真实在监听（旧逻辑只看 active，端口掉了也判健康）。
#     - 每日定时重启补上 Nowhere（旧逻辑只重启 Snell / Xray），重启后 tls=1 自动刷新 pin 文件。
#     - 自动维护菜单新增：备份全部配置、恢复配置、一键诊断 doctor、清理 journal 日志
#       （保留 200M）；备份为 /root/adam-backup-<时间>.tgz（600 权限，只留最近 5 份，含密钥仅放本地）。
#     中英文切换：
#     - 新增 ADAM_LANG（zh/en，默认 zh，存 /etc/adam/lang，环境变量 ADAM_LANG 可临时覆盖），
#       adam lang [zh|en] 切换、脚本更新菜单也有入口；L() 按词条翻译，缺词条回退中文。
#       已覆盖：主菜单、Nowhere/脚本更新/自动维护菜单、usage、通用提示、安装向导关键提问；
#       Snell / Xray / 防火墙 / Fail2ban / 调优子菜单的深层文案仍为中文，v4.5 已全部补齐。
#   ── 脚本 v4.5 修订（2026-11-17，全翻译）──
#     - 全翻译：L() 词典由约 110 条扩到约 1500 条，覆盖全部菜单、向导提问、状态与
#       提示、Snell / Xray / 防火墙 / Fail2ban / 调优子菜单、usage、连接信息与 config.txt。
#       info/success/warn/error/step 本就整句过 L，现所有中文片段也逐段过 L；未命中词条
#       回退中文，不会丢字。i18n 函数名仍为 L()（v4.4 已由 tr() 改名，避免遮蔽系统 tr 命令）。
#     - 安装开始即选语言：do_install 第 0 步先问 1) 中文 2) English（默认当前语言），
#       选完立即生效并持久化；首次打开主菜单且未存过语言时也会先问一次。adam lang zh|en 不变。
#   ── 脚本 v4.6 修订（2026-11-17）──
#     - 主菜单不再显示管理脚本版本：该行改为当前时间 + 公网 IP（时间取 date，
#       IP 复用 detect_public_host；同一进程内只探测一次，避免每次刷新菜单都等网络，
#       取不到显示未知）。版本号仍在「脚本更新」菜单与 adam version 里看。
#   ── 脚本 v8.5 修订（2026-11-23，全面深审修复 + 协议自动更新 + Realm 多转发增强 + 一键域名反代）──
#     修复（全文件深审）：
#     - do_restore：修复 tr -d ' \\r\\n' 误删 portal 里的字母 r 导致备份恢复必报角色不一致；
#     - Xray 端口转发路由：00-base.json 为所有已启用的 fwd-* 入站注入最高优先级 direct 路由，
#       解决转发到 VPC 内网 IP（geoip:private）或国内中转（geoip:cn）被全局黑洞阻断的问题；
#       dokodemo-door 自动剥离 IPv6 目标地址方括号；xray_ports 不再因节点目录不存在而跳过转发端口；
#       xray_install / xray_upgrade_to 同步统计纯转发场景的配置校验与重启；
#     - Xray 自动更新：解除主版本号锁死（Xray 采用 CalVer v26→v27），避免跨年自动更新停摆；
#     - set -e 陷阱：修复 snell_autoupdate / xray_autoupdate 的 autoupdate_check 返回值捕获，
#       以及 parse_egress_url 缺少可选 query 参数时触发 set -e 提前退出的问题；
#     - Nowhere 低权证书续期：sync_portal_cert_copy 不再覆写源路径 CRT/KEY_PEM，改用独立运行时路径
#       CRT_RUNTIME/KEY_PEM_RUNTIME，彻底修复每日同步与 acme.sh cert-sync.sh 自己比对/拷贝自己的问题；
#     - Certbot pre/post 钩子与卸载：仅 HTTP-01 且 nowhere 实际占用 80 端口时才停机（DNS-01 不再无故停机）；
#       HTTP-01 的 80 端口占用检查移入 obtain_portal_cert（已有有效证书时不再误拦）；
#       修复 do_uninstall 先删 restart-nowhere.sh 再判存在的死分支，并清理 pre/post 与 cert-sync.sh；
#     - Egress 粘贴串：egress_query_param 新增 urldecode（修复 IPv6 dial/dial6 误报），清洗后重建 eg_url；
#     - 端口占用检测：check_port_occupied_by_other 支持自定义排除进程名，Realm / Xray 转发与 SS2022 UDP
#       分别精准检测冲突并防止同模块重复监听；realm_uninstall_do 保留配置时正确清理防火墙规则；
#     - 其他修复：version_ge 预发布号自然排序（b10 >= b2）；do_install 双栈同时校验 TCP+UDP 监听与确认页
#       展示握手超时；do_doctor 修正 Snell -v 检测与明文 CDN 节点误报；services_adapt_ipv6 同步适配
#       Realm 与 Xray 转发监听地址；L() 1850+ 词条改用 Bash 关联数组按需懒加载（中文模式零开销）。
#     增强：
#     - 全协议官方仓库自动更新：新增 Nowhere（NW3 同代安全更新）与 Realm 官方仓库自动更新，与 Snell /
#       Xray / Caddy / cloudflared 一并纳入每日自动维护与自动回滚体系；Xray 节点严格校验随机密钥非空，
#       CDN 分享链接默认 mode=packet-up 提升过 Cloudflare 连通率；
#     - Realm 多转发深度增强（参考 zhboner/realm 与 zywe03/realm-xwPF）：新增端口段/多端口批量添加、
#       编辑已有规则（失败自动回滚）、多目标（含 extra_remotes）全量延迟测试、WSS 自定义证书、
#       查看渲染后的完整 TOML 与全局网络/DNS 调优；
#     - 新增一键域名反代模块（主菜单 10 / adam proxy / adam caddy / adam tunnel）：集成 Caddy 多域名
#       自动 HTTPS 反代（多预设模板、caddy validate 校验撤回、零停机重载）与 Cloudflare Tunnel（Token
#       持久化 systemd 隧道 + 临时快速隧道），完整接入防火墙、保活、备份、恢复、诊断与中英双语。
#   ── 脚本 v8.4 修订（2026-11-19，新增 Realm 与 Xray 端口转发）──
#     - 新增 Realm 端口转发（参考 zywe03/realm-xwPF）：目录模式 realm -c /etc/adam-realm/conf.d，
#       规则存 /etc/adam-realm/rules/<id>.env，渲染为 conf.d/rule-<id>.toml；主菜单 9 与 adam realm 子命令；
#       支持 TCP/UDP/双栈、多目标负载均衡（extra_remotes + roundrobin/iphash 权重）、WS/TLS/WSS 双端隧道、
#       指定出/入网卡与源 IP、Proxy Protocol v2、MPTCP；二进制走 zhboner/realm 官方 release（musl 优先，
#       SHA256 digest 校验，失败换另一 libc 构建），服务以 adam-realm 专用用户运行（失败回退 root），
#       零规则时自动停用服务；备份/恢复/卸载/保活/诊断均已接入。
#     - 新增 Xray 端口转发（3x-ui 式 dokodemo-door）：规则存 /etc/adam-xray/forward/fXX.env，渲染为
#       conf.d/20-forward.json（单个文件含全部已启用规则的 inbounds），Xray 菜单 16 与 adam xray fwd 子命令；
#       无启用规则时删除该文件；重载失败用 .bak 恢复并再次重载；转发端口纳入 xray_ports（防火墙、
#       内核保留端口、健康检查、卸载清理自动覆盖）。
#     - 协同修正：xray_reload 仅在节点与转发规则都为零时停服务；xray_healthy 补 UDP 监听检查
#       （此前只查 TCP，ss2022 与转发规则的 UDP 端口掉了也判健康）；xray 健康检查与状态行补转发规则。
#     - 稳健性：全部新增 read 加 EOF 守卫；TOML 渲染走 mktemp+mv 原子写并转义注入字符；导入备份只允许
#       etc/adam-realm/** 成员；端口冲突检测复用 check_port_occupied_by_other（排除自身进程）。
#     - 词典：新增 159 条、删 7 条失效旧 key；词典现 1834 key、0 重复、0 缺失。
#     - 未做：Realm 自动更新（手动更新即可）；真机测试（服务启动、转发连通性待实测）。
#   ── 脚本 v10 修订（2026-11-19，审计打磨：Adam 前半段审计 14 项全部落地）──
#     - 版本号与修订记录重新同步：SCRIPT_VERSION 由 v8.2 升为 v10（此前修订记录已到
#       v9/v8.3 但版本号仍停 v8.2，同一版本号对应两份内容会让自动维护的防降级保护失效，
#       菜单也无法区分修复版与旧版）。
#     - 证书：域名统一转小写再比对 SAN/CN（cert_covers_domain、cert_is_valid），
#       do_install / do_migrate_tls2 / Xray 域名证书节点读入域名时即转小写。
#     - 端口检测：第 9 步改用 check_port_occupied_by_other（awk 只比对 ss 第 4 列端口），
#       不再误命中 IPv6 地址段。
#     - 链接：build_client_links / build_probe_vector_url 公网地址为空时中止，不再生成
#       @:端口 的坏链接。
#     - Egress 粘贴连接串：补解析 sni/pin/dial/dial4/dial6/rate/etar，粘贴后也问握手超时，
#       eg_handshake 声明为 local（同一进程内多次安装不再沿用旧值），不再静默落回 10s。
#     - Cloudflare 凭证：抽出 prompt_cloudflare_creds / write_cloudflare_creds 供
#       do_migrate_tls2 与 Xray 域名证书流程共用（显式问 Token/Global Key，不再按长度猜测；
#       Token 不再强制填邮箱）；抽出 write_portal_env 供 do_install 与 do_migrate_tls2
#       共用（整文件重写 + dq_escape，替代 _mig_set 的逐行 sed）。
#     - 卸载：do_uninstall 删 Cloudflare 凭证前检查 Xray xhttp-tls 节点是否依赖；快捷命令
#       删除提示补 Xray。
#     - 防火墙：第 5 步不再强装 ufw（firewalld/cnblock 在运行时跳过并警告），依赖改走
#       apt_install；fw_is_allowed 能识别服务名与 from/to 规则。
#     - 指纹：get_tls_fingerprint 单次展示流程内缓存（_CACHED_TLS_FP），重启/换版/迁移/
#       回退时清空，避免 4 次调用叠加 24-32 秒卡顿。
#     - 回退：do_rollback 版本文件只写实测版本号（不再写本地化文案），临时文件改走
#       make_workdir，stop->替换->start 改为 install->restart，关键步失败即中止不半交换。
#     - Fail2ban：f2b_pick_banaction 先验证 iptables -L -n 是否真能执行，否则用 nftables。
#     - gai.conf：ensure_ipv4_preference 改动前先备份到 $GAI_BACKUP（不存在时建 .absent
#       标记），调优菜单恢复可用。
#     - 最小权限：Portal 新装/重配默认以专用低权用户 nowhere 运行（User=/Group=），tls=2
#       证书同步为服务可读副本（续期 hook 自动重同步）；任一步失败回退 root，启动失败也
#       自动回退（证书副本 root 仍可读，不影响回退）。
#     - 后半段深审（Fail2ban 余部 / Snell / Xray / 调优 / 自动维护）：脚本自更新
#       do_update_script 复用 script_fetch_remote（缓存击穿 + 完整性校验）并加防降级
#       拒绝（此前只在版本号相等时确认，远端更低会静默降级）；Xray 重装每次按当前
#       XRAY_CN_BLOCK 重写 00-base.json（不再只在文件不存在时写，避免开关与文件脱节）；
#       重装前先用新内核校验现有配置（与 xray_upgrade_to 一致），启动失败回滚到 .previous；
#       stable 通道在 GitHub API 限流时接受 atom 兜底的未知标记发布并警告（此前全灭）；
#       Snell 分享行补空地址拦截；健康检查不再 fail-open（ss 缺失 / 端口取不到时报不健康，
#       UDP 监听改 awk 精确比对端口）；CDN 节点客户端端口加 1-65535 校验；Xray 卸载删节点
#       配置时一并清理 Cloudflare 凭证（Nowhere 仍用则保留）、certbot 续期 cron 与 80 端口；
#       创建 Xray 证书节点不再删掉 Nowhere 的 deploy-hook 续期行；services_adapt_ipv6
#       改 Xray 监听地址后先校验、不通过恢复原文件；ip_priority_set 原地改两条 precedence
#       行（不再整文件重写丢掉其他条目）；健康检查补 xhttp-tls 证书剩余天数；证书同步同时
#       比对密钥文件、失败警告；DNS 回退保留 1.1.1.1/8.8.8.8；恢复备份先校验 tar 成员路径；
#       Snell 探测临时文件改走 make_workdir；Xray 域名证书 DNS-01/已有文件方式也做 DNS
#       预检；snell_ver_gt 解析失败不再 fail-open；交互输入循环在 stdin EOF 时退出
#       （不再空转）；菜单 2 补 XHTTP TLS 类型。
#   ── 脚本 v8.3 修订（2026-11-19，三批审计打磨，版本号由 v10 改回 8.3）──
#     - 前两批已落地：High（H1–H14）、Medium（M1–M21 与 U1/U3）；本批为 Low（L1–L29）与词典清理。
#     - 稳健性：端口校验先做 10# 规范化（08/09 不再按八进制解析）；证书选择无效输入循环重问；
#       DNS 服务商选了不支持项当场中止；维护锁拿不到返回 1 并记日志、失败时释放 fd，调用方跳过
#       本次运行并记日志（同 fd 9 已持锁时仍可重入）；回滚前先试运行备份二进制；TERM/HUP 只做
#       最小清理；向导的交互 read 统一加 EOF 守卫；循环的未引用展开改 while read 或先读入数组。
#     - 正确性：Xray 安装/升级校验时 XRAY_LOCATION_ASSET 改指 XRAY_DIR（geo 数据所在地）；
#       Xray 健康检查补 ss2022 节点的 UDP 监听与 UDP 防火墙检查；删防火墙规则时范围类规则先解
#       析起止端口、含 SSH 端口按 SSH 规则处理；80/tcp 只在仍有服务需要时保留（Xray HTTP-01
#       续期也算）；do_install 不再重复调 systemctl is-active；每日维护合并 Xray 存在性检查。
#     - 可观测性：保活未开启时健康检查的保活项降为提示级；doctor 补 Xray 各节点证书剩余天数
#       与 ufw 摘要、ss 缺失时明说工具缺失；移除定时器前警告证书同步将停止；Fail2ban 卸载选项
#       1 重启后校验 fail2ban-client status；续期 hook 里证书拷贝失败记日志并跳过重启；
#       SHA256 校验被跳过时改为醒目提示；版本列表 curl 加 -f、空列表提示可能被限流。
#     - 清理：删无调用的 validate_nonneg_int；Snell 写配置失败清理临时文件；备份轮转改
#       xargs -r -0；xray_cnblock 的 geo 缺失分支也重写基础配置；rm -rf 前校验 tag；
#       nowhere_menu 17 号项在 tls=2 时标注已是 tls=2。L16、L22 跳过（见下）。
#     - 词典：补 19 个缺失 key（含调用点拆成 L '，' + L '本机公网 IP：'，复用已有 key），
#       删 41 个无调用的死 key；词典现 1682 key、0 重复。
#     - 跳过：L16（收益有限）；L22（不加 set -u：全文件 1 万多行，需先过一遍 ${VAR:-}
#       覆盖，风险大于收益）。
#   ── 脚本 v8.2 修订（2026-11-19，REALITY 域名地址握手失败修复）──
#     - 根因：域名作 server 地址时客户端握手用的 SNI 是该域名，而服务端 REALITY 的
#       serverNames 只有伪装站点，服务端认不出客户端、转发到伪装站回了真证书，客户端
#       报 REALITY authentication failed；IP 作地址时客户端用伪装站点 SNI，所以能通。
#     - 修复：新建 REALITY 节点时 serverNames 同时写入伪装站点 + 当前域名地址；菜单 13
#       改地址与每日维护时同步全部 REALITY 节点的 serverNames（改回 IP 时自动去掉域名）。
#     - 域名仍须解析到本机 IP（菜单 13 的校验不变）；若客户端侧 DNS 把域名解析到别处，
#       仍会连到错误的服务器，与 serverNames 无关。
#   ── 脚本 v9 修订（2026-11-19，修三处实装反馈）──
#     - adam 快捷命令：install_shortcuts 失败曾被 || true 静默吞掉（管道安装且新版未推
#       GitHub 时 ensure_manager_copy 下载 404 即无快捷命令）；现快捷壳先校验管理脚本副本
#       在位、缺失时给修复命令，安装/重配结束 verify_shortcuts 再验一次，doctor 也查。
#     - Xray 分享链接地址：detect_public_host 的 hostname -I 兜底曾直接取首地址（常为内
#       网 IP），现只取公网 IP、取不到返回空；安装提示与菜单 13 改地址时校验：IP 须为公
#       网 IP、域名须能解析且解析到本机公网 IP，否则警告并由用户确认是否仍用；地址为空
#       时不再生成 @:端口 的坏链接。
#     - Xray 路由：00-base.json 补 geoip:cn / geosite:cn → block（默认开），缺 geo 数据
#       时自动从官方 release 下载，下载失败则不开启；Xray 菜单 15 与 xray cnblock [on|off]
#       可开关（状态存 XRAY_CN_BLOCK）。
#   ── 脚本 v8.3 修订（2026-11-19，新增 Xray 直连域名证书节点）──
#     - 新增节点类型 6) VLESS + XHTTP + TLS（直连域名证书）：域名申请 Let's Encrypt
#       证书（复用 Nowhere 的 certbot HTTP-01 / Cloudflare DNS-01 流程；同一域名已有
#       有效证书时直接复用；已有证书文件也可直接用），续期由每日维护 xray_sync_certs
#       同步并重启 Xray。
#     - IP 选项保留：同一节点两种连法——分享链接地址用域名或本机 IP 均可（TLS 只验证
#       SNI=域名），菜单 13 切换地址；节点详情同时给出另一地址的备用链接。
#     - 直接节点（REALITY / VLESS Encryption / SS）本来就不需要域名证书：server 地址
#       只是 TCP 目标，域名不通是 DNS 没解析到本机 IP，与证书无关。
#   ── 脚本 v4.2 修订（2026-11-16）──
#     - 主菜单重排为两组八项：协议安装（1 Nowhere / 2 Snell / 3 Xray）与系统管理（4 脚本更新 / 5 防火墙 /
#       6 Fail2ban / 7 系统调优 / 8 自动维护）。原主菜单的 17 项 Nowhere 功能收进 Nowhere 子菜单并按
#       安装与配置 / 运行与排查 / 证书 / 版本分组；「重装快捷命令」移到脚本更新。上面修订说明里的
#       "菜单 17/18/19…" 是当时的编号。命令行子命令与 zt / pz / cxpz / cq 不变。
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
SCRIPT_VERSION="8.5"   # 本管理脚本自身的修订版本（与 Nowhere 版本号相互独立）
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
TLS_PIN_FILE="${CONFIG_DIR}/tls-pin.txt"   # tls=1 当前指纹（每次重启都变），由 save_current_pin 维护
ROLE_FILE="${CONFIG_DIR}/role"   # 本机 nowhere.service 的角色：portal / egress
MORPH_UDP_PRELUDE="fade"  # NOW_MORPH_UDP_PRELUDE（v3.3.0 新增）：fade/full8/low7，仅 Morph QUIC 发起端使用
HANDSHAKE_TIMEOUT="10s"   # NOW_HANDSHAKE_TIMEOUT：持续时间格式（如 10s/500ms/1m/1h）；v3.3.0 起未设置时从 Shared Key 派生 3s–30s，显式设置可固定行为；官方未公开旧固定默认值，此处取 10s 为显式固定值
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
SNELL_PORTS_DIR="${SNELL_DIR}/ports"   # 附加端口配置：<端口>.conf，由 snell-port@<端口> 实例承载
SNELL_PORT_UNIT="/etc/systemd/system/snell-port@.service"
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

# Realm 端口转发（zhboner/realm 官方 release）
REALM_REPO="zhboner/realm"
REALM_BIN="/usr/local/bin/realm"
REALM_BIN_BACKUP="/usr/local/bin/realm.previous"
REALM_DIR="/etc/adam-realm"
REALM_CONF_D="${REALM_DIR}/conf.d"
REALM_CONFIG_FILE="${REALM_DIR}/config.toml"
REALM_RULE_DIR="${REALM_DIR}/rules"
REALM_VERSION_FILE="${REALM_DIR}/version.txt"
REALM_SERVICE="/etc/systemd/system/adam-realm.service"
REALM_STATE_FILE="${REALM_DIR}/adam-realm.env"

# 一键域名反代（Caddy 多域名自动 HTTPS + Cloudflare Tunnel）
CADDY_REPO="caddyserver/caddy"
CADDY_BIN="/usr/local/bin/caddy"
CADDY_BIN_BACKUP="/usr/local/bin/caddy.previous"
CADDY_DIR="/etc/adam-caddy"
CADDY_SITES_DIR="${CADDY_DIR}/sites"
CADDY_FILE="${CADDY_DIR}/Caddyfile"
CADDY_STATE_FILE="${CADDY_DIR}/adam-caddy.env"
CADDY_DATA_DIR="/var/lib/adam-caddy"
CADDY_SERVICE="/etc/systemd/system/adam-caddy.service"

CF_TUNNEL_REPO="cloudflare/cloudflared"
CF_TUNNEL_BIN="/usr/local/bin/cloudflared"
CF_TUNNEL_BIN_BACKUP="/usr/local/bin/cloudflared.previous"
CF_TUNNEL_DIR="/etc/adam-cloudflared"
CF_TUNNEL_ENV="${CF_TUNNEL_DIR}/tunnel.env"
CF_TUNNEL_SERVICE="/etc/systemd/system/adam-cloudflared.service"

# Xray 端口转发（dokodemo-door，3x-ui 式 tunnel）
XRAY_FWD_DIR="${XRAY_CONF_DIR}/forward"
XRAY_FWD_JSON="${XRAY_CONF_D}/20-forward.json"

# 自动维护（保活 / 自动更新）
MAINT_DIR="/etc/adam"
MAINT_ENV="${MAINT_DIR}/maintain.env"
MAINT_LOG="/var/log/adam-maintain.log"
LANG_FILE="${MAINT_DIR}/lang"   # 界面语言：zh / en（默认 zh），adam lang 切换
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

info()    { echo -e "${BLUE}[$(L '信息')]${NC} $(L "$1")"; }
success() { echo -e "${GREEN}[$(L '成功')]${NC} $(L "$1")"; }
warn()    { echo -e "${YELLOW}[$(L '警告')]${NC} $(L "$1")"; }
error()   { echo -e "${RED}[$(L '错误')]${NC} $(L "$1")"; exit 1; }
step()    { echo -e "\n${BOLD}${CYAN}━━━ $(L "$1") ━━━${NC}"; }
divider() { echo -e "${CYAN}────────────────────────────────────────────────────────${NC}"; }

# ── 界面语言 v4.4 ────────────────────────────────────────────────
# ADAM_LANG: zh（默认）/ en。优先级：环境变量 ADAM_LANG > /etc/adam/lang > zh。
# L '中文词条'：英文模式且词条在字典里时返回英文，否则原样返回中文。
# 菜单/提示用 $(L '词条')；info/success/warn/error/step 把整句过 L，整句命中
# 词条才翻译（带变量的长句命中不了，原样输出中文，不会翻坏）。
load_lang() {
    # 环境变量只在第一次加载时生效（之后 ADAM_LANG 已是运行期状态，不再当作环境输入，
    # 否则 set_lang 改过的值会在下一次 load_lang 时把文件值盖掉）。
    local env_lang=""
    [ -z "${_ADAM_LANG_LOADED:-}" ] && env_lang="${ADAM_LANG:-}"
    ADAM_LANG="zh"
    if [ -f "$LANG_FILE" ]; then
        read -r ADAM_LANG < "$LANG_FILE" 2>/dev/null || ADAM_LANG="zh"
    fi
    # 环境变量 ADAM_LANG 优先于持久化文件（临时覆盖：ADAM_LANG=en adam）
    [ -n "$env_lang" ] && ADAM_LANG="$env_lang"
    case "$ADAM_LANG" in zh|en) : ;; *) ADAM_LANG="zh" ;; esac
    [ "$ADAM_LANG" = "en" ] && init_i18n_en
    _ADAM_LANG_LOADED=1
}

declare -A I18N=()
_I18N_INIT=0
init_i18n_en() {
    [ "$_I18N_INIT" = "1" ] && return 0
    I18N=(
        ['信息']='INFO'
        ['成功']='OK'
        ['警告']='WARN'
        ['错误']='ERROR'
        ['已取消']='Cancelled'
        ['无效选择']='Invalid choice'
        ['按回车返回菜单...']='Press Enter to return to the menu...'
        ['请选择操作']='Choose an action'
        ['请选择']='Choose'
        ['协议安装']='Protocols'
        ['系统管理']='System'
        ['退出']='Exit'
        ['返回主菜单']='Back to main menu'
        ['安装与配置']='Install & configure'
        ['运行与排查']='Run & diagnose'
        ['证书']='Certificates'
        ['版本']='Versions'
        ['当前状态']='Status'
        ['脚本更新']='Script update'
        ['自动维护']='Auto maintenance'
        ['防火墙']='Firewall'
        ['系统调优']='System tuning'
        ['一键诊断']='One-click diagnostics'
        ['备份配置']='Back up config'
        ['恢复配置']='Restore config'
        ['清理日志']='Clean up logs'
        ['保活巡检定时器']='Watchdog timer'
        ['每日维护定时器']='Daily maintenance timer'
        ['运行中']='running'
        ['未启用']='disabled'
        ['未安装']='not installed'
        ['开']='on'
        ['关']='off'
        ['当前版本']='Current version'
        ['每日自动从仓库更新']='Daily auto-update from repo'
        ['一键管理脚本']='Manager'
        ['调优']='Tuning'
        ['安装、配置、连接信息、证书、版本']='Install, config, links, certs, versions'
        ['安装、跟随测试版更新、健康检查、配置']='Install, beta updates, health check, config'
        ['更新本管理脚本 / 重装快捷命令']='Update manager / reinstall shortcuts'
        ['ufw：安装、放行与删除端口、启停']='ufw: install, allow/remove ports, on/off'
        ['封禁时长、被封 IP、启停']='Ban time, banned IPs, on/off'
        ['TCP 调优 tcpfit / XanMod 内核 / DNS / IPv4·IPv6 优先级 / 禁用 IPv6']='TCP tuning tcpfit / XanMod kernel / DNS / IPv4/IPv6 priority / disable IPv6'
        ['保活巡检 / 脚本与内核自动更新']='Watchdog / auto-update scripts & kernels'
        ['提示：可直接输入']='Tip: run'
        ['唤出此菜单，或用']='for this menu, or use'
        ['快捷执行；']='for shortcuts;'
        ['查看全部子命令']='to see all commands'
        ['安装']='Install'
        ['（向导）']=' (wizard)'
        ['本机安装为 Egress 服务']='Install this machine as Egress'
        ['（出口机用，QUIC 或 TLS 载体）']=' (exit node, QUIC or TLS)'
        ['重新配置']='Reconfigure'
        ['（修改参数）']=' (change settings)'
        ['查看连接信息 / 导入链接']='Show connection info / import links'
        ['生成 v3 共享密钥']='Generate v3 shared key'
        ['（32 位十六进制）']=' (32 hex chars)'
        ['查看服务状态']='Show service status'
        ['（含 nowhere status）']=' (incl. nowhere status)'
        ['查看实时日志']='Show live logs'
        ['重启服务']='Restart service'
        ['连通性探测 probe']='Connectivity probe'
        ['（真实 TCP Flow 测试）']=' (real TCP Flow test)'
        ['查看证书指纹']='Show cert fingerprint'
        ['（tls=1 自签 / tls=2 文件证书）']=' (tls=1 self-signed / tls=2 file cert)'
        ['检查证书状态 / 手动续期']='Check cert status / manual renewal'
        ['查看当前版本 / 检查更新']='Show version / check updates'
        ['更新 Nowhere 二进制']='Update Nowhere binary'
        ['（更新到最新版）']=' (to latest)'
        ['选择指定版本']='Select version'
        ['（版本切换 / 回退到历史版本）']=' (switch / roll back)'
        ['快速回退到上一个版本']='Quick rollback to previous version'
        ['卸载']='Uninstall'
        ['tls=1 升级为真实证书 (tls=2)']='Upgrade tls=1 to a real cert (tls=2)'
        ['立即更新本管理脚本']='Update manager now'
        ['（从仓库拉取）']=' (pull from repo)'
        ['重装快捷命令']='Reinstall shortcuts'
        ['（adam / zt / pz / cxpz / cq）']=' (adam / zt / pz / cxpz / cq)'
        ['语言（中文 / English）']='Language (中文 / English)'
        ['保活巡检（每 5 分钟；服务未运行或端口未监听时自动重启）']='Watchdog (every 5 min; restart when down or port not listening)'
        ['管理脚本自动从仓库拉取更新（每日）']='Daily auto-update of manager from repo'
        ['每日定时重启 Snell / Xray / Nowhere（随每日维护执行）']='Daily scheduled restart of Snell / Xray / Nowhere'
        ['立即执行一次维护与巡检']='Run maintenance & watchdog once now'
        ['查看维护记录']='Show maintenance log'
        ['重装定时器（修复）']='Reinstall timers (repair)'
        ['备份全部配置']='Back up all configs'
        ['恢复配置（从备份文件）']='Restore config (from backup file)'
        ['清理日志（保留 200M）']='Clean up logs (keep 200M)'
        ['用法']='Usage'
        ['主菜单']='Main menu'
        ['回车默认']='Enter for default'
        ['管理']='Management'
        ['不带参数 = 打开主菜单']='Open the main menu when no argument is given'
        ['命令']='command'
        ['切换界面语言']='Switch UI language'
        ['升级为真实证书']='Upgrade to a real certificate'
        ['移除']='Remove '
        ['全部定时器']='all timers'
        ['跟随官方发布自动更新']='Auto-update following official releases'
        ['通道']='channel'
        ['保活巡检']='Watchdog'
        ['端口']='Port'
        ['通道）']='channel)'
        ['请选择:']='Please choose:'
        ['天']='days'
        ['天，域名匹配），跳过申请']='days, domain matches), skipping issuance'
        ['当前版本:']='Current version:'
        ['检测到有效证书（剩余']='Detected a valid certificate (remaining '
        ['证书申请成功']='Certificate issued successfully'
        ['附加端口']='Additional ports'
        ['TCP 端口']='TCP port'
        ['当前状态:']='Current status:'
        ['服务状态']='Service status'
        ['查看连接信息」重试']='view connection info" and retry'
        ['次']='times'
        ['脚本']='script'
        ['Fail2ban 已重启']='Fail2ban restarted'
        ['PSK 不符合要求']='PSK does not meet the requirements'
        ['dial4（IPv4 源地址，回车默认 auto）:']='dial4 (IPv4 source address, Enter = auto):'
        ['dial6（IPv6 源地址，回车默认 auto）:']='dial6 (IPv6 source address, Enter = auto):'
        ['仍要继续？']='Continue anyway?'
        ['保活']='keepalive'
        ['内失败']=', '
        ['域名格式不正确']='Invalid domain format'
        ['安装完成']='Installation complete'
        ['实时日志']='Live logs'
        ['实时日志（Ctrl+C 返回）']='Live logs (Ctrl+C to go back)'
        ['将安装:']='Will install:'
        ['已保留']='Kept'
        ['当前最新版为']='Latest version:'
        ['最新版本:']='Latest version:'
        ['未找到配置文件，请先执行安装']='Config file not found; please install first'
        ['未知']='unknown'
        ['正在获取最新版本号...']='Fetching the latest version...'
        ['确认继续']='Confirm to continue'
        ['端口不合法（1-65535）']='Invalid port (1-65535)'
        ['自动更新:']='Auto-update:'
        ['证书签发后校验未通过，请看上方告警']='Certificate verification failed after issuance; see the warnings above'
        ['输入不合法，未做任何修改']='Invalid input; nothing changed'
        ['随机 PSK 生成失败']='Failed to generate a random PSK'
        ['（当前']=' (current '
        [',端口...']=', ports...'
        ['1-4，默认1']='1-4, default 1'
        ['4=仅IPv4 / 6=仅IPv6 / 回车=不限']='4 = IPv4 only / 6 = IPv6 only / Enter = no limit'
        ['Egress出口机  :']='Egress machine  :'
        ['IP 地址格式不合法:']='Invalid IP address format:'
        ['Morph Prelude 策略']='Morph Prelude policy'
        ['Portal 出口   :']='Portal egress   :'
        ['Portal 地址 :']='Portal address :'
        ['Prelude 策略  :']='Prelude policy  :'
        ['REALITY 密钥生成失败']='Failed to generate the REALITY key'
        ['dial 不是合法 IP 字面量，已重置为 auto']='dial is not a valid IP literal; reset to auto'
        ['dial4 不是合法 IPv4 字面量，已重置为 auto']='dial4 is not a valid IPv4 literal; reset to auto'
        ['tcpfit 子命令']='tcpfit subcommand'
        ['tls=1 升级为真实证书']='Upgrade tls=1 to a real certificate'
        ['tls=1 证书只存在内存中，Nowhere 每次重启后指纹都会变化，pin= 需同步重新生成（Nowhere 菜单 4 或 pz 命令）']='The tls=1 certificate lives only in memory; its fingerprint changes on every Nowhere restart, so pin= must be regenerated in sync (Nowhere menu 4 or the pz command)'
        ['unsafe-raw 为明文传输，确认？']='unsafe-raw sends traffic in plaintext. Confirm?'
        ['unsafe-raw（明文，仅可信内网）']='unsafe-raw (plaintext, trusted internal networks only)'
        ['一键导入深链（手机点击，需 Anywhere 已支持 NW3）：']='One-tap import deep link (tap on your phone; Anywhere must already support NW3):'
        ['下载失败:']='Download failed:'
        ['严格']='strict'
        ['传输模式      :']='Transport mode      :'
        ['依赖安装失败，请检查 apt 源/网络']='Failed to install dependencies; please check your apt sources / network'
        ['保活巡检定时器未运行']='Keepalive watchdog timer is not running'
        ['保活巡检定时器运行中（每 5 分钟）']='Keepalive watchdog timer is running (every 5 minutes)'
        ['停用']='Disable '
        ['健康检查通过']='Health check passed'
        ['健康检查（只检测）']='Health check (check only)'
        ['共享密钥      :']='Shared key      :'
        ['出站源IP      :']='Outbound source IP      :'
        ['删除']='Delete '
        ['删除后可能无法再通过 SSH 登录，确认删除？']='After deletion you may no longer be able to log in via SSH. Confirm deletion?'
        ['升级到']='Upgrade to'
        ['发现']='Found'
        ['启用']='Enable '
        ['启用失败，请查看: ufw status verbose']='Failed to enable; see: ufw status verbose'
        ['回源证书剩余']='Origin certificate remaining'
        ['GitHub API 被限流，取不到预发布标记；stable 通道暂按最新发布继续，请稍后确认是否为正式版']='GitHub API rate-limited, prerelease flag unavailable; stable channel proceeds with the latest release for now, please confirm it is a stable release later'
        ['未能确定公网地址，无法生成 Snell 分享行']='Could not determine the public address, cannot generate the Snell share line'
        ['证书剩余']='Certificate remaining'
        ['证书同步失败']='Certificate sync failed'
        ['备份文件包含非法路径，已中止']='Backup contains an illegal path, aborted'
        ['Cloudflare 凭证仍被 Nowhere 使用（域名证书续期），未删除']='Cloudflare credentials are still used by Nowhere (domain certificate renewal), not deleted'
        ['删除保存的 Cloudflare API 凭证（/etc/cloudflare/credentials.ini）？']='Delete the saved Cloudflare API credentials (/etc/cloudflare/credentials.ini)?'
        ['已删除 Cloudflare 凭证']='Cloudflare credentials deleted'
        ['已移除 Xray 的 certbot 续期 cron 任务']='Xray certbot renewal cron entry removed'
        ['（REALITY Vision / XHTTP REALITY / XHTTP CDN / XHTTP TLS / VLESS Encryption / SS2022）']='(REALITY Vision / XHTTP REALITY / XHTTP CDN / XHTTP TLS / VLESS Encryption / SS2022)'
        ['新内核未通过现有配置校验，保持当前版本不变（上游可能有不兼容改动）']='The new kernel failed the existing config check, keeping the current version (upstream may have incompatible changes)'
        ['现有节点在该版本下未能启动，正在回滚到旧内核']='Existing nodes failed to start with this version, rolling back to the previous kernel'
        ['已回滚到旧内核并重启']='Rolled back to the previous kernel and restarted'
        ['回滚后仍未启动，请查看日志：journalctl -u adam-xray -n 50']='Still not running after rollback, check the logs: journalctl -u adam-xray -n 50'
        ['本地已是仓库最新版本']='Local copy is already the latest from the repo'
        ['Xray 配置改动后校验失败，已恢复原文件']='Xray config failed validation after the change, restored the original files'
        ['端口不合法（1-65535），已用默认 443']='Invalid port (1-65535), using the default 443'
        ['回车保持']='Press Enter to keep'
        ['在手机浏览器打开，自动跳转 Anywhere 导入（需 Anywhere 支持 NW3）：']='Open in your phone browser to auto-jump to Anywhere import (Anywhere must support NW3):'
        ['域名']='Domain'
        ['官方最新:']='Official latest:'
        ['官方有新版本']='A newer official version is available'
        ['已切换到']='Switched to'
        ['已启用']='Enabled'
        ['已回滚，服务恢复运行']='Rolled back; service is running again'
        ['已固定在']='Pinned to'
        ['已安装']='Installed'
        ['已是']='Already'
        ['已是仓库最新（']='Already the latest in the repo ('
        ['已是最新:']='Already the latest:'
        ['已更新:']='Updated:'
        ['已经是最新版本']='Already the latest version'
        ['已设为开机自启']='Set to start on boot'
        ['已跳过']='Skipped'
        ['已重启']='Restarted'
        ['序号无效']='Invalid number'
        ['恢复为修改前    0']='Restore to before changes    0'
        ['放行失败:']='Failed to allow:'
        ['无法获取版本号（GitHub API 与 releases/latest 跳转均失败），请检查网络']='Cannot fetch the version (both the GitHub API and the releases/latest redirect failed); please check the network'
        ['是否改用 dial4/dial6 分别绑定 IPv4/IPv6 目标出站源地址？']='Use dial4/dial6 to bind IPv4/IPv6 outbound source addresses separately?'
        ['更新时间:']='Updated at:'
        ['服务未运行（状态:']='Service not running (status: '
        ['服务运行中（systemd 自动重启次数:']='Service running (systemd auto-restart count: '
        ['未加入内核保留端口']='Not added to kernel reserved ports'
        ['未监听']='Not listening'
        ['格式不合法:']='Invalid format:'
        ['正在查询官方发布 ...']='Querying the official releases ...'
        ['正在监听']='Listening'
        ['没有在监听']='Not listening'
        ['版本     :']='Version     :'
        ['版本通道：']='Version channel:'
        ['生成失败：未能获取到有效的连接参数，可稍后通过Nowhere 菜单「4']='Failed to generate: could not get valid connection parameters; retry later via Nowhere menu "4'
        ['生成（载体']='Generating (carrier'
        ['的配置？（使用该端口的客户端将无法连接）']=' config? (Clients using this port will no longer be able to connect)'
        ['监听     :']='Listening     :'
        ['监听中']='Listening'
        ['目标版本']='Target version'
        ['端口:']='Port:'
        ['端口超出范围:']='Port out of range:'
        ['续期失败，请看上方报错']='Renewal failed; see the error above'
        ['自动更新 :']='Auto-update :'
        ['自动更新已开启（']='Auto-update enabled ('
        ['自动更新未开启']='Auto-update is off'
        ['自定义']='Custom'
        ['节点']='Node'
        ['解压失败']='Extraction failed'
        ['证书已过期']='Certificate expired'
        ['证书申请失败，请检查：1']='Certificate issuance failed; please check: 1'
        ['证书签发后校验未通过']='Certificate verification failed after issuance'
        ['说明：']='Note:'
        ['输入不合法（须为 0..2147483647 的整数），重置为0']='Invalid input (must be an integer in 0..2147483647); reset to 0'
        ['输入不合法，重置为 0']='Invalid input; reset to 0'
        ['连接串：']='Connection string:'
        ['选择:']='Select:'
        ['通道:']='Channel:'
        ['通道最新版本']='Latest version on this channel'
        ['通道有 v']='Channel has v'
        ['链接：']='Link:'
        ['防火墙未放行']='Firewall has not allowed it'
        ['项问题，可用「一键修复」处理']=' issue(s); use "One-click repair"'
        ['（暂无记录）']='(no records yet)'
        ['（适配 Nowhere']=' (for Nowhere '
        ['，不自动更新']=', no auto-update'
        ['，实际']=', actual '
        ['，开始更新']=', updating now'
        ['.bak），重新运行 adam 生效']='.bak), re-run adam to take effect'
        ['.conf、jail.local 之后，同名项以这里为准。']='.conf and jail.local; same-named items here take precedence.'
        ['.dgst，为安全起见中止']='.dgst; aborted for safety'
        ['.local：读取顺序在 jail.conf、jail.d/']='.local: read order is after jail.conf and jail.d/'
        ['/boot 可用空间只有']='/boot has only '
        ['/etc/resolv.conf 被加了不可修改属性（chattr +i）—— 通常是 cnblock 的 DNS 黑洞在接管解析']='/etc/resolv.conf has the immutable attribute (chattr +i) — usually cnblock'\''s DNS blackhole has taken over resolution'
        ['/tcpfit.sh），请检查到 GitHub 的网络']='/tcpfit.sh); please check the network to GitHub'
        ['1-5，默认1']='1-5, default 1'
        ['1/2/3/4，默认4']='1/2/3/4, default 4'
        ['1/2，回车取消']='1/2, Enter to cancel'
        ['1/2，默认']='1/2, default '
        ['2022-blake3-aes-128-gcm（默认）  2']='2022-blake3-aes-128-gcm (default)  2'
        ['3 秒后重启 ...']='Restarting in 3 seconds ...'
        ['300 MB），装新内核可能失败，请先清理旧内核']='300 MB); installing a new kernel may fail, please clean up old kernels first'
        ['80 端口是否对外开放 3']='Is port 80 open to the outside? 3'
        [':443（推荐）']=':443 (recommended)'
        ['>，如 adam fw allow 443/tcp,8000-8100']='>, e.g. adam fw allow 443/tcp,8000-8100'
        ['ACME 邮箱（Let']='ACME email (Let'
        ['ALPN   : nw3（v3 固定，不可改，App 内无需/无法填写 alpn 时忽略此项）']='ALPN   : nw3 (fixed in v3, cannot be changed; ignore this if the app does not need/cannot fill in alpn)'
        ['ARM 机器的发行版内核自带 BBR + fq，直接用「1']='ARM machines ship BBR + fq in the distro kernel; just use "1'
        ['Anywhere/第三方客户端无法与本服务端互通，升级需整条链路一起升。']='Anywhere/third-party clients cannot talk to this server; upgrades must cover the whole chain together.'
        ['CDN 回源方式：']='CDN origin-pull method:'
        ['CDN 域名:']='CDN domain:'
        ['CF API Key/Token 是否正确 2']='Is the CF API Key/Token correct? 2'
        ['CPU 指令集等级: x86-64-v']='CPU instruction level: x86-64-v'
        ['Cloudflare + Google（1.1.1.1 / 8.8.8.8，含 IPv6）']='Cloudflare + Google (1.1.1.1 / 8.8.8.8, incl. IPv6)'
        ['Cloudflare API Key（输入不回显）:']='Cloudflare API Key (input hidden):'
        ['Cloudflare API Token（建议）或 Global API Key（输入不回显）:']='Cloudflare API Token (recommended) or Global API Key (input hidden):'
        ['Cloudflare DNS-01 - 需要 CF API Key/Token（自动续期，推荐；80 端口可不开）']='Cloudflare DNS-01 - needs a CF API Key/Token (auto-renewal, recommended; port 80 may stay closed)'
        ['Cloudflare DNS-01 - 需要 CF API Key（自动续期，推荐）']='Cloudflare DNS-01 - needs a CF API Key (auto-renewal, recommended)'
        ['DNS 偏好 :']='DNS preference :'
        ['DNS 服务商：']='DNS provider:'
        ['DNS 设置（查看 / 修改 / 恢复）']='DNS settings (view / change / restore)'
        ['DNS 预检通过：']='DNS pre-check passed:'
        ['DNSPod Token（输入不回显）:']='DNSPod Token (input hidden):'
        ['Egress dial 不是合法 IP 字面量，已重置为 auto']='Egress dial is not a valid IP literal; reset to auto'
        ['Egress dial4 不是合法 IPv4 字面量，已重置为 auto']='Egress dial4 is not a valid IPv4 literal; reset to auto'
        ['Egress dial6 不是合法 IPv6 字面量（IPv4-mapped 地址不被 v3 接受），已重置为 auto']='Egress dial6 is not a valid IPv6 literal (IPv4-mapped addresses are not accepted by v3); reset to auto'
        ['Egress 到目标的出站源 IP dial（回车默认 auto，只影响目标连接，不影响回连 Portal）:']='Egress outbound source IP dial to the target (Enter = auto; only affects target connections, not the return link to the Portal):'
        ['Egress 回连载体（v3.3.0 起两种都可用；一个连接串只选一种，多台出口机可以混用）']='Egress return carrier (both work since v3.3.0; one connection string uses one carrier, different exit machines may mix them)'
        ['Egress 服务已启动（注册结果请看日志：ACCEPTED 为成功；BUSY 表示 Portal 的待命注册容量已满（主要出现在 TLS 载体），本机会自动重试）']='Egress service started (check the log for the registration result: ACCEPTED = success; BUSY = the Portal'\''s standby registration capacity is full (mainly on TLS carriers); this machine will retry automatically)'
        ['Egress 服务未能启动，日志如下：']='Egress service failed to start; log:'
        ['Egress 端出站源 IP dial（在出口机上绑定目标连接源地址，回车默认 auto）:']='Egress outbound source IP dial (binds the target-connection source address on the exit machine, Enter = auto):'
        ['Fail2ban 仍未能正常启动，最近日志：']='Fail2ban still failed to start; recent log:'
        ['Fail2ban 已停用（现有封禁随服务停止而解除，配置保留）']='Fail2ban disabled (existing bans are lifted when the service stops; config kept)'
        ['Fail2ban 已卸载']='Fail2ban uninstalled'
        ['Fail2ban 已启动，SSH 防护生效']='Fail2ban started; SSH protection active'
        ['Fail2ban 已启用（开机自启）']='Fail2ban enabled (start on boot)'
        ['Fail2ban 并启用 SSH 防护']='Fail2ban and enable SSH protection'
        ['Fail2ban 服务未运行，请先执行「10']='Fail2ban is not running; please run "10'
        ['Fail2ban 管理（SSH 防爆破）']='Fail2ban management (SSH brute-force protection)'
        ['Fail2ban（开机自启）']='Fail2ban (start on boot)'
        ['Google + Cloudflare（8.8.8.8 / 1.1.1.1，含 IPv6）']='Google + Cloudflare (8.8.8.8 / 1.1.1.1, incl. IPv6)'
        ['HOST/tcp:PORT）、多台 Egress 可同时注册、NOW_MORPH_UDP_PRELUDE、握手超时默认按共享密钥派生（3–30s）']='HOST/tcp:PORT); multiple Egress machines can register at once; NOW_MORPH_UDP_PRELUDE; handshake timeout defaults to derivation from the shared key (3–30s)'
        ['IPv4 / IPv6 优先级']='IPv4 / IPv6 priority'
        ['IPv4 优先']='IPv4 first'
        ['IPv4 优先    2']='IPv4 first    2'
        ['IPv6 优先    3']='IPv6 first    3'
        ['IPv6 优先（系统默认）']='IPv6 first (system default)'
        ['IPv6 地址已配置，但实际无法连通外网（VPS常见问题：分配了地址却未正确路由）']='IPv6 address is configured but cannot actually reach the internet (common VPS issue: address assigned but not routed correctly)'
        ['IPv6 已恢复启用（网卡的 IPv6 地址可能需要几秒，或重启网络 / 重启系统后才重新获取）']='IPv6 re-enabled (the NIC'\''s IPv6 address may take a few seconds, or come back after a network/system restart)'
        ['IPv6 连通性正常，无需调整']='IPv6 connectivity is fine; no change needed'
        ['MB（建议']='MB (recommended '
        ['ML-KEM-768（抗量子，默认）  2']='ML-KEM-768 (quantum-resistant, default)  2'
        ['Morph 是否开启（须与 Portal 一致）']='Enable Morph? (must match the Portal)'
        ['Morph 流量乱形']='Morph traffic shaping'
        ['NOW_HANDSHAKE_TIMEOUT；v3.3.0 起未设置时默认值从 Shared Key 派生（3s–30s，换密钥会变），显式设置可固定行为。持续时间格式，如 10s / 500ms / 1m / 1h，须为正数+单位；非法值会被 v3.3 启动拒绝']='NOW_HANDSHAKE_TIMEOUT; since v3.3.0 the unset default is derived from the Shared Key (3s–30s, changes when the key changes); setting it explicitly pins the behavior. Duration format, e.g. 10s / 500ms / 1m / 1h, must be a positive number + unit; invalid values are rejected at v3.3 startup'
        ['NOW_MORPH_TCP_PRELUDE / NOW_MORPH_UDP_PRELUDE，后者为 v3.3.0 新增。只对发起端（Vector / Egress）生效，Portal 自身不使用；这里的选择会写进下方生成的 Vector / Egress 启动命令。接收端三种通吃、两端无需一致、不进分享链接']='NOW_MORPH_TCP_PRELUDE / NOW_MORPH_UDP_PRELUDE, the latter new in v3.3.0. Only effective on the initiating side (Vector / Egress); the Portal itself does not use it; your choice here goes into the Vector / Egress launch commands generated below. The receiver accepts all three, both ends need not match, and it is not included in share links'
        ['Nowhere Egress 连接信息（']='Nowhere Egress connection info ('
        ['Nowhere Portal 连接信息（']='Nowhere Portal connection info ('
        ['Nowhere 已卸载']='Nowhere uninstalled'
        ['Nowhere 本地实例快照（nowhere status，v3 内置遥测）：']='Nowhere local instance snapshot (nowhere status, built-in v3 telemetry):'
        ['Portal 侧必须已设 out=egress，并放行所选载体的端口（QUIC = UDP 端口，TLS = TCP 端口）']='The Portal side must already have out=egress set, and the selected carrier'\''s port must be allowed (QUIC = UDP port, TLS = TCP port)'
        ['Portal 公网地址（域名或 IP，Egress 回连用）:']='Portal public address (domain or IP, used by Egress to connect back):'
        ['Portal 出口 out=（Portal 固定出口，运行期间不可变）：']='Portal egress out= (fixed Portal egress, cannot change while running):'
        ['Portal 的']='Portal'\''s '
        ['Portal 端点   :']='Portal endpoint   :'
        ['Portal 自签证书指纹 pin（64 位 hex，可从 Portal 机 Nowhere 菜单 10 查看，输入不回显，回车=暂不填）:']='Portal self-signed certificate fingerprint pin (64 hex chars; view it on the Portal machine under Nowhere menu 10; input hidden; Enter = leave empty for now):'
        ['Portal 证书信任方式：']='Portal certificate trust method:'
        ['QUIC/UDP 端口（回车默认2001）:']='QUIC/UDP port (Enter = 2001):'
        ['Quad9 + Cloudflare（9.9.9.9 / 1.1.1.1，含 IPv6）']='Quad9 + Cloudflare (9.9.9.9 / 1.1.1.1, incl. IPv6)'
        ['REALITY 伪装站点（需是境外、支持 TLS 1.3 + HTTP/2 的站点；握手会转发到它的 443 端口）：']='REALITY decoy site (must be an overseas site supporting TLS 1.3 + HTTP/2; the handshake is forwarded to its port 443):'
        ['SHA256 与仓库 SHA256SUMS 一致']='SHA256 matches the repo SHA256SUMS'
        ['SHA256 与仓库 SHA256SUMS 不一致（仓库']='SHA256 does not match the repo SHA256SUMS (repo '
        ['SHA256 校验失败（']='SHA256 verification failed ('
        ['SHA256 校验失败（官方']='SHA256 verification failed (official '
        ['SHA256 校验失败：官方 digest=']='SHA256 verification failed: official digest='
        ['SHA256 校验通过（']='SHA256 verification passed ('
        ['SHA256 校验通过（GitHub 官方资产 digest）']='SHA256 verification passed (GitHub official asset digest)'
        ['SHA256 校验通过（官方 .dgst）']='SHA256 verification passed (official .dgst)'
        ['SNI 格式不合法，已忽略']='Invalid SNI format; ignored'
        ['SNI（证书域名与回连地址不一致时填，回车=用回连地址）:']='SNI (fill in when the certificate domain differs from the return address; Enter = use the return address):'
        ['SOCKS5 上游 - 经一层 SOCKS5 代理出站（链式代理）']='SOCKS5 upstream - outbound via one SOCKS5 proxy layer (chained proxy)'
        ['SOCKS5 地址，格式 user:pass']='SOCKS5 address, format user:pass'
        ['SOCKS5 格式不合法，已重置为 none 并改回 direct']='Invalid SOCKS5 format; reset to none and switched back to direct'
        ['SSH 端口:']='SSH port:'
        ['Shadowsocks 2022 加密方式：']='Shadowsocks 2022 cipher:'
        ['Snell Server 管理（Surge 官方，v']='Snell Server management (Surge official, v'
        ['Snell 一键修复']='Snell one-click repair'
        ['Snell 二进制已更新到']='Snell binary updated to'
        ['Snell 健康检查']='Snell health check'
        ['Snell 官方未提供该架构的二进制:']='Snell does not officially provide a binary for this architecture:'
        ['Snell 尚未安装，请先执行「1']='Snell is not installed yet; please run "1'
        ['Snell 已卸载']='Snell uninstalled'
        ['Snell 已更新:']='Snell updated:'
        ['Snell 已重启（含全部附加端口）']='Snell restarted (incl. all additional ports)'
        ['Snell 未安装，跳过']='Snell not installed; skipped'
        ['Snell 未能正常启动，最近日志：']='Snell failed to start; recent log:'
        ['Snell 的监听地址已按当前 IPv6 状态调整']='Snell'\''s listen address adjusted to the current IPv6 state'
        ['Snell 配置']='Snell config'
        ['Surge 节点配置（粘贴到']='Surge node config (paste into '
        ['Surge 节点配置：']='Surge node config:'
        ['TCP 地址族']='TCP address family'
        ['TCP 端口      :']='TCP port      :'
        ['TCP 调优']='TCP tuning'
        ['TCP 调优」即可']='TCP tuning" is enough'
        ['TCP 调优」启用 BBR']='TCP tuning" to enable BBR'
        ['TCP 调优（tcpfit）']='TCP tuning (tcpfit)'
        ['TLS    : 开启']='TLS    : on'
        ['TLS 与 QUIC 共用同一端口，如']='TLS and QUIC share one port, e.g.'
        ['TLS 与 QUIC 分开端口，如']='TLS and QUIC use separate ports, e.g.'
        ['TLS 回源 + 已有证书文件（「完全']='TLS origin-pull + existing certificate files ("Full'
        ['TLS 回源 + 自签证书（默认；Cloudflare 的 SSL/TLS 模式选「完全 Full」，不是「完全']='TLS origin-pull + self-signed certificate (default; in Cloudflare'\''s SSL/TLS mode choose "Full", not "Full'
        ['TLS 证书方式：']='TLS certificate method:'
        ['TLS 载体下每条 Flow 独占一条连接，本机会自动预建待命连接；BUSY 表示 Portal 的待命容量已满。']='On the TLS carrier, each Flow uses its own connection; this machine pre-builds standby connections automatically; BUSY means the Portal'\''s standby capacity is full.'
        ['TLS 载体的 Egress 需要 Nowhere']='TLS-carrier Egress needs Nowhere '
        ['TLS/TCP 端口（回车默认2000）:']='TLS/TCP port (Enter = 2000):'
        ['Token 是否有 Zone:DNS:Edit 权限']='Does the Token have Zone:DNS:Edit permission?'
        ['UDP 地址族']='UDP address family'
        ['UDP 端口      :']='UDP port      :'
        ['VLESS + REALITY + Vision（TCP 直连，最常用）']='VLESS + REALITY + Vision (direct TCP, most common)'
        ['VLESS + XHTTP + REALITY（直连，可叠加 VLESS Encryption）']='VLESS + XHTTP + REALITY (direct; VLESS Encryption can be stacked)'
        ['VLESS + XHTTP + TLS / 明文回源（套 CDN，需要域名）']='VLESS + XHTTP + TLS / plaintext origin-pull (behind a CDN; needs a domain)'
        ['VLESS Encryption + XHTTP（ML-KEM-768 抗量子，不依赖 TLS）']='VLESS Encryption + XHTTP (ML-KEM-768 quantum-resistant, no TLS needed)'
        ['VLESS Encryption + XHTTP：不套 TLS / REALITY，由 VLESS 自身的加密保护（适合直连，或明文回源的 CDN 之后）。']='VLESS Encryption + XHTTP: no TLS / REALITY; protected by VLESS'\''s own encryption (for direct connections, or behind a CDN with plaintext origin-pull).'
        ['Vector 载体（二选一，v3 一条连接只用一种载体）  1']='Vector carrier (pick one; in v3 one connection uses one carrier)  1'
        ['Vector客户端  :']='Vector client  :'
        ['Vector旧名']='Vector (old name)'
        ['Vector（0=不限速）:']='Vector (0 = unlimited):'
        ['X25519（密钥更短）']='X25519 (shorter keys)'
        ['XHTTP 路径:']='XHTTP path:'
        ['XanMod 仓库密钥下载或导入失败']='Failed to download or import the XanMod repo key'
        ['XanMod 内核']='XanMod kernel'
        ['XanMod 内核已卸载，重启后生效']='XanMod kernel uninstalled; takes effect after reboot'
        ['XanMod 内核已安装:']='XanMod kernel installed:'
        ['XanMod 官方只提供 x86_64 构建，本机是']='XanMod officially provides x86_64 builds only; this machine is '
        ['Xray 一键修复']='Xray one-click repair'
        ['Xray 健康检查']='Xray health check'
        ['Xray 尚未安装，请先执行「1']='Xray is not installed yet; please run "1'
        ['Xray 已卸载']='Xray uninstalled'
        ['Xray 已重启']='Xray restarted'
        ['Xray 未能正常启动，最近日志：']='Xray failed to start; recent log:'
        ['Xray 模块暂不支持该架构:']='The Xray module does not support this architecture yet:'
        ['Xray 管理（SS / VLESS）']='Xray management (SS / VLESS)'
        ['Xray 自动更新:']='Xray auto-update:'
        ['Xray 节点列表']='Xray node list'
        ['Xray 节点的监听地址已按当前 IPv6 状态调整']='Xray nodes'\'' listen addresses adjusted to the current IPv6 state'
        ['Xray 节点配置与分享链接']='Xray node configs and share links'
        ['acme.sh cron 续期任务存在']='acme.sh cron renewal task exists'
        ['acme.sh 安装后仍找不到可执行文件（']='acme.sh installed but the executable still cannot be found ('
        ['acme.sh 安装失败，请检查网络后重试']='acme.sh installation failed; please check the network and retry'
        ['adam-maintain.timer 启用失败']='Failed to enable adam-maintain.timer'
        ['adam-watchdog.timer 启用失败']='Failed to enable adam-watchdog.timer'
        ['apt-get remove 失败，请手动处理']='apt-get remove failed; please handle it manually'
        ['apt-get update 失败，继续尝试安装']='apt-get update failed; trying to install anyway'
        ['apt-get update 部分失败，继续尝试']='apt-get update partially failed; trying anyway'
        ['auto                       打开自动维护菜单（保活巡检 / 自动更新开关）']='auto                       Open the auto-maintenance menu (keepalive watchdog / auto-update switches)'
        ['beta   - 跟随官方最新测试版（b / rc），正式版发布后自动转到正式版（默认）']='beta   - follow the official latest beta (b / rc); switches to stable automatically once a stable release is out (default)'
        ['certbot 安装失败']='certbot installation failed'
        ['certbot.timer 启用失败，请手动执行：systemctl enable --now certbot.timer']='Failed to enable certbot.timer; please run manually: systemctl enable --now certbot.timer'
        ['certbot.timer 未在运行，自动续期可能不工作，请手动检查']='certbot.timer is not running; auto-renewal may not work, please check manually'
        ['certbot.timer 运行中']='certbot.timer is running'
        ['cron 兜底续期任务存在']='cron fallback renewal task exists'
        ['cron 续期任务已写入']='cron renewal task written'
        ['default    - 流量整形混淆 + AES 加密（推荐）']='default    - traffic-shaping obfuscation + AES encryption (recommended)'
        ['default（默认）  2']='default (default)  2'
        ['dial6 不是合法 IPv6 字面量（IPv4-mapped 地址不被 v3 接受），已重置为 auto']='dial6 is not a valid IPv6 literal (IPv4-mapped addresses are not accepted by v3); reset to auto'
        ['dial6 不是合法 IPv6 字面量，已重置为 auto']='dial6 is not a valid IPv6 literal; reset to auto'
        ['direct - Portal 直接访问目标（默认）']='direct - Portal accesses the target directly (default)'
        ['egress - 远程 Egress 出口（目标解析/拨号在另一台主动回连的机器上，该机无需开放入站端口；可同时接多台）']='egress - remote Egress exit (target resolution/dialing happens on another machine that connects back; that machine needs no inbound port; multiple machines can connect)'
        ['en（当前：']='en (current: '
        ['f2b                        打开 Fail2ban 菜单']='f2b                        Open the Fail2ban menu'
        ['f2b bantime <时长>         例: adam f2b bantime 1h   （纯数字 = 分钟，-1 = 永久）']='f2b bantime <duration>      e.g. adam f2b bantime 1h   (plain number = minutes, -1 = forever)'
        ['fade（默认）  2']='fade (default)  2'
        ['fail2ban 与当前 Python 版本不兼容（缺 asynchat/asyncore，常见于 Ubuntu 24.04 的初版软件包），尝试升级 fail2ban ...']='fail2ban is incompatible with the current Python version (missing asynchat/asyncore, common in early Ubuntu 24.04 packages); trying to upgrade fail2ban ...'
        ['findtime 格式不合法']='Invalid findtime format'
        ['full8 - 全程全 8 位随机']='full8 - full 8-bit random throughout'
        ['fw                         打开防火墙菜单']='fw                         Open the firewall menu'
        ['fw allow <端口>            例: adam fw allow 443/tcp,8000-8100    （不写协议 = TCP+UDP）']='fw allow <port>            e.g. adam fw allow 443/tcp,8000-8100    (no protocol = TCP+UDP)'
        ['fw deny  <端口>            删除放行规则']='fw deny  <port>            Remove an allow rule'
        ['host:port（输入不回显）:']='host:port (input hidden):'
        ['low7  - 全程低 7 位随机']='low7  - low 7-bit random throughout'
        ['maintain-log               查看维护记录']='maintain-log               View maintenance records'
        ['maxretry 必须是正整数']='maxretry must be a positive integer'
        ['mix - TLS/TCP + QUIC/UDP 双栈（HOST:PORT，推荐）']='mix - TLS/TCP + QUIC/UDP dual-stack (HOST:PORT, recommended)'
        ['mode（服务端与客户端必须一致）：']='mode (server and client must match):'
        ['nowhere                    打开 Nowhere 菜单']='nowhere                    Open the Nowhere menu'
        ['nowhere status 未能读取到实例（服务未运行，或二进制版本低于 v2.1.2 无此命令）']='nowhere status could not read any instance (service not running, or binary older than v2.1.2 without this command)'
        ['off          开/关 跟随官方发布的自动更新（默认 beta 通道：跟随最新测试版）']='off          On/off for following official releases for auto-update (default beta channel: follow the latest beta)'
        ['out=egress 时 Portal 不能再设置 dial/dial4/dial6（与官方约束一致），目标源地址请在 Egress 端配置']='When out=egress, the Portal can no longer set dial/dial4/dial6 (per the official constraint); configure the target source address on the Egress side'
        ['pin        - 指定一个版本并固定，不自动更新']='pin        - pin to a specific version; no auto-update'
        ['pin 必须是 64 位小写十六进制字符']='pin must be 64 lowercase hex chars'
        ['prerelease - 跟随官方最新版（含预发布，默认）']='prerelease - follow the official latest (incl. pre-releases, default)'
        ['s Encrypt DNS-01 通用 - 支持多种 DNS 服务商（自动续期）']='s Encrypt DNS-01 generic - supports many DNS providers (auto-renewal)'
        ['s Encrypt HTTP-01 - 需要域名解析到本机 + 开放 80 端口（自动续期）']='s Encrypt HTTP-01 - needs the domain to resolve to this machine + port 80 open (auto-renewal)'
        ['s Encrypt HTTP-01 - 需要开放 80 端口（自动续期）']='s Encrypt HTTP-01 - needs port 80 open (auto-renewal)'
        ['s Encrypt 账户用）:']='s Encrypt account):'
        ['script                     打开脚本更新菜单']='script                     Open the script-update menu'
        ['snell                      打开 Snell 菜单']='snell                      Open the Snell menu'
        ['stable     - 只跟官方标记为正式版的发布（官方近期没有这样的发布时会提示）']='stable     - only follow releases officially marked stable (you will be told if there has been no such release recently)'
        ['stable - 只安装和跟随正式版']='stable - install and follow stable releases only'
        ['systemd 显示服务 active，但未检测到端口实际在监听']='systemd shows the service as active, but no port is actually listening'
        ['tcp - 仅 TLS/TCP（HOST/tcp:PORT）']='tcp - TLS/TCP only (HOST/tcp:PORT)'
        ['tcp / TLS        - 每条 Flow 独占一条 TLS 连接，自动维护预建连接池（Hydra）；UDP 被限制的网络选这个']='tcp / TLS        - each Flow uses its own TLS connection; pre-built connection pool maintained automatically (Hydra); pick this on networks where UDP is restricted'
        ['tcp / TLS  - 每条 Flow 独占一条 TLS 连接，出口机自动维护预建连接池；UDP 被限制的网络选这个（出口机需']='tcp / TLS  - each Flow uses its own TLS connection; the exit machine maintains a pre-built connection pool automatically; pick this on networks where UDP is restricted (exit machines need '
        ['tcp:端口']='tcp:port'
        ['tcpfit 以非 0 状态退出（如果是你主动退出菜单可忽略）']='tcpfit exited with a non-zero status (ignore this if you exited the menu yourself)'
        ['tcpfit 会按本机实测结果推导缓冲区、BBR/fq、限速器拐点与整形参数，而不是套固定值。']='tcpfit derives buffer, BBR/fq, limiter inflection points and shaping parameters from measurements on this machine, instead of applying fixed values.'
        ['tcpfit 已更新到']='tcpfit updated to'
        ['tcpfit 是第三方开源脚本（']='tcpfit is a third-party open-source script ('
        ['tcpfit 状态 / 回滚 / 更新']='tcpfit status / rollback / update'
        ['tcpfit 的菜单需要在终端里运行，请直接执行: tcpfit']='The tcpfit menu must run in a terminal; please run directly: tcpfit'
        ['tls=1 且无指纹记录文件，请用 Nowhere 菜单 10 生成']='tls=1 with no fingerprint record file; please generate one via Nowhere menu 10'
        ['tls=1 为临时自签证书，每次重启指纹会变化，仅建议测试用']='tls=1 is a temporary self-signed certificate; its fingerprint changes on every restart; test use only'
        ['tls=1 当前指纹见']='Current tls=1 fingerprint:'
        ['tls=1 时 pin 随 Portal 重启变化，Portal 重启后需在本机更新 egress.env 里的 pin 并重启服务。']='With tls=1, pin changes when the Portal restarts; after a Portal restart, update the pin in egress.env on this machine and restart the service.'
        ['tls=1 自签证书：必须用 pin= 锁定 Portal 证书指纹（指纹随 Portal 重启变化）']='tls=1 self-signed certificate: you must lock the Portal certificate fingerprint with pin= (the fingerprint changes on Portal restart)'
        ['tls=2 真实证书：走系统 CA + 主机名校验（默认）']='tls=2 real certificate: system CA + hostname verification (default)'
        ['tune                       打开调优菜单']='tune                       Open the tuning menu'
        ['udp - 仅 QUIC/UDP（HOST/udp:PORT）']='udp - QUIC/UDP only (HOST/udp:PORT)'
        ['udp / QUIC - 一条连接承载多条 Flow（推荐）']='udp / QUIC - one connection carries multiple Flows (recommended)'
        ['udp / QUIC（默认）- 一条连接承载多条 Flow']='udp / QUIC (default) - one connection carries multiple Flows'
        ['ufw 安装失败，请检查 apt 源/网络']='ufw installation failed; please check apt sources / network'
        ['ufw 安装完成']='ufw installed'
        ['ufw 已安装']='ufw is installed'
        ['ufw 当前未启用，已预先保存放行规则:']='ufw is currently disabled; allow rules have been saved in advance:'
        ['ufw 未启用（如有云厂商安全组，请确认已放行']='ufw is disabled (if your cloud provider has a security group, please confirm it allows '
        ['unsafe-raw - 不加密、不混淆，明文转发（只适合可信内网 / 专线）']='unsafe-raw - no encryption, no obfuscation, plaintext forwarding (only for trusted internal networks / dedicated lines)'
        ['unsafe-raw 下所有流量明文传输，公网使用等于裸奔']='With unsafe-raw all traffic is plaintext; using it on the public internet is like running naked'
        ['v3 会直接拒绝用该密钥启动。请用Nowhere 菜单「3']='v3 will refuse to start with this key. Please use Nowhere menu "3'
        ['v3 客户端默认校验系统 CA 与主机名，自签场景必须用 pin= 锁定指纹']='v3 clients verify the system CA and hostname by default; for self-signed certs you must lock the fingerprint with pin='
        ['v3 的 alpn/net/log/pool/up/down/socks']='v3'\''s alpn/net/log/pool/up/down/socks'
        ['v3 默认开启 morph=1；仅做流量形态混淆，不提供额外加密；两端必须一致，没有协商/回退']='v3 enables morph=1 by default; it only obfuscates traffic shape and adds no extra encryption; both ends must match, with no negotiation/fallback'
        ['v3.1.0（建议与本机同版本）；QUIC 载体与 morph=0 不受这条影响']='v3.1.0 (same version as this machine recommended); QUIC carriers and morph=0 are not affected by this'
        ['v3.1.0，再升级本机 Portal']='v3.1.0, then upgrade this machine'\''s Portal'
        ['v3.1.0，更旧的版本会被静默拒绝。']='v3.1.0; older versions are silently rejected.'
        ['v3.2.0 起 Portal 强制 Authenticated Prelude、不再有回退：仍停留在 v3.0.x 的 Vector/Egress/Anywhere 在 morph=1 的 TLS/TCP 载体上会被静默拒绝']='Since v3.2.0 the Portal enforces Authenticated Prelude with no fallback: Vector/Egress/Anywhere still on v3.0.x will be silently rejected on morph=1 TLS/TCP carriers'
        ['v3.2.0 起 Portal 强制 Authenticated Prelude：morph=1 且走 TLS/TCP 的对端']='Since v3.2.0 the Portal enforces Authenticated Prelude: peers with morph=1 on TLS/TCP'
        ['v3.3.0 新增：Egress 可走 TLS/TCP（egress://KEY']='New in v3.3.0: Egress can use TLS/TCP (egress://KEY'
        ['v3.3.0 起同一 Portal 可同时接受多台 Egress（TLS / QUIC 可混用，Portal 按先进先出轮转，不保证均衡）。']='Since v3.3.0 one Portal can accept multiple Egress machines at once (TLS / QUIC can be mixed; the Portal rotates FIFO with no balance guarantee).'
        ['v3.3.0 起同一 Portal 可同时接受多台 Egress（TLS / QUIC 可混用，Portal 按先进先出轮转，不保证均衡）；使用 tcp 载体的出口机需']='Since v3.3.0 one Portal can accept multiple Egress machines at once (TLS / QUIC can be mixed; the Portal rotates FIFO with no balance guarantee); exit machines using the tcp carrier need '
        ['v3.3.0，本机现有二进制为']='v3.3.0; the binary currently on this machine is '
        ['watchdog        立即执行一次每日维护 / 保活巡检（定时器调用的就是这两个）']='watchdog        Run one daily maintenance / keepalive check now (these are what the timers call)'
        ['xray                       打开 Xray 菜单']='xray                       Open the Xray menu'
        ['xray vlessenc 生成失败（当前内核版本可能不支持 VLESS Encryption）']='Failed to generate xray vlessenc (the current kernel may not support VLESS Encryption)'
        ['· CDN 节点：连不通时把客户端的 XHTTP mode 从 auto 改成 packet-up 再试']='· CDN node: if unreachable, change the client'\''s XHTTP mode from auto to packet-up and retry'
        ['· DNS 偏好']='· DNS preference'
        ['· REALITY 节点：较新的 Xray 服务端（社区反馈自 v26.9.8 起）要求客户端握手带 X25519MLKEM768，']='· REALITY node: newer Xray servers (community reports say since v26.9.8) require the client handshake to carry X25519MLKEM768,'
        ['· VLESS Encryption 的 encryption= 参数很长，属正常现象；客户端内核需支持该特性']='· The VLESS Encryption encryption= parameter is very long; that is normal; the client core must support this feature'
        ['· Xray 官方近期的发布基本都标记为 Pre-release，「最新预发布版」通常就是官方最新一版']='· Recent official Xray releases are mostly tagged Pre-release; the "latest pre-release" is usually the official latest'
        ['· mode 必须与服务端一致（官方要求），否则无法连通']='· mode must match the server (official requirement), otherwise it cannot connect'
        ['· v6 已移除 QUIC Proxy Mode，UDP 走 UDP over TCP，防火墙只需放行 TCP']='· v6 removed QUIC Proxy Mode; UDP goes over UDP over TCP, so the firewall only needs to allow TCP'
        ['· v6 的协议特征由 PSK 派生：更换 PSK 等于更换一套流量特征，客户端需同步修改']='· v6 protocol features are derived from the PSK: changing the PSK changes the whole traffic profile, and clients must update in sync'
        ['· 如果你的客户端跟不上，可选「指定版本」固定在一个旧版本（如 v26.3.27）']='· If your client cannot keep up, use "Specify version" to pin an old version (e.g. v26.3.27)'
        ['· 角色']='· Role'
        ['· 较新版本的 REALITY 服务端要求客户端握手带 X25519MLKEM768（社区反馈自 v26.9.8 起）：']='· Newer REALITY servers require the client handshake to carry X25519MLKEM768 (community reports say since v26.9.8):'
        ['· 需要支持 Snell v6 的 Surge 版本；官方未说明 v6 服务端兼容 v4/v5 客户端，第三方客户端是否支持请以其文档为准']='· Requires a Surge version supporting Snell v6; the official docs do not say whether the v6 server is compatible with v4/v5 clients — check third-party client docs for support'
        ['· 预发布版偶有不兼容改动：自动更新会先用新内核校验现有配置，校验不过就不换；启动失败会自动回滚']='· Pre-releases occasionally contain breaking changes: auto-update first validates the current config with the new core and will not switch if validation fails; startup failure triggers an automatic rollback'
        ['— 快速重启服务']='— Restart the service quickly'
        ['— 打开管理菜单']='— Open the management menu'
        ['— 查看服务状态']='— View service status'
        ['— 查看节点/连接信息']='— View node / connection info'
        ['— 重新修改配置']='— Reconfigure'
        ['。要换版本或恢复跟随最新，请用「1']='. To switch versions or resume following the latest, use "1'
        ['「其他/手动」需要交互式完成 DNS TXT 验证，本脚本暂不接管，请改选 1-3']='"Other/Manual" requires interactive DNS TXT verification; this script does not take that over yet, please pick 1-3 instead'
        ['」可用；证书续期后每日维护会自动同步）']='" is usable; after certificate renewal, daily maintenance syncs it automatically)'
        ['【Anywhere 分享链接 —— QUIC/UDP（net=udp）】']='[Anywhere share link — QUIC/UDP (net=udp)]'
        ['【Anywhere 分享链接 —— TLS/TCP（net=tcp，默认）】']='[Anywhere share link — TLS/TCP (net=tcp, default)]'
        ['【Anywhere 手动填写】']='[Anywhere manual entry]'
        ['【TLS 提示】']='[TLS note]'
        ['【出口机启动参数（Egress URL，用于 systemd ExecStart）】']='[Exit-machine launch parameters (Egress URL, for systemd ExecStart)]'
        ['【客户端连接参数】']='[Client connection parameters]'
        ['【服务端启动参数（Portal URL，用于 systemd ExecStart）】']='[Server launch parameters (Portal URL, for systemd ExecStart)]'
        ['【本地 Vector 客户端 —— 在电脑/路由器上跑本地 SOCKS5 入口】']='[Local Vector client — run a local SOCKS5 entry on your computer/router]'
        ['【本地 Vector 客户端】']='[Local Vector client]'
        ['【版本兼容提醒】']='[Version compatibility reminder]'
        ['【说明】']='[Notes]'
        ['【远程 Egress 出口机 —— 在出口机上运行，主动回连本 Portal，无需出口机开放入站端口】']='[Remote Egress exit machine — runs on the exit machine and connects back to this Portal; the exit machine needs no inbound port]'
        ['【远程 Egress 出口机】']='[Remote Egress exit machine]'
        ['【防火墙提醒】']='[Firewall reminder]'
        ['一键修复']='One-click repair'
        ['一键修复（单元 / 保留端口 / 防火墙 / 保活定时器）']='One-click repair (unit / reserved ports / firewall / keepalive timer)'
        ['一键诊断（只读，不改任何配置）']='One-click diagnostics (read-only; changes nothing)'
        ['上/下行限速   :']='Up/down rate limit   :'
        ['上一个版本 tag    :']='Previous version tag    :'
        ['上行限速 Mbps（0=不限速）:']='Upload limit Mbps (0 = unlimited):'
        ['上行限速 Mbps，Vector']='Upload limit Mbps, Vector'
        ['下行限速 Mbps（0=不限速）:']='Download limit Mbps (0 = unlimited):'
        ['下行限速 Mbps，目标']='Download limit Mbps, target'
        ['下载']='Download'
        ['下载 ...']='Downloading ...'
        ['下载 tcpfit 失败（']='Failed to download tcpfit ('
        ['下载到的 tcpfit 不完整或不是脚本（传输被截断或被网关拦截），已放弃']='The downloaded tcpfit is incomplete or not a script (transfer truncated or blocked by a gateway); giving up'
        ['下载到的 xray 无法在本机运行（架构不符？）']='The downloaded xray cannot run on this machine (wrong architecture?)'
        ['下载到的二进制无法在本机运行（架构或 libc 不匹配），已中止，现有安装未被改动']='The downloaded binary cannot run on this machine (architecture or libc mismatch); aborted; the existing installation was not changed'
        ['下载到的压缩包不完整或已损坏']='The downloaded archive is incomplete or damaged'
        ['下载失败（该版本可能没有']='Download failed (this version may not have '
        ['下载并校验']='Download and verify'
        ['下载或校验失败，已中止']='Download or verification failed; aborted'
        ['不一致（可能新版尚未推送到']='Mismatch (the new version may not have been pushed to '
        ['不变（上游可能有不兼容改动）']='Unchanged (upstream may have breaking changes)'
        ['不可达或页面结构变化）']='unreachable, or the page structure changed)'
        ['不可达，或该架构']='unreachable, or this architecture '
        ['不存在，已跳过']='does not exist; skipped'
        ['不支持的架构:']='Unsupported architecture:'
        ['不是合法 IP:']='Not a valid IP:'
        ['不是本机的 Snell 端口配置（现有:']='Not one of this machine'\''s Snell port configs (current: '
        ['且不同协议代的密钥格式、URL 参数可能不兼容，仅换二进制不重配大概率启动失败或连不上']='Also, key formats and URL parameters may differ across protocol generations; just swapping the binary without reconfiguring will most likely fail to start or connect'
        ['个端口 ·']='ports ·'
        ['个，累计']=', total '
        ['中文']='Chinese'
        ['临时禁用 IPv6（重启后自动恢复）？']='Temporarily disable IPv6 (auto-restored after reboot)?'
        ['临时禁用（重启恢复）    2']='Temporarily disable (restored on reboot)    2'
        ['主机/udp']='host/udp'
        ['主端口']='Main port'
        ['二进制下载失败，安装中止']='Binary download failed; installation aborted'
        ['二进制可运行（']='Binary can run ('
        ['二进制已更新到']='Binary updated to'
        ['二进制无法运行:']='Binary cannot run:'
        ['仅支持 Debian / Ubuntu（当前:']='Only Debian / Ubuntu are supported (current: '
        ['仍要使用？']='Still use it?'
        ['仍要安装吗？']='Still install it?'
        ['仍要安装该旧版本吗？']='Still install this old version?'
        ['仍要继续安装吗？']='Continue installing anyway?'
        ['仍要继续安装该版本吗？']='Continue installing this version anyway?'
        ['仍要继续（稍后需手动改 egress.env 补 pin）？']='Continue anyway (you will need to manually add the pin to egress.env later)?'
        ['从官方仓库拉取最新版并安装到']='Fetch the latest version from the official repo and install it to '
        ['从本机未能确认']='Could not be confirmed from this machine'
        ['仓库版本']='Repo version'
        ['仓库版本为']='Repo version:'
        ['以下端口正在对外监听，但还没有在防火墙里放行（启用后外部将无法访问）：']='The following ports are listening externally but are not yet allowed in the firewall (they will be unreachable from outside once enabled):'
        ['优先（新启动的程序生效；已在运行的服务重启后生效）']='Priority (applies to newly started programs; running services take effect after restart)'
        ['传输模式（决定端点路径，TCP 与 UDP 都能承载 TCP/UDP 业务流）：']='Transport mode (decides the endpoint path; both TCP and UDP can carry TCP/UDP traffic):'
        ['伪装站点:']='Decoy site:'
        ['低7位']='Low 7-bit'
        ['低于本地']='Lower than local'
        ['你当前是通过 IPv6（']='You are currently connected via IPv6 ('
        ['例：80,443,2053    400-500    443/tcp,51820/udp   （不写协议 = TCP 和 UDP 都放行）']='e.g. 80,443,2053    400-500    443/tcp,51820/udp   (no protocol = allow both TCP and UDP)'
        ['依赖安装失败']='Failed to install dependencies'
        ['依赖安装完成']='Dependencies installed'
        ['保存 Egress 配置并创建 systemd 服务']='Save the Egress config and create the systemd service'
        ['保活巡检 :']='Keepalive watchdog :'
        ['保留现有端口和 PSK？（选 n 重新配置）']='Keep the current port and PSK? (choose n to reconfigure)'
        ['保留的其他内核:']='Other kernels kept:'
        ['保留端口   :']='Reserved ports   :'
        ['修复后服务仍未正常监听，最近日志：']='The service is still not listening normally after the repair; recent log:'
        ['修复完成']='Repair complete'
        ['修复完成，服务运行正常']='Repair complete; service running normally'
        ['修改 DNS 地址族偏好']='Change DNS address-family preference'
        ['修改 mode']='Change mode'
        ['修改主端口配置（端口 / PSK / mode / DNS 偏好 / 节点名）']='Change the main port config (port / PSK / mode / DNS preference / node name)'
        ['修改分享链接用的公网地址']='Change the public address used in share links'
        ['修改封禁时长']='Change the ban duration'
        ['修改端口']='Change port'
        ['修改节点名称 / 公网地址（只影响生成的 Surge 配置行）']='Change node name / public address (only affects the generated Surge config line)'
        ['修改触发条件（失败次数 / 统计窗口）']='Change trigger conditions (failure count / time window)'
        ['停用后所有端口不再受 ufw 过滤（已添加的规则会保留，可随时重新启用）']='After disabling, no ports are filtered by ufw anymore (added rules are kept and can be re-enabled anytime)'
        ['先安装向导所需的基础工具:']='First install the basic tools the wizard needs:'
        ['全8位渐变（默认，推荐）']='Full 8-bit fade (default, recommended)'
        ['公网 IP/域名（用于 Anywhere/Vector/Egress 连接，回车使用探测值']='Public IP/domain (for Anywhere/Vector/Egress connections; Enter = detected value'
        ['公网地址      :']='Public address      :'
        ['公网地址（回车保持']='Public address (Enter = keep '
        ['公钥']='Public key'
        ['共享密钥    :']='Shared key    :'
        ['共享密钥 Shared Key（输入不回显，回车自动生成 32 位十六进制）:']='Shared Key (input hidden; Enter = auto-generate 32 hex chars):'
        ['共享密钥（必须与 Portal 完全一致，32 位小写十六进制，输入不回显）:']='Shared key (must exactly match the Portal; 32 lowercase hex chars; input hidden):'
        ['关闭自动更新']='Disable auto-update'
        ['其他/手动']='Other/Manual'
        ['其他:']='Other:'
        ['内核       :']='Kernel       :'
        ['内核:']='Kernel:'
        ['内核包安装失败']='Kernel package installation failed'
        ['内核版本']='Kernel version'
        ['内核版本 :']='Kernel version :'
        ['写入 /etc/gai.conf，让系统优先选用 IPv4（不关闭IPv6，只调整地址选择优先级）']='Write /etc/gai.conf so the system prefers IPv4 (IPv6 stays on; only address-selection priority changes)'
        ['出口机启动命令（或在出口机上运行本脚本 Nowhere 菜单 2，直接粘贴上面的连接串装成 systemd 服务）：']='Exit-machine launch command (or run this script'\''s Nowhere menu 2 on the exit machine and paste the connection string above to install it as a systemd service):'
        ['出站 DNS 地址族偏好 dns-ip-preference：']='Outbound DNS address-family preference dns-ip-preference:'
        ['出站源 IP dial（回车默认 auto；填 IP 会限定地址族，绑定失败不回退）:']='Outbound source IP dial (Enter = auto; filling in an IP pins the address family, and a failed bind does not fall back):'
        ['分享链接:']='Share link:'
        ['分享链接与 anywhere:// 深链格式已按 v3 文档更新，但能否导入成功']='Share links and anywhere:// deep-link formats were updated to the v3 docs, but whether import succeeds'
        ['分享链接用的公网地址（当前']='Public address used in share links (current '
        ['切换失败，服务可能未正常启动，请检查日志']='Switch failed; the service may not have started properly, please check the log'
        ['切换通道（当前']='Switch channel (current '
        ['创建 adam-xray 系统用户失败']='Failed to create the adam-xray system user'
        ['创建 snell 系统用户失败']='Failed to create the snell system user'
        ['删除 Snell 端口配置']='Delete a Snell port config'
        ['删除方式：']='Deletion method:'
        ['删除节点']='Delete node'
        ['删除规则']='Delete rule'
        ['剩余端口配置：']='Remaining port configs:'
        ['加密:']='Encryption:'
        ['升级完成:']='Upgrade complete:'
        ['协议代，与本脚本生成的 v3']='protocol generation; this script generates v3'
        ['卸载 Fail2ban（保留 /etc/fail2ban 下你自己的其他配置）']='Uninstall Fail2ban (keep your own other configs under /etc/fail2ban)'
        ['卸载 Nowhere']='Uninstall Nowhere'
        ['卸载 XanMod 内核']='Uninstall the XanMod kernel'
        ['卸载失败']='Uninstall failed'
        ['压缩包损坏']='Archive is damaged'
        ['压缩包里没有 snell-server']='No snell-server in the archive'
        ['压缩包里没有 xray 二进制']='No xray binary in the archive'
        ['参数），改为逐项填写']='parameters); fill in each item instead'
        ['发行版:']='Distro:'
        ['取不到仓库里的 SHA256SUMS，无法核对校验值（SHA256:']='Cannot fetch SHA256SUMS from the repo; cannot verify the checksum (SHA256: '
        ['取决于你手机上的 Anywhere 版本是否已支持 NW3，请以实测为准。']='Depends on whether the Anywhere version on your phone already supports NW3; go by what actually works.'
        ['取得完整脚本，本次跳过']='Got the full script; skipped this time'
        ['取消']='Cancel'
        ['叠加 VLESS Encryption（抗量子密钥交换的应用层加密；客户端需较新的 Xray 内核）？']='Stack VLESS Encryption (application-layer encryption with quantum-resistant key exchange; clients need a newer Xray core)?'
        ['另一个维护任务仍在运行，本次跳过']='Another maintenance task is still running; skipped this time'
        ['只移除本脚本的 SSH 防护配置（保留 Fail2ban 及其他 jail）']='Only remove this script'\''s SSH protection config (keep Fail2ban and other jails)'
        ['可以直接粘贴 Portal 端（Nowhere 菜单 4 / pz）生成的 egress:// 连接串，跳过逐项填写']='You can paste the egress:// connection string generated on the Portal side (Nowhere menu 4 / pz) to skip filling in each item'
        ['可手动补加：']='You can add manually:'
        ['可手动输入版本号继续（如 v6.0.0，回车取消）:']='You can type a version number to continue (e.g. v6.0.0, Enter to cancel):'
        ['可用:']='Available:'
        ['可能不在 XanMod 支持列表里）']='may not be in the XanMod support list)'
        ['可能是作者刚更新、两个文件的缓存不同步，也可能是下载被篡改']='The author may have just updated it and the two files'\'' caches are out of sync, or the download may have been tampered with'
        ['同时删除全部节点配置']='Also delete all node configs'
        ['同时删除配置目录']='Also delete the config directory'
        ['同时删除防火墙里 Nowhere 端口的放行规则（']='Also delete the firewall allow rules for the Nowhere ports ('
        ['同时删除防火墙里 Snell 端口（']='Also delete the firewall allow rules for the Snell ports ('
        ['同时删除防火墙里这些节点端口的放行规则（']='Also delete the firewall allow rules for these node ports ('
        ['名称只能包含字母、数字和 . _ -，已使用默认值']='Name may only contain letters, digits and . _ -; the default was used'
        ['名称格式不合法，未修改']='Invalid name format; not changed'
        ['启动命令：']='Launch command:'
        ['启动失败: journalctl -u fail2ban -n 30 --no-pager']='Startup failed: journalctl -u fail2ban -n 30 --no-pager'
        ['启动失败，回滚到']='Startup failed; rolling back to '
        ['启用 DNS over TLS（opportunistic：上游支持就加密，不支持自动回退）？']='Enable DNS over TLS (opportunistic: encrypt when the upstream supports it, fall back automatically otherwise)?'
        ['启用」或「9']='Enable" or "9'
        ['启用前先放行 SSH 端口（']='Before enabling, first allow the SSH port ('
        ['回滚 tcpfit 的全部改动    3']='Roll back all tcpfit changes    3'
        ['回滚后仍未启动: journalctl -u adam-xray -n 50']='Still not started after rollback: journalctl -u adam-xray -n 50'
        ['回滚后服务仍未启动，请查看: journalctl -u snell -n 50 --no-pager']='Service still not started after rollback; see: journalctl -u snell -n 50 --no-pager'
        ['回滚后服务仍未启动，请立即查看日志: journalctl -u nowhere -n 50 --no-pager']='Service still not started after rollback; check the log now: journalctl -u nowhere -n 50 --no-pager'
        ['回连载体:']='Return carrier:'
        ['回连载体（须与 Portal 已开放的监听对应；v3.3.0 起两种都可用）：']='Return carrier (must match the Portal'\''s open listeners; both work since v3.3.0):'
        ['回退后服务启动失败，日志如下：']='Service failed to start after rollback; log:'
        ['回退目标 :']='Rollback target :'
        ['地址优先级 :']='Address priority :'
        ['地址族（回车=不限；4=仅 IPv4；6=仅 IPv6）:']='Address family (Enter = no limit; 4 = IPv4 only; 6 = IPv6 only):'
        ['地址格式不合法，未修改']='Invalid address format; not changed'
        ['域名       :']='Domain       :'
        ['域名/主机     :']='Domain/host     :'
        ['域名/公网地址 :']='Domain/public address :'
        ['域名不合法，已中止']='Invalid domain; aborted'
        ['域名不能为空']='Domain cannot be empty'
        ['域名只能包含字母、数字、点和连字符']='Domain may only contain letters, digits, dots and hyphens'
        ['域名是否在该 CF 账号下 3']='Is the domain under this CF account? 3'
        ['域名是否已指向本 VPS（见上方 DNS 预检结果）']='Has the domain already pointed to this VPS (see the DNS pre-check above)?'
        ['域名是否正确 2']='Is the domain correct? 2'
        ['域名（须已解析到本机）:']='Domain (must already resolve to this machine):'
        ['基础工具安装失败，后续的输入校验可能不准确']='Basic tools failed to install; later input validation may be inaccurate'
        ['备份仅在执行过「更新」或「选择版本」之后才会生成']='Backups are only created after an "Update" or "Select version" run'
        ['备份含共享密钥与证书私钥，只能放本机，勿外发、勿传网盘']='The backup contains shared keys and certificate private keys; keep it on this machine only, do not send it out or upload it to any cloud drive'
        ['备份已保存：']='Backup saved:'
        ['备份文件损坏或不是有效的 tgz']='Backup file is damaged or not a valid tgz'
        ['备份文件路径（/root/adam-backup-']='Backup file path (/root/adam-backup-'
        ['复用现有二进制:']='Reuse the existing binary:'
        ['多端口：列出 / 新增 / 删除某个端口配置']='Multiple ports: list / add / delete a port config'
        ['天！请立即手动续期']='days! Please renew manually now'
        ['天（30 天内到期），建议立即手动续期']='days (expiring within 30 days); manual renewal recommended now'
        ['失败']='Failed'
        ['失败，当前仍为']='Failed; still '
        ['如果本机用 DHCP，续租或重启网络时该文件可能被改回（那种情况需在 DHCP / 网络配置里固定 DNS）']='If this machine uses DHCP, the file may be reverted on lease renewal or network restart (in that case, pin the DNS in the DHCP / network config)'
        ['它的改动只写在自己的文件里（/etc/sysctl.d/99-tcpfit.conf 等），可用 tcpfit rollback 整体回滚']='Its changes only go into its own files (/etc/sysctl.d/99-tcpfit.conf etc.); use tcpfit rollback to revert them all'
        ['安装 / 更新 XanMod 内核（BBR v3，仅 x86_64）']='Install / update the XanMod kernel (BBR v3, x86_64 only)'
        ['安装 / 更新 XanMod 内核（内置 BBR v3）']='Install / update the XanMod kernel (built-in BBR v3)'
        ['安装 / 重装」重新选择通道']='Install / reinstall" to choose a channel again'
        ['安装 Fail2ban 并启用 SSH 防护']='Install Fail2ban and enable SSH protection'
        ['安装 Fail2ban」生成']='Install Fail2ban" to generate'
        ['安装 Fail2ban」（或 adam f2b install）']='Install Fail2ban" (or adam f2b install)'
        ['安装 Snell Server（Surge 官方，v']='Install Snell Server (Surge official, v'
        ['安装 Snell」（或 adam snell install）']='Install Snell" (or adam snell install)'
        ['安装 Xray」（或 adam xray install）']='Install Xray" (or adam xray install)'
        ['安装 Xray（SS / VLESS）']='Install Xray (SS / VLESS)'
        ['安装 acme.sh...']='Installing acme.sh...'
        ['安装中止']='Installation aborted'
        ['安装中止：请按日志排查（常见：密钥 / pin / 端口 / Portal 未设 out=egress / 载体与 Portal 监听不对应）']='Installation aborted: please troubleshoot using the log (common causes: key / pin / port / Portal not set to out=egress / carrier does not match the Portal'\''s listeners)'
        ['安装包 SHA256 校验失败，已中止']='Package SHA256 verification failed; aborted'
        ['安装失败，请检查 apt 源/网络']='Installation failed; please check apt sources / network'
        ['安装快捷命令']='Install the shortcut commands'
        ['安装测试版']='Install the beta'
        ['安装系统依赖']='Install system dependencies'
        ['安装防火墙」（或 adam fw install）']='Install the firewall" (or adam fw install)'
        ['安装防火墙（ufw）']='Install the firewall (ufw)'
        ['官方已发布更高大版本']='A newer major version has been released'
        ['官方已有更高大版本']='A newer major version is already available'
        ['官方目前只有 v']='Officially there is currently only v'
        ['实时日志（Ctrl+C 退出）']='Live logs (Ctrl+C to exit)'
        ['客户端连接 CDN 的端口（回车默认 443）:']='Port clients use to connect to the CDN (Enter = 443):'
        ['客户端连接用的公网地址（回车使用']='Public address clients connect to (Enter = use '
        ['客户端需要同步修改，新的配置行如下']='Clients need to update in sync; the new config line:'
        ['密码:']='Password:'
        ['密钥   :']='Key   :'
        ['密钥不符合 v3 规范：必须是恰好 32 位小写十六进制字符，不能回车自动生成（必须与 Portal 一致）']='Key does not meet the v3 spec: it must be exactly 32 lowercase hex chars; it cannot be auto-generated with Enter (must match the Portal)'
        ['对端已就绪，继续升级']='Peers are ready; continue the upgrade'
        ['封禁动作:']='Ban action:'
        ['封禁失败（jail']='Ban failed (jail '
        ['封禁日志 / 查看被封 IP']='Ban log / view banned IPs'
        ['封禁时长 :']='Ban duration :'
        ['封禁时长:']='Ban duration:'
        ['封禁时长已改为']='Ban duration changed to'
        ['将卸载:']='Will uninstall:'
        ['将重新走一遍安装向导并覆盖当前配置']='Will run the install wizard again and overwrite the current config'
        ['尚未安装 Fail2ban，请先执行「1']='Fail2ban is not installed yet; please run "1'
        ['尚未安装 ufw，请先在防火墙菜单执行「1']='ufw is not installed yet; please run "1 in the firewall menu'
        ['属于 NW']='belongs to NW'
        ['属于新的协议代（NW']='belongs to a new protocol generation (NW'
        ['已从仓库更新:']='Updated from the repo:'
        ['已从备份恢复 /etc/resolv.conf']='Restored /etc/resolv.conf from backup'
        ['已从当前服务启动日志读取到自签证书 SHA-256 指纹：']='Read the self-signed certificate SHA-256 fingerprint from the current service startup log:'
        ['已保留，如需清除请手动删除）']='Kept; delete manually if you want to remove it)'
        ['已修正为 IPv4 优先，现在可以正常连接 Let']='Fixed to prefer IPv4; can now connect to Let'
        ['已停止']='Stopped'
        ['已关闭 Snell 自动更新（保活巡检不受影响）']='Snell auto-update disabled (keepalive watchdog unaffected)'
        ['已写入 /etc/resolv.conf:']='Written to /etc/resolv.conf:'
        ['已切换，当前:']='Switched; current:'
        ['已删除']='Deleted'
        ['已删除放行规则:']='Deleted allow rules:'
        ['已删除规则']='Deleted rules'
        ['已加入内核保留端口']='Added to kernel reserved ports'
        ['已取消安装']='Installation cancelled'
        ['已取消，防火墙保持未启用']='Cancelled; firewall stays disabled'
        ['已启动并监听 TCP']='Started and listening on TCP'
        ['已回退到:']='Rolled back to:'
        ['已在白名单中']='Already in the allowlist'
        ['已安装的 XanMod 包:']='Installed XanMod packages:'
        ['已安装续期 hook：证书更新后自动 restart nowhere']='Renewal hook installed: nowhere restarts automatically after a certificate update'
        ['已封禁']='Banned'
        ['已开启 Snell 自动更新：每日维护任务（凌晨 4–6 点）检查官方发布，']='Snell auto-update enabled: the daily maintenance task (04:00–06:00) checks official releases,'
        ['已恢复']='Restored'
        ['已恢复原来的 /etc/gai.conf']='Restored the original /etc/gai.conf'
        ['已恢复附加端口']='Additional ports restored'
        ['已恢复（原系统没有 /etc/gai.conf，已删除）']='Restored (the system had no /etc/gai.conf; deleted it)'
        ['已接入 CDN 的域名（如 cdn.example.com）:']='Domain behind a CDN (e.g. cdn.example.com):'
        ['已放行']='Allowed'
        ['已放行本脚本服务端口:']='Allowed this script'\''s service ports:'
        ['已放行的端口']='Allowed ports'
        ['已是最新版本']='Already the latest version'
        ['已更新']='Updated'
        ['已检测到 nowhere 二进制（']='Detected a nowhere binary ('
        ['已添加并生效']='Added and in effect'
        ['已添加并监听']='Added and listening'
        ['已生成 PSK:']='Generated PSK:'
        ['已生成密钥:']='Generated key:'
        ['已确认 SSH 端口放行:']='Confirmed the SSH port is allowed:'
        ['已禁用（临时，重启恢复）']='Disabled (temporary; restored on reboot)'
        ['已禁用（永久）']='Disabled (permanent)'
        ['已移除 certbot 续期的 cron 兜底任务']='Removed the certbot renewal cron fallback task'
        ['已移除本脚本的 SSH 防护配置']='Removed this script'\''s SSH protection config'
        ['已移除本脚本的 systemd-resolved 配置，DNS 恢复为系统原设置']='Removed this script'\''s systemd-resolved config; DNS restored to system defaults'
        ['已经是最新版本，无需更新']='Already the latest version; no update needed'
        ['已经是本机的一份 Snell 附加端口配置']='Already one of this machine'\''s Snell additional-port configs'
        ['已经是该版本，无需切换']='Already on this version; no switch needed'
        ['已自动回滚，服务恢复运行:']='Auto-rolled back; service running again:'
        ['已自动更新:']='Auto-updated:'
        ['已被其他进程占用']='Already in use by another process'
        ['已被占用，请换一个']='Already in use; please choose another'
        ['已解封']='Unbanned'
        ['已解封所有 IP']='Unbanned all IPs'
        ['已设置为']='Set to'
        ['已跳过启用防火墙，请确认云厂商安全组 / 其他防火墙已放行:']='Skipped enabling the firewall; please confirm your cloud security group / other firewall allows:'
        ['已跳过演练：建议 90 天内用Nowhere 菜单「11']='Skipped the dry run: it is recommended to use Nowhere menu "11 within 90 days'
        ['已通过 systemd-resolved 设置 DNS:']='DNS set via systemd-resolved:'
        ['常用命令：']='Common commands:'
        ['常用命令：systemctl status nowhere / journalctl -u nowhere -f /']='Common commands: systemctl status nowhere / journalctl -u nowhere -f /'
        ['常见原因：证书路径错误、端口被抢占、密钥格式不合 v3 规范（必须 32 位小写十六进制）']='Common causes: wrong certificate path, port taken by another process, key format not meeting the v3 spec (must be 32 lowercase hex chars)'
        ['并重新导入本链接（链接已带 support-x25519mlkem768=true，不认识该参数的客户端会忽略它）']='And re-import this link (it already carries support-x25519mlkem768=true; clients that do not recognize this parameter will ignore it)'
        ['开启自动更新？']='Enable auto-update?'
        ['开启自动更新？（每天检查一次官方发布，']='Enable auto-update? (checks official releases once a day, '
        ['开启自动更新？（每日检查官方发布；先用新内核校验配置，失败不换，启动失败自动回滚）']='Enable auto-update? (checks official releases daily; validates the config with the new core first, does not switch on failure, auto-rolls back on startup failure)'
        ['当前 DNS：']='Current DNS:'
        ['当前 Portal 仅 QUIC/UDP，Vector 载体自动选 udp']='Current Portal is QUIC/UDP only; the Vector carrier is auto-selected as udp'
        ['当前 Portal 仅 TLS/TCP，Egress 载体自动选 tcp（出口机需']='Current Portal is TLS/TCP only; the Egress carrier is auto-selected as tcp (exit machines need '
        ['当前 Portal 仅 TLS/TCP，Vector 载体自动选 tcp']='Current Portal is TLS/TCP only; the Vector carrier is auto-selected as tcp'
        ['当前 tcpfit 版本:']='Current tcpfit version:'
        ['当前 tls=2 证书 SHA-256 指纹（续期后会变化）：']='Current tls=2 certificate SHA-256 fingerprint (changes after renewal):'
        ['当前:']='Current:'
        ['当前: IPv6']='Current: IPv6'
        ['当前为纯 QUIC/UDP Portal，没有 TLS 监听，且启动日志中未找到指纹']='Current setup is a pure QUIC/UDP Portal with no TLS listener, and no fingerprint was found in the startup log'
        ['当前为自签模式（tls=1），证书只存在内存中、无需续期']='Currently in self-signed mode (tls=1); the certificate lives only in memory and needs no renewal'
        ['当前保存的共享密钥不符合 v3 规范（必须是恰好 32 位小写十六进制字符）']='The saved shared key does not meet the v3 spec (must be exactly 32 lowercase hex chars)'
        ['当前内核:']='Current kernel:'
        ['当前安装的是']='Currently installed: '
        ['当前安装的是测试版']='The currently installed version is a beta'
        ['当前密钥不符合 v3 规范，无法探测，请先用 Nowhere 菜单 3 重新配置']='The current key does not meet the v3 spec and cannot be probed; please reconfigure via Nowhere menu 3 first'
        ['当前封禁']='Currently banned:'
        ['当前封禁列表：']='Current ban list:'
        ['当前封禁时长:']='Current ban duration:'
        ['当前已是 tls=2 真实证书模式，无需迁移（证书状态见 Nowhere 菜单 11）']='Already in tls=2 real-certificate mode; no migration needed (see Nowhere menu 11 for certificate status)'
        ['当前是容器类虚拟化（']='Currently running in container-style virtualization ('
        ['当前版本 :']='Current version :'
        ['当前白名单（这些来源永远不会被封）:']='Current allowlist (these sources are never banned):'
        ['当前系统与网络状态']='Current system and network status'
        ['当前规则：']='Current rules:'
        ['当前解析不到任何 A 记录（DNS 未生效或拼写错误），HTTP-01 很可能失败']='No A record resolves right now (DNS not in effect or a typo); HTTP-01 will most likely fail'
        ['当前触发条件:']='Current trigger conditions:'
        ['当前该域名的证书状态：']='Current certificate status for this domain:'
        ['当前语言：']='Current language:'
        ['当前运行的二进制  :']='Currently running binary  :'
        ['当前：端口']='Current: port '
        ['快捷命令已删除（管理脚本副本']='Shortcut commands deleted (management script copy '
        ['快捷命令已安装完成']='Shortcut commands installed'
        ['快捷命令无法安装']='Shortcut commands cannot be installed'
        ['恢复启用    0']='Restore and enable    0'
        ['恢复失败：可能有其他 sysctl 配置文件也禁用了 IPv6（grep -r disable_ipv6 /etc/sysctl.d /etc/sysctl.conf）']='Restore failed: other sysctl config files may also disable IPv6 (grep -r disable_ipv6 /etc/sysctl.d /etc/sysctl.conf)'
        ['恢复完成（已重启启用的服务）']='Restore complete (enabled services restarted)'
        ['恢复？']='Restore?'
        ['您之前选择了「其他/手动」DNS 服务商：需先手动完成 DNS TXT 验证签发证书，本脚本无法一键接管。请重新运行并改选 Cloudflare（推荐）/ DNSPod / 阿里云']='You previously chose the "Other/Manual" DNS provider: you must first complete DNS TXT verification manually to get the certificate; this script cannot take that over in one click. Please re-run and choose Cloudflare (recommended) / DNSPod / Alibaba Cloud instead'
        ['手动封禁一个 IP']='Manually ban an IP'
        ['手动解封一个 IP']='Manually unban an IP'
        ['打包失败']='Packaging failed'
        ['执行完毕']='Done'
        ['扫码导入 Anywhere（QUIC/UDP）：']='Scan to import into Anywhere (QUIC/UDP):'
        ['扫码导入 Anywhere（TLS/TCP）：']='Scan to import into Anywhere (TLS/TCP):'
        ['找不到备份文件：']='Backup file not found:'
        ['找不到节点']='Node not found'
        ['把你当前的登录 IP（']='Add your current login IP ('
        ['拥塞控制   :']='Congestion control   :'
        ['拥塞控制:']='Congestion control:'
        ['按日志文件方式启动失败（常见原因：系统没有 /var/log/auth.log），改用 systemd journal 后端重试 ...']='Failed to start in log-file mode (common cause: the system has no /var/log/auth.log); retrying with the systemd journal backend ...'
        ['按端口']='By port'
        ['按规则编号（上表方括号里的数字）']='By rule number (the numbers in square brackets in the table above)'
        ['探测 :']='Probe :'
        ['探测未成功（Result 非 OK）。常见原因：Portal 出口不可达、没有可用的 Egress（会等到 Flow 建立超时）、对端 Morph/pin/密钥不一致、目标本身不可达']='Probe did not succeed (Result is not OK). Common causes: Portal egress unreachable, no available Egress (waits until the Flow setup timeout), peer Morph/pin/key mismatch, or the target itself unreachable'
        ['接替为主配置（']='Taking over as the main config ('
        ['接替后主服务未能启动，已恢复原样。日志：']='The main service failed to start after the takeover; restored as before. Log:'
        ['提示：Cloudflare 回源 HTTPS 只支持 443/2053/2083/2087/2096/8443 这几个端口']='Note: Cloudflare origin-pull HTTPS only supports ports 443/2053/2083/2087/2096/8443'
        ['提示：Docker 用 -p 发布的端口走 FORWARD 链，不受 ufw 入站规则限制']='Note: ports published by Docker with -p go through the FORWARD chain and are not limited by ufw inbound rules'
        ['提示：官方已发布更高大版本']='Note: a newer major version has been released'
        ['提示：官方已有更高大版本']='Note: a newer major version is already available'
        ['提醒（v3 官方说明）：Vector/Egress 默认校验系统 CA + 主机名，自签证书必须改用 pin= 指纹锁定']='Reminder (official v3 docs): Vector/Egress verify the system CA + hostname by default; self-signed certificates must use pin= fingerprint locking instead'
        ['握手超时      :']='Handshake timeout      :'
        ['握手超时    :']='Handshake timeout    :'
        ['握手超时 NOW_HANDSHAKE_TIMEOUT（v3.3.0 起未设置时从 Shared Key 派生 3s–30s；持续时间格式如 10s/500ms/1m/1h，回车默认 10s）:']='Handshake timeout NOW_HANDSHAKE_TIMEOUT (since v3.3.0, when unset it is derived from the Shared Key, 3s–30s; duration format e.g. 10s/500ms/1m/1h; Enter = 10s):'
        ['操作完成！']='Done!'
        ['支持 TLS 1.3 + HTTP/2（也可能只是本机到它的网络不通），如连不上请换一个站点']='Supports TLS 1.3 + HTTP/2 (or it may just be that the network from this machine to it is down); if you cannot connect, pick another site'
        ['支持 TLS 1.3 + HTTP/2，可用']='Supports TLS 1.3 + HTTP/2; usable'
        ['改为跟随最新预发布版']='Switch to following the latest pre-release'
        ['放行']='Allow'
        ['放行端口」添加后再启用']='Allow ports" first, then enable'
        ['文件']='File'
        ['新二进制无法在本机运行（缺少依赖库或架构不符）:']='The new binary cannot run on this machine (missing libraries or wrong architecture):'
        ['新增']='Add '
        ['新增 Snell 端口配置']='Add a Snell port config'
        ['新版 Xray 内核客户端可连；mihomo 内核需较新版本并重新导入链接；部分客户端（如当时的 sing-box）连不上']='Clients with the new Xray core can connect; mihomo cores need a newer version and the link re-imported; some clients (e.g. sing-box at the time) cannot connect'
        ['新版本即自动升级，启动失败自动回滚']='New versions auto-upgrade; auto-rollback on startup failure'
        ['新版本启动失败，日志如下：']='New version failed to start; log:'
        ['新版本就自动升级，失败自动回滚）']='New versions auto-upgrade; auto-rollback on failure)'
        ['新的 PSK（12-255 位，仅限字母、数字、- 和 _）:']='New PSK (12-255 chars; letters, digits, - and _ only):'
        ['新的封禁时长（纯数字=分钟；也可写 10m / 1h / 1d / 1w；-1=永久）']='New ban duration (plain number = minutes; also accepts 10m / 1h / 1d / 1w; -1 = forever)'
        ['新的监听端口:']='New listen port:'
        ['新端口使用独立的 PSK 与 mode，和现有端口互不影响（可以给不同设备 / 不同用途各用一份）']='A new port uses its own PSK and mode and does not affect existing ports (you can give each device / use case its own)'
        ['新端口未能启动，已撤回。日志：']='The new port failed to start and was withdrawn. Log:'
        ['新节点未能生效，已撤回本次改动']='The new node did not take effect; this change was withdrawn'
        ['新配置启动失败，已恢复原配置。日志：']='The new config failed to start; the original config was restored. Log:'
        ['无法取得官方校验值（API digest 与校验文件均不可用），跳过校验（本次经 HTTPS 直连 GitHub 下载）']='Cannot get the official checksum (neither the API digest nor the checksum file is available); skipping verification (this download goes directly to GitHub over HTTPS)'
        ['无法查询最新版本，请检查网络']='Cannot query the latest version; please check the network'
        ['无法获取版本号，请检查网络']='Cannot get the version number; please check the network'
        ['无法识别发行版代号，不能添加 XanMod 软件源']='Cannot identify the distro codename; cannot add the XanMod repo'
        ['无法识别的端口写法:']='Unrecognized port format:'
        ['无法读取证书有效期（文件缺失或损坏），建议重新签发']='Cannot read the certificate validity (file missing or damaged); reissuing is recommended'
        ['无法通过现有配置的校验，保持']='Cannot pass validation with the current config; keeping '
        ['无节点']='No nodes'
        ['日志 :']='Log :'
        ['日志后端 :']='Log backend :'
        ['日志清理完成']='Journal log cleanup complete'
        ['旧客户端会表现为超时 / reality verification failed；请使用新版 Xray 内核客户端，mihomo 内核需较新版本']='Old clients will show timeouts / reality verification failed; please use a newer Xray core client; mihomo cores need a newer version'
        ['旧版任意字符串/Base64 密钥在 v3 会被拒绝启动，请重新输入或直接回车自动生成']='Old-style arbitrary string/Base64 keys are rejected at v3 startup; please re-enter or just press Enter to auto-generate'
        ['旧的 pin= 连接串随即失效，需用新生成的连接串同步所有对端。']='The old pin= connection strings stop working immediately; sync all peers with the newly generated ones.'
        ['明文 HTTP 回源（Cloudflare 选「灵活 Flexible」；回源端口须是 80/8080/8880/2052/2082/2086/2095 之一）']='Plaintext HTTP origin-pull (choose "Flexible" in Cloudflare; the origin port must be one of 80/8080/8880/2052/2082/2086/2095)'
        ['是 SSH 端口的放行规则:']='is an allow rule for the SSH port:'
        ['是主端口配置：删除后由附加端口']='is the main port config: after deletion, an additional port '
        ['是否同时删除快捷命令 adam/zt/pz/cxpz/cq？']='Also delete the shortcut commands adam/zt/pz/cxpz/cq?'
        ['是否已启用？）']='already enabled?)'
        ['是否开启']='Enable?'
        ['是否改用 dial4/dial6 分别绑定 IPv4/IPv6 源地址？']='Use dial4/dial6 to bind IPv4/IPv6 source addresses separately?'
        ['是否现在启用防火墙？（默认拒绝入站，仅放行已添加的端口）']='Enable the firewall now? (deny inbound by default; only allow added ports)'
        ['是否生成 Egress 连接信息？']='Generate Egress connection info?'
        ['是否生成 Vector 连接信息？']='Generate Vector connection info?'
        ['是否立即做一次续期演练（certbot renew --dry-run，不消耗 LE 配额）？']='Run a renewal dry run now (certbot renew --dry-run; does not consume LE quota)?'
        ['是否立即手动触发一次续期检查？（仅当证书满足续期条件时才会真的续签）']='Trigger a manual renewal check now? (it only actually renews when the certificate meets the renewal conditions)'
        ['是否限制监听地址族？（默认不限；IPv6 未真正开通的 VPS 可选仅 IPv4）']='Limit the listen address family? (no limit by default; VPSes without real IPv6 can pick IPv4 only)'
        ['是唯一的一份配置，删除它等于卸载 Snell']='is the only config; deleting it is the same as uninstalling Snell'
        ['是当前的 SSH 端口']='is the current SSH port'
        ['暂时取不到官方发布信息，无法判断是否有新版本']='Cannot fetch official release info right now; cannot tell whether a new version exists'
        ['暂时连不上官方下载站，无法判断是否有新版本']='Cannot reach the official download site right now; cannot tell whether a new version exists'
        ['暂未获取到指纹，可稍后运行: journalctl -u nowhere -n 100']='Fingerprint not fetched yet; you can run later: journalctl -u nowhere -n 100'
        ['更换内核有风险：请确认服务商面板有 VNC / 救援模式，万一新内核起不来可以回到旧内核']='Changing the kernel is risky: please confirm your provider panel has VNC / rescue mode so you can go back to the old kernel if the new one fails to boot'
        ['更新 Nowhere 二进制」升级']='Update Nowhere binary" to upgrade'
        ['更新 Nowhere 二进制（更新到最新版）']='Update Nowhere binary (update to the latest)'
        ['更新失败']='Update failed'
        ['更新管理脚本']='Update the management script'
        ['更新，按']='update, by '
        ['最大失败次数 maxretry']='Max failures maxretry'
        ['最快导入方式（QUIC/UDP）：']='Fastest import method (QUIC/UDP):'
        ['最快导入方式（TLS/TCP）：']='Fastest import method (TLS/TCP):'
        ['最近一次每日任务输出：']='Last daily task output:'
        ['最近日志（20行）：']='Recent log (20 lines):'
        ['最近的封禁 / 解封记录：']='Recent ban / unban records:'
        ['最近的维护事件（']='Recent maintenance events ('
        ['最近的维护记录：']='Recent maintenance records:'
        ['最近错误日志（nowhere，5 行）：']='Recent error log (nowhere, 5 lines):'
        ['有新版本可用:']='New version available:'
        ['服务单元已启用崩溃自动拉起']='Service unit has crash auto-restart enabled'
        ['服务单元未启用 Restart=always（旧版单元）']='Service unit does not have Restart=always enabled (old unit)'
        ['服务启动成功，且已确认端口正在监听']='Service started; ports confirmed listening'
        ['服务器 :']='Server :'
        ['服务处于不确定状态，建议排查后再连接客户端，否则会一直 timeout']='Service is in an uncertain state; please troubleshoot before connecting clients, otherwise it will keep timing out'
        ['服务未能启动，查看日志排查：']='Service failed to start; check the log:'
        ['未修改（为空或格式不合法）']='Not changed (empty or invalid format)'
        ['未加入内核保留端口（可能被出站连接占用导致重启后绑定失败）']='Not added to kernel reserved ports (outbound connections may take them and cause bind failures after reboot)'
        ['未发现 acme.sh 自动续期任务！']='No acme.sh auto-renewal task found!'
        ['未发现有效的自动续期任务！']='No valid auto-renewal task found!'
        ['未在 root 的 crontab 中找到 acme.sh 定时任务，自动续期可能不工作']='No acme.sh scheduled task found in root'\''s crontab; auto-renewal may not work'
        ['未填 pin：自签证书走系统 CA 校验必然失败，服务会反复重连']='No pin filled in: self-signed certificates will always fail system CA verification, and the service will keep reconnecting'
        ['未安装 ufw，已跳过防火墙配置（可用主菜单「5']='ufw not installed; firewall config skipped (use main menu "5'
        ['未找到 Nowhere 二进制，请先安装']='Nowhere binary not found; please install first'
        ['未找到 apt-get（本脚本仅支持 Debian/Ubuntu），请手动安装:']='apt-get not found (this script only supports Debian/Ubuntu); please install manually:'
        ['未找到 certbot.timer，改用 cron 兜底（每天 3:00 / 15:00 检查续期）']='certbot.timer not found; using a cron fallback instead (checks renewal daily at 3:00 / 15:00)'
        ['未找到本脚本的 SSH 防护配置，请先执行「1']='This script'\''s SSH protection config not found; please run "1'
        ['未找到配置，请先安装']='Config not found; please install first'
        ['未更新（服务刚重启时可稍等再用 Nowhere 菜单 10 查看）']='Not updated yet (if the service just restarted, wait a bit and check with Nowhere menu 10)'
        ['未检测到 Snell 安装']='No Snell installation detected'
        ['未检测到已安装的 Nowhere 二进制']='No installed Nowhere binary detected'
        ['未检测到本模块安装的 Xray']='No Xray installed by this module detected'
        ['未知参数会被静默忽略，千万不要再往启动串里手动拼旧参数。']='Unknown parameters are silently ignored; never manually append old parameters to the launch string again.'
        ['未知操作:']='Unknown action:'
        ['未知的 f2b 子命令:']='Unknown f2b subcommand:'
        ['未知的 fw 子命令:']='Unknown fw subcommand:'
        ['未知的 snell 子命令:']='Unknown snell subcommand:'
        ['未知的 tune 子命令:']='Unknown tune subcommand:'
        ['未知的 xray 子命令:']='Unknown xray subcommand:'
        ['未能下载官方校验文件']='Failed to download the official checksum file'
        ['未能从']='Could not get it from '
        ['未能从官方发布页取得 v']='Could not get v from the official release page'
        ['未能确定公网地址，无法生成 Egress 连接串，可稍后通过Nowhere 菜单「4']='Could not determine the public address; cannot generate the Egress connection string; retry later via Nowhere menu "4'
        ['未能确定公网地址，无法生成 Vector 连接串，可稍后通过Nowhere 菜单「4']='Could not determine the public address; cannot generate the Vector connection string; retry later via Nowhere menu "4'
        ['未能获取']='Could not fetch '
        ['未能获取 Xray 官方发布信息（GitHub 不可达或被限流），请稍后重试，或选「指定版本」']='Could not fetch official Xray release info (GitHub unreachable or rate-limited); please retry later, or choose "Specify version"'
        ['未能获取官方版本信息（']='Could not fetch official version info ('
        ['未能获取版本列表，请检查网络']='Could not fetch the version list; please check the network'
        ['未能获取自签证书指纹，Egress 连接串暂缺 pin=（服务启动后可用 Nowhere 菜单 4 重新生成）']='Could not fetch the self-signed certificate fingerprint; the Egress connection string is missing pin= for now (regenerate via Nowhere menu 4 after the service starts)'
        ['未能获取自签证书指纹，Vector 连接串暂缺 pin=（服务启动后可用 Nowhere 菜单 4 重新生成）']='Could not fetch the self-signed certificate fingerprint; the Vector connection string is missing pin= for now (regenerate via Nowhere menu 4 after the service starts)'
        ['未能读取当前自签指纹，']='Could not read the current self-signed fingerprint, '
        ['未设为开机自启']='Not set to start on boot'
        ['未运行']='Not running'
        ['未运行或没有在监听']='Not running or not listening'
        ['本 Portal 已固定 out=egress：没有可用的 Egress 时，新连接会在 Flow 建立超时（NOW_FLOW_SETUP_TIMEOUT，默认 20s）内等待注册，超时即失败，不会回退直连']='This Portal has out=egress pinned: with no Egress available, new connections wait for registration within the Flow setup timeout (NOW_FLOW_SETUP_TIMEOUT, default 20s); on timeout they fail and do not fall back to direct'
        ['本地 SOCKS5 监听 in=（回车默认']='Local SOCKS5 listener in= (Enter = default '
        ['本地 Vector 客户端连接信息']='Local Vector client connection info'
        ['本地监听 in=']='Local listener in='
        ['本机']='This machine'
        ['本机不再是 Portal：删除防火墙里原 Portal 端口的放行规则（']='This machine is no longer a Portal: delete the firewall allow rules for the original Portal ports ('
        ['本机不是 Portal 角色（当前：']='This machine is not in the Portal role (current: '
        ['本机为 Egress 角色，但未找到']='This machine is in the Egress role, but could not find '
        ['本机将作为出口机（Egress），主动回连 Portal；这会覆盖本机现有的 nowhere.service']='This machine will act as an exit machine (Egress) and connect back to the Portal; this will overwrite this machine'\''s existing nowhere.service'
        ['本机已安装的']='Already installed on this machine: '
        ['本机当前是 Egress 角色：继续安装会把 nowhere.service 换成 Portal']='This machine is currently in the Egress role: continuing the install will replace nowhere.service with a Portal'
        ['本机是 Egress 角色，不持有监听证书，无需续期']='This machine is in the Egress role and holds no listening certificate; no renewal needed'
        ['本机是 Egress 角色，没有监听证书；Portal 的证书指纹请在 Portal 机上查看']='This machine is in the Egress role with no listening certificate; check the Portal'\''s certificate fingerprint on the Portal machine'
        ['本机是 Egress 角色：probe 需要以 Vector 身份连接 Portal，请在 Portal 机或客户端机上执行']='This machine is in the Egress role: probe needs to connect to the Portal as a Vector; please run it on the Portal machine or a client machine'
        ['本机角色          :']='This machine'\''s role          :'
        ['本机角色    : Egress（主动回连 Portal，无需本机开放入站端口）']='This machine'\''s role    : Egress (connects back to the Portal; this machine needs no inbound port)'
        ['本次升级会跨过 v3.2.0：此后 Portal 只接受带认证的 Morph TCP Prelude，仍在 v3.0.x 的 Vector/Egress/Anywhere（morph=1 + TLS/TCP）会连不上']='This upgrade crosses v3.2.0: after that, the Portal only accepts authenticated Morph TCP Prelude; Vector/Egress/Anywhere still on v3.0.x (morph=1 + TLS/TCP) will no longer connect'
        ['本节点用于套 CDN（如 Cloudflare）：客户端连 CDN 的域名，CDN 再回源到本机。']='This node is for use behind a CDN (e.g. Cloudflare): clients connect to the CDN'\''s domain, and the CDN pulls from this machine.'
        ['本配置为 NW3 协议：v1/v2 的 Portal/Vector 以及未支持 NW3 的']='This config uses the NW3 protocol: v1/v2 Portal/Vector and peers not supporting NW3'
        ['某个端口配置（可选任意一个端口）']='A port config (any port can be chosen)'
        ['查看 tcpfit 状态    2']='View tcpfit status    2'
        ['查看当前 DNS    2']='View current DNS    2'
        ['查看当前状态']='View current status'
        ['查看当前状态」确认，再用「1']='View current status" to confirm, then use "1'
        ['查看节点配置 / 分享链接']='View node configs / share links'
        ['查看记录: adam maintain-log    或 journalctl -u adam-maintain --no-pager -n 30']='View records: adam maintain-log    or journalctl -u adam-maintain --no-pager -n 30'
        ['查看配置 / Surge 节点配置行（全部端口）']='View config / Surge node config lines (all ports)'
        ['校验时找不到已下载的安装包']='The downloaded package could not be found during verification'
        ['格式不合法（须为正数+单位，如 10s / 500ms / 1m / 1h），已重置为 10s']='Invalid format (must be a positive number + unit, e.g. 10s / 500ms / 1m / 1h); reset to 10s'
        ['格式不合法（须为正数+单位，如 10s），已重置为 10s']='Invalid format (must be a positive number + unit, e.g. 10s); reset to 10s'
        ['格式：32 位小写十六进制（16 随机字节）。Portal、Vector、Egress、Anywhere 四端必须填完全相同的这串字符']='Format: 32 lowercase hex chars (16 random bytes). Portal, Vector, Egress and Anywhere must all fill in exactly the same string'
        ['检查 Snell 更新']='Check for Snell updates'
        ['检查 Xray 更新']='Check for Xray updates'
        ['检查并更新 tcpfit    0']='Check and update tcpfit    0'
        ['检查并更新内核']='Check and update the kernel'
        ['检查并更新到官方最新版']='Check and update to the official latest'
        ['检查证书状态 / 手动续期」验证一次']='Check certificate status / manual renewal" to verify once'
        ['检测到 cnblock 的端口防火墙链 FWIN 已挂在 INPUT 上：两套入站防火墙会叠加（两边都放行才通），建议只保留一套（cnblock fw off，或不启用 ufw）']='Detected that cnblock'\''s port firewall chain FWIN is already attached to INPUT: two inbound firewalls stack (traffic passes only if both allow it); it is recommended to keep only one (cnblock fw off, or do not enable ufw)'
        ['检测到 firewalld 正在运行，与 ufw 同时启用会互相覆盖规则，请只保留一个']='Detected firewalld is running; enabling it together with ufw will overwrite each other'\''s rules, please keep only one'
        ['检测到已有 Snell 配置（端口']='Detected an existing Snell config (port '
        ['检测到已有配置，已备份到']='Detected an existing config; backed up to '
        ['检测到旧版配置：SOCKS5 已由 socks= 迁移为 Portal 的 out=，已自动沿用该地址']='Detected an old config: SOCKS5 has migrated from socks= to the Portal'\''s out=; the address was carried over automatically'
        ['检测到旧版（NW1）配置文件。v3 还要求：密钥改为 32 位十六进制、删除 alpn/net/log/pool 参数，建议用Nowhere 菜单「3']='Detected an old (NW1) config file. v3 also requires: change the key to 32 hex chars and remove the alpn/net/log/pool parameters; it is recommended to use Nowhere menu "3'
        ['检测到本机当前是 Portal 角色：继续会把本机切换为 Egress（Portal 配置文件保留，但服务被替换）']='Detected that this machine is currently in the Portal role: continuing will switch it to Egress (the Portal config file is kept, but the service is replaced)'
        ['检测到本机还有其他 Xray（官方脚本安装的 xray.service 或 3x-ui）：本模块完全独立，互不影响，只需注意端口不要重复']='Detected other Xray installs on this machine (xray.service from the official script, or 3x-ui): this module is fully independent and does not interfere; just make sure ports do not overlap'
        ['检测到本机配置了 IPv6 地址，测试实际是否能连通外网...']='Detected that this machine has an IPv6 address configured; testing whether it can actually reach the internet...'
        ['检测到目标端口已被其他进程占用：']='Detected that the target port is already in use by another process:'
        ['检测到证书已续期，已同步并重启']='Detected that the certificate was renewed; synced and restarted'
        ['正在回滚到旧版本']='Rolling back to the old version'
        ['正在安装 ufw ...']='Installing ufw ...'
        ['正在安装:']='Installing:'
        ['正在更新软件包列表 ...']='Updating the package list ...'
        ['正在查询 GitHub 最新版本...']='Querying GitHub for the latest version...'
        ['正在查询 Surge 官方发布页 ...']='Querying the official Surge release page ...'
        ['正在查询官方最新版本（发布页 + 下载站探测，约几秒）...']='Querying the official latest version (release page + download-site probe, a few seconds)...'
        ['正在自动回滚到备份二进制']='Auto-rolling back to the backup binary'
        ['正在获取版本列表...']='Fetching the version list...'
        ['正在获取自签证书 SHA-256 指纹...']='Fetching the self-signed certificate SHA-256 fingerprint...'
        ['正式版通道暂无 v']='No v on the stable channel yet'
        ['此时改系统 DNS 会让它失效或互相打架，已中止。请先执行 cnblock close，或改它的上游 DNS']='Changing the system DNS now would break it or cause conflicts; aborted. Please run cnblock close first, or change its upstream DNS'
        ['段）：']='segment):'
        ['每日维护 :']='Daily maintenance :'
        ['每日重启']='Daily restart'
        ['比发布页列出的']='newer than what the release page lists'
        ['永久禁用    3']='Permanently disable    3'
        ['永久禁用 IPv6（写入']='Permanently disable IPv6 (write to '
        ['没有 v']='No v'
        ['没有可回滚的备份二进制']='No backup binary to roll back to'
        ['没有可用于回退的本地备份版本']='No local backup version to roll back to'
        ['没有找到']='Not found'
        ['没有找到任何端口配置']='No port configs found'
        ['没有找到可备份的配置目录']='No config directories found to back up'
        ['没有找到标记为正式版的发布（最新为']='No release marked as stable found (latest is '
        ['没有本脚本做过的 DNS 改动可恢复']='No DNS changes made by this script to restore'
        ['没有本脚本做过的优先级改动可恢复']='No priority changes made by this script to restore'
        ['没有检测到已安装的 XanMod 内核包']='No installed XanMod kernel packages detected'
        ['没有输入任何服务器']='No servers entered'
        ['注意：v3 密钥与 URL 语法已变更，重新配置后务必把新的 Vector/Egress/Anywhere 连接信息同步到所有对端，旧链接无法继续使用']='Note: v3 keys and URL syntax have changed; after reconfiguring, sync the new Vector/Egress/Anywhere connection info to all peers; old links will no longer work'
        ['注意：下载到的脚本版本为']='Note: the downloaded script version is '
        ['注意：防火墙当前未启用，规则已保存，启用后才生效']='Note: the firewall is currently disabled; rules are saved and take effect once enabled'
        ['添加 IP / 网段    2']='Add IP / subnet    2'
        ['添加 Xray 节点']='Add an Xray node'
        ['添加节点']='Add node'
        ['添加节点」创建）']='Add node" to create)'
        ['清理 journal 日志，只保留最近 200M？']='Clean journal logs, keeping only the latest 200M?'
        ['清理失败']='Cleanup failed'
        ['演练中（约需 30-90 秒）...']='Dry run in progress (about 30-90 seconds)...'
        ['版本信息']='Version info'
        ['版本号格式不合法']='Invalid version format'
        ['版本号格式不正确']='Invalid version number format'
        ['版本号相同，仍要用远端内容覆盖本地脚本？']='Version numbers are the same; still overwrite the local script with the remote content?'
        ['版本回退']='Version rollback'
        ['版本已固定在']='Version pinned to'
        ['版本通道 :']='Version channel :'
        ['版本）']='version)'
        ['版本；测试版最新为']='version; latest beta is '
        ['状态 :']='Status :'
        ['状态异常（未运行或端口未监听），正在重启']='Status abnormal (not running or port not listening); restarting'
        ['现在添加第一个节点？']='Add the first node now?'
        ['现在重启？']='Restart now?'
        ['现有 URL / 密钥 / 证书无需迁移；要用 TLS 载体的 Egress，出口机也需']='Existing URLs / keys / certificates need no migration; to use a TLS-carrier Egress, the exit machine also needs '
        ['现有端口配置：']='Current port configs:'
        ['现有节点在该版本下未能启动，请查看日志或换一个版本']='Existing nodes failed to start under this version; please check the log or pick another version'
        ['现有节点已随新内核重启']='Existing nodes restarted with the new core'
        ['生成分享链接用的公网地址（回车使用']='Public address used to generate share links (Enter = use '
        ['生成失败：openssl 与 nowhere 二进制均不可用']='Failed to generate: neither openssl nor the nowhere binary is available'
        ['生成（carrier=']='Generating (carrier='
        ['用法: adam f2b ban <IP>']='Usage: adam f2b ban <IP>'
        ['用法: adam f2b unban <IP>']='Usage: adam f2b unban <IP>'
        ['用法: adam fw allow <端口']='Usage: adam fw allow <port'
        ['用法: adam fw deny <端口']='Usage: adam fw deny <port'
        ['用法：adam lang zh']='Usage: adam lang zh'
        ['用的是 pin=证书指纹 锁定方式，Portal 每次重启该指纹都会变，重启后需要重新生成本连接串（Nowhere 菜单 4 或 pz 命令）']='Uses pin= certificate-fingerprint locking; the fingerprint changes on every Portal restart, so this connection string must be regenerated afterwards (Nowhere menu 4 or the pz command)'
        ['由 Adam 管理脚本生成（adam -> Fail2ban 管理）。请通过菜单修改，手动改动会在下次调整时被覆盖。']='Generated by Adam'\''s management script (adam -> Fail2ban management). Please change it via the menu; manual edits will be overwritten on the next change.'
        ['由 Adam 管理脚本生成（系统与网络调优 -> DNS）。删除本文件并重启 systemd-resolved 即恢复。']='Generated by Adam'\''s management script (system & network tuning -> DNS). Delete this file and restart systemd-resolved to restore.'
        ['由 Adam 管理脚本生成（系统与网络调优 -> 禁用 IPv6）。删除本文件并执行 sysctl --system 即恢复。']='Generated by Adam'\''s management script (system & network tuning -> disable IPv6). Delete this file and run sysctl --system to restore.'
        ['由 Adam 管理脚本生成；原文件备份在']='Generated by Adam'\''s management script; original file backup at '
        ['由 Adam 管理脚本维护：Snell / Xray / Nowhere 的监听端口，避免被本机出站连接当作临时端口占用']='Maintained by Adam'\''s management script: listen ports of Snell / Xray / Nowhere, to keep them from being taken as ephemeral ports by this machine'\''s outbound connections'
        ['申请方式   :']='Issuance method   :'
        ['申请证书中（Cloudflare DNS-01，约需 30-60 秒）...']='Requesting the certificate (Cloudflare DNS-01, about 30-60 seconds)...'
        ['申请证书中（DNS-01:']='Requesting the certificate (DNS-01: '
        ['申请证书中（HTTP-01，需 80 端口）...']='Requesting the certificate (HTTP-01, needs port 80)...'
        ['白名单   :']='Allowlist   :'
        ['白名单已更新:']='Allowlist updated:'
        ['白名单管理']='Allowlist management'
        ['白名单里没有']='Not in the allowlist: '
        ['的 XanMod 内核包（发行版']='XanMod kernel packages (distro '
        ['的发布文件）:']='release files):'
        ['的回源端口指到']='point the origin port to '
        ['的放行规则']='allow rules'
        ['的测试版（']='beta releases ('
        ['的版本信息（']='version info ('
        ['的端口与 PSK 不变）']='port and PSK stay the same)'
        ['的证书装到本 Portal 并重启服务？']='certificate onto this Portal and restart the service?'
        ['的配置已删除']='config deleted'
        ['的配置格式管理，不自动跨大版本']='config format; no automatic cross-major-version upgrade'
        ['监听地址      :']='Listen address      :'
        ['监听地址格式不合法，已改为']='Invalid listen address format; changed to '
        ['监听地址（回车=']='Listen address (Enter = '
        ['监听端口（ss）：']='Listening ports (ss):'
        ['监听端口（回车使用']='Listening port (Enter = use '
        ['监听端口（回车默认443）:']='Listening port (Enter = 443):'
        ['目标地址 host:port（回车默认 example.com:443）:']='Target address host:port (Enter = example.com:443):'
        ['目标端口空闲，可以使用']='Target port is free and usable'
        ['目标（0=不限速）:']='Target (0 = unlimited):'
        ['直接运行（Snell 自动更新不受影响）']='Run directly (Snell auto-update unaffected)'
        ['确认从']='Confirm restoring from '
        ['确认使用 unsafe-raw？']='Confirm using unsafe-raw?'
        ['确认停用防火墙？']='Confirm disabling the firewall?'
        ['确认切换到']='Confirm switching to '
        ['确认删除主端口']='Confirm deleting the main port'
        ['确认删除节点']='Confirm deleting the node'
        ['确认删除附加端口']='Confirm deleting the additional port'
        ['确认卸载']='Confirm uninstall'
        ['确认卸载 Fail2ban？']='Confirm uninstalling Fail2ban?'
        ['确认卸载 Snell（全部端口配置:']='Confirm uninstalling Snell (all port configs: '
        ['确认卸载 Xray（本模块安装的 adam-xray）？']='Confirm uninstalling Xray (adam-xray installed by this module)?'
        ['确认卸载？（卸载后重启会回到发行版内核）']='Confirm uninstall? (after uninstalling, a reboot returns to the distro kernel)'
        ['确认启用防火墙？（默认拒绝所有入站，仅放行已添加的端口）']='Confirm enabling the firewall? (deny all inbound by default; only allow added ports)'
        ['确认回退']='Confirm rollback'
        ['确认安装']='Confirm installation'
        ['确认安装为 Egress 服务']='Confirm installing as an Egress service'
        ['确认把']='Confirm putting '
        ['确认本机有可用的 IPv4 登录方式并继续？']='Confirm this machine has a usable IPv4 login method and continue?'
        ['确认解封当前所有被封禁的 IP？']='Confirm unbanning all currently banned IPs?'
        ['确认跨代升级']='Confirm cross-generation upgrade'
        ['磁盘：']='Disk:'
        ['禁用 / 恢复 IPv6']='Disable / restore IPv6'
        ['禁用失败（内核可能未编译 IPv6 或 sysctl 被限制）']='Failed to disable (the kernel may not have IPv6 compiled in, or sysctl is restricted)'
        ['私钥文件路径（privkey.pem）:']='Private key file path (privkey.pem):'
        ['私钥路径:']='Private key path:'
        ['移除 IP / 网段    0']='Remove IP / subnet    0'
        ['稳妥做法：先把对端升级到']='Safer approach: upgrade the peers to '
        ['立即执行一次保活巡检...']='Running one keepalive check now...'
        ['立即执行一次每日维护（脚本自更新 / Snell / Xray 更新检查）...']='Running one daily maintenance now (script self-update / Snell / Xray update checks)...'
        ['端口   :']='Port   :'
        ['端口不合法']='Invalid port'
        ['端口不合法，重置为 443']='Invalid port; reset to 443'
        ['端口不合法，重置为2000']='Invalid port; reset to 2000'
        ['端口不合法，重置为2001']='Invalid port; reset to 2001'
        ['端口不合法，重置为443']='Invalid port; reset to 443'
        ['端口列表（带编号）']='Port list (numbered)'
        ['端口已变更，清理旧的放行规则:']='Port changed; cleaning up old allow rules:'
        ['端口模式      :']='Port mode      :'
        ['端口模式（v3 端点路径语法）：']='Port mode (v3 endpoint path syntax):'
        ['端口范围的起点必须小于终点:']='Port range start must be smaller than the end:'
        ['端口配置（多端口：每个端口独立 PSK）']='Port config (multiple ports: each port has its own PSK)'
        ['端口（TCP / UDP）']=' Ports (TCP / UDP)'
        ['端口（回车默认 443）:']='Port (Enter = 443):'
        ['第 1 步：选择证书获取方式']='Step 1: Choose how to get the certificate'
        ['第 10 步：配置防火墙（先于服务启动，避免中间态连不通）']='Step 10: Configure the firewall (before the service starts, to avoid a half-configured unreachable state)'
        ['第 11 步：创建并启动系统服务']='Step 11: Create and start the system service'
        ['第 12 步：生成连接信息']='Step 12: Generate connection info'
        ['第 13 步：安装快捷命令']='Step 13: Install the shortcut commands'
        ['第 2 步：基础网络信息']='Step 2: Basic network info'
        ['第 3 步：监听参数']='Step 3: Listen parameters'
        ['第 4 步：协议与安全参数']='Step 4: Protocol and security parameters'
        ['第 5 步：安装系统依赖']='Step 5: Install system dependencies'
        ['第 6 步：申请 TLS 证书']='Step 6: Request the TLS certificate'
        ['第 7 步：下载 Nowhere 二进制']='Step 7: Download the Nowhere binary'
        ['第 8 步：保存配置']='Step 8: Save the config'
        ['第 9 步：安装前端口占用检测']='Step 9: Pre-install port occupancy check'
        ['等旧参数均已移除或改名，']='and other old parameters have been removed or renamed,'
        ['管理脚本 :']='Management script :'
        ['管理脚本已更新到']='Management script updated to'
        ['管理脚本未能安装到']='Management script could not be installed to '
        ['管理脚本版本      :']='Management script version      :'
        ['粘贴 egress:// 连接串（输入不回显，回车 = 逐项填写）:']='Paste the egress:// connection string (input hidden; Enter = fill in each item):'
        ['系列，自动更新不跨大版本，跳过']='series; auto-update does not cross major versions; skipped'
        ['系统与网络调优']='System & network tuning'
        ['系统与网络调优:']='System & network tuning:'
        ['系统里没有其他已安装的内核镜像，卸载 XanMod 后将无法启动，已拒绝']='No other installed kernel images on the system; uninstalling XanMod would leave it unbootable; refused'
        ['统计窗口 findtime（如 10m / 1h，纯数字=分钟）']='Time window findtime (e.g. 10m / 1h; plain number = minutes)'
        ['继续安装 / 更新 XanMod 内核？']='Continue installing / updating the XanMod kernel?'
        ['续期 deploy hook 存在（续期后自动重启 nowhere）']='Renewal deploy hook exists (nowhere restarts automatically after renewal)'
        ['续期 deploy hook 缺失（续期后不会自动重启 nowhere）']='Renewal deploy hook missing (nowhere will not restart automatically after renewal)'
        ['续期检查完成']='Renewal check complete'
        ['续期检查完成（acme.sh 的 --reloadcmd 会自动重启 nowhere）']='Renewal check complete (acme.sh --reloadcmd restarts nowhere automatically)'
        ['续期演练未通过：请根据上方报错排查（如 80 端口被占、DNS 凭证失效），否则证书到期后服务会中断']='Renewal dry run failed: please troubleshoot using the error above (e.g. port 80 taken, DNS credentials invalid); otherwise the service will break when the certificate expires'
        ['续期演练通过，自动续期链路可信']='Renewal dry run passed; the auto-renewal chain is trustworthy'
        ['编号']='Number'
        ['自动更新 开 / 关']='Auto-update on / off'
        ['自动更新 开 / 关 / 切换通道（beta']='Auto-update on / off / switch channel (beta'
        ['自动更新到']='Auto-updated to '
        ['自动更新已开启，但每日维护定时器未运行']='Auto-update is on, but the daily maintenance timer is not running'
        ['自动更新当前为：关闭']='Auto-update is currently: off'
        ['自动更新当前为：开启（']='Auto-update is currently: on ('
        ['自动续期已就绪：acme.sh 的 cron 定时任务存在（每天检查，到期自动续签并执行 --reloadcmd 重启 nowhere）']='Auto-renewal ready: the acme.sh cron task exists (checks daily; auto-renews when due and runs --reloadcmd to restart nowhere)'
        ['自动续期已就绪：certbot.timer 运行中（每天两次检查续期）']='Auto-renewal ready: certbot.timer is running (checks renewal twice daily)'
        ['自动续期链路检查：']='Auto-renewal chain check:'
        ['自动维护:']='Auto-maintenance:'
        ['自定义 PSK']='Custom PSK'
        ['自签指纹已更新到']='Self-signed fingerprint updated to '
        ['自签模式下 Vector/Egress 的 pin 请从 Portal 启动日志含 fingerprint 的一行获取']='In self-signed mode, get the Vector/Egress pin from the Portal startup log line containing "fingerprint"'
        ['自签模式无需域名，将自动探测公网 IP 作为客户端连接地址']='Self-signed mode needs no domain; the public IP is auto-detected as the client connection address'
        ['自签证书 tls=1  - 无需域名，快速测试（Vector/Egress 必须用 pin= 锁定指纹，指纹随重启变化）']='Self-signed certificate tls=1 - no domain needed, quick testing (Vector/Egress must lock the fingerprint with pin=; the fingerprint changes on restart)'
        ['自签证书仅建议测试用，生产环境请用真实域名 + CA 签发证书（选 2/3/4）']='Self-signed certificates are for testing only; for production use a real domain + CA-issued certificate (choose 2/3/4)'
        ['自签证书指纹已随本次重启变化，请用 pz / Nowhere 菜单 4 重新生成带新 pin= 的 Vector/Egress 连接串并同步到对端']='The self-signed certificate fingerprint changed with this restart; please regenerate the Vector/Egress connection strings with the new pin= via pz / Nowhere menu 4 and sync them to all peers'
        ['自签证书生成失败']='Failed to generate the self-signed certificate'
        ['节点列表']='Node list'
        ['节点名称（回车使用']='Node name (Enter = use '
        ['节点名称（回车保持']='Node name (Enter = keep '
        ['节点数量 :']='Node count :'
        ['若刚修改 DNS，请确认已传播：dig +short']='If you just changed DNS, please confirm it has propagated: dig +short'
        ['规则']='Rule'
        ['解包失败，现有配置可能已不完整，请检查']='Unpack failed; the existing config may now be incomplete, please check'
        ['解压出的 snell-server 不是 Linux 可执行文件']='The extracted snell-server is not a Linux executable'
        ['解压后未找到 nowhere 二进制']='No nowhere binary found after extraction'
        ['解封失败（该 IP 可能本来就没有被封）']='Unban failed (this IP may never have been banned)'
        ['解封失败，请查看: fail2ban-client status']='Unban failed; see: fail2ban-client status '
        ['解封所有 IP']='Unban all IPs'
        ['解析到']='Resolves to '
        ['解析测试失败，请检查，或用「恢复 DNS」撤销']='Resolution test failed; please check, or use "Restore DNS" to revert'
        ['解析测试通过']='Resolution test passed'
        ['触发条件 :']='Trigger conditions :'
        ['触发条件已改为:']='Trigger conditions changed to:'
        ['认证方式：1']='Auth method: 1'
        ['让本管理脚本每天自动从仓库拉取更新？（地址:']='Let this management script pull updates from the repo daily? (URL: '
        ['记录的版本 tag    :']='Recorded version tag    :'
        ['记得在 CDN 侧：把']='Remember to set on the CDN side: '
        ['设置 DNS']='Set DNS'
        ['设置 DNS    3']='Set DNS    3'
        ['证书 SAN 中不包含域名']='The certificate SAN does not include the domain'
        ['证书与私钥不匹配']='Certificate and private key do not match'
        ['证书剩余约']='Certificate remaining: about '
        ['证书复制失败']='Failed to copy the certificate'
        ['证书安装（install-cert）失败']='Certificate install (install-cert) failed'
        ['证书已过期或无法解析']='Certificate expired or unparseable'
        ['证书或私钥文件不存在']='Certificate or private key file does not exist'
        ['证书文件无法读取：']='Certificate file cannot be read:'
        ['证书文件未生成：']='Certificate file not generated:'
        ['证书文件路径（fullchain.pem）:']='Certificate file path (fullchain.pem):'
        ['证书方式      :']='Certificate method      :'
        ['证书有效，剩余约']='Certificate valid, about '
        ['证书校验通过：']='Certificate verified:'
        ['证书状态与续期']='Certificate status & renewal'
        ['证书申请失败：检查 CF 凭证与域名归属']='Certificate issuance failed: check CF credentials and domain ownership'
        ['证书申请失败：检查域名解析与 80 端口']='Certificate issuance failed: check domain resolution and port 80'
        ['证书签发失败：请检查 DNS API 凭证是否正确、域名 DNS 是否由所选服务商托管']='Certificate issuance failed: please check whether the DNS API credentials are correct and whether the domain'\''s DNS is hosted by the selected provider'
        ['证书路径   :']='Certificate path   :'
        ['证书路径:']='Certificate path:'
        ['该密钥不符合 v3 规范：必须是恰好 32 位小写十六进制字符（0-9a-f）']='This key does not meet the v3 spec: it must be exactly 32 lowercase hex chars (0-9a-f)'
        ['该证书的域名列表里没有']='This certificate'\''s domain list does not include '
        ['语言已切换为']='Language switched to'
        ['请以 root 用户运行此脚本']='Please run this script as root'
        ['请先停止占用该端口的服务（旧的 Nowhere 实例已自动排除在外），否则新服务会反复崩溃重启，客户端表现为一直 timeout']='Please stop the service occupying this port first (old Nowhere instances are already excluded); otherwise the new service will crash and restart repeatedly, and clients will see constant timeouts'
        ['请先安装发行版内核：Debian 用 apt install linux-image-amd64，Ubuntu 用 apt install linux-image-generic']='Please install the distro kernel first: Debian: apt install linux-image-amd64, Ubuntu: apt install linux-image-generic'
        ['请把上面新的连接串同步到全部 Vector / Egress / Anywhere 对端，旧 pin= 连接串已失效']='Please sync the new connection strings above to all Vector / Egress / Anywhere peers; the old pin= connection strings no longer work'
        ['请把所有对端升级到']='Please upgrade all peers to '
        ['请改用文件方式运行：curl -fsSL']='Please run it via a file instead: curl -fsSL'
        ['请输入域名（如: nhk.example.com）:']='Please enter the domain (e.g. nhk.example.com):'
        ['请输入邮箱（用于证书申请/找回）:']='Please enter your email (for certificate issuance/recovery):'
        ['调整后仍无法连接，请检查 VPS 出网本身是否正常: ping -c 3 8.8.8.8']='Still cannot connect after the change; please check whether the VPS itself can reach the internet: ping -c 3 8.8.8.8'
        ['跟随最新版本前请了解：']='Before following the latest version, please know:'
        ['跨代升级后请接着用Nowhere 菜单「3']='After a cross-generation upgrade, continue with Nowhere menu "3'
        ['软件源已保留（/etc/apt/sources.list.d/xanmod-release.list），之后 apt upgrade 或再次执行本项即可更新内核']='The repo source is kept (/etc/apt/sources.list.d/xanmod-release.list); a later apt upgrade or re-running this item will update the kernel'
        ['软件源里没有适合 x86-64-v']='No suitable x86-64-v in the repo sources'
        ['载体:']='Carrier:'
        ['输入 DNS 服务器 IP（空格分隔，可混合 IPv4 / IPv6）:']='Enter DNS server IPs (space-separated; IPv4 / IPv6 can be mixed):'
        ['输入域名（不带 https:// 和端口）:']='Enter a domain (without https:// and without a port):'
        ['输入序号（回车取消）:']='Enter a number (Enter to cancel):'
        ['输入版本号（如 v26.3.27）:']='Enter a version number (e.g. v26.3.27):'
        ['输入要删除的序号（回车取消）:']='Enter the number to delete (Enter to cancel):'
        ['输入要删除的端口（写法同放行，如 80,443 或 400-500）:']='Enter the port to delete (same format as allowing, e.g. 80,443 or 400-500):'
        ['输入要删除的规则编号（逗号分隔，如 3,5）:']='Enter the rule numbers to delete (comma-separated, e.g. 3,5):'
        ['输入要加入白名单的 IP 或 CIDR 网段:']='Enter the IP or CIDR subnet to add to the allowlist:'
        ['输入要封禁的 IP 地址:']='Enter the IP address to ban:'
        ['输入要放行的端口：逗号分隔，支持范围与协议后缀']='Enter the ports to allow: comma-separated, ranges and protocol suffixes supported'
        ['输入要移除的 IP 或网段:']='Enter the IP or subnet to remove:'
        ['输入要解封的 IP 地址:']='Enter the IP address to unban:'
        ['迁移后 Portal 改用域名 + CA 证书（tls=2），Vector/Egress 不再需要 pin=；']='After migration the Portal uses a domain + CA certificate (tls=2), and Vector/Egress no longer need pin=;'
        ['迁移完成：已是 tls=2，服务运行中']='Migration complete: already tls=2, service running'
        ['运行 tcpfit（不带子命令 = 它的菜单），如 adam tune tcp status']='Run tcpfit (no subcommand = its menu), e.g. adam tune tcp status'
        ['运行并监听中']='Running and listening'
        ['还没有节点']='No nodes yet'
        ['还没有节点，服务不会启动']='No nodes yet; the service will not start'
        ['这会导致 curl/certbot 优先尝试 IPv6 而报错']='This makes curl/certbot try IPv6 first and fail'
        ['这是你当前登录所用的 IP，封禁后会立刻断开且无法重连，已拒绝']='This is the IP you are currently logged in from; banning it would disconnect you immediately with no way back; refused'
        ['这是跨协议代升级（NW']='This is a cross-protocol-generation upgrade (NW'
        ['进入后选「1 一键调优」即可；所有改动可用其菜单 7 或 tcpfit rollback 回滚。']='Once inside, pick "1 One-click tuning"; all changes can be rolled back via its menu 7 or tcpfit rollback.'
        ['远程 Egress 出口机连接信息']='Remote Egress exit-machine connection info'
        ['远端版本:']='Remote version:'
        ['连接串格式不合法（应为 egress://32位hex密钥']='Invalid connection string format (should be egress://32-hex-key'
        ['连接串解析通过：']='Connection string parsed OK:'
        ['连接信息']='Connection info'
        ['连通性探测 probe（真实 TCP Flow，不发送业务数据）']='Connectivity probe (real TCP Flow; sends no application data)'
        ['选择要切换到的版本序号:']='Enter the number of the version to switch to:'
        ['选择要安装的版本（支持回退到历史版本）']='Choose the version to install (supports rolling back to older versions)'
        ['通过管道/进程替换运行，无法直接复制自身，正在从脚本地址重新下载一份...']='Running via a pipe/process substitution, so it cannot copy itself directly; re-downloading a copy from the script URL...'
        ['通道的版本信息（GitHub 不可达 / 被限流，或该通道暂无发布）']='version info for this channel (GitHub unreachable / rate-limited, or no releases on this channel)'
        ['通配']='Wildcard'
        ['通配，全监听；也可填具体 IP）:']='Wildcard, listen on all; a specific IP can also be entered):'
        ['邮箱          :']='Email          :'
        ['邮箱不能为空，已中止']='Email cannot be empty; aborted'
        ['邮箱格式不正确']='Invalid email format'
        ['部分依赖安装失败，继续尝试']='Some dependencies failed to install; trying anyway'
        ['配置 :']='Config :'
        ['配置/对端不互通']='Config / peers cannot talk to each other'
        ['配置已保存至']='Config saved to '
        ['配置已更新并重启']='Config updated and restarted'
        ['配置文件 :']='Config file :'
        ['配置文件里读不到监听端口']='Cannot read the listen port from the config file'
        ['配置校验失败:']='Config validation failed:'
        ['配置校验未通过：']='Config validation failed:'
        ['配置校验通过']='Config validation passed'
        ['配置确认：']='Config summary:'
        ['重启 :']='Restart :'
        ['重启」']='Restart"'
        ['重启后仍异常，请查看: journalctl -u']='Still abnormal after restart; see: journalctl -u'
        ['重启后未检测到服务正常监听：']='Service not detected listening normally after restart:'
        ['重启失败: journalctl -u fail2ban -n 30']='Restart failed: journalctl -u fail2ban -n 30'
        ['重启失败，请按上方日志排查']='Restart failed; please troubleshoot using the log above'
        ['重启失败，请看 journalctl -u']='Restart failed; see journalctl -u'
        ['重新下载脚本失败，管理脚本副本无法安装']='Failed to re-download the script; the management script copy cannot be installed'
        ['重新生成 PSK（同时更换一套流量特征）']='Regenerate the PSK (also changes the traffic profile)'
        ['重新配置」按 v3 向导重装一次']='Reconfigure" to reinstall once via the v3 wizard'
        ['重新配置」按新版向导重建配置（新密钥 + 新 URL），再同步更新所有对端']='Reconfigure" to rebuild the config with the new wizard (new key + new URL), then sync all peers'
        ['重新配置」生成新密钥，并同步更新所有 Vector/Egress/Anywhere 对端']='Reconfigure" to generate a new key and sync all Vector/Egress/Anywhere peers'
        ['重装']='Reinstall'
        ['防护端口 :']='Protected port :'
        ['防火墙」安装）；请确认云厂商安全组已放行:']='Firewall" to install); please confirm your cloud security group allows:'
        ['防火墙已停用']='Firewall disabled'
        ['防火墙已启用']='Firewall enabled'
        ['防火墙已启用（开机自动生效）']='Firewall enabled (takes effect automatically on boot)'
        ['防火墙已处于启用状态，补齐 SSH 与本脚本服务端口的放行规则']='Firewall is already enabled; adding allow rules for SSH and this script'\''s service ports'
        ['防火墙已放行']='Firewall allowed it'
        ['防火墙已放行:']='Firewall allowed:'
        ['防火墙已是启用状态']='Firewall is already enabled'
        ['防火墙当前未启用']='Firewall is currently disabled'
        ['防火墙未启用时 ufw 不显示规则编号，请改用「按端口」删除']='When the firewall is disabled, ufw does not show rule numbers; please delete "By port" instead'
        ['防火墙未启用，以下是已保存、启用后才生效的规则：']='Firewall is disabled; the rules below are saved and take effect once enabled:'
        ['防火墙未放行附加端口']='Firewall has not allowed the additional ports'
        ['防火墙状态（详细）']='Firewall status (detailed)'
        ['防火墙管理（ufw）']='Firewall management (ufw)'
        ['防火墙（自动放行 SSH 与本脚本服务端口）']=' Firewall (auto-allows SSH and this script'\''s service ports)'
        ['阿里云  4']='Alibaba Cloud  4'
        ['阿里云 AccessKey ID:']='Alibaba Cloud AccessKey ID:'
        ['阿里云 AccessKey Secret（输入不回显）:']='Alibaba Cloud AccessKey Secret (input hidden):'
        ['限速设置（Portal/Vector/Egress 通用语义，0=不限速）：']='Rate-limit settings (same semantics for Portal/Vector/Egress, 0 = unlimited):'
        ['需要对外提供服务的端口，请用「3']='Ports that need to serve externally; please use "3'
        ['需要重启才会切换到新内核。重启后可用本菜单「8']='A reboot is needed to switch to the new kernel. After reboot, use this menu'\''s "8'
        ['默认 30']='default 30'
        ['默认队列   :']='Default queue   :'
        ['（-1 表示永久）']=' (-1 = forever)'
        ['（32 位小写十六进制，两端必须完全一致）']=' (32 lowercase hex chars; both ends must match exactly)'
        ['（Cloudflare 可用 Origin Rules），并开启 gRPC / HTTP/2 回源以获得更好的 XHTTP 表现']=' (Cloudflare can use Origin Rules), and enable gRPC / HTTP/2 origin-pull for better XHTTP performance'
        ['（Egress 是发起端，这个设置在本机生效；Portal 三种都收，两端无需一致）：']=' (Egress is the initiating side; this setting takes effect on this machine; the Portal accepts all three, both ends need not match):'
        ['（NOW_HANDSHAKE_TIMEOUT，v3.3.0 起未设置时从 Shared Key 派生 3s–30s）']=' (NOW_HANDSHAKE_TIMEOUT; since v3.3.0, when unset it is derived from the Shared Key, 3s–30s)'
        ['（NOW_HANDSHAKE_TIMEOUT；v3.3.0 起未设置时从 Shared Key 派生 3s–30s，显式设置可固定）']=' (NOW_HANDSHAKE_TIMEOUT; since v3.3.0, when unset it is derived from the Shared Key, 3s–30s; setting it explicitly pins it)'
        ['（NOW_MORPH_TCP_PRELUDE / NOW_MORPH_UDP_PRELUDE，只在发起端 Vector / Egress 上设置，Portal 不使用；接收端通吃、两端无需一致）']=' (NOW_MORPH_TCP_PRELUDE / NOW_MORPH_UDP_PRELUDE; only set on the initiating Vector / Egress side, the Portal does not use them; the receiver accepts all, both ends need not match)'
        ['（Vector / Egress / Anywhere）必须']='(Vector / Egress / Anywhere) must '
        ['（Vector/Egress 的 pin= 请同步改为新值）']=' (please sync the Vector/Egress pin= to the new value)'
        ['（tcpfit：按本机实测推导参数，可回滚）']=' (tcpfit: derives parameters from measurements on this machine; can be rolled back)'
        ['（zh=中文 / en=English）']=' (zh=Chinese / en=English)'
        ['（zh=中文 / en=English），下次打开菜单生效']=' (zh=Chinese / en=English); takes effect next time you open the menu'
        ['（zh=中文 / en=English，切换：adam lang zh']=' (zh=Chinese / en=English; switch with: adam lang zh'
        ['（不自动跨大版本）']=' (does not cross major versions automatically)'
        ['（保活 / 自动更新）']=' (keepalive / auto-update)'
        ['（写入生成的 Vector / Egress 启动命令，Portal 自身不使用）']=' (written into the generated Vector / Egress launch commands; the Portal itself does not use it)'
        ['（务必和服务端保持一致）']=' (must match the server)'
        ['（只留最近 5 份）']=' (keep only the latest 5)'
        ['（可在「自动更新」里切到 beta 通道）']=' (you can switch to the beta channel under "Auto-update")'
        ['（可用: install / list / status / on / off / allow <端口> / deny <端口> / sync）']=' (available: install / list / status / on / off / allow <port> / deny <port> / sync)'
        ['（可用: install / status / banned / log / bantime <时长> / ban <IP> / unban <IP> / unban-all / on / off / restart / uninstall）']=' (available: install / status / banned / log / bantime <duration> / ban <IP> / unban <IP> / unban-all / on / off / restart / uninstall)'
        ['（可用: install / update / config / reconfig / ports / add-port / del-port']=' (available: install / update / config / reconfig / ports / add-port / del-port'
        ['（可用: tcp']=' (available: tcp'
        ['（可用「版本回退」快速切回）']=' (use "Version rollback" to switch back quickly)'
        ['（可能签发了错误的域名）']=' (may have issued the wrong domain)'
        ['（可选，在电脑/路由器上跑本地 SOCKS5 入口用 in=）：']=' (optional; in= for running a local SOCKS5 entry on your computer/router):'
        ['（含 PSK）？']=' (incl. PSK)?'
        ['（含密钥配置与证书文件），如需彻底清除请手动: rm -rf']=' (incl. key configs and certificate files); to remove everything, run manually: rm -rf'
        ['（含密钥）？']=' (incl. keys)?'
        ['（在出口机上运行 egress:// 主动回连本 Portal）：']=' (run egress:// on the exit machine to connect back to this Portal):'
        ['（官方未公布校验值，仅供留档比对）']=' (no official checksum published; for your records only)'
        ['（客户端端口']=' (client port'
        ['（对之后的新封禁生效）']=' (applies to new bans after this)'
        ['（或等待 10-30 分钟后重试）']=' (or wait 10-30 minutes and retry)'
        ['（无）']='(none)'
        ['（旧版备份']=' (old backup '
        ['（旧版备份在']=' (old backup at '
        ['（时长']=' (duration '
        ['（暂无）']='(none yet)'
        ['（未检测到 nowhere.service，未启动服务）']=' (nowhere.service not detected; service not started)'
        ['（未检测到 snell.service，未启动服务）']=' (snell.service not detected; service not started)'
        ['（本次安装中途失败时可手动恢复）']=' (can be restored manually if this install fails halfway)'
        ['（没有启用的 jail）']='(no enabled jails)'
        ['（真实 TCP Flow 连通性测试）']=' (real TCP Flow connectivity test)'
        ['（示例：30 / 10m / 1h / 1d / -1）']=' (examples: 30 / 10m / 1h / 1d / -1)'
        ['（端口模式']=' (port mode'
        ['（还没有节点）']='(no nodes yet)'
        ['（还没有节点，用「2']='(no nodes yet; use "2'
        ['（这里修改的是主端口配置；附加端口请用「删除端口配置」+「新增端口配置」）']='(this changes the main port config; for additional ports use "Delete port config" + "Add port config")'
        ['（通用 DNS-01 / acme.sh 请用 Nowhere 菜单 3 重新配置）']='(for generic DNS-01 / acme.sh, please reconfigure via Nowhere menu 3)'
        ['（须与 Portal 一致）']=' (must match the Portal)'
        ['）   回源:']=')   Origin:'
        ['） 语言：']=') Language:'
        ['）加入白名单，避免输错密码把自己封掉？']=') to the allowlist, to avoid locking yourself out by mistyping the password?'
        ['）登录的：禁用 IPv6 会立刻断开，且之后只能用 IPv4 登录']=') you logged in with: disabling IPv6 will disconnect you immediately, and you can only log in via IPv4 afterwards'
        ['）的放行规则？']=') allow rules?'
        ['），与宿主机共用内核，无法更换内核']='), sharing the host kernel, so the kernel cannot be replaced'
        ['），可用 Nowhere 菜单「13']='), use Nowhere menu "13'
        ['），可用「检查并更新」升级']='), use "Check and update" to upgrade'
        ['），将以 root 运行并修改 sysctl / qdisc 等网络参数']='), it will run as root and modify sysctl / qdisc and other network settings'
        ['），已中止']='), aborted'
        ['），无需迁移证书']='), no certificate migration needed'
        ['），是否跳过下载直接使用？']='), skip the download and use it directly?'
        ['），本脚本只适配 NW3：URL 语法、密钥格式、对端兼容性都可能已变化']='), this script only supports NW3: URL syntax, key format and peer compatibility may all have changed'
        ['），管理命令将指向下载到的版本']='), management commands will point to the downloaded version'
        ['），还没有正式版']='), no stable release yet'
        ['），避免把自己锁在外面']='), so you don'\''t lock yourself out'
        ['）：新旧对端不互通，Vector/Egress/Anywhere 必须一起升级']='): old and new peers cannot talk to each other; Vector/Egress/Anywhere must be upgraded together'
        ['）：期望']='): expected '
        ['）；本脚本的向导按 NW3 生成配置，可能无法直接使用']='); this script'\''s wizard generates NW3 configs, which may not work directly'
        ['，不是 v']=', not v'
        ['，不降级']=', no downgrade'
        ['，与当前运行的']=', vs. the currently running '
        ['，但本机公网 IP 疑似']=', but this machine'\''s public IP appears to be '
        ['，低于 v3.0.0，与 NW3 配置不兼容，已中止']=', below v3.0.0, incompatible with NW3 configs, aborted'
        ['，低于 v3.0.0，与本脚本的 NW3 配置不兼容，已中止（请检查仓库状态）']=', below v3.0.0, incompatible with this script'\''s NW3 configs, aborted (please check the repo status)'
        ['，剩余有效期约']=', about '
        ['，可带 user:pass']=', may include user:pass'
        ['，安装包可能被篡改或下载损坏']=', the package may be tampered with or corrupted during download'
        ['，实算']=', computed '
        ['，将下载最新版']=', the latest version will be downloaded'
        ['，将按所选通道重装 / 切换版本（节点配置保留）']=', will reinstall / switch versions via the selected channel (node configs kept)'
        ['，已进入新的协议代（NW']=', entered a new protocol generation (NW'
        ['，无法启用定时任务']=', cannot enable scheduled tasks'
        ['，更新？']=', update?'
        ['，本地实算=']=', locally computed = '
        ['，本脚本按 v']=', this script manages v'
        ['，正在从']=', downloading from '
        ['，请用 Nowhere 菜单 2 重新安装']=', please reinstall via Nowhere menu 2'
        ['，重启后仍然生效）？']=', still effective after reboot)?'
        ['，重装后节点可直接恢复']=', nodes can be restored directly after reinstall'
        ['，重装时可直接沿用端口和 PSK（附加端口也会一并恢复）']=', ports and PSK can be reused directly on reinstall (additional ports restored too)'
        ['，需要客户端同步升级，不会自动跨大版本']=', clients must upgrade in sync; no automatic cross-major-version upgrade'
        ['：两者不一致时 HTTP-01 会失败']=': HTTP-01 will fail if they differ'
        ['：官方标记为预发布，或当前取不到标记信息）']=': officially marked pre-release, or the tag could not be fetched)'
        ['：客户端需使用支持该版本的 Surge 测试渠道，协议在正式版前仍可能变动，两端要同步']=': clients need a Surge beta channel supporting this version; the protocol may still change before stable, both ends must stay in sync'
        ['：跨大版本需要客户端同步升级、配置格式也可能变化，本脚本不自动处理']=': cross-major upgrades require clients to upgrade in sync and config formats may change; this script does not handle that automatically'
        ['；beta=跟随最新测试版 b/rc 及正式版，stable=只跟正式版）']='; beta = follow latest beta b/rc and stable releases, stable = stable releases only)'
        ['；下载后校验完整性，版本不低于本地才替换）']='; integrity is verified after download, and it only replaces the local copy if the version is not lower)'
        ['；不加 --force，避免重复签发触发 LE 频率限制）...']='; no --force, to avoid repeated issuance hitting LE rate limits)...'
        ['；官方建议客户端屏蔽 QUIC 让应用回落到 HTTP/2']='; the official advice is for clients to block QUIC so apps fall back to HTTP/2'
        ['？（之后的自动更新也会跟随测试通道）']='? (later auto-updates will also follow the beta channel)'
        ['？（服务会重启，约 2 秒中断；启动失败自动回滚）']='? (the service will restart, ~2s interruption; auto-rollback on startup failure)'
        ['未知版本']='unknown version'
        ['未知版本（本地备份二进制）']='unknown version (local backup binary)'
        ['未探测到，请手动输入']='not detected, please enter manually'
        ['未设置']='not set'
        ['无']='none'
        ['旧版本']='old version'
        ['版本未知']='unknown version'
        ['新版本']='new version'
        ['（自签模式不需要）']='(not needed in self-signed mode)'
        ['选择']='Choose'
        ['返回']='Back'
        ['1/2/3，默认1']='1/2/3, default 1'
        ['1/2，默认1']='1/2, default 1'
        ['地址不能为空，且只能包含字母、数字和 . : - _']='Address cannot be empty; only letters, digits and . : - _ are allowed'
        ['Morph 乱形    :']='Morph shaping    :'
        ['PSK（回车自动生成 32 位随机串；自定义需 12-255 位，仅限字母、数字、- 和 _）:']='PSK (Enter = auto-generate a 32-char random string; custom must be 12-255 chars, letters, digits, - and _ only):'
        ['发现新版本:']='New version found:'
        ['/ 重装 Snell（自动获取官方最新版，默认跟随测试版）']='/ Reinstall Snell (auto-fetch the official latest; follows the beta channel by default)'
        ['/ 重装 Xray 内核（选择通道：最新预发布 / 正式版 / 指定版本）']='/ Reinstall the Xray core (choose a channel: latest pre-release / stable / specific version)'
        ['unshaped   - 仅 AES 加密、不做混淆，吞吐约高 10%（官方说明：相当于 Snell v3）']='unshaped   - AES encryption only, no obfuscation; throughput ~10% higher (official note: equivalent to Snell v3)'
        ['用 jail.d/']='use jail.d/'
        ['默认']='default'
        ['第 0 步：选择语言']='Step 0: Choose a language'
        ['.bak）']='.bak)'
        ['.tgz）:']='.tgz):'
        ['/ NW3）']='/ NW3)'
        ['/ status）']='/ status)'
        ['/ uninstall）']='/ uninstall)'
        ['/acme.sh）']='/acme.sh)'
        ['/tcp）']='/tcp)'
        ['Fail2ban（']='Fail2ban('
        ['Nowhere（Portal / Egress：']='Nowhere(Portal / Egress: '
        ['Shadowsocks 2022（TCP + UDP）']='Shadowsocks 2022(TCP + UDP)'
        ['Xray（SS2022 / VLESS：REALITY Vision、XHTTP REALITY、XHTTP CDN、VLESS Encryption）']='Xray(SS2022 / VLESS: REALITY Vision, XHTTP REALITY, XHTTP CDN, VLESS Encryption)'
        ['en）']='en)'
        ['mode：1']='mode: 1'
        ['stable）']='stable)'
        ['v3.3.0）']='v3.3.0)'
        ['」）']='")'
        ['（']=' ('
        ['（TCP']=' (TCP'
        ['（linux-']=' (linux-'
        ['）']=')'
        ['）  mode']=')  mode'
        ['）:']='):'
        ['）：']='): '
        ['）？']=')?'
        ['，dial4=']=', dial4='
        ['，dial=']=', dial='
        ['，morph=']=', morph='
        ['？']='?'
        ['时间']='Time'
        ['大陆流量拦截（geoip:cn / geosite:cn → 拦截）开 / 关']='Block mainland traffic (geoip:cn / geosite:cn) on / off'
        ['大陆流量拦截（geoip:cn / geosite:cn → 拦截）：']='Mainland traffic block (geoip:cn / geosite:cn): '
        ['大陆拦截:']='Mainland block:'
        ['快捷命令已就绪：输入 adam 打开菜单']='Shortcuts ready: type adam to open the menu'
        ['快捷命令未能安装（服务本身不受影响）']='Shortcuts could not be installed (services are unaffected)'
        ['修复：重新运行安装脚本文件，或执行：']='Fix: re-run the installer file, or run:'
        ['快捷命令 adam：正常（指向']='Shortcut adam: OK (points to'
        ['快捷命令 adam 不可用：请执行']='Shortcut adam is unavailable: please run'
        ['或重新运行安装脚本']='or re-run the installer'
        ['该地址不是公网 IP（内网/保留地址），客户端连不上：']='That address is not a public IP (private/reserved); clients cannot connect: '
        ['该域名解析不到任何 IP，请检查域名/DNS：']='That domain resolves to no IP; check the domain/DNS: '
        ['该域名解析到的 IP 与本机公网 IP 不一致（可能是 CDN/多线，也可能是填错）：']='That domain resolves to IPs different from this machine'\''s public IP (may be CDN/multi-line, or a typo): '
        ['本机公网 IP：']='This machine'\''s public IP: '
        ['仍要使用这个地址？']='Use this address anyway?'
        ['未能确定公网地址，分享链接暂不可用，请用 Xray 菜单 13 设置公网地址']='Could not determine the public address; share links are unavailable for now. Set it in Xray menu 13.'
        ['geo 数据缺失，大陆拦截未开启']='Geo data missing; mainland block not enabled'
        ['geo 数据缺失：本次安装先不开启大陆拦截，稍后用 Xray 菜单 15 再开']='Geo data missing: mainland block will not be enabled for this install; enable it later from Xray menu 15'
        ['下载 geo 数据失败：']='Failed to download geo data: '
        ['，大陆拦截暂不可用']='; mainland block unavailable'
        ['用法：xray cnblock on|off']='Usage: xray cnblock on|off'
        ['配置重载失败，拦截状态未生效，请查看日志']='Config reload failed; the block state did not take effect. Check the logs.'
        ['公网地址为空']='Public address is empty'
        ['未修改']='Not changed'
        ['快捷命令安装失败：请检查 /usr/local/bin 是否可写，并确认管理脚本副本存在：']='Shortcut install failed: check that /usr/local/bin is writable and the manager copy exists: '
        ['VLESS + XHTTP + TLS（直连域名证书，证书自动申请，IP 照常用）']='VLESS + XHTTP + TLS (direct domain cert, auto-issued; IP still works)'
        ['直连域名证书节点：客户端连域名或本机 IP 均可（SNI 始终为域名，证书只验证域名）']='Direct domain-cert node: clients may connect by domain or by this machine'\''s IP (SNI is always the domain; the cert only validates the domain)'
        ['域名（须已解析到本机，证书将签发给它）:']='Domain (must already resolve to this machine; the cert is issued for it): '
        ['ACME 邮箱（证书账户用）:']='ACME email (for the certificate account): '
        ['邮箱不能为空']='Email cannot be empty'
        ['证书申请方式：']='Certificate method: '
        ['HTTP-01（域名解析到本机 + 开放 80 端口，自动续期）']='HTTP-01 (domain resolves to this machine + port 80 open, auto-renewal)'
        ['Cloudflare DNS-01（需要 CF API Key/Token，自动续期，80 端口可不开）']='Cloudflare DNS-01 (needs a CF API key/token, auto-renewal, port 80 can stay closed)'
        ['已有证书文件（fullchain.pem + privkey.pem）']='Existing certificate files (fullchain.pem + privkey.pem)'
        ['检测到该域名已有有效证书，直接复用']='Found a valid certificate for this domain; reusing it'
        ['证书申请中（HTTP-01，需 80 端口）...']='Requesting the certificate (HTTP-01, needs port 80)...'
        ['证书申请中（Cloudflare DNS-01，约需 30-60 秒）...']='Requesting the certificate (Cloudflare DNS-01, about 30-60s)...'
        ['域名解析未通过，HTTP-01 很可能失败，仍要继续申请？']='DNS check failed; HTTP-01 will probably fail. Continue anyway?'
        ['Cloudflare 凭证文件已存在，直接复用']='Cloudflare credentials file already exists; reusing it'
        ['同一节点两种连法：域名或本机 IP（SNI 始终为域名），用 Xray 菜单 13 切换分享链接地址']='Same node, two addresses: domain or this machine'\''s IP (SNI is always the domain); switch the share-link address in Xray menu 13'
        ['备用链接（另一地址，SNI 仍为域名）:']='Alternate link (other address, SNI is still the domain): '
        ['certbot Cloudflare 插件安装失败']='Failed to install the certbot Cloudflare plugin'
        ['域名:']='Domain: '
        ['已同步 REALITY serverNames（域名地址可用）']='REALITY serverNames synced (domain address now works)'
        ['未找到 python3，无法同步 REALITY 域名']='python3 not found; cannot sync REALITY domain'
        ['同步 REALITY 域名失败：']='Failed to sync REALITY domain: '
        ['未能确定公网地址，无法生成 Anywhere 分享链接']='Could not determine the public address; cannot generate the Anywhere share link'
        ['未能确定公网地址，无法生成 Vector 探针链接']='Could not determine the public address; cannot generate the Vector probe link'
        ['检测到 firewalld 或 cnblock 防火墙链已在运行，跳过 ufw 安装（避免两套防火墙混用）；端口放行请用现有防火墙管理']='firewalld or a cnblock firewall chain is already active; skipping ufw install to avoid mixing two firewalls. Manage port rules with the existing firewall'
        ['删除后 Snell / Xray / 防火墙 / Fail2ban 的管理入口需改用']='After deletion, use the Snell / Xray / firewall / Fail2ban management entries via '
        ['Cloudflare 凭证仍被 Xray 域名证书节点使用（xhttp-tls，续期也依赖它），未删除；如 Xray 已卸载或不再用该凭证，请手动删除']='The Cloudflare credential is still used by an Xray domain-certificate node (xhttp-tls, renewal depends on it too) and was not deleted. If Xray no longer uses it, delete it manually'
        ['Global API Key（需邮箱）']='Global API Key (needs the account email)'
        ['API Token（建议，只需 Token，需 Zone:DNS:Edit 权限）']='API Token (recommended; only the token is needed, needs Zone:DNS:Edit permission)'
        ['Cloudflare 邮箱不能为空']='Cloudflare email must not be empty'
        ['Cloudflare 凭证不能为空']='Cloudflare credential must not be empty'
        ['Cloudflare 凭证未提供，已中止']='Cloudflare credential not provided; aborted'
        ['连接串里的 SNI 格式不合法，已忽略']='The SNI in the pasted URL is malformed and was ignored'
        ['连接串里的 pin 不是 64 位小写十六进制，已忽略']='The pin in the pasted URL is not 64 lowercase hex chars and was ignored'
        ['连接串里的 dial 不是合法 IP，已重置为 auto']='The dial in the pasted URL is not a valid IP; reset to auto'
        ['连接串里的 dial4 不是合法 IPv4，已重置为 auto']='The dial4 in the pasted URL is not a valid IPv4 address; reset to auto'
        ['连接串里的 dial6 不是合法 IPv6，已重置为 auto']='The dial6 in the pasted URL is not a valid IPv6 address; reset to auto'
        ['连接串里的上行限速不合法，已重置为 0']='The upload rate in the pasted URL is invalid; reset to 0'
        ['连接串里的下行限速不合法，已重置为 0']='The download rate in the pasted URL is invalid; reset to 0'
        ['证书副本同步失败，服务可能无法读取新证书']='Failed to sync the certificate copy; the service may not be able to read the new certificate'
        ['创建专用低权用户失败，继续以 root 运行']='Failed to create the dedicated low-privilege user; continuing to run as root'
        ['证书副本同步失败，回退 root 运行']='Failed to sync the certificate copy; falling back to running as root'
        ['低权用户启动失败，回退为 root 运行']='Failed to start as the low-privilege user; falling back to running as root'
        ['创建临时工作目录失败']='Failed to create a temporary working directory'
        ['HTTP-01 与 80 端口监听冲突：续期时 certbot 需独占 80 端口，服务将无法同时监听 80']='HTTP-01 conflicts with listening on port 80: certbot needs exclusive use of port 80 at renewal time'
        ['80 端口已被其他进程占用，HTTP-01 签发前请先停掉该服务或改用 DNS-01']='Port 80 is already in use by another process; stop that service or use DNS-01 before HTTP-01 issuance'
        ['证书副本已同步']='Certificate copy synced'
        ['新二进制试运行失败']='New binary failed its trial run'
        ['DNSPod 凭证不能为空']='DNSPod credentials must not be empty'
        ['阿里云凭证不能为空']='Alibaba Cloud credentials must not be empty'
        ['80 端口仍被占用，证书签发已中止']='Port 80 is still in use; certificate issuance aborted'
        ['注意：定时器单元文件不在备份中，异机恢复后需重装定时器（自动维护菜单 8）']='Note: timer unit files are not in the backup; after restoring on another machine, reinstall the timers (Auto-maintenance menu 8)'
        ['Xray 仍在使用 acme.sh 续期，已保留 acme.sh 的 cron 任务']='Xray still uses acme.sh for renewal; the acme.sh cron task has been kept'
        ['已移除 acme.sh 的 cron 续期任务']='Removed the acme.sh cron renewal task'
        ['acme.sh 目录仍保留，如确认不再需要请手动删除：rm -rf ~/.acme.sh']='The acme.sh directory is kept; if you are sure it is no longer needed, delete it manually: rm -rf ~/.acme.sh'
        ['备份内的角色与本机角色不一致，已中止恢复']='The role in the backup does not match this machine; restore aborted'
        ['已停用多余的 Snell 附加端口实例：']='Stopped the extra Snell port instance that no longer has a config: '
        ['分端口模式下 TCP 与 UDP 端口不能相同，已将 UDP 端口改为']='TCP and UDP ports must differ in split mode; the UDP port has been changed to'
        ['本机现有二进制版本过低或无法识别（需要 Nowhere v3 及以上），将下载最新版']='The existing binary is too old or unrecognized (Nowhere v3 or later is required); downloading the latest version'
        ['另一个维护或安装任务正在运行']='Another maintenance or install task is running'
        ['仍要继续吗？']='Continue anyway?'
        ['配置备份失败，仍要继续吗？']='Config backup failed; continue anyway?'
        ['配置保存失败，已中止']='Failed to save the config; aborted'
        ['安装完成，但快捷命令校验未通过（服务本身不受影响），请稍后执行 adam shortcuts 重新安装']='Install finished, but the shortcut check failed (the service itself is unaffected); run adam shortcuts later to reinstall the shortcuts'
        ['已恢复旧配置']='Old config restored'
        ['检测到跨大版本升级，确认继续吗？']='This is a cross-major upgrade; continue?'
        ['迁移重启失败，已恢复旧配置并再次重启，请按日志排查']='Migration restart failed; the old config has been restored and the service restarted again; please check the log'
        ['迁移失败：已恢复旧配置，但服务仍未启动，请按上方日志排查']='Migration failed: the old config was restored, but the service still did not start; please check the log above'
        ['旧配置备份失败，迁移继续（失败时无法自动恢复）']='Failed to back up the old config; migration continues (automatic restore will not be possible on failure)'
        ['已恢复旧配置，服务已恢复运行（仍为 tls=1）']='Old config restored and the service is running again (still tls=1)'
        ['官方暂无可用版本，当前']='No usable release is available from upstream; current'
        ['未能获取官方版本信息，本次跳过；当前']='Could not fetch upstream release info; skipping this time; current'
        ['最新版本属于另一个大版本（v']='The latest release belongs to another major version (v'
        ['），不自动跨大版本，当前']='); not auto-upgrading across major versions; current'
        ['限速不合法，已清空（不限速）']='Invalid rate limit; cleared (no limit)'
        ['出站源 IP 不合法，已重置为 auto']='Invalid outbound source IP; reset to auto'
        ['，']=','
        ['1/2，默认2']='1/2, default 2'
        ['握手超时']='Handshake timeout'
        ['备份当前二进制失败，回退中止']='Failed to back up the current binary; rollback aborted'
        ['回退替换失败，当前二进制未动']='Rollback replacement failed; the current binary was not touched'
        ['备份交换失败，已尽力恢复原二进制']='Backup swap failed; tried to restore the original binary'
        ['未知证书方式']='Unknown certificate method'
        ['certbot.timer 启用失败，自动续期可能不工作']='Failed to enable certbot.timer; auto-renewal may not work'
        ['下载失败或远端内容不完整，请检查网络或脚本地址（现有脚本未改动）']='Download failed or the remote content is incomplete; please check the network or script URL (the existing script was not changed)'
        ['保活巡检未开启']='Watchdog is off'
        ['ss 工具缺失，无法列出监听端口（请安装 iproute2）']='The ss tool is missing; cannot list listening ports (please install iproute2)'
        ['移除定时器后，Xray 证书同步与自动续期将停止（证书到期前需手动续期或重装定时器）']='Removing the timers will stop Xray certificate sync and auto-renewal (renew manually or reinstall the timers before certificates expire)'
        ['（当前已是 tls=2）']='(already tls=2)'
        ['Fail2ban 重启后校验失败，请查看: fail2ban-client status']='Fail2ban check failed after restart; see: fail2ban-client status'
        ['警告：SHA256 校验已被跳过，安装包未经校验']='WARNING: SHA256 verification was skipped; the package was not verified'
        ['（可能被 GitHub 限流，请稍后重试）']='(possibly rate-limited by GitHub; please retry later)'
        ['备份二进制无法运行，回退已中止']='The backup binary cannot run; rollback aborted'
        ['节点 tag 不合法，已跳过证书目录清理']='Invalid node tag; skipped certificate directory cleanup'
        ['节点 tag 不合法，已中止删除']='Invalid node tag; deletion aborted'
        ['  入站网卡 listen_interface（如 eth0，回车默认自动）: ']='  Inbound NIC listen_interface (e.g. eth0, Enter for auto): '
        ['  出站源 IP through（回车默认自动）: ']='  Outbound source IP through (Enter for auto): '
        ['  出站网卡 interface（如 eth1，回车默认自动）: ']='  Outbound NIC interface (e.g. eth1, Enter for auto): '
        ['  各目标权重（逗号分隔，含主目标，如 2,1；回车全部等权 1）: ']='  Weight per target (comma-separated, including the main target, e.g. 2,1; Enter for all weight 1): '
        ['  向目标发送 Proxy Protocol v2（send_proxy）？']='  Send Proxy Protocol v2 to the target (send_proxy)?'
        ['  启用入站 MPTCP（accept_mptcp）？']='  Enable inbound MPTCP (accept_mptcp)?'
        ['  启用出站 MPTCP（send_mptcp）？']='  Enable outbound MPTCP (send_mptcp)?'
        ['  当前机器角色：1) 中转入口机（向外加密 remote_transport）  2) 落地出口机（入站解密 listen_transport）']='  This machine role: 1) Relay entry (encrypt outbound, remote_transport)  2) Exit node (decrypt inbound, listen_transport)'
        ['  接收来源 Proxy Protocol（accept_proxy）？']='  Accept Proxy Protocol from the source (accept_proxy)?'
        ['  负载策略：1) roundrobin（加权轮询）  2) iphash（源 IP 哈希）']='  Balance strategy: 1) roundrobin (weighted round-robin)  2) iphash (source IP hash)'
        ['  选择 [1/2，默认 1]: ']='  Choose [1/2, default 1]: '
        ['  额外目标列表（逗号分隔，格式 host:port,host2:port）: ']='  Extra targets (comma-separated, host:port,host2:port): '
        [' 失败']=' failed'
        [' 安装完成（']=' installed ('
        [' 已生效：']=' is now active: '
        [' 已被其他进程占用：']=' is already in use by another process: '
        ['Host 不合法，回退标准透传']='Invalid host, falling back to plain forwarding'
        ['Realm ']='Realm '
        ['Realm 下载或校验失败']='Realm download or verification failed'
        ['Realm 已卸载']='Realm uninstalled'
        ['Realm 已重启']='Realm restarted'
        ['Realm 暂不支持该架构：']='Realm does not support this architecture: '
        ['Realm 更新失败']='Realm update failed'
        ['Realm 未安装，规则配置已保存，安装后生效']='Realm is not installed; the rule config is saved and will take effect after installation'
        ['Realm 端口转发管理']='Realm port forwarding'
        ['Realm 转发规则列表']='Realm forwarding rules'
        ['TCP + UDP 双栈（默认）']='TCP + UDP (default)'
        ['TLS SNI / 域名（如 example.com）: ']='TLS SNI / domain (e.g. example.com): '
        ['WS Path（回车默认 /ws）: ']='WS path (Enter for /ws): '
        ['Xray 未安装，转发配置已保存，重装 Xray 后生效']='Xray is not installed; the forwarding config is saved and will take effect after reinstalling Xray'
        ['Xray 端口转发（dokodemo-door）']='Xray port forwarding (dokodemo-door)'
        ['Xray 转发已重启']='Xray forwarding restarted'
        ['Xray 转发规则列表']='Xray forwarding rules'
        [']？']=']?'
        ['adam-realm 以专用用户启动失败，改以 root 重试']='adam-realm failed to start as the dedicated user, retrying as root'
        ['adam-realm 启动失败，请查看日志：journalctl -u adam-realm -n 20 --no-pager']='adam-realm failed to start, see the logs: journalctl -u adam-realm -n 20 --no-pager'
        ['下载 Realm ']='Download Realm '
        ['下载的 realm 无法在本机运行，尝试另一构建']='The downloaded realm binary cannot run on this machine, trying the other build'
        ['仍要继续添加？']='Add it anyway?'
        ['传输隧道：']=' transport tunnel:'
        ['伪装 Host（如 cdn.example.com）: ']='Disguise host (e.g. cdn.example.com): '
        ['伪装域名 Host/SNI（如 cdn.example.com）: ']='Disguise domain host/SNI (e.g. cdn.example.com): '
        ['入站解密']='Inbound decrypt'
        ['入站隧道']='inbound tunnel'
        ['出站加密']='Outbound encrypt'
        ['出站隧道']='outbound tunnel'
        ['出网卡:']='out iface:'
        ['创建 adam-realm 用户失败，改以 root 运行服务']='Failed to create the adam-realm user, running the service as root'
        ['创建临时文件失败']='Failed to create a temporary file'
        ['删除转发规则']='Delete a forwarding rule'
        ['卸载 Realm']='Uninstall Realm'
        ['压缩包损坏或格式无效']='The archive is damaged or not a valid format'
        ['同时删除规则配置目录']='Also delete the rule config directory'
        ['同时删除防火墙中 Realm 端口的放行规则（']='Also delete the firewall allow rules for the Realm ports ('
        ['启用 / 停用单条规则']='Enable / disable a single rule'
        ['域名不合法，回退标准透传']='Invalid domain, falling back to plain forwarding'
        ['备份为空或格式无效']='The backup is empty or invalid'
        ['备份包含 adam-realm 之外的成员，拒绝导入']='The backup contains entries outside adam-realm; import refused'
        ['备注含非法字符（\" 或 \），请去掉后重试']='The remark contains illegal characters (" or \); remove them and retry'
        ['安装 / 更新 Realm']='Install / update Realm'
        ['导入将覆盖 /etc/adam-realm 现有规则并重启服务，确认？']='Import will overwrite the existing rules in /etc/adam-realm and restart the service. Continue?'
        ['导入规则（从备份恢复）']='Import rules (restore from backup)'
        ['导出规则（迁移备份）']='Export rules (migration backup)'
        ['尚未安装 Realm，请先安装']='Realm is not installed yet, please install it first'
        ['已保留规则目录']='Rule directory kept'
        ['已删除规则 ']='Deleted rule '
        ['已剔除无效目标：']='Removed invalid target: '
        ['已是最新版本，仍要重新安装？']='Already the latest version. Reinstall anyway?'
        ['当前没有已启用的转发规则，adam-realm 已停止']='No enabled forwarding rules; adam-realm has stopped'
        ['恢复后重载仍失败，请检查 Xray 配置与日志']='Reload still failed after restore; check the Xray config and logs'
        ['找不到文件: ']='File not found: '
        ['新版本启动失败，自动回滚到旧二进制...']='The new version failed to start, rolling back to the old binary...'
        ['新规则未能生效，已自动撤回（原有规则不受影响）']='The new rule did not take effect and was rolled back automatically (existing rules are unaffected)'
        ['新转发规则未能生效，已自动撤回']='The new forwarding rule did not take effect and was rolled back automatically'
        ['无法获取 Realm 最新版本号，请检查网络']='Cannot get the latest Realm version; check the network'
        ['暂无可测试的规则']='No rules to test'
        ['暂无规则']='No rules yet'
        ['暂无转发规则']='No forwarding rules yet'
        ['未取到官方 SHA256 摘要，跳过校验（']='Official SHA256 digest unavailable, skipping verification ('
        ['未找到 Realm 配置目录']='Realm config directory not found'
        ['未知的 realm 子命令:']='Unknown realm subcommand:'
        ['未知的 xray fwd 子命令:']='Unknown xray fwd subcommand:'
        ['本机监听 IP（回车默认 ']='Listen IP on this machine (Enter for default '
        ['本机监听端口 (1-65535): ']='Listen port on this machine (1-65535): '
        ['权重数量与目标数不符或含非数字，已按等权生成']='Weight count does not match the target count or contains non-numbers; equal weights generated'
        ['条规则']='rules'
        ['查看转发规则列表']='List forwarding rules'
        ['标准透传（推荐，性能最高，适用于已加密协议）']='Plain forwarding (recommended, fastest, for already-encrypted protocols)'
        ['正在查询 Realm 官方最新版本...']='Querying the latest official Realm version...'
        ['测试目标连通性与延迟']='Test target connectivity and latency'
        ['添加 Realm 转发规则']='Add a Realm forwarding rule'
        ['添加 Xray 端口转发']='Add Xray port forwarding'
        ['添加转发规则']='Add a forwarding rule'
        ['添加转发规则（TCP/UDP/LB/隧道/多网卡）']='Add a forwarding rule (TCP/UDP/LB/tunnel/multi-NIC)'
        ['源IP:']='src IP:'
        ['监听 IP 格式不合法']='Invalid listen IP format'
        ['目标地址格式不合法']='Invalid target address format'
        ['目标地址（域名、公网 IP 或同区免费内网 IP）: ']='Target address (domain, public IP, or same-region free private IP): '
        ['目标地址（域名或 IP）: ']='Target address (domain or IP): '
        ['目标端口 (1-65535): ']='Target port (1-65535): '
        ['目标证书由 CA 签发（可校验）？']='Is the target certificate CA-issued (verifiable)?'
        ['确认删除规则 [']='Confirm deleting rule ['
        ['确认卸载 Realm（含服务与二进制）？']='Confirm uninstalling Realm (including the service and binary)?'
        ['私钥文件路径: ']='Private key file path: '
        ['端口 ']='Port '
        ['纯 TCP']='TCP only'
        ['纯 UDP']='UDP only'
        ['纯 UDP（自动跳过 WS/TLS 隧道选项）']='UDP only (WS/TLS tunnel options are skipped automatically)'
        ['纯TCP']='TCP only'
        ['纯UDP']='UDP only'
        ['缺少必需工具：']='Missing required tool: '
        ['网卡名格式不合法，已忽略']='Invalid NIC name, ignored'
        ['规则 ']='Rule '
        ['规则备注（可选）: ']='Rule remark (optional): '
        ['规则备注（可选，如 香港VPC落地）: ']='Rule remark (optional, e.g. HK VPC exit): '
        ['规则导入完成']='Rules imported'
        ['规则已导出至: ']='Rules exported to: '
        ['规则渲染失败，已跳过：']='Failed to render rule, skipped: '
        ['规则状态已切换为：']='Rule status changed to: '
        ['证书或私钥文件不存在，回退内置自签']='Certificate or key file not found, falling back to the built-in self-signed certificate'
        ['证书文件路径（回车使用 Realm 内置自签）: ']='Certificate file path (Enter to use the Realm built-in self-signed certificate): '
        ['跟随系统重定向（followRedirect，仅配合 iptables 转发规则使用）？']='Follow system redirect (followRedirect, only with iptables redirect rules)?'
        ['路径含非法字符（\" 或 \），回退内置自签']='The path contains illegal characters (" or \); falling back to the built-in self-signed certificate'
        ['路径含非法字符（\" 或 \），回退标准透传']='The path contains illegal characters (" or \); falling back to plain forwarding'
        ['跳过（纯 UDP 无法做 TCP 握手探测）']='Skipped (pure UDP cannot be probed with a TCP handshake)'
        ['转发协议：']='Forwarding protocol:'
        ['转发目标连通性测试（TCP 握手延迟）']='Forwarding target connectivity test (TCP handshake latency)'
        ['转发规则 ']='Forwarding rule '
        ['转发配置重载失败，恢复上一版本']='Forwarding config reload failed, restoring the previous version'
        ['输入导出的 .tgz 备份文件路径: ']='Enter the exported .tgz backup file path: '
        ['输入规则序号（回车取消）: ']='Enter the rule number (Enter to cancel): '
        ['返回 Xray 菜单']='Back to the Xray menu'
        ['选择 [1-3，默认 1]: ']='Choose [1-3, default 1]: '
        ['选择 [1-4，默认 1]: ']='Choose [1-4, default 1]: '
        ['配置 WS / TLS / WSS 双端加密隧道？']='Configure a WS / TLS / WSS two-ended encrypted tunnel?'
        ['配置多目标负载均衡（extra_remotes）？']='Configure multi-target load balancing (extra_remotes)?'
        ['配置高级选项（指定出口 IP/网卡、Proxy Protocol、MPTCP）？']='Configure advanced options (outbound source IP/NIC, Proxy Protocol, MPTCP)?'
        ['重启服务 / 查看状态与日志']='Restart the service / view status and logs'
        ['非合法 IP，已忽略']='Not a valid IP, ignored'
        ['额外目标全部无效，已跳过负载均衡']='All extra targets are invalid, load balancing skipped'
        ['首次安装启动失败，已删除新二进制']='First install failed to start; the new binary has been removed'
        ['（可用: add / list / toggle / delete / test / restart / status）']='(available: add / list / toggle / delete / test / restart / status)'
        ['（可用: install / add / list / toggle / delete / test / restart / status / logs / export / import / uninstall）']='(available: install / add / list / toggle / delete / test / restart / status / logs / export / import / uninstall)'
        ['）: ']='): '
        ['），尝试另一构建']='), trying the other build'
        ['，请先安装']=', please install it first'
        ['端口转发']='Port forwarding'
        ['端口转发（dokodemo-door）']='Port forwarding (dokodemo-door)'
        ['端口转发（TCP / UDP 转发、负载均衡、WS / TLS 隧道）']='Port forwarding (TCP/UDP forwarding, load balancing, WS/TLS tunnels)'
        ['realm                      打开 Realm 端口转发菜单']='realm                      Open the Realm port forwarding menu'
        ['当前没有节点与转发规则，Xray 服务已停止']='No nodes or forwarding rules; the Xray service has stopped'
        ['当前没有由本脚本管理的服务端口需要放行（Nowhere / Snell / Xray / Realm 均未安装）']='No service ports managed by this script need allowing (Nowhere / Snell / Xray / Realm are not installed)'
        ['条转发规则']='forwarding rules'
        ['个节点']='nodes'
        ['（无 Nowhere/Snell/Xray/Realm 的 TCP 监听）']='(no Nowhere/Snell/Xray/Realm TCP listeners)'
        ['（无 Nowhere/Snell/Xray/Realm 的 UDP 监听）']='(no Nowhere/Snell/Xray/Realm UDP listeners)'
        ['恢复会覆盖 /etc/nowhere、/etc/snell、/etc/adam-xray、/etc/adam-realm 等现有配置，并重启已启用的服务']='Restore will overwrite the existing configs in /etc/nowhere, /etc/snell, /etc/adam-xray and /etc/adam-realm, and restart the enabled services'
        ['（可用: install / add / list / links / delete / update / health / repair / status / logs / restart / cnblock / fwd / uninstall）']='(available: install / add / list / links / delete / update / health / repair / status / logs / restart / cnblock / fwd / uninstall)'
        ['是否同时卸载 Realm 端口转发？']='Also uninstall Realm port forwarding?'
        ['规则文件内容非法，已跳过：']='Invalid rule file content, skipped: '
        ['导入的规则文件内容非法，已恢复原配置']='The imported rule file content is invalid; the previous config has been restored'
        ['解包失败，已恢复原配置']='Extraction failed; the previous config has been restored'
        ['规则已导入，但服务重载失败，请检查日志']='Rules imported, but the service failed to reload; check the logs'
        ['服务重载失败，删除未生效，请检查日志']='Service reload failed; the deletion did not take effect, check the logs'
        ['转发配置已移除，但 Xray 重载失败，请检查日志']='Forwarding config removed, but Xray reload failed; check the logs'
        ['已记录 root 运行标记，下次安装不再写入专用用户：']='Recorded the run-as-root marker; the dedicated user will not be written on the next install: '
        ['改写服务文件失败']='Failed to modify the service file'
        ['创建 Realm 配置目录失败']='Failed to create the Realm config directory'
        ['备份旧二进制失败']='Failed to back up the old binary'
        ['安装 Realm 二进制失败']='Failed to install the Realm binary'
        ['导出失败']='Export failed'
        ['规则状态切换失败']='Failed to change the rule status'
        ['转发配置文件写入失败']='Failed to write the forwarding config file'
        ['Realm 服务恢复后重载失败，请检查日志']='Realm failed to reload after restore; check the logs'
        ['路径含 ; 或 =，回退标准透传']='The path contains ; or =; falling back to plain forwarding'
        ['路径含 ; 或 =，回退内置自签']='The path contains ; or =; falling back to the built-in self-signed certificate'
        ['一键放行本脚本服务端口（SSH / Nowhere / Snell / Xray / Realm）']='Allow this script'\''s service ports in one click (SSH / Nowhere / Snell / Xray / Realm)'
        ['规则文件内容非法，已恢复原配置']='Invalid rule file content; the previous config has been restored'
        ['版本号：']='Version:'
        ['域名反代']='Reverse proxy'
        ['域名反代（Caddy 多域名自动 HTTPS / Cloudflare Tunnel）']='Reverse proxy (Caddy multi-domain HTTPS / Cloudflare Tunnel)'
        ['反代']='Proxy'
        ['Caddy 多域名反代 + Cloudflare Tunnel']='Caddy multi-domain reverse proxy + Cloudflare Tunnel'
        ['一键域名反代管理']='One-click Domain Reverse Proxy'
        ['安装 / 更新 Caddy（官方仓库）']='Install / update Caddy (official repo)'
        ['添加域名反代站点（自动 HTTPS）']='Add domain reverse proxy site (auto HTTPS)'
        ['查看反代站点列表']='List reverse proxy sites'
        ['启用 / 停用站点']='Enable / disable a site'
        ['编辑反代站点']='Edit a reverse proxy site'
        ['删除反代站点']='Delete a reverse proxy site'
        ['查看当前 Caddyfile 配置']='View effective Caddyfile config'
        ['Caddy 自动更新 开 / 关']='Caddy auto-update on / off'
        ['重启 Caddy / 查看状态与日志']='Restart Caddy / view status & logs'
        ['卸载 Caddy']='Uninstall Caddy'
        ['Cloudflare Tunnel 管理（Zero Trust / 临时隧道）']='Cloudflare Tunnel management (Zero Trust / quick tunnel)'
        ['安装 / 更新 cloudflared（官方仓库）']='Install / update cloudflared (official repo)'
        ['配置持久化隧道（粘贴 Zero Trust Token）']='Configure persistent tunnel (paste Zero Trust Token)'
        ['启动临时快速隧道（trycloudflare.com，免配置）']='Start temporary quick tunnel (trycloudflare.com)'
        ['查看隧道状态与日志']='View tunnel status & logs'
        ['重启持久化隧道']='Restart persistent tunnel'
        ['停用 / 卸载 cloudflared']='Disable / uninstall cloudflared'
        ['尚未安装 Caddy，请先安装']='Caddy is not installed yet, please install it first'
        ['尚未安装 cloudflared，请先安装']='cloudflared is not installed yet, please install it first'
        ['正在查询 Caddy 官方最新版本...']='Querying latest official Caddy version...'
        ['正在查询 cloudflared 官方最新版本...']='Querying latest official cloudflared version...'
        ['无法获取 Caddy 最新版本号，请检查网络']='Cannot fetch latest Caddy version, check network'
        ['无法获取 cloudflared 最新版本号，请检查网络']='Cannot fetch latest cloudflared version, check network'
        ['Caddy 安装完成']='Caddy installed'
        ['Caddy 已卸载']='Caddy uninstalled'
        ['cloudflared 安装完成']='cloudflared installed'
        ['cloudflared 已卸载']='cloudflared uninstalled'
        ['暂无反代站点']='No reverse proxy sites yet'
        ['反代站点列表']='Reverse proxy sites'
        ['反代模式：']='Reverse proxy mode:'
        ['标准反代（本机/内网服务，自动 HTTPS + WebSocket/XHTTP 透传，推荐）']='Standard proxy (local/LAN service, auto HTTPS + WebSocket/XHTTP, recommended)'
        ['反代远程站点（自动改写 Host 头，支持 HTTPS 上游）']='Proxy remote website (auto Host header rewrite, HTTPS upstream supported)'
        ['HTTP 明文反代 / 自定义端口（适合套 Cloudflare CDN 灵活模式或非 443 端口）']='Plain HTTP / custom port proxy (for Cloudflare Flexible or non-443 port)'
        ['上游目标地址（如 127.0.0.1:8080 或 https://example.com）: ']='Upstream target (e.g. 127.0.0.1:8080 or https://example.com): '
        ['反代站点已生效：']='Reverse proxy site is active: '
        ['Caddy 配置校验失败，已自动撤回改动']='Caddy config validation failed; changes rolled back automatically'
        ['输入站点序号（回车取消）: ']='Enter site number (Enter to cancel): '
        ['站点状态已切换为：']='Site status changed to: '
        ['确认删除反代站点 ']='Confirm deleting reverse proxy site '
        ['已删除反代站点 ']='Deleted reverse proxy site '
        ['输入本地服务端口（如 8080，将映射到 *.trycloudflare.com）: ']='Enter local service port (e.g. 8080, mapped to *.trycloudflare.com): '
        ['粘贴 Cloudflare Zero Trust Tunnel Token（输入不回显）: ']='Paste Cloudflare Zero Trust Tunnel Token (hidden): '
        ['Token 不能为空']='Token cannot be empty'
        ['Cloudflare Tunnel 持久化服务已启动']='Cloudflare Tunnel persistent service started'
        ['Cloudflare Tunnel 启动失败，请查看日志：journalctl -u adam-cloudflared -n 20 --no-pager']='Cloudflare Tunnel failed to start; see logs: journalctl -u adam-cloudflared -n 20 --no-pager'
        ['批量添加转发规则（端口段 / 多端口）']='Batch add forwarding rules (port range / multi-port)'
        ['编辑已有转发规则']='Edit an existing forwarding rule'
        ['查看完整有效配置（TOML）']='View effective TOML config'
        ['全局网络 / DNS 参数调优']='Global network / DNS tuning'
        ['Realm 自动更新 开 / 关']='Realm auto-update on / off'
        ['Nowhere 自动更新（仅 NW3 同代安全更新）']='Nowhere auto-update (NW3 same-major only)'
        ['Realm 跟随官方发布自动更新']='Realm auto-update following official releases'
        ['Caddy 跟随官方发布自动更新']='Caddy auto-update following official releases'
        ['Nowhere 跟随官方发布自动更新（仅 NW3 同代）']='Nowhere auto-update following official releases (NW3 only)'
        ['该端口已被本模块其他规则占用，请换一个']='Port is already used by another rule in this module; choose another'
        ['UDP 端口已被占用，请换一个']='UDP port is already in use; choose another'
        ['批量添加完成：成功 ']='Batch add complete: succeeded '
        ['，跳过 ']=', skipped '
        ['规则已更新并生效：']='Rule updated and active: '
        ['规则更新失败，已自动恢复原配置']='Rule update failed; original config restored automatically'
        ['端口段或逗号列表（如 10000-10010 或 8080,8443,9000）: ']='Port range or comma list (e.g. 10000-10010 or 8080,8443,9000): '
        ['单次批量最多支持 100 个端口，请缩小范围']='Batch limit is 100 ports per operation; please narrow the range'
        ['目标端口模式：1) 同端口一对一映射（推荐）  2) 全部指向同一个目标端口']='Target port mode: 1) 1:1 same port mapping (recommended)  2) All to one target port'
        ['个站点']='sites'
        ['未知的 proxy 子命令:']='Unknown proxy subcommand:'
        ['隧道已运行']='tunnel active'
        ['未配置']='unconfigured'
        ['已配置']='configured'
        ['（可用: install / add / batch / edit / list / toggle / delete / test / config / tune / auto / restart / status / logs / export / import / uninstall）']='(available: install / add / batch / edit / list / toggle / delete / test / config / tune / auto / restart / status / logs / export / import / uninstall)'
        ['proxy                      打开域名反代菜单（Caddy / Cloudflare Tunnel）']='proxy                      Open domain reverse proxy menu (Caddy / Cloudflare Tunnel)'
        ['caddy / tunnel             直接操作 Caddy 反代或 Cloudflare Tunnel']='caddy / tunnel             Manage Caddy reverse proxy or Cloudflare Tunnel directly'
        ['每日定时重启 Snell / Xray / Nowhere / Realm（随每日维护执行）']='Daily scheduled restart of Snell / Xray / Nowhere / Realm'
        ['恢复会覆盖 /etc/nowhere、/etc/snell、/etc/adam-xray、/etc/adam-realm、/etc/adam-caddy、/etc/adam-cloudflared 等现有配置，并重启已启用的服务']='Restore will overwrite existing configs in /etc/nowhere, /etc/snell, /etc/adam-xray, /etc/adam-realm, /etc/adam-caddy and /etc/adam-cloudflared, and restart enabled services'
        ['一键放行本脚本服务端口（SSH / Nowhere / Snell / Xray / Realm / Caddy）']='Allow this script'\''s service ports in one click (SSH / Nowhere / Snell / Xray / Realm / Caddy)'
        ['当前没有由本脚本管理的服务端口需要放行（Nowhere / Snell / Xray / Realm / Caddy 均未安装）']='No service ports managed by this script need allowing (Nowhere / Snell / Xray / Realm / Caddy are not installed)'
        ['（无 Nowhere/Snell/Xray/Realm/Caddy 的 TCP 监听）']='(no Nowhere/Snell/Xray/Realm/Caddy TCP listeners)'
        ['（无 Nowhere/Snell/Xray/Realm/Caddy 的 UDP 监听）']='(no Nowhere/Snell/Xray/Realm/Caddy UDP listeners)'
        ['（存在端口未监听：']='(port(s) not listening: '
        ['生成随机密钥/UUID 失败，请检查 openssl 与 Xray 二进制']='Failed to generate random key/UUID; check openssl and Xray binary'
        ['Nowhere 自动更新:']='Nowhere auto-update:'
        ['Realm 自动更新:']='Realm auto-update:'
        ['Caddy 自动更新:']='Caddy auto-update:'
        ['是否同时卸载域名反代（Caddy / Cloudflare Tunnel）？']='Also uninstall reverse proxy (Caddy / Cloudflare Tunnel)?'
        ['，不自动跨大版本']=', not auto-upgrading across major versions'
        ['跳过上游 TLS 证书校验（自签上游选 y）？']='Skip upstream TLS verification (choose y for self-signed upstream)?'
    )
    _I18N_INIT=1
}

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

# confirm "提示" [y|n]：第二个参数是回车时的默认值
confirm() {
    local prompt="$1" def="${2:-n}" ans=""
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
        warn "$(L '未找到 apt-get（本脚本仅支持 Debian/Ubuntu），请手动安装:') ${need[*]}"
        return 1
    fi
    if [ "$APT_UPDATED" != "1" ]; then
        apt-get update -qq || warn "$(L 'apt-get update 失败，继续尝试安装')"
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

# record_previous_version TAG：只把符合 ^v?[0-9] 的版本号写入 PREV_VERSION_FILE（M1）
record_previous_version() {
    local v="$1"
    [[ "$v" =~ ^v?[0-9] ]] || return 0
    echo "$v" > "$PREV_VERSION_FILE"
}

# pick_udp_port_avoiding TCP_PORT：从 2001 起找与 TCP 不同且 TCP/UDP 都未监听的端口（M9）
pick_udp_port_avoiding() {
    local tcp="$1" cand=2001
    while [ "$cand" -le 65535 ]; do
        if [ "$cand" != "$tcp" ] && ! udp_listening "$cand" && ! tcp_listening "$cand"; then printf '%s' "$cand"; return 0; fi
        cand=$((cand + 1))
    done
    return 1
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
    make_workdir || return 1
    local workdir="$WORKDIR"
    url="https://github.com/${REPO}/releases/download/${tag}/${BIN_NAME}"
    if ! curl -fL --retry 3 --connect-timeout 10 --max-time 300 -o "$workdir/nowhere.tar.gz" "$url"; then
        warn "$(L '下载失败（该版本可能没有') ${ARCH_NAME}-${LIBC} $(L '的发布文件）:') ${url}"
        return 1
    fi
    verify_release_checksum "$tag" "$workdir" || { warn "$(L '安装包 SHA256 校验失败，已中止')"; return 1; }
    tar -xzf "$workdir/nowhere.tar.gz" -C "$workdir/" || { warn "$(L '解压失败')"; return 1; }
    DL_BINARY="$(find "$workdir" -type f -name nowhere | head -1)"
    if [ -z "$DL_BINARY" ]; then warn "$(L '解压后未找到 nowhere 二进制')"; return 1; fi
    chmod 755 "$DL_BINARY"
    if ! upgrade_binary_precheck "$DL_BINARY" --version; then
        warn "$(L '下载到的二进制无法在本机运行（架构或 libc 不匹配），已中止，现有安装未被改动')"
        return 1
    fi
    return 0
}

# 升级跨过关键版本时的互通提醒（依据官方 v3.2.0 / v3.3.0 文档）
print_upgrade_notes() {
    local from="$1" to="$2"
    if version_ge "$to" "v3.2.0" && ! version_ge "$from" "v3.2.0"; then
        warn "$(L 'v3.2.0 起 Portal 强制 Authenticated Prelude、不再有回退：仍停留在 v3.0.x 的 Vector/Egress/Anywhere 在 morph=1 的 TLS/TCP 载体上会被静默拒绝')"
        warn "$(L '请把所有对端升级到') ≥ $(L 'v3.1.0（建议与本机同版本）；QUIC 载体与 morph=0 不受这条影响')"
    fi
    if version_ge "$to" "v3.3.0" && ! version_ge "$from" "v3.3.0"; then
        info "$(L 'v3.3.0 新增：Egress 可走 TLS/TCP（egress://KEY')@$(L 'HOST/tcp:PORT）、多台 Egress 可同时注册、NOW_MORPH_UDP_PRELUDE、握手超时默认按共享密钥派生（3–30s）')"
        info "$(L '现有 URL / 密钥 / 证书无需迁移；要用 TLS 载体的 Egress，出口机也需') ≥ v3.3.0"
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
        printf '%s' "${GREEN}$(L '运行中')${NC}"
    else
        printf '%s' "${RED}$(L '未运行')${NC}"
    fi
}

# ── 架构 / 二进制 ─────────────────────────────────────────────

detect_binary() {
    ARCH=$(uname -m)
    case $ARCH in
        x86_64|amd64)  ARCH_NAME="x86_64" ;;
        aarch64|arm64) ARCH_NAME="aarch64" ;;
        *)             error "$(L '不支持的架构:') ${ARCH}" ;;
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
    [ -f "$VERSION_FILE" ] || return 0
    cat "$VERSION_FILE" 2>/dev/null || true
}

read_previous_version() {
    [ -f "$PREV_VERSION_FILE" ] && cat "$PREV_VERSION_FILE" || echo ""
}

# 取 tag 的主版本号，如 v3.0.0 -> 3；解析不了返回空
version_major() {
    echo "$1" | sed -n 's/^v\?\([0-9][0-9]*\)\..*/\1/p'
}

# upgrade_binary_precheck bin [version_flag]：新二进制预检（文件存在+可执行+试跑）。
# version_flag 为空时只做可执行与文件校验。Nowhere 用 --version；Snell 脚本里没有
# --version 用法，已有用 -v（snell_installed_version / snell_fetch），故 Snell 用 -v。
upgrade_binary_precheck() {
    local bin="$1" flag="${2:-}"
    [ -f "$bin" ] && [ -x "$bin" ] || return 1
    [ -z "$flag" ] && return 0
    timeout 10 "$bin" "$flag" >/dev/null 2>&1
}

# 升级通用收尾：替换已由调用方完成；重启 → 等待 sleep_secs → 健康检查 → 失败打 log_lines 行日志并回滚
# upgrade_binary_finish unit restart_fn healthy_fn rollback_fn rollback_arg sleep_secs log_lines
upgrade_binary_finish() {
    local unit="$1" restart_fn="$2" healthy_fn="$3" rollback_fn="$4" rollback_arg="${5:-}" sleep_secs="${6:-2}" log_lines="${7:-20}"
    "$restart_fn" 2>/dev/null || true
    sleep "$sleep_secs"
    if "$healthy_fn"; then return 0; fi
    warn "$(L '新版本启动失败，日志如下：')"
    journalctl -u "$unit" -n "$log_lines" --no-pager 2>/dev/null || true
    if [ -n "$rollback_fn" ]; then "$rollback_fn" "$rollback_arg" 2>/dev/null || true; fi
    return 1
}

_upgrade_restart_nowhere() { systemctl restart nowhere; }
_upgrade_healthy_nowhere() { systemctl is-active --quiet nowhere 2>/dev/null; }

# Nowhere 回滚到本地备份二进制（install_nowhere_version 的回滚段抽出，供 upgrade_binary_finish 回调）
nowhere_rollback_binary() {
    local prev="${1:-}"
    [ -f "$BIN_BACKUP_PATH" ] || return 1
    warn "$(L '正在自动回滚到备份二进制')${prev:+(${prev})}..."
    install -m 755 "$BIN_BACKUP_PATH" "$BIN_PATH"
    [ -n "$prev" ] && record_installed_version "$prev"
    systemctl restart nowhere 2>/dev/null || true
    sleep 2
    if systemctl is-active --quiet nowhere; then
        success "$(L '已自动回滚，服务恢复运行:') $(${BIN_PATH} --version 2>&1 | head -1)"
    else
        warn "$(L '回滚后服务仍未启动，请立即查看日志: journalctl -u nowhere -n 50 --no-pager')"
    fi
    return 0
}

install_nowhere_version() {
    maint_lock_manual || return 1
    local target_tag="$1"
    _CACHED_TLS_FP=""
    detect_binary

    local major
    major="$(version_major "$target_tag")"
    if [ -n "$major" ] && [ "$major" -lt 3 ]; then
        warn "$(L '目标版本') ${target_tag} $(L '属于 NW')${major} $(L '协议代，与本脚本生成的 v3')(NW3) $(L '配置/对端不互通')"
        read -rp "$(L '仍要安装该旧版本吗？')[y/N]: " OLD_CONFIRM || { [ -n "$OLD_CONFIRM" ] || return 1; }
        if [[ ! "$OLD_CONFIRM" =~ ^[Yy]$ ]]; then
            info "$(L '已取消')"
            return 1
        fi
    fi
    if [ -n "$major" ] && [ "$major" -gt 3 ]; then
        warn "$(L '目标版本') ${target_tag} $(L '属于新的协议代（NW')${major}$(L '），本脚本只适配 NW3：URL 语法、密钥格式、对端兼容性都可能已变化')"
        read -rp "$(L '仍要安装吗？')[y/N]: " NEW_CONFIRM || { [ -n "$NEW_CONFIRM" ] || return 1; }
        if [[ ! "$NEW_CONFIRM" =~ ^[Yy]$ ]]; then
            info "$(L '已取消')"
            return 1
        fi
    fi

    info "$(L '下载并校验') ${target_tag} (${ARCH_NAME}-${LIBC}) ..."
    fetch_nowhere_release "$target_tag" || return 1

    local cur_tag
    cur_tag="$(read_installed_version)"
    install -d -m 700 "$CONFIG_DIR"
    if [ -f "$BIN_PATH" ]; then
        cp "$BIN_PATH" "$BIN_BACKUP_PATH"
        record_previous_version "$cur_tag"
    fi

    # install 会先删除旧文件再写入新文件，运行中的进程不受影响；随后一次 restart 完成切换，
    # 比旧版的 stop -> 替换 -> start 少一段停机窗口
    install -m 755 "$DL_BINARY" "$BIN_PATH"
    record_installed_version "$target_tag"

    if [ ! -f "$SERVICE_FILE" ]; then
        success "$(L '二进制已更新到') ${target_tag}$(L '（未检测到 nowhere.service，未启动服务）')"
        return 0
    fi

    # 启动失败自动用本地备份二进制回滚，不把服务留在宕机状态
    if upgrade_binary_finish nowhere _upgrade_restart_nowhere _upgrade_healthy_nowhere nowhere_rollback_binary "$cur_tag" 2 20; then
        success "$(L '已切换到') ${target_tag}: $(${BIN_PATH} --version 2>&1 | head -1)"
        print_upgrade_notes "$cur_tag" "$target_tag"
        return 0
    fi
    return 1
}

# ── 通用小工具 ────────────────────────────────────────────────

urlencode() {
    local input="${1:-}"
    python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$input" 2>/dev/null \
        || echo -n "$input" | od -An -tx1 | tr ' ' % | tr -d '\n'
}

urldecode() {
    local input="${1:-}"
    python3 -c 'import sys, urllib.parse; print(urllib.parse.unquote(sys.argv[1]))' "$input" 2>/dev/null \
        || printf '%s' "$input"
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

# 是否为公网 IP（排除私网/回环/链路本地/CGNAT/文档段/组播；IPv6 排除回环/链路本地/ULA/文档段）
is_public_ip() {
    local ip="$1" a b
    ip="${ip#[}"; ip="${ip%]}"
    if [[ "$ip" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
        a="${BASH_REMATCH[1]}"; b="${BASH_REMATCH[2]}"
        case "$a" in
            0|127) return 1 ;;
            10) return 1 ;;
            100) [ "$b" -ge 64 ] && [ "$b" -le 127 ] && return 1 ;;
            169) [ "$b" = "254" ] && return 1 ;;
            172) [ "$b" -ge 16 ] && [ "$b" -le 31 ] && return 1 ;;
            192)
                case "$b" in 0|168) return 1 ;; esac
                ;;
            198)
                case "$b" in 18|19|51) return 1 ;; esac
                ;;
            203) [ "$b" = "0" ] && return 1 ;;
            224|225|226|227|228|229|230|231|232|233|234|235|236|237|238|239) return 1 ;;
            24[0-9]|25[0-9]) return 1 ;;
        esac
        return 0
    fi
    local low="${ip,,}"
    case "$low" in
        ::1|::) return 1 ;;
        fe8*|fe9*|fea*|feb*|fc*|fd*) return 1 ;;
        2001:db8*) return 1 ;;
    esac
    [[ "$low" == *:* ]] && return 0
    return 1
}

detect_public_host() {
    local detected="" u cand
    for u in https://api.ipify.org https://ipv4.icanhazip.com https://ifconfig.me/ip; do
        detected="$(curl -4fsS --max-time 4 "$u" 2>/dev/null | tr -d ' \r\n' || true)"
        if [[ "$detected" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then break; fi
        detected=""
    done
    if [ -z "$detected" ]; then
        # 纯 IPv6 机器：再查一次 IPv6 出口地址（只接受公网段）
        detected="$(curl -6fsS --max-time 4 https://api64.ipify.org 2>/dev/null | tr -d ' \r\n' || true)"
        [[ "$detected" =~ ^[0-9A-Fa-f:]+$ ]] && is_public_ip "$detected" || detected=""
    fi
    if [ -z "$detected" ]; then
        # hostname -I 可能先返回内网地址：只取其中第一个公网 IP，取不到返回空
        # （空值会强制手动输入，而不是悄悄用内网 IP 生成一堆连不上的分享链接）
        for cand in $(hostname -I 2>/dev/null || true); do
            if is_public_ip "$cand"; then detected="$cand"; break; fi
        done
    fi
    printf '%s' "$detected"
}

# 解析域名到 IP 列表（每行一个），解析不到返回空
resolve_host_ips() {
    local host="$1" out=""
    if command -v getent >/dev/null 2>&1; then
        out="$(getent hosts "$host" 2>/dev/null | awk '{print $1}' || true)"
    fi
    if [ -z "$out" ] && command -v host >/dev/null 2>&1; then
        out="$(host "$host" 2>/dev/null | awk '/has address|has IPv6 address/ {print $NF}' || true)"
    fi
    if [ -z "$out" ] && command -v dig >/dev/null 2>&1; then
        out="$(dig +short "$host" 2>/dev/null | grep -E '^[0-9A-Fa-f:.]+$' || true)"
    fi
    printf '%s' "$out"
}

# 校验分享链接用的公网地址：IP 必须是公网 IP；域名必须能解析，且解析结果须与本机公网 IP 一致
# （不一致可能是 CDN/多线，也可能是填错；调用方据此警告并由用户确认是否仍用）。返回 0=可用，1=有问题
check_public_host() {
    local host="$1" detected="" resolved="" rip
    if [ -z "$host" ]; then
        warn "$(L '公网地址为空')"
        return 1
    fi
    if [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ "$host" == *:* ]]; then
        if ! is_public_ip "$host"; then
            warn "$(L '该地址不是公网 IP（内网/保留地址），客户端连不上：')${host}"
            return 1
        fi
        return 0
    fi
    resolved="$(resolve_host_ips "$host")"
    if [ -z "$resolved" ]; then
        warn "$(L '该域名解析不到任何 IP，请检查域名/DNS：')${host}"
        return 1
    fi
    detected="$(detect_public_host)"
    if [ -n "$detected" ]; then
        while IFS= read -r rip; do
            [ "$rip" = "$detected" ] && return 0
        done <<< "$resolved"
        warn "$(L '该域名解析到的 IP 与本机公网 IP 不一致（可能是 CDN/多线，也可能是填错）：')$(printf '%s' "$resolved" | tr '\n' ' ' | sed 's/ $//')$(L '，')$(L '本机公网 IP：')${detected}"
        return 1
    fi
    return 0
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
    # 10# 规范化：08/09 之类带前导 0 的输入不能按八进制解析（L1）
    [[ "$1" =~ ^[0-9]+$ ]] || return 1
    [[ "${#1}" -le 5 ]] || return 1
    local _vp=$((10#$1))
    [ "$_vp" -ge 1 ] && [ "$_vp" -le 65535 ]
}

# v3.3 新增：握手超时为持续时间格式（官方示例 5s / 250ms / 1h）；须为正数+单位，
# 非法值会被 v3.3 在启动时直接拒绝（启动失败并点名该变量）
validate_duration() {
    [[ "$1" =~ ^[1-9][0-9]*(ms|s|m|h)$ ]]
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

# sanitize_nowhere_params：端口/时长/限速/分端口冲突一次校验并修正（向导、加载、重配、Egress 解析共用，M17）
# 读全局与调用方 locals（bash 动态作用域）；只修正内存里的值，不写文件；恒返回 0
sanitize_nowhere_params() {
    if [ -n "${PORT:-}" ]; then
        validate_port "$PORT" || { warn "$(L '端口不合法，重置为443')"; PORT=443; }
    fi
    if [ -n "${TCP_PORT:-}" ]; then
        validate_port "$TCP_PORT" || { warn "$(L '端口不合法，重置为2000')"; TCP_PORT=2000; }
    fi
    if [ -n "${UDP_PORT:-}" ]; then
        validate_port "$UDP_PORT" || { warn "$(L '端口不合法，重置为2001')"; UDP_PORT=2001; }
    fi
    if [ "${PORT_MODE:-}" = "split" ] && [ -n "${TCP_PORT:-}" ] && [ "$TCP_PORT" = "${UDP_PORT:-}" ]; then
        UDP_PORT="$(pick_udp_port_avoiding "$TCP_PORT" || echo 2001)"
        warn "$(L '分端口模式下 TCP 与 UDP 端口不能相同，已将 UDP 端口改为') ${UDP_PORT}"
    fi
    if [ -n "${HANDSHAKE_TIMEOUT:-}" ]; then
        validate_duration "$HANDSHAKE_TIMEOUT" || { warn "$(L '格式不合法（须为正数+单位，如 10s / 500ms / 1m / 1h），已重置为 10s')"; HANDSHAKE_TIMEOUT="10s"; }
    fi
    if [ -n "${RATE:-}" ]; then validate_rate "$RATE" || { warn "$(L '限速不合法，已清空（不限速）')"; RATE=""; }; fi
    if [ -n "${ETAR:-}" ]; then validate_rate "$ETAR" || { warn "$(L '限速不合法，已清空（不限速）')"; ETAR=""; }; fi
    if [ -n "${DIAL:-}" ]; then validate_ip_or_auto "$DIAL" || { warn "$(L '出站源 IP 不合法，已重置为 auto')"; DIAL="auto"; }; fi
    if [ -n "${DIAL4:-}" ]; then validate_ip_or_auto "$DIAL4" 4 || { warn "$(L '出站源 IP 不合法，已重置为 auto')"; DIAL4="auto"; }; fi
    if [ -n "${DIAL6:-}" ]; then validate_ip_or_auto "$DIAL6" 6 || { warn "$(L '出站源 IP 不合法，已重置为 auto')"; DIAL6="auto"; }; fi
    case "${MORPH_TCP_PRELUDE:-}" in ""|fade|full8|low7) : ;; *) MORPH_TCP_PRELUDE="fade" ;; esac
    case "${MORPH_UDP_PRELUDE:-}" in ""|fade|full8|low7) : ;; *) MORPH_UDP_PRELUDE="fade" ;; esac
    if [ -n "${eg_port:-}" ]; then validate_port "$eg_port" || { warn "$(L '端口不合法，重置为 443')"; eg_port=443; }; fi
    if [ -n "${eg_handshake:-}" ]; then validate_duration "$eg_handshake" || { warn "$(L '格式不合法（须为正数+单位，如 10s），已重置为 10s')"; eg_handshake="10s"; }; fi
    return 0
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
# 自签指纹取不到（服务未启动等）时返回 1，调用方应留空并提示稍后用Nowhere 菜单 4/10 重新生成
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
        local _url_crt="${CRT_RUNTIME:-$CRT}" _url_key="${KEY_PEM_RUNTIME:-$KEY_PEM}"
        query="${query}&crt=$(encode_path "$_url_crt")&key=$(encode_path "$_url_key")"
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
    UDP_LINK=""; TCP_LINK=""; IMPORT_UDP=""; IMPORT_TCP=""
    host="${PUBLIC_HOST:-}"
    [[ -z "$host" ]] && host="$(detect_public_host)"
    if [[ -z "$host" ]]; then
        warn "$(L '未能确定公网地址，无法生成 Anywhere 分享链接')"
        return 0
    fi
    host_part="$(format_host_for_url "$host")"
    encoded_name="$(urlencode "Nowhere-${DOMAIN}")"
    base="nowhere://${SHARED_KEY}@${host_part}"

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
        warn "$(L '未能确定公网地址，无法生成 Vector 连接串，可稍后通过Nowhere 菜单「4')) $(L '查看连接信息」重试')"
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
        warn "$(L '未能获取自签证书指纹，Vector 连接串暂缺 pin=（服务启动后可用 Nowhere 菜单 4 重新生成）')"
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
        warn "$(L '未能确定公网地址，无法生成 Egress 连接串，可稍后通过Nowhere 菜单「4')) $(L '查看连接信息」重试')"
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
        warn "$(L '未能获取自签证书指纹，Egress 连接串暂缺 pin=（服务启动后可用 Nowhere 菜单 4 重新生成）')"
    fi
    EGRESS_URL="egress://${SHARED_KEY}@${host_part}/${carrier}:${port}?${query}"
}

# 供 probe 使用的 Vector URL（不需要 in=）
build_probe_vector_url() {
    local host host_part port carrier query
    host="${PUBLIC_HOST:-}"
    [[ -z "$host" ]] && host="$(detect_public_host)"
    if [[ -z "$host" ]]; then
        warn "$(L '未能确定公网地址，无法生成 Vector 探针链接')"
        return 1
    fi
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
    # 单次展示流程内缓存：do_show_config 一次调 4 次，服务刚重启/指纹暂不可读时每次 timeout 8 会叠加卡顿
    if [ -n "${_CACHED_TLS_FP:-}" ]; then printf '%s' "$_CACHED_TLS_FP"; return 0; fi
    local jfp
    if ! has_tcp; then
        jfp="$(get_fingerprint_from_journal 2>/dev/null || true)"
        if [ -n "$jfp" ]; then
            _CACHED_TLS_FP="$jfp"
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
            _CACHED_TLS_FP="$fp"
            echo "$fp"
            return 0
        fi
    fi
    jfp="$(get_fingerprint_from_journal 2>/dev/null || true)"
    if [ -n "$jfp" ]; then
        _CACHED_TLS_FP="$jfp"
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
            fingerprint="$(echo "$fingerprint" | tr -d ':' | tr 'A-F' 'a-f')"
            _CACHED_TLS_FP="$fingerprint"
            echo "$fingerprint"
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
                info "$(L '当前 tls=2 证书 SHA-256 指纹（续期后会变化）：')"
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
            info "$(L '已从当前服务启动日志读取到自签证书 SHA-256 指纹：')"
            echo -e "  ${GREEN}${journal_fp}${NC}"
            warn "$(L 'tls=1 证书只存在内存中，Nowhere 每次重启后指纹都会变化，pin= 需同步重新生成（Nowhere 菜单 4 或 pz 命令）')"
        else
            warn "$(L '当前为纯 QUIC/UDP Portal，没有 TLS 监听，且启动日志中未找到指纹')"
            warn "$(L '自签模式下 Vector/Egress 的 pin 请从 Portal 启动日志含 fingerprint 的一行获取')"
        fi
        return 0
    fi
    echo
    info "$(L '正在获取自签证书 SHA-256 指纹...')"
    local fingerprint
    fingerprint="$(get_tls_fingerprint || true)"
    if [ -n "$fingerprint" ]; then
        echo -e "  ${GREEN}${fingerprint}${NC}"
        warn "$(L 'tls=1 证书只存在内存中，Nowhere 每次重启后指纹都会变化，pin= 需同步重新生成（Nowhere 菜单 4 或 pz 命令）')"
    else
        warn "$(L '暂未获取到指纹，可稍后运行: journalctl -u nowhere -n 100') | grep fingerprint"
    fi
}

ensure_ipv4_preference() {
    local has_ipv6_addr=false
    if ip -6 addr show scope global 2>/dev/null | grep -q "inet6"; then
        has_ipv6_addr=true
    fi

    [ "$has_ipv6_addr" = false ] && return 0

    info "$(L '检测到本机配置了 IPv6 地址，测试实际是否能连通外网...')"
    if curl -6 -fsS --max-time 5 https://www.cloudflare.com >/dev/null 2>&1; then
        success "$(L 'IPv6 连通性正常，无需调整')"
        return 0
    fi

    warn "$(L 'IPv6 地址已配置，但实际无法连通外网（VPS常见问题：分配了地址却未正确路由）')"
    warn "$(L '这会导致 curl/certbot 优先尝试 IPv6 而报错') 'Network is unreachable'"

    if ! grep -q "^precedence ::ffff:0:0/96" /etc/gai.conf 2>/dev/null; then
        mkdir -p "$(dirname "$GAI_BACKUP")"
        if [ ! -e "$GAI_BACKUP" ] && [ ! -e "${GAI_BACKUP}.absent" ]; then
            if [ -f /etc/gai.conf ]; then
                cp -a /etc/gai.conf "$GAI_BACKUP"
            else
                : > "${GAI_BACKUP}.absent"
            fi
        fi
        info "$(L '写入 /etc/gai.conf，让系统优先选用 IPv4（不关闭IPv6，只调整地址选择优先级）')"
        [ -n "$(tail -c 1 /etc/gai.conf 2>/dev/null)" ] && echo >> /etc/gai.conf
        echo "precedence ::ffff:0:0/96  100" >> /etc/gai.conf
    fi

    if curl -fsS --max-time 5 https://acme-v02.api.letsencrypt.org/directory >/dev/null 2>&1; then
        success "$(L '已修正为 IPv4 优先，现在可以正常连接 Let')'s Encrypt"
    else
        warn "$(L '调整后仍无法连接，请检查 VPS 出网本身是否正常: ping -c 3 8.8.8.8')"
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
        info "$(L '通过管道/进程替换运行，无法直接复制自身，正在从脚本地址重新下载一份...')"
        local dl_ok=0
        tmp="$(mktemp /tmp/adam-manager.XXXXXX)"
        if command -v curl >/dev/null 2>&1; then
            curl -fsSL --max-time 30 "$SCRIPT_URL" -o "$tmp" 2>/dev/null && dl_ok=1
        elif command -v wget >/dev/null 2>&1; then
            wget -qO "$tmp" "$SCRIPT_URL" 2>/dev/null && dl_ok=1
        fi
        if [ "$dl_ok" != "1" ] || [ ! -s "$tmp" ] || ! grep -q "Adam Nowhere" "$tmp" 2>/dev/null || ! bash -n "$tmp" 2>/dev/null; then
            rm -f "$tmp"
            warn "$(L '重新下载脚本失败，管理脚本副本无法安装')"
            warn "$(L '请改用文件方式运行：curl -fsSL') ${SCRIPT_URL} -o ${MANAGER_PATH} && chmod +x ${MANAGER_PATH} && ${MANAGER_PATH}"
            return 1
        fi
        install -m 755 "$tmp" "$MANAGER_PATH"
        rm -f "$tmp"
        self_path="$MANAGER_PATH"
        local remote_ver
        remote_ver="$(grep -m1 '^SCRIPT_VERSION=' "$MANAGER_PATH" 2>/dev/null | cut -d'"' -f2 || true)"
        if [ -n "${SCRIPT_VERSION:-}" ] && [ -n "$remote_ver" ] && [ "${remote_ver#v}" != "${SCRIPT_VERSION#v}" ]; then
            warn "$(L '注意：下载到的脚本版本为') ${remote_ver}$(L '，与当前运行的') ${SCRIPT_VERSION} $(L '不一致（可能新版尚未推送到') ${SCRIPT_URL}$(L '），管理命令将指向下载到的版本')"
        fi
    fi

    if [ "$self_path" != "$MANAGER_PATH" ]; then
        install -m 755 "$self_path" "$MANAGER_PATH"
    fi
    chmod +x "$MANAGER_PATH"
    return 0
}

# 校验快捷命令与管理脚本副本是否就绪（安装/重配结束时调用；只警告，不中断安装）
verify_shortcuts() {
    if [ -x /usr/local/bin/adam ] && [ -x "$MANAGER_PATH" ]; then
        success "$(L '快捷命令已就绪：输入 adam 打开菜单')"
        return 0
    fi
    warn "$(L '快捷命令未能安装（服务本身不受影响）')"
    info "$(L '修复：重新运行安装脚本文件，或执行：')"
    echo "  curl -fsSL ${SCRIPT_URL} -o ${MANAGER_PATH} && chmod +x ${MANAGER_PATH} && ${MANAGER_PATH} shortcuts"
    return 1
}

install_shortcuts() {
    step "$(L '安装快捷命令')"
    divider
    if ! ensure_manager_copy; then
        warn "$(L '快捷命令无法安装')"
        return 1
    fi

    # 快捷命令只是薄壳：先校验管理脚本副本在位，缺失时给出修复方法而不是报看不懂的错
    local spec name args
    for spec in "adam:" "zt:status" "pz:config" "cxpz:reconfig" "cq:restart"; do
        name="${spec%%:*}"; args="${spec#*:}"
        cat > "/usr/local/bin/${name}" << SHORTEOF
#!/bin/bash
if [ ! -x "${MANAGER_PATH}" ]; then
    echo "管理脚本副本缺失：${MANAGER_PATH}" >&2
    echo "修复：重新运行安装脚本文件，或执行：" >&2
    echo "  curl -fsSL ${SCRIPT_URL} -o ${MANAGER_PATH} && chmod +x ${MANAGER_PATH} && ${MANAGER_PATH} shortcuts" >&2
    exit 1
fi
exec "${MANAGER_PATH}" ${args} "\$@"
SHORTEOF
        chmod +x "/usr/local/bin/${name}"
    done

    local missing=0 n
    for n in adam zt pz cxpz cq; do
        [ -x "/usr/local/bin/${n}" ] || missing=1
    done
    [ -x "$MANAGER_PATH" ] || missing=1
    if [ "$missing" = "1" ]; then
        warn "$(L '快捷命令安装失败：请检查 /usr/local/bin 是否可写，并确认管理脚本副本存在：')${MANAGER_PATH}"
        return 1
    fi

    success "$(L '快捷命令已安装完成')"
    echo -e "  ${CYAN}adam${NC}   $(L '— 打开管理菜单')"
    echo -e "  ${CYAN}zt${NC}     $(L '— 查看服务状态')"
    echo -e "  ${CYAN}pz${NC}     $(L '— 查看节点/连接信息')"
    echo -e "  ${CYAN}cxpz${NC}   $(L '— 重新修改配置')"
    echo -e "  ${CYAN}cq${NC}     $(L '— 快速重启服务')"
}

# ── 证书申请与自动续期（v2 新增/重构） ──────────────────────────
# v4.4: tls=1 证书只存在内存中、无文件可续期，指纹每次重启都会变。
# save_current_pin 把当前指纹写进 ${TLS_PIN_FILE}（600 权限，含更新时间），
# 供重启后对照、给对端更新 pin= 用；config.txt 本身每次查看都会按最新 pin 重建。
# tls=2 走系统 CA 校验不靠 pin，直接返回。取不到指纹时不写旧值、不伪造。
save_current_pin() {
    local fp
    [ "$(current_role)" = "portal" ] || return 0
    [ -f "$CONFIG_FILE" ] || return 0
    load_saved_config 2>/dev/null || return 0
    [ "${TLS_MODE:-}" = "1" ] || return 0
    fp="$(get_tls_fingerprint 2>/dev/null | grep -oE '[0-9a-f]{64}' | head -1 || true)"
    if [ -z "$fp" ]; then
        warn "$(L '未能读取当前自签指纹，')${TLS_PIN_FILE} $(L '未更新（服务刚重启时可稍等再用 Nowhere 菜单 10 查看）')"
        return 1
    fi
    install -d -m 700 "$CONFIG_DIR"
    {
        echo "fingerprint=${fp}"
        echo "updated=$(date '+%Y-%m-%d %H:%M:%S %Z')"
        echo "note=tls=1 fingerprint changes on every restart; Vector/Egress pin= must be updated to this value"
    } > "$TLS_PIN_FILE"
    chmod 600 "$TLS_PIN_FILE"
    info "$(L '自签指纹已更新到') ${TLS_PIN_FILE}$(L '（Vector/Egress 的 pin= 请同步改为新值）')"
    return 0
}


# acme.sh --reloadcmd 调用的同步脚本：重拷证书副本到 ${CONFIG_DIR}/certs 再 restart Nowhere
install_nowhere_cert_sync_script() {
    local script="${CONFIG_DIR}/cert-sync.sh"
    install -d -m 700 "$CONFIG_DIR"
    cat > "$script" << SYNCEOF
#!/bin/bash
# acme.sh reloadcmd: re-sync the service-readable cert copies, then restart Nowhere
if [ -f "${CONFIG_DIR}/nowhere.env" ]; then
    # shellcheck disable=SC1091
    source "${CONFIG_DIR}/nowhere.env" 2>/dev/null || true
fi
_crt="\${CRT_VALUE:-}"; _key="\${KEY_PEM_VALUE:-}"
_dest="${CONFIG_DIR}/certs"
if [ -n "\$_crt" ] && [ -n "\$_key" ] && [ -f "\$_crt" ] && [ -f "\$_key" ] && [ "\$_crt" != "\$_dest/fullchain.pem" ]; then
    install -d -m 700 -o nowhere -g nowhere "\$_dest" 2>/dev/null || install -d -m 700 "\$_dest" 2>/dev/null || true
    install -m 600 -o nowhere -g nowhere "\$_crt" "\$_dest/fullchain.pem" 2>/dev/null || install -m 600 "\$_crt" "\$_dest/fullchain.pem" 2>/dev/null || true
    install -m 600 -o nowhere -g nowhere "\$_key" "\$_dest/privkey.pem" 2>/dev/null || install -m 600 "\$_key" "\$_dest/privkey.pem" 2>/dev/null || true
fi
systemctl restart nowhere 2>/dev/null || true
SYNCEOF
    chmod 700 "$script"
}

# 每日维护兜底：续期后副本与源证书不一致时同步（覆盖 acme.sh/certbot 两路）
nowhere_sync_cert_copy() {
    [ "$(current_role)" = "portal" ] || return 0
    [ -f "$CONFIG_FILE" ] || return 0
    load_saved_config 2>/dev/null || return 0
    [ "${TLS_MODE:-}" = "2" ] || return 0
    local dest="${CONFIG_DIR}/certs"
    [ -d "$dest" ] || return 0
    [ -f "$CRT" ] && [ -f "$KEY_PEM" ] || return 0
    # 源路径与副本路径相同时跳过，避免自己拷贝自己
    [ "$CRT" != "$dest/fullchain.pem" ] || return 0
    if cmp -s "$CRT" "$dest/fullchain.pem" && cmp -s "$KEY_PEM" "$dest/privkey.pem"; then return 0; fi
    install -m 600 -o nowhere -g nowhere "$CRT" "$dest/fullchain.pem" 2>/dev/null || install -m 600 "$CRT" "$dest/fullchain.pem" 2>/dev/null || return 1
    install -m 600 -o nowhere -g nowhere "$KEY_PEM" "$dest/privkey.pem" 2>/dev/null || install -m 600 "$KEY_PEM" "$dest/privkey.pem" 2>/dev/null || return 1
    systemctl restart nowhere 2>/dev/null || true
    info "$(L '证书副本已同步')"
    return 0
}

# restart_nowhere_with_fallback [check_listen]：写 unit 已由调用方完成；这里做
# daemon-reload/enable/restart → 低权回退 → 返回 active/监听状态。
# $1=1 时 Portal 还须校验已配载体端口真实在监听；返回 0=正常，1=异常
restart_nowhere_with_fallback() {
    local check_listen="${1:-0}"
    systemctl daemon-reload
    systemctl enable nowhere 2>/dev/null || true
    systemctl restart nowhere || true
    sleep 3
    if ! systemctl is-active --quiet nowhere && [ "${NOWHERE_USER:-root}" = "nowhere" ]; then
        warn "$(L '低权用户启动失败，回退为 root 运行')"
        sed -i 's/^User=nowhere/User=root/; s/^Group=nowhere/Group=root/' "$SERVICE_FILE"
        systemctl daemon-reload
        systemctl restart nowhere || true
        sleep 3
        NOWHERE_USER="root"
    fi
    systemctl is-active --quiet nowhere || return 1
    if [ "$check_listen" = "1" ] && [ "$(current_role)" = "portal" ]; then
        if has_tcp && ! tcp_listening "$(tcp_port)"; then return 1; fi
        if has_udp && ! udp_listening "$(udp_port)"; then return 1; fi
    fi
    return 0
}

# 证书是否覆盖指定域名：逐个 SAN 精确比对，并支持一级通配符（*.example.com）。
# 旧版用 grep "DNS:${domain}" 做子串匹配：会把 example.com.evil.org 之类前缀相同的名字当成匹配，
# 也识别不了通配符证书。
# 统一询问 Cloudflare 凭证：先问认证方式（1=Global API Key，2=API Token 建议），
# Token 只需 Token，Global Key 才需邮箱。成功时设置 CF_AUTH_TYPE(1/2)、CF_EMAIL、CF_KEY；失败返回 1
prompt_cloudflare_creds() {
    local choice key email
    echo "  1) $(L 'Global API Key（需邮箱）')"
    echo "  2) $(L 'API Token（建议，只需 Token，需 Zone:DNS:Edit 权限）')"
    while true; do
        read -rp "$(L '选择') [$(L '1/2，默认2')]: " choice || { [ -n "$choice" ] || return 1; }
        case "${choice:-2}" in
            1) CF_AUTH_TYPE="1"; break ;;
            2) CF_AUTH_TYPE="2"; break ;;
            *) warn "$(L '无效选择')" ;;
        esac
    done
    if [ "$CF_AUTH_TYPE" = "1" ]; then
        read -rp "Cloudflare Email: " email || { [ -n "$email" ] || return 1; }
        email="$(printf '%s' "$email" | tr -d ' \r\n')"
        [ -n "$email" ] || { warn "$(L 'Cloudflare 邮箱不能为空')"; return 1; }
        CF_EMAIL="$email"
    else
        CF_EMAIL=""
    fi
    read -rsp "$(L 'Cloudflare API Token（建议）或 Global API Key（输入不回显）:') " key || { [ -n "$key" ] || return 1; }; echo
    key="$(printf '%s' "$key" | tr -d ' \r\n')"
    [ -n "$key" ] || { warn "$(L 'Cloudflare 凭证不能为空')"; return 1; }
    CF_KEY="$key"
    return 0
}

# 按 CF_AUTH_TYPE 写 /etc/cloudflare/credentials.ini（Token 只写 token，Global Key 写邮箱+key），600
write_cloudflare_creds() {
    mkdir -p /etc/cloudflare
    if [ "${CF_AUTH_TYPE:-2}" = "1" ]; then
        printf 'dns_cloudflare_email = %s\ndns_cloudflare_api_key = %s\n' "$CF_EMAIL" "$CF_KEY" > /etc/cloudflare/credentials.ini
    else
        printf 'dns_cloudflare_api_token = %s\n' "$CF_KEY" > /etc/cloudflare/credentials.ini
    fi
    chmod 600 /etc/cloudflare/credentials.ini
}

# 整文件重写 nowhere.env（与 do_install 原 heredoc 内容一致，敏感值走 dq_escape）。
# 调用前须保证各 *_VALUE 全局变量已就位（do_install 向导结束时、do_migrate_tls2 已 load_saved_config 并改好待变项）。
write_portal_env() {
    local _wpe_tmp=""
    _wpe_tmp="$(mktemp "${CONFIG_DIR}/.nowhere.env.XXXXXX")" || return 1
    cat > "$_wpe_tmp" << ENVEOF
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
CRT_RUNTIME_VALUE="${CRT_RUNTIME:-${CRT:-}}"
KEY_PEM_RUNTIME_VALUE="${KEY_PEM_RUNTIME:-${KEY_PEM:-}}"
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
HANDSHAKE_TIMEOUT_VALUE="${HANDSHAKE_TIMEOUT}"
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
    chmod 600 "$_wpe_tmp" || { rm -f "$_wpe_tmp"; return 1; }
    mv -f "$_wpe_tmp" "$CONFIG_FILE" || { rm -f "$_wpe_tmp"; return 1; }
    chmod 600 "$CONFIG_FILE"
}

# ensure_system_user name [group]：建组+建用户（--system, nologin, no-create-home）；已存在返回 0；失败返回 1
ensure_system_user() {
    local name="$1" grp="${2:-$1}"
    getent group "$grp" >/dev/null 2>&1 || groupadd --system "$grp" 2>/dev/null || return 1
    if ! id "$name" >/dev/null 2>&1; then
        useradd --system --gid "$grp" --no-create-home --shell /usr/sbin/nologin "$name" 2>/dev/null || return 1
    fi
    return 0
}

# 为 Portal 创建专用低权用户 nowhere（新装/重配时）。任一步失败回退 root，不中断安装。
# 成功时设置 NOWHERE_USER="nowhere"；失败时 NOWHERE_USER="root"
setup_nowhere_user() {
    NOWHERE_USER="root"
    command -v useradd >/dev/null 2>&1 || return 0
    if ! ensure_system_user nowhere; then warn "$(L '创建专用低权用户失败，继续以 root 运行')"; return 0; fi
    install -d -m 700 -o nowhere -g nowhere "$CONFIG_DIR" 2>/dev/null || { warn "$(L '创建专用低权用户失败，继续以 root 运行')"; return 0; }
    NOWHERE_USER="nowhere"
    return 0
}

# tls=2 时把源证书复制到 CONFIG_DIR/certs 供低权用户读取（User=nowhere 读不到 /etc/letsencrypt 的私钥）。
# 保持 CRT/KEY_PEM 为原始源路径不变，将副本路径写入 CRT_RUNTIME/KEY_PEM_RUNTIME（供 Portal URL 使用）。
sync_portal_cert_copy() {
    CRT_RUNTIME="${CRT:-}"
    KEY_PEM_RUNTIME="${KEY_PEM:-}"
    [ "${TLS_MODE:-}" = "2" ] || return 0
    [ -f "$CRT" ] && [ -f "$KEY_PEM" ] || return 1
    local dest="${CONFIG_DIR}/certs"
    install -d -m 700 -o nowhere -g nowhere "$dest" 2>/dev/null || return 1
    if [ "$CRT" != "$dest/fullchain.pem" ]; then
        install -m 600 -o nowhere -g nowhere "$CRT" "$dest/fullchain.pem" 2>/dev/null || return 1
    fi
    if [ "$KEY_PEM" != "$dest/privkey.pem" ]; then
        install -m 600 -o nowhere -g nowhere "$KEY_PEM" "$dest/privkey.pem" 2>/dev/null || return 1
    fi
    CRT_RUNTIME="$dest/fullchain.pem"
    KEY_PEM_RUNTIME="$dest/privkey.pem"
    return 0
}

cert_covers_domain() {
    local crt="$1" domain="${2,,}" sans name wild
    sans="$(openssl x509 -in "$crt" -noout -ext subjectAltName 2>/dev/null | tr ',' '\n' | sed -n 's/^[[:space:]]*DNS://p' || true)"
    wild="*.${domain#*.}"
    while IFS= read -r name; do
        [ -n "$name" ] || continue
        name="${name,,}"
        if [ "$name" = "$domain" ] || [ "$name" = "$wild" ]; then return 0; fi
    done <<< "$sans"
    return 1
}

# cert_key_matches crt key：证书与私钥是否匹配（公钥比对）
cert_key_matches() {
    local crt="$1" key="$2"
    openssl x509 -in "$crt" -noout -pubkey 2>/dev/null | \
        cmp -s - <(openssl pkey -in "$key" -pubout 2>/dev/null)
}

# cert_covers crt domain [days]：证书覆盖域名（SAN）且剩余有效期 > days 天（默认 0）
cert_covers() {
    local crt="$1" domain="$2" days="${3:-0}"
    openssl x509 -in "$crt" -noout -checkend "$(( days * 86400 ))" >/dev/null 2>&1 || return 1
    cert_covers_domain "$crt" "$domain"
}

# 证书有效性：文件存在、私钥匹配、SAN/CN 含域名、剩余有效期 > 30 天
cert_is_valid() {
    local domain="$1" crt="$2" key="$3"
    [ -n "$domain" ] && [ -f "$crt" ] && [ -f "$key" ] || return 1
    cert_key_matches "$crt" "$key" || return 1
    cert_covers "$crt" "$domain" 30 && return 0
    # CN 兜底保留在 cert_is_valid 里：SAN 未覆盖时，CN 等于域名且剩余 >30 天仍算有效
    openssl x509 -in "$crt" -noout -checkend 2592000 >/dev/null 2>&1 || return 1
    local cn
    cn="$(openssl x509 -in "$crt" -noout -subject 2>/dev/null | sed -n 's/.*CN *= *\([^,\/]*\).*/\1/p' || true)"
    [ "${cn,,}" = "${domain,,}" ] && return 0
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
    [ -f "$crt" ] && [ -f "$key" ] || { warn "$(L '证书文件未生成：')${crt}"; return 1; }
    openssl x509 -in "$crt" -noout -checkend 0 >/dev/null 2>&1 || { warn "$(L '证书已过期或无法解析')"; return 1; }
    if ! cert_key_matches "$crt" "$key"; then
        warn "$(L '证书与私钥不匹配')"
        return 1
    fi
    if ! cert_covers "$crt" "$domain" 0; then
        warn "$(L '证书 SAN 中不包含域名') ${domain}$(L '（可能签发了错误的域名）')"
        openssl x509 -in "$crt" -noout -ext subjectAltName 2>/dev/null || true
        return 1
    fi
    days="$(cert_expiry_days "$crt" || echo "?")"
    success "$(L '证书校验通过：')${domain}$(L '，剩余有效期约') ${days} $(L '天')"
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
        warn "$(L '域名') ${domain} $(L '当前解析不到任何 A 记录（DNS 未生效或拼写错误），HTTP-01 很可能失败')"
        return 1
    fi
    if [ -n "$myip" ] && [ "$resolved" != "$myip" ]; then
        warn "$(L '域名') ${domain} $(L '解析到') ${resolved}$(L '，但本机公网 IP 疑似') ${myip}$(L '：两者不一致时 HTTP-01 会失败')"
        warn "$(L '若刚修改 DNS，请确认已传播：dig +short') ${domain}$(L '（或等待 10-30 分钟后重试）')"
        return 1
    fi
    success "$(L 'DNS 预检通过：')${domain} -> ${resolved}"
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
    [ -f "$tarball" ] || { warn "$(L '校验时找不到已下载的安装包')"; return 1; }
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
            success "$(L 'SHA256 校验通过（GitHub 官方资产 digest）')"
            return 0
        fi
        warn "$(L 'SHA256 校验失败：官方 digest=')${digest}$(L '，本地实算=')${actual}$(L '，安装包可能被篡改或下载损坏')"
        return 1
    fi

    local sumfile url expected
    for sumfile in "SHA256SUMS" "sha256sums.txt" "checksums.txt"; do
        url="https://github.com/${REPO}/releases/download/${tag}/${sumfile}"
        curl -fsSL --max-time 15 -o "${workdir}/${sumfile}" "$url" 2>/dev/null || continue
        expected="$(grep "${BIN_NAME}" "${workdir}/${sumfile}" 2>/dev/null | head -1 | awk '{print $1}' || true)"
        [ -n "$expected" ] || continue
        if [ "$expected" = "$actual" ]; then
            success "$(L 'SHA256 校验通过（')${sumfile}$(L '）')"
            return 0
        fi
        warn "$(L 'SHA256 校验失败（')${sumfile}$(L '）：期望') ${expected}$(L '，实算') ${actual}"
        return 1
    done
    echo -e "${RED}$(L '警告：SHA256 校验已被跳过，安装包未经校验')${NC}" >&2
    warn "$(L '无法取得官方校验值（API digest 与校验文件均不可用），跳过校验（本次经 HTTPS 直连 GitHub 下载）')"
    return 0
}

# certbot 续期 cron 兜底（Nowhere 与 Xray 共用）：规范为 0 3,15 * * * certbot renew --quiet，
# deploy hook 由 renewal-hooks/deploy 自动跑，不再写进 cron 行。
# 清理时：deploy hook 文件在位时可删全部 certbot renew 行（含旧 deploy-hook 行）；
# 否则只删无 deploy-hook 的 plain 行，保留 Portal 的 deploy-hook cron 行（v10 保护，不回归）。
certbot_renewal_cron_ensure() {
    if [ -x /etc/letsencrypt/renewal-hooks/deploy/restart-nowhere.sh ]; then
        (crontab -l 2>/dev/null | grep -v 'certbot renew' || true; echo '0 3,15 * * * certbot renew --quiet') | crontab -
    else
        (crontab -l 2>/dev/null | grep -v 'certbot renew --quiet$' || true; echo '0 3,15 * * * certbot renew --quiet') | crontab -
    fi
}

# obtain_portal_cert：cert_is_valid 复用检查 → 按 CERT_METHOD 分派签发 → 统一 verify_issued_cert + 续期注册
# 调用前须设好 DOMAIN/EMAIL/CERT_METHOD/CRT/KEY_PEM（DNS-01 通用还需 DNS_API）；失败时 error 退出
obtain_portal_cert() {
    if [ "$CERT_METHOD" = "letsencrypt-dns" ]; then
        info "$(L '安装 acme.sh...')"
        if ! curl -fsSL --max-time 60 https://get.acme.sh | bash -s email="${EMAIL}"; then
            error "$(L 'acme.sh 安装失败，请检查网络后重试')"
        fi
        [ -x "${ACME_HOME}/acme.sh" ] || error "$(L 'acme.sh 安装后仍找不到可执行文件（')${ACME_HOME}$(L '/acme.sh）')"
        . "${ACME_HOME}/acme.sh.env" 2>/dev/null || true
    fi
    if [ "$CERT_METHOD" = "cloudflare-dns" ]; then
        write_cloudflare_creds
    fi
    if cert_is_valid "$DOMAIN" "$CRT" "$KEY_PEM"; then
        info "$(L '检测到有效证书（剩余') $(cert_expiry_days "$CRT") $(L '天，域名匹配），跳过申请')"
    elif [ "$CERT_METHOD" = "letsencrypt-http" ]; then
        if has_tcp && [ "$(tcp_port)" = "80" ]; then
            warn "$(L 'HTTP-01 与 80 端口监听冲突：续期时 certbot 需独占 80 端口，服务将无法同时监听 80')"
        fi
        if tcp_listening 80; then
            warn "$(L '80 端口已被其他进程占用，HTTP-01 签发前请先停掉该服务或改用 DNS-01')"
            systemctl stop nowhere 2>/dev/null || true
            if tcp_listening 80; then error "$(L '80 端口仍被占用，证书签发已中止')"; fi
        fi
        info "$(L '申请证书中（HTTP-01，需 80 端口）...')"
        ufw allow 80/tcp 2>/dev/null || true
        certbot certonly \
            --standalone \
            --preferred-challenges http \
            --non-interactive \
            --agree-tos \
            --email "${EMAIL}" \
            -d "${DOMAIN}" \
            --http-01-port 80 --http-01-address 0.0.0.0 || {
            error "$(L '证书申请失败，请检查：1')) $(L '域名是否正确 2')) $(L '80 端口是否对外开放 3')) $(L '域名是否已指向本 VPS（见上方 DNS 预检结果）')"
        }
        verify_issued_cert "$DOMAIN" "$CRT" "$KEY_PEM" || error "$(L '证书签发后校验未通过，请看上方告警')"
        success "$(L '证书申请成功')"
    elif [ "$CERT_METHOD" = "cloudflare-dns" ]; then
        info "$(L '申请证书中（Cloudflare DNS-01，约需 30-60 秒）...')"
        certbot certonly \
            --dns-cloudflare \
            --dns-cloudflare-credentials /etc/cloudflare/credentials.ini \
            --non-interactive \
            --agree-tos \
            --email "${EMAIL}" \
            -d "${DOMAIN}" \
            --dns-cloudflare-propagation-seconds 30 || {
            error "$(L '证书申请失败，请检查：1')) $(L 'CF API Key/Token 是否正确 2')) $(L '域名是否在该 CF 账号下 3')) $(L 'Token 是否有 Zone:DNS:Edit 权限')"
        }
        verify_issued_cert "$DOMAIN" "$CRT" "$KEY_PEM" || error "$(L '证书签发后校验未通过，请看上方告警')"
        success "$(L '证书申请成功')"
    elif [ "$CERT_METHOD" = "letsencrypt-dns" ]; then
        info "$(L '申请证书中（DNS-01:') ${DNS_API}$(L '；不加 --force，避免重复签发触发 LE 频率限制）...')"
        # acme.sh 的默认 CA 是 ZeroSSL；菜单写的是 Let's Encrypt，这里显式指定以保持一致
        "${ACME_HOME}/acme.sh" --issue --server letsencrypt -d "${DOMAIN}" --dns "${DNS_API}" || {
            error "$(L '证书签发失败：请检查 DNS API 凭证是否正确、域名 DNS 是否由所选服务商托管')"
        }
        install -d -m 700 "$(dirname "$CRT")"
        install_nowhere_cert_sync_script
        "${ACME_HOME}/acme.sh" --install-cert -d "${DOMAIN}" \
            --key-file "${KEY_PEM}" \
            --fullchain-file "${CRT}" \
            --reloadcmd "${CONFIG_DIR}/cert-sync.sh" || {
            error "$(L '证书安装（install-cert）失败')"
        }
        verify_issued_cert "$DOMAIN" "$CRT" "$KEY_PEM" || error "$(L '证书签发后校验未通过，请看上方告警')"
        success "$(L '证书申请成功')"
    else
        error "$(L '未知证书方式')"
    fi
    case "$CERT_METHOD" in
        letsencrypt-dns) setup_acmesh_renewal ;;
        *) setup_certbot_renewal ;;
    esac
    return 0
}
# certbot 续期链路：deploy hook + 确保 timer 生效（缺失时 cron 兜底）+ 可选 dry-run 演练
setup_certbot_renewal() {
    mkdir -p /etc/letsencrypt/renewal-hooks/deploy
    cat > /etc/letsencrypt/renewal-hooks/deploy/restart-nowhere.sh << HOOKEOF
#!/bin/bash
# Renewal hook: re-sync the service-readable cert copies (low-priv user cannot read /etc/letsencrypt), then restart
sync_ok=1
if [ -d "${CONFIG_DIR}/certs" ] && [ -f "${CRT}" ] && [ -f "${KEY_PEM}" ] && [ "${CRT}" != "${CONFIG_DIR}/certs/fullchain.pem" ]; then
    install -m 600 -o nowhere -g nowhere "${CRT}" "${CONFIG_DIR}/certs/fullchain.pem" 2>/dev/null || sync_ok=0
    install -m 600 -o nowhere -g nowhere "${KEY_PEM}" "${CONFIG_DIR}/certs/privkey.pem" 2>/dev/null || sync_ok=0
fi
if [ "\$sync_ok" = "1" ]; then
    systemctl restart nowhere
else
    echo "nowhere cert copy failed, skip restart to avoid starting with a bad cert" >&2
    logger -t nowhere-renewal "cert copy failed, skipped nowhere restart" 2>/dev/null || true
fi
HOOKEOF
    chmod +x /etc/letsencrypt/renewal-hooks/deploy/restart-nowhere.sh
    # pre/post hook：仅 HTTP-01 且 nowhere 实际占用 80 端口时才停机，避免 DNS-01 或 443 端口场景无故断流
    if [ "$CERT_METHOD" = "letsencrypt-http" ]; then
        mkdir -p /etc/letsencrypt/renewal-hooks/pre /etc/letsencrypt/renewal-hooks/post
        cat > /etc/letsencrypt/renewal-hooks/pre/stop-nowhere.sh << 'HOOKEOF'
#!/bin/bash
if ss -tlnp 2>/dev/null | awk 'NR>1 && /"nowhere"/{n=split($4,a,":"); if(a[n]=="80") f=1} END{exit !f}'; then
    systemctl stop nowhere 2>/dev/null && touch /run/nowhere-stopped-by-certbot
fi
HOOKEOF
        cat > /etc/letsencrypt/renewal-hooks/post/start-nowhere.sh << 'HOOKEOF'
#!/bin/bash
if [ -f /run/nowhere-stopped-by-certbot ]; then
    rm -f /run/nowhere-stopped-by-certbot
    systemctl start nowhere 2>/dev/null || true
fi
HOOKEOF
        chmod +x /etc/letsencrypt/renewal-hooks/pre/stop-nowhere.sh /etc/letsencrypt/renewal-hooks/post/start-nowhere.sh
    else
        rm -f /etc/letsencrypt/renewal-hooks/pre/stop-nowhere.sh /etc/letsencrypt/renewal-hooks/post/start-nowhere.sh /run/nowhere-stopped-by-certbot
    fi
    info "$(L '已安装续期 hook：证书更新后自动 restart nowhere')"

    if systemctl list-unit-files 2>/dev/null | grep -q '^certbot\.timer'; then
        systemctl enable --now certbot.timer 2>/dev/null || warn "$(L 'certbot.timer 启用失败，请手动执行：systemctl enable --now certbot.timer')"
        if systemctl is-active --quiet certbot.timer 2>/dev/null; then
            success "$(L '自动续期已就绪：certbot.timer 运行中（每天两次检查续期）')"
        else
            warn "$(L 'certbot.timer 未在运行，自动续期可能不工作，请手动检查')"
        fi
    else
        warn "$(L '未找到 certbot.timer，改用 cron 兜底（每天 3:00 / 15:00 检查续期）')"
        certbot_renewal_cron_ensure
        success "$(L 'cron 续期任务已写入')"
    fi

    echo ""
    read -rp "$(L '是否立即做一次续期演练（certbot renew --dry-run，不消耗 LE 配额）？')[Y/n]: " DRYRUN || { [ -n "$DRYRUN" ] || return 1; }
    if [[ ! "${DRYRUN:-y}" =~ ^[Nn]$ ]]; then
        info "$(L '演练中（约需 30-90 秒）...')"
        if certbot renew --dry-run 2>&1 | tail -5; then
            success "$(L '续期演练通过，自动续期链路可信')"
        else
            warn "$(L '续期演练未通过：请根据上方报错排查（如 80 端口被占、DNS 凭证失效），否则证书到期后服务会中断')"
        fi
    else
        warn "$(L '已跳过演练：建议 90 天内用Nowhere 菜单「11')) $(L '检查证书状态 / 手动续期」验证一次')"
    fi
}

# acme.sh 续期链路：确认其自带的 cron 定时任务已就绪
setup_acmesh_renewal() {
    if crontab -l 2>/dev/null | grep -q 'acme.sh.*--cron'; then
        success "$(L '自动续期已就绪：acme.sh 的 cron 定时任务存在（每天检查，到期自动续签并执行 --reloadcmd 重启 nowhere）')"
    else
        warn "$(L '未在 root 的 crontab 中找到 acme.sh 定时任务，自动续期可能不工作')"
        warn "$(L '可手动补加：')(crontab -l 2>/dev/null; echo '0 0 * * * \"${ACME_HOME}/acme.sh\" --cron --home \"${ACME_HOME}\"') | crontab -"
    fi
    info "$(L '当前该域名的证书状态：')"
    "${ACME_HOME}/acme.sh" --list 2>/dev/null | grep -E "Main_Domain|${DOMAIN}" || true
}

# 主菜单时间 + 公网 IP：同一进程内只探测一次，避免每次刷新菜单都等网络
# （直接调用、不包在 $() 里，否则赋值落在子 shell、缓存不生效）
menu_time_ip() {
    if [ -z "${_MENU_PUBLIC_IP_DONE:-}" ]; then
        _MENU_PUBLIC_IP="$(detect_public_host)"
        _MENU_PUBLIC_IP_DONE=1
    fi
    echo -e "  $(L '时间'): $(date '+%Y-%m-%d %H:%M:%S')  IP: ${_MENU_PUBLIC_IP:-$(L '未知')}"
}

menu_status_summary() {
    echo -e "  Nowhere : $(nowhere_state_text)"
    echo -e "  Snell   : $(snell_state_text)"
    echo -e "  Xray    : $(xray_state_text)"
    echo -e "  Realm   : $(realm_state_text)"
    echo -e "  $(L '反代')    : $(proxy_state_text)"
    echo -e "  $(L '防火墙')  : $(fw_state_text)      Fail2ban : $(f2b_state_text)      $(L '保活巡检') : $(maint_timer_state adam-watchdog.timer)"
}

show_menu() {
    clear 2>/dev/null || true
    echo -e "${BOLD}${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║         Adam Nowhere Portal $(L '一键管理脚本')                     ║"
    echo "║  Nowhere ${TARGET_NW_VERSION} · Snell v${SNELL_MAJOR} · Xray · Realm · $(L '反代') · $(L '调优') ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    menu_time_ip
    menu_status_summary
    divider
    echo -e "  ${BOLD}── $(L '协议安装') ──${NC}"
    echo -e "  ${BOLD}1)${NC} $(L 'Nowhere（Portal / Egress：')$(L '安装、配置、连接信息、证书、版本')$(L '）')"
    echo -e "  ${BOLD}2)${NC} Snell v${SNELL_MAJOR}$(L '（')$(L '安装、跟随测试版更新、健康检查、配置')$(L '）')"
    echo -e "  ${BOLD}3)${NC} $(L 'Xray（SS2022 / VLESS：REALITY Vision、XHTTP REALITY、XHTTP CDN、VLESS Encryption）')"
    echo -e "  ${BOLD}── $(L '系统管理') ──${NC}"
    echo -e "  ${BOLD}4)${NC} $(L '脚本更新')$(L '（')$(L '更新本管理脚本 / 重装快捷命令')$(L '）')"
    echo -e "  ${BOLD}5)${NC} $(L '防火墙')$(L '（')$(L 'ufw：安装、放行与删除端口、启停')$(L '）')"
    echo -e "  ${BOLD}6)${NC} $(L 'Fail2ban（')$(L '封禁时长、被封 IP、启停')$(L '）')"
    echo -e "  ${BOLD}7)${NC} $(L '系统调优')$(L '（')$(L 'TCP 调优 tcpfit / XanMod 内核 / DNS / IPv4·IPv6 优先级 / 禁用 IPv6')$(L '）')"
    echo -e "  ${BOLD}8)${NC} $(L '自动维护')$(L '（')$(L '保活巡检 / 脚本与内核自动更新')$(L '）')"
    echo -e "  ${BOLD}9)${NC} Realm $(L '端口转发（TCP / UDP 转发、负载均衡、WS / TLS 隧道）')"
    echo -e "  ${BOLD}10)${NC} $(L '域名反代（Caddy 多域名自动 HTTPS / Cloudflare Tunnel）')"
    echo -e "  ${BOLD}0)${NC} $(L '退出')"
    divider
    if [ -x /usr/local/bin/adam ]; then
        echo -e "  ${YELLOW}$(L '提示：可直接输入')${NC} ${CYAN}adam${NC} ${YELLOW}$(L '唤出此菜单，或用')${NC} ${CYAN}zt${NC}/${CYAN}pz${NC}/${CYAN}cxpz${NC}/${CYAN}cq${NC} ${YELLOW}$(L '快捷执行；')${NC}${CYAN}adam help${NC} ${YELLOW}$(L '查看全部子命令')${NC}"
        divider
    fi
    read -rp "$(L '请选择操作') [0-10]: " MENU_CHOICE
}

nowhere_state_text() {
    local role ver
    role="$(current_role)"
    case "$role" in portal) role="Portal" ;; egress) role="Egress" ;; *) role="" ;; esac
    if [ -x "$BIN_PATH" ]; then
        ver="$(read_installed_version)"
        printf '%s' "${ver:-$(L '未知')}${role:+ · ${role}} · $(svc_state nowhere)"
    else
        printf '%s' "${YELLOW}$(L '未安装')${NC}"
    fi
}

nowhere_menu() {
    local choice
    while true; do
        clear 2>/dev/null || true
        echo -e "${BOLD}${CYAN}━━━ Nowhere $(L '管理')$(L '（')${TARGET_NW_VERSION} $(L '/ NW3）') ━━━${NC}"
        echo -e "  $(L '当前状态'): $(nowhere_state_text)"
        divider
        local _tls2_note=""
        if grep -q '^TLS_MODE_VALUE="2"' "$CONFIG_FILE" 2>/dev/null; then _tls2_note="$(L '（当前已是 tls=2）')"; fi
        echo -e "  ${BOLD}── $(L '安装与配置') ──${NC}"
        echo -e "  ${GREEN}1)${NC}  ${GREEN}$(L '安装')${NC} Nowhere Portal$(L '（向导）')"
        echo -e "  ${GREEN}2)${NC}  $(L '本机安装为 Egress 服务')$(L '（出口机用，QUIC 或 TLS 载体）')"
        echo -e "  ${GREEN}3)${NC}  $(L '重新配置')$(L '（修改参数）')"
        echo -e "  ${GREEN}4)${NC}  $(L '查看连接信息 / 导入链接')"
        echo -e "  ${GREEN}5)${NC}  $(L '生成 v3 共享密钥')$(L '（32 位十六进制）')"
        echo -e "  ${BOLD}── $(L '运行与排查') ──${NC}"
        echo -e "  ${GREEN}6)${NC}  $(L '查看服务状态')$(L '（含 nowhere status）')"
        echo -e "  ${GREEN}7)${NC}  $(L '查看实时日志')"
        echo -e "  ${GREEN}8)${NC}  $(L '重启服务')"
        echo -e "  ${GREEN}9)${NC}  $(L '连通性探测 probe')$(L '（真实 TCP Flow 测试）')"
        echo -e "  ${BOLD}── $(L '证书') ──${NC}"
        echo -e "  ${GREEN}10)${NC} $(L '查看证书指纹')$(L '（tls=1 自签 / tls=2 文件证书）')"
        echo -e "  ${GREEN}11)${NC} $(L '检查证书状态 / 手动续期')"
        echo -e "  ${BOLD}── $(L '版本') ──${NC}"
        echo -e "  ${GREEN}12)${NC} $(L '查看当前版本 / 检查更新')"
        echo -e "  ${GREEN}13)${NC} $(L '更新 Nowhere 二进制')$(L '（更新到最新版）')"
        echo -e "  ${GREEN}14)${NC} $(L '选择指定版本')$(L '（版本切换 / 回退到历史版本）')"
        echo -e "  ${GREEN}15)${NC} $(L '快速回退到上一个版本')"
        echo -e "  ${BOLD}──${NC}"
        echo -e "  ${GREEN}16)${NC} ${RED}$(L '卸载')${NC} Nowhere"
        maint_load
        echo -e "  ${GREEN}17)${NC} $(L 'tls=1 升级为真实证书 (tls=2)')${_tls2_note}"
        echo -e "  ${GREEN}18)${NC} $(L 'Nowhere 自动更新（仅 NW3 同代安全更新）') [$(maint_onoff "${MAINT_NOWHERE_AUTO:-0}")]"
        echo -e "  ${GREEN}0)${NC}  $(L '返回主菜单')"
        divider
        read -rp "$(L '请选择') [0-18]: " choice
        case "$choice" in
            1)  run_action do_install ;;
            2)  run_action do_install_egress_service ;;
            3)  run_action do_reconfig ;;
            4)  run_action do_show_config ;;
            5)  run_action do_genkey ;;
            6)  run_action do_show_status ;;
            7)  run_action do_show_logs ;;
            8)  run_action do_restart ;;
            9)  run_action do_probe ;;
            10) run_action do_fingerprint ;;
            11) run_action do_cert_status ;;
            12) run_action do_show_version ;;
            13) run_action do_update ;;
            14) run_action do_select_version ;;
            15) run_action do_rollback ;;
            16) run_action do_uninstall ;;
            17) run_action do_migrate_tls2 ;;
            18) run_action maint_toggle MAINT_NOWHERE_AUTO ;;
            0)  return 0 ;;
            *)  warn "$(L '无效选择')" ;;
        esac
        pause_return
    done
}

script_menu() {
    local choice
    while true; do
        clear 2>/dev/null || true
        maint_load
        echo -e "${BOLD}${CYAN}━━━ $(L '脚本更新') ━━━${NC}"
        echo -e "  $(L '当前版本'): ${SCRIPT_VERSION}    $(L '每日自动从仓库更新'): $(maint_onoff "$MAINT_SCRIPT_AUTO")"
        divider
        echo -e "  ${GREEN}1)${NC} $(L '立即更新本管理脚本')$(L '（从仓库拉取）')"
        echo -e "  ${GREEN}2)${NC} $(L '每日自动从仓库更新') $(L '开') / $(L '关')"
        echo -e "  ${GREEN}3)${NC} $(L '重装快捷命令')$(L '（adam / zt / pz / cxpz / cq）')"
        echo -e "  ${GREEN}4)${NC} $(L '语言（中文 / English）')"
        echo -e "  ${GREEN}0)${NC} $(L '返回主菜单')"
        divider
        read -rp "$(L '请选择') [0-4]: " choice
        case "$choice" in
            1) run_action do_update_script ;;
            2) run_action maint_toggle MAINT_SCRIPT_AUTO ;;
            3) run_action install_shortcuts ;;
            4) run_action set_lang_menu ;;
            0) return 0 ;;
            *) warn "$(L '无效选择')" ;;
        esac
        pause_return
    done
}

# 精确检测端口是否被其他进程占用：只比对 ss 第 4 列（本地地址）最后一个冒号后的端口号，
# 不用 grep ":端口\b"（会误命中 IPv6 地址段里的十六进制段）
# check_port_occupied_by_other PROTO PORT [EXCLUDE_PROC，默认 nowhere]
check_port_occupied_by_other() {
    local proto="$1" port="$2" own="${3:-nowhere}" flag="-tlnp"
    command -v ss >/dev/null 2>&1 || return 0
    [ "$proto" = "udp" ] && flag="-ulnp"
    ss "$flag" 2>/dev/null | awk -v p="$port" -v own="\""own"\"" '
        NR == 1 { next }
        own != "\"__none__\"" && index($0, own) > 0 { next }
        {
            n = split($4, a, ":")
            if (a[n] == p) print $0
        }'
}

do_install() {
    maint_lock_manual || return
    local OLD_NW_PORTS=""
    OLD_NW_PORTS="$(nowhere_ports 2>/dev/null || true)"
    if [ "$(current_role)" = "egress" ]; then
        warn "$(L '本机当前是 Egress 角色：继续安装会把 nowhere.service 换成 Portal')"
        read -rp "$(L '确认继续') [y/N]: " ROLE_CONFIRM || { [ -n "$ROLE_CONFIRM" ] || return 1; }
        [[ ! "$ROLE_CONFIRM" =~ ^[Yy]$ ]] && { info "$(L '已取消')"; return; }
    fi
    ensure_prereqs

    step "$(L '第 0 步：选择语言')"
    divider
    echo "  1) 中文 (zh)"
    echo "  2) English (en)"
    read -rp "$(L '选择') [1/2, $(L '默认') ${ADAM_LANG}]: " _inst_lang || { [ -n "$_inst_lang" ] || return 1; }
    case "$_inst_lang" in 2) set_lang en ;; 1) set_lang zh ;; *) : ;; esac

    step "$(L '第 1 步：选择证书获取方式')"
    divider
    echo -e "${BOLD}$(L 'TLS 证书方式：')${NC}"
    echo "  1) $(L '自签证书 tls=1  - 无需域名，快速测试（Vector/Egress 必须用 pin= 锁定指纹，指纹随重启变化）')"
    echo "  2) Let'$(L 's Encrypt HTTP-01 - 需要开放 80 端口（自动续期）')"
    echo "  3) Let'$(L 's Encrypt DNS-01 通用 - 支持多种 DNS 服务商（自动续期）')"
    echo "  4) $(L 'Cloudflare DNS-01 - 需要 CF API Key（自动续期，推荐）')"
    while true; do
        read -rp "$(L '请选择') [$(L '1/2/3/4，默认4')]: " CERT_CHOICE || { [ -n "$CERT_CHOICE" ] || return 1; }
        CERT_CHOICE=${CERT_CHOICE:-4}
        case $CERT_CHOICE in
            1) TLS_MODE=1; CERT_METHOD="self-signed" ; break ;;
            2) TLS_MODE=2; CERT_METHOD="letsencrypt-http" ; break ;;
            3) TLS_MODE=2; CERT_METHOD="letsencrypt-dns" ; break ;;
            4) TLS_MODE=2; CERT_METHOD="cloudflare-dns" ; break ;;
            *) warn "$(L '无效选择')" ;;
        esac
    done

    if [ "$TLS_MODE" = "1" ]; then
        warn "$(L '提醒（v3 官方说明）：Vector/Egress 默认校验系统 CA + 主机名，自签证书必须改用 pin= 指纹锁定')"
        warn "$(L '自签证书仅建议测试用，生产环境请用真实域名 + CA 签发证书（选 2/3/4）')"
    fi

    step "$(L '第 2 步：基础网络信息')"
    divider

    if [ "$TLS_MODE" = "2" ]; then
        while true; do
            read -rp "$(L '请输入域名（如: nhk.example.com）:') " DOMAIN || { [ -n "$DOMAIN" ] || return 1; }
            DOMAIN=$(echo "$DOMAIN" | tr -d ' \r\n')
            DOMAIN="${DOMAIN,,}"
            [[ -z "$DOMAIN" ]] && { echo -e "${RED}$(L '域名不能为空')${NC}"; continue; }
            [[ "$DOMAIN" != *.* ]] && { echo -e "${RED}$(L '域名格式不正确')${NC}"; continue; }
            [[ ! "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] && { echo -e "${RED}$(L '域名只能包含字母、数字、点和连字符')${NC}"; continue; }
            break
        done
        PUBLIC_HOST="$DOMAIN"
    else
        info "$(L '自签模式无需域名，将自动探测公网 IP 作为客户端连接地址')"
        DETECTED_IP="$(detect_public_host)"
        while true; do
            read -rp "$(L '公网 IP/域名（用于 Anywhere/Vector/Egress 连接，回车使用探测值') ${DETECTED_IP:-$(L '未探测到，请手动输入')}$(L '）:') " PUBLIC_HOST || { [ -n "$PUBLIC_HOST" ] || return 1; }
            PUBLIC_HOST=${PUBLIC_HOST:-$DETECTED_IP}
            PUBLIC_HOST=$(echo "$PUBLIC_HOST" | tr -d ' \r\n')
            is_safe_host "$PUBLIC_HOST" && break
            echo -e "${RED}$(L '地址不能为空，且只能包含字母、数字和 . : - _') [ ]${NC}"
        done
        DOMAIN="$PUBLIC_HOST"
        DOMAIN="${DOMAIN,,}"; PUBLIC_HOST="${PUBLIC_HOST,,}"
    fi

    # 邮箱只用于 ACME 账户：自签模式不申请证书，不再强制填写
    EMAIL=""
    if [ "$TLS_MODE" = "2" ]; then
        while true; do
            read -rp "$(L '请输入邮箱（用于证书申请/找回）:') " EMAIL || { [ -n "$EMAIL" ] || return 1; }
            EMAIL=$(echo "$EMAIL" | tr -d ' \r\n')
            [[ ! "$EMAIL" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] && { echo -e "${RED}$(L '邮箱格式不正确')${NC}"; continue; }
            break
        done
    fi

    if [ "$CERT_METHOD" = "cloudflare-dns" ]; then
        prompt_cloudflare_creds || error "$(L 'Cloudflare 凭证未提供，已中止')"
    elif [ "$CERT_METHOD" = "letsencrypt-dns" ]; then
        echo ""
        echo -e "${BOLD}$(L 'DNS 服务商：')${NC}"
        echo "  1) Cloudflare  2) DNSPod  3) $(L '阿里云  4')) $(L '其他/手动')"
        read -rp "$(L '选择') [$(L '1-4，默认1')]: " DNS_PROVIDER || { [ -n "$DNS_PROVIDER" ] || return 1; }
        DNS_PROVIDER=${DNS_PROVIDER:-1}
        case $DNS_PROVIDER in
            1) read -rp "Cloudflare Email: " CF_EMAIL || { [ -n "$CF_EMAIL" ] || return 1; }
               read -rsp "$(L 'Cloudflare API Key（输入不回显）:') " CF_KEY || { [ -n "$CF_KEY" ] || return 1; }; echo
               export CF_Email="${CF_EMAIL}" CF_Key="${CF_KEY}"
               DNS_API="dns_cf" ;;
            2) read -rp "DNSPod ID: " DNSPOD_ID || { [ -n "$DNSPOD_ID" ] || return 1; }
               read -rsp "$(L 'DNSPod Token（输入不回显）:') " DNSPOD_TOKEN || { [ -n "$DNSPOD_TOKEN" ] || return 1; }; echo
               export DP_Id="${DNSPOD_ID}" DP_Key="${DNSPOD_TOKEN}"
               DNS_API="dns_dp" ;;
            3) read -rp "$(L '阿里云 AccessKey ID:') " ALI_ID || { [ -n "$ALI_ID" ] || return 1; }
               read -rsp "$(L '阿里云 AccessKey Secret（输入不回显）:') " ALI_SECRET || { [ -n "$ALI_SECRET" ] || return 1; }; echo
               export Ali_Key="${ALI_ID}" Ali_Secret="${ALI_SECRET}"
               DNS_API="dns_ali" ;;
            *) warn "$(L '「其他/手动」需要交互式完成 DNS TXT 验证，本脚本暂不接管，请改选 1-3')"; DNS_API="unsupported" ;;
        esac
        # DNSPod/阿里云凭证判空：空凭证时不进 acme.sh，改为 unsupported 走手动分支
        if [ "${DNS_API:-}" = "dns_dp" ] && { [ -z "${DNSPOD_ID:-}" ] || [ -z "${DNSPOD_TOKEN:-}" ]; }; then warn "$(L 'DNSPod 凭证不能为空')"; DNS_API="unsupported"; fi
        if [ "${DNS_API:-}" = "dns_ali" ] && { [ -z "${ALI_ID:-}" ] || [ -z "${ALI_SECRET:-}" ]; }; then warn "$(L '阿里云凭证不能为空')"; DNS_API="unsupported"; fi
        if [ "${DNS_API:-}" = "unsupported" ]; then
            error "$(L '您之前选择了「其他/手动」DNS 服务商：需先手动完成 DNS TXT 验证签发证书，本脚本无法一键接管。请重新运行并改选 Cloudflare（推荐）/ DNSPod / 阿里云')"
        fi
    fi

    step "$(L '第 3 步：监听参数')"
    divider
    echo -e "${BOLD}$(L '端口模式（v3 端点路径语法）：')${NC}"
    echo "  1) $(L 'TLS 与 QUIC 共用同一端口，如') *$(L ':443（推荐）')"
    echo "  2) $(L 'TLS 与 QUIC 分开端口，如') */tcp:2000/udp:2001"
    read -rp "$(L '选择') [$(L '1/2，默认1')]: " PORT_MODE_CHOICE || { [ -n "$PORT_MODE_CHOICE" ] || return 1; }
    case ${PORT_MODE_CHOICE:-1} in
        2) PORT_MODE="split" ;;
        *) PORT_MODE="same" ;;
    esac

    if [ "$PORT_MODE" = "split" ]; then
        NET="mix"
        read -rp "$(L 'TLS/TCP 端口（回车默认2000）:') " TCP_PORT || { [ -n "$TCP_PORT" ] || return 1; }
        TCP_PORT=${TCP_PORT:-2000}
        validate_port "$TCP_PORT" || { warn "$(L '端口不合法，重置为2000')"; TCP_PORT=2000; }
        read -rp "$(L 'QUIC/UDP 端口（回车默认2001）:') " UDP_PORT || { [ -n "$UDP_PORT" ] || return 1; }
        UDP_PORT=${UDP_PORT:-2001}
        validate_port "$UDP_PORT" || { warn "$(L '端口不合法，重置为2001')"; UDP_PORT=2001; }
        if [ "$TCP_PORT" = "$UDP_PORT" ]; then
            UDP_PORT="$(pick_udp_port_avoiding "$TCP_PORT" || echo 2001)"
            warn "$(L '分端口模式下 TCP 与 UDP 端口不能相同，已将 UDP 端口改为') ${UDP_PORT}"
        fi
        PORT="$TCP_PORT"
    else
        read -rp "$(L '监听端口（回车默认443）:') " PORT || { [ -n "$PORT" ] || return 1; }
        PORT=${PORT:-443}
        validate_port "$PORT" || { warn "$(L '端口不合法，重置为443')"; PORT=443; }
        TCP_PORT="$PORT"
        UDP_PORT="$PORT"

        echo ""
        echo -e "${BOLD}$(L '传输模式（决定端点路径，TCP 与 UDP 都能承载 TCP/UDP 业务流）：')${NC}"
        echo "  1) $(L 'mix - TLS/TCP + QUIC/UDP 双栈（HOST:PORT，推荐）')"
        echo "  2) $(L 'tcp - 仅 TLS/TCP（HOST/tcp:PORT）')"
        echo "  3) $(L 'udp - 仅 QUIC/UDP（HOST/udp:PORT）')"
        read -rp "$(L '选择') [$(L '1/2/3，默认1')]: " NET_CHOICE || { [ -n "$NET_CHOICE" ] || return 1; }
        case ${NET_CHOICE:-1} in
            1) NET="mix" ;; 2) NET="tcp" ;; 3) NET="udp" ;; *) NET="mix" ;;
        esac
    fi

    TCP_FAMILY=""; UDP_FAMILY=""
    read -rp "$(L '是否限制监听地址族？（默认不限；IPv6 未真正开通的 VPS 可选仅 IPv4）')[y/N]: " FAM_CHOICE || { [ -n "$FAM_CHOICE" ] || return 1; }
    if [[ "$FAM_CHOICE" =~ ^[Yy]$ ]]; then
        if has_tcp; then
            read -rp "  $(L 'TCP 地址族') [$(L '4=仅IPv4 / 6=仅IPv6 / 回车=不限')]: " TCP_FAMILY_IN || { [ -n "$TCP_FAMILY_IN" ] || return 1; }
            case "$TCP_FAMILY_IN" in 4) TCP_FAMILY="4" ;; 6) TCP_FAMILY="6" ;; *) TCP_FAMILY="" ;; esac
        fi
        if has_udp; then
            read -rp "  $(L 'UDP 地址族') [$(L '4=仅IPv4 / 6=仅IPv6 / 回车=不限')]: " UDP_FAMILY_IN || { [ -n "$UDP_FAMILY_IN" ] || return 1; }
            case "$UDP_FAMILY_IN" in 4) UDP_FAMILY="4" ;; 6) UDP_FAMILY="6" ;; *) UDP_FAMILY="" ;; esac
        fi
    fi

    read -rp "$(L '监听地址（回车=') * $(L '通配，全监听；也可填具体 IP）:') " LISTEN_HOST || { [ -n "$LISTEN_HOST" ] || return 1; }
    LISTEN_HOST=${LISTEN_HOST:-}
    LISTEN_HOST=$(echo "$LISTEN_HOST" | tr -d ' \r\n')
    if [[ -n "$LISTEN_HOST" && "$LISTEN_HOST" != "*" ]] && ! is_safe_host "$LISTEN_HOST"; then
        warn "$(L '监听地址格式不合法，已改为') * $(L '通配')"
        LISTEN_HOST=""
    fi

    step "$(L '第 4 步：协议与安全参数')"
    divider

    # v3 密钥必须是恰好 32 位小写十六进制，旧任意字符串密钥会被直接拒绝
    while true; do
        read -rsp "$(L '共享密钥 Shared Key（输入不回显，回车自动生成 32 位十六进制）:') " SHARED_KEY || { [ -n "$SHARED_KEY" ] || return 1; }; echo
        if [ -z "$SHARED_KEY" ]; then
            SHARED_KEY="$(gen_key)"
            info "$(L '已生成密钥:') ${SHARED_KEY}"
            break
        fi
        if is_valid_key "$SHARED_KEY"; then
            break
        fi
        warn "$(L '该密钥不符合 v3 规范：必须是恰好 32 位小写十六进制字符（0-9a-f）')"
        warn "$(L '旧版任意字符串/Base64 密钥在 v3 会被拒绝启动，请重新输入或直接回车自动生成')"
    done

    echo ""
    echo -e "${BOLD}$(L 'Morph 流量乱形')${NC}$(L '（')${YELLOW}$(L 'v3 默认开启 morph=1；仅做流量形态混淆，不提供额外加密；两端必须一致，没有协商/回退')${NC}$(L '）：')"
    read -rp "$(L '是否开启') [Y/n]: " MORPH_CHOICE || { [ -n "$MORPH_CHOICE" ] || return 1; }
    if [[ "$MORPH_CHOICE" =~ ^[Nn]$ ]]; then MORPH="0"; else MORPH="$DEFAULT_MORPH"; fi

    MORPH_TCP_PRELUDE="fade"; MORPH_UDP_PRELUDE="fade"
    if [ "$MORPH" = "1" ]; then
        echo ""
        echo -e "${BOLD}$(L 'Morph Prelude 策略')${NC}$(L '（')${YELLOW}$(L 'NOW_MORPH_TCP_PRELUDE / NOW_MORPH_UDP_PRELUDE，后者为 v3.3.0 新增。只对发起端（Vector / Egress）生效，Portal 自身不使用；这里的选择会写进下方生成的 Vector / Egress 启动命令。接收端三种通吃、两端无需一致、不进分享链接')${NC}$(L '）：')"
        echo "  1) fade  - ASCII→$(L '低7位')→$(L '全8位渐变（默认，推荐）')"
        echo "  2) $(L 'full8 - 全程全 8 位随机')"
        echo "  3) $(L 'low7  - 全程低 7 位随机')"
        read -rp "$(L '选择') [$(L '1/2/3，默认1')]: " PRELUDE_CHOICE || { [ -n "$PRELUDE_CHOICE" ] || return 1; }
        case ${PRELUDE_CHOICE:-1} in
            2) MORPH_TCP_PRELUDE="full8" ;;
            3) MORPH_TCP_PRELUDE="low7" ;;
            *) MORPH_TCP_PRELUDE="fade" ;;
        esac
        MORPH_UDP_PRELUDE="$MORPH_TCP_PRELUDE"
    fi

    # v3.3 新增：握手超时对 Portal/Vector/Egress 全部角色生效，未设置时 v3.3.0 从 Shared Key 派生
    HANDSHAKE_TIMEOUT="10s"
    echo ""
    echo -e "${BOLD}$(L '握手超时')${NC}$(L '（')${YELLOW}$(L 'NOW_HANDSHAKE_TIMEOUT；v3.3.0 起未设置时默认值从 Shared Key 派生（3s–30s，换密钥会变），显式设置可固定行为。持续时间格式，如 10s / 500ms / 1m / 1h，须为正数+单位；非法值会被 v3.3 启动拒绝')${NC}$(L '）：')"
    read -rp "$(L '握手超时') [$(L '回车默认') 10s]: " HANDSHAKE_TIMEOUT_IN || { [ -n "$HANDSHAKE_TIMEOUT_IN" ] || return 1; }
    HANDSHAKE_TIMEOUT=${HANDSHAKE_TIMEOUT_IN:-10s}
    validate_duration "$HANDSHAKE_TIMEOUT" || { warn "$(L '格式不合法（须为正数+单位，如 10s / 500ms / 1m / 1h），已重置为 10s')"; HANDSHAKE_TIMEOUT="10s"; }

    echo ""
    echo -e "${BOLD}$(L 'Portal 出口 out=（Portal 固定出口，运行期间不可变）：')${NC}"
    echo "  1) $(L 'direct - Portal 直接访问目标（默认）')"
    echo "  2) $(L 'SOCKS5 上游 - 经一层 SOCKS5 代理出站（链式代理）')"
    # v3.3.0 起 out=egress 接受任意已启用的 TLS 或 QUIC 监听上的 Egress 注册，纯 TCP 的 Portal 也可用
    echo "  3) $(L 'egress - 远程 Egress 出口（目标解析/拨号在另一台主动回连的机器上，该机无需开放入站端口；可同时接多台）')"
    read -rp "$(L '选择') [$(L '1/2/3，默认1')]: " OUT_CHOICE || { [ -n "$OUT_CHOICE" ] || return 1; }
    case ${OUT_CHOICE:-1} in
        2) OUT_TYPE="socks" ;;
        3) OUT_TYPE="egress" ;;
        *) OUT_TYPE="direct" ;;
    esac

    SOCKS="none"
    if [ "$OUT_TYPE" = "socks" ]; then
        read -rsp "$(L 'SOCKS5 地址，格式 user:pass')@$(L 'host:port（输入不回显）:') " SOCKS || { [ -n "$SOCKS" ] || return 1; }; echo
        SOCKS=${SOCKS:-none}
        validate_socks "$SOCKS" || { warn "$(L 'SOCKS5 格式不合法，已重置为 none 并改回 direct')"; SOCKS="none"; OUT_TYPE="direct"; }
    fi

    DIAL_MODE="single"; DIAL="$DEFAULT_DIAL"; DIAL4="auto"; DIAL6="auto"
    if [ "$OUT_TYPE" = "egress" ]; then
        info "$(L 'out=egress 时 Portal 不能再设置 dial/dial4/dial6（与官方约束一致），目标源地址请在 Egress 端配置')"
    else
        echo ""
        read -rp "$(L '出站源 IP dial（回车默认 auto；填 IP 会限定地址族，绑定失败不回退）:') " DIAL || { [ -n "$DIAL" ] || return 1; }
        DIAL=${DIAL:-$DEFAULT_DIAL}
        validate_ip_or_auto "$DIAL" any || { warn "$(L 'dial 不是合法 IP 字面量，已重置为 auto')"; DIAL="auto"; }
        read -rp "$(L '是否改用 dial4/dial6 分别绑定 IPv4/IPv6 源地址？')[y/N]: " DIAL46_CHOICE || { [ -n "$DIAL46_CHOICE" ] || return 1; }
        if [[ "$DIAL46_CHOICE" =~ ^[Yy]$ ]]; then
            DIAL_MODE="dual"
            read -rp "  $(L 'dial4（IPv4 源地址，回车默认 auto）:') " DIAL4 || { [ -n "$DIAL4" ] || return 1; }
            DIAL4=${DIAL4:-auto}
            read -rp "  $(L 'dial6（IPv6 源地址，回车默认 auto）:') " DIAL6 || { [ -n "$DIAL6" ] || return 1; }
            DIAL6=${DIAL6:-auto}
            validate_ip_or_auto "$DIAL4" 4 || { warn "$(L 'dial4 不是合法 IPv4 字面量，已重置为 auto')"; DIAL4="auto"; }
            validate_ip_or_auto "$DIAL6" 6 || { warn "$(L 'dial6 不是合法 IPv6 字面量（IPv4-mapped 地址不被 v3 接受），已重置为 auto')"; DIAL6="auto"; }
            DIAL="auto"
        fi
    fi

    echo ""
    echo -e "${BOLD}$(L '限速设置（Portal/Vector/Egress 通用语义，0=不限速）：')${NC}"
    read -rp "$(L '上行限速 Mbps，Vector')→$(L '目标（0=不限速）:') " RATE || { [ -n "$RATE" ] || return 1; }
    RATE=${RATE:-0}
    validate_rate "$RATE" || { warn "$(L '输入不合法（须为 0..2147483647 的整数），重置为0')"; RATE=0; }

    read -rp "$(L '下行限速 Mbps，目标')→$(L 'Vector（0=不限速）:') " ETAR || { [ -n "$ETAR" ] || return 1; }
    ETAR=${ETAR:-0}
    validate_rate "$ETAR" || { warn "$(L '输入不合法（须为 0..2147483647 的整数），重置为0')"; ETAR=0; }

    echo ""
    echo -e "${BOLD}$(L '本地 Vector 客户端连接信息')${NC}$(L '（可选，在电脑/路由器上跑本地 SOCKS5 入口用 in=）：')"
    read -rp "$(L '是否生成 Vector 连接信息？')[Y/n]: " GEN_VECTOR || { [ -n "$GEN_VECTOR" ] || return 1; }
    GEN_VECTOR=${GEN_VECTOR:-y}
    if [[ "$GEN_VECTOR" =~ ^[Yy]$ ]]; then
        GENERATE_VECTOR="1"
        if has_tcp && has_udp; then
            echo "  $(L 'Vector 载体（二选一，v3 一条连接只用一种载体）  1')) tcp/TLS  2) udp/QUIC"
            read -rp "  $(L '选择') [$(L '1/2，默认1')]: " VCARRIER_CHOICE || { [ -n "$VCARRIER_CHOICE" ] || return 1; }
            case ${VCARRIER_CHOICE:-1} in 2) VECTOR_CARRIER="udp" ;; *) VECTOR_CARRIER="tcp" ;; esac
        elif has_udp; then
            VECTOR_CARRIER="udp"
            info "  $(L '当前 Portal 仅 QUIC/UDP，Vector 载体自动选 udp')"
        else
            VECTOR_CARRIER="tcp"
            info "  $(L '当前 Portal 仅 TLS/TCP，Vector 载体自动选 tcp')"
        fi
        read -rp "  $(L '本地 SOCKS5 监听 in=（回车默认') ${DEFAULT_VECTOR_SOCKS}$(L '，可带 user:pass')@$(L '）:') " VECTOR_SOCKS || { [ -n "$VECTOR_SOCKS" ] || return 1; }
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
        echo -e "${BOLD}$(L '远程 Egress 出口机连接信息')${NC}$(L '（在出口机上运行 egress:// 主动回连本 Portal）：')"
        read -rp "$(L '是否生成 Egress 连接信息？')[Y/n]: " GEN_EGRESS || { [ -n "$GEN_EGRESS" ] || return 1; }
        GEN_EGRESS=${GEN_EGRESS:-y}
        if [[ "$GEN_EGRESS" =~ ^[Yy]$ ]]; then
            GENERATE_EGRESS="1"
            if has_tcp && has_udp; then
                echo "  $(L 'Egress 回连载体（v3.3.0 起两种都可用；一个连接串只选一种，多台出口机可以混用）')"
                echo "    1) $(L 'udp / QUIC - 一条连接承载多条 Flow（推荐）')"
                echo "    2) $(L 'tcp / TLS  - 每条 Flow 独占一条 TLS 连接，出口机自动维护预建连接池；UDP 被限制的网络选这个（出口机需') ≥ $(L 'v3.3.0）')"
                read -rp "  $(L '选择') [$(L '1/2，默认1')]: " ECARRIER_CHOICE || { [ -n "$ECARRIER_CHOICE" ] || return 1; }
                case ${ECARRIER_CHOICE:-1} in 2) EGRESS_CARRIER="tcp" ;; *) EGRESS_CARRIER="udp" ;; esac
            elif has_udp; then
                EGRESS_CARRIER="udp"
            else
                EGRESS_CARRIER="tcp"
                info "  $(L '当前 Portal 仅 TLS/TCP，Egress 载体自动选 tcp（出口机需') ≥ $(L 'v3.3.0）')"
            fi
            read -rp "  $(L 'Egress 端出站源 IP dial（在出口机上绑定目标连接源地址，回车默认 auto）:') " EGRESS_DIAL || { [ -n "$EGRESS_DIAL" ] || return 1; }
            EGRESS_DIAL=${EGRESS_DIAL:-auto}
            validate_ip_or_auto "$EGRESS_DIAL" any || { warn "$(L 'Egress dial 不是合法 IP 字面量，已重置为 auto')"; EGRESS_DIAL="auto"; }
            read -rp "  $(L '是否改用 dial4/dial6 分别绑定 IPv4/IPv6 目标出站源地址？')[y/N]: " EGRESS_DIAL46_CHOICE || { [ -n "$EGRESS_DIAL46_CHOICE" ] || return 1; }
            if [[ "$EGRESS_DIAL46_CHOICE" =~ ^[Yy]$ ]]; then
                EGRESS_DIAL_MODE="dual"
                read -rp "    $(L 'dial4（IPv4 源地址，回车默认 auto）:') " EGRESS_DIAL4 || { [ -n "$EGRESS_DIAL4" ] || return 1; }
                EGRESS_DIAL4=${EGRESS_DIAL4:-auto}
                read -rp "    $(L 'dial6（IPv6 源地址，回车默认 auto）:') " EGRESS_DIAL6 || { [ -n "$EGRESS_DIAL6" ] || return 1; }
                EGRESS_DIAL6=${EGRESS_DIAL6:-auto}
                validate_ip_or_auto "$EGRESS_DIAL4" 4 || { warn "$(L 'Egress dial4 不是合法 IPv4 字面量，已重置为 auto')"; EGRESS_DIAL4="auto"; }
                validate_ip_or_auto "$EGRESS_DIAL6" 6 || { warn "$(L 'Egress dial6 不是合法 IPv6 字面量（IPv4-mapped 地址不被 v3 接受），已重置为 auto')"; EGRESS_DIAL6="auto"; }
                EGRESS_DIAL="auto"
            fi
        fi
    fi

    echo ""
    divider
    echo -e "${BOLD}$(L '配置确认：')${NC}"
    divider
    echo -e "  $(L '域名/主机     :') ${GREEN}${DOMAIN}${NC}"
    echo -e "  $(L '公网地址      :') ${GREEN}${PUBLIC_HOST}${NC}"
    echo -e "  $(L '邮箱          :') ${GREEN}${EMAIL:-$(L '（自签模式不需要）')}${NC}"
    echo -e "  $(L '证书方式      :') ${GREEN}${CERT_METHOD}${NC}"
    echo -e "  $(L '端口模式      :') ${GREEN}${PORT_MODE}$(L '（TCP') $(tcp_port) / UDP $(udp_port)$(L '）')${NC}"
    echo -e "  $(L '监听地址      :') ${GREEN}$([ -z "$LISTEN_HOST" ] && echo "*（通配）" || echo "$LISTEN_HOST")${NC}"
    echo -e "  $(L '传输模式      :') ${GREEN}${NET}${NC}"
    echo -e "  $(L 'Portal 端点   :') ${GREEN}$(build_portal_endpoint)${NC}"
    echo -e "  $(L '共享密钥      :') ${GREEN}$(mask_secret "$SHARED_KEY")$(L '（32 位十六进制）')${NC}"
    echo -e "  $(L 'Morph 乱形    :') ${GREEN}$([ "$MORPH" = "1" ] && echo "开启 morph=1（默认）" || echo "关闭 morph=0")${NC}"
    [ "$MORPH" = "1" ] && echo -e "  $(L 'Prelude 策略  :') ${GREEN}${MORPH_TCP_PRELUDE}$(L '（写入生成的 Vector / Egress 启动命令，Portal 自身不使用）')${NC}"
    echo -e "  $(L '握手超时      :') ${GREEN}${HANDSHAKE_TIMEOUT}${NC}"
    echo -e "  $(L 'Portal 出口   :') ${GREEN}${OUT_TYPE}$([ "$OUT_TYPE" = "socks" ] && echo " ($(display_socks "$SOCKS"))")${NC}"
    if [ "$OUT_TYPE" != "egress" ]; then
        if [ "$DIAL_MODE" = "dual" ]; then
            echo -e "  $(L '出站源IP      :') ${GREEN}dial4=${DIAL4} dial6=${DIAL6}${NC}"
        else
            echo -e "  $(L '出站源IP      :') ${GREEN}dial=${DIAL}${NC}"
        fi
    fi
    echo -e "  $(L '上/下行限速   :') ${GREEN}${RATE} / ${ETAR} Mbps${NC}"
    if [ "$GENERATE_VECTOR" = "1" ]; then
        echo -e "  $(L 'Vector客户端  :') ${GREEN}$(L '生成（carrier=')${VECTOR_CARRIER} in=${VECTOR_SOCKS}$(L '）')${NC}"
    fi
    if [ "$GENERATE_EGRESS" = "1" ]; then
        if [ "$EGRESS_DIAL_MODE" = "dual" ]; then
            echo -e "  $(L 'Egress出口机  :') ${GREEN}$(L '生成（载体') ${EGRESS_CARRIER}$(L '，dial4=')${EGRESS_DIAL4} dial6=${EGRESS_DIAL6}$(L '）')${NC}"
        else
            echo -e "  $(L 'Egress出口机  :') ${GREEN}$(L '生成（载体') ${EGRESS_CARRIER}$(L '，dial=')${EGRESS_DIAL}$(L '）')${NC}"
        fi
    fi
    divider
    read -rp "$(L '确认安装') [y/N]: " CONFIRM || { [ -n "$CONFIRM" ] || return 1; }
    [[ ! "$CONFIRM" =~ ^[Yy]$ ]] && { info "$(L '已取消')"; return; }

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
            info "$(L '检测到已有配置，已备份到') ${backup_dir}$(L '（本次安装中途失败时可手动恢复）')"
            # 备份里有密钥，只保留最近 3 份，避免每次重新配置都多留一份
            ls -1d "${CONFIG_DIR}".bak.* 2>/dev/null | sort -r | tail -n +4 | tr '\n' '\0' | xargs -r -0 rm -rf || true
        else
            if ! confirm "$(L '配置备份失败，仍要继续吗？')" n; then info "$(L '已取消')"; return; fi
        fi
    fi

    step "$(L '第 5 步：安装系统依赖')"
    divider
    apt_install curl wget tar socat openssl python3 qrencode iproute2 ca-certificates
    if fw_conflict_detected; then
        warn "$(L '检测到 firewalld 或 cnblock 防火墙链已在运行，跳过 ufw 安装（避免两套防火墙混用）；端口放行请用现有防火墙管理')"
    else
        apt_install ufw
    fi
    if [ "$TLS_MODE" = "2" ]; then
        apt_install certbot
        [ "$CERT_METHOD" = "cloudflare-dns" ] && apt_install python3-certbot-dns-cloudflare
    fi
    success "$(L '依赖安装完成')"

    if [ "$TLS_MODE" = "2" ]; then
        ensure_ipv4_preference
        step "$(L '第 6 步：申请 TLS 证书')"
        divider

        if [ "$CERT_METHOD" = "letsencrypt-http" ]; then
            # HTTP-01 前先做 DNS 预检；80 端口占用检查在 obtain_portal_cert 内（已有有效证书时不误拦）
            check_domain_dns "$DOMAIN" || true
        fi
        if [ "$CERT_METHOD" = "letsencrypt-dns" ] && [ "${DNS_API}" = "unsupported" ]; then
            error "$(L '您之前选择了「其他/手动」DNS 服务商：需先手动完成 DNS TXT 验证签发证书，本脚本无法一键接管。请重新运行并改选 Cloudflare（推荐）/ DNSPod / 阿里云')"
        fi
        obtain_portal_cert

        info "$(L '证书路径:') ${CRT}"
        info "$(L '私钥路径:') ${KEY_PEM}"
    fi


    step "$(L '第 7 步：下载 Nowhere 二进制')"
    divider
    detect_binary
    info "$(L '正在获取最新版本号...')"
    LATEST="$(get_latest_tag)"
    [ -z "$LATEST" ] && error "$(L '无法获取版本号（GitHub API 与 releases/latest 跳转均失败），请检查网络')"
    LATEST_MAJOR="$(version_major "$LATEST")"
    if [ -n "$LATEST_MAJOR" ] && [ "$LATEST_MAJOR" -lt 3 ]; then
        error "$(L '当前最新版为') ${LATEST}$(L '，低于 v3.0.0，与本脚本的 NW3 配置不兼容，已中止（请检查仓库状态）')"
    fi
    if [ -n "$LATEST_MAJOR" ] && [ "$LATEST_MAJOR" -gt 3 ]; then
        warn "$(L '当前最新版为') ${LATEST}$(L '，已进入新的协议代（NW')${LATEST_MAJOR}$(L '）；本脚本的向导按 NW3 生成配置，可能无法直接使用')"
        read -rp "$(L '仍要继续安装该版本吗？')[y/N]: " NEWMAJOR_CONFIRM || { [ -n "$NEWMAJOR_CONFIRM" ] || return 1; }
        [[ ! "$NEWMAJOR_CONFIRM" =~ ^[Yy]$ ]] && { info "$(L '已取消')"; return; }
    fi
    info "$(L '最新版本:') ${LATEST} (${ARCH_NAME}-${LIBC})"
    fetch_nowhere_release "$LATEST" || error "$(L '下载或校验失败，已中止')"
    install -m 755 "$DL_BINARY" "${BIN_PATH}"
    record_installed_version "$LATEST"
    success "Nowhere $(${BIN_PATH} --version 2>&1 | head -1) $(L '安装完成')"

    step "$(L '第 8 步：保存配置')"
    divider
    install -d -m 700 "$CONFIG_DIR"
    setup_nowhere_user || true
    if [ "$NOWHERE_USER" = "nowhere" ]; then
        sync_portal_cert_copy || { warn "$(L '证书副本同步失败，回退 root 运行')"; NOWHERE_USER="root"; }
    fi
    sanitize_nowhere_params
    NOWHERE_PORTAL="$(build_portal_url)"
    write_portal_env || error "$(L '配置保存失败，已中止')"
    echo "portal" > "$ROLE_FILE"
    success "$(L '配置已保存至') ${CONFIG_FILE}"

    step "$(L '第 9 步：安装前端口占用检测')"
    divider
    EXISTING_PROC=""; EXISTING_TCP=""; EXISTING_UDP=""
    if command -v ss >/dev/null 2>&1; then
        if has_tcp; then
            EXISTING_TCP="$(check_port_occupied_by_other tcp "$(tcp_port)")"
        fi
        if has_udp; then
            EXISTING_UDP="$(check_port_occupied_by_other udp "$(udp_port)")"
        fi
    fi
    EXISTING_PROC="${EXISTING_TCP}${EXISTING_UDP}"
    if [ -n "$EXISTING_PROC" ]; then
        warn "$(L '检测到目标端口已被其他进程占用：')"
        [ -n "$EXISTING_TCP" ] && echo "$EXISTING_TCP"
        [ -n "$EXISTING_UDP" ] && echo "$EXISTING_UDP"
        warn "$(L '请先停止占用该端口的服务（旧的 Nowhere 实例已自动排除在外），否则新服务会反复崩溃重启，客户端表现为一直 timeout')"
        read -rp "$(L '仍要继续安装吗？')[y/N]: " PORT_CONFIRM || { [ -n "$PORT_CONFIRM" ] || return 1; }
        [[ ! "$PORT_CONFIRM" =~ ^[Yy]$ ]] && { info "$(L '已取消安装')"; return; }
    else
        success "$(L '目标端口空闲，可以使用')"
    fi

    step "$(L '第 10 步：配置防火墙（先于服务启动，避免中间态连不通）')"
    divider
    # 旧版在这里无条件 ufw --force enable：如果机器上还跑着别的服务（Snell、面板、其他代理），
    # 它们没放行的端口会被一起挡掉。现在：ufw 已启用就只加规则；未启用则先列出未放行的监听端口再询问。
    local -a NW_FW_SPECS=()
    if has_tcp; then NW_FW_SPECS+=("$(tcp_port)/tcp"); fi
    if has_udp; then NW_FW_SPECS+=("$(udp_port)/udp"); fi
    if [ "$CERT_METHOD" = "letsencrypt-http" ]; then NW_FW_SPECS+=("80/tcp"); fi
    fw_allow_for_service "${NW_FW_SPECS[@]}"
    if [ -n "$OLD_NW_PORTS" ]; then fw_prune_old_specs "$OLD_NW_PORTS"; fi

    step "$(L '第 11 步：创建并启动系统服务')"
    divider
    # 注意：PrivateTmp 必须关闭。v3 的 nowhere status 靠系统临时目录下的
    # 受保护 IPC 注册表发现实例，PrivateTmp 会让服务与外部命令看到不同的 /tmp，
    # 导致 status 永远发现不到本服务（实测会报 namespace identity unavailable 一类问题时更难排查）
    # NOW_MORPH_*_PRELUDE 不再写进 Portal 的 unit：官方文档明确 Portal 不使用这两个变量（只有发起端使用）
    write_service_unit "$SERVICE_FILE" "Nowhere Portal" "https://github.com/${REPO}" "" "${NOWHERE_USER:-root}" "${NOWHERE_USER:-root}" "${BIN_PATH} \${NOWHERE_PORTAL}" "CAP_NET_BIND_SERVICE" "1048576" "on-failure" "3" "EnvironmentFile=${CONFIG_FILE}
Environment=NOW_HANDSHAKE_TIMEOUT=${HANDSHAKE_TIMEOUT}
PrivateTmp=false
ProtectSystem=full
ProtectHome=read-only"

    restart_nowhere_with_fallback 0 || true

    local _nw_missing=""
    if has_tcp && ! tcp_listening "$(tcp_port)"; then _nw_missing="${_nw_missing} tcp:$(tcp_port)"; fi
    if has_udp && ! udp_listening "$(udp_port)"; then _nw_missing="${_nw_missing} udp:$(udp_port)"; fi

    local _nw_active=0
    systemctl is-active --quiet nowhere && _nw_active=1
    if [ "$_nw_active" = "1" ] && [ -z "$_nw_missing" ]; then
        success "$(L '服务启动成功，且已确认端口正在监听')"
    elif [ "$_nw_active" = "1" ] && [ -n "$_nw_missing" ]; then
        warn "$(L 'systemd 显示服务 active，但未检测到端口实际在监听') $(L '（存在端口未监听：')${_nw_missing# }$(L '）')"
        warn "$(L '常见原因：证书路径错误、端口被抢占、密钥格式不合 v3 规范（必须 32 位小写十六进制）')"
        journalctl -u nowhere -n 30 --no-pager
        warn "$(L '服务处于不确定状态，建议排查后再连接客户端，否则会一直 timeout')"
    else
        warn "$(L '服务未能启动，查看日志排查：')"
        journalctl -u nowhere -n 30 --no-pager
        error "$(L '安装中止')"
    fi

    step "$(L '第 12 步：生成连接信息')"
    divider
    build_client_links
    build_vector_info
    build_egress_info
    print_all_info

    step "$(L '第 13 步：安装快捷命令')"
    divider
    install_shortcuts || true
    if ! verify_shortcuts; then
        warn "$(L '安装完成，但快捷命令校验未通过（服务本身不受影响），请稍后执行 adam shortcuts 重新安装')"
    fi
}

print_all_info() {
    local udp_section="" tcp_section="" vector_section="" egress_section=""

    if [[ -n "$UDP_LINK" ]]; then
        udp_section="
$(L '【Anywhere 分享链接 —— QUIC/UDP（net=udp）】')
$(L '链接：')
${UDP_LINK}

$(L '一键导入深链（手机点击，需 Anywhere 已支持 NW3）：')
${IMPORT_UDP}
"
    fi

    if [[ -n "$TCP_LINK" ]]; then
        tcp_section="
$(L '【Anywhere 分享链接 —— TLS/TCP（net=tcp，默认）】')
$(L '链接：')
${TCP_LINK}

$(L '一键导入深链（手机点击，需 Anywhere 已支持 NW3）：')
${IMPORT_TCP}
"
    fi

    if [ "$GENERATE_VECTOR" = "1" ]; then
        if [[ -n "$VECTOR_URL" ]]; then
            vector_section="
$(L '【本地 Vector 客户端 —— 在电脑/路由器上跑本地 SOCKS5 入口】')
$(L '载体:') ${VECTOR_CARRIER}  $(L '本地监听 in=')${VECTOR_SOCKS}
$(L '连接串：')
${VECTOR_URL}

$(L '启动命令：')
NOW_HANDSHAKE_TIMEOUT=${HANDSHAKE_TIMEOUT} NOW_MORPH_TCP_PRELUDE=${MORPH_TCP_PRELUDE} NOW_MORPH_UDP_PRELUDE=${MORPH_UDP_PRELUDE} nowhere '${VECTOR_URL}'
$([ "$TLS_MODE" = "1" ] && echo "
※ $(L '用的是 pin=证书指纹 锁定方式，Portal 每次重启该指纹都会变，重启后需要重新生成本连接串（Nowhere 菜单 4 或 pz 命令）')")
"
        else
            vector_section="
$(L '【本地 Vector 客户端】')
$(L '生成失败：未能获取到有效的连接参数，可稍后通过Nowhere 菜单「4')) $(L '查看连接信息」重试')
"
        fi
    fi

    if [ "$GENERATE_EGRESS" = "1" ]; then
        if [[ -n "$EGRESS_URL" ]]; then
            egress_section="
$(L '【远程 Egress 出口机 —— 在出口机上运行，主动回连本 Portal，无需出口机开放入站端口】')
$(L '回连载体:') ${EGRESS_CARRIER}
$(L '连接串：')
${EGRESS_URL}

$(L '出口机启动命令（或在出口机上运行本脚本 Nowhere 菜单 2，直接粘贴上面的连接串装成 systemd 服务）：')
NOW_HANDSHAKE_TIMEOUT=${HANDSHAKE_TIMEOUT} NOW_MORPH_TCP_PRELUDE=${MORPH_TCP_PRELUDE} NOW_MORPH_UDP_PRELUDE=${MORPH_UDP_PRELUDE} nowhere '${EGRESS_URL}'
※ $(L '本 Portal 已固定 out=egress：没有可用的 Egress 时，新连接会在 Flow 建立超时（NOW_FLOW_SETUP_TIMEOUT，默认 20s）内等待注册，超时即失败，不会回退直连')
※ $(L 'v3.3.0 起同一 Portal 可同时接受多台 Egress（TLS / QUIC 可混用，Portal 按先进先出轮转，不保证均衡）；使用 tcp 载体的出口机需') ≥ v3.3.0
$([ "$TLS_MODE" = "1" ] && echo "※ 同 Vector，pin= 指纹随 Portal 重启变化，重启后需同步更新出口机连接串")
"
        else
            egress_section="
$(L '【远程 Egress 出口机】')
$(L '生成失败：未能获取到有效的连接参数，可稍后通过Nowhere 菜单「4')) $(L '查看连接信息」重试')
"
        fi
    fi

    cat > "${CONFIG_DIR}/config.txt" << CONFEOF
════════════════════════════════════════════════════════════════
  $(L 'Nowhere Portal 连接信息（')${TARGET_NW_VERSION} $(L '/ NW3）')
  $(L '更新时间:') $(date '+%Y-%m-%d %H:%M:%S')
════════════════════════════════════════════════════════════════

$(L '【服务端启动参数（Portal URL，用于 systemd ExecStart）】')
${NOWHERE_PORTAL}
※ $(L 'v3 的 alpn/net/log/pool/up/down/socks')($(L 'Vector旧名')) $(L '等旧参数均已移除或改名，')
  $(L '未知参数会被静默忽略，千万不要再往启动串里手动拼旧参数。')

$(L '【客户端连接参数】')
  $(L '域名/公网地址 :') ${PUBLIC_HOST}
  $(L 'TCP 端口      :') $(tcp_port)
  $(L 'UDP 端口      :') $(udp_port)
  $(L '共享密钥      :') ${SHARED_KEY}$(L '（32 位小写十六进制，两端必须完全一致）')
  $(L '传输模式      :') ${NET}$(L '（端口模式') ${PORT_MODE}$(L '）')
  $(L 'Morph 乱形    :') $([ "$MORPH" = "1" ] && echo "开启 morph=1（v3 默认，客户端必须同步开启）" || echo "关闭 morph=0（客户端必须同步关闭）")
  $(L 'Prelude 策略  :') ${MORPH_TCP_PRELUDE}$(L '（NOW_MORPH_TCP_PRELUDE / NOW_MORPH_UDP_PRELUDE，只在发起端 Vector / Egress 上设置，Portal 不使用；接收端通吃、两端无需一致）')
  $(L '握手超时      :') ${HANDSHAKE_TIMEOUT}$(L '（NOW_HANDSHAKE_TIMEOUT；v3.3.0 起未设置时从 Shared Key 派生 3s–30s，显式设置可固定）')
  TLS           : $([ "$TLS_MODE" = "1" ] && echo "自签证书(tls=1，靠 pin= 指纹锁定)" || echo "真实证书(tls=2，系统 CA + 主机名校验)")
  $(L 'Portal 出口   :') ${OUT_TYPE}
${udp_section}${tcp_section}${vector_section}${egress_section}
$(L '【Anywhere 手动填写】')
  $(L '服务器 :') ${PUBLIC_HOST}
  $(L '端口   :') $(if has_tcp; then tcp_port; else udp_port; fi)
  $(L '密钥   :') ${SHARED_KEY}
  $(L 'TLS    : 开启')
  $(L 'ALPN   : nw3（v3 固定，不可改，App 内无需/无法填写 alpn 时忽略此项）')
  Morph  : ${MORPH}$(L '（务必和服务端保持一致）')

$(L '【防火墙提醒】')
$(if has_tcp && has_udp; then echo "  需放行: TCP $(tcp_port) 和 UDP $(udp_port)"; elif has_tcp; then echo "  需放行: TCP $(tcp_port)"; else echo "  需放行: UDP $(udp_port)"; fi)
$([ "$TLS_MODE" = "1" ] && echo "
$(L '【TLS 提示】')
  $(L 'tls=1 为临时自签证书，每次重启指纹会变化，仅建议测试用')
  $(L 'v3 客户端默认校验系统 CA 与主机名，自签场景必须用 pin= 锁定指纹')")

$(L '【版本兼容提醒】')
  $(L '本配置为 NW3 协议：v1/v2 的 Portal/Vector 以及未支持 NW3 的')
  $(L 'Anywhere/第三方客户端无法与本服务端互通，升级需整条链路一起升。')
  $(L 'v3.2.0 起 Portal 强制 Authenticated Prelude：morph=1 且走 TLS/TCP 的对端')
  $(L '（Vector / Egress / Anywhere）必须') ≥ $(L 'v3.1.0，更旧的版本会被静默拒绝。')
  $(L '分享链接与 anywhere:// 深链格式已按 v3 文档更新，但能否导入成功')
  $(L '取决于你手机上的 Anywhere 版本是否已支持 NW3，请以实测为准。')
════════════════════════════════════════════════════════════════
CONFEOF
    chmod 600 "${CONFIG_DIR}/config.txt"

    echo ""
    echo -e "${BOLD}${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║              ✅  $(L '操作完成！')                                  ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    cat "${CONFIG_DIR}/config.txt"
    echo ""
    if [[ -n "$IMPORT_UDP" ]]; then
        echo -e "${BOLD}✅ $(L '最快导入方式（QUIC/UDP）：')${NC}"
        echo -e "$(L '在手机浏览器打开，自动跳转 Anywhere 导入（需 Anywhere 支持 NW3）：')"
        echo -e "${CYAN}${IMPORT_UDP}${NC}"
    elif [[ -n "$IMPORT_TCP" ]]; then
        echo -e "${BOLD}✅ $(L '最快导入方式（TLS/TCP）：')${NC}"
        echo -e "$(L '在手机浏览器打开，自动跳转 Anywhere 导入（需 Anywhere 支持 NW3）：')"
        echo -e "${CYAN}${IMPORT_TCP}${NC}"
    fi
    if command -v qrencode >/dev/null 2>&1; then
        if [[ -n "$UDP_LINK" ]]; then
            echo ""
            echo -e "${BOLD}📱 $(L '扫码导入 Anywhere（QUIC/UDP）：')${NC}"
            qrencode -t ANSIUTF8 "$UDP_LINK" || true
        fi
        if [[ -n "$TCP_LINK" ]]; then
            echo ""
            echo -e "${BOLD}📱 $(L '扫码导入 Anywhere（TLS/TCP）：')${NC}"
            qrencode -t ANSIUTF8 "$TCP_LINK" || true
        fi
    fi
    echo ""
    print_tls_fingerprint
    echo ""
    echo -e "${BOLD}📋 $(L '常用命令：')${NC}"
    echo -e "  $(L '状态 :') ${CYAN}systemctl status nowhere${NC} / ${CYAN}nowhere status${NC}"
    echo -e "  $(L '日志 :') ${CYAN}journalctl -u nowhere -f${NC}"
    echo -e "  $(L '配置 :') ${CYAN}cat ${CONFIG_DIR}/config.txt${NC}"
    echo -e "  $(L '重启 :') ${CYAN}systemctl restart nowhere${NC}"
    echo -e "  $(L '探测 :') ${CYAN}${MANAGER_PATH} probe${NC}$(L '（真实 TCP Flow 连通性测试）')"
    divider
}

load_saved_config() {
    [ ! -f "$CONFIG_FILE" ] && error "$(L '未找到配置文件，请先执行安装')"
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
    CRT_RUNTIME="${CRT_RUNTIME_VALUE:-$CRT}"
    KEY_PEM_RUNTIME="${KEY_PEM_RUNTIME_VALUE:-$KEY_PEM}"
    # 兼容 v8.4 旧配置（CRT_VALUE 曾被覆写成副本路径）：若原始 LE/acme 证书在位则自动还原源路径
    if [ "$TLS_MODE" = "2" ] && [ "$CRT" = "${CONFIG_DIR}/certs/fullchain.pem" ] && [ -n "${DOMAIN:-}" ]; then
        if [ "$CERT_METHOD" = "letsencrypt-dns" ] && [ -f "${CONFIG_DIR}/certs/${DOMAIN}/fullchain.pem" ]; then
            CRT="${CONFIG_DIR}/certs/${DOMAIN}/fullchain.pem"
            KEY_PEM="${CONFIG_DIR}/certs/${DOMAIN}/privkey.pem"
        elif [ -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]; then
            CRT="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
            KEY_PEM="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
        fi
    fi
    # 兼容旧版（v1.5 脚本）配置文件：旧字段 ALPN/POOL/LOG/SOCKS含义已变，只做迁移提示不直接沿用
    OUT_TYPE="${OUT_TYPE_VALUE:-}"
    if [[ -z "$OUT_TYPE" ]]; then
        if [[ -n "${SOCKS_VALUE:-}" && "${SOCKS_VALUE}" != "none" ]]; then
            OUT_TYPE="socks"
            SOCKS="$SOCKS_VALUE"
            warn "$(L '检测到旧版配置：SOCKS5 已由 socks= 迁移为 Portal 的 out=，已自动沿用该地址')"
        else
            OUT_TYPE="direct"
            SOCKS="none"
        fi
        warn "$(L '检测到旧版（NW1）配置文件。v3 还要求：密钥改为 32 位十六进制、删除 alpn/net/log/pool 参数，建议用Nowhere 菜单「3')) $(L '重新配置」按 v3 向导重装一次')"
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
    HANDSHAKE_TIMEOUT="${HANDSHAKE_TIMEOUT_VALUE:-10s}"
    validate_duration "$HANDSHAKE_TIMEOUT" || HANDSHAKE_TIMEOUT="10s"
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
    sanitize_nowhere_params

    if ! is_valid_key "$SHARED_KEY"; then
        warn "$(L '当前保存的共享密钥不符合 v3 规范（必须是恰好 32 位小写十六进制字符）')"
        warn "$(L 'v3 会直接拒绝用该密钥启动。请用Nowhere 菜单「3')) $(L '重新配置」生成新密钥，并同步更新所有 Vector/Egress/Anywhere 对端')"
    fi
}

# 只下载并安装二进制，不触碰任何服务（供本机 Egress 安装用：服务文件尚未生成时，
# 不能复用 install_nowhere_version，那个函数会在装完后直接重启 nowhere）。
install_nowhere_binary_only() {
    info "$(L '正在获取最新版本号...')"
    local latest latest_major
    latest="$(get_latest_tag)"
    [ -z "$latest" ] && { warn "$(L '无法获取版本号，请检查网络')"; return 1; }
    latest_major="$(version_major "$latest")"
    if [ -n "$latest_major" ] && [ "$latest_major" -lt 3 ]; then
        warn "$(L '当前最新版为') ${latest}$(L '，低于 v3.0.0，与 NW3 配置不兼容，已中止')"
        return 1
    fi
    detect_binary
    info "$(L '最新版本:') ${latest} (${ARCH_NAME}-${LIBC})"
    fetch_nowhere_release "$latest" || return 1
    install -d -m 700 "$CONFIG_DIR"
    if [ -f "$BIN_PATH" ]; then
        cp "$BIN_PATH" "$BIN_BACKUP_PATH"
        record_previous_version "$(read_installed_version)"
    fi
    install -m 755 "$DL_BINARY" "$BIN_PATH"
    record_installed_version "$latest"
    success "Nowhere $(${BIN_PATH} --version 2>&1 | head -1) $(L '安装完成')"
    return 0
}

# 解析 egress:// 连接串（Portal 端 Nowhere 菜单 4 / pz 生成的那一串）。
# 结果写入 PE_KEY / PE_HOST / PE_PORT / PE_CARRIER / PE_FAMILY / PE_MORPH。
# 同时限制字符集：这串内容会原样写进 systemd 的 EnvironmentFile。
# 从 egress:// 查询串取单个参数的值（值须为 URL 安全字符，直接取原值）
egress_query_param() {
    local q="&$1&" k="$2" v
    case "$q" in
        *"&${k}="*) v="${q##*&${k}=}"; v="${v%%&*}"; urldecode "$v"; return 0 ;;
        *) return 1 ;;
    esac
}

parse_egress_url() {
    local u="$1" rest query=""
    local re_path='^(.+)/(tcp|udp)([46]?):([0-9]+)$' re_compact='^(.+):([0-9]+)$'
    local re_host='^[][A-Za-z0-9.:_-]+$' re_query='^[A-Za-z0-9=&%._:~-]+$'
    PE_KEY=""; PE_HOST=""; PE_PORT=""; PE_CARRIER=""; PE_FAMILY=""; PE_MORPH="1"
    PE_SNI=""; PE_PIN=""; PE_DIAL="auto"; PE_DIAL4="auto"; PE_DIAL6="auto"; PE_RATE="0"; PE_ETAR="0"
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
        local _v
        _v="$(egress_query_param "$query" sni || true)"; [ -n "$_v" ] && PE_SNI="$_v"
        _v="$(egress_query_param "$query" pin || true)"; [ -n "$_v" ] && PE_PIN="$_v"
        _v="$(egress_query_param "$query" dial || true)"; [ -n "$_v" ] && PE_DIAL="$_v"
        _v="$(egress_query_param "$query" dial4 || true)"; [ -n "$_v" ] && PE_DIAL4="$_v"
        _v="$(egress_query_param "$query" dial6 || true)"; [ -n "$_v" ] && PE_DIAL6="$_v"
        _v="$(egress_query_param "$query" rate || true)"; [ -n "$_v" ] && PE_RATE="$_v"
        _v="$(egress_query_param "$query" etar || true)"; [ -n "$_v" ] && PE_ETAR="$_v"
    fi
    return 0
}

# 本机安装为 Egress 服务（在出口机上运行，主动回连 Portal）。
# v3.3.0 起 Egress 可选 QUIC/UDP 或 TLS/TCP 载体，同一 Portal 可同时接多台 Egress。
# 注意：这会覆盖本机现有的 nowhere.service（同一服务名），一台机器同一时间只能是
# Portal 或 Egress 其中一种角色；Egress 配置单独存在 egress.env，不读写 Portal 的 nowhere.env，
# 角色记录在 ${CONFIG_DIR}/role，状态/配置/重启等命令据此区分。
do_install_egress_service() {
    step "$(L '本机安装为 Egress 服务')"
    divider
    warn "$(L '本机将作为出口机（Egress），主动回连 Portal；这会覆盖本机现有的 nowhere.service')"
    warn "$(L 'Portal 侧必须已设 out=egress，并放行所选载体的端口（QUIC = UDP 端口，TLS = TCP 端口）')"
    if [ "$(current_role)" = "portal" ]; then
        warn "$(L '检测到本机当前是 Portal 角色：继续会把本机切换为 Egress（Portal 配置文件保留，但服务被替换）')"
    fi
    read -rp "$(L '确认继续') [y/N]: " EG_CONFIRM || { [ -n "$EG_CONFIRM" ] || return 1; }
    [[ ! "$EG_CONFIRM" =~ ^[Yy]$ ]] && { info "$(L '已取消')"; return; }
    local old_portal_specs=""
    old_portal_specs="$(nowhere_ports 2>/dev/null || true)"
    ensure_prereqs

    local eg_host="" eg_port="" eg_key="" eg_morph="1" eg_sni="" eg_pin="" eg_carrier="udp" eg_family="" eg_handshake="10s"
    local eg_dial_mode eg_dial eg_dial4 eg_dial6 eg_rate eg_etar eg_prelude="fade"
    local eg_url="" eg_query eg_host_part eg_paste=""

    echo ""
    info "$(L '可以直接粘贴 Portal 端（Nowhere 菜单 4 / pz）生成的 egress:// 连接串，跳过逐项填写')"
    read -rsp "$(L '粘贴 egress:// 连接串（输入不回显，回车 = 逐项填写）:') " eg_paste || { [ -n "$eg_paste" ] || return 1; }; echo
    eg_paste="$(printf '%s' "$eg_paste" | tr -d ' \r\n')"
    if [ -n "$eg_paste" ]; then
        if parse_egress_url "$eg_paste"; then
            eg_url="$eg_paste"; eg_key="$PE_KEY"; eg_host="$PE_HOST"; eg_port="$PE_PORT"
            eg_carrier="$PE_CARRIER"; eg_family="$PE_FAMILY"; eg_morph="$PE_MORPH"
            eg_sni="$PE_SNI"; eg_pin="$PE_PIN"; eg_dial="$PE_DIAL"; eg_dial4="$PE_DIAL4"; eg_dial6="$PE_DIAL6"
            eg_rate="$PE_RATE"; eg_etar="$PE_ETAR"
            if [ "$PE_DIAL4" != "auto" ] || [ "$PE_DIAL6" != "auto" ]; then eg_dial_mode="dual"; else eg_dial_mode="single"; fi
            if [ -n "$eg_sni" ] && ! is_safe_host "$eg_sni"; then warn "$(L '连接串里的 SNI 格式不合法，已忽略')"; eg_sni=""; fi
            if [ -n "$eg_pin" ] && [[ ! "$eg_pin" =~ ^[0-9a-f]{64}$ ]]; then warn "$(L '连接串里的 pin 不是 64 位小写十六进制，已忽略')"; eg_pin=""; fi
            validate_ip_or_auto "$eg_dial" any || { warn "$(L '连接串里的 dial 不是合法 IP，已重置为 auto')"; eg_dial="auto"; }
            validate_ip_or_auto "$eg_dial4" 4 || { warn "$(L '连接串里的 dial4 不是合法 IPv4，已重置为 auto')"; eg_dial4="auto"; }
            validate_ip_or_auto "$eg_dial6" 6 || { warn "$(L '连接串里的 dial6 不是合法 IPv6，已重置为 auto')"; eg_dial6="auto"; }
            validate_rate "$eg_rate" || { warn "$(L '连接串里的上行限速不合法，已重置为 0')"; eg_rate="0"; }
            validate_rate "$eg_etar" || { warn "$(L '连接串里的下行限速不合法，已重置为 0')"; eg_etar="0"; }
            # 按清洗后的字段重建 eg_url，确保非法参数被彻底剔除、IPv6 dial/dial6 正确编码
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
            # 握手超时不在连接串里：粘贴后也要问一次，否则静默落回 10s
            read -rp "$(L '握手超时 NOW_HANDSHAKE_TIMEOUT（v3.3.0 起未设置时从 Shared Key 派生 3s–30s；持续时间格式如 10s/500ms/1m/1h，回车默认 10s）:') " eg_handshake || { [ -n "$eg_handshake" ] || return 1; }
            eg_handshake=${eg_handshake:-10s}
            validate_duration "$eg_handshake" || { warn "$(L '格式不合法（须为正数+单位，如 10s），已重置为 10s')"; eg_handshake="10s"; }
            success "$(L '连接串解析通过：')${eg_host} ${eg_carrier}${eg_family}:${eg_port}$(L '，morph=')${eg_morph}"
        else
            warn "$(L '连接串格式不合法（应为 egress://32位hex密钥')@$(L '主机/udp')|$(L 'tcp:端口')?$(L '参数），改为逐项填写')"
        fi
    fi

    if [ -z "$eg_url" ]; then
        while true; do
            read -rp "$(L 'Portal 公网地址（域名或 IP，Egress 回连用）:') " eg_host || { [ -n "$eg_host" ] || return 1; }
            eg_host=$(echo "$eg_host" | tr -d ' \r\n')
            if is_safe_host "$eg_host"; then break; fi
            warn "$(L '地址不能为空，且只能包含字母、数字和 . : - _') [ ]"
        done
        echo ""
        echo "$(L '回连载体（须与 Portal 已开放的监听对应；v3.3.0 起两种都可用）：')"
        echo "  1) $(L 'udp / QUIC（默认）- 一条连接承载多条 Flow')"
        echo "  2) $(L 'tcp / TLS        - 每条 Flow 独占一条 TLS 连接，自动维护预建连接池（Hydra）；UDP 被限制的网络选这个')"
        read -rp "$(L '选择') [$(L '1/2，默认1')]: " EG_CARRIER_CHOICE || { [ -n "$EG_CARRIER_CHOICE" ] || return 1; }
        case ${EG_CARRIER_CHOICE:-1} in 2) eg_carrier="tcp" ;; *) eg_carrier="udp" ;; esac
        read -rp "$(L 'Portal 的') ${eg_carrier^^} $(L '端口（回车默认 443）:') " eg_port || { [ -n "$eg_port" ] || return 1; }
        eg_port=${eg_port:-443}
        validate_port "$eg_port" || { warn "$(L '端口不合法，重置为 443')"; eg_port=443; }
        read -rp "$(L '地址族（回车=不限；4=仅 IPv4；6=仅 IPv6）:') " eg_family || { [ -n "$eg_family" ] || return 1; }
        case "$eg_family" in 4|6) : ;; *) eg_family="" ;; esac
        while true; do
            read -rsp "$(L '共享密钥（必须与 Portal 完全一致，32 位小写十六进制，输入不回显）:') " eg_key || { [ -n "$eg_key" ] || return 1; }; echo
            if is_valid_key "$eg_key"; then
                break
            fi
            warn "$(L '密钥不符合 v3 规范：必须是恰好 32 位小写十六进制字符，不能回车自动生成（必须与 Portal 一致）')"
        done
        read -rp "$(L 'Morph 是否开启（须与 Portal 一致）')[Y/n]: " eg_morph || { [ -n "$eg_morph" ] || return 1; }
        if [[ "$eg_morph" =~ ^[Nn]$ ]]; then eg_morph="0"; else eg_morph="1"; fi
        echo ""
        echo "$(L 'Portal 证书信任方式：')"
        echo "  1) $(L 'tls=2 真实证书：走系统 CA + 主机名校验（默认）')"
        echo "  2) $(L 'tls=1 自签证书：必须用 pin= 锁定 Portal 证书指纹（指纹随 Portal 重启变化）')"
        read -rp "$(L '选择') [$(L '1/2，默认1')]: " EG_TLS_CHOICE || { [ -n "$EG_TLS_CHOICE" ] || return 1; }
        case ${EG_TLS_CHOICE:-1} in
            2)
                while true; do
                    read -rsp "$(L 'Portal 自签证书指纹 pin（64 位 hex，可从 Portal 机 Nowhere 菜单 10 查看，输入不回显，回车=暂不填）:') " eg_pin || { [ -n "$eg_pin" ] || return 1; }; echo
                    eg_pin=$(echo "$eg_pin" | tr -d ' \r\n' | tr 'A-F' 'a-f')
                    if [ -z "$eg_pin" ]; then
                        warn "$(L '未填 pin：自签证书走系统 CA 校验必然失败，服务会反复重连')"
                        read -rp "$(L '仍要继续（稍后需手动改 egress.env 补 pin）？')[y/N]: " EG_PIN_CONFIRM || { [ -n "$EG_PIN_CONFIRM" ] || return 1; }
                        [[ ! "$EG_PIN_CONFIRM" =~ ^[Yy]$ ]] && { info "$(L '已取消')"; return; }
                        break
                    fi
                    if [[ "$eg_pin" =~ ^[0-9a-f]{64}$ ]]; then
                        break
                    fi
                    warn "$(L 'pin 必须是 64 位小写十六进制字符')"
                done
                ;;
            *)
                read -rp "  $(L 'SNI（证书域名与回连地址不一致时填，回车=用回连地址）:') " eg_sni || { [ -n "$eg_sni" ] || return 1; }
                eg_sni=$(echo "$eg_sni" | tr -d ' \r\n')
                if [ -n "$eg_sni" ] && ! is_safe_host "$eg_sni"; then warn "$(L 'SNI 格式不合法，已忽略')"; eg_sni=""; fi
                ;;
        esac
        eg_dial_mode="single"; eg_dial="auto"; eg_dial4="auto"; eg_dial6="auto"
        echo ""
        read -rp "$(L 'Egress 到目标的出站源 IP dial（回车默认 auto，只影响目标连接，不影响回连 Portal）:') " eg_dial || { [ -n "$eg_dial" ] || return 1; }
        eg_dial=${eg_dial:-auto}
        validate_ip_or_auto "$eg_dial" any || { warn "$(L 'dial 不是合法 IP 字面量，已重置为 auto')"; eg_dial="auto"; }
        read -rp "$(L '是否改用 dial4/dial6 分别绑定 IPv4/IPv6 目标出站源地址？')[y/N]: " EG_DIAL46 || { [ -n "$EG_DIAL46" ] || return 1; }
        if [[ "$EG_DIAL46" =~ ^[Yy]$ ]]; then
            eg_dial_mode="dual"
            read -rp "  $(L 'dial4（IPv4 源地址，回车默认 auto）:') " eg_dial4 || { [ -n "$eg_dial4" ] || return 1; }
            eg_dial4=${eg_dial4:-auto}
            read -rp "  $(L 'dial6（IPv6 源地址，回车默认 auto）:') " eg_dial6 || { [ -n "$eg_dial6" ] || return 1; }
            eg_dial6=${eg_dial6:-auto}
            validate_ip_or_auto "$eg_dial4" 4 || { warn "$(L 'dial4 不是合法 IPv4 字面量，已重置为 auto')"; eg_dial4="auto"; }
            validate_ip_or_auto "$eg_dial6" 6 || { warn "$(L 'dial6 不是合法 IPv6 字面量，已重置为 auto')"; eg_dial6="auto"; }
            eg_dial="auto"
        fi
        read -rp "$(L '上行限速 Mbps（0=不限速）:') " eg_rate || { [ -n "$eg_rate" ] || return 1; }
        eg_rate=${eg_rate:-0}
        validate_rate "$eg_rate" || { warn "$(L '输入不合法，重置为 0')"; eg_rate=0; }
        read -rp "$(L '下行限速 Mbps（0=不限速）:') " eg_etar || { [ -n "$eg_etar" ] || return 1; }
        eg_etar=${eg_etar:-0}
        validate_rate "$eg_etar" || { warn "$(L '输入不合法，重置为 0')"; eg_etar=0; }
        read -rp "$(L '握手超时 NOW_HANDSHAKE_TIMEOUT（v3.3.0 起未设置时从 Shared Key 派生 3s–30s；持续时间格式如 10s/500ms/1m/1h，回车默认 10s）:') " eg_handshake || { [ -n "$eg_handshake" ] || return 1; }
        eg_handshake=${eg_handshake:-10s}
        validate_duration "$eg_handshake" || { warn "$(L '格式不合法（须为正数+单位，如 10s），已重置为 10s')"; eg_handshake="10s"; }
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
        echo -e "${BOLD}$(L 'Morph Prelude 策略')${NC}$(L '（Egress 是发起端，这个设置在本机生效；Portal 三种都收，两端无需一致）：')"
        echo "  1) $(L 'fade（默认）  2')) full8  3) low7"
        read -rp "$(L '选择') [$(L '1/2/3，默认1')]: " EG_PRELUDE_CHOICE || { [ -n "$EG_PRELUDE_CHOICE" ] || return 1; }
        case ${EG_PRELUDE_CHOICE:-1} in 2) eg_prelude="full8" ;; 3) eg_prelude="low7" ;; *) eg_prelude="fade" ;; esac
    fi

    echo ""
    divider
    echo -e "  $(L 'Portal 地址 :') ${GREEN}${eg_host}:${eg_port} (${eg_carrier}${eg_family})${NC}"
    echo -e "  $(L '共享密钥    :') ${GREEN}$(mask_secret "$eg_key")${NC}"
    echo -e "  Morph       : ${GREEN}${eg_morph}$([ "$eg_morph" = "1" ] && echo "（Prelude ${eg_prelude}）")${NC}"
    echo -e "  Egress URL  : ${GREEN}${eg_url/$eg_key/$(mask_secret "$eg_key")}${NC}"
    divider
    read -rp "$(L '确认安装为 Egress 服务') [y/N]: " EG_CONFIRM2 || { [ -n "$EG_CONFIRM2" ] || return 1; }
    [[ ! "$EG_CONFIRM2" =~ ^[Yy]$ ]] && { info "$(L '已取消')"; return; }
    step "$(L '安装系统依赖')"
    divider
    apt_install curl tar ca-certificates python3 || warn "$(L '部分依赖安装失败，继续尝试')"
    local need_download=1 have_ver=""
    if [ -x "$BIN_PATH" ]; then
        have_ver="$(${BIN_PATH} --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
        local have_major=""
        have_major="$(version_major "$have_ver")"
        if [ -z "$have_major" ] || [ "$have_major" -lt 3 ]; then
            warn "$(L '本机现有二进制版本过低或无法识别（需要 Nowhere v3 及以上），将下载最新版')"
        elif [ "$eg_carrier" = "tcp" ] && ! version_ge "${have_ver:-0}" "3.3.0"; then
            warn "$(L 'TLS 载体的 Egress 需要 Nowhere') ≥ $(L 'v3.3.0，本机现有二进制为') ${have_ver:-$(L '未知')}$(L '，将下载最新版')"
        else
            read -rp "$(L '已检测到 nowhere 二进制（')${have_ver:-$(L '未知版本')}$(L '），是否跳过下载直接使用？')[Y/n]: " EG_REUSE || { [ -n "$EG_REUSE" ] || return 1; }
            if [[ ! "${EG_REUSE:-y}" =~ ^[Nn]$ ]]; then
                need_download=0
                info "$(L '复用现有二进制:') $(${BIN_PATH} --version 2>&1 | head -1)"
            fi
        fi
    fi
    if [ "$need_download" = "1" ]; then
        install_nowhere_binary_only || { warn "$(L '二进制下载失败，安装中止')"; return; }
    fi
    step "$(L '保存 Egress 配置并创建 systemd 服务')"
    divider
    install -d -m 700 "$CONFIG_DIR"
    eg_handshake="${eg_handshake:-10s}"
    validate_duration "$eg_handshake" || eg_handshake="10s"
    sanitize_nowhere_params
    cat > "$EGRESS_CONFIG_FILE" << EGENVEOF
NOWHERE_EGRESS="${eg_url}"
EGRESS_PORTAL_HOST="${eg_host}"
EGRESS_PORTAL_PORT="${eg_port}"
EGRESS_CARRIER="${eg_carrier}"
EGRESS_MORPH="${eg_morph}"
NOW_HANDSHAKE_TIMEOUT="${eg_handshake}"
EGENVEOF
    chmod 600 "$EGRESS_CONFIG_FILE"
    setup_nowhere_user || true
    write_service_unit "$SERVICE_FILE" "Nowhere Egress" "https://github.com/${REPO}" "" "${NOWHERE_USER:-root}" "${NOWHERE_USER:-root}" "${BIN_PATH} \${NOWHERE_EGRESS}" "" "1048576" "on-failure" "3" "EnvironmentFile=${EGRESS_CONFIG_FILE}
Environment=NOW_MORPH_TCP_PRELUDE=${eg_prelude}
Environment=NOW_MORPH_UDP_PRELUDE=${eg_prelude}
PrivateTmp=false
ProtectSystem=full
ProtectHome=read-only"
    echo "egress" > "$ROLE_FILE"
    restart_nowhere_with_fallback 0 || true
    if systemctl is-active --quiet nowhere; then
        success "$(L 'Egress 服务已启动（注册结果请看日志：ACCEPTED 为成功；BUSY 表示 Portal 的待命注册容量已满（主要出现在 TLS 载体），本机会自动重试）')"
    else
        warn "$(L 'Egress 服务未能启动，日志如下：')"
        journalctl -u nowhere -n 30 --no-pager || true
        warn "$(L '安装中止：请按日志排查（常见：密钥 / pin / 端口 / Portal 未设 out=egress / 载体与 Portal 监听不对应）')"
        return
    fi
    cat > "$EGRESS_CONFIG_TXT" << EGCONFEOF
════════════════════════════════════════════════════════════════
  $(L 'Nowhere Egress 连接信息（')${TARGET_NW_VERSION} $(L '/ NW3）')
  $(L '更新时间:') $(date '+%Y-%m-%d %H:%M:%S')
════════════════════════════════════════════════════════════════

$(L '【出口机启动参数（Egress URL，用于 systemd ExecStart）】')
${eg_url}

$(L '【说明】')
  $(L 'Portal 地址 :') ${eg_host}:${eg_port} (${eg_carrier}${eg_family})
  Morph       : ${eg_morph}$(L '（须与 Portal 一致）')$([ "$eg_morph" = "1" ] && echo "，Prelude 策略 ${eg_prelude}")
  $(L '握手超时    :') ${eg_handshake}$(L '（NOW_HANDSHAKE_TIMEOUT，v3.3.0 起未设置时从 Shared Key 派生 3s–30s）')
  $(L '本机角色    : Egress（主动回连 Portal，无需本机开放入站端口）')
  $(L 'v3.3.0 起同一 Portal 可同时接受多台 Egress（TLS / QUIC 可混用，Portal 按先进先出轮转，不保证均衡）。')
  $(L 'TLS 载体下每条 Flow 独占一条连接，本机会自动预建待命连接；BUSY 表示 Portal 的待命容量已满。')
  $(L 'tls=1 时 pin 随 Portal 重启变化，Portal 重启后需在本机更新 egress.env 里的 pin 并重启服务。')
════════════════════════════════════════════════════════════════
EGCONFEOF
    chmod 600 "$EGRESS_CONFIG_TXT"
    cat "$EGRESS_CONFIG_TXT"
    if [ -n "$old_portal_specs" ] && ufw_installed; then
        echo ""
        if confirm "$(L '本机不再是 Portal：删除防火墙里原 Portal 端口的放行规则（')$(echo $old_portal_specs)$(L '）？')" y; then
            local ops
            while IFS= read -r ops; do
                [ -n "$ops" ] || continue
                if [ "$ops" = "80/tcp" ] && xray_needs_port80; then continue; fi
                fw_delete_spec "$ops"
            done < <(printf '%s\n' "$old_portal_specs" | tr ' ' '\n' | grep -v '^$')
        fi
    fi
    echo ""
    info "$(L '常用命令：systemctl status nowhere / journalctl -u nowhere -f /') ${MANAGER_PATH} status"
    install_shortcuts || true
    verify_shortcuts || true
}

# Xray 是否还在用 Cloudflare 凭证（有 xhttp-tls 域名证书节点即依赖它续期）
xray_uses_cf_creds() {
    [ -n "${XRAY_NODE_DIR:-}" ] && [ -d "$XRAY_NODE_DIR" ] || return 1
    grep -l 'N_TYPE="xhttp-tls"' "${XRAY_NODE_DIR}"/*.env >/dev/null 2>&1
}

# xray_needs_port80：Xray 任一节点证书由 certbot standalone（HTTP-01）签发时，续期仍需 80 端口（L10）
xray_needs_port80() {
    local f dom
    [ -n "${XRAY_NODE_DIR:-}" ] && [ -d "$XRAY_NODE_DIR" ] || return 1
    for f in "${XRAY_NODE_DIR}"/*.env; do
        [ -f "$f" ] || continue
        dom="$(sed -n 's#^N_CERT_SRC="/etc/letsencrypt/live/\([^/]*\)/.*#\1#p' "$f" | head -1)"
        [ -n "$dom" ] || continue
        if grep -q '^authenticator *= *standalone' "/etc/letsencrypt/renewal/${dom}.conf" 2>/dev/null; then return 0; fi
    done
    return 1
}

# Xray 任一节点证书来源是否指向 acme.sh（M5：删 acme.sh cron 前先查）
xray_uses_acmesh() {
    [ -n "${XRAY_NODE_DIR:-}" ] && [ -d "$XRAY_NODE_DIR" ] || return 1
    grep -rl 'acme\.sh' "${XRAY_NODE_DIR}"/*.env >/dev/null 2>&1
}

do_uninstall() {
    maint_lock_manual || return
    step "$(L '卸载 Nowhere')"
    divider
    read -rp "$(L '确认卸载') [y/N]: " CONFIRM || { [ -n "$CONFIRM" ] || return 1; }
    [[ ! "$CONFIRM" =~ ^[Yy]$ ]] && { info "$(L '已取消')"; return; }
    local old_specs s cron_now
    old_specs="$(nowhere_ports 2>/dev/null || true)"
    systemctl disable --now nowhere 2>/dev/null || true
    local _had_deploy_hook=0
    [ -x /etc/letsencrypt/renewal-hooks/deploy/restart-nowhere.sh ] && _had_deploy_hook=1
    rm -f "$SERVICE_FILE" "$BIN_PATH" "$BIN_BACKUP_PATH" "$ROLE_FILE" "${CONFIG_DIR}/cert-sync.sh"
    rm -f /etc/letsencrypt/renewal-hooks/deploy/restart-nowhere.sh           /etc/letsencrypt/renewal-hooks/pre/stop-nowhere.sh           /etc/letsencrypt/renewal-hooks/post/start-nowhere.sh           /run/nowhere-stopped-by-certbot
    cron_now="$(crontab -l 2>/dev/null || true)"
    # 卸载前若存在本脚本的 deploy hook 且无 Xray 续期依赖，则清理 certbot renew 兜底 cron
    if [ "$_had_deploy_hook" = "1" ] && ! xray_needs_port80 && ! xray_uses_cf_creds; then
        if [[ "$cron_now" == *"certbot renew"* ]]; then
            printf '%s\n' "$cron_now" | grep -v 'certbot renew' | crontab - || true
            info "$(L '已移除 certbot 续期的 cron 兜底任务')"
        fi
    elif [[ "$cron_now" == *"certbot renew --quiet --deploy-hook"* ]]; then
        printf '%s\n' "$cron_now" | grep -v 'certbot renew --quiet --deploy-hook' | crontab - || true
        info "$(L '已移除 certbot 续期的 cron 兜底任务')"
    fi
    # acme.sh cron：Xray 仍在用 acme.sh 续期时保留，否则删除
    if [[ "$cron_now" == *"acme.sh"*"--cron"* ]]; then
        if xray_uses_acmesh; then
            warn "$(L 'Xray 仍在使用 acme.sh 续期，已保留 acme.sh 的 cron 任务')"
        else
            printf '%s\n' "$cron_now" | grep -v 'acme.sh.*--cron' | crontab - || true
            info "$(L '已移除 acme.sh 的 cron 续期任务')"
        fi
    fi
    if [ -d "$ACME_HOME" ]; then
        warn "$(L 'acme.sh 目录仍保留，如确认不再需要请手动删除：rm -rf ~/.acme.sh')"
    fi
    if [ -n "$old_specs" ] && ufw_installed; then
        if confirm "$(L '同时删除防火墙里 Nowhere 端口的放行规则（')$(echo $old_specs)$(L '）？')" y; then
            while IFS= read -r s; do
                [ -n "$s" ] || continue
                if [ "$s" = "80/tcp" ] && xray_needs_port80; then continue; fi
                fw_delete_spec "$s"
            done < <(printf '%s\n' "$old_specs" | tr ' ' '\n' | grep -v '^$')
        fi
    fi
    if [ -f /etc/cloudflare/credentials.ini ]; then
        if xray_uses_cf_creds; then
            warn "$(L 'Cloudflare 凭证仍被 Xray 域名证书节点使用（xhttp-tls，续期也依赖它），未删除；如 Xray 已卸载或不再用该凭证，请手动删除')"
        elif confirm "$(L '删除保存的 Cloudflare API 凭证（/etc/cloudflare/credentials.ini）？')" n; then
            rm -f /etc/cloudflare/credentials.ini
            info "$(L '已删除 Cloudflare 凭证')"
        fi
    fi
    if realm_installed || [ -d "$REALM_DIR" ] || [ -f "$REALM_SERVICE" ]; then
        if confirm "$(L '是否同时卸载 Realm 端口转发？')" n; then
            realm_uninstall_do
        fi
    fi
    if caddy_installed || cf_tunnel_installed || [ -d "$CADDY_DIR" ] || [ -d "$CF_TUNNEL_DIR" ]; then
        if confirm "$(L '是否同时卸载域名反代（Caddy / Cloudflare Tunnel）？')" n; then
            caddy_uninstall_do || true
            cf_tunnel_uninstall_do || true
        fi
    fi
    read -rp "$(L '是否同时删除快捷命令 adam/zt/pz/cxpz/cq？')[y/N]: " RM_SHORTCUTS || { [ -n "$RM_SHORTCUTS" ] || return 1; }
    if [[ "$RM_SHORTCUTS" =~ ^[Yy]$ ]]; then
        if [ -x "$SNELL_BIN" ] || [ -x "$XRAY_BIN" ] || ufw_installed || f2b_installed; then
            warn "$(L '删除后 Snell / Xray / 防火墙 / Fail2ban 的管理入口需改用') ${MANAGER_PATH} $(L '直接运行（Snell 自动更新不受影响）')"
        fi
        rm -f /usr/local/bin/adam /usr/local/bin/zt /usr/local/bin/pz /usr/local/bin/cxpz /usr/local/bin/cq
        info "$(L '快捷命令已删除（管理脚本副本') ${MANAGER_PATH} $(L '已保留，如需清除请手动删除）')"
    fi
    systemctl daemon-reload
    warn "$(L '已保留') ${CONFIG_DIR}$(L '（含密钥配置与证书文件），如需彻底清除请手动: rm -rf') ${CONFIG_DIR}"
    success "$(L 'Nowhere 已卸载')"
}

do_update() {
    maint_lock_manual || return
    step "$(L '更新 Nowhere 二进制（更新到最新版）')"
    divider
    local current
    current="$(read_installed_version)"
    info "$(L '当前版本:') ${current}"
    info "$(L '正在获取最新版本号...')"
    local latest
    latest="$(get_latest_tag)"
    [ -z "$latest" ] && error "$(L '无法获取版本号（GitHub API 与 releases/latest 跳转均失败），请检查网络')"
    info "$(L '最新版本:') ${latest}"

    if [ "$current" = "$latest" ]; then
        info "$(L '已经是最新版本，无需更新')"
        return
    fi

    local cur_major latest_major cross_major=0
    cur_major="$(version_major "$current")"
    latest_major="$(version_major "$latest")"
    if [[ -n "$cur_major" && -n "$latest_major" && "$cur_major" != "$latest_major" ]]; then
        cross_major=1
        warn "$(L '这是跨协议代升级（NW')${cur_major} -> NW${latest_major}$(L '）：新旧对端不互通，Vector/Egress/Anywhere 必须一起升级')"
        warn "$(L '且不同协议代的密钥格式、URL 参数可能不兼容，仅换二进制不重配大概率启动失败或连不上')"
        read -rp "$(L '确认跨代升级') [y/N]: " MAJOR_CONFIRM || { [ -n "$MAJOR_CONFIRM" ] || return 1; }
        [[ ! "$MAJOR_CONFIRM" =~ ^[Yy]$ ]] && { info "$(L '已取消')"; return; }
    elif [ "$(current_role)" = "portal" ] && version_ge "$latest" "v3.2.0" && ! version_ge "$current" "v3.2.0"; then
        warn "$(L '本次升级会跨过 v3.2.0：此后 Portal 只接受带认证的 Morph TCP Prelude，仍在 v3.0.x 的 Vector/Egress/Anywhere（morph=1 + TLS/TCP）会连不上')"
        warn "$(L '稳妥做法：先把对端升级到') ≥ $(L 'v3.1.0，再升级本机 Portal')"
        read -rp "$(L '对端已就绪，继续升级') [y/N]: " PRELUDE_CONFIRM || { [ -n "$PRELUDE_CONFIRM" ] || return 1; }
        [[ ! "$PRELUDE_CONFIRM" =~ ^[Yy]$ ]] && { info "$(L '已取消')"; return; }
    fi

    install_nowhere_version "$latest" || error "$(L '更新失败')"
    if [ "$cross_major" = "1" ]; then
        warn "$(L '跨代升级后请接着用Nowhere 菜单「3')) $(L '重新配置」按新版向导重建配置（新密钥 + 新 URL），再同步更新所有对端')"
    fi
}


# Nowhere 定时自动更新（仅限 NW3 同大版本，不跨代；校验 SHA256 + 预检 + 失败自动回滚）
nowhere_autoupdate() {
    [ -x "$BIN_PATH" ] || return 0
    local current latest cur_major latest_major
    current="$(read_installed_version)"
    latest="$(get_latest_tag)"
    if [ -z "$latest" ]; then
        echo "[Nowhere] $(L '未能获取官方版本信息，本次跳过；当前') ${current:-$(L '未知')}"
        return 1
    fi
    cur_major="$(version_major "$current")"
    latest_major="$(version_major "$latest")"
    if [ -n "$latest_major" ] && [ "$latest_major" != "3" ]; then
        echo "[Nowhere] $(L '最新版本属于另一个大版本（v')${latest_major}$(L '），不自动跨大版本，当前') ${current:-$(L '未知')}"
        return 0
    fi
    if [ -n "$cur_major" ] && [ "$cur_major" != "3" ]; then
        echo "[Nowhere] $(L '当前安装的是') ${current:-$(L '未知')}$(L '，不自动跨大版本')"
        return 0
    fi
    if [ -n "$current" ] && [ "$current" = "$latest" ]; then
        echo "[Nowhere] $(L '已是最新:') ${current}"
        return 0
    fi
    if [ -n "$current" ] && version_ge "$current" "$latest"; then
        echo "[Nowhere] $(L '已是最新:') ${current}"
        return 0
    fi
    # 跨 v3.2.0 存在 Authenticated Prelude 兼容要求，定时任务跳过并提示手动升级
    if [ "$(current_role)" = "portal" ] && [ -n "$current" ] && version_ge "$latest" "v3.2.0" && ! version_ge "$current" "v3.2.0"; then
        maint_log "[Nowhere] 发现 ${latest}（跨 v3.2.0 需先升级对端），跳过自动更新"
        return 0
    fi
    echo "[Nowhere] $(L '发现新版本:') ${current:-$(L '未知')} -> ${latest}$(L '，开始更新')"
    if install_nowhere_version "$latest"; then
        save_current_pin >/dev/null 2>&1 || true
        maint_log "[Nowhere] $(L '已自动更新:') ${current:-$(L '未知')} -> ${latest}"
        return 0
    fi
    maint_log "[Nowhere] $(L '自动更新到') ${latest} $(L '失败，当前仍为') $(read_installed_version)"
    return 1
}

do_show_version() {
    step "$(L '版本信息')"
    divider
    local current previous
    current="$(read_installed_version)"
    previous="$(read_previous_version)"

    if [ -x "$BIN_PATH" ]; then
        echo -e "  $(L '当前运行的二进制  :') ${GREEN}$(${BIN_PATH} --version 2>&1 | head -1)${NC}"
    else
        warn "$(L '未检测到已安装的 Nowhere 二进制')"
    fi
    echo -e "  $(L '记录的版本 tag    :') ${GREEN}${current}${NC}"
    [ -n "$previous" ] && echo -e "  $(L '上一个版本 tag    :') ${YELLOW}${previous}${NC}$(L '（可用「版本回退」快速切回）')"
    echo -e "  $(L '本机角色          :') ${GREEN}$(current_role)${NC}"
    echo -e "  $(L '管理脚本版本      :') ${GREEN}${SCRIPT_VERSION}${NC}$(L '（适配 Nowhere') ${TARGET_NW_VERSION}$(L '）')"

    echo ""
    info "$(L '正在查询 GitHub 最新版本...')"
    local latest
    latest="$(get_latest_tag)"
    if [ -n "$latest" ]; then
        if [ "$current" = "$latest" ]; then
            success "$(L '已是最新版本') (${latest})"
        else
            warn "$(L '有新版本可用:') ${latest}$(L '（当前') ${current}$(L '），可用 Nowhere 菜单「13')) $(L '更新 Nowhere 二进制」升级')"
        fi
    else
        warn "$(L '无法查询最新版本，请检查网络')"
    fi
}

do_select_version() {
    step "$(L '选择要安装的版本（支持回退到历史版本）')"
    divider
    local current
    current="$(read_installed_version)"
    info "$(L '当前版本:') ${current}"
    info "$(L '正在获取版本列表...')"

    local tags=()
    while IFS= read -r line; do
        tags+=("$line")
    done < <(curl -fs --max-time 20 "https://api.github.com/repos/${REPO}/releases?per_page=20" | grep '"tag_name"' | cut -d'"' -f4)

    if [ "${#tags[@]}" -eq 0 ]; then
        error "$(L '未能获取版本列表，请检查网络')$(L '（可能被 GitHub 限流，请稍后重试）')"
    fi

    echo ""
    local i=1
    for t in "${tags[@]}"; do
        if [ "$t" = "$current" ]; then
            echo -e "  ${BOLD}${i})${NC} ${t}  ${GREEN}← $(L '当前版本')${NC}"
        else
            echo -e "  ${BOLD}${i})${NC} ${t}"
        fi
        i=$((i+1))
    done
    echo -e "  ${BOLD}0)${NC} $(L '取消')"
    divider
    read -rp "$(L '选择要切换到的版本序号:') " VER_CHOICE || { [ -n "$VER_CHOICE" ] || return 1; }

    [[ "$VER_CHOICE" == "0" || -z "$VER_CHOICE" ]] && { info "$(L '已取消')"; return; }
    if ! [[ "$VER_CHOICE" =~ ^[0-9]+$ ]] || [ "$VER_CHOICE" -lt 1 ] || [ "$VER_CHOICE" -gt "${#tags[@]}" ]; then
        warn "$(L '无效选择')"
        return
    fi

    local target="${tags[$((VER_CHOICE-1))]}"
    if [ "$target" = "$current" ]; then
        info "$(L '已经是该版本，无需切换')"
        return
    fi

    read -rp "$(L '确认切换到') ${target} [y/N]: " CONFIRM || { [ -n "$CONFIRM" ] || return 1; }
    [[ ! "$CONFIRM" =~ ^[Yy]$ ]] && { info "$(L '已取消')"; return; }

    install_nowhere_version "$target" || error "$(L '切换失败，服务可能未正常启动，请检查日志')"
}

do_rollback() {
    step "$(L '版本回退')"
    divider
    if [ ! -f "$BIN_BACKUP_PATH" ]; then
        warn "$(L '没有可用于回退的本地备份版本')"
        info "$(L '备份仅在执行过「更新」或「选择版本」之后才会生成')"
        return
    fi

    local current previous
    current="$(read_installed_version)"
    previous="$(read_previous_version)"
    echo -e "  $(L '当前版本 :') ${GREEN}${current}${NC}"
    echo -e "  $(L '回退目标 :') ${YELLOW}${previous:-$(L '未知版本（本地备份二进制）')}${NC}"
    divider
    read -rp "$(L '确认回退') [y/N]: " CONFIRM || { [ -n "$CONFIRM" ] || return 1; }
    [[ ! "$CONFIRM" =~ ^[Yy]$ ]] && { info "$(L '已取消')"; return; }

    if ! "$BIN_BACKUP_PATH" --version >/dev/null 2>&1; then
        warn "$(L '新二进制试运行失败')"
        info "$(L '备份二进制无法运行，回退已中止')"
        return 1
    fi

    local tmp_bin rolled_to
    make_workdir || return 1
    tmp_bin="${WORKDIR}/nowhere.swap"
    cp "$BIN_PATH" "$tmp_bin" || { warn "$(L '备份当前二进制失败，回退中止')"; return 1; }

    _CACHED_TLS_FP=""
    # install 直接替换运行中的二进制，随后一次 restart 完成切换（与 install_nowhere_version 一致，
    # 比旧版 stop -> 替换 -> start 少一段停机窗口）；任一步失败即中止，避免半交换状态
    install -m 755 "$BIN_BACKUP_PATH" "$BIN_PATH" || { warn "$(L '回退替换失败，当前二进制未动')"; return 1; }
    install -m 755 "$tmp_bin" "$BIN_BACKUP_PATH" || { install -m 755 "$tmp_bin" "$BIN_PATH" 2>/dev/null || true; warn "$(L '备份交换失败，已尽力恢复原二进制')"; return 1; }
    rm -f "$tmp_bin"

    record_previous_version "$current"
    # 回滚后以实际安装的二进制版本为准；版本文件只写版本号，不写本地化文案
    rolled_to="$("$BIN_PATH" --version 2>&1 | grep -oE 'v?[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
    case "$rolled_to" in v*) : ;; [0-9]*) rolled_to="v$rolled_to" ;; esac
    [ -z "$rolled_to" ] && rolled_to="$previous"
    [ -n "$rolled_to" ] && echo "$rolled_to" > "$VERSION_FILE"

    systemctl restart nowhere 2>/dev/null || true
    sleep 2
    if systemctl is-active --quiet nowhere; then
        success "$(L '已回退到:') $(${BIN_PATH} --version 2>&1 | head -1)"
    else
        warn "$(L '回退后服务启动失败，日志如下：')"
        journalctl -u nowhere -n 20 --no-pager || true
    fi
}

do_reconfig() {
    step "$(L '重新配置')"
    divider
    warn "$(L '将重新走一遍安装向导并覆盖当前配置')"
    warn "$(L '注意：v3 密钥与 URL 语法已变更，重新配置后务必把新的 Vector/Egress/Anywhere 连接信息同步到所有对端，旧链接无法继续使用')"
    read -rp "$(L '确认继续') [y/N]: " CONFIRM || { [ -n "$CONFIRM" ] || return 1; }
    [[ ! "$CONFIRM" =~ ^[Yy]$ ]] && return
    do_install
}

do_show_config() {
    step "$(L '连接信息')"
    divider
    if [ "$(current_role)" = "egress" ]; then
        if [ -f "$EGRESS_CONFIG_TXT" ]; then
            cat "$EGRESS_CONFIG_TXT"
        else
            warn "$(L '本机为 Egress 角色，但未找到') ${EGRESS_CONFIG_TXT}$(L '，请用 Nowhere 菜单 2 重新安装')"
        fi
        return 0
    fi
    if [ -f "$CONFIG_FILE" ]; then
        load_saved_config
        _CACHED_TLS_FP=""
        # 每次查看都按当前保存参数重新生成（含最新自签 pin），避免展示过期指纹的旧串
        NOWHERE_PORTAL="$(build_portal_url)"
        build_client_links
        build_vector_info
        build_egress_info
        print_all_info
        save_current_pin >/dev/null 2>&1 || true
    elif [ -f "${CONFIG_DIR}/config.txt" ]; then
        cat "${CONFIG_DIR}/config.txt"
    else
        warn "$(L '未找到配置，请先安装')"
    fi
}

do_show_status() {
    step "$(L '服务状态')"
    divider
    # systemctl status 在服务停止时返回非 0：旧版在 set -e 下会在这里直接退出，
    # 恰好是服务挂了、最需要看后面日志的时候
    systemctl status nowhere --no-pager || true
    divider
    if [ -x "$BIN_PATH" ]; then
        info "$(L 'Nowhere 本地实例快照（nowhere status，v3 内置遥测）：')"
        "$BIN_PATH" status 2>&1 || warn "$(L 'nowhere status 未能读取到实例（服务未运行，或二进制版本低于 v2.1.2 无此命令）')"
        divider
    fi
    info "$(L '最近日志（20行）：')"
    journalctl -u nowhere -n 20 --no-pager || true
}

do_show_logs() {
    step "$(L '实时日志（Ctrl+C 退出）')"
    divider
    journalctl -u nowhere -f || true
}

do_fingerprint() {
    if [ "$(current_role)" = "egress" ]; then
        info "$(L '本机是 Egress 角色，没有监听证书；Portal 的证书指纹请在 Portal 机上查看')"
        return 0
    fi
    load_saved_config
    print_tls_fingerprint
}

do_restart() {
    _CACHED_TLS_FP=""
    if svc_restart_wait nowhere 1 15; then
        success "$(L '已重启')"
    else
        error "$(L '重启失败，请按上方日志排查')"
    fi
    if [ "$(current_role)" = "egress" ] || [ ! -f "$CONFIG_FILE" ]; then
        return 0
    fi
    load_saved_config
    print_tls_fingerprint
    if [[ "${TLS_MODE:-}" == "1" ]]; then
        save_current_pin || true
        warn "$(L '自签证书指纹已随本次重启变化，请用 pz / Nowhere 菜单 4 重新生成带新 pin= 的 Vector/Egress 连接串并同步到对端')"
    fi
    return 0
}

do_genkey() {
    step "$(L '生成 v3 共享密钥')"
    divider
    local k
    k="$(gen_key)"
    if is_valid_key "$k"; then
        echo -e "  ${GREEN}${k}${NC}"
        info "$(L '格式：32 位小写十六进制（16 随机字节）。Portal、Vector、Egress、Anywhere 四端必须填完全相同的这串字符')"
    else
        error "$(L '生成失败：openssl 与 nowhere 二进制均不可用')"
    fi
}

do_probe() {
    step "$(L '连通性探测 probe（真实 TCP Flow，不发送业务数据）')"
    divider
    [ -x "$BIN_PATH" ] || error "$(L '未找到 Nowhere 二进制，请先安装')"
    if [ "$(current_role)" = "egress" ]; then
        info "$(L '本机是 Egress 角色：probe 需要以 Vector 身份连接 Portal，请在 Portal 机或客户端机上执行')"
        return 0
    fi
    load_saved_config
    is_valid_key "$SHARED_KEY" || error "$(L '当前密钥不符合 v3 规范，无法探测，请先用 Nowhere 菜单 3 重新配置')"
    local vector_url target
    vector_url="$(build_probe_vector_url || true)"
    [ -n "$vector_url" ] || error "$(L '未能确定公网地址，无法生成 Vector 探针链接')"
    read -rp "$(L '目标地址 host:port（回车默认 example.com:443）:') " target || { [ -n "$target" ] || return 1; }
    target=${target:-example.com:443}
    info "Vector: ${vector_url/$SHARED_KEY/$(mask_secret "$SHARED_KEY")}"
    info "Target: ${target}"
    export NOW_MORPH_TCP_PRELUDE="${MORPH_TCP_PRELUDE:-fade}"
    export NOW_MORPH_UDP_PRELUDE="${MORPH_UDP_PRELUDE:-fade}"
    export NOW_HANDSHAKE_TIMEOUT="${HANDSHAKE_TIMEOUT:-10s}"
    "$BIN_PATH" probe "$vector_url" "$target" || warn "$(L '探测未成功（Result 非 OK）。常见原因：Portal 出口不可达、没有可用的 Egress（会等到 Flow 建立超时）、对端 Morph/pin/密钥不一致、目标本身不可达')"
}

# svc_restart_wait UNIT [SECONDS] [LOG_LINES]：重启 → 等待 → 仍未 active 则打日志并返回 1（M14）
svc_restart_wait() {
    local unit="$1" secs="${2:-2}" lines="${3:-20}"
    systemctl restart "$unit" 2>/dev/null || true
    sleep "$secs"
    if systemctl is-active --quiet "$unit" 2>/dev/null; then return 0; fi
    journalctl -u "$unit" -n "$lines" --no-pager 2>/dev/null || true
    return 1
}

do_migrate_tls2() {
    step "$(L 'tls=1 升级为真实证书') (tls=2)"
    divider
    local MIG_BAK=""
    if [ "$(current_role)" != "portal" ]; then
        warn "$(L '本机不是 Portal 角色（当前：')$(current_role)$(L '），无需迁移证书')"
        return 0
    fi
    [ -f "$CONFIG_FILE" ] || error "$(L '未找到配置文件，请先执行安装')"
    load_saved_config
    if [ "${TLS_MODE:-}" != "1" ]; then
        info "$(L '当前已是 tls=2 真实证书模式，无需迁移（证书状态见 Nowhere 菜单 11）')"
        return 0
    fi
    warn "$(L '迁移后 Portal 改用域名 + CA 证书（tls=2），Vector/Egress 不再需要 pin=；')"
    warn "$(L '旧的 pin= 连接串随即失效，需用新生成的连接串同步所有对端。')"
    echo ""
    echo "  1) Let'$(L 's Encrypt HTTP-01 - 需要域名解析到本机 + 开放 80 端口（自动续期）')"
    echo "  2) $(L 'Cloudflare DNS-01 - 需要 CF API Key/Token（自动续期，推荐；80 端口可不开）')"
    echo "  $(L '（通用 DNS-01 / acme.sh 请用 Nowhere 菜单 3 重新配置）')"
    read -rp "$(L '选择') [$(L '1/2，回车取消')]: " MIG_METHOD || { [ -n "$MIG_METHOD" ] || return 1; }
    case "$MIG_METHOD" in
        1) MIG_CERT_METHOD="letsencrypt-http" ;;
        2) MIG_CERT_METHOD="cloudflare-dns" ;;
        *) info "$(L '已取消')"; return 0 ;;
    esac
    read -rp "$(L '域名（须已解析到本机）:') " MIG_DOMAIN || { [ -n "$MIG_DOMAIN" ] || return 1; }
    MIG_DOMAIN=$(echo "$MIG_DOMAIN" | tr -d ' \r\n')
    MIG_DOMAIN="${MIG_DOMAIN,,}"
    if [ -z "$MIG_DOMAIN" ] || ! is_safe_host "$MIG_DOMAIN"; then error "$(L '域名不合法，已中止')"; fi
    read -rp "$(L 'ACME 邮箱（Let')'$(L 's Encrypt 账户用）:') " MIG_EMAIL || { [ -n "$MIG_EMAIL" ] || return 1; }
    MIG_EMAIL=$(echo "$MIG_EMAIL" | tr -d ' \r\n')
    [ -n "$MIG_EMAIL" ] || error "$(L '邮箱不能为空，已中止')"
    if [ "$MIG_CERT_METHOD" = "cloudflare-dns" ]; then
        prompt_cloudflare_creds || error "$(L 'Cloudflare 凭证未提供，已中止')"
    fi
    read -rp "$(L '确认把') ${MIG_DOMAIN} $(L '的证书装到本 Portal 并重启服务？')[y/N]: " MIG_CONFIRM || { [ -n "$MIG_CONFIRM" ] || return 1; }
    [[ "$MIG_CONFIRM" =~ ^[Yy]$ ]] || { info "$(L '已取消')"; return 0; }

    DOMAIN="$MIG_DOMAIN"; PUBLIC_HOST="$MIG_DOMAIN"; EMAIL="$MIG_EMAIL"
    CERT_METHOD="$MIG_CERT_METHOD"; TLS_MODE="2"
    CRT="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
    KEY_PEM="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
    apt_install certbot || error "$(L 'certbot 安装失败')"
    [ "$CERT_METHOD" = "cloudflare-dns" ] && apt_install python3-certbot-dns-cloudflare
    ensure_ipv4_preference
    if [ "$CERT_METHOD" = "letsencrypt-http" ]; then
        check_domain_dns "$DOMAIN" || true
    fi
    obtain_portal_cert

    # 同步保存的配置：域名 / TLS 模式 / 证书路径 / 重建的 Portal URL / 握手超时（整文件重写，与 do_install 一致）
    # 低权用户运行时：先把新证书同步到服务可读的副本，再生成 URL（URL 里嵌证书路径）
    if grep -q '^User=nowhere' "$SERVICE_FILE" 2>/dev/null; then
        sync_portal_cert_copy || warn "$(L '证书副本同步失败，服务可能无法读取新证书')"
    fi
    NOWHERE_PORTAL="$(build_portal_url)"
    MIG_BAK="${CONFIG_FILE}.bak.$(date +%Y%m%d-%H%M%S)"
    cp -f "$CONFIG_FILE" "$MIG_BAK" 2>/dev/null || warn "$(L '旧配置备份失败，迁移继续（失败时无法自动恢复）')"
    write_portal_env || error "$(L '配置保存失败，已中止')"
    # 旧 unit 可能没有握手超时行（v4.4 之前装的）：有则不动，没有则补上
    if [ -f "$SERVICE_FILE" ] && ! grep -q 'NOW_HANDSHAKE_TIMEOUT' "$SERVICE_FILE"; then
        sed -i "/^EnvironmentFile=/a Environment=NOW_HANDSHAKE_TIMEOUT=${HANDSHAKE_TIMEOUT}" "$SERVICE_FILE"
    fi
    systemctl daemon-reload
    _CACHED_TLS_FP=""
    if svc_restart_wait nowhere 2 15; then
        success "$(L '迁移完成：已是 tls=2，服务运行中')"
    else
        warn "$(L '迁移重启失败，已恢复旧配置并再次重启，请按日志排查')"
        if [ -n "$MIG_BAK" ] && [ -f "$MIG_BAK" ]; then cp -f "$MIG_BAK" "$CONFIG_FILE"; fi
        if svc_restart_wait nowhere 2 15; then
            warn "$(L '已恢复旧配置，服务已恢复运行（仍为 tls=1）')"
            return 1
        fi
        error "$(L '迁移失败：已恢复旧配置，但服务仍未启动，请按上方日志排查')"
    fi
    rm -f "$TLS_PIN_FILE"
    load_saved_config
    NOWHERE_PORTAL="$(build_portal_url)"
    build_client_links; build_vector_info; build_egress_info
    print_all_info
    warn "$(L '请把上面新的连接串同步到全部 Vector / Egress / Anywhere 对端，旧 pin= 连接串已失效')"
}

do_cert_status() {
    step "$(L '证书状态与续期')"
    divider
    if [ "$(current_role)" = "egress" ]; then
        info "$(L '本机是 Egress 角色，不持有监听证书，无需续期')"
        return 0
    fi
    [ -f "$CONFIG_FILE" ] || error "$(L '未找到配置文件，请先执行安装')"
    load_saved_config
    if [ "$TLS_MODE" != "2" ]; then
        info "$(L '当前为自签模式（tls=1），证书只存在内存中、无需续期')"
        return
    fi
    echo -e "  $(L '域名       :') ${GREEN}${DOMAIN}${NC}"
    echo -e "  $(L '证书路径   :') ${GREEN}${CRT}${NC}"
    echo -e "  $(L '申请方式   :') ${GREEN}${CERT_METHOD}${NC}"
    local days
    days="$(cert_expiry_days "$CRT" 2>/dev/null || echo "")"
    if [ -n "$days" ]; then
        if [ "$days" -lt 0 ]; then
            warn "$(L '证书已过期') $((-days)) $(L '天！请立即手动续期')"
        elif [ "$days" -le 30 ]; then
            warn "$(L '证书剩余') ${days} $(L '天（30 天内到期），建议立即手动续期')"
        else
            success "$(L '证书有效，剩余约') ${days} $(L '天')"
        fi
    else
        warn "$(L '无法读取证书有效期（文件缺失或损坏），建议重新签发')"
    fi
    echo ""
    info "$(L '自动续期链路检查：')"
    case "$CERT_METHOD" in
        letsencrypt-http|cloudflare-dns)
            if systemctl is-active --quiet certbot.timer 2>/dev/null; then
                success "$(L 'certbot.timer 运行中')"
            elif crontab -l 2>/dev/null | grep -q 'certbot renew'; then
                success "$(L 'cron 兜底续期任务存在')"
            else
                warn "$(L '未发现有效的自动续期任务！')"
            fi
            [ -x /etc/letsencrypt/renewal-hooks/deploy/restart-nowhere.sh ] \
                && success "$(L '续期 deploy hook 存在（续期后自动重启 nowhere）')" \
                || warn "$(L '续期 deploy hook 缺失（续期后不会自动重启 nowhere）')"
            ;;
        letsencrypt-dns)
            if crontab -l 2>/dev/null | grep -q 'acme.sh.*--cron'; then
                success "$(L 'acme.sh cron 续期任务存在')"
            else
                warn "$(L '未发现 acme.sh 自动续期任务！')"
            fi
            ;;
    esac
    echo ""
    read -rp "$(L '是否立即手动触发一次续期检查？（仅当证书满足续期条件时才会真的续签）')[y/N]: " DO_RENEW || { [ -n "$DO_RENEW" ] || return 1; }
    if [[ "$DO_RENEW" =~ ^[Yy]$ ]]; then
        case "$CERT_METHOD" in
            letsencrypt-http|cloudflare-dns)
                certbot renew && systemctl restart nowhere && success "$(L '续期检查完成')" \
                    || warn "$(L '续期失败，请看上方报错')"
                ;;
            letsencrypt-dns)
                "${ACME_HOME}/acme.sh" --renew -d "${DOMAIN}" && success "$(L '续期检查完成（acme.sh 的 --reloadcmd 会自动重启 nowhere）')" \
                    || warn "$(L '续期失败，请看上方报错')"
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
        warn "$(L '尚未安装 ufw，请先在防火墙菜单执行「1')) $(L '安装防火墙」（或 adam fw install）')"
        return 1
    fi
    return 0
}

fw_state_text() {
    if ! ufw_installed; then
        printf '%s' "${YELLOW}$(L '未安装')${NC}"
    elif ufw_active; then
        printf '%s' "${GREEN}$(L '已启用')${NC}"
    else
        printf '%s' "${RED}$(L '未启用')${NC}"
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
    while IFS= read -r sp; do
        if [ -n "$sp" ]; then echo "${sp}/tcp"; fi
    done < <(snell_all_ports)
    xray_ports
    realm_ports
    caddy_ports
    return 0
}

fw_allow_ssh() {
    local p
    while IFS= read -r p; do
        [ -n "$p" ] || continue
        ufw allow "${p}/tcp" >/dev/null 2>&1 || true
    done < <(detect_ssh_ports | tr ' ' '\n')
    return 0
}

fw_sync_managed() {
    local spec n=0
    while IFS= read -r spec; do
        [ -n "$spec" ] || continue
        if ufw allow "$spec" >/dev/null 2>&1; then
            info "$(L '已放行本脚本服务端口:') ${spec}"
            n=$((n + 1))
        fi
    done < <(managed_ports)
    if [ "$n" -eq 0 ]; then
        info "$(L '当前没有由本脚本管理的服务端口需要放行（Nowhere / Snell / Xray / Realm / Caddy 均未安装）')"
    fi
    return 0
}

# fw_is_allowed PORT PROTO：是否已有覆盖该端口的 allow 规则（防火墙未启用时也能查）
fw_is_allowed() {
    local port="$1" proto="$2" added line rest spec rng rp lo hi sp
    added="$(LC_ALL=C ufw show added 2>/dev/null || true)"
    while IFS= read -r line; do
        case "$line" in
            "ufw allow "*) rest="${line#ufw allow }" ;;
            *) continue ;;
        esac
        # 带来源/接口的规则：ufw allow from 1.2.3.4 to any port 22 proto tcp
        # （或 ufw allow in on eth0 to any port 443 proto tcp）
        if [[ "$rest" == *" port "* ]]; then
            local p pr
            p="$(printf '%s' "$rest" | grep -oE 'port [0-9]+' | awk '{print $2}' | head -1)"
            pr="$(printf '%s' "$rest" | grep -oE 'proto [a-z]+' | awk '{print $2}' | head -1)"
            if [ -n "$p" ] && [ "$p" = "$port" ] && { [ -z "$pr" ] || [ "$pr" = "$proto" ]; }; then return 0; fi
            continue
        fi
        spec="${rest%% *}"
        rng="${spec%%/*}"; rp="${spec#*/}"; [ "$rp" = "$spec" ] && rp=""
        if [[ "$rng" =~ ^[0-9]+$ ]]; then
            if [ "$rng" = "$port" ] && { [ -z "$rp" ] || [ "$rp" = "$proto" ]; }; then return 0; fi
        elif [[ "$rng" =~ ^[0-9]+:[0-9]+$ ]]; then
            lo="${rng%%:*}"; hi="${rng##*:}"
            if [ "$port" -ge "$lo" ] && [ "$port" -le "$hi" ] && { [ -z "$rp" ] || [ "$rp" = "$proto" ]; }; then return 0; fi
        else
            # 服务名：ufw allow ssh / http / https（用系统服务表解析端口）
            sp="$(getent services "$rng" 2>/dev/null | awk '{print $2}' | cut -d/ -f1 | head -1)"
            if [ -n "$sp" ] && [ "$sp" = "$port" ]; then return 0; fi
        fi
    done <<< "$added"
    return 1
}

# 是否存在与 ufw 冲突的防火墙：firewalld 在运行，或 cnblock 的 FWIN 链已挂在 INPUT 上
fw_conflict_detected() {
    if systemctl is-active --quiet firewalld 2>/dev/null; then return 0; fi
    if command -v iptables >/dev/null 2>&1 && iptables -S INPUT 2>/dev/null | grep -q '\-j FWIN'; then return 0; fi
    return 1
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
                warn "$(L '以下端口正在对外监听，但还没有在防火墙里放行（启用后外部将无法访问）：')"
                shown=1
            fi
            echo -e "    ${YELLOW}${spec}${NC}  ${proc}"
        fi
    done < <(fw_listening_ports)
    if [ "$shown" -eq 1 ]; then
        info "$(L '需要对外提供服务的端口，请用「3')) $(L '放行端口」添加后再启用')"
    fi
    return 0
}

fw_warn_conflicts() {
    local rules=""
    if command -v iptables >/dev/null 2>&1; then
        rules="$(iptables -S INPUT 2>/dev/null || true)"
        if [[ "$rules" == *"-j FWIN"* ]]; then
            warn "$(L '检测到 cnblock 的端口防火墙链 FWIN 已挂在 INPUT 上：两套入站防火墙会叠加（两边都放行才通），建议只保留一套（cnblock fw off，或不启用 ufw）')"
        fi
    fi
    if systemctl is-active --quiet firewalld 2>/dev/null; then
        warn "$(L '检测到 firewalld 正在运行，与 ufw 同时启用会互相覆盖规则，请只保留一个')"
    fi
    if command -v docker >/dev/null 2>&1; then
        info "$(L '提示：Docker 用 -p 发布的端口走 FORWARD 链，不受 ufw 入站规则限制')"
    fi
    return 0
}

fw_enable() {
    fw_require || return 1
    if ufw_active; then
        info "$(L '防火墙已是启用状态')"
        return 0
    fi
    fw_warn_conflicts
    info "$(L '启用前先放行 SSH 端口（')$(detect_ssh_ports)$(L '），避免把自己锁在外面')"
    fw_allow_ssh
    fw_sync_managed
    fw_show_unallowed_listening
    echo ""
    if ! confirm "$(L '确认启用防火墙？（默认拒绝所有入站，仅放行已添加的端口）')" y; then
        info "$(L '已取消，防火墙保持未启用')"
        return 0
    fi
    ufw --force enable >/dev/null 2>&1 || true
    if ufw_active; then
        success "$(L '防火墙已启用（开机自动生效）')"
    else
        warn "$(L '启用失败，请查看: ufw status verbose')"
        return 1
    fi
    return 0
}

fw_disable() {
    fw_require || return 1
    if ! ufw_active; then
        info "$(L '防火墙当前未启用')"
        return 0
    fi
    warn "$(L '停用后所有端口不再受 ufw 过滤（已添加的规则会保留，可随时重新启用）')"
    if ! confirm "$(L '确认停用防火墙？')" n; then
        info "$(L '已取消')"
        return 0
    fi
    ufw disable >/dev/null 2>&1 || true
    success "$(L '防火墙已停用')"
    return 0
}

fw_install() {
    step "$(L '安装防火墙（ufw）')"
    divider
    if ufw_installed; then
        info "$(L 'ufw 已安装')"
    else
        info "$(L '正在安装 ufw ...')"
        apt_install ufw || { warn "$(L 'ufw 安装失败，请检查 apt 源/网络')"; return 1; }
        success "$(L 'ufw 安装完成')"
    fi
    if ufw_active; then
        success "$(L '防火墙已处于启用状态，补齐 SSH 与本脚本服务端口的放行规则')"
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
            warn "$(L '无法识别的端口写法:') ${item}"
            return 1
        fi
        a="${BASH_REMATCH[1]}"; b="${BASH_REMATCH[3]}"; proto="${BASH_REMATCH[5]}"
        a=$((10#$a))
        if [ "$a" -lt 1 ] || [ "$a" -gt 65535 ]; then warn "$(L '端口超出范围:') ${item}"; return 1; fi
        if [ -n "$b" ]; then
            b=$((10#$b))
            if [ "$b" -lt 1 ] || [ "$b" -gt 65535 ]; then warn "$(L '端口超出范围:') ${item}"; return 1; fi
            if [ "$a" -ge "$b" ]; then warn "$(L '端口范围的起点必须小于终点:') ${item}"; return 1; fi
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
        echo "$(L '输入要放行的端口：逗号分隔，支持范围与协议后缀')"
        echo "  $(L '例：80,443,2053    400-500    443/tcp,51820/udp   （不写协议 = TCP 和 UDP 都放行）')"
        read -rp "$(L '端口:') " input || { [ -n "$input" ] || return 1; }
    fi
    if ! fw_parse_specs "$input"; then
        warn "$(L '输入不合法，未做任何修改')"
        return 1
    fi
    for spec in "${FW_SPECS[@]}"; do
        if ufw allow "$spec" >/dev/null 2>&1; then
            success "$(L '已放行') ${spec}"
        else
            warn "$(L '放行失败:') ${spec}"
        fi
    done
    if ! ufw_active; then
        warn "$(L '注意：防火墙当前未启用，规则已保存，启用后才生效')"
    fi
    return 0
}

# 删除一条放行规则；不带协议时把 端口 / 端口/tcp / 端口/udp 三种写法都清掉
# fw_spec_has_port SPEC PORT：规格是单端口或起止范围（400-500 或 400:500）且包含 PORT 时返回 0（L6）
fw_spec_has_port() {
    local spec="${1%%/*}" p="$2" lo hi
    if [[ "$spec" =~ ^[0-9]+$ ]]; then
        [ "$spec" = "$p" ]
        return
    fi
    if [[ "$spec" =~ ^([0-9]+)[-:]([0-9]+)$ ]]; then
        lo="${BASH_REMATCH[1]}"; hi="${BASH_REMATCH[2]}"
        [ "$p" -ge "$lo" ] && [ "$p" -le "$hi" ]
        return
    fi
    return 1
}

# fw_spec_has_ssh_port SPEC：规格含任一当前 SSH 端口时返回 0（范围类规则也按 SSH 规则处理，L6）
fw_spec_has_ssh_port() {
    local spec="$1" sp
    while IFS= read -r sp; do
        [ -n "$sp" ] || continue
        if fw_spec_has_port "$spec" "$sp"; then return 0; fi
    done < <(detect_ssh_ports | tr ' ' '\n')
    return 1
}

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
        success "$(L '已删除放行规则:') ${spec}"
    else
        info "$(L '没有找到') ${spec} $(L '的放行规则')"
    fi
    return 0
}

fw_delete_by_number() {
    local nums n line rule_port listing
    if ! ufw_active; then
        warn "$(L '防火墙未启用时 ufw 不显示规则编号，请改用「按端口」删除')"
        return 1
    fi
    read -rp "$(L '输入要删除的规则编号（逗号分隔，如 3,5）:') " nums || { [ -n "$nums" ] || return 1; }
    nums="${nums//[[:space:]]/}"
    if [[ ! "$nums" =~ ^[0-9]+(,[0-9]+)*$ ]]; then
        warn "$(L '输入不合法，未做任何修改')"
        return 1
    fi
    listing="$(LC_ALL=C ufw status numbered 2>/dev/null || true)"
    local -a _nums=()
    while IFS= read -r n; do [ -n "$n" ] && _nums+=("$n"); done < <(printf '%s\n' "$nums" | tr ',' '\n' | sort -rnu)
    for n in "${_nums[@]}"; do
        line="$(printf '%s\n' "$listing" | grep -E "^\[ *${n}\]" || true)"
        if [ -z "$line" ]; then
            warn "$(L '编号') ${n} $(L '不存在，已跳过')"
            continue
        fi
        rule_port="$(printf '%s' "$line" | sed -E 's/^\[ *[0-9]+\] *//' | awk '{print $1}' | cut -d/ -f1)"
        if fw_spec_has_ssh_port "$rule_port" && [[ "$line" == *"ALLOW"* ]]; then
            warn "$(L '规则') [${n}] $(L '是 SSH 端口的放行规则:') ${line#*] }"
            if ! confirm "$(L '删除后可能无法再通过 SSH 登录，确认删除？')" n; then
                info "$(L '已跳过') [${n}]"
                continue
            fi
        fi
        if ufw --force delete "$n" >/dev/null 2>&1; then
            success "$(L '已删除规则') [${n}] ${line#*] }"
        else
            warn "$(L '删除规则') [${n}] $(L '失败')"
        fi
    done
    return 0
}

fw_delete_ports() {
    fw_require || return 1
    local input="${1:-}" choice="" spec p
    if [ -n "$input" ]; then
        choice=2
    else
        echo "$(L '当前规则：')"
        ufw status numbered 2>/dev/null || true
        echo ""
        echo "$(L '删除方式：')"
        echo "  1) $(L '按规则编号（上表方括号里的数字）')"
        echo "  2) $(L '按端口')"
        read -rp "$(L '请选择') [1/2]: " choice || { [ -n "$choice" ] || return 1; }
    fi
    case "$choice" in
        1) fw_delete_by_number ;;
        2)
            if [ -z "$input" ]; then
                read -rp "$(L '输入要删除的端口（写法同放行，如 80,443 或 400-500）:') " input || { [ -n "$input" ] || return 1; }
            fi
            if ! fw_parse_specs "$input"; then
                warn "$(L '输入不合法，未做任何修改')"
                return 1
            fi
            for spec in "${FW_SPECS[@]}"; do
                p="${spec%%/*}"
                if fw_spec_has_ssh_port "$spec"; then
                    warn "${p} $(L '是当前的 SSH 端口')"
                    if ! confirm "$(L '删除后可能无法再通过 SSH 登录，确认删除？')" n; then
                        info "$(L '已跳过') ${spec}"
                        continue
                    fi
                fi
                fw_delete_spec "$spec"
            done
            ;;
        *) warn "$(L '无效选择')"; return 1 ;;
    esac
    return 0
}

fw_list() {
    fw_require || return 1
    if ufw_active; then
        ufw status numbered 2>/dev/null || true
    else
        warn "$(L '防火墙未启用，以下是已保存、启用后才生效的规则：')"
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
        warn "$(L '未安装 ufw，已跳过防火墙配置（可用主菜单「5')) $(L '防火墙」安装）；请确认云厂商安全组已放行:') $*"
        return 0
    fi
    fw_allow_ssh
    for spec in "$@"; do
        ufw allow "$spec" >/dev/null 2>&1 || warn "$(L '放行失败:') ${spec}"
    done
    if ufw_active; then
        success "$(L '防火墙已放行:') $*"
        return 0
    fi
    info "$(L 'ufw 当前未启用，已预先保存放行规则:') $*"
    fw_warn_conflicts
    fw_sync_managed >/dev/null
    fw_show_unallowed_listening
    if confirm "$(L '是否现在启用防火墙？（默认拒绝入站，仅放行已添加的端口）')" y; then
        ufw --force enable >/dev/null 2>&1 || true
        if ufw_active; then success "$(L '防火墙已启用')"; else warn "$(L '启用失败，请查看: ufw status verbose')"; fi
    else
        warn "$(L '已跳过启用防火墙，请确认云厂商安全组 / 其他防火墙已放行:') $*"
    fi
    return 0
}

# 重新配置换了端口后，清掉旧端口的放行规则（SSH、80、仍在使用的端口不动）
fw_prune_old_specs() {
    local old="$1" spec keep
    ufw_installed || return 0
    keep=" $(managed_ports | tr '\n' ' ') "
    while IFS= read -r spec; do
        [ -n "$spec" ] || continue
        if [ "$spec" = "80/tcp" ] && xray_needs_port80; then continue; fi
        [[ "$keep" == *" ${spec} "* ]] && continue
        fw_spec_has_ssh_port "$spec" && continue
        info "$(L '端口已变更，清理旧的放行规则:') ${spec}"
        fw_delete_spec "$spec"
    done < <(printf '%s\n' "$old" | tr ' ' '\n' | grep -v '^$')
    return 0
}

fw_menu() {
    local choice
    while true; do
        clear 2>/dev/null || true
        echo -e "${BOLD}${CYAN}━━━ $(L '防火墙管理（ufw）') ━━━${NC}"
        echo -e "  $(L '当前状态:') $(fw_state_text)    $(L 'SSH 端口:') $(detect_ssh_ports)"
        divider
        echo -e "  ${GREEN}1)${NC} ${GREEN}$(L '安装')${NC}$(L '防火墙（自动放行 SSH 与本脚本服务端口）')"
        echo -e "  ${GREEN}2)${NC} $(L '端口列表（带编号）')"
        echo -e "  ${GREEN}3)${NC} ${GREEN}$(L '放行')${NC}$(L '端口（TCP / UDP）')"
        echo -e "  ${GREEN}4)${NC} ${RED}$(L '删除')${NC}$(L '已放行的端口')"
        echo -e "  ${GREEN}5)${NC} ${GREEN}$(L '启用')${NC}$(L '防火墙')"
        echo -e "  ${GREEN}6)${NC} ${RED}$(L '停用')${NC}$(L '防火墙')"
        echo -e "  ${GREEN}7)${NC} $(L '防火墙状态（详细）')"
        echo -e "  ${GREEN}8)${NC} $(L '一键放行本脚本服务端口（SSH / Nowhere / Snell / Xray / Realm / Caddy）')"
        echo -e "  ${GREEN}0)${NC} $(L '返回主菜单')"
        divider
        read -rp "$(L '请选择') [0-8]: " choice
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
            *) warn "$(L '无效选择')" ;;
        esac
        pause_return
    done
}

fw_sync_cmd() {
    fw_require || return 1
    fw_allow_ssh
    info "$(L '已确认 SSH 端口放行:') $(detect_ssh_ports)"
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
            [ -n "${1:-}" ] || error "$(L '用法: adam fw allow <端口')[$(L ',端口...')]$(L '>，如 adam fw allow 443/tcp,8000-8100')"
            fw_open_ports "$1" ;;
        deny|delete|close)
            [ -n "${1:-}" ] || error "$(L '用法: adam fw deny <端口')[$(L ',端口...')]>"
            fw_delete_ports "$1" ;;
        sync)            fw_sync_cmd ;;
        *) error "$(L '未知的 fw 子命令:') ${sub}$(L '（可用: install / list / status / on / off / allow <端口> / deny <端口> / sync）')" ;;
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
        warn "$(L '尚未安装 Fail2ban，请先执行「1')) $(L '安装 Fail2ban」（或 adam f2b install）')"
        return 1
    fi
    return 0
}

f2b_require_running() {
    f2b_require || return 1
    if ! f2b_running; then
        warn "$(L 'Fail2ban 服务未运行，请先执行「10')) $(L '启用」或「9')) $(L '重启」')"
        return 1
    fi
    return 0
}

f2b_state_text() {
    local n=""
    if ! f2b_installed; then
        printf '%s' "${YELLOW}$(L '未安装')${NC}"
    elif f2b_running; then
        n="$(fail2ban-client status "$F2B_JAIL" 2>/dev/null | sed -n 's/.*Currently banned:[[:space:]]*//p' || true)"
        printf '%s' "${GREEN}$(L '运行中')${NC}${n:+ ($(L '当前封禁') ${n})}"
    else
        printf '%s' "${RED}$(L '已停止')${NC}"
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
    if command -v iptables >/dev/null 2>&1 && iptables -L -n >/dev/null 2>&1; then
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
# $(L '由 Adam 管理脚本生成（adam -> Fail2ban 管理）。请通过菜单修改，手动改动会在下次调整时被覆盖。')
# $(L '用 jail.d/')*$(L '.local：读取顺序在 jail.conf、jail.d/')*$(L '.conf、jail.local 之后，同名项以这里为准。')
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
        warn "$(L 'fail2ban 与当前 Python 版本不兼容（缺 asynchat/asyncore，常见于 Ubuntu 24.04 的初版软件包），尝试升级 fail2ban ...')"
        apt-get update -qq || true
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --only-upgrade fail2ban || true
        if f2b_apply; then return 0; fi
    fi
    if [ "$backend" != "systemd" ]; then
        warn "$(L '按日志文件方式启动失败（常见原因：系统没有 /var/log/auth.log），改用 systemd journal 后端重试 ...')"
        apt_install python3-systemd || true
        f2b_rewrite_keep systemd
        if f2b_apply; then return 0; fi
    fi
    warn "$(L 'Fail2ban 仍未能正常启动，最近日志：')"
    journalctl -u fail2ban -n 15 --no-pager 2>/dev/null || true
    fail2ban-client -t 2>&1 | tail -n 5 || true
    return 1
}

f2b_show_settings() {
    echo -e "  $(L '防护端口 :') ${GREEN}$(f2b_get port ssh)${NC}"
    echo -e "  $(L '封禁时长 :') ${GREEN}$(f2b_get bantime 30m)${NC}$(L '（-1 表示永久）')"
    echo -e "  $(L '触发条件 :') ${GREEN}$(f2b_get findtime 10m)${NC} $(L '内失败') ${GREEN}$(f2b_get maxretry 5)${NC} $(L '次')"
    echo -e "  $(L '白名单   :') ${GREEN}$(f2b_get ignoreip '127.0.0.1/8 ::1')${NC}"
    echo -e "  $(L '日志后端 :') ${GREEN}$(f2b_get backend auto)${NC}    $(L '封禁动作:') ${GREEN}$(f2b_get banaction -)${NC}"
}

f2b_install() {
    step "$(L '安装 Fail2ban 并启用 SSH 防护')"
    divider
    local backend ignoreip myip
    local -a pkgs=(fail2ban)
    backend="$(f2b_pick_backend)"
    if [ "$backend" = "systemd" ]; then pkgs+=(python3-systemd); fi
    if ! command -v iptables >/dev/null 2>&1 && ! command -v nft >/dev/null 2>&1; then pkgs+=(nftables); fi
    info "$(L '正在安装:') ${pkgs[*]}"
    apt_install "${pkgs[@]}" || { warn "$(L '安装失败，请检查 apt 源/网络')"; return 1; }

    # 消除 fail2ban 1.x 的 allowipv6 未设置告警（仅当发行版配置里有这一行时才改）
    sed -i 's/^#allowipv6 = auto/allowipv6 = auto/' /etc/fail2ban/fail2ban.conf 2>/dev/null || true

    ignoreip="$(f2b_get ignoreip '127.0.0.1/8 ::1')"
    myip="${SSH_CONNECTION%% *}"
    if [ -n "$myip" ] && is_ip "$myip" && [[ " $ignoreip " != *" $myip "* ]]; then
        if confirm "$(L '把你当前的登录 IP（')${myip}$(L '）加入白名单，避免输错密码把自己封掉？')" y; then
            ignoreip="${ignoreip} ${myip}"
        fi
    fi
    f2b_write_jail "$(f2b_get bantime 30m)" "$(f2b_get findtime 10m)" "$(f2b_get maxretry 5)" "$ignoreip" "$backend"
    if f2b_apply || f2b_diagnose_and_fix; then
        success "$(L 'Fail2ban 已启动，SSH 防护生效')"
        f2b_show_settings
        return 0
    fi
    return 1
}

f2b_require_managed() {
    f2b_require || return 1
    if [ ! -f "$F2B_JAIL_FILE" ]; then
        warn "$(L '未找到本脚本的 SSH 防护配置，请先执行「1')) $(L '安装 Fail2ban」生成')"
        return 1
    fi
    return 0
}

f2b_set_bantime() {
    f2b_require_managed || return 1
    local v="${1:-}" re='^[1-9][0-9]*[smhdw]$'
    if [ -z "$v" ]; then
        echo "$(L '当前封禁时长:') $(f2b_get bantime 30m)"
        read -rp "$(L '新的封禁时长（纯数字=分钟；也可写 10m / 1h / 1d / 1w；-1=永久）')[$(L '默认 30')]: " v || { [ -n "$v" ] || return 1; }
        v="${v:-30}"
    fi
    v="${v//[[:space:]]/}"
    if [[ "$v" =~ ^[1-9][0-9]*$ ]]; then
        v="${v}m"
    elif [[ "$v" =~ $re || "$v" == "-1" ]]; then
        :
    else
        warn "$(L '格式不合法:') ${v}$(L '（示例：30 / 10m / 1h / 1d / -1）')"
        return 1
    fi
    f2b_write_jail "$v" "$(f2b_get findtime 10m)" "$(f2b_get maxretry 5)" "$(f2b_get ignoreip '127.0.0.1/8 ::1')" "$(f2b_get backend '')"
    if f2b_apply || f2b_diagnose_and_fix; then
        success "$(L '封禁时长已改为') ${v}$(L '（对之后的新封禁生效）')"
        return 0
    fi
    return 1
}

f2b_tune() {
    f2b_require_managed || return 1
    local mr ft re='^[1-9][0-9]*[smhdw]?$'
    echo "$(L '当前触发条件:') $(f2b_get findtime 10m) $(L '内失败') $(f2b_get maxretry 5) $(L '次')"
    read -rp "$(L '最大失败次数 maxretry') [$(L '回车保持') $(f2b_get maxretry 5)]: " mr || { [ -n "$mr" ] || return 1; }
    mr="${mr:-$(f2b_get maxretry 5)}"
    if [[ ! "$mr" =~ ^[1-9][0-9]*$ ]]; then warn "$(L 'maxretry 必须是正整数')"; return 1; fi
    read -rp "$(L '统计窗口 findtime（如 10m / 1h，纯数字=分钟）')[$(L '回车保持') $(f2b_get findtime 10m)]: " ft || { [ -n "$ft" ] || return 1; }
    ft="${ft:-$(f2b_get findtime 10m)}"
    ft="${ft//[[:space:]]/}"
    if [[ ! "$ft" =~ $re ]]; then warn "$(L 'findtime 格式不合法')"; return 1; fi
    if [[ "$ft" =~ ^[0-9]+$ ]]; then ft="${ft}m"; fi
    f2b_write_jail "$(f2b_get bantime 30m)" "$ft" "$mr" "$(f2b_get ignoreip '127.0.0.1/8 ::1')" "$(f2b_get backend '')"
    if f2b_apply || f2b_diagnose_and_fix; then
        success "$(L '触发条件已改为:') ${ft} $(L '内失败') ${mr} $(L '次')"
        return 0
    fi
    return 1
}

f2b_unban_all() {
    f2b_require_running || return 1
    if ! confirm "$(L '确认解封当前所有被封禁的 IP？')" y; then
        info "$(L '已取消')"
        return 0
    fi
    if fail2ban-client unban --all >/dev/null 2>&1; then
        success "$(L '已解封所有 IP')"
    else
        warn "$(L '解封失败，请查看: fail2ban-client status') ${F2B_JAIL}"
        return 1
    fi
    return 0
}

f2b_banned() {
    f2b_require_running || return 1
    local jails j out cur total ips
    jails="$(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' | tr -d ',' || true)"
    if [ -z "$jails" ]; then
        echo "  $(L '（没有启用的 jail）')"
        return 0
    fi
    while IFS= read -r j; do
        [ -n "$j" ] || continue
        out="$(fail2ban-client status "$j" 2>/dev/null || true)"
        cur="$(printf '%s\n' "$out" | sed -n 's/.*Currently banned:[[:space:]]*//p')"
        total="$(printf '%s\n' "$out" | sed -n 's/.*Total banned:[[:space:]]*//p')"
        ips="$(printf '%s\n' "$out" | sed -n 's/.*Banned IP list:[[:space:]]*//p')"
        echo -e "  ${BOLD}[${j}]${NC} $(L '当前封禁') ${cur:-0} $(L '个，累计') ${total:-0} $(L '次')"
        if [ -n "$ips" ]; then echo "    ${ips}"; fi
    done < <(printf '%s\n' "$jails" | tr ' ' '\n' | grep -v '^$')
    return 0
}

f2b_banlog() {
    f2b_require || return 1
    local out=""
    info "$(L '最近的封禁 / 解封记录：')"
    if [ -f "$F2B_LOG" ]; then
        out="$(grep -E '\] (Ban|Unban|Restore Ban) ' "$F2B_LOG" 2>/dev/null | tail -n 20 || true)"
    else
        out="$(journalctl -u fail2ban --no-pager -n 2000 2>/dev/null | grep -E '\] (Ban|Unban|Restore Ban) ' | tail -n 20 || true)"
    fi
    if [ -n "$out" ]; then printf '%s\n' "$out"; else echo "  $(L '（暂无记录）')"; fi
    echo ""
    info "$(L '当前封禁列表：')"
    f2b_banned || true
    return 0
}

f2b_ban_ip() {
    f2b_require_running || return 1
    local ip="${1:-}" myip="${SSH_CONNECTION%% *}"
    if [ -z "$ip" ]; then read -rp "$(L '输入要封禁的 IP 地址:') " ip || { [ -n "$ip" ] || return 1; }; fi
    ip="${ip//[[:space:]]/}"
    if ! is_ip "$ip"; then warn "$(L 'IP 地址格式不合法:') ${ip}"; return 1; fi
    if [ -n "$myip" ] && [ "$ip" = "$myip" ]; then
        warn "$(L '这是你当前登录所用的 IP，封禁后会立刻断开且无法重连，已拒绝')"
        return 1
    fi
    if fail2ban-client set "$F2B_JAIL" banip "$ip" >/dev/null 2>&1; then
        success "$(L '已封禁') ${ip}$(L '（时长') $(f2b_get bantime 30m)$(L '）')"
    else
        warn "$(L '封禁失败（jail') ${F2B_JAIL} $(L '是否已启用？）')"
        return 1
    fi
    return 0
}

f2b_unban_ip() {
    f2b_require_running || return 1
    local ip="${1:-}"
    if [ -z "$ip" ]; then read -rp "$(L '输入要解封的 IP 地址:') " ip || { [ -n "$ip" ] || return 1; }; fi
    ip="${ip//[[:space:]]/}"
    if ! is_ip "$ip"; then warn "$(L 'IP 地址格式不合法:') ${ip}"; return 1; fi
    if fail2ban-client unban "$ip" >/dev/null 2>&1 || fail2ban-client set "$F2B_JAIL" unbanip "$ip" >/dev/null 2>&1; then
        success "$(L '已解封') ${ip}"
    else
        warn "$(L '解封失败（该 IP 可能本来就没有被封）')"
        return 1
    fi
    return 0
}

f2b_live_log() {
    f2b_require || return 1
    info "$(L '实时日志（Ctrl+C 返回）')"
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
        success "$(L 'Fail2ban 已重启')"
    elif [ -f "$F2B_JAIL_FILE" ]; then
        f2b_diagnose_and_fix || return 1
        success "$(L 'Fail2ban 已重启')"
    else
        systemctl is-active --quiet fail2ban || { warn "$(L '重启失败: journalctl -u fail2ban -n 30')"; return 1; }
        success "$(L 'Fail2ban 已重启')"
    fi
    return 0
}

f2b_on() {
    f2b_require || return 1
    systemctl enable --now fail2ban >/dev/null 2>&1 || true
    sleep 1
    if f2b_running; then
        success "$(L 'Fail2ban 已启用（开机自启）')"
    else
        warn "$(L '启动失败: journalctl -u fail2ban -n 30 --no-pager')"
        return 1
    fi
    return 0
}

f2b_off() {
    f2b_require || return 1
    systemctl disable --now fail2ban >/dev/null 2>&1 || true
    success "$(L 'Fail2ban 已停用（现有封禁随服务停止而解除，配置保留）')"
    return 0
}

f2b_whitelist() {
    f2b_require_managed || return 1
    local cur choice ip new="" w
    cur="$(f2b_get ignoreip '127.0.0.1/8 ::1')"
    echo "$(L '当前白名单（这些来源永远不会被封）:') ${cur}"
    echo "  1) $(L '添加 IP / 网段    2')) $(L '移除 IP / 网段    0')) $(L '返回')"
    read -rp "$(L '请选择:') " choice || { [ -n "$choice" ] || return 1; }
    case "$choice" in
        1)
            read -rp "$(L '输入要加入白名单的 IP 或 CIDR 网段:') " ip || { [ -n "$ip" ] || return 1; }
            ip="${ip//[[:space:]]/}"
            if ! is_ip "$ip" 1; then warn "$(L '格式不合法:') ${ip}"; return 1; fi
            if [[ " $cur " == *" $ip "* ]]; then info "$(L '已在白名单中')"; return 0; fi
            new="${cur} ${ip}"
            ;;
        2)
            read -rp "$(L '输入要移除的 IP 或网段:') " ip || { [ -n "$ip" ] || return 1; }
            ip="${ip//[[:space:]]/}"
            while IFS= read -r w; do
                [ -n "$w" ] || continue
                if [ "$w" != "$ip" ]; then new="${new:+$new }$w"; fi
            done < <(printf '%s\n' "$cur" | tr ' ' '\n' | grep -v '^$')
            if [ "$new" = "$cur" ]; then info "$(L '白名单里没有') ${ip}"; return 0; fi
            if [ -z "$new" ]; then new="127.0.0.1/8 ::1"; fi
            ;;
        *) return 0 ;;
    esac
    f2b_write_jail "$(f2b_get bantime 30m)" "$(f2b_get findtime 10m)" "$(f2b_get maxretry 5)" "$new" "$(f2b_get backend '')"
    if f2b_apply || f2b_diagnose_and_fix; then
        success "$(L '白名单已更新:') ${new}"
        return 0
    fi
    return 1
}

f2b_uninstall() {
    f2b_require || return 1
    local choice
    echo -e "  ${GREEN}1)${NC} $(L '只移除本脚本的 SSH 防护配置（保留 Fail2ban 及其他 jail）')"
    echo -e "  ${GREEN}2)${NC} $(L '卸载 Fail2ban（保留 /etc/fail2ban 下你自己的其他配置）')"
    echo -e "  ${GREEN}0)${NC} $(L '返回')"
    read -rp "$(L '请选择:') " choice || { [ -n "$choice" ] || return 1; }
    case "$choice" in
        1)
            rm -f "$F2B_JAIL_FILE"
            systemctl restart fail2ban >/dev/null 2>&1 || true
            sleep 1
            if fail2ban-client status >/dev/null 2>&1; then
                success "$(L '已移除本脚本的 SSH 防护配置')"
            else
                warn "$(L 'Fail2ban 重启后校验失败，请查看: fail2ban-client status')"
                return 1
            fi
            ;;
        2)
            if ! confirm "$(L '确认卸载 Fail2ban？')" n; then info "$(L '已取消')"; return 0; fi
            systemctl disable --now fail2ban >/dev/null 2>&1 || true
            rm -f "$F2B_JAIL_FILE"
            DEBIAN_FRONTEND=noninteractive apt-get remove -y -qq fail2ban || warn "$(L 'apt-get remove 失败，请手动处理')"
            success "$(L 'Fail2ban 已卸载')"
            ;;
        *) return 0 ;;
    esac
    return 0
}

f2b_menu() {
    local choice
    while true; do
        clear 2>/dev/null || true
        echo -e "${BOLD}${CYAN}━━━ $(L 'Fail2ban 管理（SSH 防爆破）') ━━━${NC}"
        echo -e "  $(L '当前状态:') $(f2b_state_text)    $(L '封禁时长:') $(f2b_get bantime '-')"
        divider
        echo -e "  ${GREEN}1)${NC}  ${GREEN}$(L '安装')${NC} $(L 'Fail2ban 并启用 SSH 防护')"
        echo -e "  ${GREEN}2)${NC}  $(L '修改封禁时长')"
        echo -e "  ${GREEN}3)${NC}  $(L '解封所有 IP')"
        echo -e "  ${GREEN}4)${NC}  $(L '封禁日志 / 查看被封 IP')"
        echo -e "  ${GREEN}5)${NC}  $(L '手动封禁一个 IP')"
        echo -e "  ${GREEN}6)${NC}  $(L '手动解封一个 IP')"
        echo -e "  ${GREEN}7)${NC}  $(L '实时日志')"
        echo -e "  ${GREEN}8)${NC}  $(L '服务状态')"
        echo -e "  ${GREEN}9)${NC}  $(L '重启服务')"
        echo -e "  ${GREEN}10)${NC} ${GREEN}$(L '启用')${NC} $(L 'Fail2ban（开机自启）')"
        echo -e "  ${GREEN}11)${NC} ${RED}$(L '停用')${NC} Fail2ban"
        echo -e "  ${GREEN}12)${NC} $(L '修改触发条件（失败次数 / 统计窗口）')"
        echo -e "  ${GREEN}13)${NC} $(L '白名单管理')"
        echo -e "  ${GREEN}14)${NC} ${RED}$(L '卸载')${NC}"
        echo -e "  ${GREEN}0)${NC}  $(L '返回主菜单')"
        divider
        read -rp "$(L '请选择') [0-14]: " choice
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
            *)  warn "$(L '无效选择')" ;;
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
            [ -n "${1:-}" ] || error "$(L '用法: adam f2b ban <IP>')"
            f2b_ban_ip "$1" ;;
        unban)
            [ -n "${1:-}" ] || error "$(L '用法: adam f2b unban <IP>')"
            f2b_unban_ip "$1" ;;
        unban-all)    f2b_unban_all ;;
        on|enable)    f2b_on ;;
        off|disable)  f2b_off ;;
        restart)      f2b_restart ;;
        uninstall)    f2b_uninstall ;;
        *) error "$(L '未知的 f2b 子命令:') ${sub}$(L '（可用: install / status / banned / log / bantime <时长> / ban <IP> / unban <IP> / unban-all / on / off / restart / uninstall）')" ;;
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

# state_load file "VAR=default ..." [whitelist_var "v1 v2 ..."]：读状态文件（不存在则用默认值）；
# 白名单变量取值非法时重置为默认值。state_save file dir dir_mode VAR...：写状态文件（文件 600）。
state_load() {
    local file="$1" defs="$2" wl_var="${3:-}" wl_vals="${4:-}" kv k v cur ok x wl_def=""
    while IFS= read -r kv; do
        [ -n "$kv" ] || continue
        k="${kv%%=*}"; v="${kv#*=}"
        printf -v "$k" '%s' "$v"
        [ "$k" = "$wl_var" ] && wl_def="$v"
    done < <(printf '%s\n' "$defs" | tr ' ' '\n' | grep -v '^$')
    if [ -f "$file" ]; then
        # shellcheck disable=SC1090
        source "$file" 2>/dev/null || true
    fi
    if [ -n "$wl_var" ] && [ -n "$wl_vals" ]; then
        cur="${!wl_var}"
        ok=0; while IFS= read -r x; do [ -n "$x" ] || continue; [ "$cur" = "$x" ] && ok=1; done < <(printf '%s\n' "$wl_vals" | tr ' ' '\n' | grep -v '^$')
        [ "$ok" = "1" ] || printf -v "$wl_var" '%s' "$wl_def"
    fi
    return 0
}

state_save() {
    local file="$1" dir="$2" dir_mode="$3" tmp v
    shift 3
    install -d -m "$dir_mode" "$dir"
    tmp="${file}.tmp"
    : > "$tmp"
    for v in "$@"; do printf '%s="%s"\n' "$v" "$(dq_escape "${!v}")" >> "$tmp"; done
    chmod 600 "$tmp"
    mv -f "$tmp" "$file"
}

maint_load() {
    state_load "$MAINT_ENV" "MAINT_WATCHDOG=1 MAINT_SCRIPT_AUTO=0 MAINT_DAILY_RESTART=0 MAINT_SCRIPT_ASKED=0 MAINT_NOWHERE_AUTO=0 MAINT_REALM_AUTO=0 MAINT_CADDY_AUTO=0"
    return 0
}

maint_save() {
    state_save "$MAINT_ENV" "$MAINT_DIR" 755 MAINT_WATCHDOG MAINT_SCRIPT_AUTO MAINT_DAILY_RESTART MAINT_SCRIPT_ASKED MAINT_NOWHERE_AUTO MAINT_REALM_AUTO MAINT_CADDY_AUTO
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
# $(L '由 Adam 管理脚本维护：Snell / Xray / Nowhere 的监听端口，避免被本机出站连接当作临时端口占用')
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

# ss_port_lines proto port：输出 ss 里第 4 列端口精确等于 port 的监听行（proto=tcp|udp）
ss_port_lines() {
    local proto="$1" p="$2" flag
    command -v ss >/dev/null 2>&1 || return 1
    case "$proto" in tcp) flag="-tlnp" ;; udp) flag="-ulnp" ;; *) return 1 ;; esac
    ss "$flag" 2>/dev/null | awk -v p=":${p}" '{ n = length($4); if (n >= length(p) && substr($4, n - length(p) + 1) == p) print }' || true
    return 0
}

# TCP 端口是否有进程在监听
tcp_listening() {
    local port="$1"
    [ -n "$(ss_port_lines tcp "$port" || true)" ]
}

# 与 tcp_listening 同理：只比对 ss 第 4 列的端口，避免 IPv6 地址段误命中。
# ss 不可用时返回 1（无法确认即不健康，不 fail-open）。
udp_listening() {
    local port="$1"
    [ -n "$(ss_port_lines udp "$port" || true)" ]
}


# TCP 端口是否被"名字不含 $2"的进程占用
tcp_port_conflict() {
    local p="$1" own="${2:-__none__}" out
    out="$(ss_port_lines tcp "$p" || true)"
    [ -n "$out" ] || return 1
    if [[ "$out" == *"\"${own}\""* ]]; then return 1; fi
    return 0
}

# 安装 Snell / Xray 时问一次：是否让管理脚本每天自动从仓库拉取更新（之后可在「自动维护」里改）
maint_ask_script_auto() {
    maint_load
    if [ "$MAINT_SCRIPT_ASKED" = "1" ]; then return 0; fi
    if confirm "$(L '让本管理脚本每天自动从仓库拉取更新？（地址:') ${SCRIPT_URL}$(L '；下载后校验完整性，版本不低于本地才替换）')" y; then
        MAINT_SCRIPT_AUTO="1"
    else
        MAINT_SCRIPT_AUTO="0"
    fi
    MAINT_SCRIPT_ASKED="1"
    maint_save
    return 0
}

maint_unit_installed() {
    case "$1" in
        snell-port@*) [ -f "${SNELL_PORTS_DIR}/${1#snell-port@}.conf" ] ;;
        *)            [ -f "/etc/systemd/system/$1.service" ] ;;
    esac
}

nowhere_healthy() {
    # v4.4：只看 active 不够——端口掉了服务仍可显示 active。
    # Egress 没有监听端口，只看 active；Portal 要求全部已配载体端口真实在监听。
    systemctl is-active --quiet nowhere 2>/dev/null || return 1
    [ "$(current_role)" = "portal" ] || return 0
    [ -f "$CONFIG_FILE" ] || return 0
    load_saved_config 2>/dev/null || return 0
    if has_tcp; then
        tcp_listening "$(tcp_port)" || return 1
    fi
    if has_udp; then
        udp_listening "$(udp_port)" || return 1
    fi
    return 0
}

maint_unit_healthy() {
    case "$1" in
        nowhere)   nowhere_healthy ;;
        snell)     snell_main_healthy ;;
        snell-port@*) snell_extra_healthy "${1#snell-port@}" ;;
        adam-xray) xray_healthy ;;
        adam-realm) realm_healthy ;;
        adam-caddy) caddy_healthy ;;
        adam-cloudflared) systemctl is-active --quiet adam-cloudflared 2>/dev/null ;;
        *)         systemctl is-active --quiet "$1" 2>/dev/null ;;
    esac
}

maint_install_timers() {
    if ! ensure_manager_copy >/dev/null 2>&1; then
        warn "$(L '管理脚本未能安装到') ${MANAGER_PATH}$(L '，无法启用定时任务')"
        return 1
    fi
    maint_load
    cat > /etc/systemd/system/adam-watchdog.service << WDSVC
[Unit]
Description=Adam manager: keep Snell / Xray / Nowhere / Realm alive
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
    systemctl enable --now adam-maintain.timer >/dev/null 2>&1 || warn "$(L 'adam-maintain.timer 启用失败')"
    if [ "$MAINT_WATCHDOG" = "1" ]; then
        systemctl enable --now adam-watchdog.timer >/dev/null 2>&1 || warn "$(L 'adam-watchdog.timer 启用失败')"
    else
        systemctl disable --now adam-watchdog.timer >/dev/null 2>&1 || true
    fi
    [ -f "$MAINT_ENV" ] || maint_save
    return 0
}

maint_remove_timers() {
    warn "$(L '移除定时器后，Xray 证书同步与自动续期将停止（证书到期前需手动续期或重装定时器）')"
    systemctl disable --now adam-watchdog.timer adam-maintain.timer >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/adam-watchdog.timer /etc/systemd/system/adam-watchdog.service \
          /etc/systemd/system/adam-maintain.timer /etc/systemd/system/adam-maintain.service
    systemctl daemon-reload
    return 0
}

maint_lock() {   # maint_lock [等待秒数]：拿不到锁返回 1 并记日志（L17）
    command -v flock >/dev/null 2>&1 || return 0
    # 同 fd 9 已持锁时可重入（M18）：直接再 flock，成功即返回
    if [ -e /proc/self/fd/9 ]; then
        if flock -w "${1:-0}" 9; then return 0; fi
        maint_log "$(L '另一个维护任务仍在运行，本次跳过')"
        return 1
    fi
    exec 9> "$MAINT_LOCK" || return 0
    if ! flock -w "${1:-0}" 9; then
        exec 9>&-
        maint_log "$(L '另一个维护任务仍在运行，本次跳过')"
        return 1
    fi
    return 0
}

# maint_lock_manual：手动入口拿 maint 锁；拿不到则警告并确认是否仍继续（默认否，M18）
maint_lock_manual() {
    if maint_lock 0; then return 0; fi
    warn "$(L '另一个维护或安装任务正在运行')"
    confirm "$(L '仍要继续吗？')" n
}

# 定时器每 5 分钟调用：全程不提问
maint_watchdog() {
    local unit
    maint_load
    [ "$MAINT_WATCHDOG" = "1" ] || return 0
    # 正在更新 / 安装时不插手，下一轮再看
    maint_lock 0 || { maint_log "[$(L '保活')] $(L '另一个维护任务仍在运行，本次跳过')"; return 0; }
    local -a units=(snell)
    while IFS= read -r unit; do units+=("snell-port@${unit}"); done < <(snell_extra_ports)
    units+=(adam-xray nowhere adam-realm adam-caddy adam-cloudflared)
    for unit in "${units[@]}"; do
        maint_unit_installed "$unit" || continue
        # 只管"设为开机自启"的服务：手动 disable 掉的不会被拉起
        systemctl is-enabled --quiet "$unit" 2>/dev/null || continue
        if maint_unit_healthy "$unit"; then continue; fi
        maint_log "[$(L '保活')] ${unit} $(L '状态异常（未运行或端口未监听），正在重启')"
        systemctl reset-failed "$unit" >/dev/null 2>&1 || true
        systemctl restart "$unit" >/dev/null 2>&1 || true
        sleep 3
        if maint_unit_healthy "$unit"; then
            maint_log "[$(L '保活')] ${unit} $(L '已恢复')"
            if [ "$unit" = "nowhere" ]; then save_current_pin >>"$MAINT_LOG" 2>&1 || true; fi
        else
            maint_log "[$(L '保活')] ${unit} $(L '重启后仍异常，请查看: journalctl -u') ${unit} -n 50 --no-pager"
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
    make_workdir || return 1
    tmp="$WORKDIR/manager.sh"
    if ! script_fetch_remote "$tmp"; then
        maint_log "[$(L '脚本')] $(L '未能从') ${SCRIPT_URL} $(L '取得完整脚本，本次跳过')"
        return 1
    fi
    if [ -f "$MANAGER_PATH" ] && cmp -s "$tmp" "$MANAGER_PATH"; then
        echo "[$(L '脚本')] $(L '已是仓库最新（')${SCRIPT_VERSION}$(L '）')"
        return 1
    fi
    if ! version_ge "$REMOTE_SCRIPT_VERSION" "$SCRIPT_VERSION"; then
        maint_log "[$(L '脚本')] $(L '仓库版本') ${REMOTE_SCRIPT_VERSION} $(L '低于本地') ${SCRIPT_VERSION}$(L '，不降级')"
        return 1
    fi
    if [ -f "$MANAGER_PATH" ]; then cp -f "$MANAGER_PATH" "${MANAGER_PATH}.bak"; fi
    install -m 755 "$tmp" "$MANAGER_PATH"
    maint_log "[$(L '脚本')] $(L '已从仓库更新:') ${SCRIPT_VERSION} -> ${REMOTE_SCRIPT_VERSION}$(L '（旧版备份') ${MANAGER_PATH}$(L '.bak）')"
    return 0
}

# 定时器每日调用：全程不提问
maint_daily() {
    local unit
    maint_load
    maint_lock 300 || { maint_log "$(L '另一个维护任务仍在运行，本次跳过')"; echo "$(L '另一个维护任务仍在运行，本次跳过')"; return 0; }
    if [ "$MAINT_SCRIPT_AUTO" = "1" ] && [ "${ADAM_REEXEC:-0}" != "1" ]; then
        if script_self_update_auto; then
            # 换成新脚本继续跑后面的步骤，让新逻辑当天就生效
            exec 9>&- || true
            ADAM_REEXEC=1 exec "$MANAGER_PATH" maintain
        fi
    fi
    if [ -x "$BIN_PATH" ] && [ "${MAINT_NOWHERE_AUTO:-0}" = "1" ]; then
        nowhere_autoupdate || true
    fi
    snell_load_state
    if [ -x "$SNELL_BIN" ] && [ "$SNELL_AUTO_UPDATE" = "1" ]; then
        snell_autoupdate || true
    fi
    xray_load_state
    if [ -x "$XRAY_BIN" ] && [ "$XRAY_AUTO_UPDATE" = "1" ]; then
        xray_autoupdate || true
    fi
    if [ -x "$REALM_BIN" ] && [ "${MAINT_REALM_AUTO:-0}" = "1" ]; then
        realm_autoupdate || true
    fi
    if [ -x "$CADDY_BIN" ] && [ "${MAINT_CADDY_AUTO:-0}" = "1" ]; then
        caddy_autoupdate || true
    fi
    if [ -x "$XRAY_BIN" ]; then xray_sync_certs || true; xray_sync_reality_snis || true; fi
    nowhere_sync_cert_copy || true
    reserved_ports_sync || true
    if [ "$MAINT_DAILY_RESTART" = "1" ]; then
        local -a runits=(snell)
        while IFS= read -r unit; do runits+=("snell-port@${unit}"); done < <(snell_extra_ports)
        runits+=(adam-xray nowhere adam-realm)
        for unit in "${runits[@]}"; do
            if systemctl is-active --quiet "$unit" 2>/dev/null; then
                systemctl restart "$unit" >/dev/null 2>&1 || true
                maint_log "[$(L '每日重启')] ${unit} $(L '已重启')"
                if [ "$unit" = "nowhere" ]; then save_current_pin >>"$MAINT_LOG" 2>&1 || true; fi
            fi
        done
    fi
    return 0
}

maint_timer_state() {
    if systemctl is-active --quiet "$1" 2>/dev/null; then
        printf '%s' "${GREEN}$(L '运行中')${NC}"
    else
        printf '%s' "${YELLOW}$(L '未启用')${NC}"
    fi
}

maint_onoff() { if [ "$1" = "1" ]; then printf '%s' "${GREEN}$(L '开')${NC}"; else printf '%s' "${YELLOW}$(L '关')${NC}"; fi; }

maint_toggle() {   # maint_toggle 变量名
    local name="$1" cur
    maint_load
    cur="${!name}"
    if [ "$cur" = "1" ]; then printf -v "$name" '%s' "0"; else printf -v "$name" '%s' "1"; fi
    maint_save
    maint_install_timers || return 1
    success "$(L '已切换，当前:') $([ "${!name}" = "1" ] && echo 开 || echo 关)"
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
    success "$(L 'Xray 自动更新:') $([ "$XRAY_AUTO_UPDATE" = "1" ] && echo "开（${XRAY_CHANNEL} 通道）" || echo 关)"
    return 0
}

maint_run_now() {
    info "$(L '立即执行一次每日维护（脚本自更新 / Snell / Xray 更新检查）...')"
    maint_daily
    echo ""
    info "$(L '立即执行一次保活巡检...')"
    exec 9>&- 2>/dev/null || true
    maint_watchdog
    success "$(L '执行完毕')"
    return 0
}

do_backup() {
    step "$(L '备份全部配置')"
    divider
    local ts dest
    local -a dirs=()
    ts="$(date +%Y%m%d-%H%M%S)"
    dest="/root/adam-backup-${ts}.tgz"
    local d
    for d in /etc/nowhere /etc/snell /etc/adam-xray /etc/adam-realm /etc/adam-caddy /etc/adam-cloudflared /etc/adam /etc/fail2ban/jail.d/adam-sshd.local /etc/cloudflare/credentials.ini /etc/letsencrypt; do
        [ -e "$d" ] && dirs+=("$d")
    done
    [ "${#dirs[@]}" -gt 0 ] || { warn "$(L '没有找到可备份的配置目录')"; return 1; }
    tar -czf "$dest" "${dirs[@]}" 2>/dev/null || error "$(L '打包失败')"
    chmod 600 "$dest"
    ls -1t /root/adam-backup-*.tgz 2>/dev/null | tail -n +6 | tr '\n' '\0' | xargs -r -0 rm -f
    success "$(L '备份已保存：')${dest}$(L '（只留最近 5 份）')"
    warn "$(L '备份含共享密钥与证书私钥，只能放本机，勿外发、勿传网盘')"
    info "$(L '注意：定时器单元文件不在备份中，异机恢复后需重装定时器（自动维护菜单 8）')"
    tar -tzf "$dest" | head -20
}

do_restore() {
    local file="${1:-}"
    step "$(L '恢复配置')"
    divider
    if [ -z "$file" ]; then
        read -rp "$(L '备份文件路径（/root/adam-backup-')*$(L '.tgz）:') " file || { [ -n "$file" ] || return 1; }
    fi
    [ -f "$file" ] || error "$(L '找不到备份文件：')${file}"
    tar -tzf "$file" >/dev/null 2>&1 || error "$(L '备份文件损坏或不是有效的 tgz')"
    local bak_role="" cur_role=""
    bak_role="$(tar -xzOf "$file" etc/nowhere/role 2>/dev/null | tr -d ' \r\n' || true)"
    if [ -z "$bak_role" ]; then bak_role="$(tar -xzOf "$file" /etc/nowhere/role 2>/dev/null | tr -d ' \r\n' || true)"; fi
    cur_role="$(current_role)"
    if [ -n "$bak_role" ] && [ "$cur_role" != "none" ] && [ "$bak_role" != "$cur_role" ]; then error "$(L '备份内的角色与本机角色不一致，已中止恢复')"; fi
    # 校验成员路径：只允许恢复到本脚本管理的配置目录，拒绝 ../ 越界成员
    while IFS= read -r m; do
        case "$m" in
            *".."*) error "$(L '备份文件包含非法路径，已中止'): $m" ;;
            etc/nowhere|etc/nowhere/*|etc/snell|etc/snell/*|etc/adam-realm|etc/adam-realm/*|etc/adam-caddy|etc/adam-caddy/*|etc/adam-cloudflared|etc/adam-cloudflared/*|etc/adam-xray|etc/adam-xray/*|etc/adam|etc/adam/*|etc/fail2ban/jail.d|etc/fail2ban/jail.d/*|etc/cloudflare|etc/cloudflare/*|etc/letsencrypt|etc/letsencrypt/*|/etc/nowhere|/etc/nowhere/*|/etc/snell|/etc/snell/*|/etc/adam-realm|/etc/adam-realm/*|/etc/adam-caddy|/etc/adam-caddy/*|/etc/adam-cloudflared|/etc/adam-cloudflared/*|/etc/adam-xray|/etc/adam-xray/*|/etc/adam|/etc/adam/*|/etc/fail2ban/jail.d|/etc/fail2ban/jail.d/*|/etc/cloudflare|/etc/cloudflare/*|/etc/letsencrypt|/etc/letsencrypt/*) ;;
            *) error "$(L '备份文件包含非法路径，已中止'): $m" ;;
        esac
    done < <(tar -tzf "$file" 2>/dev/null || true)
    tar -tzf "$file" | head -20
    warn "$(L '恢复会覆盖 /etc/nowhere、/etc/snell、/etc/adam-xray、/etc/adam-realm、/etc/adam-caddy、/etc/adam-cloudflared 等现有配置，并重启已启用的服务')"
    confirm "$(L '确认从') ${file} $(L '恢复？')" n || { info "$(L '已取消')"; return 0; }
    local u
    for u in nowhere snell adam-xray adam-realm adam-caddy adam-cloudflared; do
        systemctl is-active --quiet "$u" 2>/dev/null && systemctl stop "$u" >/dev/null 2>&1 || true
    done
    tar -xzf "$file" -C / || error "$(L '解包失败，现有配置可能已不完整，请检查')"
    systemctl daemon-reload
    for u in nowhere snell adam-xray adam-realm adam-caddy adam-cloudflared; do
        if systemctl is-enabled --quiet "$u" 2>/dev/null; then
            systemctl restart "$u" >/dev/null 2>&1 || warn "${u} $(L '重启失败，请看 journalctl -u') ${u}"
        fi
    done
    snell_sync_extras_after_restore || true
    # 异机恢复：Realm 的 unit 可能未启用；有启用规则时按规则状态拉起并补防火墙
    if [ -f "$REALM_SERVICE" ] && [ "$(realm_enabled_count)" -gt 0 ]; then
        realm_reload_service >/dev/null 2>&1 || warn "$(L 'Realm 服务恢复后重载失败，请检查日志')"
    fi
    fw_sync_managed >/dev/null 2>&1 || true
    if f2b_installed; then systemctl restart fail2ban 2>/dev/null || true; fi
    success "$(L '恢复完成（已重启启用的服务）')"
}

do_doctor() {
    step "$(L '一键诊断（只读，不改任何配置）')"
    divider
    echo "  $(L '管理脚本 :') ${SCRIPT_VERSION}$(L '（适配 Nowhere') ${TARGET_NW_VERSION}$(L '） 语言：')${ADAM_LANG}"
    echo "  Nowhere  : $([ -x "$BIN_PATH" ] && "$BIN_PATH" --version 2>&1 | head -1 || echo "$(L '未安装')") $(L '· 角色') $(current_role) · $(svc_state nowhere)"
    echo "  Snell    : $([ -x "$SNELL_BIN" ] && { snell_installed_version; } || echo "$(L '未安装')") · $(svc_state snell)"
    echo "  Xray     : $([ -x "$XRAY_BIN" ] && "$XRAY_BIN" version 2>&1 | head -1 || echo "$(L '未安装')") · $(svc_state adam-xray)"
    echo "  Realm    : $(realm_state_text)"
    echo "  $(L '域名反代') : $(proxy_state_text)"
    if [ -x /usr/local/bin/adam ] && [ -x "$MANAGER_PATH" ]; then info "$(L '快捷命令 adam：正常（指向') ${MANAGER_PATH}$(L '）')"; else warn "$(L '快捷命令 adam 不可用：请执行') ${MANAGER_PATH} shortcuts $(L '或重新运行安装脚本')"; fi
    echo "  $(L '保活巡检 :') $(maint_timer_state adam-watchdog.timer)    $(L '每日维护 :') $(maint_timer_state adam-maintain.timer)"
    echo ""
    info "$(L '监听端口（ss）：')"
    if command -v ss >/dev/null 2>&1; then
        ss -tlnp 2>/dev/null | grep -E 'nowhere|snell|xray|realm|caddy' || echo "  $(L '（无 Nowhere/Snell/Xray/Realm/Caddy 的 TCP 监听）')"
        ss -ulnp 2>/dev/null | grep -E 'nowhere|snell|xray|realm|caddy' || echo "  $(L '（无 Nowhere/Snell/Xray/Realm/Caddy 的 UDP 监听）')"
    else
        warn "$(L 'ss 工具缺失，无法列出监听端口（请安装 iproute2）')"
    fi
    echo ""
    if [ -f "$CONFIG_FILE" ] && [ "$(current_role)" = "portal" ]; then
        load_saved_config 2>/dev/null || true
        if [ "${TLS_MODE:-}" = "2" ] && [ -n "${CRT:-}" ]; then
            local days
            days="$(cert_expiry_days "$CRT" 2>/dev/null || echo "")"
            if [ -n "$days" ]; then
                [ "$days" -lt 0 ] && warn "$(L '证书已过期') $((-days)) $(L '天')" || info "$(L '证书剩余约') ${days} $(L '天')"
            else
                warn "$(L '证书文件无法读取：')${CRT}"
            fi
        elif [ "${TLS_MODE:-}" = "1" ]; then
            if [ -f "$TLS_PIN_FILE" ]; then info "$(L 'tls=1 当前指纹见') ${TLS_PIN_FILE}"; else warn "$(L 'tls=1 且无指纹记录文件，请用 Nowhere 菜单 10 生成')"; fi
        fi
    fi
    if [ -x "$XRAY_BIN" ] && [ "$(xray_node_count)" -gt 0 ]; then
        local _dtag _ddays
        while IFS= read -r _dtag; do
            xray_node_load "$_dtag" || continue
            if [ "$N_TYPE" = "xhttp-tls" ] || { [ "$N_TYPE" = "xhttp-cdn" ] && [ "${N_ORIGIN:-tls}" != "plain" ]; }; then
                if [ -f "${XRAY_CERT_DIR}/${_dtag}/fullchain.pem" ]; then
                    _ddays="$(cert_expiry_days "${XRAY_CERT_DIR}/${_dtag}/fullchain.pem" 2>/dev/null || echo "")"
                    if [[ "$_ddays" =~ ^-?[0-9]+$ ]]; then
                        echo "  Xray [${_dtag}] $(L '证书剩余') ${_ddays} $(L '天')"
                    fi
                else
                    warn "$(L '证书文件无法读取：')${XRAY_CERT_DIR}/${_dtag}/fullchain.pem"
                fi
            fi
        done < <(xray_node_tags)
    fi
    if command -v ufw >/dev/null 2>&1; then
        echo "  $(L '防火墙'): $(ufw status 2>/dev/null | head -n 1)"
    else
        echo "  $(L '防火墙'): $(L '未安装')"
    fi
    echo ""
    info "$(L '磁盘：')$(df -h / 2>/dev/null | tail -1)"
    info "$(L '最近错误日志（nowhere，5 行）：')"
    journalctl -u nowhere -p err -n 5 --no-pager -o cat 2>/dev/null || echo "  $(L '（无）')"
}

do_log_cleanup() {
    step "$(L '清理日志')"
    divider
    journalctl --disk-usage 2>/dev/null || true
    confirm "$(L '清理 journal 日志，只保留最近 200M？')" n || { info "$(L '已取消')"; return 0; }
    journalctl --vacuum-size=200M || warn "$(L '清理失败')"
    journalctl --disk-usage 2>/dev/null || true
    success "$(L '日志清理完成')"
}

maint_show_log() {
    info "$(L '最近的维护事件（')${MAINT_LOG}$(L '）：')"
    if [ -s "$MAINT_LOG" ]; then tail -n 30 "$MAINT_LOG"; else echo "  $(L '（暂无记录）')"; fi
    echo ""
    info "$(L '最近一次每日任务输出：')"
    journalctl -u adam-maintain --no-pager -n 20 -o cat 2>/dev/null || true
    return 0
}

maint_menu() {
    local choice
    while true; do
        clear 2>/dev/null || true
        maint_load; snell_load_state; xray_load_state
        echo -e "${BOLD}${CYAN}━━━ $(L '自动维护')$(L '（保活 / 自动更新）') ━━━${NC}"
        echo -e "  $(L '保活巡检定时器'): $(maint_timer_state adam-watchdog.timer)    $(L '每日维护定时器'): $(maint_timer_state adam-maintain.timer)"
        divider
        echo -e "  ${GREEN}1)${NC} $(L '保活巡检（每 5 分钟；服务未运行或端口未监听时自动重启）')  [$(maint_onoff "$MAINT_WATCHDOG")]"
        echo -e "  ${GREEN}2)${NC} $(L '管理脚本自动从仓库拉取更新（每日）')                      [$(maint_onoff "$MAINT_SCRIPT_AUTO")]"
        echo -e "  ${GREEN}3)${NC} Snell $(L '跟随官方发布自动更新')$(L '（')${SNELL_CHANNEL} $(L '通道')$(L '）')                  [$(maint_onoff "$SNELL_AUTO_UPDATE")]"
        echo -e "  ${GREEN}4)${NC} Xray $(L '跟随官方发布自动更新')$(L '（')${XRAY_CHANNEL} $(L '通道')$(L '）')              [$(maint_onoff "$XRAY_AUTO_UPDATE")]"
        echo -e "  ${GREEN}5)${NC} $(L 'Nowhere 跟随官方发布自动更新（仅 NW3 同代）')             [$(maint_onoff "${MAINT_NOWHERE_AUTO:-0}")]"
        echo -e "  ${GREEN}6)${NC} $(L 'Realm 跟随官方发布自动更新')                              [$(maint_onoff "${MAINT_REALM_AUTO:-0}")]"
        echo -e "  ${GREEN}7)${NC} $(L 'Caddy 跟随官方发布自动更新')                              [$(maint_onoff "${MAINT_CADDY_AUTO:-0}")]"
        echo -e "  ${GREEN}8)${NC} $(L '每日定时重启 Snell / Xray / Nowhere / Realm（随每日维护执行）') [$(maint_onoff "$MAINT_DAILY_RESTART")]"
        echo -e "  ${GREEN}9)${NC} $(L '立即执行一次维护与巡检')"
        echo -e "  ${GREEN}10)${NC} $(L '查看维护记录')"
        echo -e "  ${GREEN}11)${NC} $(L '重装定时器（修复）')"
        echo -e "  ${GREEN}12)${NC} ${RED}$(L '移除')${NC}$(L '全部定时器')"
        echo -e "  ${GREEN}13)${NC} $(L '备份全部配置')"
        echo -e "  ${GREEN}14)${NC} $(L '恢复配置（从备份文件）')"
        echo -e "  ${GREEN}15)${NC} $(L '一键诊断')"
        echo -e "  ${GREEN}16)${NC} $(L '清理日志（保留 200M）')"
        echo -e "  ${GREEN}0)${NC} $(L '返回主菜单')"
        divider
        read -rp "$(L '请选择') [0-16]: " choice
        case "$choice" in
            1) run_action maint_toggle MAINT_WATCHDOG ;;
            2) run_action maint_toggle MAINT_SCRIPT_AUTO ;;
            3) run_action maint_toggle_snell ;;
            4) run_action maint_toggle_xray ;;
            5) run_action maint_toggle MAINT_NOWHERE_AUTO ;;
            6) run_action maint_toggle MAINT_REALM_AUTO ;;
            7) run_action maint_toggle MAINT_CADDY_AUTO ;;
            8) run_action maint_toggle MAINT_DAILY_RESTART ;;
            9) run_action maint_run_now ;;
            10) run_action maint_show_log ;;
            11) run_action maint_install_timers ;;
            12) run_action maint_remove_timers ;;
            13) run_action do_backup ;;
            14) run_action do_restore ;;
            15) run_action do_doctor ;;
            16) run_action do_log_cleanup ;;
            0) return 0 ;;
            *) warn "$(L '无效选择')" ;;
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
        *) warn "$(L 'Snell 官方未提供该架构的二进制:') $(uname -m)"; return 1 ;;
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
    b="$(snell_ver_key "$2")" || return 1
    [[ "$a" > "$b" ]]
}

snell_is_prerelease() { local v="${1#v}"; [[ "$v" =~ [a-z] ]]; }

snell_ver_major() { local v="${1#v}"; printf '%s' "${v%%.*}"; }

snell_conf_get() {   # snell_conf_get KEY [配置文件，默认主配置]
    local file="${2:-$SNELL_CONF}"
    [ -f "$file" ] || return 1
    awk -v k="$1" '
        /^[ \t]*[#;\[]/ { next }
        {
            i = index($0, "="); if (i == 0) next
            kk = substr($0, 1, i - 1); gsub(/[ \t]/, "", kk)
            if (kk == k) { v = substr($0, i + 1); gsub(/^[ \t]+|[ \t\r]+$/, "", v); print v; found = 1; exit }
        }
        END { exit !found }' "$file"
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
        warn "$(L 'Snell 尚未安装，请先执行「1')) $(L '安装 Snell」（或 adam snell install）')"
        return 1
    fi
    return 0
}

snell_load_state() {
    state_load "$SNELL_STATE_FILE" "SNELL_CHANNEL=beta SNELL_AUTO_UPDATE=0 SNELL_PUBLIC_HOST= SNELL_NODE_NAME=" SNELL_CHANNEL "stable beta"
    return 0
}

snell_save_state() {
    state_save "$SNELL_STATE_FILE" "$SNELL_DIR" 750 SNELL_CHANNEL SNELL_AUTO_UPDATE SNELL_PUBLIC_HOST SNELL_NODE_NAME
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
    make_workdir || return 1
    tmp="$WORKDIR/snell-probe"
    : > "$tmp"
    for c in "$@"; do
        ( if snell_dl_exists "$arch" "$c"; then echo "$c" >> "$tmp"; fi ) &
    done
    wait
    cat "$tmp" 2>/dev/null || true
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
        while IFS= read -r v; do
            [ -n "$v" ] || continue
            # 只沿着同一大版本继续追
            if [ "$(snell_ver_major "$v")" = "$(snell_ver_major "$base")" ] && snell_ver_gt "$v" "$best"; then best="$v"; fi
        done < <(printf '%s\n' "$found" | tr ' ' '\n' | grep -v '^$')
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
    while IFS= read -r v; do
        [ -n "$v" ] || continue
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
    done < <(printf '%s\n' "$all" | tr ' ' '\n' | grep -v '^$')
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
    make_workdir || return 1
    local wd="$WORKDIR"
    url="${SNELL_DL_BASE}/snell-server-${ver}-linux-${arch}.zip"
    if ! curl -fL --retry 3 --connect-timeout 10 --max-time 300 -o "$wd/snell.zip" "$url"; then
        warn "$(L '下载失败:') ${url}"
        return 1
    fi
    if ! unzip -tq "$wd/snell.zip" >/dev/null 2>&1; then
        warn "$(L '下载到的压缩包不完整或已损坏')"
        return 1
    fi
    unzip -oq "$wd/snell.zip" snell-server -d "$wd" || { warn "$(L '压缩包里没有 snell-server')"; return 1; }
    magic="$(head -c 4 "$wd/snell-server" | od -An -tx1 | tr -d ' \n' || true)"
    if [ "$magic" != "7f454c46" ]; then
        warn "$(L '解压出的 snell-server 不是 Linux 可执行文件')"
        return 1
    fi
    chmod 755 "$wd/snell-server"
    if ! upgrade_binary_precheck "$wd/snell-server" -v; then
        out="$(cd "$wd" && timeout 5 ./snell-server -v 2>&1 < /dev/null || true)"
        warn "$(L '新二进制无法在本机运行（缺少依赖库或架构不符）:') ${out}"
        return 1
    fi
    SNELL_DL_BIN="$wd/snell-server"
    info "SHA256: $(sha256sum "$SNELL_DL_BIN" | awk '{print $1}')$(L '（官方未公布校验值，仅供留档比对）')"
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
    local f
    if getent group snell >/dev/null 2>&1; then
        chown root:snell "$SNELL_DIR" 2>/dev/null || true
        chmod 750 "$SNELL_DIR" 2>/dev/null || true
        if [ -d "$SNELL_PORTS_DIR" ]; then
            chown root:snell "$SNELL_PORTS_DIR" 2>/dev/null || true
            chmod 750 "$SNELL_PORTS_DIR" 2>/dev/null || true
        fi
        for f in "$SNELL_CONF" "$SNELL_PORTS_DIR"/*.conf; do
            [ -f "$f" ] || continue
            chown root:snell "$f" 2>/dev/null || true
            chmod 640 "$f" 2>/dev/null || true
        done
    fi
    return 0
}

# ── 多端口：主配置（snell.service）之外，每个附加端口是一份独立配置 + 一个 snell-port@端口 实例 ──

# 附加端口列表（每行一个，升序）
snell_extra_ports() {
    local f p
    [ -d "$SNELL_PORTS_DIR" ] || return 0
    for f in "$SNELL_PORTS_DIR"/*.conf; do
        [ -f "$f" ] || continue
        p="$(basename "$f" .conf)"
        if [[ "$p" =~ ^[0-9]+$ ]]; then echo "$p"; fi
    done | sort -n
    return 0
}

# 全部端口：主端口在前
snell_all_ports() {
    local p
    p="$(snell_port)"
    if [ -n "$p" ]; then echo "$p"; fi
    snell_extra_ports
    return 0
}

snell_port_conf() {   # 端口对应的配置文件路径
    if [ "$1" = "$(snell_port)" ]; then printf '%s' "$SNELL_CONF"; else printf '%s' "${SNELL_PORTS_DIR}/$1.conf"; fi
}

# 端口是否已是本机某份 Snell 配置（服务没运行时 ss 查不到，所以单独判断）
snell_port_taken() {
    local want="$1" p
    while IFS= read -r p; do
        if [ "$p" = "$want" ]; then return 0; fi
    done < <(snell_all_ports)
    return 1
}

snell_write_port_unit() {
    write_service_unit "$SNELL_PORT_UNIT" "Snell Proxy Service (extra port %i)" "https://kb.nssurge.com/surge-knowledge-base/release-notes/snell" "0" "snell" "snell" "${SNELL_BIN} -l info -c ${SNELL_PORTS_DIR}/%i.conf" "CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW" "65536" "always" "3" "ProtectSystem=full
ProtectHome=true
PrivateTmp=true
SyslogIdentifier=snell-server-%i"
}

snell_main_healthy() {
    local port
    systemctl is-active --quiet snell 2>/dev/null || return 1
    port="$(snell_port)"
    [ -n "$port" ] || return 1
    tcp_listening "$port"
}

snell_extra_healthy() {   # snell_extra_healthy 端口
    systemctl is-active --quiet "snell-port@$1" 2>/dev/null || return 1
    tcp_listening "$1"
}

# 主端口与全部附加端口都正常
snell_healthy() {
    local p
    snell_main_healthy || return 1
    while IFS= read -r p; do
        snell_extra_healthy "$p" || return 1
    done < <(snell_extra_ports)
    return 0
}

# 重启主服务与全部附加端口实例（换二进制、回滚、手动重启时用）
snell_restart_all() {
    local p
    systemctl restart snell 2>/dev/null || true
    while IFS= read -r p; do
        systemctl restart "snell-port@${p}" 2>/dev/null || true
    done < <(snell_extra_ports)
    return 0
}

# 配置目录里已有附加端口配置（如卸载时保留了配置后重装）时，把它们的实例重新拉起来
# 恢复后同步 Snell 附加端口实例：停掉配置已不存在的实例，再拉起配置里有的实例（M7）
snell_sync_extras_after_restore() {
    local inst p
    while IFS= read -r inst; do
        p="${inst#snell-port@}"; p="${p%.service}"
        if [ ! -f "${SNELL_PORTS_DIR}/${p}.conf" ]; then
            systemctl disable --now "$inst" >/dev/null 2>&1 || true
            info "$(L '已停用多余的 Snell 附加端口实例：')${p}"
        fi
    done < <(systemctl list-units --all 'snell-port@*.service' --no-legend 2>/dev/null | awk '{print $1}')
    snell_start_extras
}

snell_start_extras() {
    local p
    [ -n "$(snell_extra_ports)" ] || return 0
    snell_write_port_unit
    systemctl daemon-reload
    while IFS= read -r p; do
        systemctl enable "snell-port@${p}" >/dev/null 2>&1 || true
        systemctl restart "snell-port@${p}" 2>/dev/null || true
        if ufw_installed; then ufw allow "${p}/tcp" >/dev/null 2>&1 || true; fi
        info "$(L '已恢复附加端口') ${p}"
    done < <(snell_extra_ports)
    return 0
}

snell_rollback_binary() {
    local prev="${1:-}"
    if [ ! -f "$SNELL_BIN_BACKUP" ]; then
        warn "$(L '没有可回滚的备份二进制')"
        return 1
    fi
    warn "$(L '正在回滚到旧版本')${prev:+(${prev})} ..."
    install -m 755 "$SNELL_BIN_BACKUP" "$SNELL_BIN"
    if [ -n "$prev" ]; then echo "$prev" > "$SNELL_VERSION_FILE"; fi
    snell_restart_all
    sleep 2
    if snell_healthy; then
        success "$(L '已回滚，服务恢复运行')"
    else
        warn "$(L '回滚后服务仍未启动，请查看: journalctl -u snell -n 50 --no-pager')"
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
        success "$(L 'Snell 二进制已更新到') ${ver}$(L '（未检测到 snell.service，未启动服务）')"
        return 0
    fi
    if upgrade_binary_finish snell snell_restart_all snell_healthy snell_rollback_binary "$prev" 2 15; then
        success "$(L 'Snell 已更新:') ${prev:-$(L '未知')} → ${ver}"
        return 0
    fi
    return 1
}

snell_ensure_user() {
    ensure_system_user snell || { warn "$(L '创建 snell 系统用户失败')"; return 1; }
    return 0
}

snell_ipv6_ok() {
    [ -r /proc/sys/net/ipv6/conf/all/disable_ipv6 ] || return 1
    [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo 1)" = "0" ]
}

# snell_write_conf PORT PSK MODE DNS_PREF [目标文件，默认主配置]
snell_write_conf() {
    local port="$1" psk="$2" mode="$3" pref="$4" dest="${5:-$SNELL_CONF}" listen tmp
    if snell_ipv6_ok; then
        listen="0.0.0.0:${port},[::]:${port}"
    else
        listen="0.0.0.0:${port}"
    fi
    install -d -m 750 "$SNELL_DIR"
    tmp="$(mktemp "${SNELL_DIR}/.conf.XXXXXX")"
    cat > "$tmp" << SNCONFEOF || { rm -f "$tmp"; return 1; }
[snell-server]
mode = ${mode}
listen = ${listen}
psk = ${psk}
dns-ip-preference = ${pref}
SNCONFEOF
    chmod 640 "$tmp"
    install -d -m 750 "$(dirname "$dest")"
    mv -f "$tmp" "$dest" || { rm -f "$tmp"; return 1; }
    snell_fix_perms
}

snell_write_service() {
    write_service_unit "$SNELL_SERVICE" "Snell Proxy Service" "https://kb.nssurge.com/surge-knowledge-base/release-notes/snell" "0" "snell" "snell" "${SNELL_BIN} -l info -c ${SNELL_CONF}" "CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW" "65536" "always" "3" "ProtectSystem=full
ProtectHome=true
PrivateTmp=true
SyslogIdentifier=snell-server"
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
    local p="$1"
    tcp_port_conflict "$p" "snell-server"
}

# 询问一个可用的新端口（不能被其他进程占用，也不能是本机已有的 Snell 端口），结果写入 SNELL_ASK_PORT
snell_ask_new_port() {
    local def
    def="$(random_free_port)"
    ask_free_port "$def" snell_port_taken snell_port_conflict SNELL_ASK_PORT
}

random_free_port() {
    local p=0 i
    for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
        p=$(( (RANDOM * 32768 + RANDOM) % 40000 + 20000 ))
        if ! snell_port_conflict "$p"; then break; fi
    done
    printf '%s' "$p"
}

snell_client_line() {   # snell_client_line [端口，默认主端口]
    local host port psk mode major name conf
    port="${1:-$(snell_port)}"
    conf="$(snell_port_conf "$port")"
    psk="$(snell_conf_get psk "$conf" 2>/dev/null || true)"
    mode="$(snell_conf_get mode "$conf" 2>/dev/null || true)"
    mode="${mode:-default}"
    snell_load_state
    host="${SNELL_PUBLIC_HOST:-$(detect_public_host)}"
    if [ -z "$host" ]; then
        warn "$(L '未能确定公网地址，无法生成 Snell 分享行')"
        return 1
    fi
    name="${SNELL_NODE_NAME:-Snell-v${SNELL_MAJOR}}"
    if [ "$port" != "$(snell_port)" ]; then name="${name}-${port}"; fi
    major="$(snell_ver_major "$(snell_installed_version)")"
    [[ "$major" =~ ^[0-9]+$ ]] || major="$SNELL_MAJOR"
    printf '%s = snell, %s, %s, psk=%s, version=%s, mode=%s, reuse=true' "$name" "$host" "$port" "$psk" "$major" "$mode"
}

# 列出全部端口配置（带序号）。序号 1 始终是主端口
snell_list_ports() {
    local p n=0 conf st kind
    while IFS= read -r p; do
        n=$((n + 1))
        conf="$(snell_port_conf "$p")"
        if tcp_listening "$p"; then st="${GREEN}$(L '监听中')${NC}"; else st="${RED}$(L '未监听')${NC}"; fi
        if [ "$n" -eq 1 ]; then kind="$(L '主端口')  "; else kind="$(L '附加端口')"; fi
        echo -e "  ${BOLD}${n})${NC} ${kind} ${p}    mode $(snell_conf_get mode "$conf" 2>/dev/null || echo default)    ${st}"
    done < <(snell_all_ports)
    return 0
}

# 新增一份端口配置：独立的端口 + PSK + mode，由 snell-port@端口 实例承载
snell_add_port() {
    snell_require || return 1
    local port psk mode="default" pref ans conf
    local pskre='^[A-Za-z0-9_-]{12,255}$'
    step "$(L '新增 Snell 端口配置')"
    divider
    echo "  $(L '现有端口配置：')"
    snell_list_ports
    echo ""
    info "$(L '新端口使用独立的 PSK 与 mode，和现有端口互不影响（可以给不同设备 / 不同用途各用一份）')"
    snell_ask_new_port
    port="$SNELL_ASK_PORT"
    while true; do
        read -rp "$(L 'PSK（回车自动生成 32 位随机串；自定义需 12-255 位，仅限字母、数字、- 和 _）:') " psk || { [ -n "$psk" ] || return 1; }
        if [ -z "$psk" ]; then
            psk="$(snell_gen_psk)"
            if [ "${#psk}" -ne 32 ]; then warn "$(L '随机 PSK 生成失败')"; return 1; fi
            break
        fi
        if [[ "$psk" =~ $pskre ]]; then break; fi
        warn "$(L 'PSK 不符合要求')"
    done
    echo "  $(L 'mode：1')) $(L 'default（默认）  2')) unshaped  3) $(L 'unsafe-raw（明文，仅可信内网）')"
    read -rp "  $(L '选择') [$(L '1/2/3，默认1')]: " ans || { [ -n "$ans" ] || return 1; }
    case "${ans:-1}" in
        2) mode="unshaped" ;;
        3) if confirm "$(L 'unsafe-raw 为明文传输，确认？')" n; then mode="unsafe-raw"; fi ;;
        *) : ;;
    esac
    pref="$(snell_conf_get dns-ip-preference 2>/dev/null || true)"
    conf="${SNELL_PORTS_DIR}/${port}.conf"
    snell_ensure_user || return 1
    snell_write_conf "$port" "$psk" "$mode" "${pref:-default}" "$conf"
    snell_write_port_unit
    systemctl daemon-reload
    systemctl enable "snell-port@${port}" >/dev/null 2>&1 || true
    systemctl restart "snell-port@${port}" 2>/dev/null || true
    sleep 2
    if ! snell_extra_healthy "$port"; then
        warn "$(L '新端口未能启动，已撤回。日志：')"
        journalctl -u "snell-port@${port}" -n 15 --no-pager 2>/dev/null || true
        systemctl disable --now "snell-port@${port}" >/dev/null 2>&1 || true
        rm -f "$conf"
        return 1
    fi
    success "$(L '端口') ${port} $(L '已添加并监听')"
    fw_allow_for_service "${port}/tcp"
    reserved_ports_sync || true
    echo ""
    echo -e "${BOLD}$(L 'Surge 节点配置：')${NC}"
    SNELL_LINE="$(snell_client_line "$port")" && echo -e "${GREEN}${SNELL_LINE}${NC}"
    return 0
}

# 删除某一份端口配置。可删任意一份：
#   删附加端口 = 停掉它的实例并删除配置；
#   删主端口   = 由序号最小的附加端口接替为主配置（它的端口与 PSK 不变，用它的客户端不受影响）；
#   只剩一份时删除等同于卸载，转去走卸载流程。
snell_delete_port() {
    snell_require || return 1
    local target="${1:-}" main p ans promote bak
    local -a all=()
    step "$(L '删除 Snell 端口配置')"
    divider
    main="$(snell_port)"
    while IFS= read -r p; do all+=("$p"); done < <(snell_all_ports)
    if [ "${#all[@]}" -eq 0 ]; then warn "$(L '没有找到任何端口配置')"; return 1; fi
    if [ -z "$target" ]; then
        snell_list_ports
        read -rp "$(L '输入要删除的序号（回车取消）:') " ans || { [ -n "$ans" ] || return 1; }
        if [ -z "$ans" ]; then info "$(L '已取消')"; return 0; fi
        if [[ ! "$ans" =~ ^[0-9]+$ ]] || [ "$ans" -lt 1 ] || [ "$ans" -gt "${#all[@]}" ]; then warn "$(L '序号无效')"; return 1; fi
        target="${all[$((ans - 1))]}"
    elif ! snell_port_taken "$target"; then
        warn "$(L '端口') ${target} $(L '不是本机的 Snell 端口配置（现有:') ${all[*]}$(L '）')"
        return 1
    fi

    if [ "${#all[@]}" -eq 1 ]; then
        warn "$(L '端口') ${target} $(L '是唯一的一份配置，删除它等于卸载 Snell')"
        snell_uninstall
        return $?
    fi

    if [ "$target" != "$main" ]; then
        confirm "$(L '确认删除附加端口') ${target} $(L '的配置？（使用该端口的客户端将无法连接）')" n || { info "$(L '已取消')"; return 0; }
        systemctl disable --now "snell-port@${target}" >/dev/null 2>&1 || true
        rm -f "${SNELL_PORTS_DIR}/${target}.conf"
    else
        promote="${all[1]}"
        info "$(L '端口') ${target} $(L '是主端口配置：删除后由附加端口') ${promote} $(L '接替为主配置（')${promote} $(L '的端口与 PSK 不变）')"
        confirm "$(L '确认删除主端口') ${target} $(L '的配置？（使用该端口的客户端将无法连接）')" n || { info "$(L '已取消')"; return 0; }
        bak="${SNELL_CONF}.bak"
        cp -f "$SNELL_CONF" "$bak"
        systemctl disable --now "snell-port@${promote}" >/dev/null 2>&1 || true
        cp -f "${SNELL_PORTS_DIR}/${promote}.conf" "$SNELL_CONF"
        snell_fix_perms
        if ! svc_restart_wait snell 2 15 || ! snell_main_healthy; then
            warn "$(L '接替后主服务未能启动，已恢复原样。日志：')"
            mv -f "$bak" "$SNELL_CONF"
            snell_fix_perms
            systemctl restart snell 2>/dev/null || true
            systemctl enable "snell-port@${promote}" >/dev/null 2>&1 || true
            systemctl restart "snell-port@${promote}" 2>/dev/null || true
            return 1
        fi
        rm -f "$bak" "${SNELL_PORTS_DIR}/${promote}.conf"
    fi
    success "$(L '端口') ${target} $(L '的配置已删除')"
    fw_prune_old_specs "${target}/tcp"
    reserved_ports_sync || true
    echo ""
    echo "  $(L '剩余端口配置：')"
    snell_list_ports
    return 0
}

snell_show_config() {
    snell_require || return 1
    step "$(L 'Snell 配置')"
    divider
    snell_load_state
    echo -e "  $(L '版本     :') ${GREEN}$(snell_installed_version)${NC}"
    echo -e "  $(L '配置文件 :') ${GREEN}${SNELL_CONF}${NC}"
    echo -e "  $(L '监听     :') ${GREEN}$(snell_conf_get listen 2>/dev/null || echo '?')${NC}"
    echo -e "  PSK      : ${GREEN}$(snell_conf_get psk 2>/dev/null || echo '?')${NC}"
    echo -e "  mode     : ${GREEN}$(snell_conf_get mode 2>/dev/null || echo 'default')${NC}"
    echo -e "  $(L 'DNS 偏好 :') ${GREEN}$(snell_conf_get dns-ip-preference 2>/dev/null || echo 'default')${NC}"
    echo -e "  $(L '自动更新 :') ${GREEN}$([ "$SNELL_AUTO_UPDATE" = "1" ] && echo "开启（${SNELL_CHANNEL} 通道）" || echo "关闭")${NC}"
    echo ""
    echo -e "${BOLD}$(L 'Surge 节点配置（粘贴到') [Proxy] $(L '段）：')${NC}"
    SNELL_LINE="$(snell_client_line)" && echo -e "${GREEN}${SNELL_LINE}${NC}"
    local xp xconf
    while IFS= read -r xp; do
        xconf="${SNELL_PORTS_DIR}/${xp}.conf"
        echo ""
        echo -e "  ${BOLD}$(L '附加端口') ${xp}${NC}$(L '（')${xconf}$(L '）  mode') $(snell_conf_get mode "$xconf" 2>/dev/null || echo default)  PSK $(snell_conf_get psk "$xconf" 2>/dev/null || echo '?')"
        SNELL_LINE="$(snell_client_line "$xp")" && echo -e "${GREEN}${SNELL_LINE}${NC}"
    done < <(snell_extra_ports)
    echo ""
    echo "  $(L '说明：')"
    echo "  $(L '· mode 必须与服务端一致（官方要求），否则无法连通')"
    echo "  $(L '· v6 的协议特征由 PSK 派生：更换 PSK 等于更换一套流量特征，客户端需同步修改')"
    echo "  $(L '· v6 已移除 QUIC Proxy Mode，UDP 走 UDP over TCP，防火墙只需放行 TCP') $(snell_all_ports | paste -sd, -)$(L '；官方建议客户端屏蔽 QUIC 让应用回落到 HTTP/2')"
    echo "  $(L '· 需要支持 Snell v6 的 Surge 版本；官方未说明 v6 服务端兼容 v4/v5 客户端，第三方客户端是否支持请以其文档为准')"
    return 0
}

snell_enable_autoupdate() {
    snell_load_state
    SNELL_AUTO_UPDATE="1"
    snell_save_state
    maint_install_timers || return 1
    success "$(L '已开启 Snell 自动更新：每日维护任务（凌晨 4–6 点）检查官方发布，')${SNELL_CHANNEL} $(L '通道有 v')${SNELL_MAJOR} $(L '新版本即自动升级，启动失败自动回滚')"
    info "$(L '查看记录: adam maintain-log    或 journalctl -u adam-maintain --no-pager -n 30')"
    return 0
}

snell_disable_autoupdate() {
    snell_load_state
    SNELL_AUTO_UPDATE="0"
    if [ -d "$SNELL_DIR" ]; then snell_save_state; fi
    success "$(L '已关闭 Snell 自动更新（保活巡检不受影响）')"
    return 0
}

snell_toggle_autoupdate() {
    snell_require || return 1
    snell_load_state
    if [ "$SNELL_AUTO_UPDATE" = "1" ]; then
        info "$(L '自动更新当前为：开启（')${SNELL_CHANNEL} $(L '通道）')"
        echo "  1) $(L '关闭自动更新')"
        echo "  2) $(L '切换通道（当前') ${SNELL_CHANNEL}$(L '；beta=跟随最新测试版 b/rc 及正式版，stable=只跟正式版）')"
        echo "  0) $(L '返回')"
        local c
        read -rp "$(L '请选择:') " c || { [ -n "$c" ] || return 1; }
        case "$c" in
            1) snell_disable_autoupdate ;;
            2)
                if [ "$SNELL_CHANNEL" = "stable" ]; then SNELL_CHANNEL="beta"; else SNELL_CHANNEL="stable"; fi
                snell_save_state
                success "$(L '已切换到') ${SNELL_CHANNEL} $(L '通道')"
                ;;
            *) : ;;
        esac
    else
        info "$(L '自动更新当前为：关闭')"
        if confirm "$(L '开启自动更新？')" y; then snell_enable_autoupdate; fi
    fi
    return 0
}

# 定时器调用：全程不提问，输出进 journal
# autoupdate_check CUR LATEST MAJOR SRC_OK GT_FN：0=有新版可升，1=已最新/跳过，2=取不到版本（M10）
# MAJOR 为空表示不做大版本保护；Xray 传已装版本的主版本，同样不自动跨大版本
autoupdate_check() {
    local cur="$1" latest="$2" major="${3:-}" src_ok="${4:-0}" gt_fn="$5" lm=""
    if [ -z "$latest" ]; then
        if [ "$src_ok" = "1" ]; then
            echo "$(L '官方暂无可用版本，当前') ${cur:-$(L '未知')}"
            return 1
        fi
        echo "$(L '未能获取官方版本信息，本次跳过；当前') ${cur:-$(L '未知')}"
        return 2
    fi
    if [ -n "$major" ]; then
        lm="$(version_major "$latest")"
        if [ -n "$lm" ] && [ "$lm" != "$major" ]; then
            echo "$(L '最新版本属于另一个大版本（v')${lm}$(L '），不自动跨大版本，当前') ${cur:-$(L '未知')}"
            return 1
        fi
    fi
    if [ -n "$cur" ] && ! "$gt_fn" "$latest" "$cur"; then
        echo "$(L '已是最新:') ${cur}"
        return 1
    fi
    return 0
}

snell_autoupdate() {
    local arch current
    if [ ! -x "$SNELL_BIN" ]; then
        echo "$(L 'Snell 未安装，跳过')"
        return 0
    fi
    arch="$(snell_arch)" || return 1
    snell_load_state
    current="$(snell_installed_version)"
    if [ "$(snell_ver_major "$current")" != "$SNELL_MAJOR" ]; then
        echo "$(L '当前安装的是') ${current:-$(L '未知版本')}$(L '，不是 v')${SNELL_MAJOR} $(L '系列，自动更新不跨大版本，跳过')"
        return 0
    fi
    snell_query_latest "$arch" "$SNELL_CHANNEL" "$current"
    if [ -n "$SNELL_NEWER_MAJOR" ]; then
        echo "$(L '提示：官方已发布更高大版本') ${SNELL_NEWER_MAJOR}$(L '，需要客户端同步升级，不会自动跨大版本')"
    fi
    local _auc_rc=0
    autoupdate_check "$current" "$SNELL_LATEST" "$SNELL_MAJOR" "$SNELL_SOURCE_OK" snell_ver_gt || _auc_rc=$?
    case "$_auc_rc" in
        0) ;;
        1) return 0 ;;
        *) return 1 ;;
    esac
    echo "$(L '发现新版本:') ${current} → ${SNELL_LATEST}$(L '，开始更新')"
    if snell_upgrade_to "$SNELL_LATEST"; then
        maint_log "[Snell] $(L '已自动更新:') ${current} -> ${SNELL_LATEST}"
        return 0
    fi
    maint_log "[Snell] $(L '自动更新到') ${SNELL_LATEST} $(L '失败，当前仍为') $(snell_installed_version)"
    return 1
}

snell_update() {
    snell_require || return 1
    maint_lock_manual || return 1
    step "$(L '检查 Snell 更新')"
    divider
    local arch current
    arch="$(snell_arch)" || return 1
    snell_load_state
    current="$(snell_installed_version)"
    info "$(L '当前版本:') ${current:-$(L '未知')}$(L '（')${SNELL_CHANNEL} $(L '通道）')"
    info "$(L '正在查询 Surge 官方发布页 ...')"
    snell_query_latest "$arch" "$SNELL_CHANNEL" "$current"
    if [ -n "$SNELL_NEWER_MAJOR" ]; then
        warn "$(L '官方已发布更高大版本') ${SNELL_NEWER_MAJOR}$(L '：跨大版本需要客户端同步升级、配置格式也可能变化，本脚本不自动处理')"
    fi
    if [ -z "$SNELL_LATEST" ]; then
        if [ "$SNELL_SOURCE_OK" = "1" ] && [ -n "$SNELL_LATEST_PRE" ]; then
            info "$(L '正式版通道暂无 v')${SNELL_MAJOR} $(L '版本；测试版最新为') ${SNELL_LATEST_PRE}$(L '（可在「自动更新」里切到 beta 通道）')"
        else
            warn "$(L '未能获取官方版本信息（')${SNELL_KB_URLS[0]} $(L '不可达或页面结构变化）')"
        fi
        return 1
    fi
    info "$(L '官方最新:') ${SNELL_LATEST}"
    if [ -n "$current" ] && ! snell_ver_gt "$SNELL_LATEST" "$current"; then
        success "$(L '已经是最新版本')"
        return 0
    fi
    if ! confirm "$(L '升级到') ${SNELL_LATEST}$(L '？（服务会重启，约 2 秒中断；启动失败自动回滚）')" y; then
        info "$(L '已取消')"
        return 0
    fi
    snell_upgrade_to "$SNELL_LATEST"
}

snell_install() {
    step "$(L '安装 Snell Server（Surge 官方，v')${SNELL_MAJOR}$(L '）')"
    divider
    local arch current latest port="" psk="" mode="default" pref="default" host name keep=0 ans old_port def_port
    local hostre='^[][A-Za-z0-9.:_-]+$' namere='^[A-Za-z0-9._-]+$' pskre='^[A-Za-z0-9_-]{12,255}$'
    arch="$(snell_arch)" || return 1
    apt_install curl unzip ca-certificates iproute2 || { warn "$(L '依赖安装失败，请检查 apt 源/网络')"; return 1; }
    snell_load_state
    current="$(snell_installed_version)"
    old_port="$(snell_port)"

    echo -e "${BOLD}$(L '版本通道：')${NC}"
    echo "  1) $(L 'beta   - 跟随官方最新测试版（b / rc），正式版发布后自动转到正式版（默认）')"
    echo "  2) $(L 'stable - 只安装和跟随正式版')"
    read -rp "$(L '选择') [$(L '1/2，默认') $([ "$SNELL_CHANNEL" = "stable" ] && echo 2 || echo 1)]: " ans || { [ -n "$ans" ] || return 1; }
    case "${ans:-}" in
        1) SNELL_CHANNEL="beta" ;;
        2) SNELL_CHANNEL="stable" ;;
        *) : ;;
    esac
    info "$(L '正在查询官方最新版本（发布页 + 下载站探测，约几秒）...')"
    snell_query_latest "$arch" "$SNELL_CHANNEL" "$current"
    latest="$SNELL_LATEST"
    if [ -z "$latest" ] && [ -n "$SNELL_LATEST_PRE" ]; then
        warn "$(L '官方目前只有 v')${SNELL_MAJOR} $(L '的测试版（')${SNELL_LATEST_PRE}$(L '），还没有正式版')"
        if confirm "$(L '安装测试版') ${SNELL_LATEST_PRE}$(L '？（之后的自动更新也会跟随测试通道）')" y; then
            SNELL_CHANNEL="beta"
            latest="$SNELL_LATEST_PRE"
        else
            info "$(L '已取消')"
            return 0
        fi
    fi
    if [ -z "$latest" ]; then
        warn "$(L '未能从官方发布页取得 v')${SNELL_MAJOR} $(L '的版本信息（')${SNELL_KB_URLS[0]} $(L '不可达，或该架构') ${arch} $(L '没有 v')${SNELL_MAJOR} $(L '版本）')"
        read -rp "$(L '可手动输入版本号继续（如 v6.0.0，回车取消）:') " latest || { [ -n "$latest" ] || return 1; }
        latest="${latest//[[:space:]]/}"
        if [ -z "$latest" ]; then info "$(L '已取消')"; return 0; fi
        [[ "$latest" == v* ]] || latest="v${latest}"
        if ! snell_ver_key "$latest" >/dev/null 2>&1; then warn "$(L '版本号格式不合法')"; return 1; fi
    fi
    # 发布页偶尔滞后：本机已装的版本比发布页列出的还新时，重装不降级
    if [ -n "$current" ] && [ "$(snell_ver_major "$current")" = "$SNELL_MAJOR" ] && snell_ver_gt "$current" "$latest"; then
        info "$(L '本机已安装的') ${current} $(L '比发布页列出的') ${latest} $(L '更新，按') ${current} $(L '重装')"
        latest="$current"
    fi
    info "$(L '将安装:') ${latest}$(L '（linux-')${arch}$(L '）')"
    if [ -n "$SNELL_NEWER_MAJOR" ]; then
        info "$(L '提示：官方已有更高大版本') ${SNELL_NEWER_MAJOR}$(L '，本脚本按 v')${SNELL_MAJOR} $(L '的配置格式管理，不自动跨大版本')"
    fi

    if [ -f "$SNELL_CONF" ] && [ -n "$old_port" ] && [ -n "$(snell_conf_get psk 2>/dev/null || true)" ]; then
        info "$(L '检测到已有 Snell 配置（端口') ${old_port}$(L '）')"
        if confirm "$(L '保留现有端口和 PSK？（选 n 重新配置）')" y; then keep=1; fi
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
        SNELL_ASK_OLD_PORT="$old_port"
        ask_free_port "$def_port" snell_port_taken_new snell_port_conflict port || return 1
        while true; do
            read -rp "$(L 'PSK（回车自动生成 32 位随机串；自定义需 12-255 位，仅限字母、数字、- 和 _）:') " psk || { [ -n "$psk" ] || return 1; }
            if [ -z "$psk" ]; then
                psk="$(snell_gen_psk)"
                if [ "${#psk}" -ne 32 ]; then warn "$(L '随机 PSK 生成失败')"; return 1; fi
                info "$(L '已生成 PSK:') ${psk}"
                break
            fi
            if [[ "$psk" =~ $pskre ]]; then break; fi
            warn "$(L 'PSK 不符合要求')"
        done
        echo ""
        echo -e "${BOLD}$(L 'mode（服务端与客户端必须一致）：')${NC}"
        echo "  1) $(L 'default    - 流量整形混淆 + AES 加密（推荐）')"
        echo "  2) $(L 'unshaped   - 仅 AES 加密、不做混淆，吞吐约高 10%（官方说明：相当于 Snell v3）')"
        echo "  3) $(L 'unsafe-raw - 不加密、不混淆，明文转发（只适合可信内网 / 专线）')"
        read -rp "$(L '选择') [$(L '1/2/3，默认1')]: " ans || { [ -n "$ans" ] || return 1; }
        case "${ans:-1}" in
            2) mode="unshaped" ;;
            3)
                warn "$(L 'unsafe-raw 下所有流量明文传输，公网使用等于裸奔')"
                if confirm "$(L '确认使用 unsafe-raw？')" n; then mode="unsafe-raw"; else mode="default"; fi
                ;;
            *) mode="default" ;;
        esac
        echo ""
        echo -e "${BOLD}$(L '出站 DNS 地址族偏好 dns-ip-preference：')${NC}"
        echo "  1) default  2) prefer-ipv4  3) prefer-ipv6  4) ipv4-only  5) ipv6-only"
        read -rp "$(L '选择') [$(L '1-5，默认1')]: " ans || { [ -n "$ans" ] || return 1; }
        case "${ans:-1}" in
            2) pref="prefer-ipv4" ;; 3) pref="prefer-ipv6" ;; 4) pref="ipv4-only" ;; 5) pref="ipv6-only" ;; *) pref="default" ;;
        esac
    fi

    host="${SNELL_PUBLIC_HOST:-$(detect_public_host)}"
    while true; do
        read -rp "$(L '客户端连接用的公网地址（回车使用') ${host:-$(L '未探测到，请手动输入')}$(L '）:') " ans || { [ -n "$ans" ] || return 1; }
        ans="${ans:-$host}"
        if [[ -n "$ans" && "$ans" =~ $hostre ]]; then host="$ans"; break; fi
        warn "$(L '地址不能为空，且只能包含字母、数字和 . : - _') [ ]"
    done
    name="${SNELL_NODE_NAME:-Snell-v${SNELL_MAJOR}}"
    read -rp "$(L '节点名称（回车使用') ${name}$(L '）:') " ans || { [ -n "$ans" ] || return 1; }
    if [ -n "$ans" ]; then
        if [[ "$ans" =~ $namere ]]; then name="$ans"; else warn "$(L '名称只能包含字母、数字和 . _ -，已使用默认值')"; fi
    fi

    snell_ensure_user || return 1
    info "$(L '下载') ${latest} ..."
    snell_fetch "$latest" "$arch" || return 1
    snell_apply_binary "$latest"
    local snell_conf_bak=""
    if [ -f "$SNELL_CONF" ]; then snell_conf_bak="${SNELL_CONF}.bak.$(date +%Y%m%d-%H%M%S)"; cp -f "$SNELL_CONF" "$snell_conf_bak" || snell_conf_bak=""; fi
    snell_write_conf "$port" "$psk" "$mode" "$pref"
    snell_write_service
    systemctl daemon-reload
    systemctl enable snell >/dev/null 2>&1 || true
    systemctl restart snell 2>/dev/null || true
    sleep 2
    if snell_main_healthy; then
        success "Snell ${latest} $(L '已启动并监听 TCP') ${port}"
    else
        warn "$(L 'Snell 未能正常启动，最近日志：')"
        journalctl -u snell -n 20 --no-pager 2>/dev/null || true
        if [ -n "$snell_conf_bak" ] && [ -f "$snell_conf_bak" ]; then cp -f "$snell_conf_bak" "$SNELL_CONF"; snell_fix_perms; info "$(L '已恢复旧配置')"; fi
        snell_rollback_binary "$current" || true
        return 1
    fi

    SNELL_PUBLIC_HOST="$host"; SNELL_NODE_NAME="$name"
    snell_save_state
    snell_start_extras

    fw_allow_for_service "${port}/tcp"
    if [ -n "$old_port" ] && [ "$old_port" != "$port" ]; then fw_prune_old_specs "${old_port}/tcp"; fi

    echo ""
    reserved_ports_sync || true
    if [ "$SNELL_AUTO_UPDATE" = "1" ]; then
        snell_enable_autoupdate || true
    elif confirm "$(L '开启自动更新？（每天检查一次官方发布，')${SNELL_CHANNEL} $(L '通道有 v')${SNELL_MAJOR} $(L '新版本就自动升级，失败自动回滚）')" y; then
        snell_enable_autoupdate || true
    fi
    # 保活巡检默认随安装启用（可在主菜单「8) 自动维护」里关闭）
    maint_ask_script_auto
    maint_install_timers || true
    if snell_is_prerelease "$latest"; then
        warn "$(L '当前安装的是测试版') ${latest}$(L '：客户端需使用支持该版本的 Surge 测试渠道，协议在正式版前仍可能变动，两端要同步')"
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
    echo "$(L '当前：端口') ${port} · mode ${mode} $(L '· DNS 偏好') ${pref}"
    echo "  $(L '（这里修改的是主端口配置；附加端口请用「删除端口配置」+「新增端口配置」）')"
    echo "  1) $(L '修改端口')"
    echo "  2) $(L '重新生成 PSK（同时更换一套流量特征）')"
    echo "  3) $(L '自定义 PSK')"
    echo "  4) $(L '修改 mode')"
    echo "  5) $(L '修改 DNS 地址族偏好')"
    echo "  6) $(L '修改节点名称 / 公网地址（只影响生成的 Surge 配置行）')"
    echo "  0) $(L '返回')"
    read -rp "$(L '请选择:') " choice || { [ -n "$choice" ] || return 1; }
    case "$choice" in
        1)
            read -rp "$(L '新的监听端口:') " ans || { [ -n "$ans" ] || return 1; }
            if [[ ! "$ans" =~ ^[0-9]+$ ]] || [ "$((10#$ans))" -lt 1 ] || [ "$((10#$ans))" -gt 65535 ]; then warn "$(L '端口不合法')"; return 1; fi
            ans=$((10#$ans))
            if [ "$ans" != "$old_port" ] && snell_port_taken "$ans"; then warn "$(L '端口') ${ans} $(L '已经是本机的一份 Snell 附加端口配置')"; return 1; fi
            if snell_port_conflict "$ans"; then warn "$(L 'TCP 端口') ${ans} $(L '已被其他进程占用')"; return 1; fi
            port="$ans"
            ;;
        2)
            psk="$(snell_gen_psk)"
            if [ "${#psk}" -ne 32 ]; then warn "$(L '随机 PSK 生成失败')"; return 1; fi
            ;;
        3)
            read -rp "$(L '新的 PSK（12-255 位，仅限字母、数字、- 和 _）:') " ans || { [ -n "$ans" ] || return 1; }
            if [[ ! "$ans" =~ $pskre ]]; then warn "$(L 'PSK 不符合要求')"; return 1; fi
            psk="$ans"
            ;;
        4)
            echo "  1) default  2) unshaped  3) $(L 'unsafe-raw（明文，仅可信内网）')"
            read -rp "$(L '选择:') " ans || { [ -n "$ans" ] || return 1; }
            case "$ans" in
                1) mode="default" ;; 2) mode="unshaped" ;;
                3) if confirm "$(L 'unsafe-raw 为明文传输，确认？')" n; then mode="unsafe-raw"; else return 0; fi ;;
                *) warn "$(L '无效选择')"; return 1 ;;
            esac
            ;;
        5)
            echo "  1) default  2) prefer-ipv4  3) prefer-ipv6  4) ipv4-only  5) ipv6-only"
            read -rp "$(L '选择:') " ans || { [ -n "$ans" ] || return 1; }
            case "$ans" in
                1) pref="default" ;; 2) pref="prefer-ipv4" ;; 3) pref="prefer-ipv6" ;; 4) pref="ipv4-only" ;; 5) pref="ipv6-only" ;;
                *) warn "$(L '无效选择')"; return 1 ;;
            esac
            ;;
        6)
            local hostre='^[][A-Za-z0-9.:_-]+$' namere='^[A-Za-z0-9._-]+$'
            snell_load_state
            read -rp "$(L '公网地址（回车保持') ${SNELL_PUBLIC_HOST:-$(L '未设置')}$(L '）:') " ans || { [ -n "$ans" ] || return 1; }
            if [ -n "$ans" ]; then
                if [[ "$ans" =~ $hostre ]]; then SNELL_PUBLIC_HOST="$ans"; else warn "$(L '地址格式不合法，未修改')"; fi
            fi
            read -rp "$(L '节点名称（回车保持') ${SNELL_NODE_NAME:-Snell-v${SNELL_MAJOR}}$(L '）:') " ans || { [ -n "$ans" ] || return 1; }
            if [ -n "$ans" ]; then
                if [[ "$ans" =~ $namere ]]; then SNELL_NODE_NAME="$ans"; else warn "$(L '名称格式不合法，未修改')"; fi
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
    if ! svc_restart_wait snell 2 15 || ! snell_main_healthy; then
        warn "$(L '新配置启动失败，已恢复原配置。日志：')"
        mv -f "$bak" "$SNELL_CONF"
        snell_fix_perms
        systemctl restart snell 2>/dev/null || true
        return 1
    fi
    rm -f "$bak"
    success "$(L '配置已更新并重启')"
    if [ "$port" != "$old_port" ]; then
        fw_allow_for_service "${port}/tcp"
        fw_prune_old_specs "${old_port}/tcp"
        reserved_ports_sync || true
    fi
    warn "$(L '客户端需要同步修改，新的配置行如下')"
    snell_show_config
    return 0
}

snell_status() {
    snell_require || return 1
    systemctl status snell --no-pager 2>/dev/null | head -n 12 || true
    divider
    snell_load_state
    echo -e "  $(L '版本     :') $(snell_installed_version)"
    echo -e "  $(L '监听     :') $(snell_conf_get listen 2>/dev/null || echo '?')"
    echo -e "  $(L '自动更新 :') $([ "$SNELL_AUTO_UPDATE" = "1" ] && echo "开启（${SNELL_CHANNEL} 通道）" || echo "关闭")"
    echo "  $(L '最近的维护记录：')"
    if [ -s "$MAINT_LOG" ]; then grep -E 'Snell|snell' "$MAINT_LOG" 2>/dev/null | tail -n 5 || true; else echo "    $(L '（暂无）')"; fi
    return 0
}

# 健康检查（只检测，不改动）。返回 0 = 全部正常
# 全局健康检查行输出：HC_PROBLEMS 累计异常数（M11）
HC_PROBLEMS=0
hc_line() {
    case "$1" in
        0) echo -e "  ${GREEN}✓${NC} $2" ;;
        1) echo -e "  ${RED}✗${NC} $2"; HC_PROBLEMS=$((HC_PROBLEMS + 1)) ;;
        *) echo -e "  ${YELLOW}!${NC} $2" ;;
    esac
}

# health_check_common UNIT：服务运行/自启两行（Snell 与 Xray 健康检查共用，M11）
health_check_common() {
    local unit="$1" active enabled restarts
    active="$(systemctl is-active "$unit" 2>/dev/null || true)"
    enabled="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
    restarts="$(systemctl show "$unit" -p NRestarts --value 2>/dev/null || true)"
    if [ "$active" = "active" ]; then hc_line 0 "$(L '服务运行中（systemd 自动重启次数:') ${restarts:-0}$(L '）')"; else hc_line 1 "$(L '服务未运行（状态:') ${active:-unknown}$(L '）')"; fi
    if [ "$enabled" = "enabled" ]; then hc_line 0 "$(L '已设为开机自启')"; else hc_line 1 "$(L '未设为开机自启')"; fi
}

snell_health_check() {
    snell_require || return 1
    local port arch cur out
    HC_PROBLEMS=0
    step "$(L 'Snell 健康检查')"
    divider
    port="$(snell_port)"
    cur="$(snell_installed_version)"
    health_check_common snell
    if [ -n "$port" ]; then
        if tcp_listening "$port"; then hc_line 0 "TCP ${port} $(L '正在监听')"; else hc_line 1 "TCP ${port} $(L '没有在监听')"; fi
        if [ "$port" -ge 1024 ]; then
            if reserved_port_ok "$port"; then hc_line 0 "$(L '端口') ${port} $(L '已加入内核保留端口')"; else hc_line 1 "$(L '端口') ${port} $(L '未加入内核保留端口（可能被出站连接占用导致重启后绑定失败）')"; fi
        fi
        if ufw_active; then
            if fw_is_allowed "$port" tcp; then hc_line 0 "$(L '防火墙已放行') ${port}/tcp"; else hc_line 1 "$(L '防火墙未放行') ${port}/tcp"; fi
        else
            hc_line 2 "$(L 'ufw 未启用（如有云厂商安全组，请确认已放行') ${port}$(L '/tcp）')"
        fi
    else
        hc_line 1 "$(L '配置文件里读不到监听端口')"
    fi
    out="$(timeout 5 "$SNELL_BIN" -v 2>&1 < /dev/null || true)"
    if [[ "$out" == *"not found"* || "$out" == *"cannot execute"* || "$out" == *"GLIBC"* ]]; then
        hc_line 1 "$(L '二进制无法运行:') ${out}"
    else
        hc_line 0 "$(L '二进制可运行（')${cur:-$(L '版本未知')}$(L '）')"
    fi
    local xp
    while IFS= read -r xp; do
        if snell_extra_healthy "$xp"; then hc_line 0 "$(L '附加端口') ${xp} $(L '运行并监听中')"; else hc_line 1 "$(L '附加端口') ${xp} $(L '未运行或没有在监听')"; fi
        if [ "$xp" -ge 1024 ] && ! reserved_port_ok "$xp"; then hc_line 1 "$(L '附加端口') ${xp} $(L '未加入内核保留端口')"; fi
        if ufw_active && ! fw_is_allowed "$xp" tcp; then hc_line 1 "$(L '防火墙未放行附加端口') ${xp}/tcp"; fi
    done < <(snell_extra_ports)
    if grep -q '^Restart=always' "$SNELL_SERVICE" 2>/dev/null; then hc_line 0 "$(L '服务单元已启用崩溃自动拉起')"; else hc_line 1 "$(L '服务单元未启用 Restart=always（旧版单元）')"; fi
    maint_load
    if [ "$MAINT_WATCHDOG" = "1" ] && systemctl is-active --quiet adam-watchdog.timer 2>/dev/null; then
        hc_line 0 "$(L '保活巡检定时器运行中（每 5 分钟）')"
    elif [ "$MAINT_WATCHDOG" != "1" ]; then
        hc_line 2 "$(L '保活巡检未开启')"
    else
        hc_line 1 "$(L '保活巡检定时器未运行')"
    fi
    snell_load_state
    if [ "$SNELL_AUTO_UPDATE" = "1" ]; then
        if systemctl is-active --quiet adam-maintain.timer 2>/dev/null; then
            hc_line 0 "$(L '自动更新已开启（')${SNELL_CHANNEL} $(L '通道）')"
        else
            hc_line 1 "$(L '自动更新已开启，但每日维护定时器未运行')"
        fi
    else
        hc_line 2 "$(L '自动更新未开启')"
    fi
    arch="$(snell_arch 2>/dev/null || true)"
    if [ -n "$arch" ] && [ -n "$cur" ]; then
        if snell_dl_exists "$arch" "$cur"; then
            snell_query_latest "$arch" "$SNELL_CHANNEL" "$cur"
            if [ -n "$SNELL_LATEST" ] && snell_ver_gt "$SNELL_LATEST" "$cur"; then
                hc_line 2 "$(L '官方有新版本') ${SNELL_LATEST}$(L '（当前') ${cur}$(L '），可用「检查并更新」升级')"
            else
                hc_line 0 "$(L '已是') ${SNELL_CHANNEL} $(L '通道最新版本')"
            fi
            if [ -n "$SNELL_NEWER_MAJOR" ]; then hc_line 2 "$(L '官方已有更高大版本') ${SNELL_NEWER_MAJOR}$(L '（不自动跨大版本）')"; fi
        else
            hc_line 2 "$(L '暂时连不上官方下载站，无法判断是否有新版本')"
        fi
    fi
    divider
    if [ "$HC_PROBLEMS" -eq 0 ]; then
        success "$(L '健康检查通过')"
        return 0
    fi
    warn "$(L '发现') ${HC_PROBLEMS} $(L '项问题，可用「一键修复」处理')"
    return 1
}

# 一键修复：补齐服务单元 / 权限 / 保留端口 / 防火墙 / 定时器，然后重启并复查
snell_repair() {
    snell_require || return 1
    local port
    step "$(L 'Snell 一键修复')"
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
    snell_start_extras
    if ufw_active; then
        local rp
        while IFS= read -r rp; do ufw allow "${rp}/tcp" >/dev/null 2>&1 || true; done < <(snell_extra_ports)
    fi
    systemctl restart snell 2>/dev/null || true
    sleep 2
    if snell_healthy; then
        success "$(L '修复完成，服务运行正常')"
    else
        warn "$(L '修复后服务仍未正常监听，最近日志：')"
        journalctl -u snell -n 20 --no-pager 2>/dev/null || true
        return 1
    fi
    return 0
}

snell_logs() {
    snell_require || return 1
    info "$(L '实时日志（Ctrl+C 返回）')"
    journalctl -u snell -n 30 -f || true
    return 0
}

snell_restart() {
    snell_require || return 1
    snell_restart_all
    sleep 2
    if snell_healthy; then
        success "$(L 'Snell 已重启（含全部附加端口）')"
    else
        warn "$(L '重启后未检测到服务正常监听：')"
        journalctl -u snell -n 15 --no-pager 2>/dev/null || true
        return 1
    fi
    return 0
}

snell_uninstall() {
    if [ ! -x "$SNELL_BIN" ] && [ ! -f "$SNELL_SERVICE" ]; then
        info "$(L '未检测到 Snell 安装')"
        return 0
    fi
    local port p ports
    port="$(snell_port)"
    ports="$(snell_all_ports | tr '\n' ' ')"
    if ! confirm "$(L '确认卸载 Snell（全部端口配置:') ${ports:-$(L '无')}$(L '）？')" n; then info "$(L '已取消')"; return 0; fi
    systemctl disable --now snell >/dev/null 2>&1 || true
    while IFS= read -r p; do
        systemctl disable --now "snell-port@${p}" >/dev/null 2>&1 || true
    done < <(snell_extra_ports)
    rm -f "$SNELL_PORT_UNIT"
    rm -f "$SNELL_SERVICE" "$SNELL_BIN" "$SNELL_BIN_BACKUP" "$SNELL_VERSION_FILE"
    systemctl daemon-reload
    if [ -n "${ports// /}" ] && ufw_installed; then
        if confirm "$(L '同时删除防火墙里 Snell 端口（')${ports}$(L '）的放行规则？')" y; then
            # 配置还在时 managed_ports 仍会包含这些端口，这里直接删
            while IFS= read -r p; do [ -n "$p" ] || continue; fw_delete_spec "${p}/tcp"; done < <(printf '%s\n' "$ports" | tr ' ' '\n' | grep -v '^$')
        fi
    fi
    if confirm "$(L '同时删除配置目录') ${SNELL_DIR}$(L '（含 PSK）？')" n; then
        rm -rf "$SNELL_DIR"
        userdel snell >/dev/null 2>&1 || true
    else
        info "$(L '已保留') ${SNELL_DIR}$(L '，重装时可直接沿用端口和 PSK（附加端口也会一并恢复）')"
    fi
    reserved_ports_sync || true
    success "$(L 'Snell 已卸载')"
    return 0
}

snell_state_text() {
    local v
    if [ ! -x "$SNELL_BIN" ]; then
        printf '%s' "${YELLOW}$(L '未安装')${NC}"
        return 0
    fi
    v=""
    if [ -f "$SNELL_VERSION_FILE" ]; then v="$(tr -d ' \r\n' < "$SNELL_VERSION_FILE" 2>/dev/null || true)"; fi
    local n; n="$(snell_all_ports | grep -c . || true)"
    printf '%s' "${v:-$(L '版本未知')} · ${n} $(L '个端口 ·') $(svc_state snell)"
}

snell_menu() {
    local choice
    while true; do
        clear 2>/dev/null || true
        snell_load_state
        echo -e "${BOLD}${CYAN}━━━ $(L 'Snell Server 管理（Surge 官方，v')${SNELL_MAJOR}$(L '）') ━━━${NC}"
        echo -e "  $(L '当前状态:') $(snell_state_text)    $(L '通道:') ${SNELL_CHANNEL}    $(L '自动更新:') $(maint_onoff "$SNELL_AUTO_UPDATE")"
        divider
        echo -e "  ${GREEN}1)${NC}  ${GREEN}$(L '安装')${NC} $(L '/ 重装 Snell（自动获取官方最新版，默认跟随测试版）')"
        echo -e "  ${GREEN}2)${NC}  $(L '检查并更新到官方最新版')"
        echo -e "  ${GREEN}3)${NC}  $(L '查看配置 / Surge 节点配置行（全部端口）')"
        echo -e "  ${GREEN}4)${NC}  $(L '修改主端口配置（端口 / PSK / mode / DNS 偏好 / 节点名）')"
        echo -e "  ${GREEN}5)${NC}  ${GREEN}$(L '新增')${NC}$(L '端口配置（多端口：每个端口独立 PSK）')"
        echo -e "  ${GREEN}6)${NC}  ${RED}$(L '删除')${NC}$(L '某个端口配置（可选任意一个端口）')"
        echo -e "  ${GREEN}7)${NC}  $(L '自动更新 开 / 关 / 切换通道（beta') ⇄ $(L 'stable）')"
        echo -e "  ${GREEN}8)${NC}  $(L '健康检查（只检测）')"
        echo -e "  ${GREEN}9)${NC}  $(L '一键修复（单元 / 保留端口 / 防火墙 / 保活定时器）')"
        echo -e "  ${GREEN}10)${NC} $(L '服务状态')"
        echo -e "  ${GREEN}11)${NC} $(L '实时日志')"
        echo -e "  ${GREEN}12)${NC} $(L '重启服务')"
        echo -e "  ${GREEN}13)${NC} ${RED}$(L '卸载')${NC} Snell"
        echo -e "  ${GREEN}0)${NC}  $(L '返回主菜单')"
        divider
        read -rp "$(L '请选择') [0-13]: " choice
        case "$choice" in
            1)  run_action snell_install ;;
            2)  run_action snell_update ;;
            3)  run_action snell_show_config ;;
            4)  run_action snell_reconfig ;;
            5)  run_action snell_add_port ;;
            6)  run_action snell_delete_port ;;
            7)  run_action snell_toggle_autoupdate ;;
            8)  run_action snell_health_check ;;
            9)  run_action snell_repair ;;
            10) run_action snell_status ;;
            11) run_action snell_logs ;;
            12) run_action snell_restart ;;
            13) run_action snell_uninstall ;;
            0)  return 0 ;;
            *)  warn "$(L '无效选择')" ;;
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
        ports)       snell_require && snell_list_ports ;;
        add-port)    snell_add_port ;;
        del-port)    snell_delete_port "${1:-}" ;;
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
        *) error "$(L '未知的 snell 子命令:') ${sub}$(L '（可用: install / update / config / reconfig / ports / add-port / del-port') [$(L '端口')] / status / health / repair / logs / restart / auto [on|off] $(L '/ uninstall）')" ;;
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
    local ver="$1" asset base want got
    asset="$(xray_asset_name)" || return 1
    XRAY_DL_DIR=""
    make_workdir || return 1
    local wd="$WORKDIR"
    base="https://github.com/${XRAY_REPO}/releases/download/${ver}"
    if ! curl -fL --retry 3 --connect-timeout 10 --max-time 300 -o "$wd/xray.zip" "${base}/${asset}"; then
        warn "$(L '下载失败:') ${base}/${asset}"
        return 1
    fi
    if ! curl -fsSL --retry 2 --max-time 30 -o "$wd/xray.dgst" "${base}/${asset}.dgst"; then
        warn "$(L '未能下载官方校验文件') ${asset}$(L '.dgst，为安全起见中止')"
        return 1
    fi
    want="$(grep -iE '^SHA(2-)?256' "$wd/xray.dgst" | awk '{print $NF}' | head -n 1 || true)"
    got="$(sha256sum "$wd/xray.zip" | awk '{print $1}')"
    if [ -z "$want" ] || [ "$want" != "$got" ]; then
        warn "$(L 'SHA256 校验失败（官方') ${want:-$(L '未知')}$(L '，实际') ${got}$(L '），已中止')"
        return 1
    fi
    success "$(L 'SHA256 校验通过（官方 .dgst）')"
    unzip -tq "$wd/xray.zip" >/dev/null 2>&1 || { warn "$(L '压缩包损坏')"; return 1; }
    mkdir -p "$wd/x"
    unzip -oq "$wd/xray.zip" -d "$wd/x" || { warn "$(L '解压失败')"; return 1; }
    [ -f "$wd/x/xray" ] || { warn "$(L '压缩包里没有 xray 二进制')"; return 1; }
    chmod 755 "$wd/x/xray"
    if ! "$wd/x/xray" version >/dev/null 2>&1; then
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

# 确保 geoip.dat / geosite.dat 在位（大陆拦截规则依赖它们）；缺失时从官方 release 下载
xray_ensure_geo_data() {
    local missing=0 f url
    for f in geoip.dat geosite.dat; do
        [ -f "$XRAY_DIR/$f" ] || missing=1
    done
    [ "$missing" = "0" ] && return 0
    install -d -m 755 "$XRAY_DIR"
    for f in geoip.dat geosite.dat; do
        [ -f "$XRAY_DIR/$f" ] && continue
        case "$f" in
            geoip.dat) url="https://github.com/v2fly/geoip/releases/latest/download/geoip.dat" ;;
            geosite.dat) url="https://github.com/v2fly/domain-list-community/releases/latest/download/geosite.dat" ;;
        esac
        if curl -fsSL --max-time 60 "$url" -o "$XRAY_DIR/$f.tmp" 2>/dev/null && [ -s "$XRAY_DIR/$f.tmp" ]; then
            install -m 644 "$XRAY_DIR/$f.tmp" "$XRAY_DIR/$f"
        else
            rm -f "$XRAY_DIR/$f.tmp"
            warn "$(L '下载 geo 数据失败：')${f}$(L '，大陆拦截暂不可用')"
            return 1
        fi
    done
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
    if [ "${XRAY_CN_BLOCK:-1}" = "1" ]; then
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
# write_service_unit FILE DESC DOC STARTLIMIT USER GROUP EXEC CAPS NOFILE RESTART RESTARTSEC SVC_EXTRA：
# 五处 systemd unit 写出共用同一模板（原子写 mktemp+mv；M13）
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
        printf 'LimitNOFILE=%s\nRestart=%s\nRestartSec=%s\nNoNewPrivileges=true\n' "$nofile" "$restart" "$restartsec"
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

# xray_new_node_begin DEFAULT_PORT TAG_PREFIX NAME_PREFIX：问端口 + 生成 uuid/sid/listen/path/tag/name，结果写入 XN_*（M12）
xray_new_node_begin() {
    local def="$1" prefix="$2" name_prefix="$3"
    xray_ask_port "$(xray_default_port "$def")" || return 1
    XN_PORT="$XP_PORT"
    XN_UUID="$(xray_gen_uuid)"
    XN_SID="$(openssl rand -hex 8 2>/dev/null || true)"
    XN_LISTEN="$(xray_listen_addr)"
    XN_PATH="/$(openssl rand -hex 6 2>/dev/null || true)"
    if [[ ! "$XN_UUID" =~ ^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$ ]] || [[ ! "$XN_SID" =~ ^[0-9a-f]{16}$ ]] || [ "${#XN_PATH}" -lt 8 ]; then
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
    if ! tcp_port_conflict "$want" "__none__"; then printf '%s' "$want"; else random_free_port; fi
}

# 询问 REALITY 伪装站点，结果写入 XR_SNI
xray_ask_sni() {
    local ans re='^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$'
    echo "$(L 'REALITY 伪装站点（需是境外、支持 TLS 1.3 + HTTP/2 的站点；握手会转发到它的 443 端口）：')"
    echo "  1) www.microsoft.com   2) www.apple.com   3) www.amazon.com   4) $(L '自定义')"
    read -rp "$(L '选择') [$(L '1-4，默认1')]: " ans || { [ -n "$ans" ] || return 1; }
    case "${ans:-1}" in
        2) XR_SNI="www.apple.com" ;;
        3) XR_SNI="www.amazon.com" ;;
        4)
            while true; do
                read -rp "$(L '输入域名（不带 https:// 和端口）:') " ans || { [ -n "$ans" ] || return 1; }
                ans="$(printf '%s' "$ans" | tr -d ' \r\n')"
                if [[ "$ans" == *.* && "$ans" =~ $re ]]; then XR_SNI="$ans"; break; fi
                warn "$(L '域名格式不正确')"
            done
            ;;
        *) XR_SNI="www.microsoft.com" ;;
    esac
    # 尽力检查：从本机能否与该站点完成 TLS 1.3 + h2 握手（失败只提醒，不拦截）
    if command -v openssl >/dev/null 2>&1; then
        ans="$(timeout 8 openssl s_client -connect "${XR_SNI}:443" -servername "$XR_SNI" -tls1_3 -alpn h2 < /dev/null 2>/dev/null || true)"
        if [[ "$ans" == *"TLSv1.3"* && "$ans" == *"ALPN protocol: h2"* ]]; then
            success "${XR_SNI} $(L '支持 TLS 1.3 + HTTP/2，可用')"
        else
            warn "$(L '从本机未能确认') ${XR_SNI} $(L '支持 TLS 1.3 + HTTP/2（也可能只是本机到它的网络不通），如连不上请换一个站点')"
        fi
    fi
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
    local port uuid sid tag listen name
    xray_new_node_begin 443 vision VLESS-Vision || return 1
    port="$XN_PORT"; uuid="$XN_UUID"; sid="$XN_SID"; listen="$XN_LISTEN"; tag="$XN_TAG"; name="$XN_NAME"
    xray_ask_sni
    xray_gen_x25519 || { warn "$(L 'REALITY 密钥生成失败')"; return 1; }
    xray_commit_node "$tag" "    {
      \"tag\": \"${tag}\", \"listen\": \"${listen}\", \"port\": ${port}, \"protocol\": \"vless\",
      \"settings\": { \"clients\": [ { \"id\": \"${uuid}\", \"flow\": \"xtls-rprx-vision\" } ], \"decryption\": \"none\" },
      \"streamSettings\": {
        \"network\": \"tcp\", \"security\": \"reality\",
        \"realitySettings\": { \"show\": false, \"target\": \"${XR_SNI}:443\", \"xver\": 0, \"serverNames\": $(xray_reality_snis_json "${XR_SNI}"), \"privateKey\": \"${XK_PRIV}\", \"shortIds\": [\"${sid}\"] }
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
    xray_new_node_begin 8443 xhttp-reality VLESS-XHTTP-REALITY || return 1
    port="$XN_PORT"; uuid="$XN_UUID"; sid="$XN_SID"; listen="$XN_LISTEN"; path="$XN_PATH"; tag="$XN_TAG"; name="$XN_NAME"
    xray_ask_sni
    xray_gen_x25519 || { warn "$(L 'REALITY 密钥生成失败')"; return 1; }
    xray_ask_vlessenc ask || true
    xray_commit_node "$tag" "    {
      \"tag\": \"${tag}\", \"listen\": \"${listen}\", \"port\": ${port}, \"protocol\": \"vless\",
      \"settings\": { \"clients\": [ { \"id\": \"${uuid}\" } ], \"decryption\": \"${VE_DEC}\" },
      \"streamSettings\": {
        \"network\": \"xhttp\", \"security\": \"reality\",
        \"xhttpSettings\": { \"path\": \"${path}\", \"mode\": \"auto\" },
        \"realitySettings\": { \"show\": false, \"target\": \"${XR_SNI}:443\", \"xver\": 0, \"serverNames\": $(xray_reality_snis_json "${XR_SNI}"), \"privateKey\": \"${XK_PRIV}\", \"shortIds\": [\"${sid}\"] }
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
    local -a _ntags=()
    while IFS= read -r tag; do [ -n "$tag" ] && _ntags+=("$tag"); done < <(xray_node_tags)
    for tag in "${_ntags[@]}"; do
        (
            xray_node_load "$tag" || exit 1
            [ -n "$N_CERT_SRC" ] && [ -f "$N_CERT_SRC" ] && [ -f "$N_KEY_SRC" ] || exit 1
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
    if systemctl list-unit-files 2>/dev/null | grep -q '^certbot\.timer'; then
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
    local ans src_crt="" src_key="" cf_email cf_key
    if cert_is_valid "$domain" "$le_crt" "$le_key"; then
        info "$(L '检测到该域名已有有效证书，直接复用')"
        xray_install_cert "$tag" "$le_crt" "$le_key" || { warn "$(L '证书复制失败')"; return 1; }
        XRAY_OBT_CRT="$le_crt"; XRAY_OBT_KEY="$le_key"
        xray_ensure_certbot_timer
        return 0
    fi
    echo "$(L '证书申请方式：')"
    echo "  1) $(L 'HTTP-01（域名解析到本机 + 开放 80 端口，自动续期）')"
    echo "  2) $(L 'Cloudflare DNS-01（需要 CF API Key/Token，自动续期，80 端口可不开）')"
    echo "  3) $(L '已有证书文件（fullchain.pem + privkey.pem）')"
    read -rp "$(L '选择') [$(L '1/2/3，默认1')]: " ans || { [ -n "$ans" ] || return 1; }
    case "${ans:-1}" in
        3)
            # 域名仍须解析到本机，客户端才能连上（仅警告，不拦截）
            check_domain_dns "$domain" || true
            read -rp "$(L '证书文件路径（fullchain.pem）:') " src_crt || { [ -n "$src_crt" ] || return 1; }
            read -rp "$(L '私钥文件路径（privkey.pem）:') " src_key || { [ -n "$src_key" ] || return 1; }
            if [ ! -f "$src_crt" ] || [ ! -f "$src_key" ]; then warn "$(L '证书或私钥文件不存在')"; return 1; fi
            if ! cert_covers_domain "$src_crt" "$domain"; then
                warn "$(L '该证书的域名列表里没有') ${domain}"
                confirm "$(L '仍要使用？')" n || return 1
            fi
            xray_install_cert "$tag" "$src_crt" "$src_key" || { warn "$(L '证书复制失败')"; return 1; }
            XRAY_OBT_CRT="$src_crt"; XRAY_OBT_KEY="$src_key"
            return 0
            ;;
        2)
            check_domain_dns "$domain" || true
            apt_install certbot || { warn "$(L 'certbot 安装失败')"; return 1; }
            apt_install python3-certbot-dns-cloudflare || { warn "$(L 'certbot Cloudflare 插件安装失败')"; return 1; }
            if [ -s /etc/cloudflare/credentials.ini ]; then
                info "$(L 'Cloudflare 凭证文件已存在，直接复用')"
            else
                prompt_cloudflare_creds || return 1
                write_cloudflare_creds
            fi
            info "$(L '证书申请中（Cloudflare DNS-01，约需 30-60 秒）...')"
            certbot certonly --dns-cloudflare --dns-cloudflare-credentials /etc/cloudflare/credentials.ini \
                --non-interactive --agree-tos --email "$email" -d "$domain" \
                --dns-cloudflare-propagation-seconds 30 || { warn "$(L '证书申请失败：检查 CF 凭证与域名归属')"; return 1; }
            verify_issued_cert "$domain" "$le_crt" "$le_key" || { warn "$(L '证书签发后校验未通过')"; return 1; }
            success "$(L '证书申请成功')"
            xray_ensure_certbot_timer
            xray_install_cert "$tag" "$le_crt" "$le_key" || { warn "$(L '证书复制失败')"; return 1; }
            XRAY_OBT_CRT="$le_crt"; XRAY_OBT_KEY="$le_key"
            return 0
            ;;
        *)
            if ! check_domain_dns "$domain"; then
                confirm "$(L '域名解析未通过，HTTP-01 很可能失败，仍要继续申请？')" n || return 1
            fi
            apt_install certbot || { warn "$(L 'certbot 安装失败')"; return 1; }
            info "$(L '证书申请中（HTTP-01，需 80 端口）...')"
            ufw allow 80/tcp 2>/dev/null || true
            certbot certonly --standalone --preferred-challenges http --non-interactive \
                --agree-tos --email "$email" -d "$domain" \
                --http-01-port 80 --http-01-address 0.0.0.0 || { warn "$(L '证书申请失败：检查域名解析与 80 端口')"; return 1; }
            verify_issued_cert "$domain" "$le_crt" "$le_key" || { warn "$(L '证书签发后校验未通过')"; return 1; }
            success "$(L '证书申请成功')"
            xray_ensure_certbot_timer
            xray_install_cert "$tag" "$le_crt" "$le_key" || { warn "$(L '证书复制失败')"; return 1; }
            XRAY_OBT_CRT="$le_crt"; XRAY_OBT_KEY="$le_key"
            return 0
            ;;
    esac
}

# VLESS + XHTTP + TLS（直连域名证书）：TLS 只验证 SNI=域名，server 地址用域名或本机 IP 均可
xray_add_xhttp_tls() {
    local port uuid tag listen name path domain email re='^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$'
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
    port="$XN_PORT"; uuid="$XN_UUID"; listen="$XN_LISTEN"; path="$XN_PATH"; tag="$XN_TAG"; name="$XN_NAME"
    xray_ask_vlessenc ask || true
    XRAY_OBT_CRT=""; XRAY_OBT_KEY=""
    xray_obtain_cert "$domain" "$tag" "$email" || return 1
    local crt="${XRAY_CERT_DIR}/${tag}/fullchain.pem" key="${XRAY_CERT_DIR}/${tag}/privkey.pem"
    xray_commit_node "$tag" "    {
      \"tag\": \"${tag}\", \"listen\": \"${listen}\", \"port\": ${port}, \"protocol\": \"vless\",
      \"settings\": { \"clients\": [ { \"id\": \"${uuid}\" } ], \"decryption\": \"${VE_DEC}\" },
      \"streamSettings\": {
        \"network\": \"xhttp\", \"security\": \"tls\",
        \"tlsSettings\": { \"serverName\": \"${domain}\", \"alpn\": [\"h2\", \"http/1.1\"], \"certificates\": [ { \"certificateFile\": \"${crt}\", \"keyFile\": \"${key}\" } ] },
        \"xhttpSettings\": { \"path\": \"${path}\", \"mode\": \"auto\" }
      },
      ${XRAY_SNIFF}
    }" "N_TAG=\"${tag}\"
N_TYPE=\"xhttp-tls\"
N_PORT=\"${port}\"
N_UUID=\"${uuid}\"
N_DOMAIN=\"${domain}\"
N_PATH=\"${path}\"
N_ENC=\"${VE_ENC}\"
N_CERT_SRC=\"${XRAY_OBT_CRT}\"
N_KEY_SRC=\"${XRAY_OBT_KEY}\"
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

# 把全部 REALITY 节点的 serverNames 同步为 [伪装站点, 当前域名地址?]；有改动才重载
xray_sync_reality_snis() {
    local tag conf rc changed=0 dom
    xray_load_state
    dom="$(xray_host_domain || true)"
    command -v python3 >/dev/null 2>&1 || { warn "$(L '未找到 python3，无法同步 REALITY 域名')"; return 1; }
    local -a _ntags=()
    while IFS= read -r tag; do [ -n "$tag" ] && _ntags+=("$tag"); done < <(xray_node_tags)
    for tag in "${_ntags[@]}"; do
        xray_node_load "$tag" || continue
        case "$N_TYPE" in vision|xhttp-reality) ;; *) continue ;; esac
        conf="${XRAY_CONF_D}/10-in-${tag}.json"
        [ -f "$conf" ] || continue
        rc=0
        python3 - "$conf" "$N_SNI" "$dom" <<'PYEOF' || rc=$?
import json, sys
conf, sni, dom = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(conf) as f:
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
try:
    with open(conf, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
except Exception as e:
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
        xray_reload || return 1
        info "$(L '已同步 REALITY serverNames（域名地址可用）')"
    fi
    return 0
}

xray_add_xhttp_cdn() {
    local port uuid tag listen name path domain ans origin="tls" crt="" key="" src_crt="" src_key="" cport="443" tls_block=""
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
    port="$XN_PORT"; uuid="$XN_UUID"; listen="$XN_LISTEN"; path="$XN_PATH"; tag="$XN_TAG"; name="$XN_NAME"
    read -rp "$(L '客户端连接 CDN 的端口（回车默认 443）:') " ans || { [ -n "$ans" ] || return 1; }
    if [[ "${ans:-443}" =~ ^[0-9]+$ ]] && [ "$((10#${ans:-443}))" -ge 1 ] && [ "$((10#${ans:-443}))" -le 65535 ]; then
        cport="${ans:-443}"
    else
        warn "$(L '端口不合法（1-65535），已用默认 443')"
    fi
    xray_ask_vlessenc ask || true

    if [ "$origin" = "tls" ]; then
        dir="${XRAY_CERT_DIR}/${tag}"
        if [ -n "$src_crt" ]; then
            xray_install_cert "$tag" "$src_crt" "$src_key" || { warn "$(L '证书复制失败')"; return 1; }
        else
            install -d -m 750 "$dir"
            openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
                -subj "/CN=${domain}" -addext "subjectAltName=DNS:${domain}" \
                -keyout "$dir/privkey.pem" -out "$dir/fullchain.pem" >/dev/null 2>&1 \
                || { warn "$(L '自签证书生成失败')"; return 1; }
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
    info "$(L '记得在 CDN 侧：把') ${domain} $(L '的回源端口指到') ${port}$(L '（Cloudflare 可用 Origin Rules），并开启 gRPC / HTTP/2 回源以获得更好的 XHTTP 表现')"
}

xray_add_venc() {
    local port uuid tag listen name path
    echo "$(L 'VLESS Encryption + XHTTP：不套 TLS / REALITY，由 VLESS 自身的加密保护（适合直连，或明文回源的 CDN 之后）。')"
    xray_new_node_begin 8880 venc VLESS-ENC-XHTTP || return 1
    port="$XN_PORT"; uuid="$XN_UUID"; listen="$XN_LISTEN"; path="$XN_PATH"; tag="$XN_TAG"; name="$XN_NAME"
    xray_ask_vlessenc force || return 1
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
    pass="$(openssl rand -base64 "$bytes" 2>/dev/null | tr -d '\n' || true)"
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
                echo "vless://${N_UUID}@${N_DOMAIN}:${N_CPORT}?encryption=${N_ENC}&security=tls&sni=${N_DOMAIN}&fp=chrome&alpn=h2&type=xhttp&host=${N_DOMAIN}&path=${pathenc}&mode=packet-up#${N_NAME}" ;;
            xhttp-tls)
                echo "vless://${N_UUID}@${h}:${N_PORT}?encryption=${N_ENC}&security=tls&sni=${N_DOMAIN}&fp=chrome&alpn=h2&type=xhttp&host=${N_DOMAIN}&path=${pathenc}&mode=auto#${N_NAME}" ;;
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
            vision|xhttp-reality) echo "  $(L '伪装站点:') ${N_SNI}    $(L '公钥')(pbk): ${N_PBK}    shortId: ${N_SID}" ;;
        esac
        case "$N_TYPE" in
            xhttp-reality|xhttp-cdn|venc|xhttp-tls) echo "  $(L 'XHTTP 路径:') ${N_PATH}    VLESS Encryption: $([ "$N_ENC" = "none" ] && echo 未启用 || echo 已启用)" ;;
        esac
        if [ "$N_TYPE" = "xhttp-cdn" ]; then
            echo "  $(L 'CDN 域名:') ${N_DOMAIN}$(L '（客户端端口') ${N_CPORT}$(L '）   回源:') $([ "$N_ORIGIN" = "plain" ] && echo "明文 HTTP" || echo "TLS") → $(L '本机') ${N_PORT}"
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
            if tcp_listening "$N_PORT"; then st="${GREEN}$(L '监听中')${NC}"; else st="${RED}$(L '未监听')${NC}"; fi
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
    local ans old_specs
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
            read -rp "$(L '输入版本号（如 v26.3.27）:') " ans || { [ -n "$ans" ] || return 1; }
            ans="$(printf '%s' "$ans" | tr -d ' \r\n')"
            if [[ ! "$ans" =~ $re ]]; then warn "$(L '版本号格式不正确')"; return 1; fi
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
    step "$(L '安装 Xray（SS / VLESS）')"
    divider
    local host ans out hostre='^[][A-Za-z0-9.:_-]+$'
    xray_asset_name >/dev/null || return 1
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
    xray_fetch "$XRAY_TARGET" || return 1
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
        if svc_restart_wait adam-xray 2 10 && xray_healthy; then maint_log "[Xray] $(L '已回滚，服务恢复运行')"; else maint_log "[Xray] $(L '回滚后仍未启动: journalctl -u adam-xray -n 50')"; fi
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
    info "$(L '官方最新:') ${XRAY_LATEST}$([ "$XRAY_LATEST_IS_PRE" = "1" ] && echo "（预发布）")"
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
    local tag out cur days cert_lbl
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

xray_repair() {
    xray_require || return 1
    local spec
    step "$(L 'Xray 一键修复')"
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
    if xray_reload; then success "$(L '修复完成')"; else return 1; fi
    return 0
}

xray_status() {
    xray_require || return 1
    systemctl status adam-xray --no-pager 2>/dev/null | head -n 12 || true
    divider
    xray_load_state
    echo "  $(L '内核版本 :') $(xray_installed_version)"
    echo "  $(L '版本通道 :') ${XRAY_CHANNEL}$([ "$XRAY_CHANNEL" = "pin" ] && echo "（${XRAY_PIN_VERSION}）")    $(L '自动更新:') $([ "$XRAY_AUTO_UPDATE" = "1" ] && echo 开 || echo 关)"
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
    local specs
    confirm "$(L '确认卸载 Xray（本模块安装的 adam-xray）？')" n || { info "$(L '已取消')"; return 0; }
    specs="$(xray_ports | tr '\n' ' ')"
    systemctl disable --now adam-xray >/dev/null 2>&1 || true
    rm -f "$XRAY_SERVICE"
    rm -rf "$XRAY_DIR"
    systemctl daemon-reload
    if confirm "$(L '同时删除全部节点配置') ${XRAY_CONF_DIR}$(L '（含密钥）？')" n; then
        rm -rf "$XRAY_CONF_DIR"
        userdel adam-xray >/dev/null 2>&1 || true
        if [ -n "${specs// /}" ] && ufw_installed; then
            if confirm "$(L '同时删除防火墙里这些节点端口的放行规则（')${specs}$(L '）？')" y; then fw_prune_old_specs "$specs"; fi
        fi
        # 节点已全删：域名证书流程留下的凭证与续期任务一并清理（保留配置时不动，节点重装后仍需续期）
        if [ -f /etc/cloudflare/credentials.ini ]; then
            if [ -f "$CONFIG_FILE" ] && grep -q 'CERT_METHOD_VALUE="cloudflare-dns"' "$CONFIG_FILE" 2>/dev/null; then
                warn "$(L 'Cloudflare 凭证仍被 Nowhere 使用（域名证书续期），未删除')"
            elif confirm "$(L '删除保存的 Cloudflare API 凭证（/etc/cloudflare/credentials.ini）？')" n; then
                rm -f /etc/cloudflare/credentials.ini
                info "$(L '已删除 Cloudflare 凭证')"
            fi
        fi
        # 只删 Xray 的 certbot 续期 cron（无 deploy-hook 的那行）；Nowhere 自带 deploy-hook 的那行不动
        if crontab -l 2>/dev/null | grep -q 'certbot renew --quiet$'; then
            (crontab -l 2>/dev/null | grep -v 'certbot renew --quiet$' || true) | crontab - 2>/dev/null || true
            info "$(L '已移除 Xray 的 certbot 续期 cron 任务')"
        fi
        # Xray 的 HTTP-01 不再需要 80 端口时收回（Nowhere 用 HTTP-01 时保留，nowhere_ports 会列出它）
        if ! nowhere_ports 2>/dev/null | grep -qx '80/tcp'; then
            ufw delete allow 80/tcp 2>/dev/null || true
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
        echo -e "  ${GREEN}0)${NC}  $(L '返回主菜单')"
        divider
        read -rp "$(L '请选择') [0-16]: " choice
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
        *) error "$(L '未知的 xray 子命令:') ${sub}$(L '（可用: install / add / list / links / delete / update / health / repair / status / logs / restart / cnblock / fwd / uninstall）')" ;;
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
    make_workdir || return 1
    local wd="$WORKDIR"
    if ! curl -fsSL --max-time 60 "${TCPFIT_RAW}/tcpfit.sh" -o "$wd/tcpfit.sh"; then
        warn "$(L '下载 tcpfit 失败（')${TCPFIT_RAW}$(L '/tcpfit.sh），请检查到 GitHub 的网络')"
        return 1
    fi
    # 与 tcpfit 自己的安装脚本相同的三项自检：是脚本、有版本号、语法完整（防传输截断）
    if ! head -n 1 "$wd/tcpfit.sh" | grep -q '^#!' || ! grep -q '^VERSION=' "$wd/tcpfit.sh" || ! bash -n "$wd/tcpfit.sh" 2>/dev/null; then
        warn "$(L '下载到的 tcpfit 不完整或不是脚本（传输被截断或被网关拦截），已放弃')"
        return 1
    fi
    TCPFIT_REMOTE_VER="$(grep -m1 '^VERSION=' "$wd/tcpfit.sh" | cut -d'"' -f2 || true)"
    got="$(sha256sum "$wd/tcpfit.sh" | awk '{print $1}')"
    want="$(curl -fsSL --max-time 20 "${TCPFIT_RAW}/SHA256SUMS" 2>/dev/null | awk '$2 == "tcpfit.sh" {print $1}' | head -n 1 || true)"
    if [ -z "$want" ]; then
        warn "$(L '取不到仓库里的 SHA256SUMS，无法核对校验值（SHA256:') ${got}$(L '）')"
        confirm "$(L '仍要继续？')" n || return 1
    elif [ "$want" != "$got" ]; then
        warn "$(L 'SHA256 与仓库 SHA256SUMS 不一致（仓库') ${want}$(L '，实际') ${got}$(L '）')"
        warn "$(L '可能是作者刚更新、两个文件的缓存不同步，也可能是下载被篡改')"
        confirm "$(L '仍要继续？')" n || return 1
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
    local cur
    cur="$(tcpfit_installed_version)"
    info "$(L 'tcpfit 是第三方开源脚本（')${TCPFIT_RAW%/main}$(L '），将以 root 运行并修改 sysctl / qdisc 等网络参数')"
    info "$(L '它的改动只写在自己的文件里（/etc/sysctl.d/99-tcpfit.conf 等），可用 tcpfit rollback 整体回滚')"
    confirm "${cur:+当前已安装 ${cur}，}$(L '从官方仓库拉取最新版并安装到') ${TCPFIT_BIN}$(L '？')" y || return 1
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
    local arch virt id="" codename="" lvl pkg="" free_mb c keyring=/etc/apt/keyrings/xanmod-archive-keyring.gpg
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
    install -d -m 755 /etc/apt/keyrings
    make_workdir || return 1
    if ! curl -fsSL --max-time 30 https://dl.xanmod.org/archive.key -o "$WORKDIR/xanmod.key" \
        || ! gpg --dearmor --yes -o "$keyring" < "$WORKDIR/xanmod.key" 2>/dev/null; then
        warn "$(L 'XanMod 仓库密钥下载或导入失败')"
        return 1
    fi
    chmod 644 "$keyring"
    echo "deb [signed-by=${keyring}] http://deb.xanmod.org ${codename} main" > /etc/apt/sources.list.d/xanmod-release.list
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
    # 必须还有别的内核可以启动，否则卸完就起不来了
    others="$(dpkg-query -W -f='${Status} ${Package}\n' 'linux-image-*' 2>/dev/null | awk '$1 == "install" && $3 == "installed" && $4 !~ /xanmod/ {print $4}' | tr '\n' ' ' || true)"
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
    local ans choice servers="" dot="no" s v4 v6 iface
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
            read -rp "$(L '输入 DNS 服务器 IP（空格分隔，可混合 IPv4 / IPv6）:') " ans || { [ -n "$ans" ] || return 1; }
            v4=""; v6=""
            while IFS= read -r s; do
                [ -n "$s" ] || continue
                if ! is_ip "$s"; then warn "$(L '不是合法 IP:') ${s}"; return 1; fi
                if [[ "$s" == *:* ]]; then v6="${v6:+$v6 }$s"; else v4="${v4:+$v4 }$s"; fi
            done < <(printf '%s\n' "$ans" | tr ' ' '\n' | grep -v '^$')
            if [ -z "$v4$v6" ]; then warn "$(L '没有输入任何服务器')"; return 1; fi
            ;;
        *) return 0 ;;
    esac
    # 本机 IPv6 不可用时不写 IPv6 的 DNS，避免解析超时
    if snell_ipv6_ok && ip -6 route show default 2>/dev/null | grep -q .; then servers="${v4:+$v4 }${v6}"; else servers="${v4:-$v6}"; fi
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
        if [ ! -e "$DNS_RESOLV_BACKUP" ]; then
            install -d -m 755 "$MAINT_DIR"
            cp -P /etc/resolv.conf "$DNS_RESOLV_BACKUP" 2>/dev/null || true
        fi
        rm -f /etc/resolv.conf
        {
            echo "# $(L '由 Adam 管理脚本生成；原文件备份在') ${DNS_RESOLV_BACKUP}"
            while IFS= read -r s; do [ -n "$s" ] || continue; echo "nameserver $s"; done < <(printf '%s\n' "$servers" | tr ' ' '\n' | grep -v '^$')
            echo "options timeout:2 attempts:2"
        } > /etc/resolv.conf
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
    local ans
    echo "  1) $(L '查看当前 DNS    2')) $(L '设置 DNS    3')) $(L '恢复为修改前    0')) $(L '返回')"
    read -rp "$(L '请选择:') " ans
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
    if [[ "$p4" =~ ^[0-9]+$ ]] && [ "$p4" -ge 50 ]; then printf "$(L 'IPv4 优先')"; else printf "$(L 'IPv6 优先（系统默认）')"; fi
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
    #（旧版整文件重写会丢掉发行版或用户原有的条目；注释掉的默认行不影响追加）
    [ -f /etc/gai.conf ] || : > /etc/gai.conf
    if grep -q '^precedence ::ffff:0:0/96' /etc/gai.conf; then
        sed -i "s/^precedence ::ffff:0:0\/96.*/precedence ::ffff:0:0\/96  ${p4}/" /etc/gai.conf
    else
        echo "precedence ::ffff:0:0/96  ${p4}" >> /etc/gai.conf
    fi
    if grep -q '^precedence ::/0' /etc/gai.conf; then
        sed -i "s/^precedence ::\/0.*/precedence ::\/0           ${p6}/" /etc/gai.conf
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
    local ans
    echo "  $(L '当前:') $(ip_priority_current)"
    echo "  1) $(L 'IPv4 优先    2')) $(L 'IPv6 优先    3')) $(L '恢复为修改前    0')) $(L '返回')"
    read -rp "$(L '请选择:') " ans
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
            if snell_ipv6_ok; then
                if grep -q '"listen": "0.0.0.0"' "$f"; then
                    [ -n "$xbak" ] || { make_workdir || return 1; xbak="$WORKDIR"; }
                    cp -a "$f" "$xbak/" 2>/dev/null || true
                    sed -i 's/"listen": "0.0.0.0"/"listen": "::"/' "$f"; changed=1
                fi
            else
                if grep -q '"listen": "::"' "$f"; then
                    [ -n "$xbak" ] || { make_workdir || return 1; xbak="$WORKDIR"; }
                    cp -a "$f" "$xbak/" 2>/dev/null || true
                    sed -i 's/"listen": "::"/"listen": "0.0.0.0"/' "$f"; changed=1
                fi
            fi
        done
        if [ "$changed" = "1" ]; then
            # 改完先校验，不通过就恢复原文件、不重启（原先改完直接 try-restart 且总返回成功）
            if xray_test_conf >/dev/null 2>&1; then
                systemctl try-restart adam-xray >/dev/null 2>&1 || true
                info "$(L 'Xray 节点的监听地址已按当前 IPv6 状态调整')"
            else
                warn "$(L 'Xray 配置改动后校验失败，已恢复原文件')"
                [ -n "$xbak" ] && cp -a "$xbak"/*.json "$XRAY_CONF_D/" 2>/dev/null || true
            fi
        fi
    fi
    # 同步调整 Xray 转发规则的默认监听地址
    if [ -d "$XRAY_FWD_DIR" ]; then
        local _fchg=0 _ff
        while IFS= read -r _ff; do
            if snell_ipv6_ok; then
                if grep -q '^FWD_LIP="0.0.0.0"$' "$_ff"; then sed -i 's/^FWD_LIP="0.0.0.0"$/FWD_LIP="::"/' "$_ff"; _fchg=1; fi
            else
                if grep -q '^FWD_LIP="::"$' "$_ff"; then sed -i 's/^FWD_LIP="::"$/FWD_LIP="0.0.0.0"/' "$_ff"; _fchg=1; fi
            fi
        done < <(xray_fwd_rule_files)
        [ "$_fchg" = "1" ] && xray_fwd_rebuild >/dev/null 2>&1 || true
    fi
    # 同步调整 Realm 规则的默认监听地址
    if [ -d "$REALM_RULE_DIR" ]; then
        local _rchg=0 _rf
        while IFS= read -r _rf; do
            if snell_ipv6_ok; then
                if grep -q '^RULE_LIP="0.0.0.0"$' "$_rf"; then sed -i 's/^RULE_LIP="0.0.0.0"$/RULE_LIP="[::]"/' "$_rf"; _rchg=1; fi
            else
                if grep -q '^RULE_LIP="\[::\]"$' "$_rf"; then sed -i 's/^RULE_LIP="\[::\]"$/RULE_LIP="0.0.0.0"/' "$_rf"; _rchg=1; fi
            fi
        done < <(realm_rule_files)
        [ "$_rchg" = "1" ] && realm_reload_service >/dev/null 2>&1 || true
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
    local ans
    echo "  $(L '当前: IPv6') $(ipv6_state_text)"
    echo "  1) $(L '临时禁用（重启恢复）    2')) $(L '永久禁用    3')) $(L '恢复启用    0')) $(L '返回')"
    read -rp "$(L '请选择:') " ans
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
    echo "  tcpfit     : $([ -x "$TCPFIT_BIN" ] && echo "已安装 $(tcpfit_installed_version)" || echo "$(L '未安装')")"
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
        read -rp "$(L '请选择') [0-8]: " choice
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
    local ans
    echo "  1) $(L '查看 tcpfit 状态    2')) $(L '回滚 tcpfit 的全部改动    3')) $(L '检查并更新 tcpfit    0')) $(L '返回')"
    read -rp "$(L '请选择:') " ans
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

# ══════════════════════════════════════════════════════════════
#   Realm 端口转发（参考 zywe03/realm-xwPF · 适配 adam 脚本架构）
#   目录模式：realm -c /etc/adam-realm/conf.d（00-base.toml + rule-<id>.toml）
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

realm_default_listen_ip() {
    if [ "$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo 0)" = "1" ]; then
        printf '0.0.0.0'
    else
        printf '[::]'
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
    local tag=""
    tag="$(curl -fsS --max-time 20 "https://api.github.com/repos/${REALM_REPO}/releases/latest" 2>/dev/null \
        | grep -m1 '"tag_name"' | cut -d'"' -f4 || true)"
    if [ -z "$tag" ]; then
        tag="$(curl -fsSI --max-time 20 "https://github.com/${REALM_REPO}/releases/latest" 2>/dev/null \
            | tr -d '\r' | awk 'tolower($1)=="location:" {print $2}' | sed -n 's#.*/tag/##p' | tail -1 || true)"
    fi
    printf '%s' "$tag"
}

realm_fetch_binary() {
    local tag="$1" arch libc asset url api_json digest actual bin
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
        if ! curl -fL --retry 3 --connect-timeout 10 --max-time 300 -o "${subdir}/realm.tar.gz" "$url" 2>/dev/null; then
            asset=""; continue
        fi

        # SHA256 校验（复用 GitHub Release API digest）；取不到摘要时明示跳过，不静默放行
        actual="$(sha256sum "${subdir}/realm.tar.gz" | awk '{print $1}')"
        api_json="$(curl -fsS --max-time 20 "https://api.github.com/repos/${REALM_REPO}/releases/tags/${tag}" 2>/dev/null || true)"
        digest=""
        if [ -n "$api_json" ] && command -v python3 >/dev/null 2>&1; then
            digest="$(printf '%s' "$api_json" | ASSET="$asset" python3 -c 'import json,os,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit(0)
for a in d.get("assets",[]):
    if a.get("name")==os.environ["ASSET"]:
        print((a.get("digest") or "").replace("sha256:",""))
        break' 2>/dev/null || true)"
        fi
        if [ -n "$digest" ]; then
            if [ "$digest" != "$actual" ]; then
                warn "$(L 'SHA256 校验失败（')${asset}$(L '），尝试另一构建')"
                asset=""; continue
            fi
            success "$(L 'SHA256 校验通过（')${asset}$(L '）')"
        else
            warn "$(L '未取到官方 SHA256 摘要，跳过校验（')${asset}$(L '）')"
        fi

        tar -xzf "${subdir}/realm.tar.gz" -C "$subdir" || { asset=""; continue; }
        bin="$(find "$subdir" -maxdepth 2 -type f -name realm | head -1)"
        [ -n "$bin" ] || { asset=""; continue; }
        chmod 755 "$bin" || { asset=""; continue; }
        if ! "$bin" --version >/dev/null 2>&1; then
            warn "$(L '下载的 realm 无法在本机运行，尝试另一构建')"
            asset=""; continue
        fi
        REALM_DL_BIN="$bin"
        return 0
    done
    warn "$(L '下载 Realm ')${tag}$(L ' 失败')"
    return 1
}

realm_write_base_config() {
    install -d -m 755 "$REALM_DIR" "$REALM_CONF_D" "$REALM_RULE_DIR"
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
        chmod 644 "${REALM_CONF_D}/00-base.toml"
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

# 校验 .env 文件内容是否可安全 source：只允许 KEY="值" 行，值内不含未转义的 $ ` "
# （本脚本写出的文件经 dq_escape 转义，$ 一律写成 \$、反引号写成 \`，故残留的 $ ` " 即为注入）
realm_env_file_safe() {
    local f="$1" line key val rest n=0
    [ -f "$f" ] || return 1
    while IFS= read -r line || [ -n "$line" ]; do
        n=$((n + 1))
        case "$line" in
            *=*) key="${line%%=*}"; rest="${line#*=}" ;;
            *) return 1 ;;
        esac
        case "$key" in
            RULE_*|FWD_*) : ;;
            *) return 1 ;;
        esac
        case "$rest" in
            \"*\") val="${rest:1:${#rest}-2}" ;;
            *) return 1 ;;
        esac
        val="${val//\\\\/}"
        val="${val//\\\$/}"
        val="${val//\\\`/}"
        val="${val//\\\"/}"
        case "$val" in *'$'*|*'`'*|*'"'*) return 1 ;; esac
    done < "$f"
    [ "$n" -gt 0 ] || return 1
    return 0
}

# 将单条 rules/<id>.env 渲染为 conf.d/rule-<id>.toml（停用时删除对应 .toml）
realm_render_rule() {
    local id="$1"
    local env_file="${REALM_RULE_DIR}/${id}.env"
    local toml_file="${REALM_CONF_D}/rule-${id}.toml"
    [ -f "$env_file" ] || { rm -f "$toml_file"; return 0; }
    (
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
        _lip="${_lip#[}"; _lip="${_lip%]}"
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
        local laddr raddr
        laddr="$(format_host_for_url "$RULE_LIP"):${RULE_LPORT}"
        raddr="$(format_host_for_url "$RULE_RHOST"):${RULE_RPORT}"

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
                    ehost="${item%:*}"; eport="${item##*:}"
                    [ "$ehost" = "$item" ] && continue
                    is_safe_host "$ehost" || continue
                    validate_port "$eport" || continue
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
        chmod 644 "$tmpf"
        mv -f "$tmpf" "$toml_file"
    )
}

realm_rebuild_all() {
    realm_write_base_config
    local f id
    while IFS= read -r f; do
        id="$(basename "$f" .env)"
        realm_env_file_safe "$f" || { warn "$(L '规则文件内容非法，已跳过：')${id}"; rm -f "${REALM_CONF_D}/rule-${id}.toml"; continue; }
        realm_render_rule "$id" || warn "$(L '规则渲染失败，已跳过：')${id}"
    done < <(realm_rule_files)
    # 删除无对应 .env 的残留 rule-*.toml（逐个渲染后再清理，不断档）
    local t
    for t in "${REALM_CONF_D}"/rule-*.toml; do
        [ -f "$t" ] || continue
        id="$(basename "$t" .toml)"
        id="${id#rule-}"
        [ -f "${REALM_RULE_DIR}/${id}.env" ] || rm -f "$t"
    done
    # 合并为单个 /etc/adam-realm/config.toml：zhboner/realm 目录模式要求每个 .toml 都含 endpoints 字段，
    # 单独的 00-base.toml 会触发 missing field `endpoints` 崩溃；合并单文件同时避免目录读取顺序不确定。
    local tmpcfg ep_cnt=0
    tmpcfg="$(mktemp "${REALM_DIR}/.config.toml.XXXXXX")" || return 1
    {
        if [ -f "${REALM_CONF_D}/00-base.toml" ]; then
            # 剔除可能残留的空 endpoints = []，避免与后续 [[endpoints]] 产生 TOML 重复键冲突
            grep -vE '^[[:space:]]*endpoints[[:space:]]*=[[:space:]]*\[\][[:space:]]*$' "${REALM_CONF_D}/00-base.toml" || true
        fi
        for t in "${REALM_CONF_D}"/rule-*.toml; do
            [ -f "$t" ] || continue
            printf '
'
            cat "$t"
            ep_cnt=$((ep_cnt + 1))
        done
        if [ "$ep_cnt" -eq 0 ]; then
            printf '
endpoints = []
'
        fi
    } > "$tmpcfg" || { rm -f "$tmpcfg"; return 1; }
    chmod 644 "$tmpcfg"
    mv -f "$tmpcfg" "$REALM_CONFIG_FILE"
}

# 有启用规则时 enable+启动；无规则时 disable+停止；是否 enable 由此处决定
realm_reload_service() {
    if ! realm_installed && [ ! -d "$REALM_DIR" ]; then
        info "$(L 'Realm 未安装，规则配置已保存，安装后生效')"
        return 0
    fi
    realm_rebuild_all
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
    systemctl enable adam-realm >/dev/null 2>&1 || true
    if svc_restart_wait adam-realm 2 20; then
        return 0
    fi
    # 专用用户启动失败时改以 root 重试一次（参照 Nowhere 的回退模式）
    if grep -q '^User=' "$REALM_SERVICE" 2>/dev/null; then
        warn "$(L 'adam-realm 以专用用户启动失败，改以 root 重试')"
        sed -i '/^User=/d; /^Group=/d' "$REALM_SERVICE" || { warn "$(L '改写服务文件失败')"; return 1; }
        systemctl daemon-reload || true
        if svc_restart_wait adam-realm 2 20; then
            touch "${REALM_DIR}/run-as-root" 2>/dev/null || true
            info "$(L '已记录 root 运行标记，下次安装不再写入专用用户：')${REALM_DIR}/run-as-root"
            return 0
        fi
    fi
    warn "$(L 'adam-realm 启动失败，请查看日志：journalctl -u adam-realm -n 20 --no-pager')"
    return 1
}

realm_install() {
    step "$(L '安装 / 更新 Realm')"
    divider
    apt_install curl tar ca-certificates python3 iproute2 || true
    local _t
    for _t in curl tar sha256sum python3 ss; do
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

    realm_fetch_binary "$tag" || error "$(L 'Realm 下载或校验失败')"
    install -d -m 755 "$REALM_DIR" "$REALM_CONF_D" "$REALM_RULE_DIR" || error "$(L '创建 Realm 配置目录失败')"
    if [ -f "$REALM_BIN" ]; then cp "$REALM_BIN" "$REALM_BIN_BACKUP" 2>/dev/null || warn "$(L '备份旧二进制失败')"; fi
    install -m 755 "$REALM_DL_BIN" "$REALM_BIN" || error "$(L '安装 Realm 二进制失败')"
    realm_write_base_config
    realm_write_service

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
    success "$(L 'Realm ')${tag}$(L ' 安装完成（')$(${REALM_BIN} --version 2>&1 | head -1)$(L '）')"
}

realm_next_id() {
    local i=1 id
    while true; do
        id="$(printf 'r%02d' "$i")"
        [ ! -f "${REALM_RULE_DIR}/${id}.env" ] && { printf '%s' "$id"; return 0; }
        i=$((i + 1))
    done
}

# 构建 ws/tls/wss 隧道字符串（参考 xwPF 中转端/落地端配对）
realm_prompt_transport() {
    local role_label="$1" is_server="$2" choice host path sni crt key
    REALM_TRANS_RESULT=""
    echo "  ${role_label}$(L '传输隧道：')"
    echo "    1) $(L '标准透传（推荐，性能最高，适用于已加密协议）')"
    echo "    2) WS（WebSocket）"
    echo "    3) TLS"
    echo "    4) WSS（WebSocket + TLS）"
    read -rp "  $(L '选择 [1-4，默认 1]: ')" choice || { [ -n "$choice" ] || return 0; }
    case "${choice:-1}" in
        1) return 0 ;;
        2)
            read -rp "    $(L '伪装 Host（如 cdn.example.com）: ')" host || { [ -n "$host" ] || return 0; }
            read -rp "    $(L 'WS Path（回车默认 /ws）: ')" path || { [ -n "$path" ] || return 0; }
            path="${path:-/ws}"; [[ "$path" == /* ]] || path="/${path}"
            is_safe_host "$host" || { warn "$(L 'Host 不合法，回退标准透传')"; return 0; }
            realm_has_toml_special "$path" && { warn "$(L '路径含非法字符（\" 或 \），回退标准透传')"; return 0; }
            case "$path" in *';'*|*'='*) warn "$(L '路径含 ; 或 =，回退标准透传')"; return 0 ;; esac
            REALM_TRANS_RESULT="ws;host=${host};path=${path}"
            ;;
        3)
            read -rp "    $(L 'TLS SNI / 域名（如 example.com）: ')" sni || { [ -n "$sni" ] || return 0; }
            is_safe_host "$sni" || { warn "$(L '域名不合法，回退标准透传')"; return 0; }
            if [ "$is_server" = "1" ]; then
                read -rp "    $(L '证书文件路径（回车使用 Realm 内置自签）: ')" crt || { [ -n "$crt" ] || return 0; }
                if [ -n "$crt" ]; then
                    if realm_has_toml_special "$crt"; then warn "$(L '路径含非法字符（\" 或 \），回退内置自签')"; REALM_TRANS_RESULT="tls;servername=${sni}"; return 0; fi
                    case "$crt" in *';'*|*'='*) warn "$(L '路径含 ; 或 =，回退内置自签')"; REALM_TRANS_RESULT="tls;servername=${sni}"; return 0 ;; esac
                    read -rp "    $(L '私钥文件路径: ')" key || { [ -n "$key" ] || return 0; }
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
            read -rp "    $(L '伪装域名 Host/SNI（如 cdn.example.com）: ')" host || { [ -n "$host" ] || return 0; }
            read -rp "    $(L 'WS Path（回车默认 /ws）: ')" path || { [ -n "$path" ] || return 0; }
            path="${path:-/ws}"; [[ "$path" == /* ]] || path="/${path}"
            is_safe_host "$host" || { warn "$(L '域名不合法，回退标准透传')"; return 0; }
            realm_has_toml_special "$path" && { warn "$(L '路径含非法字符（\" 或 \），回退标准透传')"; return 0; }
            case "$path" in *';'*|*'='*) warn "$(L '路径含 ; 或 =，回退标准透传')"; return 0 ;; esac
            if [ "$is_server" = "1" ]; then
                read -rp "    $(L '证书文件路径（回车使用 Realm 内置自签）: ')" crt || { [ -n "$crt" ] || return 0; }
                if [ -n "$crt" ]; then
                    if realm_has_toml_special "$crt"; then warn "$(L '路径含非法字符（\" 或 \），回退内置自签')"; REALM_TRANS_RESULT="ws;host=${host};path=${path};tls;servername=${host}"; return 0; fi
                    case "$crt" in *';'*|*'='*) warn "$(L '路径含 ; 或 =，回退内置自签')"; REALM_TRANS_RESULT="ws;host=${host};path=${path};tls;servername=${host}"; return 0 ;; esac
                    read -rp "    $(L '私钥文件路径: ')" key || { [ -n "$key" ] || return 0; }
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
            ;;
    esac
}

realm_add_rule() {
    realm_installed || { warn "$(L '尚未安装 Realm，请先安装')"; return 1; }
    step "$(L '添加 Realm 转发规则')"
    divider

    local id remark proto lip lport rhost rport proto_c def_lip occ
    local extra_remotes="" balance="" through="" out_if="" in_if=""
    local ltrans="" rtrans="" send_proxy=0 accept_proxy=0 send_mptcp=0 accept_mptcp=0

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
    local _lip_check="${lip#[}"; _lip_check="${_lip_check%]}"
    is_ip "$_lip_check" 0 || { warn "$(L '监听 IP 格式不合法')"; return 1; }

    while true; do
        read -rp "$(L '本机监听端口 (1-65535): ')" lport || { [ -n "$lport" ] || return 1; }
        validate_port "$lport" && break
        warn "$(L '端口不合法')"
    done
    lport=$((10#$lport))

    # 冲突检测：先查本 Realm 模块是否已有同端口规则，再查其他进程（排除 realm）
    if realm_port_used "$lport" "$proto"; then
        warn "$(L '该端口已被本模块其他规则占用，请换一个') (${lport})"
        return 1
    fi
    if command -v ss >/dev/null 2>&1; then
        occ=""
        [ "$proto" != "udp" ] && occ="$(check_port_occupied_by_other tcp "$lport" realm || true)"
        [ -z "$occ" ] && [ "$proto" != "tcp" ] && occ="$(check_port_occupied_by_other udp "$lport" realm || true)"
        if [ -n "$occ" ]; then
            warn "$(L '端口 ')${lport}$(L ' 已被其他进程占用：')"
            echo "$occ"
            confirm "$(L '仍要继续添加？')" n || return 0
        fi
    fi

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
                _ih="${_item%:*}"; _ip="${_item##*:}"
                if [ "$_ih" = "$_item" ] || ! is_safe_host "$_ih" || ! validate_port "$_ip"; then
                    warn "$(L '已剔除无效目标：')${_item}"
                    continue
                fi
                _clean="${_clean:+${_clean},}${_item}"
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
                    # 权重数量须等于目标总数（主目标 + 额外目标）且全为数字
                    local _wc=0 _wok=1 _wi
                    local -a _warr=()
                    IFS=',' read -r -a _warr <<< "$lb_w"
                    for _wi in "${_warr[@]}"; do
                        _wi="${_wi//[[:space:]]/}"
                        [ -n "$_wi" ] || continue
                        _wc=$((_wc + 1))
                        [[ "$_wi" =~ ^[0-9]+$ ]] || _wok=0
                    done
                    if [ "$_wok" != "1" ] || [ "$_wc" -ne "$_cnt" ]; then
                        warn "$(L '权重数量与目标数不符或含非数字，已按等权生成')"
                        lb_w=""
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
            realm_prompt_transport "$(L '入站解密')" 1
            ltrans="$REALM_TRANS_RESULT"
        else
            realm_prompt_transport "$(L '出站加密')" 0
            rtrans="$REALM_TRANS_RESULT"
        fi
    fi

    # 可选：多 IP / 多网卡 / Proxy Protocol / MPTCP
    if confirm "$(L '配置高级选项（指定出口 IP/网卡、Proxy Protocol、MPTCP）？')" n; then
        read -rp "$(L '  出站源 IP through（回车默认自动）: ')" through || { [ -n "$through" ] || return 1; }
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

    id="$(realm_next_id)"
    local env_file="${REALM_RULE_DIR}/${id}.env"
    cat > "$env_file" << RULEEOF
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

    if ! realm_reload_service; then
        rm -f "$env_file"
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
            # shellcheck disable=SC1090
            source "$f" 2>/dev/null || exit 0
            tags=""
            [ "${RULE_PROTO:-both}" = "tcp" ] && tags="${tags}[$(L '纯TCP')]"
            [ "${RULE_PROTO:-both}" = "udp" ] && tags="${tags}[$(L '纯UDP')]"
            [ -n "${RULE_LTRANS:-}" ] && tags="${tags}[$(L '入站隧道')]"
            [ -n "${RULE_RTRANS:-}" ] && tags="${tags}[$(L '出站隧道')]"
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
    local f="$PICKED_RULE_FILE" cur next
    cur="$(grep -m1 '^RULE_ENABLED=' "$f" | cut -d'"' -f2 || echo 0)"
    if [ "$cur" = "1" ]; then next="0"; else next="1"; fi
    if grep -q '^RULE_ENABLED=' "$f"; then
        sed -i "s|^RULE_ENABLED=.*|RULE_ENABLED=\"${next}\"|" "$f" || { warn "$(L '规则状态切换失败')"; return 1; }
    else
        printf '%s\n' "RULE_ENABLED=\"${next}\"" >> "$f"
    fi
    realm_reload_service && success "$(L '规则状态已切换为：')$([ "$next" = "1" ] && echo "$(L '启用')" || echo "$(L '停用')")"
}

realm_delete_rule() {
    realm_pick_rule_file || return 0
    local f="$PICKED_RULE_FILE" old_port old_proto rid rlip rrhost rrport
    rid="$(grep -m1 '^RULE_ID=' "$f" | cut -d'"' -f2 || true)"
    rlip="$(grep -m1 '^RULE_LIP=' "$f" | cut -d'"' -f2 || true)"
    old_port="$(grep -m1 '^RULE_LPORT=' "$f" | cut -d'"' -f2 || true)"
    old_proto="$(grep -m1 '^RULE_PROTO=' "$f" | cut -d'"' -f2 || true)"
    rrhost="$(grep -m1 '^RULE_RHOST=' "$f" | cut -d'"' -f2 || true)"
    rrport="$(grep -m1 '^RULE_RPORT=' "$f" | cut -d'"' -f2 || true)"
    confirm "$(L '确认删除规则 [')${rid}] ${rlip}:${old_port} -> ${rrhost}:${rrport}$(L ']？')" n || return 0
    rm -f "$f"
    if ! realm_reload_service; then
        warn "$(L '服务重载失败，删除未生效，请检查日志')"
        return 1
    fi
    if ufw_installed && validate_port "$old_port"; then
        local old_specs=""
        [ "$old_proto" != "udp" ] && old_specs="${old_specs} ${old_port}/tcp"
        [ "$old_proto" != "tcp" ] && old_specs="${old_specs} ${old_port}/udp"
        fw_prune_old_specs "$old_specs"
    fi
    success "$(L '已删除规则 ')${rid}"
}

# TCP 目标连通性与延迟检测（类似 xwPF 链路检测，支持 IPv4/IPv6）
realm_test_rules() {
    step "$(L '转发目标连通性测试（TCP 握手延迟）')"
    divider
    local f any=0
    while IFS= read -r f; do
        any=1
        (
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
                    _eh="${_ex%:*}"; _ep="${_ex##*:}"
                    [ "$_eh" = "$_ex" ] && continue
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
    [ "$any" -eq 0 ] && info "$(L '暂无可测试的规则')"
}

realm_export_rules() {
    [ -d "$REALM_DIR" ] || { warn "$(L '未找到 Realm 配置目录')"; return 1; }
    local out="/root/adam-realm-$(date +%Y%m%d-%H%M%S).tgz"
    tar -czf "$out" -C / etc/adam-realm 2>/dev/null || error "$(L '导出失败')"
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
    if ! tar -xzf "$fpath" -C /; then
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
    rm -rf "$bakdir"
    if realm_reload_service; then
        fw_sync_managed
        [ -n "${old_ports// /}" ] && fw_prune_old_specs "$old_ports"
        success "$(L '规则导入完成')"
    else
        warn "$(L '规则已导入，但服务重载失败，请检查日志')"
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
    else
        warn "$(L '已保留规则目录') ${REALM_DIR}"
    fi
    if [ -n "${old_specs// /}" ] && ufw_installed && confirm "$(L '同时删除防火墙中 Realm 端口的放行规则（')${old_specs}$(L '）？')" y; then
        local _rs
        while IFS= read -r _rs; do
            [ -n "$_rs" ] || continue
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
            return 1
        fi
    fi
    echo "$latest" > "$REALM_VERSION_FILE"
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
    local _lip_check="${lip#[}"; _lip_check="${_lip_check%]}"
    is_ip "$_lip_check" 0 || { warn "$(L '监听 IP 格式不合法')"; return 1; }

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

    local rp
    for p in "${ports[@]}"; do
        if realm_port_used "$p" "$proto"; then
            warn "$(L '端口 ')${p} $(L '已被占用，请换一个')"
            skip_cnt=$((skip_cnt + 1))
            continue
        fi
        rp="${rport_fixed:-$p}"
        id="$(realm_next_id)"
        env_file="${REALM_RULE_DIR}/${id}.env"
        cat > "$env_file" << RULEEOF
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
    source "$f"
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
        local _lc="${ans#[}"; _lc="${_lc%]}"
        is_ip "$_lc" 0 || { warn "$(L '监听 IP 格式不合法')"; return 1; }
        lip="$ans"
    fi

    read -rp "$(L '本机监听端口 (1-65535): ') [${lport}] ($(L '回车保持')): " ans || { [ -n "$ans" ] || return 1; }
    if [ -n "$ans" ]; then
        validate_port "$ans" || { warn "$(L '端口不合法')"; return 1; }
        lport=$((10#$ans))
        if realm_port_used "$lport" "$proto" "$RULE_ID"; then
            warn "$(L '该端口已被本模块其他规则占用，请换一个') (${lport})"
            return 1
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
                _ih="${_item%:*}"; _ip="${_item##*:}"
                if [ "$_ih" = "$_item" ] || ! is_safe_host "$_ih" || ! validate_port "$_ip"; then
                    warn "$(L '已剔除无效目标：')${_item}"; continue
                fi
                _clean="${_clean:+${_clean},}${_item}"; _cnt=$((_cnt + 1))
            done
            extra_remotes="$_clean"
            if [ -n "$extra_remotes" ]; then
                balance="roundrobin: $(printf '1, %.0s' $(seq 1 "$_cnt") | sed 's/, $//')"
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
            realm_prompt_transport "$(L '入站解密')" 1
            ltrans="$REALM_TRANS_RESULT"; rtrans=""
        else
            realm_prompt_transport "$(L '出站加密')" 0
            rtrans="$REALM_TRANS_RESULT"; ltrans=""
        fi
    elif [ "$proto" = "udp" ]; then
        ltrans=""; rtrans=""
    fi

    bak="${f}.bak"
    cp -f "$f" "$bak" || return 1
    cat > "$f" << RULEEOF
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

    local -a fw_specs=()
    [ "$proto" != "udp" ] && fw_specs+=("${lport}/tcp")
    [ "$proto" != "tcp" ] && fw_specs+=("${lport}/udp")
    fw_allow_for_service "${fw_specs[@]}"
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
    echo "  DNS mode: 1) ipv4_and_ipv6  2) ipv4_only  3) ipv6_only  4) ipv4_then_ipv6  5) ipv6_then_ipv4"
    local ans dns_mode="ipv4_and_ipv6" tcp_to="5" udp_to="30" ka="15"
    read -rp "  DNS mode [1-5, default 1]: " ans || { [ -n "$ans" ] || return 1; }
    case "${ans:-1}" in
        2) dns_mode="ipv4_only" ;;
        3) dns_mode="ipv6_only" ;;
        4) dns_mode="ipv4_then_ipv6" ;;
        5) dns_mode="ipv6_then_ipv4" ;;
        *) dns_mode="ipv4_and_ipv6" ;;
    esac
    read -rp "  tcp_timeout (s, default 5): " ans || { [ -n "$ans" ] || return 1; }
    [[ "${ans:-5}" =~ ^[1-9][0-9]*$ ]] && tcp_to="${ans:-5}"
    read -rp "  udp_timeout (s, default 30): " ans || { [ -n "$ans" ] || return 1; }
    [[ "${ans:-30}" =~ ^[1-9][0-9]*$ ]] && udp_to="${ans:-30}"
    read -rp "  tcp_keepalive (s, default 15): " ans || { [ -n "$ans" ] || return 1; }
    [[ "${ans:-15}" =~ ^[1-9][0-9]*$ ]] && ka="${ans:-15}"

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
    chmod 644 "${REALM_CONF_D}/00-base.toml"
    realm_reload_service && success "$(L '配置已更新并重启')"
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
        echo -e "  ${GREEN}15)${NC} ${RED}$(L '卸载')${NC} Realm"
        echo -e "  ${GREEN}0)${NC}  $(L '返回主菜单')"
        divider
        read -rp "$(L '请选择') [0-15]: " choice
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
            15) run_action realm_uninstall ;;
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
        restart)   realm_reload_service && success "$(L 'Realm 已重启')" ;;
        status)    systemctl status adam-realm --no-pager || true ;;
        logs)      journalctl -u adam-realm -f || true ;;
        export)    realm_export_rules ;;
        import)    realm_import_rules ;;
        uninstall) realm_uninstall ;;
        *) error "$(L '未知的 realm 子命令:') ${sub}$(L '（可用: install / add / batch / edit / list / toggle / delete / test / config / tune / auto / restart / status / logs / export / import / uninstall）')" ;;
    esac
}

# ══════════════════════════════════════════════════════════════
#   Xray 端口转发（dokodemo-door，3x-ui 面板 tunnel 同款）
#   存储：${XRAY_CONF_DIR}/forward/fXX.env（600 权限）
#   渲染：${XRAY_CONF_D}/20-forward.json（单个文件含全部已启用规则的 inbounds）
#   无启用规则时删除 20-forward.json；重载失败时用 .bak 恢复并再次重载
# ══════════════════════════════════════════════════════════════

xray_fwd_rule_files() {
    local f
    [ -d "$XRAY_FWD_DIR" ] || return 0
    for f in "${XRAY_FWD_DIR}"/*.env; do
        [ -f "$f" ] && printf '%s\n' "$f"
    done
}

xray_fwd_tags() {
    local f
    [ -d "$XRAY_FWD_DIR" ] || return 0
    for f in "$XRAY_FWD_DIR"/*.env; do
        [ -f "$f" ] || continue
        basename "$f" .env
    done
    return 0
}

xray_fwd_rule_count() {
    local n=0 f
    while IFS= read -r f; do n=$((n + 1)); done < <(xray_fwd_rule_files)
    printf '%s' "$n"
}

xray_fwd_enabled_count() {
    local f n=0
    while IFS= read -r f; do
        grep -q '^FWD_ENABLED="1"$' "$f" 2>/dev/null && n=$((n + 1))
    done < <(xray_fwd_rule_files)
    printf '%s' "$n"
}

# 读取转发规则元数据到 FWD_* 变量（调用方应在子 shell 或 local 环境里用）
xray_fwd_load() {
    FWD_ID=""; FWD_ENABLED=""; FWD_REMARK=""; FWD_PROTO=""; FWD_LIP=""; FWD_LPORT=""; FWD_RHOST=""; FWD_RPORT=""; FWD_FOLLOW="0"
    [ -f "${XRAY_FWD_DIR}/$1.env" ] || return 1
    # shellcheck disable=SC1090
    source "${XRAY_FWD_DIR}/$1.env" 2>/dev/null || return 1
    return 0
}

# 单个 env 文件的某字段值（仅数字/枚举类字段用，不含 remark 等转义值）
xray_fwd_env_get() {
    grep -m1 "^$2=" "$1" 2>/dev/null | cut -d'"' -f2 || true
}

xray_fwd_state_text() {
    local total enabled
    total="$(xray_fwd_rule_count)"
    enabled="$(xray_fwd_enabled_count)"
    if [ ! -x "$XRAY_BIN" ]; then
        printf '%s' "${YELLOW}$(L '未安装')${NC}"
        return 0
    fi
    printf '%s' "${enabled}/${total} $(L '条规则') · $(svc_state adam-xray)"
}

# 全部已启用转发规则的 ufw 端口规格（供 xray_ports / managed_ports 调用）
xray_fwd_ports() {
    local f
    while IFS= read -r f; do
        (
            # shellcheck disable=SC1090
            source "$f" 2>/dev/null || exit 0
            [ "${FWD_ENABLED:-0}" = "1" ] || exit 0
            validate_port "${FWD_LPORT:-}" || exit 0
            case "${FWD_PROTO:-both}" in
                tcp)  echo "${FWD_LPORT}/tcp" ;;
                udp)  echo "${FWD_LPORT}/udp" ;;
                both) echo "${FWD_LPORT}/tcp"; echo "${FWD_LPORT}/udp" ;;
            esac
        )
    done < <(xray_fwd_rule_files) | sort -u
}

xray_fwd_default_listen_ip() {
    if [ "$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo 0)" = "1" ]; then
        printf '0.0.0.0'
    else
        printf '::'
    fi
}

xray_fwd_next_id() {
    local i=1 id
    while true; do
        id="$(printf 'f%02d' "$i")"
        [ ! -f "${XRAY_FWD_DIR}/${id}.env" ] && { printf '%s' "$id"; return 0; }
        i=$((i + 1))
    done
}

# 单条已启用规则的 inbound JSON（未启用/非法时不输出）
xray_fwd_rule_json() {
    local f="$1" id enabled lip lport proto rhost rport follow network fr
    id="$(xray_fwd_env_get "$f" FWD_ID)"
    enabled="$(xray_fwd_env_get "$f" FWD_ENABLED)"
    [ "$enabled" = "1" ] || return 0
    lip="$(xray_fwd_env_get "$f" FWD_LIP)"
    lport="$(xray_fwd_env_get "$f" FWD_LPORT)"
    proto="$(xray_fwd_env_get "$f" FWD_PROTO)"
    rhost="$(xray_fwd_env_get "$f" FWD_RHOST)"
    rport="$(xray_fwd_env_get "$f" FWD_RPORT)"
    follow="$(xray_fwd_env_get "$f" FWD_FOLLOW)"
    validate_port "$lport" || return 0
    validate_port "$rport" || return 0
    is_ip "$lip" 0 || return 0
    is_safe_host "$rhost" || return 0
    lport=$((10#$lport))
    rport=$((10#$rport))
    case "$proto" in
        tcp) network="tcp" ;;
        udp) network="udp" ;;
        *)   network="tcp,udp" ;;
    esac
    rhost="${rhost#[}"; rhost="${rhost%]}"
    fr="false"; [ "$follow" = "1" ] && fr="true"
    printf '%s' "{\"tag\":\"fwd-${id}\",\"listen\":\"${lip}\",\"port\":${lport},\"protocol\":\"dokodemo-door\",\"settings\":{\"address\":\"${rhost}\",\"port\":${rport},\"network\":\"${network}\",\"followRedirect\":${fr}}}"
}

# 重建 20-forward.json 并重载；失败时用 .bak 恢复并再次重载
xray_fwd_rebuild() {
    local tmpf first=1 count=0 f frag
    install -d -m 750 "$XRAY_FWD_DIR" 2>/dev/null || true
    tmpf="$(mktemp "${XRAY_CONF_D}/.20-forward.XXXXXX")" || { warn "$(L '创建临时文件失败')"; return 1; }
    {
        printf '%s\n' '{' '  "inbounds": ['
        while IFS= read -r f; do
            frag="$(xray_fwd_rule_json "$f")"
            [ -n "$frag" ] || continue
            if [ "$first" = "1" ]; then first=0; else printf '%s\n' ','; fi
            printf '%s' "    ${frag}"
            count=$((count + 1))
        done < <(xray_fwd_rule_files)
        printf '\n%s\n' '  ]' '}'
    } > "$tmpf" || { rm -f "$tmpf"; return 1; }
    if [ "$count" -eq 0 ]; then
        rm -f "$tmpf" "$XRAY_FWD_JSON" "${XRAY_FWD_JSON}.bak"
    else
        [ -f "$XRAY_FWD_JSON" ] && cp -f "$XRAY_FWD_JSON" "${XRAY_FWD_JSON}.bak" || true
        mv -f "$tmpf" "$XRAY_FWD_JSON" || { rm -f "$tmpf"; warn "$(L '转发配置文件写入失败')"; return 1; }
        chmod 644 "$XRAY_FWD_JSON" || true
    fi
    # 同步刷新 00-base.json 中的 fwd-* 直连路由规则，确保内网/国内目标不被阻断
    xray_load_state
    xray_write_base
    if [ ! -x "$XRAY_BIN" ]; then
        info "$(L 'Xray 未安装，转发配置已保存，重装 Xray 后生效')"
        return 0
    fi
    if xray_reload; then
        return 0
    fi
    if [ "$count" -eq 0 ]; then
        warn "$(L '转发配置已移除，但 Xray 重载失败，请检查日志')"
        return 1
    fi
    warn "$(L '转发配置重载失败，恢复上一版本')"
    if [ -f "${XRAY_FWD_JSON}.bak" ]; then mv -f "${XRAY_FWD_JSON}.bak" "$XRAY_FWD_JSON"; else rm -f "$XRAY_FWD_JSON"; fi
    xray_reload >/dev/null 2>&1 || warn "$(L '恢复后重载仍失败，请检查 Xray 配置与日志')"
    return 1
}

xray_fwd_add() {
    xray_require || return 1
    step "$(L '添加 Xray 端口转发')"
    divider

    local id remark proto lip lport rhost rport follow=0 proto_c def_lip occ
    read -rp "$(L '规则备注（可选）: ')" remark || { [ -n "$remark" ] || return 1; }

    echo "$(L '转发协议：')"
    echo "  1) $(L 'TCP + UDP 双栈（默认）')"
    echo "  2) $(L '纯 TCP')"
    echo "  3) $(L '纯 UDP')"
    read -rp "$(L '选择 [1-3，默认 1]: ')" proto_c || { [ -n "$proto_c" ] || return 1; }
    case "${proto_c:-1}" in 2) proto="tcp" ;; 3) proto="udp" ;; *) proto="both" ;; esac

    def_lip="$(xray_fwd_default_listen_ip)"
    read -rp "$(L '本机监听 IP（回车默认 ')${def_lip}$(L '）: ')" lip || { [ -n "$lip" ] || return 1; }
    lip="${lip:-$def_lip}"
    is_ip "$lip" 0 || { warn "$(L '监听 IP 格式不合法')"; return 1; }

    while true; do
        read -rp "$(L '本机监听端口 (1-65535): ')" lport || { [ -n "$lport" ] || return 1; }
        validate_port "$lport" && break
        warn "$(L '端口不合法')"
    done
    lport=$((10#$lport))

    # 冲突检测：先查本 Xray 模块是否已用该端口，再查系统监听（排除 xray 自身）
    if xray_port_used "$lport"; then
        warn "$(L '该端口已被本模块其他规则占用，请换一个') (${lport})"
        return 1
    fi
    if command -v ss >/dev/null 2>&1; then
        occ=""
        [ "$proto" != "udp" ] && occ="$(check_port_occupied_by_other tcp "$lport" xray || true)"
        [ -z "$occ" ] && [ "$proto" != "tcp" ] && occ="$(check_port_occupied_by_other udp "$lport" xray || true)"
        if [ -n "$occ" ]; then
            warn "$(L '端口 ')${lport}$(L ' 已被其他进程占用：')"
            echo "$occ"
            confirm "$(L '仍要继续添加？')" n || return 0
        fi
    fi

    while true; do
        read -rp "$(L '目标地址（域名或 IP）: ')" rhost || { [ -n "$rhost" ] || return 1; }
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

    if confirm "$(L '跟随系统重定向（followRedirect，仅配合 iptables 转发规则使用）？')" n; then follow=1; fi

    id="$(xray_fwd_next_id)"
    local env_file="${XRAY_FWD_DIR}/${id}.env"
    install -d -m 750 "$XRAY_FWD_DIR"
    cat > "$env_file" << FWDEOF
FWD_ID="${id}"
FWD_ENABLED="1"
FWD_REMARK="$(dq_escape "$remark")"
FWD_PROTO="${proto}"
FWD_LIP="${lip}"
FWD_LPORT="${lport}"
FWD_RHOST="${rhost}"
FWD_RPORT="${rport}"
FWD_FOLLOW="${follow}"
FWDEOF
    chmod 600 "$env_file"

    if ! xray_fwd_rebuild; then
        rm -f "$env_file"
        xray_fwd_rebuild >/dev/null 2>&1 || true
        error "$(L '新转发规则未能生效，已自动撤回')"
    fi

    local -a fw_specs=()
    [ "$proto" != "udp" ] && fw_specs+=("${lport}/tcp")
    [ "$proto" != "tcp" ] && fw_specs+=("${lport}/udp")
    fw_allow_for_service "${fw_specs[@]}"
    reserved_ports_sync || true
    success "$(L '转发规则 ')${id}$(L ' 已生效：')${lip}:${lport} -> ${rhost}:${rport}"
}

xray_fwd_list() {
    step "$(L 'Xray 转发规则列表')"
    divider
    local f idx=0 tags status
    while IFS= read -r f; do
        idx=$((idx + 1))
        (
            # shellcheck disable=SC1090
            source "$f" 2>/dev/null || exit 0
            tags=""
            [ "${FWD_PROTO:-both}" = "tcp" ] && tags="${tags}[$(L '纯TCP')]"
            [ "${FWD_PROTO:-both}" = "udp" ] && tags="${tags}[$(L '纯UDP')]"
            [ "${FWD_FOLLOW:-0}" = "1" ] && tags="${tags}[followRedirect]"
            if [ "${FWD_ENABLED:-0}" = "1" ]; then
                status="${GREEN}$(L '启用')${NC}"
            else
                status="${YELLOW}$(L '停用')${NC}"
            fi
            echo -e "  ${BOLD}${idx})${NC} [${FWD_ID}] ${status}  ${CYAN}${FWD_LIP}:${FWD_LPORT}${NC} -> ${GREEN}${FWD_RHOST}:${FWD_RPORT}${NC} ${tags}${FWD_REMARK:+  # ${FWD_REMARK}}"
        )
    done < <(xray_fwd_rule_files)
    if [ "$idx" -eq 0 ]; then
        info "$(L '暂无转发规则')"
    fi
}

xray_fwd_pick() {
    local -a files=()
    local f choice
    while IFS= read -r f; do files+=("$f"); done < <(xray_fwd_rule_files)
    [ "${#files[@]}" -gt 0 ] || { info "$(L '暂无规则')"; return 1; }
    xray_fwd_list
    echo ""
    read -rp "$(L '输入规则序号（回车取消）: ')" choice || { [ -n "$choice" ] || return 1; }
    [[ -n "$choice" && "$choice" =~ ^[0-9]+$ ]] || return 1
    choice=$((10#$choice))
    [ "$choice" -ge 1 ] && [ "$choice" -le "${#files[@]}" ] || { warn "$(L '序号无效')"; return 1; }
    PICKED_FWD_FILE="${files[$((choice - 1))]}"
    return 0
}

xray_fwd_toggle() {
    xray_fwd_pick || return 0
    local f="$PICKED_FWD_FILE" cur next
    cur="$(grep -m1 '^FWD_ENABLED=' "$f" | cut -d'"' -f2 || echo 0)"
    if [ "$cur" = "1" ]; then next="0"; else next="1"; fi
    if grep -q '^FWD_ENABLED=' "$f"; then
        sed -i "s|^FWD_ENABLED=.*|FWD_ENABLED=\"${next}\"|" "$f" || { warn "$(L '规则状态切换失败')"; return 1; }
    else
        printf '%s\n' "FWD_ENABLED=\"${next}\"" >> "$f"
    fi
    xray_fwd_rebuild && success "$(L '规则状态已切换为：')$([ "$next" = "1" ] && echo "$(L '启用')" || echo "$(L '停用')")"
}

xray_fwd_delete() {
    xray_fwd_pick || return 0
    local f="$PICKED_FWD_FILE" old_port old_proto fid flip frhost frport
    fid="$(grep -m1 '^FWD_ID=' "$f" | cut -d'"' -f2 || true)"
    flip="$(grep -m1 '^FWD_LIP=' "$f" | cut -d'"' -f2 || true)"
    old_port="$(grep -m1 '^FWD_LPORT=' "$f" | cut -d'"' -f2 || true)"
    old_proto="$(grep -m1 '^FWD_PROTO=' "$f" | cut -d'"' -f2 || true)"
    frhost="$(grep -m1 '^FWD_RHOST=' "$f" | cut -d'"' -f2 || true)"
    frport="$(grep -m1 '^FWD_RPORT=' "$f" | cut -d'"' -f2 || true)"
    confirm "$(L '确认删除规则 [')${fid}] ${flip}:${old_port} -> ${frhost}:${frport}$(L ']？')" n || return 0
    rm -f "$f"
    if ! xray_fwd_rebuild; then
        warn "$(L '服务重载失败，删除未生效，请检查日志')"
        return 1
    fi
    if ufw_installed && validate_port "$old_port"; then
        local old_specs=""
        [ "$old_proto" != "udp" ] && old_specs="${old_specs} ${old_port}/tcp"
        [ "$old_proto" != "tcp" ] && old_specs="${old_specs} ${old_port}/udp"
        fw_prune_old_specs "$old_specs"
    fi
    success "$(L '已删除规则 ')${fid}"
}

# TCP 目标连通性与延迟检测（与 realm_test_rules 共用 probe_tcp_host_port）
xray_fwd_test() {
    step "$(L '转发目标连通性测试（TCP 握手延迟）')"
    divider
    local f any=0
    while IFS= read -r f; do
        any=1
        (
            # shellcheck disable=SC1090
            source "$f" 2>/dev/null || exit 0
            local res
            if [ "${FWD_PROTO:-both}" = "udp" ]; then
                echo -e "  [${FWD_ID}] ${FWD_RHOST}:${FWD_RPORT}  $(L '跳过（纯 UDP 无法做 TCP 握手探测）')  ${FWD_REMARK}"
                exit 0
            fi
            res="$(probe_tcp_host_port "$FWD_RHOST" "$FWD_RPORT")"
            if [[ "$res" == OK* ]]; then
                echo -e "  [${FWD_ID}] ${FWD_RHOST}:${FWD_RPORT}  ${GREEN}${res}${NC}  ${FWD_REMARK}"
            else
                echo -e "  [${FWD_ID}] ${FWD_RHOST}:${FWD_RPORT}  ${RED}${res}${NC}  ${FWD_REMARK}"
            fi
        )
    done < <(xray_fwd_rule_files)
    [ "$any" -eq 0 ] && info "$(L '暂无可测试的规则')"
}

xray_fwd_menu() {
    local choice
    while true; do
        clear 2>/dev/null || true
        echo -e "${BOLD}${CYAN}━━━ $(L 'Xray 端口转发（dokodemo-door）') ━━━${NC}"
        echo -e "  $(L '当前状态:') $(xray_fwd_state_text)"
        divider
        echo -e "  ${GREEN}1)${NC}  $(L '添加转发规则')"
        echo -e "  ${GREEN}2)${NC}  $(L '查看转发规则列表')"
        echo -e "  ${GREEN}3)${NC}  $(L '启用 / 停用单条规则')"
        echo -e "  ${GREEN}4)${NC}  $(L '删除转发规则')"
        echo -e "  ${GREEN}5)${NC}  $(L '测试目标连通性与延迟')"
        echo -e "  ${GREEN}6)${NC}  $(L '重启服务 / 查看状态与日志')"
        echo -e "  ${GREEN}0)${NC}  $(L '返回 Xray 菜单')"
        divider
        read -rp "$(L '请选择') [0-6]: " choice
        case "$choice" in
            1) run_action xray_fwd_add ;;
            2) run_action xray_fwd_list ;;
            3) run_action xray_fwd_toggle ;;
            4) run_action xray_fwd_delete ;;
            5) run_action xray_fwd_test ;;
            6) run_action bash -c 'systemctl restart adam-xray 2>/dev/null || true; systemctl status adam-xray --no-pager || true; journalctl -u adam-xray -n 20 --no-pager || true' ;;
            0) return 0 ;;
            *) warn "$(L '无效选择')" ;;
        esac
        pause_return
    done
}

xray_fwd_cli() {
    local sub="${1:-menu}"
    [ "$#" -gt 0 ] && shift
    case "$sub" in
        menu)      xray_fwd_menu ;;
        add)       xray_fwd_add ;;
        list)      xray_fwd_list ;;
        toggle)    xray_fwd_toggle ;;
        delete)    xray_fwd_delete ;;
        test)      xray_fwd_test ;;
        restart)   xray_fwd_rebuild && success "$(L 'Xray 转发已重启')" ;;
        status)    systemctl status adam-xray --no-pager || true ;;
        *) error "$(L '未知的 xray fwd 子命令:') ${sub}$(L '（可用: add / list / toggle / delete / test / restart / status）')" ;;
    esac
}

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
    state_save "$CADDY_STATE_FILE" "$CADDY_DIR" 755 CADDY_EMAIL
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
            # shellcheck disable=SC1090
            source "$f" 2>/dev/null || exit 0
            [ "${SITE_ENABLED:-0}" = "1" ] || exit 0
            if [ "${SITE_MODE:-https}" = "http" ]; then
                validate_port "${SITE_PORT:-80}" && echo "${SITE_PORT:-80}/tcp"
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
    local tag=""
    tag="$(curl -fsS --max-time 20 "https://api.github.com/repos/${CADDY_REPO}/releases/latest" 2>/dev/null \
        | grep -m1 '"tag_name"' | cut -d'"' -f4 || true)"
    if [ -z "$tag" ]; then
        tag="$(curl -fsSI --max-time 20 "https://github.com/${CADDY_REPO}/releases/latest" 2>/dev/null \
            | tr -d '\r' | awk 'tolower($1)=="location:" {print $2}' | sed -n 's#.*/tag/##p' | tail -1 || true)"
    fi
    printf '%s' "$tag"
}

caddy_fetch_binary() {
    local tag="$1" arch ver_num asset url sums_url expected actual bin
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
    if ! curl -fL --retry 3 --connect-timeout 10 --max-time 300 -o "${wd}/${asset}" "$url"; then
        warn "$(L '下载失败:') ${url}"
        return 1
    fi
    actual="$(sha256sum "${wd}/${asset}" | awk '{print $1}')"
    expected=""
    if curl -fsSL --max-time 20 -o "${wd}/checksums.txt" "$sums_url" 2>/dev/null; then
        expected="$(awk -v a="$asset" '$2 == a || $2 == "*"a {print $1; exit}' "${wd}/checksums.txt" || true)"
    fi
    if [ -n "$expected" ]; then
        if [ "$expected" != "$actual" ]; then
            warn "$(L 'SHA256 校验失败（官方') ${expected}$(L '，实际') ${actual}$(L '），已中止')"
            return 1
        fi
        success "$(L 'SHA256 校验通过（')${asset}$(L '）')"
    else
        warn "$(L '未取到官方 SHA256 摘要，跳过校验（')${asset}$(L '）')"
    fi
    tar -xzf "${wd}/${asset}" -C "$wd" || { warn "$(L '解压失败')"; return 1; }
    bin="$(find "$wd" -maxdepth 2 -type f -name caddy | head -1)"
    [ -n "$bin" ] || { warn "$(L '解压失败')"; return 1; }
    chmod 755 "$bin"
    "$bin" version >/dev/null 2>&1 || { warn "$(L '下载到的二进制无法在本机运行（架构或 libc 不匹配），已中止，现有安装未被改动')"; return 1; }
    CADDY_DL_BIN="$bin"
    return 0
}

caddy_write_main_config() {
    install -d -m 755 "$CADDY_DIR" "$CADDY_SITES_DIR" "$CADDY_DATA_DIR"
    caddy_load_state
    local email_line=""
    [ -n "${CADDY_EMAIL:-}" ] && email_line="    email ${CADDY_EMAIL}"
    cat > "$CADDY_FILE" << CADEOF
{
    admin off
${email_line}
}

import ${CADDY_SITES_DIR}/*.caddy
CADEOF
    chmod 644 "$CADDY_FILE"
}

caddy_write_service() {
    local run_user="adam-caddy" run_group="adam-caddy"
    if [ -f "${CADDY_DIR}/run-as-root" ]; then
        run_user=""; run_group=""
    elif ! ensure_system_user adam-caddy adam-caddy 2>/dev/null; then
        run_user=""; run_group=""
    else
        install -d -m 750 -o adam-caddy -g adam-caddy "$CADDY_DATA_DIR" 2>/dev/null || true
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
        # shellcheck disable=SC1090
        source "$env_file" 2>/dev/null || exit 1
        if [ "${SITE_ENABLED:-0}" != "1" ]; then
            rm -f "$caddy_file"
            exit 0
        fi
        local addr="" up="${SITE_UPSTREAM}"
        case "${SITE_MODE:-https}" in
            http)
                local sp="${SITE_PORT:-80}"
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
        chmod 644 "$tmpf"
        mv -f "$tmpf" "$caddy_file"
    )
}

caddy_rebuild_all() {
    caddy_write_main_config
    local f id
    while IFS= read -r f; do
        id="$(basename "$f" .env)"
        caddy_render_site "$id" || true
    done < <(caddy_site_files)
    local c
    for c in "${CADDY_SITES_DIR}"/*.caddy; do
        [ -f "$c" ] || continue
        id="$(basename "$c" .caddy)"
        [ -f "${CADDY_SITES_DIR}/${id}.env" ] || rm -f "$c"
    done
}

caddy_reload_service() {
    caddy_rebuild_all
    if [ "$(caddy_enabled_count)" -eq 0 ]; then
        systemctl disable --now adam-caddy 2>/dev/null || true
        return 0
    fi
    caddy_installed || return 0
    local out
    if ! out="$("$CADDY_BIN" validate --config "$CADDY_FILE" --adapter caddyfile 2>&1)"; then
        warn "$(L '配置校验未通过：')"
        printf '%s\n' "$out" | tail -n 8
        return 1
    fi
    systemctl enable adam-caddy >/dev/null 2>&1 || true
    if svc_restart_wait adam-caddy 2 15; then
        return 0
    fi
    if grep -q '^User=' "$CADDY_SERVICE" 2>/dev/null; then
        sed -i '/^User=/d; /^Group=/d' "$CADDY_SERVICE" || return 1
        systemctl daemon-reload || true
        if svc_restart_wait adam-caddy 2 15; then
            touch "${CADDY_DIR}/run-as-root" 2>/dev/null || true
            return 0
        fi
    fi
    return 1
}

caddy_install() {
    step "$(L '安装 / 更新 Caddy（官方仓库）')"
    divider
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
    caddy_fetch_binary "$tag" || error "$(L '下载或校验失败，已中止')"
    install -d -m 755 "$CADDY_DIR" "$CADDY_SITES_DIR" "$CADDY_DATA_DIR"
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
    if [ "$(caddy_enabled_count)" -gt 0 ]; then
        if ! caddy_reload_service; then
            if [ -f "$CADDY_BIN_BACKUP" ]; then
                install -m 755 "$CADDY_BIN_BACKUP" "$CADDY_BIN"
                caddy_reload_service >/dev/null 2>&1 || true
            fi
            error "$(L '更新失败')"
        fi
    fi
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
            read -rp "$(L '本机监听端口 (1-65535): ') [default 80]: " port || { [ -n "$port" ] || return 1; }
            port="${port:-80}"
            validate_port "$port" || { warn "$(L '端口不合法')"; return 1; }
            port=$((10#$port))
            ;;
        *) mode="https" ;;
    esac

    if [ "$mode" != "http" ]; then
        check_domain_dns "$domain" || true
        local occ=""
        occ="$(check_port_occupied_by_other tcp 443 caddy || true)"
        if [ -n "$occ" ]; then
            warn "$(L '端口 ')443$(L ' 已被其他进程占用：')"
            echo "$occ"
            confirm "$(L '仍要继续添加？')" n || return 0
        fi
    fi

    while true; do
        read -rp "$(L '上游目标地址（如 127.0.0.1:8080 或 https://example.com）: ')" upstream || { [ -n "$upstream" ] || return 1; }
        upstream="$(printf '%s' "$upstream" | tr -d ' \r\n')"
        if [[ "$upstream" =~ ^[A-Za-z0-9._:/\[\]-]+$ ]] && [[ "$upstream" == *:* ]]; then break; fi
        warn "$(L '目标地址格式不合法')"
    done
    if [[ "$upstream" == https://* ]]; then
        if confirm "$(L '跳过上游 TLS 证书校验（自签上游选 y）？')" n; then insecure=1; fi
    fi

    read -rp "$(L '规则备注（可选）: ')" remark || { [ -n "$remark" ] || return 1; }
    remark="${remark//\"/}"

    id="$(caddy_next_id)"
    local env_file="${CADDY_SITES_DIR}/${id}.env"
    install -d -m 755 "$CADDY_SITES_DIR"
    cat > "$env_file" << SITEEOF
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
            # shellcheck disable=SC1090
            source "$f" 2>/dev/null || exit 0
            if [ "${SITE_ENABLED:-0}" = "1" ]; then st="${GREEN}$(L '启用')${NC}"; else st="${YELLOW}$(L '停用')${NC}"; fi
            local pinfo=""
            [ "${SITE_MODE:-https}" = "http" ] && pinfo=":${SITE_PORT:-80} [HTTP]" || pinfo=" [HTTPS/${SITE_MODE}]"
            echo -e "  ${BOLD}${idx})${NC} [${SITE_ID}] ${st}  ${CYAN}${SITE_DOMAIN}${pinfo}${NC} -> ${GREEN}${SITE_UPSTREAM}${NC}${SITE_REMARK:+  # ${SITE_REMARK}}"
        )
    done < <(caddy_site_files)
    [ "$idx" -eq 0 ] && info "$(L '暂无反代站点')"
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
    local f="$PICKED_SITE_FILE" cur next
    cur="$(grep -m1 '^SITE_ENABLED=' "$f" | cut -d'"' -f2 || echo 0)"
    if [ "$cur" = "1" ]; then next="0"; else next="1"; fi
    sed -i "s|^SITE_ENABLED=.*|SITE_ENABLED=\"${next}\"|" "$f"
    caddy_reload_service && success "$(L '站点状态已切换为：')$([ "$next" = "1" ] && echo "$(L '启用')" || echo "$(L '停用')")"
}

caddy_edit_site() {
    caddy_pick_site || return 0
    local f="$PICKED_SITE_FILE" bak ans
    # shellcheck disable=SC1090
    source "$f"
    local domain="$SITE_DOMAIN" upstream="$SITE_UPSTREAM" mode="$SITE_MODE" port="${SITE_PORT:-443}" insecure="${SITE_INSECURE:-0}" remark="${SITE_REMARK:-}"
    read -rp "$(L '请输入域名（如: nhk.example.com）:') [${domain}] ($(L '回车保持')): " ans || { [ -n "$ans" ] || return 1; }
    [ -n "$ans" ] && domain="${ans,,}"
    read -rp "$(L '上游目标地址（如 127.0.0.1:8080 或 https://example.com）: ') [${upstream}] ($(L '回车保持')): " ans || { [ -n "$ans" ] || return 1; }
    [ -n "$ans" ] && upstream="${ans//[[:space:]]/}"
    read -rp "$(L '规则备注（可选）: ') [${remark}] ($(L '回车保持')): " ans || { [ -n "$ans" ] || return 1; }
    [ -n "$ans" ] && remark="${ans//\"/}"
    bak="${f}.bak"
    cp -f "$f" "$bak"
    cat > "$f" << SITEEOF
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
    success "$(L '反代站点已生效：')${domain} -> ${upstream}"
}

caddy_delete_site() {
    caddy_pick_site || return 0
    local f="$PICKED_SITE_FILE"
    # shellcheck disable=SC1090
    source "$f"
    confirm "$(L '确认删除反代站点 ')${SITE_DOMAIN}$(L '？')" n || return 0
    rm -f "$f" "${CADDY_SITES_DIR}/${SITE_ID}.caddy"
    caddy_reload_service || true
    reserved_ports_sync || true
    success "$(L '已删除反代站点 ')${SITE_DOMAIN}"
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
    systemctl disable --now adam-caddy 2>/dev/null || true
    rm -f "$CADDY_SERVICE" "$CADDY_BIN" "$CADDY_BIN_BACKUP"
    systemctl daemon-reload || true
    if confirm "$(L '同时删除配置目录') ${CADDY_DIR}$(L '？')" n; then
        rm -rf "$CADDY_DIR" "$CADDY_DATA_DIR"
        userdel adam-caddy >/dev/null 2>&1 || true
    fi
    reserved_ports_sync || true
    success "$(L 'Caddy 已卸载')"
}

# ── Cloudflare Tunnel (cloudflared) ─────────────────────────────

cf_tunnel_latest_tag() {
    local tag=""
    tag="$(curl -fsS --max-time 20 "https://api.github.com/repos/${CF_TUNNEL_REPO}/releases/latest" 2>/dev/null \
        | grep -m1 '"tag_name"' | cut -d'"' -f4 || true)"
    if [ -z "$tag" ]; then
        tag="$(curl -fsSI --max-time 20 "https://github.com/${CF_TUNNEL_REPO}/releases/latest" 2>/dev/null \
            | tr -d '\r' | awk 'tolower($1)=="location:" {print $2}' | sed -n 's#.*/tag/##p' | tail -1 || true)"
    fi
    printf '%s' "$tag"
}

cf_tunnel_install() {
    step "$(L '安装 / 更新 cloudflared（官方仓库）')"
    divider
    local arch asset tag url api_json digest actual
    case "$(uname -m)" in
        x86_64|amd64)  arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        armv7l)        arch="arm" ;;
        *) error "$(L '不支持的架构:') $(uname -m)" ;;
    esac
    info "$(L '正在查询 cloudflared 官方最新版本...')"
    tag="$(cf_tunnel_latest_tag)"
    [ -n "$tag" ] || error "$(L '无法获取 cloudflared 最新版本号，请检查网络')"
    asset="cloudflared-linux-${arch}"
    url="https://github.com/${CF_TUNNEL_REPO}/releases/download/${tag}/${asset}"
    make_workdir || return 1
    local wd="$WORKDIR"
    curl -fL --retry 3 --connect-timeout 10 --max-time 300 -o "${wd}/cloudflared" "$url" || error "$(L '下载失败:') ${url}"
    actual="$(sha256sum "${wd}/cloudflared" | awk '{print $1}')"
    api_json="$(curl -fsS --max-time 20 "https://api.github.com/repos/${CF_TUNNEL_REPO}/releases/tags/${tag}" 2>/dev/null || true)"
    digest=""
    if [ -n "$api_json" ] && command -v python3 >/dev/null 2>&1; then
        digest="$(printf '%s' "$api_json" | ASSET="$asset" python3 -c 'import json,os,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit(0)
for a in d.get("assets",[]):
    if a.get("name")==os.environ["ASSET"]:
        print((a.get("digest") or "").replace("sha256:",""))
        break' 2>/dev/null || true)"
    fi
    if [ -n "$digest" ] && [ "$digest" != "$actual" ]; then
        error "$(L 'SHA256 校验失败（官方') ${digest}$(L '，实际') ${actual}$(L '），已中止')"
    fi
    chmod 755 "${wd}/cloudflared"
    "${wd}/cloudflared" --version >/dev/null 2>&1 || error "$(L '下载到的二进制无法在本机运行（架构或 libc 不匹配），已中止，现有安装未被改动')"
    [ -f "$CF_TUNNEL_BIN" ] && cp -f "$CF_TUNNEL_BIN" "$CF_TUNNEL_BIN_BACKUP" 2>/dev/null || true
    install -m 755 "${wd}/cloudflared" "$CF_TUNNEL_BIN"
    if [ -f "$CF_TUNNEL_SERVICE" ] && systemctl is-enabled --quiet adam-cloudflared 2>/dev/null; then
        systemctl restart adam-cloudflared 2>/dev/null || true
    fi
    success "$(L 'cloudflared 安装完成') (${tag})"
}

cf_tunnel_setup_token() {
    cf_tunnel_installed || cf_tunnel_install || return 1
    step "$(L '配置持久化隧道（粘贴 Zero Trust Token）')"
    divider
    local token=""
    read -rsp "$(L '粘贴 Cloudflare Zero Trust Tunnel Token（输入不回显）: ')" token || { [ -n "$token" ] || return 1; }; echo
    token="$(printf '%s' "$token" | tr -d ' \r\n')"
    [ -n "$token" ] || { warn "$(L 'Token 不能为空')"; return 1; }
    install -d -m 700 "$CF_TUNNEL_DIR"
    printf 'TUNNEL_TOKEN="%s"\n' "$(dq_escape "$token")" > "$CF_TUNNEL_ENV"
    chmod 600 "$CF_TUNNEL_ENV"
    write_service_unit "$CF_TUNNEL_SERVICE" "Adam Cloudflare Tunnel" "https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/" "60" "" "" \
        "${CF_TUNNEL_BIN} --no-autoupdate tunnel run" "" "65536" "always" "5" \
        "EnvironmentFile=${CF_TUNNEL_ENV}
ProtectSystem=full
ProtectHome=read-only" "StartLimitBurst=10"
    systemctl daemon-reload
    systemctl enable adam-cloudflared >/dev/null 2>&1 || true
    if svc_restart_wait adam-cloudflared 3 20; then
        success "$(L 'Cloudflare Tunnel 持久化服务已启动')"
    else
        warn "$(L 'Cloudflare Tunnel 启动失败，请查看日志：journalctl -u adam-cloudflared -n 20 --no-pager')"
        return 1
    fi
}

cf_tunnel_quick() {
    cf_tunnel_installed || cf_tunnel_install || return 1
    step "$(L '启动临时快速隧道（trycloudflare.com，免配置）')"
    divider
    local port=""
    read -rp "$(L '输入本地服务端口（如 8080，将映射到 *.trycloudflare.com）: ')" port || { [ -n "$port" ] || return 1; }
    validate_port "$port" || { warn "$(L '端口不合法')"; return 1; }
    info "Ctrl+C 停止临时隧道 ..."
    "$CF_TUNNEL_BIN" tunnel --url "http://127.0.0.1:$((10#$port))" || true
}

cf_tunnel_uninstall_do() {
    if ! cf_tunnel_installed && [ ! -d "$CF_TUNNEL_DIR" ] && [ ! -f "$CF_TUNNEL_SERVICE" ]; then return 0; fi
    systemctl disable --now adam-cloudflared 2>/dev/null || true
    rm -f "$CF_TUNNEL_SERVICE" "$CF_TUNNEL_BIN" "$CF_TUNNEL_BIN_BACKUP"
    systemctl daemon-reload || true
    if confirm "$(L '同时删除配置目录') ${CF_TUNNEL_DIR}$(L '？')" n; then
        rm -rf "$CF_TUNNEL_DIR"
    fi
    success "$(L 'cloudflared 已卸载')"
}

cf_tunnel_menu() {
    local choice
    while true; do
        clear 2>/dev/null || true
        echo -e "${BOLD}${CYAN}━━━ $(L 'Cloudflare Tunnel 管理（Zero Trust / 临时隧道）') ━━━${NC}"
        echo -e "  $(L '当前状态:') $([ -x "$CF_TUNNEL_BIN" ] && "$CF_TUNNEL_BIN" --version 2>/dev/null | head -1 || echo "$(L '未安装')") · $(svc_state adam-cloudflared)"
        divider
        echo -e "  ${GREEN}1)${NC} $(L '安装 / 更新 cloudflared（官方仓库）')"
        echo -e "  ${GREEN}2)${NC} $(L '配置持久化隧道（粘贴 Zero Trust Token）')"
        echo -e "  ${GREEN}3)${NC} $(L '启动临时快速隧道（trycloudflare.com，免配置）')"
        echo -e "  ${GREEN}4)${NC} $(L '查看隧道状态与日志')"
        echo -e "  ${GREEN}5)${NC} $(L '重启持久化隧道')"
        echo -e "  ${GREEN}6)${NC} ${RED}$(L '停用 / 卸载 cloudflared')${NC}"
        echo -e "  ${GREEN}0)${NC} $(L '返回')"
        divider
        read -rp "$(L '请选择') [0-6]: " choice
        case "$choice" in
            1) run_action cf_tunnel_install ;;
            2) run_action cf_tunnel_setup_token ;;
            3) run_action cf_tunnel_quick ;;
            4) run_action bash -c 'systemctl status adam-cloudflared --no-pager || true; journalctl -u adam-cloudflared -n 20 --no-pager || true' ;;
            5) run_action svc_restart_wait adam-cloudflared 2 15 ;;
            6) run_action cf_tunnel_uninstall_do ;;
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
        echo -e "  ${GREEN}10)${NC} ${RED}$(L '卸载 Caddy')${NC}"
        echo -e "  ${BOLD}── Cloudflare Tunnel ──${NC}"
        echo -e "  ${GREEN}11)${NC} $(L 'Cloudflare Tunnel 管理（Zero Trust / 临时隧道）')"
        echo -e "  ${GREEN}0)${NC}  $(L '返回主菜单')"
        divider
        read -rp "$(L '请选择') [0-11]: " choice
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
            10) run_action caddy_uninstall_do ;;
            11) cf_tunnel_menu ;;
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
        restart)   caddy_reload_service && success "$(L '已重启')" ;;
        status)    systemctl status adam-caddy --no-pager || true ;;
        logs)      journalctl -u adam-caddy -f || true ;;
        uninstall) caddy_uninstall_do ;;
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
        restart)   svc_restart_wait adam-cloudflared 2 15 ;;
        status)    systemctl status adam-cloudflared --no-pager || true ;;
        logs)      journalctl -u adam-cloudflared -f || true ;;
        uninstall) cf_tunnel_uninstall_do ;;
        *) error "$(L '未知的 proxy 子命令:') ${sub}" ;;
    esac
}

usage() {
    cat << USAGEEOF
$(L '用法'): adam [$(L '命令')]          $(L '（')$(L '不带参数 = 打开主菜单')$(L '）')

$(L '主菜单'): 1 Nowhere · 2 Snell · 3 Xray · 4 $(L '脚本更新') · 5 $(L '防火墙') · 6 Fail2ban · 7 $(L '系统调优') · 8 $(L '自动维护') · 9 Realm · 10 $(L '域名反代')

Nowhere:
  $(L 'nowhere                    打开 Nowhere 菜单')
  install | uninstall | update | reconfig | config | status | logs | restart
  fingerprint | version | select-version | rollback | generate-key | probe
  cert-status | install-egress | shortcuts

Snell v${SNELL_MAJOR}:
  $(L 'snell                      打开 Snell 菜单')
  snell install | update | config | reconfig | status | health | repair | logs | restart | uninstall
  snell ports | add-port | del-port [$(L '端口')]    $(L '多端口：列出 / 新增 / 删除某个端口配置')
  snell auto on|$(L 'off          开/关 跟随官方发布的自动更新（默认 beta 通道：跟随最新测试版）')

Xray (SS / VLESS):
  $(L 'xray                       打开 Xray 菜单')
  xray install | add | list | links | delete | update | health | repair | status | logs | restart | cnblock [on|off] | uninstall
  xray fwd add | list | toggle | delete | test | restart | status    $(L '端口转发') (dokodemo-door)

Realm $(L '端口转发'):
  $(L 'realm                      打开 Realm 端口转发菜单')
  realm install | add | batch | edit | list | toggle | delete | test | config | tune | auto | restart | status | logs | export | import | uninstall

$(L '域名反代') (Caddy / Cloudflare Tunnel):
  $(L 'proxy                      打开域名反代菜单（Caddy / Cloudflare Tunnel）')
  $(L 'caddy / tunnel             直接操作 Caddy 反代或 Cloudflare Tunnel')

$(L '系统与网络调优:')
  $(L 'tune                       打开调优菜单')
  tune tcp [$(L 'tcpfit 子命令')]   $(L '运行 tcpfit（不带子命令 = 它的菜单），如 adam tune tcp status')
  tune xanmod | xanmod-remove
  tune dns [show|set|restore] | prefer [ipv4|ipv6|restore] | ipv6 [off|off-temp|on] | status

$(L '自动维护:')
  $(L 'auto                       打开自动维护菜单（保活巡检 / 自动更新开关）')
  maintain | $(L 'watchdog        立即执行一次每日维护 / 保活巡检（定时器调用的就是这两个）')
  $(L 'maintain-log               查看维护记录')

$(L '防火墙') (ufw):
  $(L 'fw                         打开防火墙菜单')
  fw install | list | status | on | off | sync
  $(L 'fw allow <端口>            例: adam fw allow 443/tcp,8000-8100    （不写协议 = TCP+UDP）')
  $(L 'fw deny  <端口>            删除放行规则')

Fail2ban:
  $(L 'f2b                        打开 Fail2ban 菜单')
  f2b install | status | banned | log | on | off | restart | uninstall
  $(L 'f2b bantime <时长>         例: adam f2b bantime 1h   （纯数字 = 分钟，-1 = 永久）')
  f2b ban <IP> | unban <IP> | unban-all

$(L '其他:')
  $(L 'script                     打开脚本更新菜单')
  update-script              $(L '立即更新本管理脚本')
  lang [zh|en]               $(L '切换界面语言')$(L '（zh=中文 / en=English）')
  backup | restore [$(L '文件')]      $(L '备份配置') / $(L '恢复配置')
  doctor                     $(L '一键诊断')
  log-cleanup                $(L '清理日志')
  migrate-tls2               tls=1 $(L '升级为真实证书') (tls=2)
USAGEEOF
}

run_interactive_menu() {
    ask_lang_first_time
    while true; do
        show_menu
        case "$MENU_CHOICE" in
            1) nowhere_menu ;;
            2) snell_menu ;;
            3) xray_menu ;;
            4) script_menu ;;
            5) fw_menu ;;
            6) f2b_menu ;;
            7) tune_menu ;;
            8) maint_menu ;;
            9) realm_menu ;;
            10) proxy_menu ;;
            0) exit 0 ;;
            *) warn "$(L '无效选择')"; pause_return ;;
        esac
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
    nowhere)    nowhere_menu ;;
    script)     script_menu ;;
    xray)       xray_cli "${ACTION_ARGS[@]}" ;;
    realm|pf)   realm_cli "${ACTION_ARGS[@]}" ;;
    proxy|caddy) proxy_cli "${ACTION_ARGS[@]}" ;;
    tunnel)     cf_tunnel_cli "${ACTION_ARGS[@]}" ;;
    tune)       tune_cli "${ACTION_ARGS[@]}" ;;
    auto|maint) maint_menu ;;
    watchdog)   maint_watchdog ;;
    maintain)   maint_daily ;;
    maintain-log) maint_show_log ;;
    lang)       set_lang "${ACTION_ARGS[0]:-}" ;;
    backup)     do_backup ;;
    restore)    do_restore "${ACTION_ARGS[0]:-}" ;;
    doctor)     do_doctor ;;
    log-cleanup) do_log_cleanup ;;
    migrate-tls2) do_migrate_tls2 ;;
    help|-h|--help) usage ;;
    *) usage; error "$(L '未知操作:') ${ACTION}" ;;
esac
