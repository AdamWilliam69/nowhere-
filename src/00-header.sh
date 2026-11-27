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
#   ── 脚本 v8.6 修订（2026-11-25，抗指纹 / CSPRNG / 官方源校验 / 权限与二段自愈 / 深度 Bug 修复）──
#     - CSPRNG 随机引擎：新增 csprng_hex / csprng_base64 / csprng_int（拒绝采样无取模偏差）/
#       csprng_alnum / csprng_short_id / csprng_url_path（拟真多段无扩展名路径，防 CDN 缓存）；
#       零 tr|head SIGPIPE 风险；random_free_port / pick_udp_port_avoiding 全面替代 $RANDOM 并避开
#       TCP/UDP 监听、SSH 端口及全部已托管服务端口。
#     - 协议抗指纹优化：
#         · Xray：新增 xray_pick_fp（REALITY 避开 Xray ≥ v26.9.8 必拒的 edge/ios 无 X25519MLKEM768
#           指纹，按 chrome/firefox/safari 主流权重随机或手选并落盘 N_FP；TLS/CDN 支持全主流指纹）；
#           xray_ask_sni 移出 microsoft/apple 改用 12 站点境外非 CF TLS 1.3 + H2 池并 CSPRNG 随机实测；
#           REALITY 生成 2–3 条变长偶数位 shortIds + 随机 spiderX(spx=) + maxTimeDiff:60000；
#           CDN 自签证书改 ECDSA P-256 + RFC 5280 正整数随机序列号 + 365–730 天有效期并在每日维护自动轮换。
#         · Snell v6：PSK 升级为 CSPRNG 变长 32–48 位（A-Za-z0-9_-，首尾字母数字），三处校验同步放宽。
#         · Nowhere v3.3.0：HANDSHAKE_TIMEOUT 默认 auto（Portal/Egress unit、egress.env、probe 及启动命令
#           省略 NOW_HANDSHAKE_TIMEOUT，启用官方按密钥派生 3–30s，避免传入字面量 auto 被启动拒绝）。
#         · Realm：WS/WSS 默认路径改用 csprng_url_path 并明确提示双端配对参数。
#     - 官方源安全校验：全量下载统一走 secure_curl（强制 --proto '=https' --tlsv1.2）与 verify_elf_binary
#       （ELF 魔数 + 本机 e_machine 架构校验）；统一 github_asset_sha256（Python + 纯 awk + expanded_assets
#       限流兜底）覆盖 Nowhere / Xray / Realm / Caddy / cloudflared；修复 xray_ensure_geo_data 拉取官方
#       dlc.dat + .sha256sum 强校验并清理临时文件。
#     - 目录与安装流程：新增 preflight_install_check（架构 / 分区剩余空间 <200MB 预警 / <30MB 中止 / 路径展示）；
#       补齐 nowhere_fix_perms / realm_fix_perms / caddy_fix_perms / cf_tunnel_fix_perms 并加固 snell/xray 权限
#       收敛（无组也强制 chmod、不跟随符号链接）；do_install_egress_service 补齐下载重试与共享端口防误删保护。
#     - 自动修复与二段自愈：新增 nowhere_repair / realm_repair / caddy_repair / cf_tunnel_repair 与全局
#       do_repair_all（adam repair / 自动维护菜单 17），升级 xray_repair 与 snell_repair；maint_watchdog 升级为
#       两段式自愈（常规重启失败 → 30min 冷却保护下执行对应组件自动修复 → 二次复验）；do_doctor 新增敏感文件
#       权限巡检与 Fail2ban SSH 端口漂移检测；cloudflared 纳入每日自动更新（菜单 18）。
#     - 深度 Bug 修复（16 项）：修复 check_port_occupied_by_other awk 引号拼错（BUG-01）、Caddy 128 位 SHA-512
#       校验误判（BUG-02）、geosite 404 与 .tmp 泄漏（BUG-03）、$RANDOM 子 shell 端口冲突（BUG-04）、Caddy 数据目录
#       0700 回退 0755（BUG-05）、cloudflared 缺自动更新（BUG-06）、CF Tunnel Token 尾空格被整串清空（BUG-07）、
#       Realm/Caddy 重建失败仍返回 0（BUG-08）、未安装残留目录引发幽灵端口冲突（BUG-09）、备份 umask 竞争与恢复
#       符号链接越界风险（BUG-10）、无用户组跳过 chmod（BUG-11）、Xray 修复/vlessenc/SNI 原子写（BUG-12）、Realm/Caddy/
#       IPv6 回滚与 env_file_safe（BUG-13）、Fail2ban 后端/UFW SSH 命名与多端口/tcp_port_conflict 逐行检测（BUG-14）、
#       XanMod/DNS 悬空软链/Nowhere 每日重启 pin 竞争（BUG-15）、port_used_by_other_services pipefail SIGPIPE 漏判（BUG-16）。
#     - 二轮全流程审校修复（R2-BUG-01..09）：统一 /etc/nowhere 0750 防低权用户 nowhere 读证书被锁死；
#       统一 /etc/adam-caddy 0750/0640 消除 doctor↔repair 死循环；env_file_safe / state_load 强化正则键名与尾部反斜杠
#       转义拦截防 root 命令注入；消除 realm_import_rules / certbot.timer / iptables / crontab 的 pipefail SIGPIPE 绕过；
#       修复 musl 下 ldd --version 退出码 1 误判 gnu；xray_uninstall 仅收回确实启用过的 80/tcp；state_save 与
#       write_cloudflare_creds 原子 umask 077；_upgrade_healthy_nowhere 校验端口监听并全量组件安装自动装定时器。
#   ── 脚本 v4.2 修订（2026-11-16）──
#     - 主菜单重排为两组八项：协议安装（1 Nowhere / 2 Snell / 3 Xray）与系统管理（4 脚本更新 / 5 防火墙 /
#       6 Fail2ban / 7 系统调优 / 8 自动维护）。原主菜单的 17 项 Nowhere 功能收进 Nowhere 子菜单并按
#       安装与配置 / 运行与排查 / 证书 / 版本分组；「重装快捷命令」移到脚本更新。上面修订说明里的
#       "菜单 17/18/19…" 是当时的编号。命令行子命令与 zt / pz / cxpz / cq 不变。
#   ── 脚本 v8.7 修订（2026-11-26：实网安装全流程验证与运维体验打磨）──
#     - 快捷命令自动就绪：新增 ensure_adam_shortcut，首次进入交互主菜单或通过任意组件（Snell / Xray /
#       Realm / Caddy / CF-Tunnel / Nowhere）安装后均自动安装 /usr/local/bin/adam，不再因未装 Nowhere
#       而出现 adam: command not found。
#     - Nowhere 探针与指纹优化：do_probe 支持命令行传参（adam probe [target] [--local]）与非交互默认目标，
#       在公网探测遇 NAT 无回流超时时自动回环自测 127.0.0.1 定位故障边界；get_tls_fingerprint 改为优先
#       按当前 PID 读 journalctl（零 tls connection failed 报错污染）并在父 shell 缓存指纹。
#     - 诊断与容器兼容优化：do_doctor 在容器 / hidepid 环境下自动按托管端口回退识别监听状态、精简 Xray/Nowhere
#       版本展示、修复 ufw 不可用时空白输出；_doctor_json 区分已装二进制但未配置单元为 unconfigured；
#       fw_status 在容器无 netfilter 时明确提示；xray/snell 健康检查对只读 ip_local_reserved_ports 容器降级为提示。
#     - 交互与展示细节：xray_add_ss 加密方式严格循环校验；xray_show_node 对 ~2600B ML-DSA-65 pqv 改为摘要展示并
#       为超长链接跳过不可扫二维码；修复主菜单中英文 Banner 框线错位并展示脚本版本号；修正英文界面空格与 Caddy
#       端口提示；xray fwd 统一 [::]:PORT 格式；Caddyfile 改用 Tab 缩进消除未格式化告警；手动 watchdog 给出健康反馈。
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
INSTALL_DRAFT_FILE="${CONFIG_DIR}/.install-draft.env"
VERSION_FILE="${CONFIG_DIR}/version.txt"
PREV_VERSION_FILE="${CONFIG_DIR}/version.previous.txt"
SERVICE_FILE="/etc/systemd/system/nowhere.service"
ACME_HOME="/root/.acme.sh"
MANAGER_PATH="/usr/local/bin/adam-nowhere-manager.sh"

DEFAULT_MORPH="1"
DEFAULT_VECTOR_SOCKS="127.0.0.1:1080"
DEFAULT_DIAL="auto"
SCRIPT_VERSION="8.7"   # 本管理脚本自身的修订版本（与 Nowhere 版本号相互独立）
TARGET_NW_VERSION="v3.3.0"   # 本脚本文案与向导所对照的 Nowhere 版本
MORPH_TCP_PRELUDE="fade"  # NOW_MORPH_TCP_PRELUDE：fade(v3.0.1起默认，v3.1.0不变)/full8/low7，仅影响本机发起的 Morph TCP 连接
TCP_FAMILY=""             # 监听地址族限制：""/4/6 -> tcp/tcp4/tcp6
UDP_FAMILY=""             # 同上 -> udp/udp4/udp6
EGRESS_DIAL="auto"        # Egress 端目标出站源地址（在出口机上生效）
EGRESS_DIAL_MODE="single"   # Egress dial 模式：single 用 dial=，dual 用 dial4=/dial6=，二选一
EGRESS_DIAL4="auto"       # Egress 端 IPv4 目标出站源地址
EGRESS_DIAL6="auto"       # Egress 端 IPv6 目标出站源地址
SCRIPT_URL="https://raw.githubusercontent.com/AdamWilliam69/nowhere-/main/nowhere-install.sh"
SCRIPT_SHA256_URL="${SCRIPT_URL}.sha256"
EGRESS_CONFIG_FILE="${CONFIG_DIR}/egress.env"
EGRESS_CONFIG_TXT="${CONFIG_DIR}/egress-config.txt"
TLS_PIN_FILE="${CONFIG_DIR}/tls-pin.txt"   # tls=1 当前指纹（每次重启都变），由 save_current_pin 维护
ROLE_FILE="${CONFIG_DIR}/role"   # 本机 nowhere.service 的角色：portal / egress
MORPH_UDP_PRELUDE="fade"  # NOW_MORPH_UDP_PRELUDE（v3.3.0 新增）：fade/full8/low7，仅 Morph QUIC 发起端使用
HANDSHAKE_TIMEOUT="auto"  # NOW_HANDSHAKE_TIMEOUT：v8.6 默认 auto（省略环境变量以启用 v3.3.0 官方按密钥派生 3s–30s）；也兼容自定义时长如 10s/500ms/1m/1h
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
NOTIFY_ENV="${MAINT_DIR}/notify.env"
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

