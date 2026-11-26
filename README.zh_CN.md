[English](/README.md) | [简体中文](/README.zh_CN.md)

# Adam VPS 一键管理脚本（v8.6）

[![CI — Build, Lint & Test](https://github.com/AdamWilliam69/nowhere-/actions/workflows/ci.yml/badge.svg)](https://github.com/AdamWilliam69/nowhere-/actions/workflows/ci.yml)

一个面向 Linux VPS 的一体化交互式管理脚本：在同一个菜单或命令行中安装、加固并维护 **Nowhere（v3.3.0 / NW3）**、**Snell v6**、**Xray（SS2022 / VLESS REALITY / XHTTP / dokodemo-door）**、**Realm 端口转发**、**域名反代（Caddy / Cloudflare Tunnel）**，并集成 UFW 防火墙、Fail2ban、系统网络调优、加密备份恢复、告警推送、多客户端导出与两段式自愈维护。

内置中英双语界面（`adam lang zh` / `adam lang en`，或 `ADAM_LANG=en adam`），自动化部署支持 `ADAM_ASSUME_YES=1`。

---

## 快速开始

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/AdamWilliam69/nowhere-/main/nowhere-install.sh)
```

> 请使用上面的 `bash <(...)` 写法，不要用 `curl ... | bash`：后者会把脚本内容当作键盘输入，交互向导无法正常工作。

安装完成后，脚本会把自己安装为 `/usr/local/bin/adam-nowhere-manager.sh`（快捷命令 `/usr/local/bin/adam`），之后直接输入：

```bash
adam
```

即可打开主菜单。

---

## 系统要求

| 项目 | 要求 |
| --- | --- |
| 系统 | Debian 11+ / Ubuntu 20.04+（`apt`）、RHEL / Rocky / Fedora（`dnf`/`yum`）、Alpine（`apk`），需 `systemd` |
| 架构 | `x86_64` / `arm64`（Snell、Xray 另支持 `i386`、`armv7l`） |
| 权限 | `root` |
| 网络 | 能访问 GitHub、`dl.nssurge.com`（安装与自动更新需要） |
| 可选 | Cloudflare API Token（DNS-01 证书 / Tunnel）；只读 `GITHUB_TOKEN`（将 GitHub API 限额从 60 次/时提升至 5000 次/时） |

XanMod 内核仅支持 `x86_64` 且不能在 LXC / OpenVZ 等容器类虚拟化中使用。

---

## v8.6 核心升级亮点

- **CSPRNG 随机引擎**：全量替换 `$RANDOM`，新增 `csprng_hex`、无偏拒绝采样 `csprng_int`、`csprng_alnum`（Python + 纯 awk 兜底）、`csprng_short_id`、`csprng_url_path`；`random_free_port` 避开 TCP/UDP 监听与全部已托管服务端口。
- **协议抗指纹与后量子进阶**：
  - **Xray**：REALITY 生成 2–3 条变长偶数位 `shortIds` + 随机 `spiderX` + `"maxTimeDiff": 60000` + **ML-DSA-65 后量子签名**（`mldsa65Seed` / `&pqv=`）+ PQ 安全 `uTLS` 指纹池（`chrome` / `firefox` / `safari`）+ 候选 SNI **TLS 1.3 + H2 握手 RTT 延迟择优**；XHTTP 随机化 `xPaddingBytes`（`&extra=`）与拟真多段路径；CDN 自签证书改用 ECDSA P-256 + 随机序列号 + 365–730 天随机有效期；新增**原地热轮换节点**（`adam xray edit`，支持换 SNI / 轮换 shortIds+spiderX / 换 fp / 换端口 / 轮换 XHTTP 路径与填充 / 生成或轮换 ML-DSA-65，重载失败自动回滚）。
  - **Snell v6**：PSK 升级为 CSPRNG 变长 32–48 位（`A-Za-z0-9_-`）。
  - **Nowhere v3.3.0**：`HANDSHAKE_TIMEOUT` 默认 `auto`（省略环境变量以启用官方按密钥派生 3–30s），仍兼容自定义时长。
  - **Realm**：WS/WSS 默认路径改用拟真多段随机路径。
- **供应链与运行期安全**：
  - 全量下载统一走 `secure_curl`（强制 HTTPS TLS ≥ 1.2）；可选只读 `GITHUB_TOKEN` 通过 `curl -K` 私有 fd 仅对 `https://api.github.com/*` 注入（不暴露于 `ps`、绝不泄露第三方域名）。
  - 官方 Release SHA-256/SHA-512 + 本机架构 ELF 头校验覆盖 Nowhere / Xray / Snell / Realm / Caddy / cloudflared；Xray 规则库强校验官方 `dlc.dat` + `.sha256sum`。
  - 管理脚本自更新强制校验 **[`nowhere-install.sh.sha256`](nowhere-install.sh.sha256)**（不匹配即拒绝替换，支持 `MAINT_SCRIPT_STRICT_SHA=1` 严格模式）。
  - 全部 6 个 systemd 服务单元统一启用沙箱加固（`NoNewPrivileges`、`PrivateDevices`、`ProtectKernelTunables`、`ProtectKernelModules`、`ProtectControlGroups`、`RestrictNamespaces`、`LockPersonality`、`RestrictSUIDSGID`）。
  - 备份支持可选 **AES-256-CBC (PBKDF2 600k iter)** 口令加密（`adam backup --encrypt` 生成 `.tgz.enc`，口令走 `fd:3` 不进命令行），`adam restore` 自动识别并解密恢复。
- **可观测性、自动自愈与多客户端导出**：
  - **两段式 Watchdog 自愈**：常规重启未恢复时自动执行对应服务的权限收敛/证书同步/配置重建/保留端口同步（30 分钟冷却防风暴）。
  - **运维告警推送（`adam notify`）**：支持 Telegram Bot / Bark / HTTPS Webhook，覆盖二段自愈、服务宕机、自动更新回滚、证书剩余 `<14` 天、Nowhere `tls=1` 指纹变动与脚本更新。
  - **NTP 时钟同步检查**（保障 REALITY `maxTimeDiff: 60000`）+ **`adam doctor --json`** 结构化巡检输出。
  - **多客户端配置一键导出（`adam export mihomo|singbox|surge`）**，内置 Mihomo REALITY 指纹兼容自动规范化。

---

## 主菜单

```
── 协议安装 ──
1) Nowhere     Portal / Egress：安装、配置、连接信息、证书、版本、一键修复
2) Snell v6    安装、多端口、跟随官方测试版自动更新、健康检查、一键修复
3) Xray        SS2022 / VLESS：REALITY Vision、XHTTP REALITY/TLS/CDN、VLESS Encryption、热编辑、端口转发
── 系统与转发 ──
4) 脚本更新    更新本脚本（SHA-256 校验）/ 重装快捷命令
5) 防火墙      ufw：安装、放行与删除端口、同步托管端口、启停
6) Fail2ban    SSH 防爆破：封禁时长、被封 IP、启停
7) 系统调优    TCP 调优（tcpfit）/ XanMod 内核 / DNS / IPv4·IPv6 优先级 / 禁用 IPv6
8) 自动维护    两段式保活 / 自动更新 / 加密备份恢复 / 诊断 / 全局修复 / 告警推送 / 客户端导出
9) Realm       TCP/UDP/WS/WSS 端口转发、批量建规、TOML 校验、导入导出、一键修复
10) 域名反代   Caddy 多域名自动 HTTPS 反代与 Cloudflare Tunnel
```

---

## 命令行用法

```bash
adam                         # 打开主菜单
adam help                    # 查看全部子命令
```

| 分类 | 示例 |
| --- | --- |
| Nowhere | `adam nowhere` · `adam install` · `adam config` · `adam status` · `adam update` · `adam rollback` · `adam probe` · `adam nowhere-repair` |
| Snell | `adam snell` · `adam snell install` · `adam snell add-port` · `adam snell del-port 30002` · `adam snell health` · `adam snell repair` |
| Xray | `adam xray` · `adam xray add` · `adam xray edit [tag]` · `adam xray links` · `adam xray health` · `adam xray repair` · `adam xray fwd` |
| Realm 与反代 | `adam realm` · `adam proxy` · `adam caddy` · `adam tunnel` |
| 防火墙与 Fail2ban | `adam fw allow 443/tcp,8000-8100` · `adam fw sync` · `adam f2b bantime 1h` · `adam f2b banned` |
| 系统调优 | `adam tune tcp` · `adam tune xanmod` · `adam tune dns set` · `adam tune prefer ipv4` · `adam tune ipv6 off` |
| 运维与维护 | `adam repair` · `adam doctor [--json]` · `adam notify` · `adam export mihomo\|singbox\|surge` · `adam backup [--encrypt]` · `adam restore <文件>` · `adam lang [zh\|en]` |

**Nowhere 快捷命令**：`zt`（状态）· `pz`（配置）· `cxpz`（重新配置）· `cq`（重启）

---

## 仓库目录结构与开发协作

本仓库采用**模块化源码 + 自动构建单文件发行版**结构，根目录保留构建产物 `nowhere-install.sh` 与 `nowhere-install.sh.sha256`，100% 兼容既有的一键安装与每日自动更新链接：

```text
.
├── nowhere-install.sh             # 构建产物：单文件发行版（由 scripts/build.sh 生成，勿手工直接编辑）
├── nowhere-install.sh.sha256      # 构建产物：官方 SHA-256 校验文件
├── src/
│   ├── 00-header.sh               # 版本元数据、全局变量、颜色与日志、语言加载
│   ├── 10-i18n/en.tsv             # 中英双语词典（构建期自动查重与查漏）
│   ├── 20-lib/                    # 核心基础、CSPRNG 与安全、UFW、Fail2ban、自动维护/备份/诊断/导出
│   ├── 30-modules/                # Nowhere、Snell、Xray、系统调优、Realm、Xray 转发、Caddy/CF Tunnel
│   └── 99-main.sh                 # usage()、主菜单与 CLI 分发
├── scripts/
│   ├── build.sh                   # 拼接 src/ -> nowhere-install.sh + .sha256（--check 供 CI 检测漂移）
│   └── lint.sh                    # 构建同步 + bash -n + 安全不变量 + 零警告 ShellCheck
├── tests/                         # 回归、安全权限、v8.6 增强与 8 组件全流程端到端测试套件
└── .github/workflows/ci.yml       # GitHub Actions 自动门禁
```

### 本地构建与验证

```bash
./scripts/build.sh                             # 从 src/ 构建 nowhere-install.sh 与 .sha256
./scripts/lint.sh                              # 校验构建同步、I18N、安全不变量与 0 警告 ShellCheck
for t in tests/test_*.sh; do bash "$t"; done   # 运行全部 5 套自动化测试
```

---

## 文件位置

| 路径 | 内容 |
| --- | --- |
| `/usr/local/bin/adam-nowhere-manager.sh` | 管理脚本本体 |
| `/etc/nowhere/` | Nowhere 配置、密钥、证书 |
| `/etc/snell/` | Snell 主配置；附加端口配置在 `ports/` 下 |
| `/opt/adam-xray/`、`/etc/adam-xray/` | 独立 Xray 二进制、节点配置、转发规则与证书 |
| `/etc/adam-realm/` | Realm 合并配置与规则元数据 |
| `/etc/adam-caddy/`、`/etc/adam-cloudflared/` | Caddy 反代站点与 Cloudflare Tunnel 配置 |
| `/etc/adam/` | 自动维护设置、告警推送配置（`notify.env`，`0600`）与调优原始配置备份 |
| `/var/log/adam-maintain.log` | 保活自愈与自动更新事件日志（`0600`） |

---

## 注意事项

- **REALITY 客户端兼容性**：较新的 Xray 版本要求客户端握手带 `X25519MLKEM768`（并支持可选 ML-DSA-65 `pqv` 验签），旧客户端可能超时。请使用较新的 Xray 内核客户端，或在安装 Xray 时固定旧版本。
- **NTP 时钟同步**：REALITY 已启用 `"maxTimeDiff": 60000`（容忍 ±60 秒偏差），请保持系统 NTP 同步（`adam doctor` 与 `adam xray health` 会自动检查）。
- **云厂商安全组**：脚本只管理本机 `ufw`，云厂商控制台的安全组需要自行放行端口。

---

## 致谢

本项目基于或参考了以下开源项目：

- [NodePassProject/Nowhere](https://github.com/NodePassProject/Nowhere) — Nowhere 协议
- [NodePassProject/Anywhere](https://github.com/NodePassProject/Anywhere) — Nowhere 客户端
- [chikacya/nowhere-sh](https://github.com/chikacya/nowhere-sh) — Nowhere 部署脚本
- [Surge Snell](https://kb.nssurge.com/surge-knowledge-base/release-notes/snell) — Snell 协议
- [XTLS/Xray-core](https://github.com/XTLS/Xray-core) — Xray 内核
- [zhboner/realm](https://github.com/zhboner/realm) — Realm 端口转发
- [caddyserver/caddy](https://github.com/caddyserver/caddy) & [cloudflare/cloudflared](https://github.com/cloudflare/cloudflared) — 域名反代与内网穿透
- [MHSanaei/3x-ui](https://github.com/MHSanaei/3x-ui) — 防火墙、Fail2ban 与 VLESS 入站的设计参考
- [Eric86777/vps-tcp-tune](https://github.com/Eric86777/vps-tcp-tune) — Snell 保活与系统调优的设计参考
- [Kylin010/tcpfit](https://github.com/Kylin010/tcpfit) — TCP 调优

## 许可证

[AGPL-3.0](LICENSE)

## 免责声明

本脚本仅供学习与合法用途，请遵守所在地区的法律法规。使用本脚本造成的任何后果由使用者自行承担。
