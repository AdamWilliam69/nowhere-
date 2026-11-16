[English](/README.md) | [简体中文](/README.zh_CN.md)

# Adam VPS 一键管理脚本

一个面向 Debian / Ubuntu VPS 的交互式管理脚本：在同一个菜单里安装和维护 **Nowhere**、**Snell v6**、**Xray（SS / VLESS）** 三类代理协议，并附带防火墙、Fail2ban、系统网络调优和自动维护（保活、自动更新）。

所有功能既可以在菜单里点选，也可以用 `adam <子命令>` 直接执行，方便写进自己的运维流程。

---

## 快速开始

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/AdamWilliam69/nowhere-/main/nowhere-install.sh)
```

> 请使用上面的 `bash <(...)` 写法，不要用 `curl ... | bash`：后者会把脚本内容当作键盘输入，交互向导无法正常工作。

安装完成后，脚本会把自己安装为 `/usr/local/bin/adam-nowhere-manager.sh`，之后直接输入：

```bash
adam
```

即可打开主菜单。

---

## 系统要求

| 项目 | 要求 |
| --- | --- |
| 系统 | Debian 11+ / Ubuntu 20.04+（依赖 `apt` 与 `systemd`） |
| 架构 | x86_64 / arm64（Snell、Xray 另支持 i386、armv7l） |
| 权限 | root |
| 网络 | 能访问 GitHub、`dl.nssurge.com`（安装与自动更新需要） |
| 可选 | 已托管在 Cloudflare 的域名 + API Token（Nowhere 使用 DNS 方式申请证书时需要） |

XanMod 内核仅支持 x86_64 且不能在 LXC / OpenVZ 等容器类虚拟化中使用。

---

## 主菜单

```
── 协议安装 ──
1) Nowhere     Portal / Egress：安装、配置、连接信息、证书、版本
2) Snell v6    安装、多端口、跟随官方测试版自动更新、健康检查
3) Xray        SS2022 / VLESS：REALITY Vision、XHTTP REALITY、XHTTP CDN、VLESS Encryption
── 系统管理 ──
4) 脚本更新    更新本脚本 / 重装快捷命令
5) 防火墙      ufw：安装、放行与删除端口、启停
6) Fail2ban    SSH 防爆破：封禁时长、被封 IP、启停
7) 系统调优    TCP 调优（tcpfit）/ XanMod 内核 / DNS / IPv4·IPv6 优先级 / 禁用 IPv6
8) 自动维护    保活巡检 / 脚本与内核自动更新
```

---

## 功能详情

### 1. Nowhere（适配 v3.3.0 / NW3）

基于 [NodePassProject/Nowhere](https://github.com/NodePassProject/Nowhere)。

- **Portal 安装向导**：自签证书、Let's Encrypt HTTP 验证、Cloudflare DNS 验证（certbot）、其他 DNS 服务商（acme.sh）多种证书方式；TCP / UDP / 混合监听，同端口或分端口
- **出口方式**：直连、SOCKS 上游、远程 Egress
- **Egress 出口机**：支持 QUIC 与 TLS（v3.3.0 新增）两种回连载体；可直接粘贴 Portal 生成的 `egress://` 连接串一键装成服务；同一 Portal 可接多台 Egress
- **连接信息**：自动生成 Anywhere 导入链接、Vector / Egress 启动命令与二维码
- **运维**：服务状态（含 `nowhere status`）、实时日志、连通性探测 `probe`、证书指纹、证书续期检查
- **版本管理**：更新到最新版、切换任意历史版本、一键回退上一版；下载包按 GitHub Release 的 SHA256 校验，新版本启动失败自动回滚
- **兼容提醒**：升级跨过 v3.2.0（强制认证 Prelude）、v3.3.0 时会提示对端需同步升级

### 2. Snell v6（Surge 官方）

- **一键安装**：从 Surge 官方发布页获取最新版本，二进制只从 `dl.nssurge.com` 下载
- **跟随测试版**：默认 beta 通道，自动跟随最新 b / rc 版，正式版发布后自动转正式版；也可切到只跟正式版的 stable 通道
- **自动发现新版本**：官方没有版本接口，脚本除读取发布页外，还按官方版本演进规律到下载站探测，发布页取不到时也能发现新版
- **多端口**：可新增多个端口配置，每个端口独立 PSK 与 mode；可删除任意一个端口配置（删主端口时由附加端口自动接替）
- **保活**：服务崩溃由 systemd 立即拉起；每 5 分钟巡检一次，进程退出或端口不在监听时自动重启；监听端口写入内核保留端口，避免被出站连接占用
- **健康检查 / 一键修复**：检查服务、监听、保留端口、防火墙、定时器与版本状态，发现问题可一键修复
- **安全升级**：新版本启动失败自动回滚到旧二进制
- **客户端配置**：直接输出可粘贴到 Surge `[Proxy]` 段的配置行

### 3. Xray（SS / VLESS）

基于 [XTLS/Xray-core](https://github.com/XTLS/Xray-core)，节点类型参考 [3x-ui](https://github.com/MHSanaei/3x-ui) 的入站设计。

| 节点类型 | 说明 |
| --- | --- |
| VLESS + REALITY + Vision | TCP 直连，最常用 |
| VLESS + XHTTP + REALITY | 直连，可叠加 VLESS Encryption |
| VLESS + XHTTP + CDN | 套 Cloudflare 等 CDN，支持 TLS 回源（自签或已有证书）与明文回源 |
| VLESS Encryption + XHTTP | ML-KEM-768（抗量子）或 X25519，不依赖 TLS |
| Shadowsocks 2022 | blake3-aes-128/256-gcm、chacha20-poly1305，TCP + UDP |

- **多节点**：每个节点独立一份配置，可随时增删；每次改动先用 `xray run -test` 校验，校验不过自动撤回
- **跟随官方最新版**：默认跟随最新发布（含预发布），也可只跟正式版或固定某个版本
- **安全升级**：按官方 `.dgst` 校验 SHA256；新内核先校验现有配置，不兼容就不替换；启动失败自动回滚
- **完全隔离**：独立目录（`/opt/adam-xray`、`/etc/adam-xray`）和独立服务（`adam-xray`），不影响官方脚本或 3x-ui 安装的 Xray
- **分享链接**：自动生成 `vless://`、`ss://` 链接与二维码

### 4. 脚本更新

- 从仓库拉取最新脚本，校验完整性与语法后再替换，并保留旧版备份
- 可开启每日自动从仓库更新（版本号不低于本地才替换，不会降级）
- 重装快捷命令

### 5. 防火墙（ufw）

菜单结构参考 3x-ui 的 Firewall Management：

- 安装 / 启用 / 停用，启用前自动放行 SSH 端口，防止把自己锁在外面
- 放行或删除端口，支持 `80,443`、`400-500`、`443/tcp`、`51820/udp` 等写法
- 按编号删除时从大到小删，避免编号前移删错规则；删除 SSH 端口前会二次确认
- 启用前列出正在监听但尚未放行的端口
- 一键放行本脚本管理的全部服务端口（SSH / Nowhere / Snell / Xray）

### 6. Fail2ban

菜单结构参考 3x-ui 的 IP Limit Management，防护对象为 SSH 爆破：

- 修改封禁时长（`30`=30 分钟、`1h`、`1d`、`-1`=永久）、失败次数与统计窗口
- 查看被封 IP 与封禁日志，手动封禁 / 解封，一键解封全部
- 白名单管理；安装时可自动把当前登录 IP 加入白名单
- 配置只写在 `jail.d/adam-sshd.local`，不改动系统自带的 jail 配置
- 自动适配没有 `/var/log/auth.log` 的系统（改用 systemd journal）

### 7. 系统调优

- **TCP 调优**：调用 [Kylin010/tcpfit](https://github.com/Kylin010/tcpfit)，按本机实测结果推导缓冲区、BBR / fq、限速器拐点等参数，所有改动可回滚
- **XanMod 内核**：自动识别 CPU 指令集等级（x86-64-v1 ~ v4）安装对应内核，内置 BBR v3；卸载前确认系统中还有其他可启动的内核
- **DNS**：Cloudflare / Google / Quad9 预设或自定义，可选 DNS over TLS；自动适配 systemd-resolved
- **IPv4 / IPv6 优先级**：通过 `/etc/gai.conf` 调整，不关闭任何协议栈
- **禁用 IPv6**：临时（重启恢复）或永久，禁用后自动调整 Snell、Xray 的监听地址

以上每一项都会备份原始配置，可一键恢复。

### 8. 自动维护

| 任务 | 频率 | 内容 |
| --- | --- | --- |
| 保活巡检 | 每 5 分钟 | Snell（含所有附加端口）、Xray、Nowhere 未运行或端口未监听时自动重启 |
| 每日维护 | 每天凌晨 | 脚本从仓库自更新 → Snell / Xray 跟随官方更新 → 证书同步 → 可选每日重启 |

每一项都可以单独开关；事件记录在 `/var/log/adam-maintain.log`。手动停用（`systemctl disable`）的服务不会被保活拉起。

---

## 命令行用法

```bash
adam                         # 打开主菜单
adam help                    # 查看全部子命令
```

| 分类 | 示例 |
| --- | --- |
| Nowhere | `adam nowhere` · `adam install` · `adam config` · `adam status` · `adam update` · `adam rollback` · `adam probe` |
| Snell | `adam snell` · `adam snell install` · `adam snell add-port` · `adam snell del-port 30002` · `adam snell health` · `adam snell update` |
| Xray | `adam xray` · `adam xray add` · `adam xray links` · `adam xray delete` · `adam xray health` · `adam xray update` |
| 防火墙 | `adam fw allow 443/tcp,8000-8100` · `adam fw deny 8080` · `adam fw list` · `adam fw on` / `off` |
| Fail2ban | `adam f2b bantime 1h` · `adam f2b banned` · `adam f2b ban 1.2.3.4` · `adam f2b unban-all` |
| 系统调优 | `adam tune tcp` · `adam tune xanmod` · `adam tune dns set` · `adam tune prefer ipv4` · `adam tune ipv6 off` |
| 维护 | `adam auto` · `adam maintain` · `adam watchdog` · `adam maintain-log` · `adam update-script` |

**Nowhere 快捷命令**

| 命令 | 作用 |
| --- | --- |
| `zt` | 查看服务状态 |
| `pz` | 查看连接信息 |
| `cxpz` | 重新配置 |
| `cq` | 重启服务 |

---

## 文件位置

| 路径 | 内容 |
| --- | --- |
| `/usr/local/bin/adam-nowhere-manager.sh` | 管理脚本本体 |
| `/etc/nowhere/` | Nowhere 配置、密钥、证书 |
| `/etc/snell/` | Snell 主配置；附加端口配置在 `ports/` 下 |
| `/opt/adam-xray/`、`/etc/adam-xray/` | Xray 二进制；节点配置与证书 |
| `/etc/adam/` | 自动维护设置与各项调优的原始配置备份 |
| `/var/log/adam-maintain.log` | 保活与自动更新记录 |

---

## 注意事项

- **REALITY 客户端兼容性**：较新的 Xray 版本要求客户端握手带 X25519MLKEM768，旧客户端会表现为超时。请使用较新的 Xray 内核客户端；客户端跟不上时，可在安装 Xray 时选择"指定版本"固定在旧版本。
- **Snell 测试版**：beta 通道安装的是官方测试版，协议在正式版前仍可能变化，客户端需使用支持对应版本的 Surge。
- **更换内核有风险**：安装 XanMod 前请确认服务商面板有 VNC 或救援模式。
- **云厂商安全组**：脚本只管理本机 ufw，云厂商控制台的安全组需要自行放行端口。
- 建议先在测试机上熟悉各项功能，再用于生产环境。

---

## 致谢

本项目基于或参考了以下开源项目：

- [NodePassProject/Nowhere](https://github.com/NodePassProject/Nowhere) — Nowhere 协议
- [NodePassProject/Anywhere](https://github.com/NodePassProject/Anywhere) — Nowhere 客户端
- [chikacya/nowhere-sh](https://github.com/chikacya/nowhere-sh) — Nowhere 部署脚本
- [Surge Snell](https://kb.nssurge.com/surge-knowledge-base/release-notes/snell) — Snell 协议
- [XTLS/Xray-core](https://github.com/XTLS/Xray-core) — Xray 内核
- [MHSanaei/3x-ui](https://github.com/MHSanaei/3x-ui) — 防火墙、Fail2ban 与 VLESS 入站的设计参考
- [Eric86777/vps-tcp-tune](https://github.com/Eric86777/vps-tcp-tune) — Snell 保活与系统调优的设计参考
- [Kylin010/tcpfit](https://github.com/Kylin010/tcpfit) — TCP 调优

## 许可证

[AGPL-3.0](LICENSE)

## 免责声明

本脚本仅供学习与合法用途，请遵守所在地区的法律法规。使用本脚本造成的任何后果由使用者自行承担。
