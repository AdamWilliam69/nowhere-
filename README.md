[English](/README.md) | [简体中文](/README.zh_CN.md)

# Adam VPS Manager (v8.7)

[![CI — Build, Lint & Test](https://github.com/AdamWilliam69/nowhere-/actions/workflows/ci.yml/badge.svg)](https://github.com/AdamWilliam69/nowhere-/actions/workflows/ci.yml)

An all-in-one interactive VPS management script for Linux. From a single menu (or direct CLI subcommands) it installs, hardens, and maintains **Nowhere (NW3)**, **Snell v6**, **Xray (SS2022 / VLESS REALITY / XHTTP / dokodemo-door)**, **Realm**, and **Domain Reverse Proxy (Caddy / Cloudflare Tunnel)** — together with UFW firewall, Fail2ban, system & network tuning, encrypted backup/restore, alert notifications, multi-client config export, and two-stage self-healing maintenance.

The interactive UI supports both **Simplified Chinese** and **English** (`adam lang zh` / `adam lang en`, or `ADAM_LANG=en adam`).

---

## Quick Start

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/AdamWilliam69/nowhere-/main/nowhere-install.sh)
```

> Use the `bash <(...)` form above, not `curl ... | bash`. With a pipe, the script's own text is fed in as keyboard input and the interactive wizards break.

On first run (or after installing any component), the script automatically installs itself as `/usr/local/bin/adam-nowhere-manager.sh` (with shortcut `/usr/local/bin/adam`). From then on, run:

```bash
adam
```

For unattended automation / provisioning, set `ADAM_ASSUME_YES=1`.

---

## Requirements

| Item | Requirement |
| --- | --- |
| OS | Debian 11+ / Ubuntu 20.04+ (`apt`), RHEL / Rocky / Fedora (`dnf`/`yum`), or Alpine (`apk`) with `systemd` |
| Architecture | `x86_64` / `arm64` (Snell and Xray also support `i386` and `armv7l`) |
| Privileges | `root` |
| Network | HTTPS access to GitHub and `dl.nssurge.com` (for installation & auto-updates) |
| Optional | Cloudflare API Token (for DNS-01 certificates / Tunnel), read-only `GITHUB_TOKEN` (raises GitHub API limit from 60/hr to 5000/hr) |

The XanMod kernel is `x86_64` only and cannot be used in container-based virtualization such as LXC or OpenVZ.

---

## What's New in v8.7

- **Seamless First-Run & Multi-Component Experience**:
  - Automatic `/usr/local/bin/adam` shortcut bootstrap on first interactive menu launch and across every component installer (Snell, Xray, Realm, Caddy, Cloudflare Tunnel, Nowhere).
  - Enhanced `adam probe [target] [--local]` with CLI arguments, non-TTY defaults, and automatic loopback (`127.0.0.1`) diagnosis when cloud NAT lacks hairpinning; journal-first TLS fingerprint lookup eliminates spurious `tls connection failed` log noise.
  - Container / `hidepid` resilient diagnostics: `adam doctor` falls back to managed-port matching when `ss -p` hides process names, formats concise versions, reports restricted `ufw` clearly, and distinguishes `unconfigured` vs `not-installed` in `--json`; `xray`/`snell` health checks downgrade read-only `ip_local_reserved_ports` cleanly.
  - Strict cipher validation in `xray_add_ss`, compact ML-DSA-65 `pqv` summary & QR length guard (`>1200` chars), tab-formatted Caddyfile (0 Caddy format warnings), bracketed `[::]:PORT` Xray forward display, aligned bilingual menu banner with script version, and interactive `adam watchdog` summary.
- **v8.6 Core Architecture (Included)**:
  - **CSPRNG Engine**: Cryptographic randomness across keys, ports, shortIds, paths, and Snell 32–48 char PSKs.
  - **Protocol Anti-Fingerprinting & Post-Quantum**: Xray REALITY multi-shortIds, CSPRNG `spiderX`, `maxTimeDiff: 60000`, ML-DSA-65 (`&pqv=`), RTT latency-ranked SNI selection, XHTTP `xPaddingBytes`, ECDSA P-256 self-signed certs, and `adam xray edit` hot-rotation; Nowhere `HANDSHAKE_TIMEOUT=auto`.
  - **Supply-Chain & Runtime Security**: `secure_curl` (HTTPS TLS ≥ 1.2), official SHA-256/SHA-512 + native ELF verification (minified GitHub JSON & `mawk` compatible), systemd 8-directive sandbox hardening, `.sha256`-verified self-update, and AES-256-CBC (PBKDF2 600k) encrypted backups.
  - **Observability & Self-Healing**: Two-stage Watchdog self-healing (30-min cooldown), `adam notify` (Telegram/Bark/Webhook), NTP sync check, `adam doctor --json`, and `adam export mihomo|singbox|surge`.

---

## Main Menu

```
── Protocols ──
1) Nowhere     Portal / Egress: install, configure, connection info, certificates, versions, repair
2) Snell v6    Install, multiple ports, follow official betas, health check, repair
3) Xray        SS2022 / VLESS: REALITY Vision, XHTTP REALITY/TLS/CDN, VLESS Encryption, hot-edit, dokodemo-door
── System & Forwarding ──
4) Script      Update this script (SHA-256 verified) / reinstall shortcuts
5) Firewall    ufw: install, allow and remove ports, sync managed ports, enable / disable
6) Fail2ban    SSH brute-force protection: ban time, banned IPs, enable / disable
7) Tuning      TCP tuning (tcpfit) / XanMod kernel / DNS / IPv4·IPv6 priority / disable IPv6
8) Maintenance Two-stage watchdog / auto-updates / encrypted backup & restore / doctor / repair-all / notify / export
9) Realm       TCP/UDP/WS/WSS port forwarding, batch rules, TOML validation, export/import, repair
10) Proxy      Domain reverse proxy (Caddy auto-HTTPS multi-site & Cloudflare Tunnel)
```

---

## Command-line Usage

```bash
adam                         # open the main menu
adam help                    # list every subcommand
```

| Area | Examples |
| --- | --- |
| Nowhere | `adam nowhere` · `adam install` · `adam config` · `adam status` · `adam update` · `adam rollback` · `adam probe` · `adam nowhere-repair` |
| Snell | `adam snell` · `adam snell install` · `adam snell add-port` · `adam snell del-port 30002` · `adam snell health` · `adam snell repair` |
| Xray | `adam xray` · `adam xray add` · `adam xray edit [tag]` · `adam xray links` · `adam xray health` · `adam xray repair` · `adam xray fwd` |
| Realm & Proxy | `adam realm` · `adam proxy` · `adam caddy` · `adam tunnel` |
| Firewall & Fail2ban | `adam fw allow 443/tcp,8000-8100` · `adam fw sync` · `adam f2b bantime 1h` · `adam f2b banned` |
| Tuning | `adam tune tcp` · `adam tune xanmod` · `adam tune dns set` · `adam tune prefer ipv4` · `adam tune ipv6 off` |
| Ops & Maintenance | `adam repair` · `adam doctor [--json]` · `adam notify` · `adam export mihomo\|singbox\|surge` · `adam backup [--encrypt]` · `adam restore <file>` · `adam lang [zh\|en]` |

**Nowhere shortcuts**: `zt` (status) · `pz` (config) · `cxpz` (reconfigure) · `cq` (restart)

---

## Repository Structure & Development

This repository keeps modular source files under `src/` and assembles the single-file release artifact `nowhere-install.sh` + `nowhere-install.sh.sha256` at the repository root via `scripts/build.sh`, preserving full compatibility with one-line `curl` installation and self-updates.

```text
.
├── nowhere-install.sh             # Built single-file release (generated by scripts/build.sh — do not edit directly)
├── nowhere-install.sh.sha256      # Official SHA-256 checksum for script self-update verification
├── src/
│   ├── 00-header.sh               # Version metadata, globals, logging, language loader
│   ├── 10-i18n/en.tsv             # Bilingual zh->en dictionary (auto-validated at build time)
│   ├── 20-lib/                    # Core utils, CSPRNG & security, UFW, Fail2ban, maintenance/ops
│   ├── 30-modules/                # Nowhere, Snell, Xray, Tuning, Realm, Xray-Fwd, Caddy/CF-Tunnel
│   └── 99-main.sh                 # usage(), interactive menu, CLI dispatcher
├── scripts/
│   ├── build.sh                   # Assemble src/ -> nowhere-install.sh + .sha256 (--check for CI)
│   └── lint.sh                    # Build sync + bash -n + security invariants + zero-warning ShellCheck
├── tests/                         # Regression, Round-2 security, enhancement, and 8-flow E2E test suites
└── .github/workflows/ci.yml       # GitHub Actions CI gate
```

### Build, Lint & Test Locally

```bash
./scripts/build.sh                             # rebuild nowhere-install.sh & .sha256 from src/
./scripts/lint.sh                              # verify build sync, I18N, security invariants, 0-warning ShellCheck
for t in tests/test_*.sh; do bash "$t"; done   # run all 6 automated test suites
```

---

## File Locations

| Path | Contents |
| --- | --- |
| `/usr/local/bin/adam-nowhere-manager.sh` | Management script binary |
| `/etc/nowhere/` | Nowhere configuration, keys, and certificates |
| `/etc/snell/` | Snell main configuration; extra ports under `ports/` |
| `/opt/adam-xray/`, `/etc/adam-xray/` | Isolated Xray binary, node configs, forwards, and certificates |
| `/etc/adam-realm/` | Realm merged TOML config and per-rule metadata |
| `/etc/adam-caddy/`, `/etc/adam-cloudflared/` | Caddy reverse proxy sites and Cloudflare Tunnel env |
| `/etc/adam/` | Maintenance config, alert notification config (`notify.env`, `0600`), tuning backups |
| `/var/log/adam-maintain.log` | Watchdog self-heal and auto-update event log (`0600`) |

---

## Notes

- **REALITY client compatibility**: Recent Xray versions require clients to offer `X25519MLKEM768` in the handshake (and optional ML-DSA-65 `pqv` verification); older clients may time out. Use a modern Xray-core client or pin an older version during Xray installation.
- **NTP Clock Sync**: REALITY enforces `"maxTimeDiff": 60000` (±60s). Keep NTP enabled (`adam doctor` and `adam xray health` verify clock sync automatically).
- **Cloud security groups**: The script manages local `ufw` only; open ports in your cloud provider's security group separately.

---

## Acknowledgements

This project builds on or takes ideas from:

- [NodePassProject/Nowhere](https://github.com/NodePassProject/Nowhere) — Nowhere protocol
- [NodePassProject/Anywhere](https://github.com/NodePassProject/Anywhere) — Nowhere client
- [chikacya/nowhere-sh](https://github.com/chikacya/nowhere-sh) — Nowhere deployment script
- [Surge Snell](https://kb.nssurge.com/surge-knowledge-base/release-notes/snell) — Snell protocol
- [XTLS/Xray-core](https://github.com/XTLS/Xray-core) — Xray core
- [zhboner/realm](https://github.com/zhboner/realm) — Realm forwarder
- [caddyserver/caddy](https://github.com/caddyserver/caddy) & [cloudflare/cloudflared](https://github.com/cloudflare/cloudflared) — Reverse proxy & Tunnel
- [MHSanaei/3x-ui](https://github.com/MHSanaei/3x-ui) — Design reference for firewall, Fail2ban, and VLESS inbounds
- [Eric86777/vps-tcp-tune](https://github.com/Eric86777/vps-tcp-tune) — Design reference for Snell keep-alive and system tuning
- [Kylin010/tcpfit](https://github.com/Kylin010/tcpfit) — TCP tuning

## License

[AGPL-3.0](LICENSE)

## Disclaimer

This script is intended for learning and lawful use only. Please comply with the laws and regulations where you live. You are solely responsible for any consequences of using it.
