[English](/README.md) | [简体中文](/README.zh_CN.md)

# Adam VPS Manager

An interactive management script for Debian / Ubuntu VPS. From a single menu it installs and maintains three proxy protocols — **Nowhere**, **Snell v6** and **Xray (SS / VLESS)** — together with a firewall, Fail2ban, system and network tuning, and automatic maintenance (keep-alive and auto-update).

Every feature can be used from the menu or run directly as `adam <subcommand>`, so it fits into your own scripts and routines.

> The script's interactive interface is in Simplified Chinese. Menu items are translated below for reference.

---

## Quick Start

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/AdamWilliam69/nowhere-/main/nowhere-install.sh)
```

> Use the `bash <(...)` form above, not `curl ... | bash`. With a pipe, the script's own text is fed in as keyboard input and the interactive wizards break.

After installation the script installs itself as `/usr/local/bin/adam-nowhere-manager.sh`. From then on, just run:

```bash
adam
```

to open the main menu.

---

## Requirements

| Item | Requirement |
| --- | --- |
| OS | Debian 11+ / Ubuntu 20.04+ (needs `apt` and `systemd`) |
| Architecture | x86_64 / arm64 (Snell and Xray also support i386 and armv7l) |
| Privileges | root |
| Network | Access to GitHub and `dl.nssurge.com` (for installation and auto-updates) |
| Optional | A domain on Cloudflare plus an API token (when Nowhere requests certificates via DNS) |

The XanMod kernel is x86_64 only and cannot be used in container-based virtualization such as LXC or OpenVZ.

---

## Main Menu

```
── Protocols ──
1) Nowhere     Portal / Egress: install, configure, connection info, certificates, versions
2) Snell v6    Install, multiple ports, follow official betas, health check
3) Xray        SS2022 / VLESS: REALITY Vision, XHTTP REALITY, XHTTP CDN, VLESS Encryption
── System ──
4) Script      Update this script / reinstall shortcuts
5) Firewall    ufw: install, allow and remove ports, enable / disable
6) Fail2ban    SSH brute-force protection: ban time, banned IPs, enable / disable
7) Tuning      TCP tuning (tcpfit) / XanMod kernel / DNS / IPv4·IPv6 priority / disable IPv6
8) Maintenance Keep-alive watchdog / automatic script and core updates
```

---

## Features

### 1. Nowhere (for v3.3.0 / NW3)

Built on [NodePassProject/Nowhere](https://github.com/NodePassProject/Nowhere).

- **Portal setup wizard**: self-signed certificates, Let's Encrypt via HTTP challenge, Cloudflare DNS challenge (certbot), or other DNS providers (acme.sh); TCP, UDP or mixed listeners, on one port or separate ports
- **Outbound modes**: direct, upstream SOCKS, or remote Egress
- **Egress exit nodes**: QUIC and TLS (new in v3.3.0) callback carriers; paste the `egress://` string generated on the Portal to install it as a service in one step; one Portal can serve several Egress nodes
- **Connection info**: generates Anywhere import links, Vector / Egress launch commands and QR codes
- **Operations**: service status (including `nowhere status`), live logs, `probe` connectivity tests, certificate fingerprints, certificate renewal checks
- **Version management**: update to the latest release, switch to any past release, or roll back to the previous one; downloads are verified against the GitHub Release SHA256, and a new version that fails to start is rolled back automatically
- **Compatibility warnings**: when an upgrade crosses v3.2.0 (mandatory authenticated Prelude) or v3.3.0, the script reminds you to upgrade peers as well

### 2. Snell v6 (official Surge server)

- **One-step install**: finds the latest version from the official Surge release notes; binaries are downloaded only from `dl.nssurge.com`
- **Follows betas**: the default beta channel tracks the latest b / rc builds and moves to the stable release once it ships; switch to the stable channel to follow stable releases only
- **Finds new versions on its own**: Surge has no version API, so besides reading the release notes the script probes the download server following Surge's version numbering, which still works when the release page is unreachable
- **Multiple ports**: add extra port configurations, each with its own PSK and mode; delete any one of them (when the main port is deleted, an extra port takes over as the main configuration)
- **Keep-alive**: systemd restarts the service immediately if it crashes; a watchdog checks every 5 minutes and restarts any instance that has exited or stopped listening; listening ports are added to the kernel's reserved ports so outbound connections cannot take them
- **Health check / one-step repair**: checks the service, listeners, reserved ports, firewall, timers and version, and repairs what it finds
- **Safe upgrades**: if a new version fails to start, the previous binary is restored automatically
- **Client config**: prints a line ready to paste into the `[Proxy]` section of Surge

### 3. Xray (SS / VLESS)

Built on [XTLS/Xray-core](https://github.com/XTLS/Xray-core). Node types follow the inbound design of [3x-ui](https://github.com/MHSanaei/3x-ui).

| Node type | Notes |
| --- | --- |
| VLESS + REALITY + Vision | Direct TCP; the most common choice |
| VLESS + XHTTP + REALITY | Direct; VLESS Encryption can be layered on top |
| VLESS + XHTTP + CDN | Behind Cloudflare or another CDN; TLS origin (self-signed or your own certificate) or plain-HTTP origin |
| VLESS Encryption + XHTTP | ML-KEM-768 (post-quantum) or X25519; no TLS needed |
| Shadowsocks 2022 | blake3-aes-128/256-gcm, chacha20-poly1305; TCP + UDP |

- **Multiple nodes**: each node has its own config file and can be added or removed at any time; every change is checked with `xray run -test` first and reverted if the check fails
- **Follows the latest official release**: by default tracks the newest release including pre-releases; can also follow stable releases only or pin a specific version
- **Safe upgrades**: SHA256 is verified against the official `.dgst`; the new core must validate the existing config before it replaces the old one; if it fails to start, it is rolled back automatically
- **Fully isolated**: its own directories (`/opt/adam-xray`, `/etc/adam-xray`) and its own service (`adam-xray`); it does not touch Xray installed by the official script or by 3x-ui
- **Share links**: generates `vless://` and `ss://` links and QR codes

### 4. Script updates

- Downloads the latest script from this repository, checks it is complete and syntactically valid before replacing the current one, and keeps a backup
- Optional daily auto-update from the repository (only replaces when the remote version is not lower than the local one, so it never downgrades)
- Reinstall the shortcut commands

### 5. Firewall (ufw)

Menu layout follows the Firewall Management menu of 3x-ui:

- Install, enable and disable; the SSH port is allowed automatically before enabling so you cannot lock yourself out
- Allow or remove ports, using forms such as `80,443`, `400-500`, `443/tcp` and `51820/udp`
- Rules removed by number are deleted from the highest number down, so shifting numbers never remove the wrong rule; removing the SSH port asks for confirmation
- Before enabling, lists ports that are listening but not yet allowed
- Allow every port managed by this script (SSH / Nowhere / Snell / Xray) in one step

### 6. Fail2ban

Menu layout follows the IP Limit Management menu of 3x-ui, protecting SSH against brute force:

- Change the ban time (`30` = 30 minutes, `1h`, `1d`, `-1` = permanent), the number of failures and the time window
- View banned IPs and the ban log, ban / unban manually, unban everyone at once
- Whitelist management; the IP you are logged in from can be whitelisted during installation
- Configuration is written only to `jail.d/adam-sshd.local`; the system's own jail files are left untouched
- Works on systems without `/var/log/auth.log` by switching to the systemd journal

### 7. System tuning

- **TCP tuning**: runs [Kylin010/tcpfit](https://github.com/Kylin010/tcpfit), which derives buffer sizes, BBR / fq, rate-limiter knee points and more from measurements on your own machine; every change can be rolled back
- **XanMod kernel**: detects the CPU instruction level (x86-64-v1 to v4) and installs the matching kernel with BBR v3; before removal it checks that another bootable kernel is installed
- **DNS**: Cloudflare / Google / Quad9 presets or custom servers, with optional DNS over TLS; works with systemd-resolved
- **IPv4 / IPv6 priority**: set through `/etc/gai.conf` without turning either protocol off
- **Disable IPv6**: temporarily (until reboot) or permanently; Snell and Xray listening addresses are adjusted automatically

Each of these backs up the original configuration and can be restored in one step.

### 8. Automatic maintenance

| Task | Schedule | What it does |
| --- | --- | --- |
| Keep-alive watchdog | Every 5 minutes | Restarts Snell (including all extra ports), Xray or Nowhere if it is not running or not listening |
| Daily maintenance | Early morning, daily | Script self-update from the repository → Snell / Xray updates from upstream → certificate sync → optional daily restart |

Each task can be switched on or off separately; events are logged to `/var/log/adam-maintain.log`. Services you disable yourself (`systemctl disable`) are not restarted by the watchdog.

---

## Command-line usage

```bash
adam                         # open the main menu
adam help                    # list every subcommand
```

| Area | Examples |
| --- | --- |
| Nowhere | `adam nowhere` · `adam install` · `adam config` · `adam status` · `adam update` · `adam rollback` · `adam probe` |
| Snell | `adam snell` · `adam snell install` · `adam snell add-port` · `adam snell del-port 30002` · `adam snell health` · `adam snell update` |
| Xray | `adam xray` · `adam xray add` · `adam xray links` · `adam xray delete` · `adam xray health` · `adam xray update` |
| Firewall | `adam fw allow 443/tcp,8000-8100` · `adam fw deny 8080` · `adam fw list` · `adam fw on` / `off` |
| Fail2ban | `adam f2b bantime 1h` · `adam f2b banned` · `adam f2b ban 1.2.3.4` · `adam f2b unban-all` |
| Tuning | `adam tune tcp` · `adam tune xanmod` · `adam tune dns set` · `adam tune prefer ipv4` · `adam tune ipv6 off` |
| Maintenance | `adam auto` · `adam maintain` · `adam watchdog` · `adam maintain-log` · `adam update-script` |

**Nowhere shortcuts**

| Command | Action |
| --- | --- |
| `zt` | Show service status |
| `pz` | Show connection info |
| `cxpz` | Reconfigure |
| `cq` | Restart the service |

---

## File locations

| Path | Contents |
| --- | --- |
| `/usr/local/bin/adam-nowhere-manager.sh` | The management script |
| `/etc/nowhere/` | Nowhere configuration, keys and certificates |
| `/etc/snell/` | Snell main configuration; extra ports under `ports/` |
| `/opt/adam-xray/`, `/etc/adam-xray/` | Xray binary; node configs and certificates |
| `/etc/adam/` | Maintenance settings and backups of original configs changed by tuning |
| `/var/log/adam-maintain.log` | Keep-alive and auto-update log |

---

## Notes

- **REALITY client compatibility**: recent Xray versions require clients to offer X25519MLKEM768 in the handshake; older clients simply time out. Use a recent Xray-core based client. If your client cannot keep up, choose "pin a version" when installing Xray to stay on an older release.
- **Snell betas**: the beta channel installs official test builds. The protocol may still change before the stable release, and clients need a Surge build that supports that version.
- **Changing kernels carries risk**: before installing XanMod, make sure your provider offers VNC or a rescue mode.
- **Cloud security groups**: the script manages only the local ufw. Open ports in your provider's security group yourself.
- Try the features on a test machine before using them in production.

---

## Acknowledgements

This project builds on or takes ideas from:

- [NodePassProject/Nowhere](https://github.com/NodePassProject/Nowhere) — the Nowhere protocol
- [NodePassProject/Anywhere](https://github.com/NodePassProject/Anywhere) — Nowhere client
- [chikacya/nowhere-sh](https://github.com/chikacya/nowhere-sh) — Nowhere deployment script
- [Surge Snell](https://kb.nssurge.com/surge-knowledge-base/release-notes/snell) — the Snell protocol
- [XTLS/Xray-core](https://github.com/XTLS/Xray-core) — the Xray core
- [MHSanaei/3x-ui](https://github.com/MHSanaei/3x-ui) — design reference for the firewall, Fail2ban and VLESS inbounds
- [Eric86777/vps-tcp-tune](https://github.com/Eric86777/vps-tcp-tune) — design reference for Snell keep-alive and system tuning
- [Kylin010/tcpfit](https://github.com/Kylin010/tcpfit) — TCP tuning

## License

[AGPL-3.0](LICENSE)

## Disclaimer

This script is intended for learning and lawful use only. Please comply with the laws and regulations where you live. You are solely responsible for any consequences of using it.
