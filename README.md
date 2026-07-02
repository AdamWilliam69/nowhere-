## Installation
curl -fsSL https://raw.githubusercontent.com/AdamWilliam69/nowhere-/main/nowhere-install.sh | bash

bash nowhere-install.sh

查看状态 : systemctl status nowhere

查看日志 : journalctl -u nowhere -f

重启服务 : systemctl restart nowhere

查看配置 : cat /etc/nowhere/config.txt

# Nowhere Portal Installer

A simple one-click installer for automatic TLS certificate setup and deployment of the Nowhere service.

## Features

- One-click deployment script
- Automatic SSL certificate via Cloudflare DNS API
- Systemd service management
- Minimal configuration required

## Requirements

- A domain managed by Cloudflare
- Cloudflare API Token with DNS edit permission
- Linux VPS (Ubuntu/Debian recommended)

