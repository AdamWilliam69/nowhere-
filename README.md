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
- Linux VPS (Ubuntu 20+/Debian 11+recommended)

## Installation

```bash
wget -O nowhere-install.sh https://raw.githubusercontent.com/AdamWilliam69/nowhere-/main/nowhere-install.sh && chmod +x nowhere-install.sh && bash nowhere-install.sh

## Upstream Projects

Nowhere: https://github.com/NodePassProject/Nowhere
Anywhere: https://github.com/NodePassProject/Anywhere
VPS.sh：
https://github.com/chikacya/nowhere-sh
