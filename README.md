## Installation

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/AdamWilliam69/nowhere-/main/nowhere-install.sh)

📖 Description

A simple one-click installer for automatic TLS certificate setup and deployment of the Nowhere service.

This project helps users quickly deploy a server with:

* Automatic SSL certificate (Cloudflare DNS API)
* Systemd service management
* Minimal configuration setup

⸻

✨ Features

* One-click deployment script
* Automatic SSL certificate via Cloudflare DNS API
* Systemd service management
* Lightweight and fast setup
* Minimal configuration required

⸻

📦 Requirements

Before installation, ensure you have:

* A domain managed by Cloudflare
* Cloudflare API Token with DNS edit permission
* A Linux VPS (Ubuntu / Debian recommended)
* Root access to the server

⸻

⚙️ Notes

* Must run as root user
* Ensure Cloudflare API Token has:
    * Zone:Read
    * DNS:Edit
* Recommended OS: Ubuntu 20.04+ / Debian 11+

⸻

📌 Usage Flow

1. Run installation command
2. Enter domain + Cloudflare token
3. Automatic certificate issuance
4. Service starts automatically

⸻

🧠 Disclaimer

This project is intended for educational and legitimate deployment purposes only.


