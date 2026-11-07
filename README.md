# OpenWebfilemgr <img src="https://github.com/user-attachments/assets/439c4ef8-e9a7-476c-8a87-f96b0f6a78ad" width="50" height="50" align="center" alt="logo" />

## What is OpenWebfilemgr?
* An open-source, lightweight web-based file manager.
* Designed to run efficiently on low-end hardware and resource-constrained devices.

## Installation
You can download and run the interactive installer script using `curl`

### install by curl (version 1.1)
```bash
curl -L https://github.com/AhmedXV-V12/OpenWebfilemgr/archive/refs/tags/v1.1.tar.gz | tar -xz && cd OpenWebfilemgr-1.1 && chmod +x build.sh && ./build.sh
```

### install the latest code from main
```bash
curl -L https://github.com/AhmedXV-V12/OpenWebfilemgr/archive/refs/heads/main.tar.gz | tar -xz && cd OpenWebfilemgr-main && chmod +x build.sh && ./build.sh
```

### What the installer does:

1. Opens `config.json` and `docker-compose.yml` sequentially in `nano` for configuration.
2. Prompts you optionally to edit front-end files (`style.css`, `index.html`) and the core application (`app.py`).
3. Prompts you to build the Docker image using `docker compose build`, then optionally starts it.

### Password
* Set your password in `config.json` under `single_account` → `"password"`. On start it is replaced by a secure hash (`"password_hash"`), so the plain password is never kept on disk.
* If you leave it empty (or `admin`), a random password is generated and printed once in the log: `docker compose logs openwebfilemgr`.
* To change a password later, put `"password": "new password"` back in the account entry; it is hashed automatically and every old session is logged out.

### Accounts
* `"make_account": 0` (default): one account, `single_account`.
* `"make_account": 1`: several accounts listed in `"accounts"` (`{"name": {"password": "...", "root_path": "./storage/users/name"}}`).
* `"allow_registration": true` lets visitors create accounts in multi-account mode. Each new account gets its own folder inside `accounts_root`; visitors can no longer pick the folder.
* A storage folder that contains the app folder itself (for example `/` or `.`) is refused.

### Behind a reverse proxy / HTTPS
* `"trust_proxy": true` when OpenWebfilemgr runs behind exactly one reverse proxy, so login limits see the real client address.
* `"cookie_secure": "auto"` marks the session cookie `Secure` on HTTPS; set it to `true` to always require HTTPS.

### Versions
Every version and what it changed is in [CHANGELOG.md](CHANGELOG.md). Older versions stay available under [Releases](https://github.com/AhmedXV-V12/OpenWebfilemgr/releases) / tags.

---

## License and Restrictions

You are free to modify, fork, and distribute this software under the following terms:

> Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0)

### Key Requirements:

1. **Brand Retention:** You must retain the original OpenWebfilemgr name, logo, and copyright attributions within the user interface.
2. **Copyleft Enforcement:** Any modifications or forks used over a network as a web service must make their modified source code available to the public under the same AGPL-3.0 license.

---
## Screenshots

### Dashboard Overview
<img width="925" alt="Dashboard Overview" src="https://github.com/user-attachments/assets/b7744397-b416-45ff-9997-124402e9bf07" />

### File Management Interface
<img width="589" alt="File Management" src="https://github.com/user-attachments/assets/55178bc9-11aa-469a-bf12-e84a086b5d34" />

### Terminal and Logs Preview
<img width="1718" alt="Terminal Preview" src="https://github.com/user-attachments/assets/3a2cb584-105d-43cb-9557-b580499913fd" />
