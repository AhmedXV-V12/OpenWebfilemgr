# OpenWebfilemgr <img src="https://github.com/user-attachments/assets/439c4ef8-e9a7-476c-8a87-f96b0f6a78ad" width="48" height="48" align="center" alt="logo" />

## What is OpenWebfilemgr?
* An open-source, lightweight web-based file manager.
* Designed to run efficiently on low-end hardware and resource-constrained devices.

## Installation
You can download and run the interactive installer script using either `curl` or `wget`.

### Option 1: Using curl
```bash
curl -L https://github.com/AhmedXV-V12/OpenWebfilemgr/archive/refs/heads/main.tar.gz | tar -xz && cd OpenWebfilemgr-main && chmod +x build.sh && ./build.sh

```
### What the installer does:

1. Opens `config.json` and `docker-compose.yml` sequentially in `nano` for configuration.
2. Prompts you optionally to edit front-end files (`style.css`, `index.html`) and the core application (`app.py`).
3. Prompts you to build the Docker image using `docker compose build`.

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
