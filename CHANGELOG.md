# Changelog

All versions of OpenWebfilemgr. Older versions stay downloadable from the tags on GitHub.

## 1.1 — 2026-11-07

### New
* **Video loop:** a `Loop: On / Off` button under every video. The choice is remembered in the browser.
* Upload several files at once; large files are sent in chunks (10 MB by default) with retries, so uploads up to the configured limit (10 GB) work behind proxies and on weak connections.
* The version is shown at the bottom of every page.

### Security fixes
* **Session forgery:** the shipped `secret_key` placeholder was used as the real key, so anyone could forge a login cookie. A random key is now generated whenever the key is empty, the placeholder or too short.
* **Open registration with a free choice of folder:** any visitor could create an account whose folder was `/` (the whole disk) or `.` (the app folder, so `app.py` could be edited). Registration is now off by default (`allow_registration`), new accounts always get their own folder inside `accounts_root`, and a folder that contains the app is refused for every account.
* **Plain-text passwords:** passwords are now stored as hashes (`password_hash`); existing plain passwords are converted automatically. The default `admin` / empty password is replaced by a random one printed in the log.
* **Changing a password logs out every old session.**
* **Login brute force:** failed logins are limited per address and per account (`login_max_attempts`, `login_window_seconds`).
* **Path escape:** paths are now checked with the real path, so `../`, folders that only start with the same name (`data2` vs `data`) and symlinks can no longer reach files outside the user's folder.
* **Stored XSS:** uploaded `.html`, `.svg`, `.js` and similar files were shown as web pages of the site. Only images, video and audio are shown inline now, everything else is downloaded, and every file is served with a sandbox Content-Security-Policy and `nosniff`.
* **CSRF:** every change request must carry an `X-OWFM-Request` header, which other sites cannot send.
* **Deleting the root folder** (empty path) is refused.
* **Uploads of other users:** unfinished chunked uploads are now kept per user, chunk and total sizes are checked while uploading, the number of unfinished uploads is limited and old ones are removed after `upload_stale_hours`.
* Requests that are too large are refused before they are read (`text_max_bytes`, upload limits); `/api/upload_config` now needs a login.
* Security headers on every page (`X-Frame-Options`, `Referrer-Policy`, `Content-Security-Policy`); the session cookie gets `Secure` on HTTPS (`cookie_secure`); `trust_proxy` for reverse proxies.

### Bug fixes
* **Docker lost the files:** the files were saved in `/app/data`, which is not in a volume. The default folders are now inside `./storage` (`storage/data`, `storage/users`, `storage/.upload_tmp`, `storage/.heic_cache`). `EXPOSE` now matches port 7000.
* Arabic and other non-English file names were changed or removed on upload; they are kept now.
* A finished chunked upload overwrote an existing file with the same name, and missing chunks were not detected.
* Saving a text file changed Windows line endings and could corrupt files that are not UTF-8 (those open read-only now); saving is atomic, very large files are not loaded into the editor.
* Pressing Enter on the login form reloaded the page instead of logging in.
* When the session expired, the page broke instead of going back to the login page.
* A folder link to a folder that no longer exists showed an empty page; it now opens the root folder.
* A broken symlink in a folder made the listing fail; deleting a symlink deletes the link, not the folder it points to.
* New folders with an existing name now report "already exists"; HEIC previews that fail fall back to the original file.
* The config file is no longer read from disk on every request and is written safely (also when it is mounted as a single file by Docker).
* Pinned dependency versions in `requirements.txt`; Python logs show up right away in `docker compose logs`.
* Added `viewport` so the page fits phone screens.

### Upgrading from 1.0
1. **Copy your files out of the old container first**, they are not in a volume in 1.0:
   `docker cp openwebfilemgr:/app/data ./storage/data`
2. In your `config.json`, set `root_path` to `./storage/data` (or `./storage/users/<name>` for each account).
3. Check the `root_path` of accounts created by registration in 1.0: visitors could choose any folder.
4. Rebuild: `docker compose build && docker compose up -d`. Everyone has to log in again once.

## 1.0 — 2026-07-08
* First version: web file manager (browse, create, upload, download, delete), image/video/HEIC preview, text editor, single or multiple accounts, Docker installer.
