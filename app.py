# Copyright (C) 2026 AXV (AhmedXV-V12)
# OpenWebfilemgr is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.

import os
import re
import json
import hmac
import time
import base64
import hashlib
import secrets
import shutil
import threading
import mimetypes
from datetime import datetime
from flask import Flask, request, redirect, jsonify, send_file, abort, make_response, render_template
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash, check_password_hash

VERSION = "1.1"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

app = Flask(__name__, template_folder=BASE_DIR)

try:
    import pillow_heif
    pillow_heif.register_heif_opener()
    from PIL import Image
    HEIC_SUPPORTED = True
except Exception:
    HEIC_SUPPORTED = False

for _ext, _type in ((".mkv", "video/x-matroska"), (".webm", "video/webm"), (".mov", "video/quicktime"),
                    (".m4v", "video/mp4"), (".heic", "image/heic"), (".heif", "image/heif"),
                    (".avif", "image/avif"), (".webp", "image/webp"), (".md", "text/markdown")):
    mimetypes.add_type(_type, _ext)

# Values shipped in the public config.json; never accepted as real secrets or passwords.
PLACEHOLDER_SECRETS = {"", "make_any_secret_key_here"}
DEFAULT_PASSWORDS = {"", "admin"}

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")
UPLOAD_ID_RE = re.compile(r"^[A-Za-z0-9]{8,64}$")
CSRF_HEADER = "X-OWFM-Request"

# Media types the browser may show inline from /api/raw. Anything else (html, js, pdf, ...) is
# sent as a download so an uploaded file can never run script in this site's origin.
INLINE_IMAGE_TYPES = {"image/png", "image/jpeg", "image/gif", "image/webp", "image/bmp",
                      "image/x-ms-bmp", "image/avif", "image/svg+xml"}
RAW_CSP = "default-src 'none'; img-src 'self' data:; media-src 'self'; style-src 'unsafe-inline'; sandbox"
PAGE_CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; media-src 'self' blob:; object-src 'none'; base-uri 'none'; "
            "frame-ancestors 'none'; form-action 'self'")


# ---------------------------------------------------------------- config

_config_lock = threading.RLock()
_config_cache = {"mtime": None, "cfg": None}


def log(msg):
    print(f"[OpenWebfilemgr] {msg}", flush=True)


def save_config(cfg):
    data = json.dumps(cfg, indent=2, ensure_ascii=False) + "\n"
    with _config_lock:
        tmp = CONFIG_PATH + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, CONFIG_PATH)
        except OSError:
            # Docker bind-mounts config.json as a single file, which cannot be replaced by rename.
            try:
                os.remove(tmp)
            except OSError:
                pass
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
        _config_cache["mtime"] = os.stat(CONFIG_PATH).st_mtime_ns
        _config_cache["cfg"] = cfg


def _migrate_account(acc, label):
    """Turn a plain-text "password" into "password_hash". Returns True if acc changed."""
    if "password" not in acc:
        if acc.get("password_hash"):
            return False
        plain = ""
    else:
        plain = str(acc.pop("password") or "")
    if plain in DEFAULT_PASSWORDS:
        if acc.get("password_hash"):
            if plain:
                log(f"account '{label}': the default password is not allowed, the old password was kept")
            return True
        plain = secrets.token_urlsafe(12)
        log(f"account '{label}' had no password or the default one. Its new password is: {plain}")
        log("to choose your own, put \"password\": \"...\" in its entry in config.json (it is hashed automatically)")
    acc["password_hash"] = generate_password_hash(plain)
    return True


def _migrate_config(cfg):
    changed = False
    if str(cfg.get("secret_key", "")) in PLACEHOLDER_SECRETS or len(str(cfg.get("secret_key"))) < 16:
        cfg["secret_key"] = secrets.token_hex(32)
        changed = True
    if not isinstance(cfg.get("single_account"), dict):
        cfg["single_account"] = {"name": "admin", "root_path": "./storage/data"}
        changed = True
    sa = cfg["single_account"]
    changed |= _migrate_account(sa, sa.get("name", "admin"))
    accounts = cfg.get("accounts")
    if not isinstance(accounts, dict):
        cfg["accounts"] = accounts = {}
        changed = True
    for name, acc in accounts.items():
        if isinstance(acc, dict):
            changed |= _migrate_account(acc, name)
    return changed


def load_config():
    """Return the parsed config. It is re-read only when config.json changes on disk; plain-text
    passwords and placeholder secrets found there are replaced right away."""
    with _config_lock:
        mtime = os.stat(CONFIG_PATH).st_mtime_ns
        if _config_cache["cfg"] is not None and _config_cache["mtime"] == mtime:
            return _config_cache["cfg"]
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        if _migrate_config(cfg):
            save_config(cfg)
        else:
            _config_cache["mtime"] = mtime
            _config_cache["cfg"] = cfg
        return cfg


def cfg_int(cfg, key, default):
    try:
        return int(cfg.get(key, default))
    except (TypeError, ValueError):
        return default


def get_secret(cfg):
    return cfg["secret_key"].encode()


def cookie_name(cfg):
    return cfg.get("cookie_name", "owfm_session")


def multi_account(cfg):
    return cfg.get("make_account", 0) == 1


def registration_open(cfg):
    return multi_account(cfg) and cfg.get("allow_registration", False) is True


def text_max_bytes(cfg):
    return cfg_int(cfg, "text_max_bytes", 2 * 1024 * 1024)


def upload_chunk_size(cfg):
    return cfg_int(cfg, "upload_chunk_size_bytes", 10485760)


def upload_max_size(cfg):
    return cfg_int(cfg, "upload_max_file_size_bytes", 10737418240)


# ---------------------------------------------------------------- accounts and sessions

def get_account(cfg, name):
    if not isinstance(name, str) or not name:
        return None
    if multi_account(cfg):
        acc = cfg.get("accounts", {}).get(name)
        return acc if isinstance(acc, dict) else None
    sa = cfg.get("single_account", {})
    return sa if name == sa.get("name") else None


_dummy_hash = None


def check_password(acc, password):
    """Constant-work password check: unknown accounts still pay for one hash."""
    global _dummy_hash
    if not acc or not acc.get("password_hash"):
        if _dummy_hash is None:
            _dummy_hash = generate_password_hash(secrets.token_hex(16))
        check_password_hash(_dummy_hash, password)
        return False
    try:
        return check_password_hash(acc["password_hash"], password)
    except (ValueError, TypeError):
        return False  # hand-edited, malformed password_hash


def _token_sig(payload, acc, cfg):
    # Binding the signature to the password hash logs every session out when the password changes.
    bind = acc.get("password_hash", "")
    return hmac.new(get_secret(cfg), f"{payload}|{bind}".encode(), hashlib.sha256).hexdigest()


def make_token(username, acc, cfg):
    expiry = int(time.time()) + cfg_int(cfg, "session_days", 10) * 86400
    payload = f"{username}|{expiry}"
    raw = f"{payload}|{_token_sig(payload, acc, cfg)}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


def verify_token(token, cfg):
    try:
        raw = base64.urlsafe_b64decode(token.encode()).decode()
        username, expiry, sig = raw.rsplit("|", 2)
        acc = get_account(cfg, username)
        if not acc:
            return None
        if not hmac.compare_digest(_token_sig(f"{username}|{expiry}", acc, cfg), sig):
            return None
        if int(expiry) < int(time.time()):
            return None
        return username, acc
    except Exception:
        return None


def get_current_user(cfg):
    token = request.cookies.get(cookie_name(cfg))
    if not token:
        return None
    return verify_token(token, cfg)


def set_session_cookie(resp, token, cfg):
    secure = cfg.get("cookie_secure", "auto")
    if secure == "auto":
        secure = request.is_secure
    resp.set_cookie(cookie_name(cfg), token, max_age=cfg_int(cfg, "session_days", 10) * 86400,
                    httponly=True, samesite="Lax", secure=bool(secure))


_fail_lock = threading.Lock()
_fails = {}


def _recent_fails(key, cfg):
    window = cfg_int(cfg, "login_window_seconds", 300)
    now = time.time()
    with _fail_lock:
        lst = [t for t in _fails.get(key, []) if now - t < window]
        if lst:
            _fails[key] = lst
        else:
            _fails.pop(key, None)
        return lst


def login_blocked(cfg, name):
    limit = cfg_int(cfg, "login_max_attempts", 5)
    return (len(_recent_fails("ip:" + str(request.remote_addr), cfg)) >= limit or
            len(_recent_fails("user:" + name, cfg)) >= limit * 2)


def record_login_fail(name):
    now = time.time()
    with _fail_lock:
        if len(_fails) > 10000:
            _fails.clear()
        _fails.setdefault("ip:" + str(request.remote_addr), []).append(now)
        _fails.setdefault("user:" + name, []).append(now)
    log(f"failed login for '{name[:64]}' from {request.remote_addr}")


def clear_login_fails(name):
    with _fail_lock:
        _fails.pop("ip:" + str(request.remote_addr), None)
        _fails.pop("user:" + name, None)


# ---------------------------------------------------------------- paths

def resolve_dir(path):
    return os.path.realpath(path if os.path.isabs(path) else os.path.join(BASE_DIR, path))


def is_within(root, path):
    try:
        return os.path.normcase(os.path.commonpath([root, path])) == os.path.normcase(root)
    except ValueError:
        return False


def root_is_safe(root):
    """A storage root must not contain the app folder, or users could edit app.py and config.json."""
    return not is_within(root, os.path.realpath(BASE_DIR))


def account_root_setting(username, acc, cfg):
    if multi_account(cfg):
        return acc.get("root_path") or os.path.join(cfg.get("accounts_root", "./storage/users"), username)
    return acc.get("root_path", "./storage/data")


def get_user_root(username, acc, cfg):
    root = resolve_dir(account_root_setting(username, acc, cfg))
    if not root_is_safe(root):
        return None
    os.makedirs(root, exist_ok=True)
    return os.path.realpath(root)


def safe_join(root, rel_path, resolve_last=True):
    """Map a path from the client onto root and return the absolute path.

    Aborts with 403 if the path, or what it points to through symlinks, is outside root.
    With resolve_last=False only the parent folder is resolved, so a symlink itself can be
    deleted even when it points somewhere else."""
    if not isinstance(rel_path, str) or "\x00" in rel_path:
        abort(400)
    rel = rel_path.lstrip("/\\" if os.name == "nt" else "/")
    target = os.path.normpath(os.path.join(root, rel)) if rel else root
    if not is_within(root, target):
        abort(403)
    resolved = os.path.realpath(target) if resolve_last else os.path.join(
        os.path.realpath(os.path.dirname(target)), os.path.basename(target))
    if not is_within(root, resolved):
        abort(403)
    return target


def child_path(rel, name):
    return rel.rstrip("/") + "/" + name if rel.strip("/") else name


def clean_name(name):
    """Validate one file or folder name. Unicode (Arabic, ...) is kept. Returns None if invalid."""
    if not isinstance(name, str):
        return None
    name = name.strip()
    if name in ("", ".", "..") or len(name.encode("utf-8")) > 255:
        return None
    if "/" in name or "\\" in name or any(ord(c) < 32 or ord(c) == 127 for c in name):
        return None
    return name


def upload_name(filename):
    if not isinstance(filename, str):
        return None
    return clean_name(re.split(r"[/\\]", filename)[-1])


def unique_target(dst):
    """
    If dst exists, return a non-conflicting path by appending suffix.
    Example: file.txt -> file_copy.txt, file_copy_2.txt, ...
    """
    if not os.path.lexists(dst):
        return dst

    parent = os.path.dirname(dst)
    name = os.path.basename(dst)
    stem, suffix = os.path.splitext(name)
    counter = 1
    while True:
        candidate = os.path.join(parent, f"{stem}_copy{'' if counter == 1 else '_' + str(counter)}{suffix}")
        if not os.path.lexists(candidate):
            return candidate
        counter += 1


def file_kind(name, cfg):
    ext = os.path.splitext(name)[1].lower()
    if ext in cfg.get("image_extensions", []):
        return "image"
    if ext in cfg.get("video_extensions", []):
        return "video"
    if ext in cfg.get("text_extensions", []):
        return "text"
    return "file"


def get_heic_cache_dir(cfg):
    path = resolve_dir(cfg.get("heic_cache_dir", "./storage/.heic_cache"))
    os.makedirs(path, exist_ok=True)
    return path


def get_heic_preview(cfg, target):
    cache_dir = get_heic_cache_dir(cfg)
    stat = os.stat(target)
    key = hashlib.sha256(f"{target}|{stat.st_mtime}|{stat.st_size}".encode()).hexdigest()
    cached = os.path.join(cache_dir, key + ".jpg")
    if os.path.exists(cached):
        return cached
    if not HEIC_SUPPORTED:
        return None
    max_dim = cfg_int(cfg, "heic_preview_max_dimension", 1600)
    quality = cfg_int(cfg, "heic_preview_quality", 85)
    tmp = cached + f".{secrets.token_hex(4)}.tmp"
    with Image.open(target) as img:
        img.thumbnail((max_dim, max_dim))
        img.convert("RGB").save(tmp, "JPEG", quality=quality)
    os.replace(tmp, cached)
    return cached


# ---------------------------------------------------------------- request guards

def json_body():
    data = request.get_json(force=True, silent=True)
    return data if isinstance(data, dict) else {}


def str_field(data, key):
    value = data.get(key, "")
    return value if isinstance(value, str) else ""


@app.before_request
def guard_request():
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        # A custom header cannot be sent cross-site without CORS, which this app never allows.
        if request.headers.get(CSRF_HEADER) != "1":
            return jsonify(ok=False, error="missing request header"), 403
    cfg = load_config()
    if request.path == "/api/upload":
        limit = upload_max_size(cfg) + 1024 * 1024
    elif request.path == "/api/upload_chunk":
        limit = upload_chunk_size(cfg) + 1024 * 1024
    else:
        limit = text_max_bytes(cfg) * 2 + 1024 * 1024
    request.max_content_length = limit
    if request.content_length is not None and request.content_length > limit:
        abort(413)


@app.after_request
def security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    resp.headers.setdefault("Content-Security-Policy", PAGE_CSP)
    return resp


@app.errorhandler(HTTPException)
def http_error(e):
    if request.path.startswith("/api/"):
        return jsonify(ok=False, error=e.name.lower()), e.code
    return e


@app.errorhandler(OSError)
def os_error(e):
    log(f"error on {request.path}: {e}")
    if request.path.startswith("/api/"):
        return jsonify(ok=False, error=e.strerror or "server error"), 500
    return "server error", 500


def require_user():
    cfg = load_config()
    current = get_current_user(cfg)
    if not current:
        abort(401)
    user, acc = current
    root = get_user_root(user, acc, cfg)
    if not root:
        abort(401)
    return cfg, user, root


# ---------------------------------------------------------------- pages

def render_page(page, cfg):
    return render_template("index.html", page=page, make_account=cfg.get("make_account", 0),
                           allow_registration=registration_open(cfg), style_path=resolve_style_path(cfg),
                           version=VERSION)


@app.route("/")
def login_page():
    cfg = load_config()
    current = get_current_user(cfg)
    if current and get_user_root(current[0], current[1], cfg):
        return redirect("/files")
    return render_page("login", cfg)


@app.route("/files")
def files_page():
    cfg = load_config()
    current = get_current_user(cfg)
    if not current or not get_user_root(current[0], current[1], cfg):
        return redirect("/")
    return render_page("files", cfg)


def resolve_style_path(cfg):
    style_path = cfg.get("style_path")
    if style_path:
        full = os.path.abspath(os.path.join(BASE_DIR, style_path))
        if os.path.exists(full):
            return full
    default_css = os.path.join(BASE_DIR, "style.css")
    if os.path.exists(default_css):
        return default_css
    return None


@app.route("/logo.png")
def logo():
    full = os.path.join(BASE_DIR, "logo.png")
    if not os.path.exists(full):
        abort(404)
    return send_file(full, mimetype="image/png")


@app.route("/user-style")
def user_style():
    cfg = load_config()
    full = resolve_style_path(cfg)
    if not full:
        abort(404)
    return send_file(full, mimetype="text/css")


# ---------------------------------------------------------------- auth API

@app.route("/api/login", methods=["POST"])
def api_login():
    cfg = load_config()
    data = json_body()
    name = str_field(data, "name")
    password = str_field(data, "password")

    if login_blocked(cfg, name):
        minutes = max(1, cfg_int(cfg, "login_window_seconds", 300) // 60)
        return jsonify(ok=False, error=f"too many failed attempts, try again in {minutes} minutes"), 429

    acc = get_account(cfg, name)
    if not check_password(acc, password):
        record_login_fail(name)
        return jsonify(ok=False, error="invalid credentials")
    clear_login_fails(name)

    if not get_user_root(name, acc, cfg):
        log(f"account '{name}': root_path contains the app folder, refusing it; change root_path in config.json")
        return jsonify(ok=False, error="this account's storage folder is not allowed, ask the admin to change root_path")

    resp = make_response(jsonify(ok=True))
    set_session_cookie(resp, make_token(name, acc, cfg), cfg)
    return resp


@app.route("/api/register", methods=["POST"])
def api_register():
    cfg = load_config()
    if not registration_open(cfg):
        return jsonify(ok=False, error="registration disabled")
    data = json_body()
    name = str_field(data, "name")
    password = str_field(data, "password")

    if login_blocked(cfg, name):
        return jsonify(ok=False, error="too many attempts, try again later"), 429
    if not NAME_RE.match(name):
        return jsonify(ok=False, error="name must be 1-32 letters, digits, '.', '_' or '-'")
    if len(password) < 8 or len(password) > 256:
        return jsonify(ok=False, error="password must be 8 to 256 characters")

    with _config_lock:
        cfg = load_config()
        accounts = cfg.setdefault("accounts", {})
        if any(existing.lower() == name.lower() for existing in accounts):
            record_login_fail(name)
            return jsonify(ok=False, error="account exists")
        root_setting = os.path.join(cfg.get("accounts_root", "./storage/users"), name).replace("\\", "/")
        root = resolve_dir(root_setting)
        if not root_is_safe(root):
            return jsonify(ok=False, error="accounts_root is not allowed, ask the admin to change it")
        if os.path.isdir(root) and os.listdir(root):
            return jsonify(ok=False, error="a folder for this name already exists, ask the admin")
        os.makedirs(root, exist_ok=True)
        acc = {"password_hash": generate_password_hash(password), "root_path": root_setting}
        accounts[name] = acc
        save_config(cfg)

    log(f"account '{name}' registered from {request.remote_addr}")
    resp = make_response(jsonify(ok=True))
    set_session_cookie(resp, make_token(name, acc, cfg), cfg)
    return resp


@app.route("/api/logout", methods=["POST"])
def api_logout():
    resp = make_response(jsonify(ok=True))
    resp.delete_cookie(cookie_name(load_config()))
    return resp


# ---------------------------------------------------------------- files API

@app.route("/api/list")
def api_list():
    cfg, user, root = require_user()
    rel = request.args.get("path", "")
    target = safe_join(root, rel)
    if not os.path.isdir(target):
        return jsonify(ok=False, error="not a directory")
    entries = []
    for name in sorted(os.listdir(target)):
        full = os.path.join(target, name)
        rel_path = os.path.relpath(full, root).replace(os.sep, "/")
        try:
            stat = os.stat(full)
        except OSError:
            stat = os.lstat(full)  # broken symlink
        is_dir = os.path.isdir(full)
        entries.append({
            "name": name,
            "rel_path": rel_path,
            "is_dir": is_dir,
            "kind": None if is_dir else file_kind(name, cfg),
            "size": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
        })
    return jsonify(ok=True, entries=entries)


def inline_allowed(mimetype):
    return bool(mimetype) and (mimetype in INLINE_IMAGE_TYPES or mimetype.startswith("video/")
                               or mimetype.startswith("audio/"))


@app.route("/api/raw")
def api_raw():
    cfg, user, root = require_user()
    rel = request.args.get("path", "")
    target = safe_join(root, rel)
    if not os.path.isfile(target):
        abort(404)
    download = request.args.get("download") == "1"
    ext = os.path.splitext(target)[1].lower()
    max_age = cfg_int(cfg, "cache_max_age_seconds", 86400)

    if ext in (".heic", ".heif") and not download:
        try:
            preview = get_heic_preview(cfg, target)
        except Exception as e:
            log(f"heic preview failed for {rel}: {e}")
            preview = None
        if preview:
            resp = make_response(send_file(preview, mimetype="image/jpeg", conditional=True))
            resp.headers["Cache-Control"] = f"private, max-age={max_age}"
            resp.headers["Content-Security-Policy"] = RAW_CSP
            return resp

    mimetype, _ = mimetypes.guess_type(target)
    attachment = download or not inline_allowed(mimetype)
    resp = make_response(send_file(target, mimetype=mimetype or "application/octet-stream",
                                   as_attachment=attachment, download_name=os.path.basename(target),
                                   conditional=True))
    resp.headers["Content-Security-Policy"] = RAW_CSP
    if not download:
        resp.headers["Cache-Control"] = f"private, max-age={max_age}"
    return resp


def write_file_atomic(path, data):
    real = os.path.realpath(path)
    tmp = os.path.join(os.path.dirname(real), f".{os.path.basename(real)}.owfm-{secrets.token_hex(4)}.tmp")
    try:
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if os.path.exists(real):
            shutil.copymode(real, tmp)
        os.replace(tmp, real)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


@app.route("/api/text", methods=["GET", "POST"])
def api_text():
    cfg, user, root = require_user()
    limit = text_max_bytes(cfg)
    if request.method == "GET":
        rel = request.args.get("path", "")
        target = safe_join(root, rel)
        if not os.path.isfile(target):
            return jsonify(ok=False, error="not found")
        if os.path.getsize(target) > limit:
            return jsonify(ok=False, error=f"file is larger than {limit // 1024} KB, download it instead")
        with open(target, "rb") as f:
            raw = f.read()
        try:
            return jsonify(ok=True, content=raw.decode("utf-8"), read_only=False)
        except UnicodeDecodeError:
            return jsonify(ok=True, content=raw.decode("utf-8", errors="replace"), read_only=True)

    data = json_body()
    rel = str_field(data, "path")
    content = data.get("content", "")
    if not isinstance(content, str):
        return jsonify(ok=False, error="invalid content")
    target = safe_join(root, rel)
    if os.path.normcase(target) == os.path.normcase(root) or os.path.isdir(target):
        return jsonify(ok=False, error="not a file")
    if not os.path.isdir(os.path.dirname(target)):
        return jsonify(ok=False, error="folder not found")
    encoded = content.encode("utf-8")
    if len(encoded) > limit:
        return jsonify(ok=False, error=f"file is larger than {limit // 1024} KB")
    write_file_atomic(target, encoded)
    return jsonify(ok=True)


def new_entry_target(root, data):
    rel = str_field(data, "path")
    name = clean_name(str_field(data, "name"))
    if not name:
        return None, "invalid name"
    parent = safe_join(root, rel)
    if not os.path.isdir(parent):
        return None, "folder not found"
    target = safe_join(root, child_path(rel, name), resolve_last=False)
    if os.path.lexists(target):
        return None, "already exists"
    return target, None


@app.route("/api/mkdir", methods=["POST"])
def api_mkdir():
    cfg, user, root = require_user()
    target, error = new_entry_target(root, json_body())
    if error:
        return jsonify(ok=False, error=error)
    os.mkdir(target)
    return jsonify(ok=True)


@app.route("/api/mkfile", methods=["POST"])
def api_mkfile():
    cfg, user, root = require_user()
    target, error = new_entry_target(root, json_body())
    if error:
        return jsonify(ok=False, error=error)
    with open(target, "x", encoding="utf-8"):
        pass
    return jsonify(ok=True)


@app.route("/api/delete", methods=["POST"])
def api_delete():
    cfg, user, root = require_user()
    rel = str_field(json_body(), "path")
    target = safe_join(root, rel, resolve_last=False)
    if os.path.normcase(target) == os.path.normcase(root):
        return jsonify(ok=False, error="the root folder cannot be deleted")
    if os.path.islink(target):
        os.unlink(target)
    elif os.path.isdir(target):
        shutil.rmtree(target)
    elif os.path.isfile(target):
        os.remove(target)
    else:
        return jsonify(ok=False, error="not found")
    return jsonify(ok=True)


# ---------------------------------------------------------------- uploads

def get_upload_tmp_dir(cfg):
    path = resolve_dir(cfg.get("upload_tmp_dir", "./storage/.upload_tmp"))
    os.makedirs(path, exist_ok=True)
    return path


def user_upload_dir(cfg, user):
    # Upload sessions are kept per user, so nobody can add chunks to another user's upload.
    return os.path.join(get_upload_tmp_dir(cfg), hashlib.sha256(user.encode()).hexdigest()[:24])


def cleanup_stale_uploads(cfg):
    max_age = cfg_int(cfg, "upload_stale_hours", 24) * 3600
    now = time.time()
    base = get_upload_tmp_dir(cfg)
    for user_dir in os.listdir(base):
        user_path = os.path.join(base, user_dir)
        if not os.path.isdir(user_path):
            continue
        for session in os.listdir(user_path):
            path = os.path.join(user_path, session)
            try:
                if now - os.path.getmtime(path) > max_age:
                    shutil.rmtree(path, ignore_errors=True)
            except OSError:
                pass


def save_upload(storage, dest):
    try:
        storage.save(dest)
    except Exception:
        if os.path.exists(dest):
            os.remove(dest)
        raise


@app.route("/api/upload", methods=["POST"])
def api_upload():
    cfg, user, root = require_user()
    rel = request.form.get("path", "")
    upload_type = request.form.get("upload_type", "file")
    parent = safe_join(root, rel)

    if not os.path.isdir(parent):
        return jsonify(ok=False, error="invalid destination")

    if upload_type == "files":
        # Handle multiple file upload
        if "files[]" not in request.files:
            return jsonify(ok=False, error="no files received")

        uploaded_files = request.files.getlist("files[]")
        successful_uploads = 0

        for up in uploaded_files:
            if up.filename == "":
                continue

            filename = upload_name(up.filename)
            if not filename:
                return jsonify(ok=False, error="invalid file name")
            dest = unique_target(safe_join(root, child_path(rel, filename), resolve_last=False))

            try:
                save_upload(up, dest)
                successful_uploads += 1
            except Exception as e:
                return jsonify(ok=False, error=f"failed to upload {filename}: {str(e)}")

        return jsonify(ok=True, uploaded=successful_uploads)

    # Handle single file upload
    if "file" not in request.files:
        return jsonify(ok=False, error="no file")
    f = request.files["file"]
    if f.filename == "":
        return jsonify(ok=False, error="empty filename")

    filename = upload_name(f.filename)
    if not filename:
        return jsonify(ok=False, error="invalid file name")
    dest = unique_target(safe_join(root, child_path(rel, filename), resolve_last=False))
    save_upload(f, dest)
    return jsonify(ok=True)


@app.route("/api/upload_config")
def api_upload_config():
    cfg, user, root = require_user()
    return jsonify(ok=True, chunk_size=upload_chunk_size(cfg), max_file_size=upload_max_size(cfg))


def parts_size(tmp_dir, skip=None):
    total = 0
    for p in os.listdir(tmp_dir):
        if p.endswith(".part") and p != skip:
            total += os.path.getsize(os.path.join(tmp_dir, p))
    return total


@app.route("/api/upload_chunk", methods=["POST"])
def api_upload_chunk():
    cfg, user, root = require_user()
    upload_id = request.form.get("upload_id", "")
    chunk_index = request.form.get("chunk_index", "")
    if not upload_id or chunk_index == "" or "chunk" not in request.files:
        return jsonify(ok=False, error="missing fields")
    if not UPLOAD_ID_RE.match(upload_id):
        return jsonify(ok=False, error="invalid upload id")
    try:
        chunk_index = int(chunk_index)
    except ValueError:
        return jsonify(ok=False, error="invalid chunk index")
    chunk_size = upload_chunk_size(cfg)
    max_size = upload_max_size(cfg)
    if chunk_index < 0 or chunk_index * chunk_size > max_size:
        return jsonify(ok=False, error="invalid chunk index")

    user_dir = user_upload_dir(cfg, user)
    tmp_dir = os.path.join(user_dir, upload_id)
    if not os.path.isdir(tmp_dir):
        cleanup_stale_uploads(cfg)
        os.makedirs(user_dir, exist_ok=True)
        if len(os.listdir(user_dir)) >= cfg_int(cfg, "upload_max_sessions", 8):
            return jsonify(ok=False, error="too many unfinished uploads, wait or cancel them")
        os.makedirs(tmp_dir, exist_ok=True)

    part_name = f"{chunk_index:08d}.part"
    chunk_path = os.path.join(tmp_dir, part_name)
    incoming = chunk_path + ".tmp"
    save_upload(request.files["chunk"], incoming)
    size = os.path.getsize(incoming)
    if size > chunk_size:
        os.remove(incoming)
        return jsonify(ok=False, error="chunk too large")
    if parts_size(tmp_dir, skip=part_name) + size > max_size:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return jsonify(ok=False, error="file exceeds max allowed size")
    os.replace(incoming, chunk_path)
    return jsonify(ok=True)


@app.route("/api/upload_finish", methods=["POST"])
def api_upload_finish():
    cfg, user, root = require_user()
    data = json_body()
    upload_id = str_field(data, "upload_id")
    rel = str_field(data, "path")
    filename = upload_name(str_field(data, "filename"))
    total_chunks = data.get("total_chunks", 0)
    if not UPLOAD_ID_RE.match(upload_id) or not filename:
        return jsonify(ok=False, error="missing fields")
    if not isinstance(total_chunks, int) or isinstance(total_chunks, bool) or total_chunks < 1:
        return jsonify(ok=False, error="invalid total_chunks")

    tmp_dir = os.path.join(user_upload_dir(cfg, user), upload_id)
    if not os.path.isdir(tmp_dir):
        return jsonify(ok=False, error="upload session not found")

    parent = safe_join(root, rel)
    if not os.path.isdir(parent):
        return jsonify(ok=False, error="invalid destination")

    expected = [f"{i:08d}.part" for i in range(total_chunks)]
    present = set(os.listdir(tmp_dir))
    missing = [i for i, p in enumerate(expected) if p not in present]
    if missing:
        return jsonify(ok=False, error=f"upload incomplete, missing chunk {missing[0]}")
    if len([p for p in present if p.endswith(".part")]) != total_chunks:
        return jsonify(ok=False, error=f"expected {total_chunks} chunks")

    total_size = sum(os.path.getsize(os.path.join(tmp_dir, p)) for p in expected)
    if total_size > upload_max_size(cfg):
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return jsonify(ok=False, error="file exceeds max allowed size")

    # Join the chunks inside the temp folder first, so a half-written file never shows up.
    assembled = os.path.join(tmp_dir, "assembled.bin")
    with open(assembled, "wb") as out:
        for part_name in expected:
            with open(os.path.join(tmp_dir, part_name), "rb") as part_file:
                shutil.copyfileobj(part_file, out, 1024 * 1024)

    dest = unique_target(safe_join(root, child_path(rel, filename), resolve_last=False))
    shutil.move(assembled, dest)
    shutil.rmtree(tmp_dir, ignore_errors=True)
    return jsonify(ok=True, name=os.path.basename(dest))


@app.route("/api/upload_cancel", methods=["POST"])
def api_upload_cancel():
    cfg, user, root = require_user()
    upload_id = str_field(json_body(), "upload_id")
    if UPLOAD_ID_RE.match(upload_id):
        shutil.rmtree(os.path.join(user_upload_dir(cfg, user), upload_id), ignore_errors=True)
    return jsonify(ok=True)


# ---------------------------------------------------------------- startup

def print_roots(cfg):
    if multi_account(cfg):
        items = [(n, a) for n, a in cfg.get("accounts", {}).items() if isinstance(a, dict)]
        log(f"multi-account mode, {len(items)} account(s), registration {'open' if registration_open(cfg) else 'closed'}")
    else:
        sa = cfg["single_account"]
        items = [(sa.get("name", "admin"), sa)]
    for name, acc in items:
        r = resolve_dir(account_root_setting(name, acc, cfg))
        state = "" if root_is_safe(r) else "  <-- REFUSED: it contains the app folder, change root_path"
        log(f"account '{name}' root: {r}{state}")


if __name__ == "__main__":
    cfg = load_config()
    log(f"version {VERSION}")
    print_roots(cfg)
    log(f"heic support: {HEIC_SUPPORTED}")
    cleanup_stale_uploads(cfg)
    if cfg.get("trust_proxy", False) is True:
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
        log("trusting X-Forwarded-* headers from one reverse proxy")
    from waitress import serve
    serve(app, host=cfg.get("host", "0.0.0.0"), port=cfg_int(cfg, "port", 7000),
          threads=cfg_int(cfg, "waitress_threads", 8),
          max_request_body_size=upload_max_size(cfg) + 2 * 1024 * 1024)
