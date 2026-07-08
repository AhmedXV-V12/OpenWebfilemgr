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
import json
import hmac
import time
import base64
import hashlib
import secrets
import shutil
import mimetypes
from datetime import datetime
from flask import Flask, request, redirect, jsonify, send_file, abort, make_response, render_template
from werkzeug.utils import secure_filename

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


def load_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    changed = False
    if not cfg.get("secret_key"):
        cfg["secret_key"] = secrets.token_hex(32)
        changed = True
    if changed:
        save_config(cfg)
    return cfg


def save_config(cfg):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)


def get_secret(cfg):
    return cfg["secret_key"].encode()


def cookie_name(cfg):
    return cfg.get("cookie_name", "owfm_session")


def sign(payload, secret):
    return hmac.new(secret, payload.encode(), hashlib.sha256).hexdigest()


def make_token(username, cfg):
    days = cfg.get("session_days", 10)
    expiry = int(time.time()) + days * 86400
    payload = f"{username}|{expiry}"
    sig = sign(payload, get_secret(cfg))
    raw = f"{payload}|{sig}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


def verify_token(token, cfg):
    try:
        raw = base64.urlsafe_b64decode(token.encode()).decode()
        username, expiry, sig = raw.split("|")
        payload = f"{username}|{expiry}"
        expected = sign(payload, get_secret(cfg))
        if not hmac.compare_digest(expected, sig):
            return None
        if int(expiry) < int(time.time()):
            return None
        return username
    except Exception:
        return None


def get_current_user(cfg):
    token = request.cookies.get(cookie_name(cfg))
    if not token:
        return None
    return verify_token(token, cfg)


def get_user_root(username, cfg):
    if cfg.get("make_account", 0) == 1:
        acc = cfg.get("accounts", {}).get(username)
        if not acc:
            return None
        root = acc["root_path"]
    else:
        root = cfg["single_account"]["root_path"]
    if os.path.isabs(root):
        root = os.path.abspath(root)
    else:
        root = os.path.abspath(os.path.join(BASE_DIR, root))
    os.makedirs(root, exist_ok=True)
    return root


def safe_join(root, rel_path):
    rel_path = rel_path.lstrip("/").lstrip("\\")
    target = os.path.abspath(os.path.join(root, rel_path))
    if not target.startswith(os.path.abspath(root)):
        abort(403)
    return target


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
    path = cfg.get("heic_cache_dir", "./.heic_cache")
    path = path if os.path.isabs(path) else os.path.abspath(os.path.join(BASE_DIR, path))
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
    max_dim = cfg.get("heic_preview_max_dimension", 1600)
    quality = cfg.get("heic_preview_quality", 85)
    img = Image.open(target)
    img.thumbnail((max_dim, max_dim))
    img.convert("RGB").save(cached, "JPEG", quality=quality)
    return cached


@app.route("/")
def login_page():
    cfg = load_config()
    user = get_current_user(cfg)
    if user and get_user_root(user, cfg):
        return redirect("/files")
    return render_template("index.html", page="login", make_account=cfg.get("make_account", 0), style_path=resolve_style_path(cfg))


@app.route("/files")
def files_page():
    cfg = load_config()
    user = get_current_user(cfg)
    if not user or not get_user_root(user, cfg):
        return redirect("/")
    return render_template("index.html", page="files", make_account=cfg.get("make_account", 0), style_path=resolve_style_path(cfg))


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


@app.route("/api/login", methods=["POST"])
def api_login():
    cfg = load_config()
    data = request.get_json(force=True)
    name = data.get("name", "")
    password = data.get("password", "")

    if cfg.get("make_account", 0) == 1:
        acc = cfg.get("accounts", {}).get(name)
        if not acc or acc["password"] != password:
            return jsonify(ok=False, error="invalid credentials")
    else:
        sa = cfg["single_account"]
        if name != sa["name"] or password != sa["password"]:
            return jsonify(ok=False, error="invalid credentials")

    token = make_token(name, cfg)
    resp = make_response(jsonify(ok=True))
    resp.set_cookie(cookie_name(cfg), token, max_age=cfg.get("session_days", 10) * 86400, httponly=True, samesite="Lax")
    return resp


@app.route("/api/register", methods=["POST"])
def api_register():
    cfg = load_config()
    if cfg.get("make_account", 0) != 1:
        return jsonify(ok=False, error="registration disabled")
    data = request.get_json(force=True)
    name = data.get("name", "")
    password = data.get("password", "")
    root_path = data.get("root_path", "")
    if not name or not password or not root_path:
        return jsonify(ok=False, error="missing fields")
    if name in cfg.get("accounts", {}):
        return jsonify(ok=False, error="account exists")
    full_root = os.path.abspath(os.path.join(BASE_DIR, root_path))
    os.makedirs(full_root, exist_ok=True)
    cfg.setdefault("accounts", {})[name] = {"password": password, "root_path": root_path}
    save_config(cfg)
    token = make_token(name, cfg)
    resp = make_response(jsonify(ok=True))
    resp.set_cookie(cookie_name(cfg), token, max_age=cfg.get("session_days", 10) * 86400, httponly=True, samesite="Lax")
    return resp


@app.route("/api/logout", methods=["POST"])
def api_logout():
    resp = make_response(jsonify(ok=True))
    resp.delete_cookie(cookie_name(load_config()))
    return resp


def require_user():
    cfg = load_config()
    user = get_current_user(cfg)
    if not user:
        abort(401)
    root = get_user_root(user, cfg)
    if not root:
        abort(401)
    return cfg, user, root


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
        rel_path = os.path.relpath(full, root).replace("\\", "/")
        is_dir = os.path.isdir(full)
        stat = os.stat(full)
        entries.append({
            "name": name,
            "rel_path": rel_path,
            "is_dir": is_dir,
            "kind": None if is_dir else file_kind(name, cfg),
            "size": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
        })
    return jsonify(ok=True, entries=entries)


@app.route("/api/raw")
def api_raw():
    cfg, user, root = require_user()
    rel = request.args.get("path", "")
    target = safe_join(root, rel)
    if not os.path.isfile(target):
        abort(404)
    download = request.args.get("download") == "1"
    ext = os.path.splitext(target)[1].lower()

    if ext in (".heic", ".heif") and not download:
        preview = get_heic_preview(cfg, target)
        if preview:
            resp = make_response(send_file(preview, mimetype="image/jpeg", conditional=True))
            resp.headers["Cache-Control"] = f"private, max-age={cfg.get('cache_max_age_seconds', 86400)}"
            return resp

    mimetype, _ = mimetypes.guess_type(target)
    resp = make_response(send_file(target, mimetype=mimetype, as_attachment=download, download_name=os.path.basename(target), conditional=True))
    if not download:
        resp.headers["Cache-Control"] = f"private, max-age={cfg.get('cache_max_age_seconds', 86400)}"
    return resp


@app.route("/api/text", methods=["GET", "POST"])
def api_text():
    cfg, user, root = require_user()
    if request.method == "GET":
        rel = request.args.get("path", "")
        target = safe_join(root, rel)
        if not os.path.isfile(target):
            return jsonify(ok=False, error="not found")
        with open(target, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        return jsonify(ok=True, content=content)
    else:
        data = request.get_json(force=True)
        rel = data.get("path", "")
        content = data.get("content", "")
        target = safe_join(root, rel)
        with open(target, "w", encoding="utf-8") as f:
            f.write(content)
        return jsonify(ok=True)


@app.route("/api/mkdir", methods=["POST"])
def api_mkdir():
    cfg, user, root = require_user()
    data = request.get_json(force=True)
    rel = data.get("path", "")
    name = data.get("name", "")
    if not name:
        return jsonify(ok=False, error="missing name")
    parent = safe_join(root, rel)
    target = os.path.join(parent, name)
    if not os.path.abspath(target).startswith(os.path.abspath(root)):
        abort(403)
    os.makedirs(target, exist_ok=True)
    return jsonify(ok=True)


@app.route("/api/mkfile", methods=["POST"])
def api_mkfile():
    cfg, user, root = require_user()
    data = request.get_json(force=True)
    rel = data.get("path", "")
    name = data.get("name", "")
    if not name:
        return jsonify(ok=False, error="missing name")
    parent = safe_join(root, rel)
    target = os.path.join(parent, name)
    if not os.path.abspath(target).startswith(os.path.abspath(root)):
        abort(403)
    if os.path.exists(target):
        return jsonify(ok=False, error="already exists")
    with open(target, "w", encoding="utf-8") as f:
        f.write("")
    return jsonify(ok=True)


@app.route("/api/delete", methods=["POST"])
def api_delete():
    cfg, user, root = require_user()
    data = request.get_json(force=True)
    rel = data.get("path", "")
    target = safe_join(root, rel)
    if os.path.isdir(target):
        shutil.rmtree(target)
    elif os.path.isfile(target):
        os.remove(target)
    else:
        return jsonify(ok=False, error="not found")
    return jsonify(ok=True)


def get_upload_tmp_dir(cfg):
    path = cfg.get("upload_tmp_dir", "./.upload_tmp")
    path = path if os.path.isabs(path) else os.path.abspath(os.path.join(BASE_DIR, path))
    os.makedirs(path, exist_ok=True)
    return path


UPLOAD_CHUNK_SIZE = 4096


def unique_target(dst):
    """
    If dst exists, return a non-conflicting path by appending suffix.
    Example: file.txt -> file_copy.txt, file_copy_2.txt, ...
    """
    if not os.path.exists(dst):
        return dst

    parent = os.path.dirname(dst)
    name = os.path.basename(dst)
    stem, suffix = os.path.splitext(name)
    counter = 1
    while True:
        candidate = os.path.join(parent, f"{stem}_copy{'' if counter == 1 else '_' + str(counter)}{suffix}")
        if not os.path.exists(candidate):
            return candidate
        counter += 1


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

            filename = secure_filename(up.filename)
            dest = os.path.join(parent, filename)
            if not os.path.abspath(dest).startswith(os.path.abspath(root)):
                abort(403)
            dest = unique_target(dest)

            try:
                up.save(dest)
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

    filename = secure_filename(f.filename)
    dest = os.path.join(parent, filename)
    if not os.path.abspath(dest).startswith(os.path.abspath(root)):
        abort(403)
    dest = unique_target(dest)

    f.save(dest)

    return jsonify(ok=True)


@app.route("/api/upload_config")
def api_upload_config():
    cfg = load_config()
    return jsonify(
        chunk_size=cfg.get("upload_chunk_size_bytes", 10485760),
        max_file_size=cfg.get("upload_max_file_size_bytes", 10737418240)
    )


@app.route("/api/upload_chunk", methods=["POST"])
def api_upload_chunk():
    cfg, user, root = require_user()
    upload_id = request.form.get("upload_id", "")
    chunk_index = request.form.get("chunk_index", "")
    if not upload_id or chunk_index == "" or "chunk" not in request.files:
        return jsonify(ok=False, error="missing fields")
    if not upload_id.isalnum():
        return jsonify(ok=False, error="invalid upload id")
    try:
        chunk_index = int(chunk_index)
    except ValueError:
        return jsonify(ok=False, error="invalid chunk index")

    tmp_dir = os.path.join(get_upload_tmp_dir(cfg), upload_id)
    os.makedirs(tmp_dir, exist_ok=True)
    chunk_path = os.path.join(tmp_dir, f"{chunk_index:08d}.part")

    f = request.files["chunk"]
    f.save(chunk_path)
    return jsonify(ok=True)


@app.route("/api/upload_finish", methods=["POST"])
def api_upload_finish():
    cfg, user, root = require_user()
    data = request.get_json(force=True)
    upload_id = data.get("upload_id", "")
    rel = data.get("path", "")
    filename = data.get("filename", "")
    filename = secure_filename(filename)
    total_chunks = data.get("total_chunks", 0)
    if not upload_id or not upload_id.isalnum() or not filename:
        return jsonify(ok=False, error="missing fields")

    tmp_dir = os.path.join(get_upload_tmp_dir(cfg), upload_id)
    if not os.path.isdir(tmp_dir):
        return jsonify(ok=False, error="upload session not found")

    parent = safe_join(root, rel)
    dest = os.path.join(parent, filename)
    if not os.path.abspath(dest).startswith(os.path.abspath(root)):
        abort(403)

    parts = sorted(os.listdir(tmp_dir))
    if len(parts) != total_chunks:
        return jsonify(ok=False, error=f"expected {total_chunks} chunks, got {len(parts)}")

    total_size = sum(os.path.getsize(os.path.join(tmp_dir, p)) for p in parts)
    max_size = cfg.get("upload_max_file_size_bytes", 10737418240)
    if total_size > max_size:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return jsonify(ok=False, error="file exceeds max allowed size")

    with open(dest, "wb") as out:
        for part_name in parts:
            with open(os.path.join(tmp_dir, part_name), "rb") as part_file:
                shutil.copyfileobj(part_file, out)

    shutil.rmtree(tmp_dir, ignore_errors=True)
    return jsonify(ok=True)


@app.route("/api/upload_cancel", methods=["POST"])
def api_upload_cancel():
    cfg, user, root = require_user()
    data = request.get_json(force=True)
    upload_id = data.get("upload_id", "")
    if upload_id and upload_id.isalnum():
        tmp_dir = os.path.join(get_upload_tmp_dir(cfg), upload_id)
        shutil.rmtree(tmp_dir, ignore_errors=True)
    return jsonify(ok=True)


if __name__ == "__main__":
    cfg = load_config()
    if cfg.get("make_account", 0) == 1:
        for name, acc in cfg.get("accounts", {}).items():
            r = acc["root_path"]
            r = r if os.path.isabs(r) else os.path.abspath(os.path.join(BASE_DIR, r))
            print(f"[OpenWebfilemgr] account '{name}' root: {r}")
    else:
        r = cfg["single_account"]["root_path"]
        r = r if os.path.isabs(r) else os.path.abspath(os.path.join(BASE_DIR, r))
        print(f"[OpenWebfilemgr] storage root: {r}")
    print(f"[OpenWebfilemgr] heic support: {HEIC_SUPPORTED}")
    from waitress import serve
    serve(app, host=cfg.get("host", "0.0.0.0"), port=cfg.get("port", 5000), threads=cfg.get("waitress_threads", 8))
