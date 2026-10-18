"""Owner dashboard. Password auth, absolute session expiry, CSRF, audit and metadata only."""
import functools
import hashlib
import json
import os
import secrets
import time
from flask import Blueprint, jsonify, render_template, request, session
from werkzeug.security import check_password_hash, generate_password_hash
from licensing.service import Denied, FEATURES, b64
from cryptography.hazmat.primitives import serialization


def register_admin(app, store, jobs):
    password_hash = os.environ.get("ROOMLITE_ADMIN_PASSWORD_HASH", "")
    if not password_hash and len(os.environ.get("ROOMLITE_ADMIN_PASSWORD", "")) >= 16:
        password_hash = generate_password_hash(os.environ["ROOMLITE_ADMIN_PASSWORD"])
    secret = os.environ.get("ROOMLITE_ADMIN_SESSION_SECRET", "") or getattr(store, "admin_secret", "")
    username = os.environ.get("ROOMLITE_ADMIN_USERNAME", "owner")
    configured = password_hash.startswith(("scrypt:", "pbkdf2:")) and len(secret) >= 32
    local = os.environ.get("ROOMLITE_ADMIN_LOCAL_HTTP") == "1"
    if configured:
        app.secret_key = secret
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SECURE=not local,
                      SESSION_COOKIE_SAMESITE="Strict", SESSION_COOKIE_NAME="roomlite_owner",
                      MAX_CONTENT_LENGTH=2 * 1024 * 1024)
    credential_version = hashlib.sha256(password_hash.encode()).hexdigest()
    store.init_audit()
    bp = Blueprint("admin", __name__, template_folder="templates", static_folder="static", static_url_path="/admin/assets")

    @app.before_request
    def sizes():
        if request.path.startswith("/v1/") and (request.content_length or 0) > 40000:
            return jsonify(error="Request too large."), 413

    @app.after_request
    def dashboard_headers(response):
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    def guard():
        if not configured:
            raise Denied("Dashboard is not configured. Set the administrator environment variables.")
        if local and request.remote_addr not in {"127.0.0.1", "::1"}:
            raise Denied("Local HTTP dashboard only accepts loopback connections.")

    def csrf():
        expected = session.get("csrf", "")
        if not expected or not secrets.compare_digest(expected, request.headers.get("X-CSRF-Token", "")):
            raise Denied("Session verification failed. Reload the page.")

    def logged_in():
        return session.get("owner") is True and session.get("credential_version") == credential_version and session.get("login_time", 0) + 1800 > time.time()

    def owner(fn):
        @functools.wraps(fn)
        def wrapped(*args, **kwargs):
            guard()
            if not logged_in():
                return jsonify(error="Please sign in again."), 401
            if request.method != "GET":
                csrf()
            return fn(*args, **kwargs)
        return wrapped

    def audit(action, target):
        store.record_audit(action, target)

    @bp.get("/")
    @bp.get("/admin")
    def dashboard():
        return render_template("admin.html")

    @bp.get("/admin/api/session")
    def state():
        guard()
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        return {"authenticated": logged_in(), "csrf": session["csrf"], "username": username if logged_in() else ""}

    @bp.post("/admin/api/login")
    def login():
        guard()
        csrf()
        now = int(time.time())
        bucket = "admin:" + hashlib.sha256((request.remote_addr or "unknown").encode()).hexdigest() + ":" + str(now // 300)
        count = store.increment_limit(bucket, now + 600)
        if count > 10:
            return jsonify(error="Too many attempts. Retry in five minutes."), 429
        body = request.get_json()
        password = body.get("password", "")
        if not isinstance(password, str) or len(password) > 512 or not secrets.compare_digest(str(body.get("username", "")), username) or not check_password_hash(password_hash, password):
            return jsonify(error="Incorrect username or password."), 401
        session.clear()
        session.update(owner=True, login_time=now, credential_version=credential_version, csrf=secrets.token_urlsafe(32))
        audit("admin_login", username)
        return {"ok": True, "csrf": session["csrf"]}

    @bp.post("/admin/api/logout")
    @owner
    def logout():
        session.clear()
        return {"ok": True}

    @bp.get("/admin/api/overview")
    @owner
    def overview():
        now = int(time.time())
        devices, groups, grants, events = store.overview_rows()
        for device in devices:
            device["features"] = json.loads(device["features"])
            device["groups"] = [g["group_id"] for g in grants if g["device"] == device["id"]]
            device["status"] = "revoked" if device["revoked"] else "pending" if device["expires"] == 0 else "expired" if device["expires"] <= now else "active"
            device["online"] = device["active_until"] > now and device["status"] == "active"
        all_jobs = []
        with jobs.lock:
            device_ids = {j["device"] for j in jobs.jobs.values()}
        for device in device_ids:
            all_jobs.extend(dict(job, device=device) for job in jobs.status(device))
        key = store.signer.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return {"devices": devices, "groups": groups, "jobs": all_jobs, "audit": events,
                "features": sorted(FEATURES), "server_public_key": b64(key), "server_time": now}

    @bp.post("/admin/api/devices/<device>/subscription")
    @owner
    def subscription(device):
        body = request.get_json()
        features, days = body.get("features"), body.get("days")
        if not isinstance(features, list) or any(not isinstance(f, str) for f in features) or not features or not set(features) <= FEATURES or type(days) is not int or not 1 <= days <= 3660:
            raise Denied("Choose valid features and 1–3660 days.")
        # Dependencies make the chosen feature usable without silently granting unrelated extras.
        selected = set(features)
        if selected & {"music", "effects", "audio_target"}:
            selected.add("audio")
        if selected & {"audio", "multi_account", "audio_target", "ktv"}:
            selected.add("room")
        store.set_subscription(device, selected, days, body.get("extend") is True)
        jobs.stop(device)
        audit("subscription_extended" if body.get("extend") is True else "subscription_granted", device)
        return {"ok": True}

    @bp.post("/admin/api/devices/<device>/revoke")
    @owner
    def revoke(device):
        store.revoke_device(device)
        jobs.stop(device)
        audit("subscription_revoked", device)
        return {"ok": True}

    @bp.post("/admin/api/devices/<device>/groups")
    @owner
    def assignments(device):
        selected = request.get_json().get("groups")
        if not isinstance(selected, list) or len(selected) > 100 or any(not isinstance(g, str) for g in selected):
            raise Denied("Invalid groups.")
        store.assign_groups(device, selected)
        jobs.stop(device)
        audit("groups_assigned", device)
        return {"ok": True}

    @bp.post("/admin/api/groups")
    @owner
    def upload():
        file = request.files.get("accounts")
        if file is None:
            raise Denied("Choose an accounts JSON file.")
        try:
            accounts = json.loads(file.read().decode("utf-8-sig"))
        except Exception:
            raise Denied("Invalid JSON file.") from None
        group = request.form.get("id", "")
        # Replacing an assigned group must not leave old credentials running in workers.
        with jobs.lock:
            if any(j["running"] and j["group"] == group for j in jobs.jobs.values()):
                raise Denied("Stop jobs using this group before replacing its file.")
        result = store.import_group(group, request.form.get("name", ""), accounts)
        audit("group_uploaded", group)
        return result

    @bp.post("/admin/api/jobs/stop")
    @owner
    def stop():
        body = request.get_json()
        device = body.get("device")
        if not isinstance(device, str):
            raise Denied("Invalid device.")
        jobs.stop(device, body.get("panel"))
        audit("jobs_stopped", device)
        return {"ok": True}

    app.register_blueprint(bp)
