import os, json, uuid, time
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from functools import wraps
from flask import (
    Flask, request, jsonify, render_template,
    session, redirect, url_for, flash, send_file
)
import requests
from dotenv import load_dotenv

load_dotenv()

# ==================== CONFIGURATION ====================
class Config:
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")
    SECRET_KEY = os.getenv("SECRET_KEY", "change-me-to-a-random-string")
    TIMEZONE = os.getenv("TIMEZONE", "Asia/Karachi")  # fallback if geolocation fails
    DEBUG = os.getenv("DEBUG", "False").lower() == "true"
    PORT = int(os.getenv("PORT", 5000))
    API_KEYS_FILE = os.path.join(os.path.dirname(__file__), "data", "api_keys.json")
    AUDIT_LOG_MAX = 100
    DEFAULT_RATE_LIMIT = 500  # requests per minute per key
    SESSION_TIMEOUT = 15 * 60  # seconds

app = Flask(__name__)
app.config["SECRET_KEY"] = Config.SECRET_KEY
app.config["JSONIFY_PRETTYPRINT_REGULAR"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(seconds=Config.SESSION_TIMEOUT)

os.makedirs(os.path.dirname(Config.API_KEYS_FILE), exist_ok=True)

# ==================== IN-MEMORY STRUCTURES ====================
rate_limit_data = {}   # key -> list of timestamps (per-key rate limiter)
ip_tz_cache = {}       # ip -> timezone string (reduce geolocation API calls)

# ==================== DATABASE HELPERS ====================
def load_db():
    try:
        with open(Config.API_KEYS_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"keys": {}, "proxies": {}, "audit_log": []}

def save_db(data):
    with open(Config.API_KEYS_FILE, "w") as f:
        json.dump(data, f, indent=2)

def add_audit(action, details=""):
    db = load_db()
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "details": details,
        "ip": request.remote_addr if request else "unknown"
    }
    db.setdefault("audit_log", []).insert(0, entry)
    db["audit_log"] = db["audit_log"][:Config.AUDIT_LOG_MAX]
    save_db(db)

# ==================== TIMEZONE DETECTION ====================
def get_user_timezone(ip):
    # Check cache first
    if ip in ip_tz_cache:
        return ip_tz_cache[ip]
    # Try free ipapi.co (rate limit 1000/day)
    try:
        resp = requests.get(f"https://ipapi.co/{ip}/json/", timeout=3)
        if resp.status_code == 200:
            tz = resp.json().get("timezone")
            if tz:
                ip_tz_cache[ip] = tz
                return tz
    except:
        pass
    # Fallback to configured timezone
    return Config.TIMEZONE

def get_localized_time(tz_str):
    utc_now = datetime.now(timezone.utc)
    try:
        local_tz = ZoneInfo(tz_str)
        local_dt = utc_now.astimezone(local_tz)
        return local_dt.strftime("%Y-%m-%d %H:%M:%S %Z"), local_dt.timestamp(), tz_str
    except:
        local_tz = ZoneInfo(Config.TIMEZONE)
        local_dt = utc_now.astimezone(local_tz)
        return local_dt.strftime("%Y-%m-%d %H:%M:%S %Z"), local_dt.timestamp(), Config.TIMEZONE

# ==================== NUMBER VALIDATION ====================
def validate_number(number: str):
    if len(number) == 10:
        if not number.startswith("03") or not number.isdigit():
            return False, "Mobile must be 10-digit starting with 03"
        return True, "sim"
    elif len(number) == 13:
        if not number.isdigit():
            return False, "CNIC must be 13 digits numeric"
        return True, "cnic"
    return False, "Must be 10-digit mobile or 13-digit CNIC"

# ==================== UPSTREAM LOOKUP ====================
def perform_lookup(number, query_type):
    form_data = {
        'post_id': '413',
        'form_id': '5e17544',
        'referer_title': 'Search SIM and CNIC Details - Instant Ownership Check',
        'queried_id': '413',
        'form_fields[search]': number,
        'action': 'elementor_pro_forms_send_form',
        'referrer': 'https://simownership.com/search/'
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'X-Requested-With': 'XMLHttpRequest',
        'Origin': 'https://simownership.com',
        'Referer': 'https://simownership.com/search/',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    try:
        resp = requests.post(
            'https://simownership.com/wp-admin/admin-ajax.php',
            headers=headers,
            data=form_data,
            timeout=30
        )
        if resp.status_code == 200:
            api_data = resp.json()
            if api_data.get('success') and api_data.get('data', {}).get('data', {}).get('results'):
                return {'success': True, 'results': api_data['data']['data']['results']}
            else:
                return {'success': False, 'error': 'No records found'}
        else:
            return {'success': False, 'error': f'Upstream status {resp.status_code}'}
    except Exception as e:
        return {'success': False, 'error': str(e)}

# ==================== AUTH DECORATOR ====================
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin_logged_in"):
            flash("Please log in first.", "warning")
            return redirect(url_for("login_page"))
        last_activity = session.get("last_activity")
        if last_activity and (time.time() - last_activity > Config.SESSION_TIMEOUT):
            session.pop("admin_logged_in", None)
            flash("Session expired. Please log in again.", "warning")
            return redirect(url_for("login_page"))
        session["last_activity"] = time.time()
        return f(*args, **kwargs)
    return decorated

# ==================== PUBLIC API ROUTES ====================
@app.route("/api", methods=["GET", "POST"])
def api_search():
    if request.method == "GET":
        api_key = request.args.get("key", "").strip()
        number = request.args.get("number", "").strip()
        tz_param = request.args.get("tz", "").strip()
    else:  # POST
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"success": False, "error": "Invalid JSON"}), 400
        api_key = data.get("key", "").strip()
        number = data.get("number", "").strip()
        tz_param = data.get("tz", "").strip()

    db = load_db()
    if not api_key or api_key not in db["keys"]:
        return jsonify({"success": False, "error": "Invalid API key"}), 401

    key_info = db["keys"][api_key]
    # Active check
    if not key_info.get("active", True):
        return jsonify({"success": False, "error": "API key is disabled"}), 403
    # Expiry check
    expiry = key_info.get("expiry")
    if expiry:
        try:
            exp_dt = datetime.fromisoformat(expiry)
            if datetime.now(timezone.utc) > exp_dt:
                return jsonify({"success": False, "error": "API key has expired"}), 403
        except:
            pass
    # Per-key rate limiting
    rate_limit = key_info.get("rate_limit", Config.DEFAULT_RATE_LIMIT)
    now = time.time()
    if api_key not in rate_limit_data:
        rate_limit_data[api_key] = []
    rate_limit_data[api_key] = [t for t in rate_limit_data[api_key] if now - t < 60]
    if len(rate_limit_data[api_key]) >= rate_limit:
        return jsonify({"success": False, "error": f"Rate limit exceeded ({rate_limit}/min)"}), 429
    rate_limit_data[api_key].append(now)

    if not number:
        return jsonify({"success": False, "error": "Parameter 'number' required"}), 400

    valid, qtype = validate_number(number)
    if not valid:
        return jsonify({"success": False, "error": qtype}), 400

    # Determine timezone
    if tz_param:
        tz_str = tz_param
    else:
        ip = request.remote_addr
        tz_str = get_user_timezone(ip)

    result = perform_lookup(number, qtype)
    datetime_str, epoch, used_tz = get_localized_time(tz_str)

    # Update usage stats
    db = load_db()
    if api_key in db["keys"]:
        usage = db["keys"][api_key].setdefault("usage", {})
        usage["total"] = usage.get("total", 0) + 1
        today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        if usage.get("date") != today_str:
            usage["today"] = 1
            usage["date"] = today_str
        else:
            usage["today"] = usage.get("today", 0) + 1
        usage["last_used"] = datetime.now(timezone.utc).isoformat()
        save_db(db)

    add_audit("api_call", f"key={api_key} number={number} type={qtype} success={result['success']}")

    if result["success"]:
        return jsonify({
            "success": True,
            "number": number,
            "type": qtype,
            "results": result["results"],
            "count": len(result["results"]),
            "timestamp": epoch,
            "datetime": datetime_str,
            "timezone": used_tz,
            "utc_timestamp": datetime.now(timezone.utc).timestamp()
        })
    else:
        return jsonify(result), 404 if "No records" in result.get("error", "") else 503

@app.route("/api/proxy/<endpoint>", methods=["GET"])
def api_proxy(endpoint):
    db = load_db()
    if endpoint not in db.get("proxies", {}):
        return jsonify({"success": False, "error": "Proxy endpoint not found"}), 404

    proxy = db["proxies"][endpoint]
    key = request.args.get("key", "").strip()
    if key != proxy.get("key"):
        return jsonify({"success": False, "error": "Invalid proxy key"}), 401

    number = request.args.get("number", "").strip()
    tz_param = request.args.get("tz", "").strip()

    # Use the main key associated with this proxy for rate limiting & usage stats
    main_key = proxy.get("key")
    if main_key in db["keys"]:
        k_info = db["keys"][main_key]
        if not k_info.get("active", True):
            return jsonify({"success": False, "error": "Proxy key is disabled"}), 403
        if k_info.get("expiry"):
            try:
                exp_dt = datetime.fromisoformat(k_info["expiry"])
                if datetime.now(timezone.utc) > exp_dt:
                    return jsonify({"success": False, "error": "Proxy key has expired"}), 403
            except:
                pass
        rate_limit = k_info.get("rate_limit", Config.DEFAULT_RATE_LIMIT)
        now = time.time()
        if main_key not in rate_limit_data:
            rate_limit_data[main_key] = []
        rate_limit_data[main_key] = [t for t in rate_limit_data[main_key] if now - t < 60]
        if len(rate_limit_data[main_key]) >= rate_limit:
            return jsonify({"success": False, "error": f"Rate limit exceeded ({rate_limit}/min)"}), 429
        rate_limit_data[main_key].append(now)

    if not number:
        return jsonify({"success": False, "error": "Parameter 'number' required"}), 400
    valid, qtype = validate_number(number)
    if not valid:
        return jsonify({"success": False, "error": qtype}), 400

    if tz_param:
        tz_str = tz_param
    else:
        tz_str = get_user_timezone(request.remote_addr)

    result = perform_lookup(number, qtype)
    datetime_str, epoch, used_tz = get_localized_time(tz_str)

    add_audit("proxy_call", f"proxy={endpoint} number={number} success={result['success']}")

    if result["success"]:
        return jsonify({
            "success": True,
            "number": number,
            "type": qtype,
            "results": result["results"],
            "count": len(result["results"]),
            "timestamp": epoch,
            "datetime": datetime_str,
            "timezone": used_tz,
            "utc_timestamp": datetime.now(timezone.utc).timestamp()
        })
    else:
        return jsonify(result), 404 if "No records" in result.get("error", "") else 503

@app.route("/api/health")
def api_health():
    return jsonify({"status": "ok"})

@app.route("/api/docs")
def api_docs():
    return jsonify({
        "name": "Pakistan Number Info API v4 (Advanced)",
        "usage": {
            "main": "/api?key=YOUR_KEY&number=03XXXXXXXXX",
            "optional_tz": "/api?key=YOUR_KEY&number=03XXXXXXXXX&tz=Europe/Berlin",
            "proxy": "/api/proxy/{endpoint}?key=PROXY_KEY&number=03XXXXXXXXX"
        },
        "admin": "/admin"
    })

# ==================== ADMIN AUTH ====================
@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "POST":
        if request.form.get("password") == Config.ADMIN_PASSWORD:
            session["admin_logged_in"] = True
            session["last_activity"] = time.time()
            add_audit("admin_login", "success")
            flash("Login successful", "success")
            return redirect(url_for("admin_dashboard"))
        add_audit("admin_login", "failed")
        flash("Incorrect password", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("admin_logged_in", None)
    flash("Logged out.", "info")
    return redirect(url_for("login_page"))

# ==================== ADMIN DASHBOARD ====================
@app.route("/admin")
@login_required
def admin_dashboard():
    db = load_db()
    keys = db.get("keys", {})
    proxies_count = len(db.get("proxies", {}))
    active_keys = sum(1 for k in keys.values() if k.get("active", True))

    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    # Count today's API calls from audit log
    audit = db.get("audit_log", [])
    today_api_calls = 0
    for entry in audit:
        if "api_call" in entry["action"] and entry["timestamp"].startswith(today_str):
            today_api_calls += 1

    # System info (optional, tries to import psutil)
    sys_info = {}
    try:
        import psutil
        sys_info["memory"] = psutil.virtual_memory().percent
        sys_info["disk"] = psutil.disk_usage('/').percent
        sys_info["uptime_seconds"] = time.time() - psutil.boot_time()
    except:
        pass

    return render_template("dashboard.html",
                           keys_count=len(keys),
                           active_keys=active_keys,
                           proxies_count=proxies_count,
                           today_calls=today_api_calls,
                           sys_info=sys_info)

# ==================== KEY MANAGEMENT ====================
@app.route("/admin/keys", methods=["GET"])
@login_required
def admin_keys():
    search = request.args.get("search", "").strip().lower()
    db = load_db()
    keys = db.get("keys", {})
    if search:
        keys = {k: v for k, v in keys.items() if search in k.lower() or search in v.get("name", "").lower()}
    return render_template("keys.html", keys=keys, search=search)

@app.route("/admin/keys/add", methods=["POST"])
@login_required
def add_key():
    db = load_db()
    new_key = str(uuid.uuid4())[:12].upper()
    name = request.form.get("name", "Unnamed").strip()
    active = request.form.get("active", "1") == "1"
    rate_limit = int(request.form.get("rate_limit", Config.DEFAULT_RATE_LIMIT))
    expiry = request.form.get("expiry", "").strip()
    db["keys"][new_key] = {
        "name": name,
        "active": active,
        "rate_limit": rate_limit,
        "expiry": expiry if expiry else None,
        "created": datetime.now(timezone.utc).isoformat(),
        "usage": {"total": 0, "today": 0, "last_used": None}
    }
    save_db(db)
    add_audit("key_added", f"key={new_key} name={name}")
    flash(f"Key generated: <code>{new_key}</code>", "success")
    return redirect(url_for("admin_keys"))

@app.route("/admin/keys/delete/<key>", methods=["POST"])
@login_required
def delete_key(key):
    db = load_db()
    if key in db["keys"]:
        del db["keys"][key]
        save_db(db)
        add_audit("key_deleted", f"key={key}")
        flash("Key deleted.", "info")
    return redirect(url_for("admin_keys"))

@app.route("/admin/keys/edit/<key>", methods=["GET", "POST"])
@login_required
def edit_key(key):
    db = load_db()
    if key not in db["keys"]:
        flash("Key not found", "danger")
        return redirect(url_for("admin_keys"))
    if request.method == "POST":
        kdata = db["keys"][key]
        kdata["name"] = request.form.get("name", kdata["name"]).strip()
        kdata["active"] = request.form.get("active", "1") == "1"
        kdata["rate_limit"] = int(request.form.get("rate_limit", kdata.get("rate_limit", Config.DEFAULT_RATE_LIMIT)))
        expiry = request.form.get("expiry", "").strip()
        kdata["expiry"] = expiry if expiry else None
        save_db(db)
        add_audit("key_edited", f"key={key}")
        flash("Key updated.", "success")
        return redirect(url_for("admin_keys"))
    return render_template("edit_key.html", key=key, key_data=db["keys"][key])

@app.route("/admin/keys/toggle/<key>", methods=["POST"])
@login_required
def toggle_key(key):
    db = load_db()
    if key in db["keys"]:
        db["keys"][key]["active"] = not db["keys"][key].get("active", True)
        save_db(db)
        add_audit("key_toggle", f"key={key} active={db['keys'][key]['active']}")
    return redirect(url_for("admin_keys"))

# ==================== PROXY MANAGEMENT ====================
@app.route("/admin/proxy", methods=["GET", "POST"])
@login_required
def admin_proxy():
    db = load_db()
    if request.method == "POST":
        if "delete_proxy" in request.form:
            ep = request.form.get("endpoint")
            if ep in db.get("proxies", {}):
                proxy_key = db["proxies"][ep]["key"]
                del db["proxies"][ep]
                if proxy_key in db.get("keys", {}):
                    del db["keys"][proxy_key]
                save_db(db)
                add_audit("proxy_deleted", f"endpoint={ep}")
                flash("Proxy deleted.", "info")
        else:
            endpoint = request.form.get("endpoint", "").strip().lower()
            if not endpoint.isalnum():
                flash("Endpoint must contain only letters and numbers.", "danger")
            elif endpoint in db.get("proxies", {}):
                flash("Endpoint already exists.", "danger")
            else:
                proxy_key = str(uuid.uuid4())[:12].upper()
                note = request.form.get("note", "").strip()
                db["proxies"][endpoint] = {
                    "key": proxy_key,
                    "created": datetime.now(timezone.utc).isoformat(),
                    "note": note
                }
                db["keys"][proxy_key] = {
                    "name": f"Proxy /{endpoint}",
                    "active": True,
                    "rate_limit": Config.DEFAULT_RATE_LIMIT,
                    "expiry": None,
                    "created": datetime.now(timezone.utc).isoformat(),
                    "usage": {"total": 0, "today": 0, "last_used": None}
                }
                save_db(db)
                add_audit("proxy_created", f"endpoint={endpoint} key={proxy_key}")
                flash(f"Proxy created: <code>/api/proxy/{endpoint}</code> (key: {proxy_key})", "success")
        return redirect(url_for("admin_proxy"))
    return render_template("proxy.html", proxies=db.get("proxies", {}))

# ==================== AUDIT LOG ====================
@app.route("/admin/audit")
@login_required
def admin_audit():
    db = load_db()
    audit = db.get("audit_log", [])
    return render_template("audit.html", audit=audit)

# ==================== BACKUP / RESTORE ====================
@app.route("/admin/backup")
@login_required
def download_backup():
    return send_file(Config.API_KEYS_FILE, as_attachment=True, download_name="api_keys_backup.json")

@app.route("/admin/restore", methods=["GET", "POST"])
@login_required
def restore_backup():
    if request.method == "POST":
        file = request.files.get("backup_file")
        if file and file.filename.endswith(".json"):
            try:
                data = json.load(file)
                if "keys" in data and "proxies" in data:
                    save_db(data)
                    flash("Database restored successfully.", "success")
                    add_audit("db_restored")
                else:
                    flash("Invalid backup file format.", "danger")
            except:
                flash("Error reading file.", "danger")
        else:
            flash("Please upload a .json file.", "danger")
        return redirect(url_for("restore_backup"))
    return render_template("restore.html")

# ==================== ERROR HANDLERS ====================
@app.errorhandler(404)
def not_found(e):
    return jsonify({"success": False, "error": "Not found"}), 404

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=Config.PORT, debug=Config.DEBUG)
