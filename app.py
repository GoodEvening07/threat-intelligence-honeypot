from flask import Flask, request, render_template, redirect, url_for, flash, Response
from datetime import datetime, timedelta
from functools import wraps
import os, time, random, re, threading

try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

try:
    import requests as http
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "supersecretkey")

ADMIN_PREFIX = os.environ.get("ADMIN_PREFIX", "changeme")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(BASE_DIR, "logs", "attacks.log")
GEOIP_DB = os.path.join(BASE_DIR, "geoip", "GeoLite2-City.mmdb")

BOT_SIGNALS = ["curl", "python", "wget", "scanner", "bot", "scrapper", "go-http-client"]

os.makedirs(os.path.join(BASE_DIR, "logs"), exist_ok=True)

# --- Auth ---

def _check_auth(username, password):
    return username == "admin" and password == os.environ.get("ADMIN_PASSWORD", "CHANGE_ME")

def _deny():
    return Response("Authentication required", 401, {"WWW-Authenticate": 'Basic realm="Admin"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not _check_auth(auth.username, auth.password):
            return _deny()
        return f(*args, **kwargs)
    return decorated

# --- Geolocation ---

def get_location(ip):
    if not GEOIP_AVAILABLE or not os.path.exists(GEOIP_DB):
        return "Unknown", "Unknown"
    try:
        with geoip2.database.Reader(GEOIP_DB) as reader:
            r = reader.city(ip)
            return r.country.name or "Unknown", r.city.name or "Unknown"
    except Exception:
        return "Unknown", "Unknown"

# --- Map data (lat/lon per unique IP, batched GeoIP read) ---

def get_map_data(entries):
    if not GEOIP_AVAILABLE or not os.path.exists(GEOIP_DB):
        return []
    ip_stats = {}
    for e in entries:
        ip = e["ip"]
        if ip not in ip_stats:
            ip_stats[ip] = {"count": 0, "bots": 0}
        ip_stats[ip]["count"] += 1
        if e["is_bot"]:
            ip_stats[ip]["bots"] += 1
    points = {}
    try:
        with geoip2.database.Reader(GEOIP_DB) as reader:
            for ip, stats in ip_stats.items():
                try:
                    r = reader.city(ip)
                    lat, lon = r.location.latitude, r.location.longitude
                    if not lat or not lon:
                        continue
                    key = f"{round(lat, 1)},{round(lon, 1)}"
                    if key not in points:
                        points[key] = {
                            "lat": lat, "lon": lon,
                            "country": r.country.name or "Unknown",
                            "city": r.city.name or "Unknown",
                            "count": 0, "bots": 0,
                        }
                    points[key]["count"] += stats["count"]
                    points[key]["bots"] += stats["bots"]
                except Exception:
                    pass
    except Exception:
        pass
    return list(points.values())

# --- Splunk ---

def _splunk_send(data):
    url = os.environ.get("SPLUNK_HEC_URL")
    token = os.environ.get("SPLUNK_HEC_TOKEN")
    if not url or not token or not REQUESTS_AVAILABLE:
        return

    def _post():
        try:
            http.post(
                url,
                json={"event": data, "sourcetype": "honeypot"},
                headers={"Authorization": f"Splunk {token}"},
                timeout=5,
                verify=False,
            )
        except Exception:
            pass

    threading.Thread(target=_post, daemon=True).start()

# --- Log parsing (supports old format without Country/City) ---

_LOG_NEW = re.compile(
    r"\[(?P<ts>[^\]]+)\] IP: (?P<ip>[\d.a-fA-F:]+) \| "
    r"Username: (?P<user>.*?) \| Password: (?P<pw>.*?) \| "
    r"Country: (?P<country>.*?) \| City: (?P<city>.*?) \| "
    r"UA: (?P<ua>.*?) \| Bot: (?P<bot>True|False)"
)
_LOG_OLD = re.compile(
    r"\[(?P<ts>[^\]]+)\] IP: (?P<ip>[\d.a-fA-F:]+) \| "
    r"Username: (?P<user>.*?) \| Password: (?P<pw>.*?) \| "
    r"UA: (?P<ua>.*?) \| Bot: (?P<bot>True|False)"
)

def parse_logs():
    entries = []
    try:
        with open(LOG_PATH, "r") as f:
            for line in f:
                line = line.strip()
                m = _LOG_NEW.match(line) or _LOG_OLD.match(line)
                if not m:
                    continue
                d = m.groupdict()
                entries.append({
                    "timestamp": d["ts"],
                    "ip": d["ip"],
                    "username": d["user"],
                    "country": d.get("country", "Unknown") or "Unknown",
                    "city": d.get("city", "Unknown") or "Unknown",
                    "ua": d["ua"],
                    "is_bot": d["bot"] == "True",
                })
    except FileNotFoundError:
        pass
    return entries

# --- Security headers ---

@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

# --- Public routes ---

@app.route("/")
def index():
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    ip_address = request.remote_addr
    user_agent = request.headers.get("User-Agent", "")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    is_bot = not username or not password
    if not is_bot and user_agent:
        is_bot = any(sig in user_agent.lower() for sig in BOT_SIGNALS)

    country, city = get_location(ip_address)

    log_entry = (
        f"[{timestamp}] IP: {ip_address} | Username: {username} | Password: {password} | "
        f"Country: {country} | City: {city} | UA: {user_agent} | Bot: {is_bot}\n"
    )

    with open(LOG_PATH, "a") as f:
        f.write(log_entry)

    _splunk_send({
        "timestamp": timestamp,
        "ip": ip_address,
        "username": username,
        "country": country,
        "city": city,
        "user_agent": user_agent,
        "is_bot": is_bot,
    })

    time.sleep(random.uniform(1.2, 2.5))
    flash(random.choice([
        "We don't recognize that username or password. Please try again.",
        "Your username or password is incorrect. Please try again.",
        "Sign on failed. Please verify your username and password.",
        "We're unable to sign you on. Please check your credentials and try again.",
    ]), "error")
    return redirect(url_for("index"))

# --- Admin routes ---

@app.route(f"/admin-{ADMIN_PREFIX}/dashboard")
@requires_auth
def dashboard():
    entries = parse_logs()
    total = len(entries)
    unique_ips = len(set(e["ip"] for e in entries))
    bot_count = sum(1 for e in entries if e["is_bot"])
    human_count = total - bot_count
    bot_pct = round(bot_count / total * 100, 1) if total else 0

    ip_counts = {}
    for e in entries:
        ip_counts[e["ip"]] = ip_counts.get(e["ip"], 0) + 1
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    today = datetime.now().date()
    timeline = {(today - timedelta(days=i)).strftime("%Y-%m-%d"): 0 for i in range(6, -1, -1)}
    for e in entries:
        day = e["timestamp"][:10]
        if day in timeline:
            timeline[day] += 1

    return render_template(
        "dashboard.html",
        total=total,
        unique_ips=unique_ips,
        bot_count=bot_count,
        human_count=human_count,
        bot_pct=bot_pct,
        human_pct=round(100 - bot_pct, 1) if total else 0,
        top_ips=top_ips,
        recent=list(reversed(entries[-10:])),
        timeline_labels=list(timeline.keys()),
        timeline_data=list(timeline.values()),
        map_data=get_map_data(entries),
        entries=entries,
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
