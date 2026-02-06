from flask import Flask, request, render_template, redirect, url_for, flash
from datetime import datetime
import os, time, random

#Setting Application
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'change-this-in-production')

# Fix for getting real IP behind nginx proxy
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# Security headers to make it look more real
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# We check if the logs directory exists otherwise nothing gets logged
os.makedirs("logs", exist_ok=True)

# The app.py runs on every HTML page
@app.route("/")
def index():
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    ip_address = request.remote_addr
    user_agent = request.headers.get("User-Agent")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    is_bot = False
    if user_agent:
        ua_lower = user_agent.lower()
        if any(bot in ua_lower for bot in ["curl", "python", "wget", "scanner", "bot", "scraper"]):
            is_bot = True

    log_entry = (
        f"[{timestamp}] "
        f"IP: {ip_address} | "
        f"Username: {username} | "
        f"Password: {password} | "
        f"UA: {user_agent} | "
        f"Bot: {is_bot}\n"
    )

    # Error messages that Credit Bank Union would generate
    error_messages = [
        "We don't recognize that username or password. Please try again.",
        "Your username or password is incorrect. Please try again.",
        "Sign on failed. Please verify your username and password.",
        "We're unable to sign you on. Please check your credentials and try again.",
    ]

    with open("logs/attacks.log", "a") as f:
        f.write(log_entry)

    # Realistic delay to simulate the server processing
    time.sleep(random.uniform(1.2, 2.5))

    # Returns a fake failure message when trying to login
    flash(random.choice(error_messages), "error")
    return redirect(url_for("index"))

# The initialization
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
