# Credit Bank Union — Threat Intelligence Honeypot

A realistic fake bank login portal that captures and analyzes real-world credential stuffing, brute-force, and automated scanning activity in real time.

Built as a hands-on cybersecurity learning project to study attacker behavior, bot traffic patterns, and threat intelligence collection — no advertising required. Just expose an IP and watch what shows up.

![Python](https://img.shields.io/badge/Python-3.10+-blue) ![Flask](https://img.shields.io/badge/Flask-2.3+-lightgrey) ![License](https://img.shields.io/badge/License-MIT-green)

---

## Features

- **Realistic decoy** — Convincing bank login page styled as "Credit Bank Union" to attract automated scanners and manual attackers
- **Real-time logging** — Every login attempt logged with IP, credentials tried, user agent, geolocation, and bot flag
- **Admin dashboard** (password-protected) with:
  - Attack counters: total attempts, unique IPs, bot vs. human split
  - 7-day attack timeline chart
  - Interactive world map with per-location attack markers
  - IP enrichment on click — ISP, org, AS number, proxy/VPN/datacenter/mobile flags via ip-api.com (fetched browser-side, zero extra server load)
  - Full searchable log table with live filtering across all fields
- **Bot detection** — Flags automated tools by User-Agent signature (curl, wget, python-requests, scanners, etc.)
- **Geolocation** — Maps attack origins using MaxMind GeoLite2-City
- **Splunk integration** — Optional HEC forwarding for SIEM ingestion
- **Mobile responsive** — Dashboard and login page work on all screen sizes

---

## Stack

| Component     | Technology                          |
|---------------|-------------------------------------|
| Backend       | Python / Flask                      |
| WSGI server   | Gunicorn                            |
| Frontend      | Vanilla JS, Leaflet.js, Chart.js    |
| Geolocation   | MaxMind GeoLite2-City               |
| IP enrichment | ip-api.com (browser-side)           |
| Deployment    | Ubuntu 24.04, systemd service       |

---

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/GoodEvening07/threat-intelligence-honeypot.git
cd threat-intelligence-honeypot
```

### 2. Create a virtual environment and install dependencies

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Get the GeoLite2 database (optional — enables the map)

1. Create a free MaxMind account at [maxmind.com](https://www.maxmind.com/en/geolite2/signup)
2. Download `GeoLite2-City.mmdb`
3. Place it at `geoip/GeoLite2-City.mmdb`

Without this file the app still runs — the map just shows a placeholder.

### 4. Set environment variables

```bash
export FLASK_SECRET_KEY="your-random-secret-key"
export ADMIN_PASSWORD="your-strong-password"

# Optional: Splunk HEC
export SPLUNK_HEC_URL="https://your-splunk:8088/services/collector"
export SPLUNK_HEC_TOKEN="your-token"
```

### 5. Run

```bash
# Development
python app.py

# Production
gunicorn --workers 2 --bind 0.0.0.0:5000 app:app
```

### 6. Access the dashboard

Before running, change `ADMIN_PREFIX` in `app.py` to a unique random string.  
Then navigate to `/admin-{YOUR_PREFIX}/dashboard` — you'll be prompted for HTTP Basic Auth (username: `admin`, password: value of `ADMIN_PASSWORD`).

---

## Analyze Logs (CLI)

A standalone terminal script for quick analysis of captured data:

```bash
python analyze_logs.py
```

Outputs: top attacking IPs, most-tried usernames and passwords (masked), bot ratio, and hourly attack distribution bar chart.

---

## Production Deployment (VPS)

Key notes from running this on a $6/mo Vultr Ubuntu 24.04 server:

- Run behind **nginx** as a reverse proxy on port 80/443
- Firewall: only expose ports 22 (SSH), 80, 443
- Use a **systemd service** with `Restart=always` so it survives reboots
- Install geoip2 **inside the venv**: `venv/bin/pip install geoip2` — system pip won't affect the venv Python
- Keep secrets in systemd `Environment=` lines, never hardcode them

Example systemd unit (`/etc/systemd/system/honeypot.service`):

```ini
[Unit]
Description=Credit Bank Union Honeypot
After=network.target

[Service]
User=root
WorkingDirectory=/root/threat-intelligence-honeypot
Environment="PATH=/root/threat-intelligence-honeypot/venv/bin"
Environment="FLASK_SECRET_KEY=your-secret"
Environment="ADMIN_PASSWORD=your-password"
ExecStart=/root/threat-intelligence-honeypot/venv/bin/gunicorn --workers 2 --bind 127.0.0.1:5000 app:app
Restart=always

[Install]
WantedBy=multi-user.target
```

---

## What I Observed

Within hours of exposing the server (no links shared, no advertising):

- The majority of traffic was **automated bots** running credential stuffing wordlists 24/7
- Attacks originated from dozens of countries, many routing through **datacenter IPs and VPNs**
- Bot user-agents are obvious (`python-requests`, `curl`, `Go-http-client`) — manual attackers are rarer but slower and more deliberate
- Common credential pairs: `admin/admin`, `admin/123456`, `test/test`, and large rockyou-style password lists

---

## Legal & Ethics

This project is for **educational and research purposes only**. Deploy only on infrastructure you own or have explicit permission to operate. Attack logs are excluded from this repository — never publish real attacker data (IPs, credentials) publicly.

---

## License

MIT
