# 🎣 Threat Intelligence Honeypot

A production-grade credential harvesting honeypot that mimics an online banking portal to capture real-world credential stuffing attacks, botnet activity, and authentication-based threats.

![Python](https://img.shields.io/badge/Python-3.12-blue)
![Flask](https://img.shields.io/badge/Flask-3.0-green)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Status](https://img.shields.io/badge/Status-Active-success)

## 📊 Project Stats

- **5+ attacks** captured in the first 72 hours.
- **3+ unique IPs** from 4 countries.
- **20+ login attempts** analyzed.
- **40% bot traffic** vs human attackers.
- **99.99% uptime** achieved.

## 🎯 Overview

This honeypot was built to:
- Capture real-world credential stuffing attacks.
- Analyze attacker behavior patterns.
- Collect threat intelligence on botnet activity.
- Learn production security infrastructure deployment.

### Key Features
- Realistic Bank login portal.
- HTTPS with SSL/TLS encryption.
- Comprehensive attack logging (IP, credentials, user-agent, timestamp).
- Bot detection via user-agent analysis.
- Python-based log analytics engine.
- Security hardened infrastructure.
- Production-ready deployment.

## 🏗️ Architecture

```
Internet Traffic
    ↓
UFW Firewall
    ↓
Nginx Reverse Proxy
    ↓
Gunicorn WSGI Server
    ↓
Flask Application
    ↓
attacks.log
```

### Technology Stack

**Backend:**
- Python 3.12
- Flask (web framework)
- Gunicorn (WSGI server)
- Werkzeug ProxyFix (IP preservation)

**Frontend:**
- HTML5/CSS3
- Responsive design
- JavaScript

**Infrastructure:**
- Ubuntu 24.04 LTS
- Nginx (reverse proxy)
- Let's Encrypt (SSL/TLS)
- UFW firewall
- Systemd (service management)

## 🚀 Quick Start

### Prerequisites
- Ubuntu 24.04 LTS
- Python 3.12+
- pip3
- nginx

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/threat-intelligence-honeypot.git
cd threat-intelligence-honeypot
```

2. **Set up Python environment**
```bash
python3 -m venv venv
source venv/bin/activate
pip install flask gunicorn
```

3. **Set environment variable **
```bash
export FLASK_SECRET_KEY='your-super-secret-random-key-here'
```

4. **Run locally for testing**
```bash
python app.py
```

Search for `http://localhost:5000` to test the honeypot.

## 🔒 Production Deployment

### 1. Set Up Systemd Service

Create `/etc/systemd/system/honeypot.service`:

```ini
[Unit]
Description=Threat Intelligence Honeypot
After=network.target

[Service]
User=root
WorkingDirectory=/path/to/honeypot
Environment="PATH=/path/to/honeypot/venv/bin"
Environment="FLASK_SECRET_KEY=your-secret-key-here"
ExecStart=/path/to/honeypot/venv/bin/gunicorn --workers 2 --bind 127.0.0.1:5000 app:app
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable honeypot
sudo systemctl start honeypot
```

### 2. Configure Nginx

Create `/etc/nginx/sites-available/honeypot`:

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable:
```bash
sudo ln -s /etc/nginx/sites-available/honeypot /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### 3. Add SSL/TLS (Optional but Recommended)

```bash
sudo apt install certbot python3-certbot-nginx -y
sudo certbot --nginx -d your-domain.com
```

### 4. Configure Firewall

```bash
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

## 📊 Log Analysis

Run the analytics script to view attack statistics:

```bash
python analyze_logs.py
```

### Sample Output
```
============================================================
HONEYPOT ATTACK ANALYSIS
============================================================

- Total Login Attempts: 25
- Unique IP Addresses: 15
- Bot Attempts: 15 (60.0%)
- First Attack: 2026-02-04 20:55
- Last Attack: 2026-02-05 18:31

------------------------------------------------------------
 TOP 10 MOST ACTIVE IPs
------------------------------------------------------------
  45.xxx.xxx.xxx       -    5 attempts
  103.xxx.xxx.xxx      -    3 attempts
  ...
```

### Export to CSV

The script can export data to CSV for further analysis in Excel or other tools.

## 🛡️ Security Features

- **Firewall Rules:** UFW configured for minimal attack surface.
- **SSH Hardening:** Key-based authentication only.
- **Reverse Proxy:** Nginx isolates Flask application.
- **SSL/TLS:** Encrypted traffic with Let's Encrypt.
- **Security Headers:** X-Frame-Options, CSP, XSS Protection.
- **Bot Detection:** User-agent analysis.
- **Rate Limiting:** Built-in delays prevent log flooding.

## 📈 Projected Attack Discovery

How attackers find this honeypot:

- **Hours 1-6:** Initial port scans.
- **Hours 6-24:** First login attempts from bots.
- **Day 2-3:** Multiple IPs attempting credential stuffing.

### Discovery Mechanisms
1. **Mass IP Scanning** - Masscan, ZMap scanning port 80/443.
2. **Certificate Transparency Logs** - SSL certificate indexed publicly.
3. **Search Engines** - Shodan, Censys, ZoomEye.
4. **Login Page Fingerprinting** - Bots detect authentication forms.

## 📚 What I Learned

### Technical Skills
- Cloud infrastructure deployment (VPS).
- Linux system administration.
- Nginx reverse proxy configuration.
- SSL/TLS certificate management.
- Python Flask development.
- Systemd service management.
- Firewall configuration (UFW).
- Log analysis and data parsing.

### Security Concepts
- How attackers discover targets.
- Botnet behavior patterns.
- Credential stuffing methodologies.
- Threat intelligence collection.
- Attack pattern recognition.
- Security operations workflows.

## 🎓 Use Cases

This project demonstrates skills relevant to:
- **SOC Analyst** - Log analysis, threat detection.
- **Security Engineer** - Infrastructure hardening, deployment.
- **Threat Intelligence Analyst** - Attack pattern analysis.
- **Incident Response** - Attack investigation, forensics.
- **Security Researcher** - Honeypot design, data collection.

## ⚠️ Disclaimer

**Educational and Research Purposes Only**

This honeypot is designed for:
- Learning cybersecurity concepts.
- Threat intelligence research.
- Security operations training.
- Understanding attacker methodologies.

**Important:**
- Deploy on isolated infrastructure only.
- Never use with real credentials or sensitive data!
- Ensure compliance with local laws and regulations.
- Use responsibly and ethically.

## 📝 Project Structure

```
threat-intelligence-honeypot/
├── app.py                  # Flask application
├── analyze_logs.py         # Log analysis script
├── templates/
│   └── login.html         # Honeypot login page
├── static/
│   └── style.css          # Wells Fargo styling
├── logs/
│   └── attacks.log        # Attack logs (auto-created)
├── requirements.txt       # Python dependencies
└── README.md             # This file
```

## 🔧 Configuration

### Environment Variables

- `FLASK_SECRET_KEY` - Secret key for Flask sessions (REQUIRED in production)

---
Built by Gabriel Hernandez as part of hands-on cybersecurity learning.
