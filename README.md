# 🛡️ Web Shield - Vulnerability Scanner

A Django-based automated web vulnerability scanner with ML risk classification.

**By:** Anish Dharu | MIT-WPU, Pune | Mini Project 2024-25

---

## 📦 Installation & Setup

### Step 1: Install dependencies
```
pip install -r requirements.txt
```

### Step 2: Run setup (migrations + ML training)
```
python setup.py
```

### Step 3: Create admin user
```
python manage.py createsuperuser
```

### Step 4: Start the server
```
python manage.py runserver
```

### Step 5: Open browser
```
http://127.0.0.1:8000
```

---

## 🔌 Scanning Modules (10 Plugins)

| Plugin | What it checks |
|--------|---------------|
| 🔒 Security Headers | HSTS, CSP, X-Frame-Options, X-Content-Type-Options |
| 🔐 SSL/TLS | Certificate validity, expiry, protocol version |
| 🌐 DNS/IP | SPF, DMARC, MX records, IP resolution |
| 🚪 Port Scanner | MySQL, Redis, MongoDB, RDP, VNC, Telnet |
| 🍪 Cookie Security | Secure, HttpOnly, SameSite flags |
| 💉 XSS Detection | Inline scripts, event handlers, URL reflection |
| 🗄️ SQL Injection | SQL error messages, suspicious parameters |
| 🎭 CSRF Analysis | Form CSRF token presence |
| 🔍 Subdomain Discovery | admin, dev, staging, api subdomains |
| 📡 Server Info | Server version, X-Powered-By disclosure |

---

## 🤖 Machine Learning

- **Model:** Logistic Regression (Scikit-learn)
- **Features:** 12 extracted security indicators
- **Classes:** Low / Medium / High / Critical
- **Training:** Run `python setup.py` or use Admin Panel → Train ML Model

---

## 🛠️ Tech Stack

- **Backend:** Python 3.x, Django 4.2
- **Database:** SQLite (default)
- **ML:** Scikit-learn, NumPy
- **PDF Reports:** ReportLab
- **Frontend:** HTML, CSS, Bootstrap 5, Chart.js
- **Scanning:** requests, socket, ssl, dnspython
