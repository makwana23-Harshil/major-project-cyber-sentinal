# CyberSentinel Pro

A unified AI-powered cybersecurity threat detection platform.

## 🚀 Quick Start

### 1. Start the Backend
```
Double-click: start.bat
```
OR manually:
```bash
cd backend
python app.py
```
Server runs at: **http://127.0.0.1:5000**

### 2. Open the Frontend
Open `frontend/index.html` in your browser (Chrome recommended).

> **Note**: Keep the backend running while using the frontend.

---

## 🔐 Default Credentials

| Role  | Email | Password | Token |
|-------|-------|----------|-------|
| Admin | `admin@cybersentinel.com` | `Admin@2024` | `Atoken` |
| User  | Register at `/register.html` | Your choice | `Utoken` |

---

## 📁 Project Structure

```
cyber-sentinel/
├── start.bat               ← Run this to start!
├── backend/
│   ├── app.py              ← Main Flask app (port 5000)
│   ├── config.py           ← Settings + API keys
│   ├── database.py         ← SQLAlchemy models
│   ├── auth/               ← JWT auth (Utoken/Atoken)
│   ├── detection/          ← ML detectors + link inspector
│   ├── models/             ← Trained ML model files (.pkl)
│   └── api/                ← REST API blueprints
└── frontend/
    ├── index.html          ← Landing page
    ├── login.html          ← Login (User + Admin tabs)
    ├── register.html       ← User registration
    ├── scan.html           ← Main 4-tab scanner
    ├── dashboard.html      ← User dashboard + charts
    ├── admin.html          ← Admin dashboard
    ├── history.html        ← Scan history
    └── assets/
        ├── css/            ← Stylesheets
        └── js/             ← JavaScript modules
```

---

## 🧠 Detection Modules

### SMS Spam Detection
- ML: TF-IDF + Multinomial Naive Bayes
- Extracts & inspects URLs from SMS

### Email Address Validation
- Syntax check (RFC 5322)
- DNS MX record lookup
- Domain age via WHOIS
- Disposable email detection (30+ domains)

### Email Body Analysis
- ML: TF-IDF + LinearSVC
- Extracts & deep-inspects all links

### URL / Phishing Detection
- ML: Gradient Boosting on 15 URL features
- **Deep Link Inspector:**
  - Follows redirect chains
  - SSL certificate validation
  - Live page content analysis
  - Phishing keyword detection
  - Brand impersonation check
  - Login form harvesting detection
  - VirusTotal API (optional)
  - Google Safe Browsing API (optional)

---

## 🔧 Configuration

Edit `backend/config.py` or create `backend/.env`:

```env
SECRET_KEY=your-secret-key
VIRUSTOTAL_API_KEY=your-vt-key
GOOGLE_SAFE_BROWSING_API_KEY=your-gsb-key
```

**VirusTotal API** (free): https://www.virustotal.com/gui/join-us  
**Google Safe Browsing** (free): https://developers.google.com/safe-browsing/

---

## 📊 Visualizations

### User Dashboard
- Scan types breakdown (donut)
- Threat verdicts (donut)
- 30-day activity (line chart)
- Recent scans table

### Admin Dashboard
- Global threat distribution
- Platform-wide activity
- Hourly heat map
- Top users by scans
- Top flagged domains
- User management table
- All scans with pagination

---

## 🔄 Migration to MongoDB

When ready to switch from SQLite to MongoDB:
1. Install `pymongo` and `flask-pymongo`
2. Update `SQLALCHEMY_DATABASE_URI` in `config.py`
3. Replace SQLAlchemy models in `database.py` with PyMongo collections

---

## 🛡️ Auth Flow

```
User Login  → POST /api/auth/login → token_name: "Utoken" → stored in localStorage
Admin Login → POST /api/auth/login → token_name: "Atoken" → stored in localStorage
Logout      → removes token from localStorage + POST /api/auth/logout
```

All protected routes require: `Authorization: Bearer <token>`
