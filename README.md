# Hybrid Web Application Firewall — SQL Injection Detection

A Python-based security system that detects and blocks SQL injection
attacks in real time using a two-layer hybrid detection approach.

## What It Does
- Classifies incoming requests into HIGH, MEDIUM, LOW, and ML-detected threat levels
- Blocks HIGH-risk attacks instantly and temporarily blocks IPs after 3 medium-risk attempts
- Sends automated email alerts to admins on critical detections
- Provides an admin dashboard with real-time attack statistics and logs

## Tech Stack
Python | FastAPI | Logistic Regression | bcrypt | SMTP | Jinja2 | MySQL

## How to Run
pip install -r requirements.txt
uvicorn main:app --reload

Then open http://localhost:8000 in your browser.

## Project Structure
├── main.py                        # FastAPI app and detection logic
├── templates/                     # HTML templates
│   ├── login.html
│   ├── register.html
│   ├── welcome.html
│   └── blocked.html
├── reports/
│   └── model_baseline.joblib      # Trained ML model
└── requirements.txt

## Detection Logic
| Risk Level | Trigger | Action |
|---|---|---|
| HIGH | DROP, TRUNCATE, DELETE, UNION SELECT | Permanent block + email alert |
| MEDIUM | OR injections, 1=1, comments | Temp block after 3 attempts |
| LOW | SELECT, WHERE clauses | Logged only |
| ML | Logistic Regression score > 0.5 | Block + email alert |
