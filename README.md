# 🛡️ LogGuard – Security Log Threat Detector

A Python-based cybersecurity log analysis dashboard that detects suspicious activity, brute-force attacks, and repeated failed login attempts from server log files.

---

## 📋 Features

- **Dashboard** — Metric cards showing total logs, failed logins, suspicious IPs, and threats
- **Visual Analytics** — Interactive Plotly charts for log events, IPs, and threat distribution
- **Threat Detection** — Time-window based detection (1-second brute force, 1-minute suspicious activity)
- **Threat Alerts** — Filterable table of all detected security threats
- **Log Stream** — Searchable, filterable view of all parsed log records
- **Detection Rules** — Clear documentation of the rules used
- **Light/Dark Theme** — Toggle between white and dark mode
- **File Upload** — Upload custom `.log` files or use the included sample

---

## 🛠️ Technology Stack

| Technology | Purpose |
|------------|---------|
| Python | Core language |
| Streamlit | Web dashboard framework |
| Pandas | Data processing & analysis |
| Plotly | Interactive charts |

---

## 📁 Project Structure

```
LogGuard/
├── app.py              # Main application (all Python logic & Streamlit UI)
├── index.html          # Standalone frontend SOC dashboard (HTML presentation)
├── style.css           # External stylesheet for both index.html & Streamlit
├── sample_logs.log     # Sample log file with test data
├── requirements.txt    # Python dependencies
├── README.md           # Project documentation
└── design.md           # Architecture & design documentation
```

---

## ⚙️ Installation

1. **Clone/download** this project.

2. **Install dependencies:**

```bash
pip install -r requirements.txt
```

---

## 🚀 Running the Application

```bash
streamlit run app.py
```

The dashboard will open in your browser at `http://localhost:8501`.

---

## 📄 Log Format

The application expects comma-separated log files with this format:

```
timestamp,ip,username,event
```

Example:

```
2026-10-08 10:01:12,192.168.1.10,admin,LOGIN_SUCCESS
2026-10-08 10:01:15,192.168.1.20,admin,LOGIN_FAILED
```

---

## 🔍 Detection Rules

| # | Rule | Condition | Severity |
|---|------|-----------|----------|
| 1 | Brute Force Attack | 3+ failed logins from same IP within 1 second | HIGH |
| 2 | Suspicious Login Activity | 5+ failed logins from same IP within 1 minute | MEDIUM |
| 3 | Repeated Failed Login | 5+ total failed login attempts from one IP | MEDIUM |
| 4 | Suspicious Event | Event contains UNAUTHORIZED, ACCESS_DENIED, MALICIOUS, or ATTACK | HIGH |

---

## 🚨 Example Threat Detection

Given these log entries:

```
2026-10-08 10:01:25,10.0.0.25,attacker,LOGIN_FAILED
2026-10-08 10:01:25,10.0.0.25,attacker,LOGIN_FAILED
2026-10-08 10:01:25,10.0.0.25,attacker,LOGIN_FAILED
```

**Result:**

```
Threat:   Brute Force Attack
IP:       10.0.0.25
Attempts: 3
Window:   1 second
Severity: HIGH
```

---

## 📺 Screens / Pages

1. **Dashboard** — Metric cards + summary info + recent threats
2. **Visual Analytics** — 5 interactive Plotly charts
3. **Threat Alerts** — Filterable threat table
4. **Log Stream** — Filterable log record viewer
5. **Detection Rules** — Rule documentation

---

## 🔮 Future Improvements

- Real-time log streaming via file watcher
- Export threat reports as PDF/CSV
- IP geolocation mapping
- Custom rule configuration UI
- Email/Slack alert notifications
- Multi-file log analysis
- User authentication for the dashboard
