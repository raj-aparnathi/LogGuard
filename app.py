import os
import re
from datetime import timedelta
from pathlib import Path
from flask import Flask, jsonify, request, send_from_directory
import pandas as pd

# ── Paths and Configuration ───────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent
SAMPLE_LOG_PATH = BASE_DIR / "sample_logs.log"

FAILED_1SEC_THRESHOLD = 3    # Brute Force: 3+ failed logins within 1 second
FAILED_1MIN_THRESHOLD = 5    # Suspicious Activity: 5+ failed logins within 1 minute
REPEATED_FAIL_THRESHOLD = 5  # Repeated Failed Login: 5+ total failed logins per IP
SUSPICIOUS_KEYWORDS = ["UNAUTHORIZED", "ACCESS_DENIED", "MALICIOUS", "ATTACK"]

# ── Top-level Flask Application (Vercel WSGI entrypoint) ───────────────────────
app = Flask(__name__, static_folder=".", static_url_path="")


# ── Core Log Analysis & Detection Engine ──────────────────────────────────────
def parse_logs(text: str) -> pd.DataFrame:
    """Parse CSV-style log lines into a normalized pandas DataFrame."""
    rows = []
    if not text:
        return pd.DataFrame(columns=["timestamp", "ip", "username", "event"])

    for line in text.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",", 3)
        if len(parts) != 4:
            continue
        try:
            ts = pd.to_datetime(parts[0].strip())
        except Exception:
            continue

        rows.append({
            "timestamp": ts,
            "ip": parts[1].strip(),
            "username": parts[2].strip(),
            "event": parts[3].strip(),
        })

    if not rows:
        return pd.DataFrame(columns=["timestamp", "ip", "username", "event"])

    df = pd.DataFrame(rows)
    df.sort_values("timestamp", inplace=True, ignore_index=True)
    return df


def classify_event(event: str) -> str:
    """Classify an event into Success, Failed, Suspicious, or Other."""
    upper = str(event).upper()
    if "SUCCESS" in upper:
        return "Success"
    if "FAILED" in upper:
        return "Failed"
    if any(kw in upper for kw in SUSPICIOUS_KEYWORDS):
        return "Suspicious"
    return "Other"


def detect_threats(df: pd.DataFrame) -> list:
    """Run all 4 heuristic detection rules and return threat alerts."""
    threats = []
    if df.empty:
        return threats

    failed = df[df["event"].str.contains("FAILED", case=False, na=False)]

    for ip, group in failed.groupby("ip"):
        times = group["timestamp"].sort_values().tolist()

        # Rule 1 — Brute Force (1-second window)
        for i in range(len(times)):
            window = [t for t in times[i:] if t <= times[i] + timedelta(seconds=1)]
            if len(window) >= FAILED_1SEC_THRESHOLD:
                threats.append({
                    "time": times[i].strftime("%Y-%m-%d %H:%M:%S"),
                    "ip": str(ip),
                    "threat": "Brute Force Attack",
                    "attempts": len(window),
                    "window": "1 sec",
                    "severity": "HIGH",
                    "description": f"{len(window)} failed logins within 1 second",
                })
                break  # one alert per IP per rule

        # Rule 2 — Suspicious Login Activity (1-minute window)
        for i in range(len(times)):
            window = [t for t in times[i:] if t <= times[i] + timedelta(minutes=1)]
            if len(window) >= FAILED_1MIN_THRESHOLD:
                threats.append({
                    "time": times[i].strftime("%Y-%m-%d %H:%M:%S"),
                    "ip": str(ip),
                    "threat": "Suspicious Login Activity",
                    "attempts": len(window),
                    "window": "1 min",
                    "severity": "MEDIUM",
                    "description": f"{len(window)} failed logins within 1 minute",
                })
                break

        # Rule 3 — Repeated Failed Login (total count across entire dataset)
        if len(group) >= REPEATED_FAIL_THRESHOLD:
            already = any(
                t["ip"] == str(ip) and t["threat"] in ("Brute Force Attack", "Suspicious Login Activity")
                for t in threats
            )
            if not already:
                threats.append({
                    "time": times[0].strftime("%Y-%m-%d %H:%M:%S"),
                    "ip": str(ip),
                    "threat": "Repeated Failed Login",
                    "attempts": len(group),
                    "window": "total",
                    "severity": "MEDIUM",
                    "description": f"{len(group)} total failed login attempts",
                })

    # Rule 4 — Suspicious Events (keyword matching)
    for kw in SUSPICIOUS_KEYWORDS:
        matches = df[df["event"].str.contains(kw, case=False, na=False)]
        for _, row in matches.iterrows():
            threats.append({
                "time": row["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                "ip": str(row["ip"]),
                "threat": "Suspicious Event",
                "attempts": 1,
                "window": "–",
                "severity": "HIGH",
                "description": f"Event: {row['event']}",
            })

    return threats


def calculate_metrics(df: pd.DataFrame, threats: list) -> dict:
    """Calculate dynamic KPIs and summary insights."""
    total_logs = int(len(df))
    if total_logs == 0:
        return {
            "total_logs": 0,
            "failed_logins": 0,
            "suspicious_ips": 0,
            "clean_entries": 0,
            "most_active_ip": "–",
            "most_failed_ip": "–",
            "latest_timestamp": "–",
            "threat_level": "LOW",
            "threats_count": 0,
        }

    failed = df[df["event"].str.contains("FAILED", case=False, na=False)]
    failed_logins = int(len(failed))
    suspicious_ips = sorted(list({t["ip"] for t in threats}))
    suspicious_ips_count = len(suspicious_ips)

    # Clean/Normal entries: events that are neither Failed nor Suspicious
    clean_count = int(sum(
        1 for _, row in df.iterrows()
        if "FAILED" not in row["event"].upper()
        and not any(kw in row["event"].upper() for kw in SUSPICIOUS_KEYWORDS)
    ))

    most_active_ip = str(df["ip"].value_counts().idxmax()) if not df.empty else "–"
    most_failed_ip = str(failed["ip"].value_counts().idxmax()) if not failed.empty else "–"
    latest_ts = df["timestamp"].max().strftime("%Y-%m-%d %H:%M:%S") if not df.empty else "–"

    n_threats = len(threats)
    threat_level = "CRITICAL" if n_threats >= 5 else "HIGH" if n_threats >= 3 else "MEDIUM" if n_threats >= 1 else "LOW"

    return {
        "total_logs": total_logs,
        "failed_logins": failed_logins,
        "suspicious_ips": suspicious_ips_count,
        "clean_entries": clean_count,
        "most_active_ip": most_active_ip,
        "most_failed_ip": most_failed_ip,
        "latest_timestamp": latest_ts,
        "threat_level": threat_level,
        "threats_count": n_threats,
    }


def generate_analytics(df: pd.DataFrame, threats: list) -> dict:
    """Compile visualization data structures for charts."""
    if df.empty:
        return {
            "timeline": [],
            "status_distribution": {"Success": 0, "Failed": 0, "Suspicious": 0, "Other": 0},
            "severity_distribution": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "top_ips": [],
            "failed_ips": [],
        }

    # Timeline (events per minute)
    df_time = df.copy()
    df_time["minute"] = df_time["timestamp"].dt.strftime("%Y-%m-%d %H:%M")
    timeline_series = df_time.groupby("minute").size()
    timeline = [{"minute": str(m), "count": int(c)} for m, c in timeline_series.items()]

    # Status distribution
    status_counts = {"Success": 0, "Failed": 0, "Suspicious": 0, "Other": 0}
    for _, row in df.iterrows():
        cat = classify_event(row["event"])
        status_counts[cat] = status_counts.get(cat, 0) + 1

    # Threat severity distribution
    sev_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for t in threats:
        sev = t.get("severity", "LOW")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    # Top IP activity
    top_ip_series = df["ip"].value_counts().head(10)
    top_ips = [{"ip": str(ip), "count": int(c)} for ip, c in top_ip_series.items()]

    # Failed logins by IP
    failed = df[df["event"].str.contains("FAILED", case=False, na=False)]
    if not failed.empty:
        failed_ip_series = failed["ip"].value_counts().head(10)
        failed_ips = [{"ip": str(ip), "count": int(c)} for ip, c in failed_ip_series.items()]
    else:
        failed_ips = []

    return {
        "timeline": timeline,
        "status_distribution": status_counts,
        "severity_distribution": sev_counts,
        "top_ips": top_ips,
        "failed_ips": failed_ips,
    }


def analyze_log_content(text: str) -> dict:
    """Complete pipeline: parse text -> detect threats -> compute KPIs & chart analytics."""
    df = parse_logs(text)
    threats = detect_threats(df)
    metrics = calculate_metrics(df, threats)
    analytics = generate_analytics(df, threats)

    threat_ips = {t["ip"] for t in threats}
    logs_data = []
    for _, row in df.iterrows():
        cls = classify_event(row["event"])
        threat_class = (
            "🔴 Threat IP" if row["ip"] in threat_ips
            else ("⚠️ Failed" if "FAILED" in row["event"].upper() else "✅ Clean")
        )
        logs_data.append({
            "timestamp": row["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
            "iso": row["timestamp"].isoformat(),
            "ip": row["ip"],
            "username": row["username"],
            "event": row["event"],
            "status": cls,
            "threat_class": threat_class,
        })

    return {
        "status": "success",
        "metrics": metrics,
        "threats": threats,
        "logs": logs_data,
        "analytics": analytics,
    }


# ── Frontend Static Routes ────────────────────────────────────────────────────
@app.route("/")
def index():
    """Serve the single-page application frontend."""
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/style.css")
def serve_css():
    """Serve the master stylesheet."""
    return send_from_directory(BASE_DIR, "style.css", mimetype="text/css")


@app.route("/sample_logs.log")
def serve_sample_log_file():
    """Serve the raw sample logs file for direct download or fetch."""
    return send_from_directory(BASE_DIR, "sample_logs.log", mimetype="text/plain")


# ── REST API Endpoints ────────────────────────────────────────────────────────
@app.route("/api/health", methods=["GET"])
def api_health():
    """Service health check endpoint."""
    return jsonify({
        "status": "ok",
        "service": "LogGuard SOC Backend",
        "version": "1.0.0",
        "platform": "Flask/Vercel WSGI",
    })


@app.route("/api/rules", methods=["GET"])
def api_rules():
    """Return active detection heuristic rules and threshold specifications."""
    return jsonify({
        "status": "success",
        "rules": [
            {
                "id": "1",
                "title": "Brute Force Detection",
                "condition": f"{FAILED_1SEC_THRESHOLD}+ failed logins from the same IP within 1 second",
                "severity": "HIGH",
                "description": "Detects rapid-fire login attempts that indicate an automated brute-force attack tool.",
            },
            {
                "id": "2",
                "title": "Suspicious Login Activity",
                "condition": f"{FAILED_1MIN_THRESHOLD}+ failed logins from the same IP within 1 minute",
                "severity": "MEDIUM",
                "description": "Identifies an IP that is persistently trying to log in within a short time window.",
            },
            {
                "id": "3",
                "title": "Repeated Failed Login",
                "condition": f"{REPEATED_FAIL_THRESHOLD}+ total failed login attempts from one IP",
                "severity": "MEDIUM",
                "description": "Flags any IP with a high total count of failed logins across the entire log.",
            },
            {
                "id": "4",
                "title": "Suspicious Event Detection",
                "condition": f"Event contains keywords: {', '.join(SUSPICIOUS_KEYWORDS)}",
                "severity": "HIGH",
                "description": "Catches log entries with explicitly suspicious or malicious event types.",
            },
        ],
    })


@app.route("/api/sample-logs", methods=["GET"])
def api_sample_logs():
    """Load default sample logs and return fully parsed, dynamic security analysis."""
    if not SAMPLE_LOG_PATH.exists():
        return jsonify({"status": "error", "message": "sample_logs.log not found"}), 404

    try:
        raw_text = SAMPLE_LOG_PATH.read_text(encoding="utf-8")
        analysis = analyze_log_content(raw_text)
        analysis["raw"] = raw_text
        return jsonify(analysis)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """Analyze log content from JSON body, plain text body, or form data."""
    try:
        text = ""
        if request.is_json:
            data = request.get_json(silent=True) or {}
            text = data.get("log_text") or data.get("logs") or ""
        elif request.form and ("log_text" in request.form or "logs" in request.form):
            text = request.form.get("log_text") or request.form.get("logs") or ""
        else:
            text = request.get_data(as_text=True) or ""

        if not text.strip():
            return jsonify({"status": "error", "message": "No log text provided"}), 400

        analysis = analyze_log_content(text)
        return jsonify(analysis)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/upload", methods=["POST"])
def api_upload():
    """Accept multipart file upload (.log or .txt), parse and return dynamic security analysis."""
    file = request.files.get("file") or request.files.get("log_file")
    if not file:
        return jsonify({"status": "error", "message": "No file uploaded"}), 400

    filename = file.filename or ""
    if not (filename.endswith(".log") or filename.endswith(".txt") or filename == ""):
        # Still accept if plain text MIME
        pass

    try:
        content = file.read().decode("utf-8", errors="replace")
        analysis = analyze_log_content(content)
        analysis["filename"] = filename
        return jsonify(analysis)
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to process uploaded file: {e}"}), 500


# ── Local Development Runner ──────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"[LogGuard] SOC Server listening on http://127.0.0.1:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)
