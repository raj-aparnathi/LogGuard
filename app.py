import re
import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import timedelta
from pathlib import Path

# ── Configuration ────────────────────────────────────────────────────────────
FAILED_1SEC_THRESHOLD = 3   # Brute Force: 3+ failed logins within 1 second
FAILED_1MIN_THRESHOLD = 5   # Suspicious Activity: 5+ failed logins within 1 minute
REPEATED_FAIL_THRESHOLD = 5 # Repeated Failed Login: 5+ total failed logins per IP
SUSPICIOUS_KEYWORDS = ["UNAUTHORIZED", "ACCESS_DENIED", "MALICIOUS", "ATTACK"]
SAMPLE_LOG_PATH = Path(__file__).parent / "sample_logs.log"
CSS_PATH = Path(__file__).parent / "style.css"

st.set_page_config(page_title="LogGuard – Security Log Threat Detector", page_icon="🛡️", layout="wide")

# ── Theme ────────────────────────────────────────────────────────────────────
if "theme" not in st.session_state:
    st.session_state.theme = "Dark"

def load_ui_styles():
    """Load CSS from style.css and return style tag with active theme overrides."""
    try:
        css = ""
        if CSS_PATH.exists():
            css = CSS_PATH.read_text(encoding="utf-8")

        theme_vars = """
        :root, .stApp {
            --bg-primary: #0a0c10;
            --bg-secondary: #13161d;
            --bg-card: #181b23;
            --bg-card-hover: #1e222c;
            --text-primary: #e6edf3;
            --text-secondary: #8b949e;
            --border-color: #21262d;
            --border-light: #30363d;
            --accent: #58a6ff;
        }
        .stApp { background-color: var(--bg-primary); color: var(--text-primary); }
        section[data-testid="stSidebar"] { background: var(--bg-secondary); }
        """ if st.session_state.theme == "Dark" else """
        :root, .stApp {
            --bg-primary: #ffffff;
            --bg-secondary: #f6f8fa;
            --bg-card: #f6f8fa;
            --bg-card-hover: #eef1f5;
            --text-primary: #1b1f24;
            --text-secondary: #57606a;
            --border-color: #d8dee4;
            --border-light: #e1e4e8;
            --accent: #0969da;
        }
        .stApp { background-color: var(--bg-primary); color: var(--text-primary); }
        section[data-testid="stSidebar"] { background: var(--bg-secondary); }
        """
        return f"<style>\n{css}\n{theme_vars}\n</style>"
    except Exception:
        return ""

# ── Log Parsing ──────────────────────────────────────────────────────────────
def load_logs(source):
    """Load log text from file path or uploaded file."""
    try:
        if isinstance(source, (str, Path)):
            path = Path(source)
            if not path.exists():
                st.error(f"⚠️ Sample log file not found: {path}")
                return None
            text = path.read_text(encoding="utf-8")
        else:
            text = source.read().decode("utf-8")
        return text
    except Exception as e:
        st.error(f"⚠️ Error reading file: {e}")
        return None

def parse_logs(text):
    """Parse CSV-style log lines into a DataFrame."""
    rows = []
    for line in text.strip().split("\n"):
        line = line.strip()
        if not line:
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

# ── Threat Detection ─────────────────────────────────────────────────────────
def detect_threats(df):
    """Run all detection rules and return a list of threat dicts."""
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
                    "time": times[i], "ip": ip, "threat": "Brute Force Attack",
                    "attempts": len(window), "window": "1 sec",
                    "severity": "HIGH",
                    "description": f"{len(window)} failed logins within 1 second"
                })
                break  # one alert per IP per rule

        # Rule 2 — Suspicious Login Activity (1-minute window)
        for i in range(len(times)):
            window = [t for t in times[i:] if t <= times[i] + timedelta(minutes=1)]
            if len(window) >= FAILED_1MIN_THRESHOLD:
                threats.append({
                    "time": times[i], "ip": ip, "threat": "Suspicious Login Activity",
                    "attempts": len(window), "window": "1 min",
                    "severity": "MEDIUM",
                    "description": f"{len(window)} failed logins within 1 minute"
                })
                break

        # Rule 3 — Repeated Failed Login (total count)
        if len(group) >= REPEATED_FAIL_THRESHOLD:
            already = any(t["ip"] == ip and t["threat"] in
                         ("Brute Force Attack", "Suspicious Login Activity") for t in threats)
            if not already:
                threats.append({
                    "time": group["timestamp"].iloc[0], "ip": ip,
                    "threat": "Repeated Failed Login",
                    "attempts": len(group), "window": "total",
                    "severity": "MEDIUM",
                    "description": f"{len(group)} total failed login attempts"
                })

    # Rule 4 — Suspicious Events
    for kw in SUSPICIOUS_KEYWORDS:
        matches = df[df["event"].str.contains(kw, case=False, na=False)]
        for _, row in matches.iterrows():
            threats.append({
                "time": row["timestamp"], "ip": row["ip"],
                "threat": "Suspicious Event",
                "attempts": 1, "window": "–",
                "severity": "HIGH",
                "description": f"Event: {row['event']}"
            })

    return threats

def get_suspicious_ips(threats):
    """Unique IPs from threat list."""
    return list({t["ip"] for t in threats})

def classify_log(event, suspicious_keywords):
    """Classify a single log event string."""
    upper = event.upper()
    if "FAILED" in upper:
        return "Failed"
    if any(kw in upper for kw in suspicious_keywords):
        return "Suspicious"
    return "Clean"

def calculate_metrics(df, threats):
    """Return dict of dashboard metrics."""
    failed = df[df["event"].str.contains("FAILED", case=False, na=False)] if not df.empty else df
    suspicious_ips = get_suspicious_ips(threats)

    # Clean/Normal entries: everything that isn't a failed login or suspicious event
    if not df.empty:
        classifications = df["event"].apply(lambda e: classify_log(e, SUSPICIOUS_KEYWORDS))
        clean_count = int((classifications == "Clean").sum())
    else:
        clean_count = 0

    return {
        "total_logs": len(df),
        "failed_logins": len(failed),
        "suspicious_ips": len(suspicious_ips),
        "clean_entries": clean_count,
    }

# ── UI Helpers ───────────────────────────────────────────────────────────────
def metric_card(label, value, emoji=""):
    st.markdown(
        f'<div class="metric-card fade-in">'
        f'<span class="icon-bg">{emoji}</span>'
        f'<p class="value">{value}</p>'
        f'<p class="label">{label}</p></div>',
        unsafe_allow_html=True,
    )

def severity_badge(sev):
    cls = {"HIGH": "severity-badge-high", "MEDIUM": "severity-badge-medium"}.get(sev, "severity-badge-low")
    return f'<span class="severity-badge {cls}">{sev}</span>'

def page_header(icon, title, subtitle=""):
    sub = f'<span class="subtitle">{subtitle}</span>' if subtitle else ""
    st.markdown(
        f'<div class="page-header fade-in"><span class="icon">{icon}</span>'
        f'<span class="title">{title}</span>{sub}</div>',
        unsafe_allow_html=True,
    )

# ── MAIN APP ─────────────────────────────────────────────────────────────────
def main():
    st.markdown(load_ui_styles(), unsafe_allow_html=True)

    # ── Sidebar ──────────────────────────────────────────────────────────────
    with st.sidebar:
        st.markdown("## 🛡️ LogGuard")
        st.markdown("---")
        page = st.radio("Navigation", ["Dashboard", "Visual Analytics", "Threat Alerts", "Log Stream", "Detection Rules"], label_visibility="collapsed")
        st.markdown("---")

        # Theme toggle
        theme = st.radio("Theme", ["Dark", "Light"], index=0 if st.session_state.theme == "Dark" else 1, horizontal=True)
        if theme != st.session_state.theme:
            st.session_state.theme = theme
            st.rerun()

        st.markdown("---")
        st.markdown("**📂 Log Source**")
        use_sample = st.button("📄 Load Sample Log", use_container_width=True)
        uploaded = st.file_uploader("Upload .log / .txt file", type=["log", "txt"])

    # ── Load & parse ─────────────────────────────────────────────────────────
    if uploaded:
        text = load_logs(uploaded)
    elif use_sample or "df" not in st.session_state:
        text = load_logs(SAMPLE_LOG_PATH)
    else:
        text = None

    if text is not None:
        st.session_state.df = parse_logs(text)
        st.session_state.threats = detect_threats(st.session_state.df)

    df = st.session_state.get("df", pd.DataFrame(columns=["timestamp", "ip", "username", "event"]))
    threats = st.session_state.get("threats", [])

    if df.empty:
        st.warning("No log data loaded. Use the sidebar to load a sample or upload a file.")
        return

    metrics = calculate_metrics(df, threats)

    # ── Pages ────────────────────────────────────────────────────────────────
    if page == "Dashboard":
        render_dashboard(df, metrics, threats)
    elif page == "Visual Analytics":
        render_analytics(df, threats)
    elif page == "Threat Alerts":
        render_alerts(threats)
    elif page == "Log Stream":
        render_log_stream(df, threats)
    elif page == "Detection Rules":
        render_rules()

# ── PAGE: Dashboard ──────────────────────────────────────────────────────────
def render_dashboard(df, metrics, threats):
    page_header("📊", "Dashboard", "Security Overview")
    c1, c2, c3, c4 = st.columns(4)
    with c1: metric_card("Total Log Entries", metrics["total_logs"], "📋")
    with c2: metric_card("Failed Logins", metrics["failed_logins"], "❌")
    with c3: metric_card("Suspicious IPs", metrics["suspicious_ips"], "🔍")
    with c4: metric_card("Clean / Normal Entries", metrics["clean_entries"], "✅")

    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

    # Quick summary row
    most_active_ip = df["ip"].value_counts().idxmax() if not df.empty else "–"
    failed = df[df["event"].str.contains("FAILED", case=False, na=False)] if not df.empty else df
    most_failed_ip = failed["ip"].value_counts().idxmax() if not failed.empty else "–"
    latest_ts = df["timestamp"].max().strftime("%Y-%m-%d %H:%M:%S") if not df.empty else "–"
    n_threats = len(threats)
    threat_level = "CRITICAL" if n_threats >= 5 else "HIGH" if n_threats >= 3 else "MEDIUM" if n_threats >= 1 else "LOW"

    st.markdown('<div class="summary-box fade-in">', unsafe_allow_html=True)
    s1, s2, s3, s4 = st.columns(4)
    s1.markdown(
        f'<div class="summary-item"><div class="summary-label">Most Active IP</div>'
        f'<div class="summary-value">{most_active_ip}</div></div>',
        unsafe_allow_html=True)
    s2.markdown(
        f'<div class="summary-item"><div class="summary-label">Most Failed-Login IP</div>'
        f'<div class="summary-value">{most_failed_ip}</div></div>',
        unsafe_allow_html=True)
    s3.markdown(
        f'<div class="summary-item"><div class="summary-label">Latest Timestamp</div>'
        f'<div class="summary-value">{latest_ts}</div></div>',
        unsafe_allow_html=True)
    lv = threat_level
    lv_cls = lv.lower()
    dot_cls = {"CRITICAL": "status-dot-danger", "HIGH": "status-dot-warning", "MEDIUM": "status-dot-warning", "LOW": "status-dot-active"}.get(lv, "")
    s4.markdown(
        f'<div class="summary-item"><div class="summary-label">Threat Level</div>'
        f'<div class="summary-value"><span class="threat-level threat-level-{lv_cls}">'
        f'<span class="status-dot {dot_cls} pulse"></span>{lv}</span></div></div>',
        unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

    # Quick recent threats
    if threats:
        st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
        st.markdown("#### Recent Threats")
        for t in threats[:5]:
            css = {"HIGH": "threat-high", "MEDIUM": "threat-medium"}.get(t["severity"], "threat-low")
            st.markdown(
                f'<div class="rule-card {css} fade-in">'
                f'<strong>{t["threat"]}</strong> — IP: <code>{t["ip"]}</code> '
                f'| Attempts: {t["attempts"]} | Window: {t["window"]} '
                f'| Severity: {severity_badge(t["severity"])}'
                f'</div>', unsafe_allow_html=True,
            )

# ── PAGE: Visual Analytics ───────────────────────────────────────────────────
def render_analytics(df, threats):
    page_header("📈", "Visual Analytics", "Charts & Trends")
    theme_template = "plotly_dark" if st.session_state.theme == "Dark" else "plotly_white"

    # Chart 1 – Login events over time (timeline)
    df_time = df.copy()
    df_time["minute"] = df_time["timestamp"].dt.floor("min")
    time_counts = df_time.groupby("minute").size().reset_index(name="count")
    fig1 = px.area(time_counts, x="minute", y="count", title="Log Events Timeline",
                   template=theme_template, color_discrete_sequence=["#58a6ff"])
    fig1.update_layout(xaxis_title="Time", yaxis_title="Events")
    st.plotly_chart(fig1, use_container_width=True)

    col1, col2 = st.columns(2)

    # Chart 2 – Login Status Distribution (success vs failed vs other)
    status_map = df["event"].apply(
        lambda e: "Success" if "SUCCESS" in e.upper()
        else ("Failed" if "FAILED" in e.upper()
        else ("Suspicious" if any(k in e.upper() for k in SUSPICIOUS_KEYWORDS) else "Other"))
    )
    status_counts = status_map.value_counts().reset_index()
    status_counts.columns = ["status", "count"]
    colors_map = {"Success": "#3fb950", "Failed": "#f85149", "Suspicious": "#d29922", "Other": "#58a6ff"}
    fig2 = px.pie(status_counts, names="status", values="count", title="Login Status Distribution",
                  template=theme_template, color="status", color_discrete_map=colors_map)
    col1.plotly_chart(fig2, use_container_width=True)

    # Chart 3 – Threat Severity Distribution
    if threats:
        sev_df = pd.DataFrame(threats)["severity"].value_counts().reset_index()
        sev_df.columns = ["severity", "count"]
        colors = {"HIGH": "#f85149", "MEDIUM": "#d29922", "LOW": "#3fb950"}
        fig3 = px.bar(sev_df, x="severity", y="count", title="Threat Severity Distribution",
                      template=theme_template, color="severity", color_discrete_map=colors)
    else:
        fig3 = px.bar(title="Threat Severity Distribution (none)", template=theme_template)
    col2.plotly_chart(fig3, use_container_width=True)

    col3, col4 = st.columns(2)

    # Chart 4 – Top IP Activity
    ip_counts = df["ip"].value_counts().head(10).reset_index()
    ip_counts.columns = ["ip", "count"]
    fig4 = px.bar(ip_counts, x="ip", y="count", title="Top IP Addresses by Activity",
                  template=theme_template, color_discrete_sequence=["#58a6ff"])
    col3.plotly_chart(fig4, use_container_width=True)

    # Chart 5 – Failed Logins by IP
    failed = df[df["event"].str.contains("FAILED", case=False, na=False)]
    if not failed.empty:
        fc = failed["ip"].value_counts().head(10).reset_index()
        fc.columns = ["ip", "failed"]
        fig5 = px.bar(fc, x="ip", y="failed", title="Failed Logins by IP",
                      template=theme_template, color_discrete_sequence=["#f85149"])
    else:
        fig5 = px.bar(title="Failed Logins by IP (none)", template=theme_template)
    col4.plotly_chart(fig5, use_container_width=True)

# ── PAGE: Threat Alerts ──────────────────────────────────────────────────────
def render_alerts(threats):
    page_header("🚨", "Threat Alerts", f"{len(threats)} detected")

    sev_filter = st.selectbox("Filter by Severity", ["All", "HIGH", "MEDIUM", "LOW"])
    filtered = [t for t in threats if sev_filter == "All" or t["severity"] == sev_filter]

    if not filtered:
        st.info("✅ No threats detected for the selected filter.")
        return

    for t in filtered:
        css = {"HIGH": "threat-high", "MEDIUM": "threat-medium"}.get(t["severity"], "threat-low")
        ts = t["time"].strftime("%Y-%m-%d %H:%M:%S") if hasattr(t["time"], "strftime") else str(t["time"])
        st.markdown(
            f'<div class="rule-card {css} fade-in">'
            f'<strong>{t["threat"]}</strong> {severity_badge(t["severity"])}<br>'
            f'🕐 <code>{ts}</code> &nbsp;|&nbsp; 🌐 IP: <code>{t["ip"]}</code> &nbsp;|&nbsp; '
            f'⚡ Attempts: {t["attempts"]} &nbsp;|&nbsp; ⏱ Window: {t["window"]}<br>'
            f'📝 {t["description"]}'
            f'</div>', unsafe_allow_html=True,
        )

    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
    st.markdown("#### Threat Summary Table")
    rows = []
    for t in filtered:
        rows.append({
            "Timestamp": t["time"].strftime("%Y-%m-%d %H:%M:%S") if hasattr(t["time"], "strftime") else str(t["time"]),
            "IP Address": t["ip"],
            "Threat": t["threat"],
            "Attempts": t["attempts"],
            "Window": t["window"],
            "Severity": t["severity"],
            "Description": t["description"],
        })
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

# ── PAGE: Log Stream ─────────────────────────────────────────────────────────
def render_log_stream(df, threats):
    page_header("📜", "Log Stream", f"{len(df)} records")

    fc1, fc2, fc3, fc4 = st.columns(4)
    ip_filter = fc1.text_input("IP Address", placeholder="e.g. 192.168.1.10")
    user_filter = fc2.text_input("Username", placeholder="e.g. admin")
    status_filter = fc3.selectbox("Status", ["All", "Success", "Failed", "Suspicious", "Other"])
    search = fc4.text_input("Search", placeholder="keyword…")

    # Build threat IP set for classification
    threat_ips = {t["ip"] for t in threats}

    display = df.copy()
    display["status"] = display["event"].apply(
        lambda e: "✅ Success" if "SUCCESS" in e.upper()
        else ("❌ Failed" if "FAILED" in e.upper()
        else ("⚠️ Suspicious" if any(k in e.upper() for k in SUSPICIOUS_KEYWORDS) else "ℹ️ Other"))
    )
    display["threat_class"] = display.apply(
        lambda r: "🔴 Threat IP" if r["ip"] in threat_ips
        else ("⚠️ Failed" if "FAILED" in r["event"].upper()
        else "✅ Clean"),
        axis=1,
    )

    if ip_filter:
        display = display[display["ip"].str.contains(ip_filter, case=False, na=False)]
    if user_filter:
        display = display[display["username"].str.contains(user_filter, case=False, na=False)]
    if status_filter == "Success":
        display = display[display["event"].str.contains("SUCCESS", case=False, na=False)]
    elif status_filter == "Failed":
        display = display[display["event"].str.contains("FAILED", case=False, na=False)]
    elif status_filter == "Suspicious":
        display = display[display["event"].apply(lambda e: any(k in e.upper() for k in SUSPICIOUS_KEYWORDS))]
    elif status_filter == "Other":
        display = display[~display["event"].str.contains("SUCCESS|FAILED", case=False, na=False)]
        display = display[~display["event"].apply(lambda e: any(k in e.upper() for k in SUSPICIOUS_KEYWORDS))]
    if search:
        mask = display.apply(lambda r: search.lower() in " ".join(r.astype(str)).lower(), axis=1)
        display = display[mask]

    display_out = display[["timestamp", "ip", "username", "event", "status", "threat_class"]].copy()
    display_out.columns = ["Timestamp", "IP", "Username", "Event", "Status", "Threat Classification"]
    st.dataframe(display_out, use_container_width=True, hide_index=True)
    st.caption(f"Showing {len(display_out)} of {len(df)} records")

# ── PAGE: Detection Rules ───────────────────────────────────────────────────
def render_rules():
    page_header("📏", "Detection Rules", "4 active rules")

    st.markdown(
        '<div class="summary-box fade-in">'
        '<div class="summary-label">ENGINE STATUS</div>'
        '<div class="summary-value" style="color:#3fb950;">● All 4 detection rules active</div>'
        '</div>', unsafe_allow_html=True
    )
    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

    rules = [
        ("1", "Brute Force Detection", f"{FAILED_1SEC_THRESHOLD}+ failed logins from the same IP within 1 second", "HIGH",
         "Detects rapid-fire login attempts that indicate an automated brute-force attack tool."),
        ("2", "Suspicious Login Activity", f"{FAILED_1MIN_THRESHOLD}+ failed logins from the same IP within 1 minute", "MEDIUM",
         "Identifies an IP that is persistently trying to log in within a short time window."),
        ("3", "Repeated Failed Login", f"{REPEATED_FAIL_THRESHOLD}+ total failed login attempts from one IP", "MEDIUM",
         "Flags any IP with a high total count of failed logins across the entire log."),
        ("4", "Suspicious Event", f"Event contains keywords: {', '.join(SUSPICIOUS_KEYWORDS)}", "HIGH",
         "Catches log entries with explicitly suspicious or malicious event types."),
    ]
    for num, title, condition, severity, desc in rules:
        st.markdown(
            f'<div class="rule-card fade-in">'
            f'<span class="rule-number">{num}</span>'
            f'<strong>{title}</strong><br>'
            f'<em>{condition}</em><br>'
            f'Severity: {severity_badge(severity)}<br>'
            f'<span class="rule-desc">{desc}</span></div>',
            unsafe_allow_html=True,
        )

# ── Entry Point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    main()
