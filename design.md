# 🛡️ LogGuard – Design Document

## Architecture Overview

```
Log File (.log)
      ↓
   Parser (parse_logs)
      ↓
  Pandas DataFrame
      ↓
  Threat Detection (detect_threats)
      ↓
  Metrics + Analytics (calculate_metrics)
      ↓
  Streamlit Dashboard (app.py + style.css styles)
  Standalone Web UI (index.html + style.css)
```

All core logic resides in `app.py`, design tokens in `style.css`, and `index.html` provides a standalone SOC frontend.

---

## UI Layout

The application uses a **sidebar + main area** layout:

- **Sidebar** — Navigation, theme toggle, log source (sample/upload)
- **Main Area** — Content for the selected page

### Pages

| Page | Description |
|------|-------------|
| Dashboard | Metric cards, summary, recent threats |
| Visual Analytics | 5 interactive Plotly charts |
| Threat Alerts | Filterable table of detected threats |
| Log Stream | Searchable table of all log records |
| Detection Rules | Documentation of the 4 detection rules |

---

## Navigation

Navigation is handled via a Streamlit `st.radio` in the sidebar. Clicking a section renders the corresponding page in the main area. No multi-page routing is needed.

---

## Data Flow

```
1. User loads sample_logs.log  OR  uploads .log file
2. load_logs() reads the file content as text
3. parse_logs() splits lines, extracts fields, returns DataFrame
4. detect_threats() runs all 4 rules against the DataFrame
5. calculate_metrics() computes dashboard statistics
6. Streamlit renders the selected page using the data
```

Data is kept in `st.session_state` so it persists across page switches.

---

## Threat Detection Logic

### Rule 1 — Brute Force (1-second window)

For each IP with failed logins:
1. Sort timestamps
2. Slide through timestamps
3. Count how many fall within `timestamp + 1 second`
4. If count ≥ 3 → **Brute Force Attack** (HIGH)

### Rule 2 — Suspicious Login Activity (1-minute window)

Same sliding-window approach:
1. Count failed logins within `timestamp + 1 minute`
2. If count ≥ 5 → **Suspicious Login Activity** (MEDIUM)

### Rule 3 — Repeated Failed Login (total count)

1. Group failed logins by IP
2. If total count ≥ 5 and no Rule 1/2 already flagged → **Repeated Failed Login** (MEDIUM)

### Rule 4 — Suspicious Event (keyword match)

1. Scan all events for keywords: `UNAUTHORIZED`, `ACCESS_DENIED`, `MALICIOUS`, `ATTACK`
2. Each match → **Suspicious Event** (HIGH)

---

## Theme Design

Two themes controlled by `st.session_state.theme`:

| Property | Dark Mode | Light Mode |
|----------|-----------|------------|
| Background | `#0e1117` (near black) | `#ffffff` (white) |
| Text | `#fafafa` (white) | `#1a1a1a` (black) |
| Cards | `#1a1d23` dark gray | `#f8f9fa` light gray |
| Borders | `#2d2d2d` | `#e0e0e0` |

Themes are applied via injected CSS — no external theme packages.

---

## File Structure

```
LogGuard/
├── app.py              # All application logic (parsing, detection, UI)
├── index.html          # UI design system (CSS loaded by app.py)
├── sample_logs.log     # Pre-built sample data for demonstration
├── requirements.txt    # streamlit, pandas, plotly
├── README.md           # User-facing documentation
└── design.md           # This design document
```

**6 files total** — minimum viable structure.

`index.html` contains the CSS design system. `app.py` reads its `<style>` blocks at runtime and injects them into Streamlit via `st.markdown()`. No separate frontend server is needed.

---

## Why No Database?

- Log files are small enough to fit in memory
- Pandas DataFrames provide fast in-memory analysis
- No need for persistence between sessions
- Keeps the project simple and dependency-free
- Suitable for a college mini project scope

---

## Limitations

1. **No real-time streaming** — logs are loaded as a batch, not monitored live
2. **In-memory only** — data is lost when the app restarts
3. **Fixed log format** — only supports the 4-field CSV format
4. **No authentication** — anyone with access can use the dashboard
5. **Simple rules** — not a replacement for production SIEM/IDS tools
6. **Single file processing** — one log file at a time

---

## Future Improvements

- File watcher for real-time log ingestion
- Support for additional log formats (syslog, JSON)
- CSV/PDF export of threat reports
- IP geolocation on a world map
- Configurable detection rules via UI
- Multi-file and directory scanning
- Alert notifications (email, Slack, webhook)
- User login and role-based access
- Historical trend analysis across multiple sessions
