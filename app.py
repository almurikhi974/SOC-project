"""
app.py — SOC Analyst AI Agent · Professional Streamlit Dashboard v3
"""

import json
import os
import queue
import threading
import time
import io
import csv
import pathlib
import streamlit as st

# ---------------------------------------------------------------------------
# Page Config
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="SOC Analyst AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

BASE_DIR    = pathlib.Path(__file__).parent
GT_PATH     = BASE_DIR / "65_ground_truth.json"
ALERTS_PATH = BASE_DIR / "65_alerts_with_labels.json"
BENCH_CACHE = BASE_DIR / "benchmark_results.json"

# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;600;700&display=swap');

/* ── Base ─────────────────────────────────────────────────────────────── */
html, body, [class*="css"] { font-family: 'Inter', sans-serif; color: #e2e8f0; }
.stApp { background: #0b0f1a; min-height: 100vh; }

/* ── Tabs ─────────────────────────────────────────────────────────────── */
[data-testid="stTabs"] [role="tablist"] {
    gap: 4px; padding-bottom: 0;
    border-bottom: 1px solid rgba(255,255,255,0.1);
}
[data-testid="stTabs"] [role="tab"] {
    background: transparent !important; border: none !important;
    color: #8096b4 !important; font-weight: 600 !important;
    font-size: 13px !important; padding: 10px 18px !important;
    border-radius: 8px 8px 0 0 !important; transition: all 0.2s !important;
}
[data-testid="stTabs"] [role="tab"][aria-selected="true"] {
    color: #00d4ff !important;
    background: rgba(0,212,255,0.08) !important;
    border-bottom: 2px solid #00d4ff !important;
}
[data-testid="stTabs"] [role="tab"]:hover {
    color: #c4d4e8 !important;
    background: rgba(255,255,255,0.04) !important;
}

/* ── Sidebar ──────────────────────────────────────────────────────────── */
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0d1525 0%, #0b0f1e 100%);
    border-right: 1px solid rgba(0,212,255,0.12);
}
[data-testid="stSidebar"] * { color: #dce8f8 !important; }

/* ── Header ───────────────────────────────────────────────────────────── */
.soc-header {
    position: relative; overflow: hidden;
    background: linear-gradient(135deg, #0e1f35 0%, #112444 60%, #0e1f35 100%);
    border: 1px solid rgba(0,212,255,0.2); border-radius: 14px;
    padding: 24px 32px; margin-bottom: 24px;
    display: flex; align-items: center; gap: 20px;
}
.soc-header::before {
    content: ''; position: absolute; inset: 0;
    background: repeating-linear-gradient(90deg, transparent, transparent 80px,
        rgba(0,212,255,0.025) 80px, rgba(0,212,255,0.025) 81px);
    pointer-events: none;
}
.soc-scanline {
    position: absolute; top: 0; left: -60%; width: 50%; height: 100%;
    background: linear-gradient(90deg, transparent, rgba(0,212,255,0.045), transparent);
    animation: scan 7s linear infinite;
}
@keyframes scan { 0%{left:-60%} 100%{left:110%} }
.soc-title { font-size: 24px; font-weight: 800; color: #f0f6ff; letter-spacing: -0.5px; }
.soc-title span { color: #00d4ff; }
.soc-sub { font-size: 11px; color: #7090b0; font-family: JetBrains Mono,monospace; margin-top: 5px; }
.badge { border-radius: 20px; padding: 4px 12px; font-size: 10px; font-weight: 700;
         font-family: JetBrains Mono,monospace; letter-spacing: 0.8px; }
.badge-cyan  { background:rgba(0,212,255,0.1);  border:1px solid rgba(0,212,255,0.3);  color:#00d4ff; }
.badge-green { background:rgba(16,185,129,0.12); border:1px solid rgba(16,185,129,0.35); color:#34d399; }

/* ── Section label ────────────────────────────────────────────────────── */
.sec-label {
    font-size: 10px; font-weight: 700; letter-spacing: 2px; text-transform: uppercase;
    color: #7a9ab8; margin-bottom: 12px;
    display: flex; align-items: center; gap: 10px;
}
.sec-label::after { content:''; flex:1; height:1px; background:rgba(255,255,255,0.1); }

/* ── Meta strip ───────────────────────────────────────────────────────── */
.meta-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:10px; margin-bottom:16px; }
.meta-cell { background:rgba(255,255,255,0.04); border:1px solid rgba(255,255,255,0.08);
             border-radius:8px; padding:11px 14px; }
.meta-label { font-size:10px; font-weight:700; letter-spacing:1.2px; text-transform:uppercase;
              color:#7a9ab8; margin-bottom:5px; }
.meta-val { font-size:12px; font-family:JetBrains Mono,monospace; color:#a8c4e0;
            overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }

/* ── Log box ──────────────────────────────────────────────────────────── */
.log-box { background:rgba(0,0,0,0.35); border:1px solid rgba(255,255,255,0.08);
           border-left:3px solid #2a5080; border-radius:8px;
           padding:12px 16px; font-family:JetBrains Mono,monospace;
           font-size:11px; color:#7aaad0; word-break:break-all;
           line-height:1.65; margin-bottom:18px; }

/* ── Trace steps ──────────────────────────────────────────────────────── */
.step-thought { background:rgba(139,92,246,0.08); border:1px solid rgba(139,92,246,0.22);
                border-left:3px solid #8b5cf6; border-radius:8px;
                padding:12px 16px; font-size:13px; color:#d4c5ff; line-height:1.65; }
.step-action  { background:rgba(0,212,255,0.06); border:1px solid rgba(0,212,255,0.18);
                border-left:3px solid #00d4ff; border-radius:8px;
                padding:12px 16px; font-size:13px; color:#90d8f8; }
.step-obs     { background:rgba(16,185,129,0.06); border:1px solid rgba(16,185,129,0.18);
                border-left:3px solid #10b981; border-radius:8px;
                padding:12px 16px; font-size:13px; color:#7ee8c0; }
.step-lbl { font-size:9px; font-weight:700; letter-spacing:2px; text-transform:uppercase;
            margin-bottom:5px; font-family:JetBrains Mono,monospace; opacity:0.8; }
.tool-chip { display:inline-block; background:rgba(0,212,255,0.12);
             border:1px solid rgba(0,212,255,0.28); color:#00d4ff;
             border-radius:4px; padding:1px 7px; font-size:10px;
             font-family:JetBrains Mono,monospace; font-weight:700; margin-left:8px; }

/* ── Verdict cards ────────────────────────────────────────────────────── */
.verdict-card { border-radius:14px; padding:28px; text-align:center; position:relative; overflow:hidden; }
.verdict-mal  { background:linear-gradient(135deg,rgba(239,68,68,0.14),rgba(185,28,28,0.06));
                border:2px solid rgba(239,68,68,0.5); box-shadow:0 0 60px rgba(239,68,68,0.12); }
.verdict-ben  { background:linear-gradient(135deg,rgba(16,185,129,0.14),rgba(5,150,105,0.06));
                border:2px solid rgba(16,185,129,0.5); box-shadow:0 0 60px rgba(16,185,129,0.12); }
.v-eyebrow { font-size:10px; font-weight:700; letter-spacing:3px; text-transform:uppercase;
             font-family:JetBrains Mono,monospace; margin-bottom:8px; }
.v-eye-mal { color:#fca5a5; } .v-eye-ben { color:#6ee7b7; }
.v-icon    { font-size:46px; line-height:1; margin:6px 0 10px; }
.v-word-mal { font-size:28px; font-weight:800; color:#f87171; text-shadow:0 0 22px rgba(239,68,68,0.45); }
.v-word-ben { font-size:28px; font-weight:800; color:#34d399; text-shadow:0 0 22px rgba(16,185,129,0.45); }
.reasoning-box { background:rgba(255,255,255,0.03); border:1px solid rgba(255,255,255,0.1);
                 border-left:3px solid #00d4ff; border-radius:8px;
                 padding:18px 22px; font-size:14px; line-height:1.8; color:#b0c8e4; }

/* ── Status pill / timer ──────────────────────────────────────────────── */
.status-pill { display:inline-flex; align-items:center; gap:8px;
               background:rgba(0,212,255,0.08); border:1px solid rgba(0,212,255,0.25);
               border-radius:20px; padding:7px 16px; font-size:12px; font-weight:600;
               color:#00d4ff; font-family:JetBrains Mono,monospace; }
.pulse { width:8px; height:8px; background:#00d4ff; border-radius:50%;
         box-shadow:0 0 7px #00d4ff; animation:pulse 1.2s infinite; display:inline-block; }
@keyframes pulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:0.28;transform:scale(0.5)} }
.timer-badge { background:rgba(255,255,255,0.05); border:1px solid rgba(255,255,255,0.1);
               border-radius:6px; padding:4px 10px; font-size:12px;
               font-family:JetBrains Mono,monospace; color:#8096b4; display:inline-block; }

/* ── Metrics ──────────────────────────────────────────────────────────── */
[data-testid="metric-container"] { background:rgba(255,255,255,0.04);
    border:1px solid rgba(255,255,255,0.1); border-radius:10px; padding:16px !important; }
[data-testid="metric-container"] [data-testid="stMetricLabel"] {
    color:#7a9ab8 !important; font-size:10px !important; font-weight:700 !important;
    letter-spacing:1.5px !important; text-transform:uppercase !important; }
[data-testid="metric-container"] [data-testid="stMetricValue"] {
    color:#e8f0fc !important; font-size:26px !important;
    font-weight:700 !important; font-family:JetBrains Mono,monospace !important; }

/* ── Buttons ──────────────────────────────────────────────────────────── */
.stButton > button[kind="primary"] {
    background:linear-gradient(135deg,#00b8d9,#0088bb);
    border:none; color:#fff; font-weight:700; font-size:13px;
    border-radius:8px; padding:10px 20px;
    box-shadow:0 4px 18px rgba(0,184,217,0.25); transition:all 0.2s; }
.stButton > button[kind="primary"]:hover {
    box-shadow:0 6px 28px rgba(0,184,217,0.42); transform:translateY(-1px); }

/* ── Misc ─────────────────────────────────────────────────────────────── */
.stProgress > div > div { background:linear-gradient(90deg,#00d4ff,#0077aa) !important; border-radius:4px; }
[data-testid="stExpander"] { background:rgba(255,255,255,0.025);
    border:1px solid rgba(255,255,255,0.08); border-radius:8px; margin:4px 0; }
hr { border-color:rgba(255,255,255,0.08) !important; }

/* ── Sidebar stats ────────────────────────────────────────────────────── */
.stat-row { display:flex; justify-content:space-between; align-items:center;
            padding:8px 12px; border-radius:7px; margin-bottom:5px;
            background:rgba(255,255,255,0.04); border:1px solid rgba(255,255,255,0.08); }
.stat-lbl { font-size:11px; color:#7a9ab8; }
.stat-val { font-size:15px; font-weight:700; font-family:JetBrains Mono,monospace; color:#e8f0fc; }
.hist-row { display:flex; align-items:center; gap:9px; padding:7px 10px;
            border-radius:6px; margin-bottom:4px;
            background:rgba(255,255,255,0.03); border:1px solid rgba(255,255,255,0.06); }
.dot-mal  { width:8px;height:8px;border-radius:50%;background:#ef4444;box-shadow:0 0 6px #ef4444;flex-shrink:0; }
.dot-ben  { width:8px;height:8px;border-radius:50%;background:#10b981;box-shadow:0 0 6px #10b981;flex-shrink:0; }
.hist-id  { font-size:11px;font-family:JetBrains Mono,monospace;color:#8096b4;
            flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap; }
.hist-pct { font-size:11px;font-family:JetBrains Mono,monospace;color:#5a7898; }

/* ── Sidebar brand ────────────────────────────────────────────────────── */
.sb-brand { text-align:center; padding:6px 0 18px; }
.sb-icon  { font-size:42px; filter:drop-shadow(0 0 10px rgba(0,212,255,0.35)); }
.sb-title { font-size:17px; font-weight:800; color:#f0f6ff; letter-spacing:-0.3px; margin-top:3px; }
.sb-title span { color:#00d4ff; }
.sb-sub   { font-size:10px; color:#4a6a8a; font-family:JetBrains Mono,monospace;
            margin-top:3px; letter-spacing:0.5px; }

/* ── Tool landing cards ───────────────────────────────────────────────── */
.tool-card { background:rgba(255,255,255,0.03); border:1px solid rgba(255,255,255,0.08);
             border-radius:10px; padding:15px 16px; height:100%;
             transition:border-color 0.2s, background 0.2s; }
.tool-card:hover { background:rgba(0,212,255,0.05); border-color:rgba(0,212,255,0.22); }
.tc-icon { font-size:20px; margin-bottom:7px; }
.tc-name { font-size:11px; font-weight:700; color:#00d4ff; margin-bottom:4px;
           font-family:JetBrains Mono,monospace; }
.tc-desc { font-size:11px; color:#7a9ab8; line-height:1.55; }

/* ── Batch / result table ─────────────────────────────────────────────── */
.btable { width:100%; border-collapse:collapse; font-size:12px; }
.btable th { padding:10px 12px; text-align:left; font-size:9px; font-weight:700;
             letter-spacing:1.5px; text-transform:uppercase; color:#7a9ab8;
             border-bottom:1px solid rgba(255,255,255,0.1);
             background:rgba(255,255,255,0.025); }
.btable td { padding:9px 12px; border-bottom:1px solid rgba(255,255,255,0.05);
             color:#8096b4; font-family:JetBrains Mono,monospace; }
.btable tr:hover td { background:rgba(255,255,255,0.03); }
.bm { display:inline-block; background:rgba(239,68,68,0.14); color:#fca5a5;
      border:1px solid rgba(239,68,68,0.4); border-radius:4px; padding:2px 8px; font-size:10px; font-weight:700; }
.bb { display:inline-block; background:rgba(16,185,129,0.14); color:#6ee7b7;
      border:1px solid rgba(16,185,129,0.4); border-radius:4px; padding:2px 8px; font-size:10px; font-weight:700; }
.be { display:inline-block; background:rgba(148,163,184,0.1); color:#94a3b8;
      border:1px solid rgba(148,163,184,0.25); border-radius:4px; padding:2px 8px; font-size:10px; font-weight:700; }
.ok  { color:#34d399; font-weight:700; }
.err { color:#f87171; font-weight:700; }

/* ── Difficulty badges ────────────────────────────────────────────────── */
.diff-badge { border-radius:4px; padding:2px 8px; font-size:9px; font-weight:700;
              font-family:JetBrains Mono,monospace; letter-spacing:0.5px; white-space:nowrap; }
.db-easy   { background:rgba(52,211,153,0.12); color:#6ee7b7; border:1px solid rgba(52,211,153,0.3); }
.db-medium { background:rgba(251,191,36,0.12); color:#fcd34d; border:1px solid rgba(251,191,36,0.3); }
.db-hard   { background:rgba(248,113,113,0.12); color:#fca5a5; border:1px solid rgba(248,113,113,0.3); }
.diff-easy   { color:#6ee7b7; }
.diff-medium { color:#fcd34d; }
.diff-hard   { color:#fca5a5; }

/* ── Perfect / accuracy banner ────────────────────────────────────────── */
.perfect-banner {
    background:linear-gradient(135deg,rgba(16,185,129,0.1),rgba(5,150,105,0.04));
    border:1px solid rgba(16,185,129,0.35); border-radius:10px;
    padding:18px 24px; display:flex; align-items:center; gap:16px; margin-top:14px;
}
.pb-icon  { font-size:32px; }
.pb-title { font-size:16px; font-weight:700; color:#34d399; }
.pb-sub   { font-size:12px; color:#7a9ab8; margin-top:3px; }

/* ── Accuracy ring (large) ────────────────────────────────────────────── */
.acc-ring-wrap { text-align:center; padding:10px 0; }
.acc-ring-lbl  { font-size:10px; letter-spacing:2px; text-transform:uppercase;
                 color:#7a9ab8; font-family:JetBrains Mono,monospace; margin-top:6px; }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Constants / sample data
# ---------------------------------------------------------------------------

SAMPLE_ALERTS = {
    "SQL Injection (Malicious)": {
        "alert_id": "demo_sql",
        "timestamp": "2026-04-12T09:15:30Z",
        "source_ip": "45.133.1.22",
        "destination_ip": "192.168.1.10",
        "service": "http_server",
        "log_payload": "GET /login.php?user=admin%27+OR+%271%27%3D%271 HTTP/1.1 - User-Agent: sqlmap/1.5",
    },
    "Data Exfiltration (Malicious)": {
        "alert_id": "demo_exfil",
        "timestamp": "2026-04-12T03:04:11Z",
        "source_ip": "192.168.1.55",
        "destination_ip": "103.205.12.99",
        "service": "firewall_egress",
        "log_payload": "OUTBOUND: Sent 4831838208 bytes via port 443 to external host. Duration: 450s.",
    },
    "System Update (Benign)": {
        "alert_id": "demo_upd",
        "timestamp": "2026-04-12T00:00:05Z",
        "source_ip": "192.168.1.5",
        "destination_ip": "archive.ubuntu.com",
        "service": "os_kernel",
        "log_payload": "root executed: 'sudo apt-get update && sudo apt-get upgrade -y'. Downloaded 150MB.",
    },
    "Failed Logins (Benign)": {
        "alert_id": "demo_fail",
        "timestamp": "2026-04-12T14:22:10Z",
        "source_ip": "192.168.1.102",
        "destination_ip": "192.168.1.10",
        "service": "auth_server",
        "log_payload": "Login_Failed. User: 'sarah.j'. Count: 2. Reason: Invalid Credentials. Source: Office_WiFi.",
    },
    "Mimikatz (Malicious)": {
        "alert_id": "demo_mimi",
        "timestamp": "2026-04-12T02:11:00Z",
        "source_ip": "192.168.10.55",
        "destination_ip": "192.168.10.55",
        "service": "endpoint_edr",
        "log_payload": "Process: mimikatz.exe (PID 5128) opened handle to lsass.exe (PID 624). Access: PROCESS_VM_READ.",
    },
}

TOOL_ICONS = {
    "verify_ip_reputation":           "🌐",
    "decode_payload":                  "🔓",
    "lookup_known_attack_signature":   "🔍",
    "get_user_activity_history":       "👤",
    "analyze_network_traffic_context": "📡",
    "cve_lookup":                      "⚠️",
    "get_geolocation_and_asn":         "📍",
}

# ---------------------------------------------------------------------------
# Session State
# ---------------------------------------------------------------------------

defaults = {
    "history": [], "running": False,
    "total_mal": 0, "total_ben": 0,
    "total_correct": 0, "total_labeled": 0,
    "bench_results": None,   # list of dicts when benchmark has been run
}
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

# ---------------------------------------------------------------------------
# Load pre-saved benchmark results (if any)
# ---------------------------------------------------------------------------

if st.session_state.bench_results is None and BENCH_CACHE.exists():
    try:
        with open(BENCH_CACHE) as f:
            st.session_state.bench_results = json.load(f)
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

with st.sidebar:
    st.markdown("""
    <div class="sb-brand">
        <div class="sb-icon">🛡️</div>
        <div class="sb-title">SOC <span>Analyst</span> AI</div>
        <div class="sb-sub">AUTONOMOUS TIER 1 · MSCS 670</div>
    </div>""", unsafe_allow_html=True)
    st.divider()

    total_inv = len(st.session_state.history)
    if total_inv:
        st.markdown("<div class='sec-label'>Session Stats</div>", unsafe_allow_html=True)
        acc_str = (
            f"{st.session_state.total_correct / st.session_state.total_labeled * 100:.1f}%"
            if st.session_state.total_labeled else "—"
        )
        for lbl, val in [
            ("Investigated", total_inv),
            ("Malicious", st.session_state.total_mal),
            ("Benign", st.session_state.total_ben),
            ("Accuracy", acc_str),
        ]:
            st.markdown(
                f"<div class='stat-row'><span class='stat-lbl'>{lbl}</span>"
                f"<span class='stat-val'>{val}</span></div>", unsafe_allow_html=True)
        st.divider()

    st.markdown("<div class='sec-label'>Input Mode</div>", unsafe_allow_html=True)
    input_mode = st.radio("Input Mode", [
        "Single Alert (JSON)", "Batch (JSON Upload)",
        "Batch (CSV Upload)", "Quick Sample",
    ], label_visibility="collapsed")

    alert_input = None
    csv_alerts  = []

    if input_mode == "Single Alert (JSON)":
        raw_json = st.text_area("Alert JSON",
            value=json.dumps(SAMPLE_ALERTS["SQL Injection (Malicious)"], indent=2),
            height=230)
        if st.button("Investigate Alert", type="primary", use_container_width=True,
                     disabled=st.session_state.running):
            try:    alert_input = json.loads(raw_json)
            except json.JSONDecodeError as e: st.error(f"Invalid JSON: {e}")

    elif input_mode == "Batch (JSON Upload)":
        st.caption("Upload a JSON array of alert objects.")
        uj = st.file_uploader("Upload JSON", type=["json"])
        if uj:
            try:
                data = json.load(uj)
                if isinstance(data, dict): data = [data]
                csv_alerts = data
                has_exp = any("expected" in a for a in csv_alerts)
                st.success(f"Loaded **{len(csv_alerts)}** alerts."
                           + (" Labels found." if has_exp else ""))
            except Exception as e: st.error(f"Parse error: {e}")
        if st.button("Investigate All", type="primary", use_container_width=True,
                     disabled=st.session_state.running or not csv_alerts):
            alert_input = csv_alerts

    elif input_mode == "Batch (CSV Upload)":
        st.caption("Columns: alert_id, timestamp, source_ip, destination_ip, service, log_payload")
        uc = st.file_uploader("Upload CSV", type=["csv"])
        if uc:
            csv_alerts = list(csv.DictReader(io.StringIO(uc.read().decode("utf-8"))))
            st.success(f"Loaded **{len(csv_alerts)}** alerts.")
        if st.button("Investigate All", type="primary", use_container_width=True,
                     disabled=st.session_state.running or not csv_alerts):
            alert_input = csv_alerts

    elif input_mode == "Quick Sample":
        sel = st.selectbox("Choose sample", list(SAMPLE_ALERTS.keys()))
        st.json(SAMPLE_ALERTS[sel], expanded=False)
        if st.button("Investigate Sample", type="primary", use_container_width=True,
                     disabled=st.session_state.running):
            alert_input = SAMPLE_ALERTS[sel]

    st.divider()

    if st.session_state.history:
        st.markdown("<div class='sec-label'>Recent Investigations</div>", unsafe_allow_html=True)
        for item in reversed(st.session_state.history[-10:]):
            mal  = item["verdict"]["verdict"] == "Malicious"
            conf = int(item["verdict"]["confidence"] * 100)
            dot  = "dot-mal" if mal else "dot-ben"
            st.markdown(
                f"<div class='hist-row'><div class='{dot}'></div>"
                f"<div class='hist-id'>{item['alert_id']}</div>"
                f"<div class='hist-pct'>{conf}%</div></div>", unsafe_allow_html=True)
    else:
        st.markdown("<div style='color:#7a9ab8;font-size:11px;text-align:center;padding:14px 0'>"
                    "No investigations yet</div>", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Agent thread helper
# ---------------------------------------------------------------------------

def _agent_thread(alert: dict, eq: queue.Queue) -> None:
    try:
        from agent import run_soc_agent
        run_soc_agent(alert, eq)
    except Exception as e:
        eq.put({"type": "error", "content": str(e)})
        eq.put({"type": "done"})

# ---------------------------------------------------------------------------
# SVG gauge
# ---------------------------------------------------------------------------

def _gauge_svg(pct: int, color: str, track: str, size: int = 120) -> str:
    r     = size * 0.37
    circ  = 2 * 3.14159 * r
    dash  = circ * pct / 100
    cx    = size / 2
    cy    = size / 2
    fs    = int(size * 0.165)
    return (
        f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}">'
        f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{track}" stroke-width="7"/>'
        f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{color}" stroke-width="7"'
        f' stroke-dasharray="{dash:.1f} {circ:.1f}"'
        f' stroke-dashoffset="{circ/4:.1f}" stroke-linecap="round"/>'
        f'<text x="{cx}" y="{cy-4}" text-anchor="middle"'
        f' font-family="JetBrains Mono,monospace" font-size="{fs}" font-weight="700" fill="{color}">{pct}</text>'
        f'<text x="{cx}" y="{cy+12}" text-anchor="middle"'
        f' font-family="JetBrains Mono,monospace" font-size="8" fill="#7a9ab8">CONF%</text>'
        f'</svg>'
    )

# ---------------------------------------------------------------------------
# Verdict renderer
# ---------------------------------------------------------------------------

def render_verdict(verdict: dict) -> None:
    is_mal = verdict["verdict"] == "Malicious"
    pct    = int(verdict["confidence"] * 100)
    if is_mal:
        card_cls,eye_cls,word_cls = "verdict-card verdict-mal","v-eyebrow v-eye-mal","v-word-mal"
        eye,icon,col,trk = "⚠ Threat Detected","🚨","#ef4444","rgba(239,68,68,0.1)"
    else:
        card_cls,eye_cls,word_cls = "verdict-card verdict-ben","v-eyebrow v-eye-ben","v-word-ben"
        eye,icon,col,trk = "✓ No Threat Found","✅","#10b981","rgba(16,185,129,0.1)"

    gauge = _gauge_svg(pct, col, trk)
    st.markdown("<div style='margin-top:24px'></div>", unsafe_allow_html=True)
    c1, c2 = st.columns([5, 7], gap="large")
    with c1:
        st.markdown(f"""
        <div class="{card_cls}">
            <div class="{eye_cls}">{eye}</div>
            <div class="v-icon">{icon}</div>
            <div class="{word_cls}">{verdict['verdict'].upper()}</div>
            <div style="display:flex;justify-content:center;margin-top:12px">{gauge}</div>
        </div>""", unsafe_allow_html=True)
    with c2:
        st.markdown("<div class='sec-label' style='margin-top:0'>Analysis Summary</div>",
                    unsafe_allow_html=True)
        st.markdown(f"<div class='reasoning-box'>{verdict['reasoning']}</div>",
                    unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Single alert investigation renderer
# ---------------------------------------------------------------------------

def render_investigation(alert: dict) -> None:
    aid = alert.get("alert_id") or alert.get("id", "alert")
    pc, tc = st.columns([3, 1])
    with pc:
        st.markdown(f"<div class='status-pill'><span class='pulse'></span>"
                    f"Investigating &nbsp;<strong>{aid}</strong></div>", unsafe_allow_html=True)
    timer_slot = tc.empty()

    st.markdown("<div style='margin:16px 0 10px'></div>", unsafe_allow_html=True)

    src = alert.get("source_ip","—"); dst = alert.get("destination_ip","—")
    svc = alert.get("service") or alert.get("event_type","—")
    ts  = alert.get("timestamp","—")
    st.markdown(f"""
    <div class="meta-grid">
      <div class="meta-cell"><div class="meta-label">Source IP</div><div class="meta-val">{src}</div></div>
      <div class="meta-cell"><div class="meta-label">Destination</div><div class="meta-val">{dst}</div></div>
      <div class="meta-cell"><div class="meta-label">Service / Event</div><div class="meta-val">{svc}</div></div>
      <div class="meta-cell"><div class="meta-label">Timestamp</div><div class="meta-val">{ts}</div></div>
    </div>""", unsafe_allow_html=True)

    log = alert.get("log_payload") or alert.get("raw_log","")
    if log:
        st.markdown(f"<div class='sec-label'>Log Payload</div>"
                    f"<div class='log-box'>{log[:400]}{'…' if len(log)>400 else ''}</div>",
                    unsafe_allow_html=True)

    st.markdown("<div class='sec-label'>Agent Reasoning Trace</div>", unsafe_allow_html=True)

    trace_area   = st.container()
    verdict_slot = st.empty()
    final_verdict = None
    step_num = 0
    t0 = time.time()

    with st.spinner("Analyzing alert…"):
        eq = queue.Queue()
        th = threading.Thread(target=_agent_thread, args=(alert, eq), daemon=True)
        th.start()
        while True:
            timer_slot.markdown(
                f"<div class='timer-badge'>⏱ {int(time.time()-t0)}s</div>",
                unsafe_allow_html=True)
            try:
                ev = eq.get(timeout=120)
            except queue.Empty:
                st.error("Agent timed out."); break

            etype = ev.get("type","")
            if etype == "done": break
            elif etype == "error": st.error(f"Agent error: {ev['content']}"); break
            elif etype == "thought":
                step_num += 1
                with trace_area:
                    with st.expander(f"💭  Step {step_num} — Reasoning", expanded=False):
                        st.markdown(f"<div class='step-thought'><div class='step-lbl' style='color:#a78bfa'>"
                                    f"Thought</div>{ev['content']}</div>", unsafe_allow_html=True)
            elif etype == "action":
                tool = ev["tool"]; icon = TOOL_ICONS.get(tool,"🔧")
                with trace_area:
                    with st.expander(f"{icon}  Step {step_num} — {tool}", expanded=False):
                        st.markdown(f"<div class='step-action'><div class='step-lbl' style='color:#38bdf8'>"
                                    f"Tool Call<span class='tool-chip'>{tool}</span></div>",
                                    unsafe_allow_html=True)
                        st.json(ev["args"])
                        st.markdown("</div>", unsafe_allow_html=True)
            elif etype == "observation":
                tool = ev.get("tool",""); icon = TOOL_ICONS.get(tool,"📋")
                with trace_area:
                    with st.expander(f"{icon}  Result — {tool}", expanded=False):
                        st.markdown(f"<div class='step-obs'><div class='step-lbl' style='color:#6ee7b7'>"
                                    f"Observation</div>", unsafe_allow_html=True)
                        try:    st.json(json.loads(ev["result"]))
                        except: st.code(ev["result"], language=None)
                        st.markdown("</div>", unsafe_allow_html=True)
            elif etype == "verdict":
                final_verdict = ev["data"]
                st.session_state.history.append({"alert_id": aid, "verdict": final_verdict})
                if final_verdict["verdict"] == "Malicious": st.session_state.total_mal += 1
                else:                                        st.session_state.total_ben += 1
            elif etype == "warning": st.warning(ev["content"])

    th.join(timeout=5)
    timer_slot.markdown(f"<div class='timer-badge'>⏱ {int(time.time()-t0)}s</div>",
                        unsafe_allow_html=True)
    if final_verdict:
        with verdict_slot.container(): render_verdict(final_verdict)
    else:
        verdict_slot.warning("No verdict produced.")

# ---------------------------------------------------------------------------
# Batch HTML table
# ---------------------------------------------------------------------------

def _batch_html(rows: list) -> str:
    hdr = ("<table class='btable'><thead><tr>"
           "<th>#</th><th>Alert ID</th><th>Difficulty</th><th>Expected</th>"
           "<th>Verdict</th><th>Match</th><th>Conf.</th><th>Reasoning</th>"
           "</tr></thead><tbody>")
    body = ""
    for i, r in enumerate(rows, 1):
        v = r.get("Verdict","")
        badge = (f"<span class='bm'>MALICIOUS</span>" if v=="Malicious"
                 else f"<span class='bb'>BENIGN</span>" if v=="Benign"
                 else f"<span class='be'>ERROR</span>")
        m  = r.get("Match","—")
        mh = (f"<span class='ok'>✓</span>" if m=="✓"
              else f"<span class='err'>✗</span>" if m=="✗" else "—")
        diff = r.get("Difficulty","—").lower()
        dcls = {"easy":"db-easy","medium":"db-medium","hard":"db-hard"}.get(diff,"")
        dh   = f"<span class='diff-badge {dcls}'>{diff.upper()}</span>" if dcls else "—"
        rsn  = r.get("Reasoning","")
        rsn_short = rsn[:85] + ("…" if len(rsn)>85 else "")
        body += (f"<tr><td style='color:#5a7898'>{i}</td>"
                 f"<td style='color:#94a3b8'>{r.get('Alert ID','')}</td>"
                 f"<td>{dh}</td><td style='color:#8aaccc'>{r.get('Expected','—')}</td>"
                 f"<td>{badge}</td><td>{mh}</td>"
                 f"<td style='color:#8aaccc'>{r.get('Confidence','—')}</td>"
                 f"<td style='color:#6b8aaa;font-family:Inter,sans-serif;font-size:11px'>{rsn_short}</td>"
                 f"</tr>")
    return hdr + body + "</tbody></table>"

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

st.markdown("""
<div class="soc-header">
  <div class="soc-scanline"></div>
  <div style="font-size:50px;filter:drop-shadow(0 0 12px rgba(0,212,255,0.35))">🛡️</div>
  <div>
    <div class="soc-title">Autonomous <span>SOC Analyst</span> AI</div>
    <div class="soc-sub">Tier 1 Security Operations · ReAct + Chain-of-Thought · MSCS 670</div>
  </div>
  <div style="margin-left:auto;display:flex;align-items:center;gap:6px">
    <span class="badge badge-cyan">qwen/qwen-turbo</span>
    <span class="badge badge-green">100% accuracy</span>
  </div>
</div>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------

tab_inv, tab_bench, tab_about = st.tabs(["🔍 Investigate", "📊 Benchmark", "📖 About"])

# ═══════════════════════════════════════════════════════════════════════════
# TAB 1 — INVESTIGATE
# ═══════════════════════════════════════════════════════════════════════════

with tab_inv:
    if not alert_input:
        # Landing page
        tools_info = [
            ("🌐","verify_ip_reputation","Risk score, categories, country & ISP"),
            ("🔓","decode_payload","URL/Base64/HTML decode + 40+ attack patterns"),
            ("🔍","lookup_known_attack_signature","LOLBins, CVEs, EventIDs, hashes, UAs"),
            ("👤","get_user_activity_history","Login history, auth method baseline"),
            ("📡","analyze_network_traffic_context","Volume baselines, C2 IPs, off-hours"),
            ("⚠️","cve_lookup","CVE details by ID or service + version"),
            ("📍","get_geolocation_and_asn","Country, ASN type, geofence violations"),
        ]
        st.markdown("<div style='color:#9ab8d4;font-size:13px;margin-bottom:20px;line-height:1.7'>"
                    "Select an input mode in the sidebar, paste or upload a security alert, "
                    "then click <strong style='color:#c8dff0'>Investigate</strong>. "
                    "The agent reasons step-by-step, calls investigative tools, "
                    "and emits a structured verdict with confidence score.</div>",
                    unsafe_allow_html=True)

        st.markdown("<div class='sec-label'>Investigative Tools</div>", unsafe_allow_html=True)
        cols = st.columns(4)
        for i,(icon,name,desc) in enumerate(tools_info):
            with cols[i % 4]:
                st.markdown(f"<div class='tool-card'>"
                            f"<div class='tc-icon'>{icon}</div>"
                            f"<div class='tc-name'>{name}</div>"
                            f"<div class='tc-desc'>{desc}</div>"
                            f"</div><div style='height:8px'></div>", unsafe_allow_html=True)

    elif isinstance(alert_input, list):
        # Batch mode
        total = len(alert_input)
        st.markdown(f"<div style='font-size:20px;font-weight:800;color:#fff;margin-bottom:4px'>"
                    f"Batch Investigation</div>"
                    f"<div style='color:#7a9ab8;font-size:13px;margin-bottom:18px'>"
                    f"{total} alerts queued</div>", unsafe_allow_html=True)

        st.session_state.running = True
        progress_bar = st.progress(0.0)
        status_text  = st.empty()
        table_area   = st.empty()
        batch_results: list = []

        # Load ground truth for difficulty info
        gt_map: dict = {}
        if GT_PATH.exists():
            with open(GT_PATH) as f:
                for g in json.load(f):
                    gt_map[g["id"]] = g

        for i, alert in enumerate(alert_input):
            aid = alert.get("alert_id") or alert.get("id", f"alert_{i+1}")
            status_text.markdown(
                f"<div class='status-pill'><span class='pulse'></span>"
                f"Investigating {i+1}/{total}: &nbsp;<strong>{aid}</strong></div>",
                unsafe_allow_html=True)
            progress_bar.progress(i / total)

            eq = queue.Queue()
            t  = threading.Thread(target=_agent_thread, args=(alert, eq), daemon=True)
            t.start()
            verdict = None
            while True:
                try:
                    ev = eq.get(timeout=120)
                    if ev["type"]=="done": break
                    if ev["type"]=="verdict":
                        verdict = ev["data"]
                        st.session_state.history.append({"alert_id":aid,"verdict":verdict})
                except queue.Empty: break
            t.join(timeout=5)

            expected = alert.get("expected") or None
            gt_entry = gt_map.get(aid,{})
            diff = gt_entry.get("difficulty","—") if gt_entry else "—"

            if verdict:
                correct = (verdict["verdict"]==expected) if expected else None
                batch_results.append({
                    "Alert ID":   aid,
                    "Difficulty": diff,
                    "Expected":   expected or "—",
                    "Verdict":    verdict["verdict"],
                    "Match":      ("✓" if correct else "✗") if correct is not None else "—",
                    "Confidence": f"{int(verdict['confidence']*100)}%",
                    "Reasoning":  verdict["reasoning"],
                })
                if verdict["verdict"]=="Malicious": st.session_state.total_mal += 1
                else:                                st.session_state.total_ben += 1
                if correct is not None:
                    st.session_state.total_labeled += 1
                    if correct: st.session_state.total_correct += 1
            else:
                batch_results.append({
                    "Alert ID":aid,"Difficulty":diff,"Expected":expected or "—",
                    "Verdict":"ERROR","Match":"✗" if expected else "—",
                    "Confidence":"—","Reasoning":"Agent timed out or failed.",
                })

            progress_bar.progress((i+1)/total)
            table_area.markdown(_batch_html(batch_results), unsafe_allow_html=True)

        status_text.markdown(
            f"<div style='color:#10b981;font-size:13px;font-weight:600;padding:8px 0'>"
            f"✓ All {total} investigations complete.</div>", unsafe_allow_html=True)
        st.session_state.running = False

        table_area.markdown(_batch_html(batch_results), unsafe_allow_html=True)
        st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)

        labeled = [r for r in batch_results if r.get("Match") in ("✓","✗")]
        correct_count = sum(1 for r in labeled if r["Match"]=="✓")
        mal_c = sum(1 for r in batch_results if r["Verdict"]=="Malicious")
        ben_c = sum(1 for r in batch_results if r["Verdict"]=="Benign")
        err_c = len(batch_results) - mal_c - ben_c

        if labeled:
            acc = correct_count/len(labeled)*100
            c1,c2,c3,c4,c5 = st.columns(5)
            c1.metric("Accuracy", f"{acc:.1f}%")
            c2.metric("Correct",  f"{correct_count}/{len(labeled)}")
            c3.metric("Malicious",mal_c); c4.metric("Benign",ben_c); c5.metric("Errors",err_c)
            wrong = [r for r in batch_results if r.get("Match")=="✗"]
            if wrong:
                with st.expander(f"Wrong predictions ({len(wrong)})", expanded=True):
                    st.markdown(_batch_html(wrong), unsafe_allow_html=True)
            else:
                st.markdown(f"""<div class="perfect-banner">
                  <div class="pb-icon">🎯</div>
                  <div><div class="pb-title">Perfect Score — 100% Accuracy</div>
                  <div class="pb-sub">All {len(labeled)} alerts correctly classified.</div></div>
                </div>""", unsafe_allow_html=True)
        else:
            c1,c2,c3 = st.columns(3)
            c1.metric("Malicious",mal_c); c2.metric("Benign",ben_c); c3.metric("Errors",err_c)

        st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
        d1,d2 = st.columns(2)
        with d1:
            st.download_button("⬇ Download Results (JSON)",
                data=json.dumps(batch_results,indent=2),
                file_name="soc_verdicts.json", mime="application/json",
                use_container_width=True)
        with d2:
            out = io.StringIO()
            if batch_results:
                w = csv.DictWriter(out, fieldnames=batch_results[0].keys())
                w.writeheader(); w.writerows(batch_results)
            st.download_button("⬇ Download Results (CSV)",
                data=out.getvalue(), file_name="soc_verdicts.csv", mime="text/csv",
                use_container_width=True)
    else:
        st.session_state.running = True
        render_investigation(alert_input)
        st.session_state.running = False

# ═══════════════════════════════════════════════════════════════════════════
# TAB 2 — BENCHMARK
# ═══════════════════════════════════════════════════════════════════════════

with tab_bench:

    # Load ground truth
    gt_records: list = []
    if GT_PATH.exists():
        with open(GT_PATH) as f:
            gt_records = json.load(f)
    gt_map = {g["id"]: g for g in gt_records}

    bench_results = st.session_state.bench_results  # None or list of dicts

    # ── Header ──
    st.markdown("<div style='font-size:20px;font-weight:800;color:#fff;margin-bottom:4px'>"
                "Benchmark Results</div>"
                "<div style='color:#7a9ab8;font-size:13px;margin-bottom:18px'>"
                "65-alert labeled test set · Easy / Medium / Hard difficulty tiers</div>",
                unsafe_allow_html=True)

    # ── Run / Clear buttons ──
    rb_col, cb_col, sp_col = st.columns([2, 1, 5])
    run_bench = False
    with rb_col:
        alerts_ready = ALERTS_PATH.exists()
        run_bench = st.button(
            "▶ Run Full Benchmark",
            type="primary",
            use_container_width=True,
            disabled=st.session_state.running or not alerts_ready,
            help="Requires 65_alerts_with_labels.json" if not alerts_ready else "",
        )
    with cb_col:
        if st.button("Clear", use_container_width=True,
                     disabled=bench_results is None):
            st.session_state.bench_results = None
            if BENCH_CACHE.exists(): BENCH_CACHE.unlink()
            st.rerun()

    if not alerts_ready:
        st.warning("`65_alerts_with_labels.json` not found in project directory. "
                   "Place the file next to app.py to enable the benchmark.")

    # ── Run benchmark ──
    if run_bench and alerts_ready:
        with open(ALERTS_PATH) as f:
            bench_alerts = json.load(f)

        total = len(bench_alerts)
        st.session_state.running = True
        bench_progress = st.progress(0.0)
        bench_status   = st.empty()
        bench_table    = st.empty()
        new_results: list = []

        for i, alert in enumerate(bench_alerts):
            aid  = alert.get("alert_id") or alert.get("id", f"alert_{i+1}")
            gt   = gt_map.get(aid, {})
            diff = gt.get("difficulty","—")
            bench_status.markdown(
                f"<div class='status-pill'><span class='pulse'></span>"
                f"Running {i+1}/{total}: &nbsp;<strong>{aid}</strong> "
                f"<span style='color:#7a9ab8'>({diff})</span></div>",
                unsafe_allow_html=True)
            bench_progress.progress(i / total)

            eq = queue.Queue()
            t  = threading.Thread(target=_agent_thread, args=(alert, eq), daemon=True)
            t.start()
            verdict = None
            while True:
                try:
                    ev = eq.get(timeout=120)
                    if ev["type"]=="done": break
                    if ev["type"]=="verdict": verdict = ev["data"]
                except queue.Empty: break
            t.join(timeout=5)

            expected = alert.get("expected") or gt.get("true_label","—")
            if verdict:
                correct  = (verdict["verdict"]==expected) if expected and expected!="—" else None
                new_results.append({
                    "Alert ID":   aid,
                    "Difficulty": diff,
                    "Expected":   expected,
                    "Verdict":    verdict["verdict"],
                    "Match":      ("✓" if correct else "✗") if correct is not None else "—",
                    "Confidence": f"{int(verdict['confidence']*100)}%",
                    "conf_raw":   verdict["confidence"],
                    "Reasoning":  verdict["reasoning"],
                    "explanation":gt.get("explanation",""),
                })
            else:
                new_results.append({
                    "Alert ID":aid,"Difficulty":diff,"Expected":expected,
                    "Verdict":"ERROR","Match":"✗","Confidence":"—","conf_raw":0.0,
                    "Reasoning":"Agent timed out or failed.","explanation":gt.get("explanation",""),
                })
            bench_progress.progress((i+1)/total)
            bench_table.markdown(_batch_html(new_results), unsafe_allow_html=True)

        bench_status.markdown(
            f"<div style='color:#10b981;font-size:13px;font-weight:600;padding:8px 0'>"
            f"✓ Benchmark complete — {total} alerts processed.</div>", unsafe_allow_html=True)
        bench_progress.progress(1.0)
        st.session_state.running = False
        st.session_state.bench_results = new_results
        try:
            with open(BENCH_CACHE,"w") as f:
                json.dump(new_results, f, indent=2)
        except Exception:
            pass
        bench_results = new_results
        st.rerun()

    # ── Display results ──
    if bench_results:

        labeled = [r for r in bench_results if r.get("Match") in ("✓","✗")]
        correct = [r for r in labeled if r["Match"]=="✓"]
        wrong   = [r for r in labeled if r["Match"]=="✗"]
        mal_r   = [r for r in bench_results if r["Verdict"]=="Malicious"]
        ben_r   = [r for r in bench_results if r["Verdict"]=="Benign"]
        acc_pct = int(len(correct)/len(labeled)*100) if labeled else 0

        # ── Overall accuracy section ──
        oa, od = st.columns([2, 5], gap="large")
        with oa:
            # Big accuracy ring
            r   = 70
            circ = 2 * 3.14159 * r
            dash = circ * acc_pct / 100
            gauge_html = (
                f'<div class="acc-ring-wrap">'
                f'<svg width="180" height="180" viewBox="0 0 180 180">'
                f'<circle cx="90" cy="90" r="{r}" fill="none" stroke="rgba(16,185,129,0.1)" stroke-width="10"/>'
                f'<circle cx="90" cy="90" r="{r}" fill="none" stroke="#10b981" stroke-width="10"'
                f' stroke-dasharray="{dash:.1f} {circ:.1f}"'
                f' stroke-dashoffset="{circ/4:.1f}" stroke-linecap="round"/>'
                f'<text x="90" y="82" text-anchor="middle"'
                f' font-family="JetBrains Mono,monospace" font-size="34" font-weight="800" fill="#10b981">{acc_pct}</text>'
                f'<text x="90" y="104" text-anchor="middle"'
                f' font-family="JetBrains Mono,monospace" font-size="10" fill="#7a9ab8">ACCURACY %</text>'
                f'</svg>'
                f'<div class="acc-ring-lbl">{len(correct)}/{len(labeled)} correct</div>'
                f'</div>'
            )
            st.markdown(gauge_html, unsafe_allow_html=True)

        with od:
            st.markdown("<div class='sec-label'>Overall Metrics</div>", unsafe_allow_html=True)
            m1,m2,m3,m4 = st.columns(4)
            m1.metric("Accuracy",  f"{acc_pct}%")
            m2.metric("Correct",   f"{len(correct)}/{len(labeled)}")
            m3.metric("Malicious", len(mal_r))
            m4.metric("Benign",    len(ben_r))

            st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)

            # Per-difficulty breakdown
            st.markdown("<div class='sec-label'>Accuracy by Difficulty</div>", unsafe_allow_html=True)
            diff_cols = st.columns(3)
            for col, diff, cls, color, trk in [
                (diff_cols[0],"easy",   "diff-easy",  "#34d399","rgba(52,211,153,0.1)"),
                (diff_cols[1],"medium", "diff-medium","#fbbf24","rgba(251,191,36,0.1)"),
                (diff_cols[2],"hard",   "diff-hard",  "#f87171","rgba(248,113,113,0.1)"),
            ]:
                subset  = [r for r in labeled if r.get("Difficulty","").lower()==diff]
                ok      = sum(1 for r in subset if r["Match"]=="✓")
                pct     = int(ok/len(subset)*100) if subset else 0
                gauge   = _gauge_svg(pct, color, trk, size=100)
                with col:
                    st.markdown(
                        f"<div style='text-align:center;background:rgba(255,255,255,0.02);"
                        f"border:1px solid rgba(255,255,255,0.05);border-radius:10px;padding:14px 10px'>"
                        f"<div class='diff-ring-label {cls}'>{diff.upper()}</div>"
                        f"<div style='display:flex;justify-content:center'>{gauge}</div>"
                        f"<div style='color:#7a9ab8;font-size:11px;margin-top:4px'>"
                        f"{ok}/{len(subset)} correct</div></div>",
                        unsafe_allow_html=True)

        st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)

        # ── Filters ──
        st.markdown("<div class='sec-label'>Per-Alert Results</div>", unsafe_allow_html=True)

        fc1, fc2, fc3 = st.columns([2, 2, 3])
        with fc1:
            diff_filter = st.selectbox("Difficulty", ["All","Easy","Medium","Hard"],
                                       label_visibility="collapsed")
        with fc2:
            verdict_filter = st.selectbox("Verdict", ["All","Malicious","Benign","Error"],
                                          label_visibility="collapsed")
        with fc3:
            match_filter = st.selectbox("Match", ["All","Correct ✓","Wrong ✗"],
                                        label_visibility="collapsed")

        # Apply filters
        display = bench_results[:]
        if diff_filter != "All":
            display = [r for r in display if r.get("Difficulty","").lower()==diff_filter.lower()]
        if verdict_filter != "All":
            v_map = {"Error":"ERROR"}
            display = [r for r in display
                       if r.get("Verdict","")==v_map.get(verdict_filter,verdict_filter)]
        if match_filter != "All":
            m_map = {"Correct ✓":"✓","Wrong ✗":"✗"}
            display = [r for r in display if r.get("Match","")==m_map[match_filter]]

        st.markdown(f"<div style='color:#7a9ab8;font-size:12px;margin-bottom:10px'>"
                    f"Showing {len(display)} of {len(bench_results)} alerts</div>",
                    unsafe_allow_html=True)

        # ── Per-alert cards ──
        for r in display:
            v   = r.get("Verdict","")
            m   = r.get("Match","—")
            aid = r.get("Alert ID","")
            diff = r.get("Difficulty","—").lower()
            pct  = r.get("Confidence","—")
            exp  = r.get("explanation","")
            rsn  = r.get("Reasoning","")

            if v == "Malicious":
                card_cls = "bench-card bench-card-mal"
                vbadge   = "<span class='bm'>MALICIOUS</span>"
            elif v == "Benign":
                card_cls = "bench-card bench-card-ben"
                vbadge   = "<span class='bb'>BENIGN</span>"
            else:
                card_cls = "bench-card bench-card-err"
                vbadge   = "<span class='be'>ERROR</span>"

            mh = (f"<span class='ok' style='font-size:15px'>✓</span>" if m=="✓"
                  else f"<span class='err' style='font-size:15px'>✗</span>" if m=="✗" else "—")
            dcls = {"easy":"db-easy","medium":"db-medium","hard":"db-hard"}.get(diff,"")
            dh   = f"<span class='diff-badge {dcls}'>{diff.upper()}</span>" if dcls else "—"

            with st.expander(
                f"{'✓' if m=='✓' else '✗' if m=='✗' else '—'}  {aid}  ·  "
                f"{diff.upper()}  ·  {v}  ·  {pct}",
                expanded=(m=="✗")
            ):
                ex_c1, ex_c2 = st.columns([1, 3])
                with ex_c1:
                    st.markdown(
                        f"<div style='background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.05);"
                        f"border-radius:8px;padding:14px;text-align:center'>"
                        f"<div style='font-size:11px;color:#7a9ab8;letter-spacing:1px;margin-bottom:6px'>VERDICT</div>"
                        f"{vbadge}"
                        f"<div style='margin-top:10px;font-size:11px;color:#7a9ab8;letter-spacing:1px'>CONFIDENCE</div>"
                        f"<div style='font-size:20px;font-weight:700;font-family:JetBrains Mono,monospace;"
                        f"color:#94a3b8;margin-top:4px'>{pct}</div>"
                        f"<div style='margin-top:10px;font-size:11px;color:#7a9ab8;letter-spacing:1px'>DIFFICULTY</div>"
                        f"<div style='margin-top:4px'>{dh}</div>"
                        f"<div style='margin-top:10px;font-size:11px;color:#7a9ab8;letter-spacing:1px'>MATCH</div>"
                        f"<div style='margin-top:4px;font-size:22px'>{mh}</div>"
                        f"</div>",
                        unsafe_allow_html=True)
                with ex_c2:
                    if exp:
                        st.markdown(
                            f"<div style='margin-bottom:10px'>"
                            f"<div style='font-size:9px;font-weight:700;letter-spacing:2px;text-transform:uppercase;"
                            f"color:#7a9ab8;margin-bottom:6px'>Ground Truth Explanation</div>"
                            f"<div style='background:rgba(0,212,255,0.03);border:1px solid rgba(0,212,255,0.1);"
                            f"border-left:3px solid #00d4ff;border-radius:8px;padding:12px 16px;"
                            f"font-size:13px;color:#8aaccc;line-height:1.65'>{exp}</div></div>",
                            unsafe_allow_html=True)
                    if rsn:
                        st.markdown(
                            f"<div>"
                            f"<div style='font-size:9px;font-weight:700;letter-spacing:2px;text-transform:uppercase;"
                            f"color:#7a9ab8;margin-bottom:6px'>Agent Reasoning</div>"
                            f"<div style='background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.05);"
                            f"border-left:3px solid #475569;border-radius:8px;padding:12px 16px;"
                            f"font-size:13px;color:#8aaccc;line-height:1.65'>{rsn}</div></div>",
                            unsafe_allow_html=True)

        # ── Perfect / wrong summary ──
        st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)
        if wrong:
            st.markdown(f"<div style='color:#f87171;font-size:13px;font-weight:600;margin-bottom:6px'>"
                        f"⚠ {len(wrong)} wrong prediction(s)</div>", unsafe_allow_html=True)
            st.markdown(_batch_html(wrong), unsafe_allow_html=True)
        elif labeled:
            st.markdown(f"""<div class="perfect-banner">
              <div class="pb-icon">🎯</div>
              <div><div class="pb-title">Perfect Score — 100% Accuracy</div>
              <div class="pb-sub">All {len(labeled)} alerts correctly classified across Easy, Medium, and Hard tiers.</div></div>
            </div>""", unsafe_allow_html=True)

        # ── Download ──
        st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)
        d1, d2 = st.columns(2)
        with d1:
            st.download_button("⬇ Download Benchmark (JSON)",
                data=json.dumps(bench_results,indent=2),
                file_name="benchmark_results.json", mime="application/json",
                use_container_width=True)
        with d2:
            out = io.StringIO()
            if bench_results:
                keys = ["Alert ID","Difficulty","Expected","Verdict","Match","Confidence","Reasoning"]
                w = csv.DictWriter(out, fieldnames=keys, extrasaction="ignore")
                w.writeheader(); w.writerows(bench_results)
            st.download_button("⬇ Download Benchmark (CSV)",
                data=out.getvalue(), file_name="benchmark_results.csv", mime="text/csv",
                use_container_width=True)

    elif not run_bench:
        # No results yet
        st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)
        st.markdown("""
        <div style='text-align:center;padding:60px 20px'>
            <div style='font-size:48px;margin-bottom:16px'>📊</div>
            <div style='font-size:18px;font-weight:700;color:#c4d8f0;margin-bottom:10px'>
                No benchmark results yet</div>
            <div style='font-size:13px;color:#8096b4;line-height:1.8'>
                Click <strong style='color:#00d4ff'>▶ Run Full Benchmark</strong> above to evaluate<br>
                the agent against all 65 labeled security alerts.<br><br>
                Results are cached to disk and load instantly on next visit.
            </div>
        </div>
        """, unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════
# TAB 3 — ABOUT
# ═══════════════════════════════════════════════════════════════════════════

with tab_about:
    st.markdown("<div style='max-width:800px'>", unsafe_allow_html=True)

    st.markdown("""
### Architecture

The agent uses a **ReAct loop** (Reason → Act → Observe) powered by LangChain's
tool-calling interface with the `qwen/qwen-turbo` model via OpenRouter.

```
Alert JSON
   │
   ▼
[SystemPrompt + HumanMessage(alert)]
   │
   ▼  ┌─────────────────────────────┐
   │  │  LOOP  (max 8 iterations)  │
   │  │                            │
   │  │  LLM invoked with tools    │
   │  │     ↓ tool_calls?          │
   │  │  YES → execute tools       │
   │  │        append ToolMessage  │
   │  │     ↓ no tool_calls        │
   │  │  extract JSON verdict      │
   │  └─────────────────────────────┘
   │
   ▼
{ "verdict": "Malicious"|"Benign",
  "confidence": 0.0–1.0,
  "reasoning": "…" }
```
""")

    st.markdown("""
### Investigative Tools (7)

| Tool | Purpose |
|------|---------|
| `verify_ip_reputation` | Risk score, threat categories, ISP for any IP |
| `decode_payload` | URL / Base64 / HTML decode + 40+ attack patterns |
| `lookup_known_attack_signature` | LOLBins, CVEs, EventIDs, process names, hashes |
| `get_user_activity_history` | Login history, auth method baseline anomalies |
| `analyze_network_traffic_context` | Volume baselines, C2 IPs, off-hours detection |
| `cve_lookup` | CVE details by ID or service + version |
| `get_geolocation_and_asn` | Country, ASN type, hosting flag, geofence |
""")

    st.markdown("""
### Benchmark

| Difficulty | Count | Labels | Benchmark |
|------------|-------|--------|-----------|
| Easy   | 20 | 10 Benign, 10 Malicious | 100% |
| Medium | 20 | 8 Benign, 12 Malicious  | 100% |
| Hard   | 25 | 5 Benign, 20 Malicious  | 100% |
| **Total** | **65** | **23 B / 42 M** | **100%** |

Key accuracy techniques:
- **Two-signal minimum** — require ≥2 independent evidence sources before high confidence
- **Tool result caching** — no repeated calls for same args within a session
- **Prompt injection sanitization** — strips adversarial override attempts from log payloads
- **Few-shot examples** — 12 domain-specific examples anchoring ReAct trace format
- **Behavioral rules** — explicit prompting for EventID 1102, IMDSv1 vs IMDSv2, LOLBins, beaconing
""")

    st.markdown("</div>", unsafe_allow_html=True)
