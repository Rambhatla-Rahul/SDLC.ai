"""
Streamlit frontend for the AI-Native Dev Pipeline.

Install deps:
    pip install streamlit websocket-client requests

Run:
    streamlit run pipeline_ui.py
"""

import json
import queue
import threading
import time
from datetime import datetime

import requests
import streamlit as st
import websocket

# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

API_BASE = "http://localhost:8000"
WS_BASE  = "ws://localhost:8000"

PIPELINE_STAGES = [
    ("intent_agent",         "🧠 Intent Parser",        "parse"),
    ("ip_guard_agent",       "🔒 IP Guard",             "scan"),
    ("hitl_gate_1",          "👤 Human Review I",       "gate"),
    ("compliance_agent",     "📋 Compliance",           "analyse"),
    ("architecture_agent",   "🏛️  Architect",           "design"),
    ("hitl_gate_2",          "👤 Human Review II",      "gate"),
    ("codegen_agent",        "⚙️  Code Generator",      "generate"),
    ("optimizer_agent",      "✨ Optimizer",            "optimise"),
    ("security_agent",       "🛡️  Security Scan",       "scan"),
    ("explainability_agent", "📖 Explainability",       "document"),
    ("quality_agent",        "🔬 Quality Gate",         "assess"),
    ("audit_agent",          "📝 Audit Logger",         "audit"),
    ("hitl_gate_3",          "👤 Human Review III",     "gate"),
]

STAGE_NAMES = [s[0] for s in PIPELINE_STAGES]

# ─────────────────────────────────────────────────────────────────────────────
# Page config & dark-terminal theme
# ─────────────────────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="AI Dev Pipeline",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Syne:wght@400;600;700;800&display=swap');

/* ── Root variables ── */
:root {
    --bg:        #0a0c0f;
    --surface:   #10141a;
    --surface2:  #161c26;
    --border:    #1e2a38;
    --amber:     #f5a623;
    --amber-dim: #a06b10;
    --green:     #4ade80;
    --red:       #f87171;
    --blue:      #60a5fa;
    --text:      #c8d6e5;
    --muted:     #566779;
    --font-mono: 'JetBrains Mono', monospace;
    --font-ui:   'Syne', sans-serif;
}

/* ── Global resets ── */
html, body, [data-testid="stAppViewContainer"] {
    background: var(--bg) !important;
    color: var(--text) !important;
    font-family: var(--font-mono) !important;
}
[data-testid="stSidebar"] {
    background: var(--surface) !important;
    border-right: 1px solid var(--border) !important;
}
[data-testid="stSidebar"] * { color: var(--text) !important; }

/* ── Hide Streamlit chrome ── */
#MainMenu, footer, header { visibility: hidden; }
[data-testid="stToolbar"] { display: none; }
.block-container { padding-top: 1.5rem !important; }

/* ── Typography ── */
h1, h2, h3 { font-family: var(--font-ui) !important; color: #e8f0f8 !important; }
p, li, span, label, div { font-family: var(--font-mono) !important; }

/* ── Inputs & buttons ── */
[data-testid="stTextArea"] textarea,
[data-testid="stTextInput"] input {
    background: var(--surface2) !important;
    border: 1px solid var(--border) !important;
    color: var(--text) !important;
    font-family: var(--font-mono) !important;
    border-radius: 4px !important;
}
[data-testid="stTextArea"] textarea:focus,
[data-testid="stTextInput"] input:focus {
    border-color: var(--amber) !important;
    box-shadow: 0 0 0 2px rgba(245,166,35,0.15) !important;
}
button[kind="primary"], [data-testid="baseButton-primary"] {
    background: var(--amber) !important;
    color: #0a0c0f !important;
    font-family: var(--font-ui) !important;
    font-weight: 700 !important;
    border: none !important;
    border-radius: 4px !important;
    letter-spacing: 0.08em !important;
}
button[kind="secondary"], [data-testid="baseButton-secondary"] {
    background: transparent !important;
    border: 1px solid var(--border) !important;
    color: var(--text) !important;
    font-family: var(--font-mono) !important;
    border-radius: 4px !important;
}

/* ── Selectbox ── */
[data-testid="stSelectbox"] > div > div {
    background: var(--surface2) !important;
    border: 1px solid var(--border) !important;
    color: var(--text) !important;
}

/* ── Tabs ── */
[data-testid="stTabs"] [role="tab"] {
    font-family: var(--font-mono) !important;
    color: var(--muted) !important;
    font-size: 0.78rem !important;
    border-bottom: 2px solid transparent !important;
}
[data-testid="stTabs"] [role="tab"][aria-selected="true"] {
    color: var(--amber) !important;
    border-bottom: 2px solid var(--amber) !important;
    background: transparent !important;
}
[data-testid="stTabs"] [role="tablist"] {
    border-bottom: 1px solid var(--border) !important;
    gap: 0.5rem !important;
}

/* ── Expander ── */
[data-testid="stExpander"] {
    background: var(--surface) !important;
    border: 1px solid var(--border) !important;
    border-radius: 4px !important;
}
[data-testid="stExpander"] summary {
    font-family: var(--font-mono) !important;
    color: var(--text) !important;
    font-size: 0.82rem !important;
}

/* ── Code blocks ── */
pre, code, [data-testid="stCode"] {
    background: #070a0e !important;
    border: 1px solid var(--border) !important;
    font-family: var(--font-mono) !important;
    font-size: 0.75rem !important;
    border-radius: 4px !important;
}

/* ── Custom components ── */
.pipeline-header {
    font-family: var(--font-ui);
    font-weight: 800;
    font-size: 1.6rem;
    color: var(--amber);
    letter-spacing: -0.02em;
    border-bottom: 1px solid var(--border);
    padding-bottom: 0.5rem;
    margin-bottom: 1rem;
}
.pipeline-header span {
    font-family: var(--font-ui) !important;
    color: var(--muted);
    font-size: 0.85rem;
    font-weight: 400;
    margin-left: 0.5rem;
    letter-spacing: 0.05em;
}

.stage-row {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    padding: 0.35rem 0.6rem;
    border-radius: 3px;
    margin-bottom: 2px;
    font-size: 0.78rem;
    transition: background 0.2s;
}
.stage-pending  { color: var(--muted); }
.stage-running  { color: var(--amber); background: rgba(245,166,35,0.05); }
.stage-complete { color: var(--green); }
.stage-gate     { color: var(--blue); }
.stage-waiting  { color: var(--blue); background: rgba(96,165,250,0.05); animation: pulse 1.5s ease-in-out infinite; }
.stage-error    { color: var(--red); }

@keyframes pulse {
    0%, 100% { opacity: 1; }
    50%       { opacity: 0.55; }
}

.event-log {
    background: #070a0e;
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0.75rem;
    height: 280px;
    overflow-y: auto;
    font-size: 0.72rem;
    font-family: var(--font-mono);
    line-height: 1.7;
}
.ev-node     { color: var(--green); }
.ev-hitl     { color: var(--blue); }
.ev-complete { color: var(--amber); font-weight: 600; }
.ev-error    { color: var(--red); }
.ev-ping     { color: var(--muted); }
.ev-ts       { color: var(--muted); margin-right: 0.4rem; }

.hitl-panel {
    border: 1px solid var(--blue);
    border-radius: 6px;
    padding: 1.25rem;
    background: rgba(96,165,250,0.04);
    margin: 1rem 0;
}
.hitl-title {
    font-family: var(--font-ui) !important;
    font-weight: 700;
    color: var(--blue) !important;
    font-size: 1rem;
    margin-bottom: 0.75rem;
    letter-spacing: 0.05em;
    text-transform: uppercase;
}

.metric-chip {
    display: inline-block;
    padding: 0.2rem 0.6rem;
    border-radius: 3px;
    font-size: 0.72rem;
    font-family: var(--font-mono);
    margin-right: 0.4rem;
}
.chip-green  { background: rgba(74,222,128,0.12); color: var(--green); border: 1px solid rgba(74,222,128,0.25); }
.chip-amber  { background: rgba(245,166,35,0.12);  color: var(--amber); border: 1px solid rgba(245,166,35,0.25); }
.chip-red    { background: rgba(248,113,113,0.12); color: var(--red);   border: 1px solid rgba(248,113,113,0.25); }
.chip-blue   { background: rgba(96,165,250,0.12);  color: var(--blue);  border: 1px solid rgba(96,165,250,0.25); }

.result-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 5px;
    padding: 1rem;
    margin-bottom: 0.75rem;
}
.result-card-title {
    font-family: var(--font-ui) !important;
    font-weight: 700;
    font-size: 0.85rem;
    color: var(--amber) !important;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    margin-bottom: 0.5rem;
}

.status-badge {
    display: inline-block;
    padding: 0.25rem 0.8rem;
    border-radius: 99px;
    font-size: 0.75rem;
    font-weight: 600;
    font-family: var(--font-ui);
    letter-spacing: 0.06em;
    text-transform: uppercase;
}
.badge-running  { background: rgba(245,166,35,0.15);  color: var(--amber); border: 1px solid var(--amber-dim); }
.badge-paused   { background: rgba(96,165,250,0.15);  color: var(--blue);  border: 1px solid rgba(96,165,250,0.4); }
.badge-complete { background: rgba(74,222,128,0.15);  color: var(--green); border: 1px solid rgba(74,222,128,0.4); }
.badge-error    { background: rgba(248,113,113,0.15); color: var(--red);   border: 1px solid rgba(248,113,113,0.4); }
.badge-idle     { background: rgba(86,103,121,0.2);   color: var(--muted); border: 1px solid var(--border); }

.separator { border: none; border-top: 1px solid var(--border); margin: 1rem 0; }

.finding-row {
    display: flex;
    gap: 0.5rem;
    align-items: flex-start;
    padding: 0.45rem 0;
    border-bottom: 1px solid var(--border);
    font-size: 0.76rem;
}
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# Session state initialisation
# ─────────────────────────────────────────────────────────────────────────────

def init_state():
    defaults = {
        "thread_id":       None,
        "status":          "idle",       # idle | running | paused | complete | error
        "paused_at":       None,
        "event_log":       [],
        "stage_status":    {s[0]: "pending" for s in PIPELINE_STAGES},
        "current_node":    None,
        "gate_context":    {},
        "final_state":     None,
        "ev_queue":        queue.Queue(),
        "ws_thread":       None,
        "ws_running":      False,
        "audit_log":       [],
        "auto_scroll":     True,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

init_state()


# ─────────────────────────────────────────────────────────────────────────────
# WebSocket background listener
# ─────────────────────────────────────────────────────────────────────────────

def ws_listener(thread_id: str, ev_queue: queue.Queue):
    """Runs in a daemon thread. Pushes parsed events onto ev_queue."""
    url = f"{WS_BASE}/ws/pipeline/{thread_id}"

    def on_message(ws, raw):
        try:
            ev_queue.put(json.loads(raw))
        except Exception as e:
            ev_queue.put({"type": "error", "message": str(e)})

    def on_error(ws, err):
        ev_queue.put({"type": "error", "message": str(err)})

    def on_close(ws, *_):
        ev_queue.put({"type": "_closed"})

    ws_app = websocket.WebSocketApp(
        url,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close,
    )
    ws_app.run_forever(ping_interval=25, ping_timeout=10)


# ─────────────────────────────────────────────────────────────────────────────
# Event processor — drains the queue and updates session_state
# ─────────────────────────────────────────────────────────────────────────────

def process_events():
    """Drain the event queue and mutate session_state. Returns True if rerun needed."""
    changed = False
    ss = st.session_state

    while not ss.ev_queue.empty():
        try:
            event = ss.ev_queue.get_nowait()
        except queue.Empty:
            break

        etype = event.get("type", "")
        ts    = datetime.now().strftime("%H:%M:%S")
        changed = True

        if etype == "node_completed":
            node    = event.get("node", "")
            summary = event.get("summary", {})
            ss.stage_status[node] = "complete"
            ss.current_node       = node
            ss.event_log.append({
                "ts": ts, "type": "node",
                "text": f"✅ {node}  {_fmt_summary(summary)}",
            })

        elif etype == "hitl_pause":
            gate = event.get("paused_at", "")
            ss.stage_status[gate] = "waiting"
            ss.status             = "paused"
            ss.paused_at          = gate
            ss.gate_context       = event.get("gate_context", {})
            ss.audit_log          = event.get("audit_log", ss.audit_log)
            ss.event_log.append({
                "ts": ts, "type": "hitl",
                "text": f"⏸  PAUSED at {gate} — awaiting human decision",
            })

        elif etype == "pipeline_complete":
            ss.status      = "complete"
            ss.paused_at   = None
            ss.audit_log   = event.get("audit_log", ss.audit_log)
            ss.final_state = event
            ss.event_log.append({
                "ts": ts, "type": "complete",
                "text": f"🏁 COMPLETE — {event.get('final_status', '?')}",
            })
            # Fetch full result
            try:
                resp = requests.get(
                    f"{API_BASE}/pipeline/{ss.thread_id}/result", timeout=15
                )
                if resp.status_code == 200:
                    ss.final_state = resp.json()
            except Exception:
                pass

        elif etype == "error":
            ss.status = "error"
            ss.event_log.append({
                "ts": ts, "type": "error",
                "text": f"❌ ERROR — {event.get('message', '?')}",
            })

        elif etype == "ping":
            ss.event_log.append({"ts": ts, "type": "ping", "text": "· keepalive"})

        elif etype == "_closed":
            ss.ws_running = False

    return changed


def _fmt_summary(s: dict) -> str:
    if not s:
        return ""
    parts = []
    for k, v in s.items():
        if isinstance(v, list):
            parts.append(f"{k}={len(v)}")
        elif v is not None:
            parts.append(f"{k}={v}")
    return "  |  ".join(parts[:4])


# ─────────────────────────────────────────────────────────────────────────────
# API helpers
# ─────────────────────────────────────────────────────────────────────────────

def start_pipeline(raw_input: str) -> tuple[bool, str]:
    try:
        resp = requests.post(
            f"{API_BASE}/pipeline/start",
            json={"raw_input": raw_input},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        return True, data["thread_id"]
    except Exception as e:
        return False, str(e)


def submit_decision(thread_id: str, payload: dict) -> tuple[bool, str]:
    try:
        resp = requests.post(
            f"{API_BASE}/pipeline/{thread_id}/decide",
            json=payload,
            timeout=10,
        )
        resp.raise_for_status()
        return True, resp.json().get("message", "OK")
    except Exception as e:
        return False, str(e)


# ─────────────────────────────────────────────────────────────────────────────
# UI helpers
# ─────────────────────────────────────────────────────────────────────────────

def badge(status: str) -> str:
    MAP = {
        "running":  ("badge-running",  "● RUNNING"),
        "paused":   ("badge-paused",   "⏸ PAUSED"),
        "complete": ("badge-complete", "✓ COMPLETE"),
        "error":    ("badge-error",    "✗ ERROR"),
        "idle":     ("badge-idle",     "○ IDLE"),
    }
    cls, label = MAP.get(status, ("badge-idle", status.upper()))
    return f'<span class="status-badge {cls}">{label}</span>'


def severity_chip(sev: str) -> str:
    cls = {"critical": "chip-red", "high": "chip-red", "medium": "chip-amber", "low": "chip-green"}.get(sev, "chip-blue")
    return f'<span class="metric-chip {cls}">{sev.upper()}</span>'


def render_stage_list():
    ss = st.session_state
    lines = []
    for node, label, kind in PIPELINE_STAGES:
        status = ss.stage_status.get(node, "pending")
        icon   = {"pending": "○", "running": "◉", "complete": "✓",
                  "waiting": "◈", "gate": "◈", "error": "✗"}.get(status, "○")
        css    = {"pending": "stage-pending", "running": "stage-running",
                  "complete": "stage-complete", "waiting": "stage-waiting",
                  "error": "stage-error"}.get(status, "stage-pending")
        if kind == "gate" and status == "pending":
            css = "stage-gate"
        lines.append(
            f'<div class="stage-row {css}">'
            f'  <span>{icon}</span>'
            f'  <span style="flex:1">{label}</span>'
            f'</div>'
        )
    st.markdown("".join(lines), unsafe_allow_html=True)


def render_event_log():
    ss = st.session_state
    entries = ss.event_log[-60:]  # keep last 60
    rows = []
    for e in reversed(entries):  # newest first
        cls  = {"node": "ev-node", "hitl": "ev-hitl", "complete": "ev-complete",
                "error": "ev-error", "ping": "ev-ping"}.get(e["type"], "ev-node")
        rows.append(
            f'<span class="ev-ts">{e["ts"]}</span>'
            f'<span class="{cls}">{e["text"]}</span><br>'
        )
    st.markdown(
        f'<div class="event-log">{"".join(rows) if rows else "<span style=\'color:var(--muted)\'>Waiting for events…</span>"}</div>',
        unsafe_allow_html=True,
    )


def render_hitl_panel():
    ss = st.session_state
    if ss.status != "paused":
        return

    gate = ss.paused_at or "?"
    gate_labels = {
        "hitl_gate_1": "Gate I — Intent & IP Review",
        "hitl_gate_2": "Gate II — Architecture & Compliance Review",
        "hitl_gate_3": "Gate III — Security & Quality Sign-off",
    }

    st.markdown(f"""
    <div class="hitl-panel">
        <div class="hitl-title">⏸ {gate_labels.get(gate, gate)}</div>
    </div>
    """, unsafe_allow_html=True)

    # Show gate context as expandable JSON
    ctx = ss.gate_context
    if ctx:
        with st.expander("📄 Review Context", expanded=True):
            for key, val in ctx.items():
                if val is not None:
                    st.markdown(f"**`{key}`**")
                    st.json(val)

    st.markdown("**Submit Decision**")
    col1, col2 = st.columns([1, 2])
    with col1:
        choice = st.selectbox(
            "Choice",
            options=["A — Approve", "M — Modify (approve with notes)", "R — Reject", "H — Hold"],
            key=f"choice_{gate}",
        )
    with col2:
        approver = st.text_input("Your name / ID", value="reviewer", key=f"approver_{gate}")

    feedback = st.text_area("Feedback / notes (optional)", height=70, key=f"feedback_{gate}")
    risk_ack = st.checkbox("I acknowledge any flagged risks", key=f"risk_{gate}")

    if st.button("⚡ Submit Decision", type="primary", key=f"submit_{gate}"):
        choice_code = choice.split(" — ")[0]
        ok, msg = submit_decision(ss.thread_id, {
            "choice":            choice_code,
            "approver":          approver or "anonymous",
            "feedback":          feedback or None,
            "risk_acknowledged": risk_ack,
        })
        if ok:
            # Reset gate status so it no longer shows as waiting
            ss.stage_status[gate] = "complete"
            ss.status             = "running"
            ss.paused_at          = None
            ss.event_log.append({
                "ts":   datetime.now().strftime("%H:%M:%S"),
                "type": "node",
                "text": f"✅ {gate} — decision submitted: {choice_code} by {approver}",
            })
            st.rerun()
        else:
            st.error(f"Decision failed: {msg}")


# ─────────────────────────────────────────────────────────────────────────────
# Result panels
# ─────────────────────────────────────────────────────────────────────────────

def render_results():
    ss = st.session_state
    fs = ss.final_state
    if not fs:
        return

    tabs = st.tabs(["📦 Code", "🛡️ Security", "🔬 Quality", "📋 Compliance", "📖 Explainability", "📝 Audit"])

    # ── Code tab ─────────────────────────────────────────────────────────────
    with tabs[0]:
        gc = fs.get("generated_code") or {}
        modules = gc.get("modules", [])
        if not modules:
            st.info("No code generated yet.")
        else:
            deps = gc.get("dependencies", [])
            if deps:
                st.markdown(f'<div class="result-card"><div class="result-card-title">Dependencies</div>'
                            f'{"  ".join(f"<span class=\'metric-chip chip-blue\'>{d}</span>" for d in deps)}'
                            f'</div>', unsafe_allow_html=True)

            for m in modules:
                with st.expander(f"📄 {m['filename']}  ·  {m.get('layer','?')} layer", expanded=False):
                    cols = st.columns([3, 1])
                    with cols[0]:
                        st.markdown(f"*{m.get('description', '')}*")
                    with cols[1]:
                        st.markdown(
                            "  ".join(f'<span class="metric-chip chip-green">{c}</span>'
                                      for c in m.get("compliance_controls", [])[:3]),
                            unsafe_allow_html=True,
                        )
                    st.code(m.get("code", ""), language="python")

    # ── Security tab ─────────────────────────────────────────────────────────
    with tabs[1]:
        sr = fs.get("security_report") or {}
        findings = sr.get("findings", [])
        risk     = sr.get("overall_security_risk", "?")
        passed   = sr.get("passed", False)

        risk_chip = severity_chip(risk) if risk != "?" else ""
        pass_chip = '<span class="metric-chip chip-green">PASSED</span>' if passed else '<span class="metric-chip chip-red">FAILED</span>'
        st.markdown(
            f'<div class="result-card">'
            f'<div class="result-card-title">Security Summary</div>'
            f'{risk_chip} {pass_chip}'
            f'  <span class="metric-chip chip-blue">{len(findings)} findings</span>'
            f'</div>',
            unsafe_allow_html=True,
        )

        if findings:
            st.markdown("**Findings**")
            for f in findings:
                sev = f.get("severity", "?")
                chip = severity_chip(sev)
                st.markdown(
                    f'<div class="finding-row">'
                    f'  {chip}'
                    f'  <div style="flex:1">'
                    f'    <b style="color:#c8d6e5">{f.get("filename")}</b> · '
                    f'    <span style="color:var(--muted)">{f.get("rule")}</span><br>'
                    f'    <span style="font-size:0.7rem;color:var(--muted)">{f.get("owasp_ref")}  →  {f.get("fix")}</span>'
                    f'  </div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
        else:
            st.success("No findings!")

        cov = sr.get("compliance_tag_coverage", {})
        if cov:
            st.markdown(f"**Compliance tag coverage:** `{cov.get('coverage_percent', 0)}%`")
            missing = cov.get("files_without_tags", [])
            if missing:
                st.warning(f"Missing compliance tags in: {', '.join(missing)}")

    # ── Quality tab ──────────────────────────────────────────────────────────
    with tabs[2]:
        qr    = fs.get("quality_report") or {}
        score = qr.get("overall_quality_score", 0)
        qpass = qr.get("passed", False)

        score_color = "var(--green)" if score >= 70 else "var(--amber)" if score >= 50 else "var(--red)"
        st.markdown(
            f'<div class="result-card" style="text-align:center">'
            f'  <div style="font-size:3rem;font-weight:800;color:{score_color};font-family:var(--font-ui)">{score}</div>'
            f'  <div style="color:var(--muted);font-size:0.75rem">QUALITY SCORE / 100</div>'
            f'  <div style="margin-top:0.5rem">{"<span class=\'metric-chip chip-green\'>PASSED</span>" if qpass else "<span class=\'metric-chip chip-red\'>FAILED</span>"}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

        cq = qr.get("code_quality", {})
        if cq:
            flags = []
            flags.append(("Docstrings",     cq.get("has_docstrings", False)))
            flags.append(("Type hints",     cq.get("has_type_hints", False)))
            flags.append(("Error handling", cq.get("has_error_handling", False)))
            flags.append(("Async support",  cq.get("has_async_support", False)))
            chips = ""
            for label, ok in flags:
                chips += f'<span class="metric-chip {"chip-green" if ok else "chip-red"}">{label}</span>'
            st.markdown(f'<div class="result-card"><div class="result-card-title">Code Quality</div>{chips}</div>', unsafe_allow_html=True)

        recs = qr.get("recommendations", [])
        if recs:
            with st.expander("💡 Recommendations"):
                for r in recs:
                    st.markdown(f"- {r}")

        crit = qr.get("acceptance_criteria_check", [])
        if crit:
            with st.expander("✅ Acceptance Criteria"):
                for c in crit:
                    icon = "✅" if c["status"] == "met" else ("⚠️" if c["status"] == "partial" else "❌")
                    st.markdown(f"{icon} **{c['criterion']}** — *{c['evidence']}*")

    # ── Compliance tab ────────────────────────────────────────────────────────
    with tabs[3]:
        cr = fs.get("compliance_rules") or {}
        frameworks = cr.get("applicable_frameworks", [])
        for fw in frameworks:
            priority_chip = '<span class="metric-chip chip-red">MANDATORY</span>' if fw.get("priority") == "mandatory" else '<span class="metric-chip chip-amber">RECOMMENDED</span>'
            with st.expander(f"**{fw['name']}**  {fw.get('reason', '')}"):
                st.markdown(priority_chip, unsafe_allow_html=True)
                for rule in fw.get("rules", []):
                    st.markdown(f"- {rule}")

        gaps = cr.get("gaps", [])
        if gaps:
            st.markdown("**⚠️ Compliance Gaps**")
            for g in gaps:
                st.warning(g)

    # ── Explainability tab ────────────────────────────────────────────────────
    with tabs[4]:
        ex = fs.get("explainability_docs") or {}

        narrative = ex.get("audit_narrative", "")
        if narrative:
            st.markdown(
                f'<div class="result-card"><div class="result-card-title">Audit Narrative</div>'
                f'<p style="line-height:1.7;font-size:0.82rem">{narrative}</p></div>',
                unsafe_allow_html=True,
            )

        decisions = ex.get("decision_log", [])
        if decisions:
            with st.expander(f"🗂 Decision Log ({len(decisions)} decisions)"):
                for d in decisions:
                    st.markdown(f"**{d.get('decision_point', '?')}**")
                    st.markdown(f"- *What:* {d.get('what_was_decided', '')}")
                    st.markdown(f"- *Why:* {d.get('why', '')}")
                    alts = d.get("alternatives_considered", [])
                    if alts:
                        st.markdown(f"- *Alternatives:* {', '.join(alts)}")
                    st.markdown("---")

        glossary = ex.get("glossary", [])
        if glossary:
            with st.expander(f"📚 Glossary ({len(glossary)} terms)"):
                for g in glossary:
                    st.markdown(f"**{g.get('term')}** — {g.get('plain_english')}")

    # ── Audit tab ─────────────────────────────────────────────────────────────
    with tabs[5]:
        final_audit = (fs.get("quality_report") or {}).get("final_audit", {})
        if final_audit:
            fs_status = final_audit.get("final_status", "?")
            color_map = {
                "approved_for_deploy":  "var(--green)",
                "requires_remediation": "var(--amber)",
                "blocked":              "var(--red)",
            }
            color = color_map.get(fs_status, "var(--muted)")
            st.markdown(
                f'<div class="result-card" style="border-color:{color}">'
                f'  <div class="result-card-title" style="color:{color}">Final Status</div>'
                f'  <div style="font-size:1.1rem;font-weight:700;color:{color}">{fs_status.replace("_", " ").upper()}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )

            sign_off = final_audit.get("sign_off_note", "")
            if sign_off:
                st.markdown(
                    f'<div class="result-card"><div class="result-card-title">Auditor Sign-off</div>'
                    f'<p style="line-height:1.8;font-size:0.8rem;font-style:italic">{sign_off}</p></div>',
                    unsafe_allow_html=True,
                )

            digest = final_audit.get("immutable_digest", {})
            if digest:
                with st.expander("🔐 Immutable Digest"):
                    for k, v in digest.items():
                        st.markdown(f"`{k}` : `{v}`")

            hitl_trail = final_audit.get("human_accountability", [])
            if hitl_trail:
                with st.expander(f"👤 HITL Trail ({len(hitl_trail)} decisions)"):
                    for d in hitl_trail:
                        st.markdown(
                            f"- **{d.get('gate')}**  |  {d.get('decision')} by *{d.get('approver')}*"
                            f"  |  `{d.get('timestamp', '')[:19]}`"
                        )

        audit_log = ss.audit_log or (fs.get("audit_log") or [])
        if audit_log:
            with st.expander(f"📋 Full Audit Log ({len(audit_log)} entries)", expanded=False):
                for entry in audit_log:
                    ts = entry.get("timestamp", "")[:19]
                    st.markdown(
                        f'<div style="padding:0.3rem 0;border-bottom:1px solid var(--border);font-size:0.73rem">'
                        f'  <span style="color:var(--muted)">{ts}</span>  '
                        f'  <span style="color:var(--amber)">[{entry.get("agent")}]</span>  '
                        f'  {entry.get("summary")}'
                        f'</div>',
                        unsafe_allow_html=True,
                    )


# ─────────────────────────────────────────────────────────────────────────────
# Sidebar
# ─────────────────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown('<div class="pipeline-header">⚡ AI Dev Pipeline<span>v2.0</span></div>', unsafe_allow_html=True)

    ss = st.session_state
    st.markdown(
        f'**Status** &nbsp; {badge(ss.status)}',
        unsafe_allow_html=True,
    )
    if ss.thread_id:
        st.markdown(f'<span style="font-size:0.7rem;color:var(--muted)">thread: {ss.thread_id[:20]}…</span>', unsafe_allow_html=True)

    st.markdown('<hr class="separator">', unsafe_allow_html=True)

    # ── Input form ────────────────────────────────────────────────────────────
    st.markdown("**What do you want to build?**")
    raw_input = st.text_area(
        label="",
        placeholder="e.g. Build a FastAPI app with JWT auth, user registration, and PostgreSQL persistence.",
        height=120,
        disabled=(ss.status in ("running", "paused")),
        label_visibility="collapsed",
    )

    server_url = st.text_input("API server", value=API_BASE, label_visibility="visible")

    can_start = ss.status not in ("running", "paused") and raw_input.strip()

    if st.button("⚡ Run Pipeline", type="primary", disabled=not can_start, use_container_width=True):
        # Reset state
        for k in ["thread_id", "paused_at", "gate_context", "final_state", "paused_at"]:
            ss[k] = None
        ss.status       = "running"
        ss.event_log    = []
        ss.audit_log    = []
        ss.stage_status = {s[0]: "pending" for s in PIPELINE_STAGES}
        ss.ev_queue     = queue.Queue()
        ss.ws_running   = True

        ok, result = start_pipeline(raw_input.strip())
        if ok:
            ss.thread_id = result
            t = threading.Thread(
                target=ws_listener,
                args=(result, ss.ev_queue),
                daemon=True,
            )
            t.start()
            ss.ws_thread = t
        else:
            ss.status = "error"
            ss.event_log.append({
                "ts": datetime.now().strftime("%H:%M:%S"),
                "type": "error",
                "text": f"❌ Could not start pipeline: {result}",
            })
        st.rerun()

    if ss.status in ("complete", "error"):
        if st.button("↺ Reset", use_container_width=True):
            for k in list(ss.keys()):
                del ss[k]
            st.rerun()

    st.markdown('<hr class="separator">', unsafe_allow_html=True)

    # ── Pipeline stage list ───────────────────────────────────────────────────
    st.markdown("**Pipeline stages**")
    render_stage_list()


# ─────────────────────────────────────────────────────────────────────────────
# Main content
# ─────────────────────────────────────────────────────────────────────────────

ss = st.session_state

# Process any queued events
if ss.status in ("running", "paused") and not ss.ev_queue.empty():
    process_events()

col_main, col_log = st.columns([3, 2])

with col_main:
    if ss.status == "idle":
        st.markdown("""
        <div style="padding:3rem 1rem;text-align:center;color:var(--muted)">
            <div style="font-size:2.5rem;margin-bottom:0.75rem">⚡</div>
            <div style="font-family:var(--font-ui);font-size:1.1rem;color:#4a5a6a">
                Enter a description in the sidebar<br>and hit <b style="color:var(--amber)">Run Pipeline</b> to begin.
            </div>
        </div>
        """, unsafe_allow_html=True)

    elif ss.status in ("running", "paused"):
        render_hitl_panel()
        if ss.status == "paused":
            st.markdown("")
        elif ss.current_node:
            node_label = next((s[1] for s in PIPELINE_STAGES if s[0] == ss.current_node), ss.current_node)
            st.markdown(
                f'<div style="padding:0.5rem 0.75rem;background:rgba(245,166,35,0.06);border-left:2px solid var(--amber);'
                f'font-size:0.8rem;color:var(--amber);margin-bottom:1rem">'
                f'  ◉ Running → {node_label}'
                f'</div>',
                unsafe_allow_html=True,
            )

    elif ss.status in ("complete", "error"):
        render_results()

with col_log:
    st.markdown("**Live event stream**")
    render_event_log()

    if ss.thread_id:
        st.markdown(
            f'<div style="font-size:0.7rem;color:var(--muted);margin-top:0.4rem">'
            f'WS → {WS_BASE}/ws/pipeline/{ss.thread_id[:20]}…'
            f'</div>',
            unsafe_allow_html=True,
        )

# ─────────────────────────────────────────────────────────────────────────────
# Auto-refresh while pipeline is running
# ─────────────────────────────────────────────────────────────────────────────

if ss.status in ("running", "paused"):
    time.sleep(0.8)
    process_events()
    st.rerun()