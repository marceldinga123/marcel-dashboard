# app.py — Generative AI–Powered IDS Dashboard (single file)
# Requirements: streamlit, pandas, altair  (add "altair>=5.0.0" to requirements.txt)

import pandas as pd
import streamlit as st
import altair as alt
from typing import Dict, Tuple

st.set_page_config(page_title="Generative AI–Powered IDS", layout="wide")

# ================================
# ---- Animated sticky header ----
# ================================
st.markdown("""
<style>
/* Animated gradient header (3 colors) */
.animated-header {
  position: sticky;
  top: 0;
  z-index: 999;
  padding: 20px 16px;
  text-align: center;
  color: white;
  font-size: 28px;
  font-weight: 800;
  letter-spacing: .2px;
  border-radius: 0 0 12px 12px;
  background: linear-gradient(270deg, #2563eb, #8b5cf6, #0ea5e9);
  background-size: 600% 600%;
  animation: gradientMove 10s ease infinite;
  box-shadow: 0 2px 8px rgba(15, 23, 42, 0.10);
}
.animated-sub {
  color: #e6f1ff;
  font-size: 15px;
  margin-top: 6px;
  font-weight: 500;
  opacity: .95;
}
@keyframes gradientMove {
  0%   { background-position: 0% 50%; }
  50%  { background-position: 100% 50%; }
  100% { background-position: 0% 50%; }
}

/* page width + fonts */
.main .block-container { padding-top: 1.0rem; padding-bottom: 2rem; max-width: 1200px; }
h1, h2, h3 { letter-spacing: 0.2px; }

/* metric cards */
div[data-testid="stMetric"] {
  background: #ffffff;
  border: 1px solid #eef0f3;
  box-shadow: 0 1px 4px rgba(16,24,40,0.06);
  border-radius: 14px;
  padding: 14px 16px;
}

/* dataframe polish */
.stDataFrame, .stTable { border-radius: 12px; overflow: hidden; }

/* radio row weight */
[data-testid="stHorizontalBlock"] label { font-weight: 600; }
</style>

<div class="animated-header">
  🔐 Generative AI–Powered Intrusion Detection System (IDS)
  <div class="animated-sub">
    DATA 675 – Generative AI • Marcel Dinga • University of Maryland Global Campus
  </div>
</div>
""", unsafe_allow_html=True)

# ================================
# ---- Color palette ----
# ================================
PALETTE = {
    "primary": "#2563eb",   # blue-600
    "secondary": "#0ea5e9", # sky-500
    "accent": "#8b5cf6",    # violet-500
    "neutral": "#64748b",   # slate-500
    "danger": "#ef4444",    # red-500
    "success": "#10b981",   # emerald-500
    "warning": "#f59e0b",   # amber-500
}
ATTACK_COLORS = {
    "BENIGN": "#2563eb",
    "DoS": "#ef4444",
    "DDoS": "#b91c1c",
    "PortScan": "#8b5cf6",
    "Bot": "#0ea5e9",
    "WebAttack": "#f59e0b",
    "FTP-Patator": "#10b981",
    "SSH-Patator": "#14b8a6",
}
SEVERITY_COLORS = {"High": "#ef4444", "Medium": "#f59e0b", "Informational": "#2563eb"}

# Expected columns (we’ll create empty ones if missing)
EXPECTED_COLS = [
    "timestamp", "attack_type", "severity", "confidence",
    "src_ip", "dst_ip", "summary", "model", "readability_flesch"
]

# ================================
# ---- AI helpers (rules-based) ----
# ================================
PLAYBOOK: Dict[str, str] = {
    "BENIGN": "No action required. Continue routine monitoring.",
    "DoS": "Block offending IP(s), enable rate limiting on affected ports, and review logs.",
    "DDoS": "Engage ISP/DDoS protection, activate filtering, and isolate impacted servers if needed.",
    "PortScan": "Monitor for repeated scans, raise IDS sensitivity, and block source if persistent.",
    "Bot": "Quarantine the host, run malware scans, and investigate command-and-control (C2) indicators.",
    "WebAttack": "Review WAF/web server logs, patch endpoints, and block malicious IP addresses.",
    "FTP-Patator": "Block source IP, enforce strong FTP authentication/rate limiting, and review brute-force attempts.",
    "SSH-Patator": "Block source IP, enforce SSH key authentication/fail2ban, and review authentication logs.",
}

def _rules_summary(attack_type: str, severity: str, confidence: float,
                   src_ip: str = None, dst_ip: str = None) -> str:
    conf_txt = f"{float(confidence):.2f}" if confidence is not None and confidence != "" else "N/A"
    src_txt = f" from {src_ip}" if src_ip and str(src_ip).lower() != "nan" else ""
    dst_txt = f" targeting {dst_ip}" if dst_ip and str(dst_ip).lower() != "nan" else ""
    if attack_type == "BENIGN":
        return f"Traffic classified as BENIGN with confidence {conf_txt}. No malicious activity detected."
    elif attack_type == "DoS":
        return f"Denial of Service (DoS) detected with confidence {conf_txt}{src_txt}{dst_txt}."
    elif attack_type == "DDoS":
        return f"Distributed Denial of Service (DDoS) detected with confidence {conf_txt}{src_txt}{dst_txt}."
    elif attack_type == "PortScan":
        return f"Port scanning detected with confidence {conf_txt}{src_txt}{dst_txt}."
    elif attack_type == "Bot":
        return f"Bot-like behavior detected with confidence {conf_txt}{src_txt}{dst_txt}."
    elif attack_type == "WebAttack":
        return f"Web application attack detected with confidence {conf_txt}{src_txt}{dst_txt}."
    elif attack_type in ("FTP-Patator", "SSH-Patator"):
        proto = "FTP" if "FTP" in attack_type else "SSH"
        return f"{proto} brute-force indicators detected with confidence {conf_txt}{src_txt}{dst_txt}."
    else:
        return f"{attack_type} detected with confidence {conf_txt}{src_txt}{dst_txt}."

def _rules_solution(attack_type: str) -> str:
    return PLAYBOOK.get(
        attack_type,
        "Investigate in SIEM, review IDS/firewall logs, and escalate per incident response playbook."
    )

def generate_summary_and_solution(
    attack_type: str,
    severity: str,
    confidence: float,
    src_ip: str = None,
    dst_ip: str = None,
) -> Tuple[str, str]:
    return (
        _rules_summary(attack_type, severity, confidence, src_ip, dst_ip),
        _rules_solution(attack_type),
    )

def enrich_df_with_ai(df: pd.DataFrame) -> pd.DataFrame:
    if df is None or df.empty:
        return df
    summaries, actions = [], []
    for _, r in df.iterrows():
        s, a = generate_summary_and_solution(
            str(r.get("attack_type", "")),
            str(r.get("severity", "")),
            float(r.get("confidence", 0) or 0),
            r.get("src_ip"),
            r.get("dst_ip"),
        )
        summaries.append(s)
        actions.append(a)
    out = df.copy()
    out["summary"] = summaries
    out["proposed_action"] = actions
    return out

# ================================
# ---- Charts (Altair) ----
# ================================
def _cat_color_scale(mapping: dict):
    return alt.Scale(domain=list(mapping.keys()), range=list(mapping.values()))

def chart_counts_by_attack(df):
    data = (df.groupby("attack_type", dropna=False)
              .size().reset_index(name="count").sort_values("count", ascending=False))
    return (
        alt.Chart(data)
        .mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4)
        .encode(
            x=alt.X("attack_type:N", title="Attack type", sort="-y"),
            y=alt.Y("count:Q", title="Count"),
            color=alt.Color("attack_type:N", scale=_cat_color_scale(ATTACK_COLORS), legend=None),
            tooltip=["attack_type:N","count:Q"]
        )
        .properties(height=320)
    )

def chart_severity_share(df):
    data = (df.groupby("severity", dropna=False)
              .size().reset_index(name="count").sort_values("count", ascending=False))
    total = max(int(data["count"].sum()), 1)
    data["share"] = data["count"] / total
    return (
        alt.Chart(data)
        .mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4)
        .encode(
            x=alt.X("severity:N", title="Severity", sort=["High","Medium","Informational"]),
            y=alt.Y("count:Q", title="Count"),
            color=alt.Color("severity:N", scale=_cat_color_scale(SEVERITY_COLORS), legend=None),
            tooltip=["severity:N","count:Q", alt.Tooltip("share:Q", title="Share", format=".1%")]
        )
        .properties(height=320)
    )

def chart_confidence(df):
    s = pd.to_numeric(df["confidence"], errors="coerce").dropna()
    data = pd.DataFrame({"confidence": s})
    return (
        alt.Chart(data)
        .transform_bin("bin_conf", field="confidence", bin=alt.Bin(maxbins=30))
        .mark_bar(color=PALETTE["primary"], cornerRadiusTopLeft=3, cornerRadiusTopRight=3)
        .encode(
            x=alt.X("bin_conf:Q", title="Confidence", scale=alt.Scale(domain=[0,1])),
            y=alt.Y("count():Q", title="Frequency"),
            tooltip=[alt.Tooltip("count():Q", title="Count")]
        )
        .properties(height=260)
    )

def chart_flesch(df):
    if "readability_flesch" not in df.columns:
        return None
    s = pd.to_numeric(df["readability_flesch"], errors="coerce").dropna()
    if s.empty:
        return None
    data = pd.DataFrame({"flesch": s})
    return (
        alt.Chart(data)
        .transform_bin("bin_f", field="flesch", bin=alt.Bin(maxbins=30))
        .mark_bar(color=PALETTE["accent"], cornerRadiusTopLeft=3, cornerRadiusTopRight=3)
        .encode(
            x=alt.X("bin_f:Q", title="Readability (Flesch — higher is easier)"),
            y=alt.Y("count():Q", title="Frequency"),
            tooltip=[alt.Tooltip("count():Q", title="Count")]
        )
        .properties(height=260)
    )

# ================================
# ---- UI ----
# ================================
mode = st.radio("Summary mode", ["Executive (concise)", "SOC (detailed)"], horizontal=True)
st.markdown("---")

# File upload + info
left, right = st.columns([1, 3], vertical_alignment="top")
with left:
    uploaded = st.file_uploader("Upload alerts CSV", type=["csv"], help="Limit 200MB per file • CSV")
with right:
    if uploaded is None:
        st.info("No CSV found. Please upload one using the sidebar.")
    else:
        # Load
        df = pd.read_csv(uploaded)

        # Ensure expected columns exist
        for c in EXPECTED_COLS:
            if c not in df.columns:
                if c == "summary":
                    df[c] = ""
                else:
                    df[c] = pd.NA

        # Sidebar filters
        st.sidebar.header("Filters")
        atk_all = sorted([x for x in df["attack_type"].dropna().unique().tolist()])
        sev_all = sorted([x for x in df["severity"].dropna().unique().tolist()])
        mdl_all = sorted([x for x in df["model"].dropna().unique().tolist()]) if "model" in df.columns else []

        atk_sel = st.sidebar.multiselect("Attack type", atk_all, default=atk_all[:min(6, len(atk_all))])
        sev_sel = st.sidebar.multiselect("Severity", sev_all, default=sev_all)
        mdl_sel = st.sidebar.multiselect("Model", mdl_all, default=mdl_all) if mdl_all else mdl_all
        conf_min, conf_max = st.sidebar.slider("Confidence range", 0.0, 1.0, (0.0, 1.0), step=0.01)

        # Apply filters
        dff = df.copy()
        if atk_sel:
            dff = dff[dff["attack_type"].isin(atk_sel)]
        if sev_sel:
            dff = dff[dff["severity"].isin(sev_sel)]
        if mdl_sel:
            dff = dff[dff["model"].isin(mdl_sel)]
        dff["confidence"] = pd.to_numeric(dff["confidence"], errors="coerce").fillna(0.0)
        dff = dff[(dff["confidence"] >= conf_min) & (dff["confidence"] <= conf_max)]

        # Enrich with AI (summary + proposed_action)
        dff = enrich_df_with_ai(dff)

        # KPIs
        total_alerts = len(dff)
        pct_high = (dff["severity"].eq("High").mean() * 100) if total_alerts else 0
        avg_conf = dff["confidence"].mean() if total_alerts else 0
        avg_flesch = dff["readability_flesch"].astype(float).mean() if "readability_flesch" in dff.columns and total_alerts else 0

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total alerts", f"{total_alerts:,}")
        m2.metric("% High severity", f"{pct_high:.1f}%")
        m3.metric("Avg confidence", f"{avg_conf:.1%}" if avg_conf <= 1.0 else f"{avg_conf:.3f}")
        m4.metric("Avg Flesch score", f"{avg_flesch:.1f}")

        st.markdown("### Visual insights")
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**Counts by attack type**")
            st.altair_chart(chart_counts_by_attack(dff), use_container_width=True)
        with c2:
            st.markdown("**Severity share**")
            st.altair_chart(chart_severity_share(dff), use_container_width=True)

        c3, c4 = st.columns(2)
        with c3:
            st.markdown("**Confidence distribution**")
            st.altair_chart(chart_confidence(dff), use_container_width=True)
        with c4:
            ch = chart_flesch(dff)
            if ch is not None:
                st.markdown("**Readability (Flesch) distribution**")
                st.altair_chart(ch, use_container_width=True)

        st.markdown("---")
        st.subheader("Alerts")

        # Columns to display/export
        display_cols = [
            "timestamp", "attack_type", "severity", "confidence",
            "src_ip", "dst_ip", "summary", "model", "readability_flesch"
        ]
        if mode == "SOC (detailed)":
            insert_at = display_cols.index("model")
            display_cols.insert(insert_at, "proposed_action")

        # Only keep existing columns
        display_cols = [c for c in display_cols if c in dff.columns]

        # Table
        st.dataframe(dff[display_cols], use_container_width=True, height=520)

        # Export CSV (matches current view)
        csv_bytes = dff[display_cols].to_csv(index=False).encode("utf-8")
        st.download_button(
            "Download filtered CSV",
            data=csv_bytes,
            file_name="alerts_filtered.csv",
            mime="text/csv"
        )

        st.caption("Tip: Switch Executive/SOC mode to change table & export columns.")
