# app.py — IDS Dashboard with AI Model Selector (single file)
# Requirements: streamlit, pandas, altair>=5.0.0, openai>=1.30.0

import os
import json
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
    "primary": "#2563eb", "secondary": "#0ea5e9", "accent": "#8b5cf6",
    "neutral": "#64748b", "danger": "#ef4444", "success": "#10b981", "warning": "#f59e0b",
}
ATTACK_COLORS = {
    "BENIGN": "#2563eb", "DoS": "#ef4444", "DDoS": "#b91c1c", "PortScan": "#8b5cf6",
    "Bot": "#0ea5e9", "WebAttack": "#f59e0b", "FTP-Patator": "#10b981", "SSH-Patator": "#14b8a6",
}
SEVERITY_COLORS = {"High": "#ef4444", "Medium": "#f59e0b", "Informational": "#2563eb"}

EXPECTED_COLS = [
    "timestamp","attack_type","severity","confidence","src_ip","dst_ip","summary","model","readability_flesch"
]

# ================================
# ---- AI helpers (rules + GPT) ----
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

def _gpt_summary_solution(attack_type: str, severity: str, confidence: float,
                          src_ip: str, dst_ip: str, model_name: str, api_key: str) -> Tuple[str, str]:
    """
    Use OpenAI GPT to return (summary, proposed_action). Falls back to rules on error.
    """
    try:
        os.environ["OPENAI_API_KEY"] = api_key or os.getenv("OPENAI_API_KEY", "")
        if not os.getenv("OPENAI_API_KEY"):
            raise RuntimeError("Missing OpenAI API key.")

        # OpenAI v1 client (chat.completions)
        from openai import OpenAI
        client = OpenAI()

        prompt = f"""
You are a SOC analyst assistant.
Write a concise plain-language SUMMARY and a short PROPOSED ACTION for this IDS alert.
Fields: attack_type={attack_type}, severity={severity}, confidence={confidence}, src_ip={src_ip}, dst_ip={dst_ip}.
Return strict JSON: {{"summary": "...", "proposed_action": "..."}}.
If attack_type is BENIGN, proposed_action should be "No action required. Continue routine monitoring."
Keep each value to 1–2 sentences.
"""
        resp = client.chat.completions.create(
            model=model_name,
            temperature=0.2,
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
        )
        data = json.loads(resp.choices[0].message.content)
        summary = data.get("summary") or _rules_summary(attack_type, severity, confidence, src_ip, dst_ip)
        action  = data.get("proposed_action") or _rules_solution(attack_type)
        return summary, action
    except Exception:
        # graceful fallback
        return _rules_summary(attack_type, severity, confidence, src_ip, dst_ip), _rules_solution(attack_type)

def generate_summary_and_solution(
    attack_type: str,
    severity: str,
    confidence: float,
    src_ip: str = None,
    dst_ip: str = None,
    mode: str = "rules",
    model_name: str = "gpt-4o-mini",
    api_key: str = ""
) -> Tuple[str, str]:
    if mode == "gpt":
        return _gpt_summary_solution(attack_type, severity, confidence, src_ip, dst_ip, model_name, api_key)
    return _rules_summary(attack_type, severity, confidence, src_ip, dst_ip), _rules_solution(attack_type)

def enrich_df_with_ai(df: pd.DataFrame, mode: str, model_name: str, api_key: str, max_gpt_rows: int = 200) -> pd.DataFrame:
    """
    Adds 'summary' and 'proposed_action'.
    - rules mode: all rows via rules
    - gpt mode: first N rows via GPT (max_gpt_rows), rest via rules for speed/cost
    """
    if df is None or df.empty:
        return df

    df = df.copy().reset_index(drop=True)
    n = len(df)

    summaries, actions = [""]*n, [""]*n
    use_gpt = (mode == "gpt")
    gpt_limit = min(max_gpt_rows, n) if use_gpt else 0

    # First block (GPT or rules)
    for i in range(n):
        use_llm = use_gpt and (i < gpt_limit)
        s, a = generate_summary_and_solution(
            str(df.at[i, "attack_type"]) if "attack_type" in df.columns else "",
            str(df.at[i, "severity"]) if "severity" in df.columns else "",
            float(df.at[i, "confidence"]) if "confidence" in df.columns and pd.notna(df.at[i, "confidence"]) else 0.0,
            df.at[i, "src_ip"] if "src_ip" in df.columns else None,
            df.at[i, "dst_ip"] if "dst_ip" in df.columns else None,
            mode="gpt" if use_llm else "rules",
            model_name=model_name,
            api_key=api_key,
        )
        summaries[i], actions[i] = s, a

    df["summary"] = summaries
    df["proposed_action"] = actions
    return df

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
        ).properties(height=320)
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
        ).properties(height=320)
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
        ).properties(height=260)
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
        ).properties(height=260)
    )

# ================================
# ---- UI ----
# ================================
# Executive vs SOC (table columns & export)
mode_view = st.radio("Summary mode", ["Executive (concise)", "SOC (detailed)"], horizontal=True)
st.markdown("---")

# Sidebar: File + Filters + AI model selection
st.sidebar.header("Upload")
uploaded = st.sidebar.file_uploader("Upload alerts CSV", type=["csv"], help="Limit 200MB per file • CSV")

st.sidebar.header("Filters")
# filters are built after loading df (since we need unique values)

st.sidebar.header("🤖 Generative AI (Summaries)")
summary_source = st.sidebar.radio("Summary source", ["Rules (offline)", "OpenAI GPT"], index=0)
use_gpt = (summary_source == "OpenAI GPT")
model_name = st.sidebar.selectbox("Model", ["gpt-4o-mini", "gpt-4o"], index=0, disabled=not use_gpt)
max_gpt_rows = st.sidebar.slider("Max rows to summarize with GPT", 50, 1000, 200, 50, disabled=not use_gpt)

# API key preference: st.secrets first, then env, then manual input
prefilled_key = st.secrets.get("OPENAI_API_KEY", os.getenv("OPENAI_API_KEY", ""))
api_key = st.sidebar.text_input("OpenAI API Key", value=prefilled_key, type="password", disabled=not use_gpt,
                                help="Prefer using st.secrets or environment variable. This field overrides if filled.")

# Body content
if uploaded is None:
    st.info("No CSV found. Upload one from the sidebar.")
else:
    # Load
    df = pd.read_csv(uploaded)

    # Ensure expected columns exist
    for c in EXPECTED_COLS:
        if c not in df.columns:
            df[c] = "" if c == "summary" else pd.NA

    # Build Filters now that df is known
    atk_all = sorted([x for x in df["attack_type"].dropna().unique().tolist()])
    sev_all = sorted([x for x in df["severity"].dropna().unique().tolist()])
    mdl_all = sorted([x for x in df["model"].dropna().unique().tolist()]) if "model" in df.columns else []

    atk_sel = st.sidebar.multiselect("Attack type", atk_all, default=atk_all[:min(6, len(atk_all))])
    sev_sel = st.sidebar.multiselect("Severity", sev_all, default=sev_all)
    mdl_sel = st.sidebar.multiselect("Model (detector)", mdl_all, default=mdl_all) if mdl_all else mdl_all
    conf_min, conf_max = st.sidebar.slider("Confidence range", 0.0, 1.0, (0.0, 1.0), step=0.01)

    # Apply filters
    dff = df.copy()
    if atk_sel: dff = dff[dff["attack_type"].isin(atk_sel)]
    if sev_sel: dff = dff[dff["severity"].isin(sev_sel)]
    if mdl_sel: dff = dff[dff["model"].isin(mdl_sel)]
    dff["confidence"] = pd.to_numeric(dff["confidence"], errors="coerce").fillna(0.0)
    dff = dff[(dff["confidence"] >= conf_min) & (dff["confidence"] <= conf_max)]

    # Enrich with AI summaries + actions
    ai_mode = "gpt" if use_gpt else "rules"
    dff = enrich_df_with_ai(dff, mode=ai_mode, model_name=model_name, api_key=api_key, max_gpt_rows=max_gpt_rows)

    # KPIs
    total_alerts = len(dff)
    pct_high = (dff["severity"].eq("High").mean() * 100) if total_alerts else 0
    avg_conf = dff["confidence"].mean() if total_alerts else 0
    avg_flesch = pd.to_numeric(dff.get("readability_flesch", pd.Series(dtype=float)), errors="coerce").mean()

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total alerts", f"{total_alerts:,}")
    c2.metric("% High severity", f"{pct_high:.1f}%")
    c3.metric("Avg confidence", f"{avg_conf:.1%}" if avg_conf <= 1.0 else f"{avg_conf:.3f}")
    c4.metric("Avg Flesch score", f"{avg_flesch:.1f}")

    st.markdown("### Visual insights")
    v1, v2 = st.columns(2)
    with v1:
        st.markdown("**Counts by attack type**")
        st.altair_chart(chart_counts_by_attack(dff), use_container_width=True)
    with v2:
        st.markdown("**Severity share**")
        st.altair_chart(chart_severity_share(dff), use_container_width=True)

    v3, v4 = st.columns(2)
    with v3:
        st.markdown("**Confidence distribution**")
        st.altair_chart(chart_confidence(dff), use_container_width=True)
    with v4:
        ch = chart_flesch(dff)
        if ch is not None:
            st.markdown("**Readability (Flesch) distribution**")
            st.altair_chart(ch, use_container_width=True)

    st.markdown("---")
    st.subheader("Alerts")

    # Columns to display/export
    display_cols = [
        "timestamp","attack_type","severity","confidence","src_ip","dst_ip","summary","model","readability_flesch"
    ]
    if mode_view == "SOC (detailed)":
        insert_at = display_cols.index("model")
        display_cols.insert(insert_at, "proposed_action")
    display_cols = [c for c in display_cols if c in dff.columns]

    st.dataframe(dff[display_cols], use_container_width=True, height=520)

    # Export CSV (matches current view)
    csv_bytes = dff[display_cols].to_csv(index=False).encode("utf-8")
    st.download_button("Download filtered CSV", data=csv_bytes, file_name="alerts_filtered.csv", mime="text/csv")

    # Helpful tips
    if use_gpt and not api_key:
        st.warning("OpenAI GPT selected, but no API key provided. Add it in the sidebar or via st.secrets / environment variable.")
    if use_gpt:
        st.caption(f"GPT model: {model_name} • Summarized up to {max_gpt_rows} rows with GPT; remaining rows use rules for speed/cost.")
    else:
        st.caption("Using rules-based summaries (offline).")
