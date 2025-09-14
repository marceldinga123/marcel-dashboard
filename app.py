import io, datetime as dt
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
import re
from pathlib import Path
import numpy as np
import pandas as pd
import streamlit as st

# -------------------- PDF builder --------------------
def build_pdf(df, mode_label, kpi, title="IDS Alerts Report"):
    """Return PDF bytes for download."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=landscape(A4),
        leftMargin=12*mm, rightMargin=12*mm, topMargin=12*mm, bottomMargin=12*mm,
        title=title,
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="tiny", fontSize=7, leading=8))
    elements = []

    # Header
    now = dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    elements.append(Paragraph(f"<b>{title}</b>", styles["Heading1"]))
    elements.append(Paragraph(f"Generated: {now} • Mode: {mode_label}", styles["Normal"]))
    elements.append(Spacer(1, 6))

    # KPIs
    kpi_line = " • ".join([
        f"Total alerts: <b>{kpi.get('total','—')}</b>",
        f"% High severity: <b>{kpi.get('pct_high','—')}</b>",
        f"Avg confidence: <b>{kpi.get('avg_conf','—')}</b>",
        f"Avg Flesch: <b>{kpi.get('avg_flesch','—')}</b>",
    ])
    elements.append(Paragraph(kpi_line, styles["Normal"]))
    elements.append(Spacer(1, 6))

    # Table
    cols_pref = ["timestamp","attack_type","severity","confidence","src_ip","dst_ip","summary"]
    cols = [c for c in cols_pref if c in df.columns]
    data = [cols]
    for _, r in df[cols].iterrows():
        row = []
        for c in cols:
            val = str(r[c])[:200] + ("…" if len(str(r[c])) > 200 else "")
            row.append(Paragraph(val, styles["tiny"]))
        data.append(row)

    tbl = Table(data, repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#e6eef9")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.HexColor("#0b3a75")),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE", (0,0), (-1,0), 9),
        ("GRID", (0,0), (-1,-1), 0.25, colors.lightgrey),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.whitesmoke, colors.HexColor("#fbfbfb")]),
    ]))
    elements.append(tbl)

    doc.build(elements)
    buf.seek(0)
    return buf.read()

# -------------------- App setup --------------------
st.set_page_config(page_title="IDS Alerts + Generative Summaries", layout="wide")

# Default directory
DEFAULT_REPORT_DIR = Path("artifacts/gen_reports")

# -------- Helpers --------
def discover_latest_csv(dir_path: Path):
    if not dir_path.exists():
        return None, None
    csvs = sorted(dir_path.glob("*.csv"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not csvs:
        return None, None
    return pd.read_csv(csvs[0]), csvs[0]

def coerce_columns(df: pd.DataFrame):
    df = df.copy()
    for c in df.columns:
        if "time" in c.lower():
            df[c] = pd.to_datetime(df[c], errors="coerce")
    for c in ["confidence", "readability_flesch"]:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce")
    for c in ["attack_type", "severity", "model", "src_ip", "dst_ip", "summary"]:
        if c in df.columns:
            df[c] = df[c].astype(str)
    return df

def kpis(df: pd.DataFrame):
    total = len(df)
    high = float((df["severity"].str.lower()=="high").mean()*100) if "severity" in df else np.nan
    conf = float(df["confidence"].mean()*100) if "confidence" in df else np.nan
    read = float(df["readability_flesch"].mean()) if "readability_flesch" in df else np.nan
    c1,c2,c3,c4 = st.columns(4)
    c1.metric("Total alerts", f"{total:,}")
    c2.metric("% High severity", "—" if np.isnan(high) else f"{high:0.1f}%")
    c3.metric("Avg confidence", "—" if np.isnan(conf) else f"{conf:0.1f}%")
    c4.metric("Avg Flesch score", "—" if np.isnan(read) else f"{read:0.1f}")

def apply_filters(df: pd.DataFrame):
    st.sidebar.header("Filters")
    if "attack_type" in df.columns:
        types = sorted(df["attack_type"].dropna().unique().tolist())
        chosen = st.sidebar.multiselect("Attack type", types, default=types)
        df = df[df["attack_type"].isin(chosen)]
    if "severity" in df.columns:
        sev_all = ["Informational", "Low", "Medium", "High"]
        present = [s for s in sev_all if s in set(df["severity"].unique())]
        chosen = st.sidebar.multiselect("Severity", present, default=present)
        df = df[df["severity"].isin(chosen)]
    if "model" in df.columns:
        models = sorted(df["model"].dropna().unique().tolist())
        chosen = st.sidebar.multiselect("Model", models, default=models)
        df = df[df["model"].isin(chosen)]
    if "confidence" in df.columns and df["confidence"].notna().any():
        cmin, cmax = float(df["confidence"].min()), float(df["confidence"].max())
        lo, hi = st.sidebar.slider("Confidence range", 0.0, 1.0, (round(cmin,2), round(cmax,2)), step=0.01)
        df = df[(df["confidence"]>=lo) & (df["confidence"]<=hi)]
    q = st.sidebar.text_input("Search in summary/IPs")
    if q.strip():
        patt = re.compile(re.escape(q.strip()), re.IGNORECASE)
        cols = [c for c in ["summary","src_ip","dst_ip","attack_type"] if c in df.columns]
        mask = np.zeros(len(df), dtype=bool)
        for c in cols: mask |= df[c].astype(str).str.contains(patt, na=False)
        df = df[mask]
    return df

def charts(df: pd.DataFrame):
    c1,c2 = st.columns([2,1])
    with c1:
        if "attack_type" in df.columns and not df.empty:
            st.subheader("Counts by attack type")
            st.bar_chart(df["attack_type"].value_counts().sort_values(ascending=False))
    with c2:
        if "severity" in df.columns and not df.empty:
            st.subheader("Severity share")
            st.bar_chart(df["severity"].value_counts())
    c3,c4 = st.columns(2)
    with c3:
        if "confidence" in df.columns and not df.empty:
            st.subheader("Confidence distribution")
            st.line_chart(df["confidence"].sort_values(ignore_index=True))
    with c4:
        if "readability_flesch" in df.columns and not df.empty:
            st.subheader("Readability (Flesch) distribution")
            st.line_chart(df["readability_flesch"].sort_values(ignore_index=True))

def alerts_table(df: pd.DataFrame):
    cols_pref = ["timestamp","attack_type","severity","confidence","src_ip","dst_ip","summary","model","readability_flesch"]
    cols = [c for c in cols_pref if c in df.columns]
    st.subheader("Alerts")
    st.dataframe(df[cols].reset_index(drop=True), use_container_width=True, height=460)

# CSV download helper
def download_button(df: pd.DataFrame):
    st.download_button("⬇️ Download filtered CSV", data=df.to_csv(index=False), file_name="alerts_filtered.csv", mime="text/csv")

# Executive mode helper: keep the first sentence (short)
def first_sentence(text: str) -> str:
    if not isinstance(text, str): 
        return ""
    m = re.search(r'(.+?[.!?])(\s|$)', text)
    s = m.group(1).strip() if m else text.strip()
    return (s[:180] + "…") if len(s) > 180 else s

# -------------------- UI --------------------
st.title("🔐 IDS Alerts + Generative Summaries")
st.caption("CICIDS2017 • Detection → Generative Summary → Analyst Report")

# Summary mode toggle
mode = st.radio(
    "Summary mode",
    ["Executive (concise)", "SOC (detailed)"],
    horizontal=True,
    help="Executive = 1 sentence per alert. SOC = full multi-sentence summary."
)

uploaded = st.sidebar.file_uploader("Upload alerts CSV", type=["csv"])
if uploaded is not None:
    df = pd.read_csv(uploaded)
    src_msg = f"Uploaded: {uploaded.name}"
else:
    df, latest = discover_latest_csv(DEFAULT_REPORT_DIR)
    if df is None:
        st.warning("No CSV found. Please upload one using the sidebar.")
        st.stop()
    src_msg = f"Loaded latest file: {latest.name}"

df = coerce_columns(df)
st.info(src_msg)

# KPIs
kpis(df)

# Filters + charts
filtered = apply_filters(df)
st.markdown("---"); charts(filtered)

# Build display copy (apply Executive trimming if chosen)
display_df = filtered.copy()
if "summary" in display_df.columns and mode.startswith("Executive"):
    display_df["summary"] = display_df["summary"].apply(first_sentence)

# Table
st.markdown("---"); alerts_table(display_df)

# Downloads (CSV + PDF)
download_button(display_df)

kpi_dict = {
    "total": len(display_df),
    "pct_high": f"{(display_df['severity'].str.lower()=='high').mean()*100:0.1f}%" if "severity" in display_df else "—",
    "avg_conf": f"{display_df['confidence'].mean()*100:0.1f}%" if "confidence" in display_df else "—",
    "avg_flesch": f"{display_df['readability_flesch'].mean():0.1f}" if "readability_flesch" in display_df else "—",
}
pdf_bytes = build_pdf(display_df, mode, kpi_dict, title="IDS Alerts + Generative Summaries")
st.download_button("📄 Download PDF report", data=pdf_bytes, file_name="ids_alerts_report.pdf", mime="application/pdf")

st.caption("Use the sidebar to filter by type, severity, model, confidence, and search text.")
