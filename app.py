# app.py — Generative AI–Powered Intrusion Detection System (IDS)

import io, os, time, datetime as dt, re
from pathlib import Path

import numpy as np
import pandas as pd
import streamlit as st

# ---- ReportLab for PDF ----
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
)

# ---- OpenAI (LLM) ----
try:
    from openai import OpenAI
    _OPENAI_AVAILABLE = True
except Exception:
    _OPENAI_AVAILABLE = False

# ====================== PDF builder (branded) ======================
def build_pdf(
    df: pd.DataFrame,
    mode_label: str,
    kpi: dict,
    title: str = "Generative AI–Powered Intrusion Detection System (IDS)",
    org_name: str = "University of Maryland Global Campus (UMGC)",
    student_name: str = "Marcel Dinga",
    course_name: str = "DATA 675 – Generative AI",
    logo_path: str = "assets/logo.png",
) -> bytes:
    """Return branded PDF bytes for download."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=landscape(A4),
        leftMargin=12 * mm,
        rightMargin=12 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm,
        title=title,
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="tiny", fontSize=7, leading=8))
    styles.add(ParagraphStyle(name="subtle", fontSize=9, textColor=colors.HexColor("#4a5568")))
    h1 = styles["Heading1"]

    elements = []

    # ---- Header (logo + heading) ----
    logo_el = None
    try:
        if Path(logo_path).exists():
            logo_el = Image(logo_path, width=28 * mm, height=28 * mm, kind="proportional")
    except Exception:
        logo_el = None

    now = dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    heading_html = (
        f"<b>{title}</b><br/>"
        f"{course_name} | {student_name} | {org_name}<br/>"
        f"<font size=9>Generated: {now} • Mode: {mode_label}</font>"
    )
    heading = Paragraph(heading_html, h1)

    if logo_el:
        header_tbl = Table([[logo_el, heading]], colWidths=[32 * mm, None])
    else:
        header_tbl = Table([[heading]], colWidths=[None])

    header_tbl.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    elements.append(header_tbl)
    elements.append(Spacer(1, 6))

    # ---- KPIs ----
    kpi_line = " • ".join(
        [
            f"Total alerts: <b>{kpi.get('total', '—')}</b>",
            f"% High severity: <b>{kpi.get('pct_high', '—')}</b>",
            f"Avg confidence: <b>{kpi.get('avg_conf', '—')}</b>",
            f"Avg Flesch: <b>{kpi.get('avg_flesch', '—')}</b>",
        ]
    )
    elements.append(Paragraph(kpi_line, styles["Normal"]))
    elements.append(Spacer(1, 6))

    # ---- Table ----
    cols_pref = ["timestamp", "attack_type", "severity", "confidence", "src_ip", "dst_ip", "summary"]
    cols = [c for c in cols_pref if c in df.columns]
    data = [cols]

    for _, r in df[cols].iterrows():
        row = []
        for c in cols:
            val = str(r[c])
            if c == "summary" and len(val) > 400:
                val = val[:400] + "…"
            if c == "confidence":
                try:
                    val = f"{float(val):.2f}"
                except Exception:
                    pass
            row.append(Paragraph(val, styles["tiny"]))
        data.append(row)

    tbl = Table(data, repeatRows=1)
    tbl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e6eef9")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#0b3a75")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 9),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.HexColor("#fbfbfb")]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    elements.append(tbl)

    # ---- Footer (page number) ----
    def footer(canvas, _doc):
        canvas.saveState()
        footer_text = f"{org_name}  •  {title}  •  Page {_doc.page}"
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#4a5568"))
        canvas.drawRightString(_doc.pagesize[0] - 12 * mm, 8 * mm, footer_text)
        canvas.restoreState()

    doc.build(elements, onFirstPage=footer, onLaterPages=footer)
    buf.seek(0)
    return buf.read()


# ====================== Streamlit app ======================
st.set_page_config(
    page_title="Generative AI–Powered Intrusion Detection System (IDS)",
    layout="wide"
)

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
    high = float((df["severity"].str.lower() == "high").mean() * 100) if "severity" in df else np.nan
    conf = float(df["confidence"].mean() * 100) if "confidence" in df else np.nan
    read = float(df["readability_flesch"].mean()) if "readability_flesch" in df else np.nan
    c1, c2, c3, c4 = st.columns(4)
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
        lo, hi = st.sidebar.slider("Confidence range", 0.0, 1.0, (round(cmin, 2), round(cmax, 2)), step=0.01)
        df = df[(df["confidence"] >= lo) & (df["confidence"] <= hi)]
    q = st.sidebar.text_input("Search in summary/IPs")
    if q.strip():
        patt = re.compile(re.escape(q.strip()), re.IGNORECASE)
        cols = [c for c in ["summary", "src_ip", "dst_ip", "attack_type"] if c in df.columns]
        mask = np.zeros(len(df), dtype=bool)
        for c in cols:
            mask |= df[c].astype(str).str.contains(patt, na=False)
        df = df[mask]
    return df

def charts(df: pd.DataFrame):
    c1, c2 = st.columns([2, 1])
    with c1:
        if "attack_type" in df.columns and not df.empty:
            st.subheader("Counts by attack type")
            st.bar_chart(df["attack_type"].value_counts().sort_values(ascending=False))
    with c2:
        if "severity" in df.columns and not df.empty:
            st.subheader("Severity share")
            st.bar_chart(df["severity"].value_counts())
    c3, c4 = st.columns(2)
    with c3:
        if "confidence" in df.columns and not df.empty:
            st.subheader("Confidence distribution")
            st.line_chart(df["confidence"].sort_values(ignore_index=True))
    with c4:
        if "readability_flesch" in df.columns and not df.empty:
            st.subheader("Readability (Flesch) distribution")
            st.line_chart(df["readability_flesch"].sort_values(ignore_index=True))

def alerts_table(df: pd.DataFrame):
    cols_pref = [
        "timestamp",
        "attack_type",
        "severity",
        "confidence",
        "src_ip",
        "dst_ip",
        "summary",
        "model",
        "readability_flesch",
    ]
    cols = [c for c in cols_pref if c in df.columns]
    st.subheader("Alerts")
    st.dataframe(df[cols].reset_index(drop=True), use_container_width=True, height=460)

def first_sentence(text: str) -> str:
    if not isinstance(text, str):
        return ""
    m = re.search(r"(.+?[.!?])(\s|$)", text)
    s = m.group(1).strip() if m else text.strip()
    return (s[:180] + "…") if len(s) > 180 else s

# ====================== LLM Summarization ======================
EXEC_PROMPT = """You are a security analyst. Produce a single-sentence executive summary (max ~35 words) of the following IDS alert for non-technical leaders. Be precise, avoid jargon, include impact and basic recommended response.
{fields}
"""

SOC_PROMPT = """You are a SOC analyst. Produce a detailed, 2–3 sentence summary of the IDS alert, using clear plain language. Include: attack type, indicators, likely intent/impact, and 1–2 recommended actions. Avoid speculation; be specific.
{fields}
"""

def make_fields_string(row: pd.Series) -> str:
    fields = {
        "Attack Type": row.get("attack_type", ""),
        "Severity": row.get("severity", ""),
        "Confidence": row.get("confidence", ""),
        "Source IP": row.get("src_ip", ""),
        "Destination IP": row.get("dst_ip", ""),
        "Timestamp": row.get("timestamp", ""),
        "Model": row.get("model", ""),
    }
    # mask IPs mildly (last octet)
    def mask(ip):
        if not isinstance(ip, str) or ip.count(".") != 3:
            return ip
        parts = ip.split("."); parts[-1] = "xxx"; return ".".join(parts)
    fields["Source IP"] = mask(fields["Source IP"])
    fields["Destination IP"] = mask(fields["Destination IP"])
    return "\n".join([f"{k}: {v}" for k, v in fields.items() if str(v)])

def build_prompt_for_row(row: pd.Series, mode_label: str) -> str:
    base = SOC_PROMPT if mode_label.startswith("SOC") else EXEC_PROMPT
    return base.format(fields=make_fields_string(row))

@st.cache_data(show_spinner=False)
def _model_choices_cached():
    # sensible defaults that exist broadly
    return ["gpt-4o-mini", "gpt-4o", "gpt-4.1-mini"]

def get_openai_client():
    api_key = st.secrets.get("OPENAI_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("Missing OPENAI_API_KEY (set it in Streamlit secrets or env).")
    if not _OPENAI_AVAILABLE:
        raise RuntimeError("OpenAI SDK not installed. Add `openai>=1.40.0` to requirements.txt.")
    return OpenAI(api_key=api_key)

def generate_summaries_with_gpt(df: pd.DataFrame, mode: str, model: str, max_rows: int = 100, temperature: float = 0.2, delay_s: float = 0.2) -> pd.DataFrame:
    """
    Fills/overwrites 'summary' for up to max_rows entries in df that are missing or empty.
    Returns a new DataFrame copy.
    """
    client = get_openai_client()
    work = df.copy()
    if "summary" not in work.columns:
        work["summary"] = ""

    # only rows needing summaries
    need_mask = work["summary"].isna() | (work["summary"].astype(str).str.strip() == "")
    idxs = work[need_mask].head(max_rows).index.tolist()
    if not idxs:
        return work

    prog = st.progress(0, text=f"Generating {len(idxs)} summaries with {model} ({mode}) …")
    for j, idx in enumerate(idxs, start=1):
        row = work.loc[idx]
        prompt = build_prompt_for_row(row, mode)
        try:
            # Chat Completions (widely available)
            resp = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": "You are a helpful cybersecurity assistant."},
                    {"role": "user", "content": prompt},
                ],
                temperature=temperature,
                max_tokens=180,
            )
            summary_text = resp.choices[0].message.content.strip()
            work.at[idx, "summary"] = summary_text
        except Exception as e:
            work.at[idx, "summary"] = f"(LLM error: {e})"
        prog.progress(j / len(idxs))
        time.sleep(delay_s)  # gentle pacing
    prog.empty()
    return work


# ====================== UI ======================
st.title("🔐 Generative AI–Powered Intrusion Detection System (IDS)")
st.caption("DATA 675 – Generative AI | Marcel Dinga | University of Maryland Global Campus (UMGC)")

# Summary mode toggle
mode = st.radio(
    "Summary mode",
    ["Executive (concise)", "SOC (detailed)"],
    horizontal=True,
    help="Executive = 1 sentence per alert. SOC = full multi-sentence summary.",
)

# Upload or load latest
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

# ==== LLM controls ====
with st.sidebar.expander("🤖 Generative AI (GPT)"):
    st.write("Generate human-readable summaries from raw alert fields.")
    model_choice = st.selectbox("Model", _model_choices_cached())
    max_rows = st.slider("Max rows to generate", 10, 300, 100, step=10)
    temperature = st.slider("Creativity (temperature)", 0.0, 1.0, 0.2, step=0.1)
    do_generate = st.button("Generate summaries now")

if do_generate:
    try:
        df = generate_summaries_with_gpt(df, mode, model_choice, max_rows=max_rows, temperature=temperature)
        st.success(f"Summaries generated with {model_choice}.")
    except Exception as e:
        st.error(f"LLM generation failed: {e}")

# KPIs + filters + charts
kpis(df)
filtered = apply_filters(df)
st.markdown("---")
charts(filtered)

# Executive mode view (trim to first sentence)
display_df = filtered.copy()
if "summary" in display_df.columns and mode.startswith("Executive"):
    display_df["summary"] = display_df["summary"].apply(first_sentence)

# Table
st.markdown("---")
alerts_table(display_df)

# ---------------- EXPORT ----------------
st.markdown("---")
st.subheader("📦 Export report")

# CSV
csv_bytes = display_df.to_csv(index=False).encode("utf-8")
st.download_button(
    label="⬇️ Download filtered CSV",
    data=csv_bytes,
    file_name="alerts_filtered.csv",
    mime="text/csv",
    key="dl_csv",
)

# KPIs for PDF header
kpi_dict = {
    "total": len(display_df),
    "pct_high": f"{(display_df['severity'].str.lower()=='high').mean()*100:0.1f}%" if "severity" in display_df else "—",
    "avg_conf": f"{display_df['confidence'].mean()*100:0.1f}%" if "confidence" in display_df else "—",
    "avg_flesch": f"{display_df['readability_flesch'].mean():0.1f}" if "readability_flesch" in display_df else "—",
}

# PDF
pdf_bytes, pdf_error = None, None
try:
    pdf_bytes = build_pdf(
        display_df,
        mode,
        kpi_dict,
        title="Generative AI–Powered Intrusion Detection System (IDS)",
        org_name="University of Maryland Global Campus (UMGC)",
        student_name="Marcel Dinga",
        course_name="DATA 675 – Generative AI",
        logo_path="assets/logo.png",  # optional
    )
except Exception as e:
    pdf_error = str(e)

if pdf_bytes:
    st.download_button(
        label="📄 Download PDF report",
        data=pdf_bytes,
        file_name="ids_alerts_report.pdf",
        mime="application/pdf",
        key="dl_pdf",
    )
else:
    st.info("PDF not available yet.")
    if pdf_error:
        st.error(f"PDF generation error: {pdf_error}")

st.caption("Use the sidebar to filter by type, severity, model, confidence, and search text.")
