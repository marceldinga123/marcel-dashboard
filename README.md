# IDS Alerts + Generative Summaries (Streamlit)

Quick start (local):
```
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

Streamlit Cloud:
- Push this folder to GitHub.
- On https://streamlit.io/cloud → New app → select repo → `app.py`.
- Upload your alerts CSV from the sidebar, or keep CSVs in `artifacts/gen_reports/`.

Data folder for CSVs:
```
artifacts/gen_reports/
```
