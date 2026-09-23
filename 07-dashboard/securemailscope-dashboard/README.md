# 07-dashboard — SecureMailScope

This is Safa's part of the SIH'26 project (PS 159 / SIH26159): the results
screen that shows scan output as a dashboard.

## Files

- `app.py` — the Streamlit dashboard (the actual app)
- `sample_data/scan_results.json` — FAKE sample data, shaped the way the
  real rules-engine/ML output will eventually look. Used so the dashboard
  works before teammates finish their parts.
- `requirements.txt` — Python packages needed to run this

## How to run it

```
pip install -r requirements.txt
streamlit run app.py
```

Your browser opens automatically at http://localhost:8501

## What it shows

- Top row: total servers scanned, average risk score, how many are
  critical/high risk, total issues found
- A bar chart comparing risk score across servers
- A pie chart of how many servers fall in each risk level
- An expandable card per server with its issues and recommended fix
- A "Download JSON Report" button (placeholder for the full PDF/HTML
  report from 08-reports-docs)

## Swapping in real data later

Once folders 04-certs-rules / 05-ml-ai produce real output, save their
JSON in the same shape as `sample_data/scan_results.json` and update the
`DATA_FILE` line near the top of `app.py` to point at it. Nothing else
needs to change.

## Expected JSON shape

```json
{
  "scan_summary": {
    "scan_id": "...",
    "scan_date": "...",
    "pcap_source": "...",
    "total_sessions_analyzed": 0
  },
  "servers": [
    {
      "server": "hostname",
      "ip": "0.0.0.0",
      "protocol": "SMTP | IMAP | POP3",
      "risk_score": 0,
      "risk_level": "Low | Medium | High | Critical",
      "issues": [
        {"severity": "Low|Medium|High", "category": "...", "description": "..."}
      ],
      "recommendation": "..."
    }
  ]
}
```
Share this shape with the rules-engine/ML team so their output plugs in directly.
