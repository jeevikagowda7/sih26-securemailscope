"""
Refresh the demo page with the latest data.

Run this from the 07-dashboard/demo folder:
    python update_demo.py

It reads ../../05-ml-ai/real_data.csv and rewrites the data inside index.html.
Your design is not touched. Only the numbers change.

To use a different CSV:
    python update_demo.py path\\to\\other_real_data.csv
"""
import csv
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).parent
HTML = HERE / "index.html"
DEFAULT_CSV = HERE.parent.parent / "05-ml-ai" / "real_data.csv"


def to_bool(v):
    return str(v).strip().lower() == "true"


def load_rows(csv_path):
    rows, seen = [], set()
    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        for r in csv.DictReader(f):
            sid = (r.get("session_id") or "").strip()
            if not sid or sid in seen:  # skip blanks and duplicate sessions
                continue
            seen.add(sid)
            rows.append({
                "session_id": sid,
                "tls_version": float(r.get("tls_version") or 0),
                "weak_cipher": to_bool(r.get("weak_cipher")),
                "starttls_used": to_bool(r.get("starttls_used")),
                "starttls_offered": to_bool(r.get("starttls_offered")),
                "insecure_auth": to_bool(r.get("insecure_auth")),
                "credentials_exposed": to_bool(r.get("credentials_exposed")),
                "encrypted": to_bool(r.get("encrypted")),
                "cert_valid": to_bool(r.get("cert_valid")),
                "risk_score": int(float(r.get("risk_score") or 0)),
                "risk_level": (r.get("risk_level") or "LOW").strip().upper(),
                "reason": (r.get("reason") or "").strip(),
            })
    return rows


def main():
    csv_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_CSV
    if not csv_path.exists():
        sys.exit(f"Could not find the CSV file:\n  {csv_path}\nRun this from the demo folder, or give the path to real_data.csv.")
    if not HTML.exists():
        sys.exit(f"Could not find index.html next to this script:\n  {HTML}")

    rows = load_rows(csv_path)
    if not rows:
        sys.exit("The CSV has no rows, so nothing was changed.")

    html = HTML.read_text(encoding="utf-8")
    new_block = "const DATA = " + json.dumps(rows, indent=1) + ";\n"
    updated, n = re.subn(r"const DATA = \[.*?\];\n", lambda m: new_block, html, count=1, flags=re.S)
    if n != 1:
        sys.exit("Could not find the data block in index.html. Nothing was changed.")

    HTML.write_text(updated, encoding="utf-8")
    high = sum(r["risk_level"] == "HIGH" for r in rows)
    med = sum(r["risk_level"] == "MEDIUM" for r in rows)
    low = sum(r["risk_level"] == "LOW" for r in rows)
    print(f"Done. index.html now shows {len(rows)} sessions: {high} vulnerable, {med} flagged, {low} secure.")
    print(f"Data came from: {csv_path}")


if __name__ == "__main__":
    main()
