import json
from pathlib import Path

# The repo root is one folder above 06-api
REPO_ROOT = Path(__file__).resolve().parent.parent

TLS_FILE = REPO_ROOT / "03-tls-parser" / "tls_parsed_output.json"
RULES_FILE = REPO_ROOT / "04-certs-rules" / "output.json"
AI_FILE = REPO_ROOT / "05-ml-ai" / "analysis_results.json"
STREAMS_DIR = REPO_ROOT / "02-pcap-streams" / "extracted_streams"
ALL_SUMMARIES_FILE = STREAMS_DIR / "all_summaries.json"

HIDDEN = "***hidden***"


def _read_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _hide_nested_password(stream):
    """Copy a nested stream and hide any password inside it."""
    clean = json.loads(json.dumps(stream))
    creds = clean.get("signals", {}).get("decoded_credentials")
    if isinstance(creds, dict) and creds.get("password"):
        creds["password"] = HIDDEN
    return clean


def _hide_flat_password(stream):
    """Copy a flat stream and hide any leaked password."""
    clean = json.loads(json.dumps(stream))
    if clean.get("leaked_password"):
        clean["leaked_password"] = HIDDEN
    return clean


def load_streams():
    """Read folder 02 in BOTH formats. Returns {capture_name: [streams]}."""
    streams = {}
    warnings = []

    # Format 1: nested (first 6 captures) - all_summaries.json
    if ALL_SUMMARIES_FILE.exists():
        for group in _read_json(ALL_SUMMARIES_FILE):
            name = group["pcap"]
            for st in group.get("streams", []):
                item = _hide_nested_password(st)
                item["stream_format"] = "nested"
                streams.setdefault(name, []).append(item)
    else:
        warnings.append("all_summaries.json not found")

    # Format 2: flat - one *_streams.json file per capture
    for path in sorted(STREAMS_DIR.glob("*_streams.json")):
        for st in _read_json(path):
            name = st["source_pcap"]
            if name in streams and streams[name][0]["stream_format"] == "nested":
                warnings.append(f"{name} found in BOTH formats (kept nested one)")
                continue
            item = _hide_flat_password(st)
            item["stream_format"] = "flat"
            streams.setdefault(name, []).append(item)

    return streams, warnings


def load_all():
    """Read every teammate's file and join them by capture name."""
    tls_rows = _read_json(TLS_FILE)
    rules_rows = _read_json(RULES_FILE)
    ai_rows = _read_json(AI_FILE)
    stream_map, warnings = load_streams()

    sessions = {}

    def get(name):
        if name not in sessions:
            sessions[name] = {
                "session_id": name,
                "streams": [],
                "tls": [],
                "rules": None,
                "ai": None,
            }
        return sessions[name]

    for name, items in stream_map.items():
        get(name)["streams"] = items

    for row in tls_rows:
        get(row["source_pcap"])["tls"].append(row)

    for row in rules_rows:
        s = get(row["session_id"])
        if s["rules"] is not None:
            warnings.append(f"Duplicate rules row for {row['session_id']}")
        s["rules"] = row

    for row in ai_rows:
        s = get(row["session_id"])
        if s["ai"] is not None:
            warnings.append(f"Duplicate AI row for {row['session_id']}")
        s["ai"] = row

    for s in sessions.values():
        s["stages_present"] = {
            "streams": len(s["streams"]) > 0,
            "tls_parser": len(s["tls"]) > 0,
            "rules": s["rules"] is not None,
            "ai": s["ai"] is not None,
        }
        s["complete"] = all(s["stages_present"].values())

    return sessions, warnings


if __name__ == "__main__":
    sessions, warnings = load_all()
    print("Total captures:", len(sessions))
    print("Complete (all 4 stages):", sum(1 for s in sessions.values() if s["complete"]))
    print()
    for name in sorted(sessions):
        s = sessions[name]
        st = s["stages_present"]
        fmt = s["streams"][0]["stream_format"] if s["streams"] else "-"
        print(
            f"{name:42} streams={len(s['streams'])}({fmt:6}) "
            f"tls={st['tls_parser']}  rules={st['rules']}  ai={st['ai']}"
        )
    print()
    print("Warnings:", warnings if warnings else "none")

    # Safety check: make sure no password leaks through
    text = json.dumps(sessions)
    print("Password leak check:", "FAIL - password found!" if "yourNewPassword123" in text else "PASS - no password found")
