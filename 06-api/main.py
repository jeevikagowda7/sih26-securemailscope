from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from data_loader import load_all

app = FastAPI(title="SecureMailScope API", version="0.2.0")

# Permission slip so a dashboard on another address can call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _short(s):
    """A small summary of one capture, for lists."""
    rules = s["rules"] or {}
    ai = s["ai"] or {}
    tls = s["tls"][0] if s["tls"] else {}
    stream = s["streams"][0] if s["streams"] else {}
    return {
        "session_id": s["session_id"],
        "complete": s["complete"],
        "stages_present": s["stages_present"],
        "protocol": stream.get("protocol"),
        "encrypted": tls.get("encrypted"),
        "risk_score": rules.get("risk_score"),
        "risk_level": rules.get("risk_level"),
        "verdict": ai.get("verdict"),
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/sessions")
def list_sessions(risk_level: str | None = None, complete: bool | None = None):
    sessions, warnings = load_all()
    rows = [_short(s) for s in sessions.values()]

    if risk_level is not None:
        rows = [r for r in rows if r["risk_level"] == risk_level.upper()]
    if complete is not None:
        rows = [r for r in rows if r["complete"] == complete]

    rows.sort(key=lambda r: r["session_id"])
    return {"count": len(rows), "sessions": rows, "warnings": warnings}


@app.get("/sessions/{session_id}")
def get_session(session_id: str):
    sessions, warnings = load_all()
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail=f"No capture named {session_id}")
    return {"session": sessions[session_id], "warnings": warnings}


@app.get("/summary")
def summary():
    sessions, warnings = load_all()

    by_level = {}
    scores = []
    for s in sessions.values():
        r = s["rules"]
        if r:
            by_level[r["risk_level"]] = by_level.get(r["risk_level"], 0) + 1
            scores.append(r["risk_score"])

    tls_rows = [t for s in sessions.values() for t in s["tls"]]
    incomplete = sorted(
        (
            {
                "session_id": s["session_id"],
                "missing": [k for k, v in s["stages_present"].items() if not v],
            }
            for s in sessions.values()
            if not s["complete"]
        ),
        key=lambda x: x["session_id"],
    )

    return {
        "total_captures": len(sessions),
        "complete_captures": sum(1 for s in sessions.values() if s["complete"]),
        "incomplete_captures": incomplete,
        "by_risk_level": by_level,
        "average_risk_score": round(sum(scores) / len(scores), 1) if scores else None,
        "encrypted_sessions": sum(1 for t in tls_rows if t.get("encrypted") is True),
        "plaintext_sessions": sum(1 for t in tls_rows if t.get("encrypted") is False),
        "credentials_exposed_sessions": sum(
            1 for t in tls_rows if t.get("credentials_exposed") is True
        ),
        "warnings": warnings,
    }
