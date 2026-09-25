import json

with open("../03-tls-parser/tls_parsed_output.json", "r") as f:
    all_sessions = json.load(f)

tls_version_map = {
    "0x0301": "TLSv1.0",
    "0x0302": "TLSv1.1",
    "0x0303": "TLSv1.2",
    "0x0304": "TLSv1.3"
}

weak_cipher_codes = ["0x0004", "0x0005"]
weak_cipher_keywords = ["3DES", "RC4", "DES", "MD5", "NULL", "EXPORT"]

results = []

for i, data in enumerate(all_sessions):
    source_file = data.get("source_pcap", f"session_{i}")
    encrypted = data.get("encrypted", False)
    credentials_exposed = data.get("credentials_exposed", False)
    insecure_auth = data.get("insecure_auth", False)

    # Highest priority checks first — these alone force HIGH risk
    if credentials_exposed:
        results.append({
            "session_id": source_file,
            "cert_valid": False,
            "nist_compliant": False,
            "risk_score": 100,
            "risk_level": "HIGH",
            "reason": "Credentials exposed in plaintext"
        })
        continue

    if insecure_auth:
        results.append({
            "session_id": source_file,
            "cert_valid": False,
            "nist_compliant": False,
            "risk_score": 100,
            "risk_level": "HIGH",
            "reason": "Insecure authentication method used"
        })
        continue

    if not encrypted:
        results.append({
            "session_id": source_file,
            "cert_valid": False,
            "nist_compliant": False,
            "risk_score": 100,
            "risk_level": "HIGH",
            "reason": data.get("note", "No encryption detected")
        })
        continue

    # Handle tls_version whether it's a hex code ("0x0303") or already a name ("TLSv1.0")
    tls_raw = data.get("tls_version", "")
    tls_version = tls_version_map.get(tls_raw, tls_raw)

    # Handle cipher_suite whether it's a hex code or a readable cipher name
    cipher_code = data.get("cipher_suite", "")
    is_weak_cipher = (
        cipher_code in weak_cipher_codes
        or any(keyword in cipher_code for keyword in weak_cipher_keywords)
    )

    # REAL certificate validity check, using Jeevika's actual cert fields
    cert_expired = data.get("cert_expired", None)
    cert_not_yet_valid = data.get("cert_not_yet_valid", None)

    if cert_expired is None:
        cert_valid = False
    else:
        cert_valid = (not cert_expired) and (not cert_not_yet_valid)

    good_tls_versions = ["TLSv1.2", "TLSv1.3"]

    risk_score = 0
    if not cert_valid:
        risk_score += 50
    if tls_version not in good_tls_versions:
        risk_score += 30
    if is_weak_cipher:
        risk_score += 40

    # Cap the score at 100 so it always reads like a percentage
    risk_score = min(risk_score, 100)

    nist_compliant = cert_valid and (tls_version in good_tls_versions) and (not is_weak_cipher)

    if risk_score == 0:
        risk_level = "LOW"
    elif risk_score <= 50:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"

    results.append({
        "session_id": source_file,
        "cert_valid": cert_valid,
        "nist_compliant": nist_compliant,
        "risk_score": risk_score,
        "risk_level": risk_level
    })

print(json.dumps(results, indent=2))

with open("output.json", "w") as f:
    json.dump(results, f, indent=2)