import json

# Step 1: Read Jeevika's real output (a LIST of connections now)
with open("../03-tls-parser/tls_parsed_output.json", "r") as f:
    all_sessions = json.load(f)

# TLS version codes -> readable names
tls_version_map = {
    "0x0301": "TLSv1.0",
    "0x0302": "TLSv1.1",
    "0x0303": "TLSv1.2",
    "0x0304": "TLSv1.3"
}

# Weak cipher codes (basic starter list — expand later if needed)
weak_cipher_codes = ["0x0004", "0x0005"]  # old/broken ciphers, example placeholders

results = []

for i, data in enumerate(all_sessions):
    session_id = f"{data.get('src_ip')}->{data.get('dst_ip')}_{i}"

    tls_code = data.get("tls_version", "")
    tls_version = tls_version_map.get(tls_code, "UNKNOWN")

    cipher_code = data.get("cipher_suite", "")
    is_weak_cipher = cipher_code in weak_cipher_codes

    # NOTE: certificate_presented doesn't exist in her data yet — assuming True for now
    # ASK JEEVIKA/TEAM: should this field be added?
    cert_valid = True

    good_tls_versions = ["TLSv1.2", "TLSv1.3"]

    risk_score = 0
    if not cert_valid:
        risk_score += 50
    if tls_version not in good_tls_versions:
        risk_score += 30
    if is_weak_cipher:
        risk_score += 40

    nist_compliant = cert_valid and (tls_version in good_tls_versions) and (not is_weak_cipher)

    if risk_score == 0:
        risk_level = "LOW"
    elif risk_score <= 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"

    results.append({
        "session_id": session_id,
        "cert_valid": cert_valid,
        "nist_compliant": nist_compliant,
        "risk_score": risk_score,
        "risk_level": risk_level
    })

print(results)

with open("output.json", "w") as f:
    json.dump(results, f, indent=2)