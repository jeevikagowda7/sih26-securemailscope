import pandas as pd
import json

# Load Jeevika's raw parsed details (richer: tls_version, cipher_suite, encrypted)
with open("../03-tls-parser/tls_parsed_output.json") as f:
    parsed = json.load(f)

# Load Krithiksha's calculated risk verdicts
with open("../04-certs-rules/output.json") as f:
    rules_output = json.load(f)

tls_version_map = {
    "0x0301": 1.0, "0x0302": 1.1, "0x0303": 1.2, "0x0304": 1.3
}
weak_cipher_codes = ["0x0004", "0x0005"]

rows = []
for entry in parsed:
    session_id = entry.get("source_file", "unknown")
    encrypted = entry.get("encrypted", False)
    tls_code = entry.get("tls_version", "")
    cipher_code = entry.get("cipher_suite", "")

    rows.append({
        "session_id": session_id,
        "tls_version": tls_version_map.get(tls_code, 0.0),  # 0.0 = unknown/none
        "weak_cipher": cipher_code in weak_cipher_codes,
        "starttls_used": encrypted,
    })

parsed_df = pd.DataFrame(rows).drop_duplicates()

rules_df = pd.DataFrame(rules_output)[["session_id", "cert_valid", "risk_score", "risk_level"]].drop_duplicates()

# Merge both on session_id
final_df = pd.merge(parsed_df, rules_df, on="session_id", how="inner")

print(final_df)
final_df.to_csv("real_data.csv", index=False)
print(f"\nSaved {len(final_df)} merged rows to real_data.csv ✅")