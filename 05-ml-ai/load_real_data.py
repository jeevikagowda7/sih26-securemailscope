import pandas as pd
import json

with open("../03-tls-parser/tls_parsed_output.json") as f:
    parsed = json.load(f)

with open("../04-certs-rules/output.json") as f:
    rules_output = json.load(f)

tls_version_map = {
    "0x0301": 1.0, "0x0302": 1.1, "0x0303": 1.2, "0x0304": 1.3
}
weak_cipher_codes = ["0x0004", "0x0005"]

rows = []
for entry in parsed:
    rows.append({
        "session_id": entry.get("source_pcap", "unknown"),
        "tls_version": tls_version_map.get(entry.get("tls_version", ""), 0.0),
        "weak_cipher": entry.get("cipher_suite", "") in weak_cipher_codes,
        "starttls_used": entry.get("starttls_used_by_client", False),
        "starttls_offered": entry.get("starttls_offered_by_server", False),
        "insecure_auth": entry.get("insecure_auth", False),
        "credentials_exposed": entry.get("credentials_exposed", False),
        "encrypted": entry.get("encrypted", False),
    })

parsed_df = pd.DataFrame(rows).drop_duplicates(subset="session_id")

rules_df = pd.DataFrame(rules_output)[["session_id", "cert_valid", "risk_score", "risk_level"]].drop_duplicates(subset="session_id")

final_df = pd.merge(parsed_df, rules_df, on="session_id", how="inner")

print(final_df)
final_df.to_csv("real_data.csv", index=False)
print(f"\nSaved {len(final_df)} merged rows to real_data.csv ✅")