import pandas as pd

df = pd.read_csv("real_data.csv")

for idx, row in df.iterrows():
    print(f"\n=== {row['session_id']} ===")
    print(f"Risk Level: {row['risk_level']} (score: {row['risk_score']})")
    print(f"TLS version: {row['tls_version']}, Weak cipher: {row['weak_cipher']}, STARTTLS used: {row['starttls_used']}")