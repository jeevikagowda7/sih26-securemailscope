import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
import shap

df = pd.read_csv("real_data.csv")
print("Loaded real data:")
print(df)

# --- Prepare numeric features for the models ---
features_df = df.copy()
for col in ["weak_cipher", "starttls_used", "starttls_offered", "insecure_auth", "credentials_exposed", "encrypted", "cert_valid"]:
    features_df[col] = features_df[col].astype(int)

feature_cols = ["tls_version", "weak_cipher", "starttls_used", "starttls_offered",
                 "insecure_auth", "credentials_exposed", "encrypted", "cert_valid"]
X = features_df[feature_cols]

# --- 1. Anomaly detection (Isolation Forest) ---
iso_model = IsolationForest(contamination=0.5, random_state=42)
df["ai_anomaly"] = iso_model.fit_predict(X) == -1

# --- 2. Rule-based verdict (already computed by Krithiksha: risk_level) ---

# --- 3. Combined verdict ---
def combined_verdict(row):
    rule_risky = row["risk_level"] != "LOW"
    if rule_risky and row["ai_anomaly"]:
        return "HIGH RISK (AI + rules agree)"
    elif rule_risky:
        return "MEDIUM RISK (rules flagged, AI didn't)"
    elif row["ai_anomaly"]:
        return "WATCH (AI flagged, rules didn't)"
    else:
        return "SAFE"

df["final_verdict"] = df.apply(combined_verdict, axis=1)

print("\n=== Combined Risk Report ===")
print(df[["session_id", "risk_level", "ai_anomaly", "final_verdict"]])

# --- 4. Plain-English fix suggestions ---
def build_explanation(row):
    if row["risk_level"] == "LOW":
        return "No issues detected."
    issues = []
    if row["credentials_exposed"]:
        issues.append("Login credentials were sent in plaintext — enforce STARTTLS/TLS before allowing authentication.")
    if row["insecure_auth"]:
        issues.append("Insecure authentication method used (e.g. AUTH PLAIN/LOGIN without encryption).")
    if not row["starttls_offered"]:
        issues.append("Server never offered STARTTLS — enable STARTTLS support on the mail server.")
    if not row["starttls_used"] and row["starttls_offered"]:
        issues.append("Server offered STARTTLS but client didn't use it — possible downgrade issue.")
    if row["tls_version"] < 1.2 and row["tls_version"] > 0:
        issues.append("Outdated TLS version — upgrade to TLS 1.2 or higher.")
    if not row["cert_valid"]:
        issues.append("Certificate issue detected — renew/reissue from a trusted CA.")
    return " | ".join(issues) if issues else row.get("reason", "Flagged, reason unclear.")

df["explanation"] = features_df.apply(build_explanation, axis=1)

print("\n=== Explanations ===")
for _, row in df.iterrows():
    print(f"\n{row['session_id']}: {row['final_verdict']}")
    print(f"  -> {row['explanation']}")

# --- 5. Train a classifier ---
y = (df["risk_level"] != "LOW").astype(int)

clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X, y)

print("\n=== Feature importance (trained on real data) ===")
importances = pd.Series(clf.feature_importances_, index=feature_cols)
print(importances.sort_values(ascending=False))

# --- 6. SHAP explanation for one risky real session ---
explainer = shap.TreeExplainer(clf)
shap_values = np.array(explainer.shap_values(X))

risky_idx = df.index[df["risk_level"] != "LOW"]
target_idx = risky_idx[0] if len(risky_idx) > 0 else 0
print(f"\n=== SHAP explanation for: {df.loc[target_idx, 'session_id']} ===")
if shap_values.ndim == 3:
    vals = shap_values[target_idx, :, 1]
else:
    vals = shap_values[1][target_idx]
print(pd.Series(vals, index=feature_cols).sort_values(ascending=False))