import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
import shap

FEATURE_COLS = ["tls_version", "weak_cipher", "starttls_used", "starttls_offered",
                 "insecure_auth", "credentials_exposed", "encrypted", "cert_valid"]

def prepare_features(df):
    """Takes the raw real_data.csv dataframe and converts True/False columns to 1/0."""
    features_df = df.copy()
    for col in ["weak_cipher", "starttls_used", "starttls_offered", "insecure_auth",
                "credentials_exposed", "encrypted", "cert_valid"]:
        features_df[col] = features_df[col].astype(int)
    return features_df

def train_models(df):
    """Trains the Isolation Forest and Random Forest on the given dataset.
    Returns the trained models plus the SHAP explainer, so they can be reused
    for every row instead of retraining every time."""
    features_df = prepare_features(df)
    X = features_df[FEATURE_COLS]

    iso_model = IsolationForest(contamination=0.5, random_state=42)
    iso_model.fit(X)

    y = (df["risk_level"] != "LOW").astype(int)
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X, y)

    explainer = shap.TreeExplainer(clf)

    return {
        "iso_model": iso_model,
        "clf": clf,
        "explainer": explainer,
        "X_all": X,
        "features_df": features_df,
    }

def build_explanation(row):
    """Turns rule violations into a plain-English explanation."""
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

def analyze_connection(session_id, df, models):
    """
    THE MAIN FUNCTION your teammates will call.
    Give it a session_id (e.g. "bad_capture1.pcap") plus the full dataframe
    and trained models, and it returns one clean dictionary with everything
    needed to display or report on that connection.
    """
    row = df[df["session_id"] == session_id].iloc[0]
    features_row = models["features_df"][models["features_df"]["session_id"] == session_id].iloc[0]

    row_idx = df.index[df["session_id"] == session_id][0]
    X_row = models["X_all"].loc[[row_idx]]

    ai_anomaly = models["iso_model"].predict(X_row)[0] == -1

    rule_risky = row["risk_level"] != "LOW"
    if rule_risky and ai_anomaly:
        verdict = "HIGH RISK (AI + rules agree)"
    elif rule_risky:
        verdict = "MEDIUM RISK (rules flagged, AI didn't)"
    elif ai_anomaly:
        verdict = "WATCH (AI flagged, rules didn't)"
    else:
        verdict = "SAFE"

    shap_values = np.array(models["explainer"].shap_values(X_row))
    if shap_values.ndim == 3:
        vals = shap_values[0, :, 1]
    else:
        vals = shap_values[1][0]
    shap_breakdown = dict(pd.Series(vals, index=FEATURE_COLS).sort_values(ascending=False))

    return {
        "session_id": session_id,
        "risk_score": int(row["risk_score"]),
        "risk_level": row["risk_level"],
        "ai_anomaly": bool(ai_anomaly),
        "verdict": verdict,
        "explanation": build_explanation(features_row),
        "shap_breakdown": {k: round(float(v), 4) for k, v in shap_breakdown.items()},
    }
