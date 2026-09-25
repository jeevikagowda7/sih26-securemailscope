import pandas as pd
import json
from analyzer import train_models, analyze_connection

df = pd.read_csv("real_data.csv")
models = train_models(df)

all_results = []
for session_id in df["session_id"]:
    result = analyze_connection(session_id, df, models)
    all_results.append(result)

print(json.dumps(all_results, indent=2))

# Save it as a proper report file too — this is what Safa/Varshini can load directly
with open("analysis_results.json", "w") as f:
    json.dump(all_results, f, indent=2)

print(f"\nSaved {len(all_results)} results to analysis_results.json ✅")
