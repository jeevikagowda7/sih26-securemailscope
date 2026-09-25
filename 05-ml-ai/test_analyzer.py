import pandas as pd
from analyzer import train_models, analyze_connection

df = pd.read_csv("real_data.csv")
models = train_models(df)

# Try it on one specific session
result = analyze_connection("bad_capture1.pcap", df, models)

import json
print(json.dumps(result, indent=2))