import json

with open("analysis_results.json") as f:
    results = json.load(f)

print(f"{'Session':<35} {'Risk':<8} {'Verdict':<35}")
print("-" * 80)
for r in results:
    print(f"{r['session_id']:<35} {r['risk_level']:<8} {r['verdict']:<35}")

print("\n" + "=" * 80)
print("DETAILED EXPLANATIONS")
print("=" * 80)
for r in results:
    print(f"\n[{r['risk_level']}] {r['session_id']}")
    print(f"  {r['explanation']}")