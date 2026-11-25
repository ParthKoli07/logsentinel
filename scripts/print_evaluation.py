"""Quick manual look at precision/recall/F1 across rules, ML, and hybrid."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from logsentinel.evaluation import run_full_evaluation
from logsentinel.generator import generate_dataset

lines = generate_dataset(normal_count=100, seed=42)
results = run_full_evaluation(lines)

print(f"Parsed lines: {results['parsed_lines']}, malformed: {results['malformed_lines']}")
print()

print("--- Rules (per attack type) ---")
for attack, m in results["rules"].items():
    print(f"{attack:15s} P={m.precision:.2f} R={m.recall:.2f} F1={m.f1:.2f}")

print("--- ML (any anomaly, trained on independent baseline) ---")
m = results["ml"]
print(f"{'ml':15s} P={m.precision:.2f} R={m.recall:.2f} F1={m.f1:.2f}")

print("--- Hybrid (rules OR ML) ---")
m = results["hybrid"]
print(f"{'hybrid':15s} P={m.precision:.2f} R={m.recall:.2f} F1={m.f1:.2f}")
