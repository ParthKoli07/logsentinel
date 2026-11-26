"""Quick manual look at precision/recall/F1 across rules, ML, and hybrid,
plus incident-level recall and the extra value hybrid adds over rules."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from logsentinel.evaluation import run_full_evaluation_with_incidents
from logsentinel.generator import generate_dataset_with_incidents

lines, incidents = generate_dataset_with_incidents(normal_count=100, seed=42)
results = run_full_evaluation_with_incidents(lines, incidents)

print(f"ML threshold used: {results['ml_threshold']}")
print(f"Parsed lines: {results['parsed_lines']}, malformed: {results['malformed_lines']}")
print()

print("--- Rules (per attack type) ---")
for attack, m in results["rules"].items():
    print(
        f"{attack:17s} P={m.precision:.2f} R={m.recall:.2f} F1={m.f1:.2f} "
        f"TP={m.true_positives} FP={m.false_positives} FN={m.false_negatives}"
    )

rc = results["rules_combined"]
print(
    f"{'rules (combined)':17s} P={rc.precision:.2f} R={rc.recall:.2f} F1={rc.f1:.2f} "
    f"TP={rc.true_positives} FP={rc.false_positives} FN={rc.false_negatives}"
)

ml = results["ml"]
print(
    f"{'ml':17s} P={ml.precision:.2f} R={ml.recall:.2f} F1={ml.f1:.2f} "
    f"TP={ml.true_positives} FP={ml.false_positives} FN={ml.false_negatives}"
)

hy = results["hybrid"]
print(
    f"{'hybrid':17s} P={hy.precision:.2f} R={hy.recall:.2f} F1={hy.f1:.2f} "
    f"TP={hy.true_positives} FP={hy.false_positives} FN={hy.false_negatives}"
)

print()
print("--- Hybrid's added value over rules-combined ---")
print(f"extra attacker IPs caught: {hy.true_positives - rc.true_positives}")
print(f"extra benign IPs flagged:  {hy.false_positives - rc.false_positives}")

print()
print("--- Incident-level recall (did we catch each SPECIFIC incident?) ---")
for approach, info in results["incidents"].items():
    print(
        f"{approach:17s} {info['incidents_caught']}/{info['incidents_total']} "
        f"caught (recall={info['incident_recall']:.2f})"
    )
