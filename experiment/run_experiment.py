#!/usr/bin/env python3
"""
run_experiment.py  -  the main experiment.

Question: how much worse does BOLA detection get as the API map becomes
more incomplete?

Method:
  - Start from the full, correct map.
  - Remove 0, 1, 2, ... endpoints from the map (many random tries at each level).
  - Each time, run the BOLA tester and see how many real flaws it still finds.
  - Average the results and report "recall" = (flaws found) / (flaws that exist).

Output:
  - A table printed to the screen.
  - A CSV file (results/experiment_results.csv) for charts and the report.

Before running, start the target API in another terminal:
  cd target-api && npm start
"""

import argparse
import csv
import json
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "tester"))

import bola_tester as bt          # noqa: E402
from degrade_spec import degrade, object_paths  # noqa: E402


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def main():
    ap = argparse.ArgumentParser(description="Measure how map incompleteness affects BOLA detection.")
    ap.add_argument("--spec", default=os.path.join(ROOT, "target-api", "openapi.json"))
    ap.add_argument("--ground-truth", default=os.path.join(ROOT, "ground_truth.json"))
    ap.add_argument("--base-url", default="http://localhost:3000")
    ap.add_argument("--trials", type=int, default=30, help="Random maps tried per removal level.")
    ap.add_argument("--out", default=os.path.join(ROOT, "results", "experiment_results.csv"))
    args = ap.parse_args()

    full_spec = load_json(args.spec)
    gt = load_json(args.ground_truth)["endpoints"]
    true_vulnerable = {k for k, v in gt.items() if v}
    total_vuln = len(true_vulnerable)

    all_obj = object_paths(full_spec)
    n_obj = len(all_obj)

    print(f"Object endpoints in full map : {n_obj}")
    print(f"Real BOLA flaws (ground truth): {total_vuln}  -> {sorted(true_vulnerable)}\n")

    # sanity: confirm the server is reachable with the full map
    try:
        bt.scan(full_spec, args.base_url)
    except Exception as e:
        sys.exit(f"Could not reach the target API at {args.base_url}. "
                 f"Start it first (cd target-api && npm start). Error: {e}")

    rng = random.Random(42)
    rows = []
    print(f"{'removed':>7} | {'map left %':>10} | {'avg found':>9} | {'recall':>6}")
    print("-" * 44)
    for k in range(0, n_obj + 1):
        recalls, founds, maps_left = [], [], []
        for t in range(args.trials):
            damaged, removed = degrade(full_spec, k, rng)
            summary = bt.scan(damaged, args.base_url)
            detected = set(summary["detected_vulnerable"])
            found = len(detected & true_vulnerable)
            recalls.append(found / total_vuln if total_vuln else 1.0)
            founds.append(found)
            maps_left.append(summary["endpoints_in_map"])
        avg_recall = sum(recalls) / len(recalls)
        avg_found = sum(founds) / len(founds)
        avg_left = sum(maps_left) / len(maps_left)
        map_pct = 100.0 * avg_left / n_obj
        rows.append({
            "endpoints_removed": k,
            "map_completeness_pct": round(map_pct, 1),
            "avg_flaws_found": round(avg_found, 2),
            "total_flaws": total_vuln,
            "recall": round(avg_recall, 3),
        })
        print(f"{k:>7} | {map_pct:>9.1f}% | {avg_found:>9.2f} | {avg_recall:>6.2f}")

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    print(f"\nResults written to {args.out}")
    print("Use this CSV to draw the main chart: map completeness vs recall.")


if __name__ == "__main__":
    main()
