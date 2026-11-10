#!/usr/bin/env python3
"""
analyse_results.py  -  statistics over the raw per-trial data.

run_experiment.py writes two files. experiment_results.csv holds the averaged
points that the charts are drawn from. experiment_trials.csv holds every
individual run before averaging, and that is what this script reads, because a
trend test needs the spread of the data and not just its mean.

It reports two things.

1. TREND. For each quality dimension, a Spearman rank correlation between the
   fraction of endpoints degraded and the recall achieved. Spearman is used
   rather than Pearson because the relationship is not assumed to be a straight
   line, only monotonic. rho near -1 means recall falls steadily as damage
   rises; rho near 0 means the dimension does not move recall at all.

2. SEPARABILITY. For each pair of dimensions, the largest gap between their mean
   curves, measured on recall AND on precision. This is the direct test of
   whether the experiment can tell two dimensions apart. A pair is only
   indistinguishable when both gaps are 0.000, because a dimension can leave
   recall untouched and still move precision.

Run after run_experiment.py:
  python analyse_results.py
"""

import csv
import itertools
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TRIALS_CSV = os.path.join(ROOT, "results", "experiment_trials.csv")

try:
    from scipy.stats import spearmanr
except ImportError:
    spearmanr = None


def load(path):
    if not os.path.exists(path):
        sys.exit(f"Missing {path}. Run run_experiment.py first.")
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def ofat(rows, id_mode, safe_mode, dimension, metric="recall"):
    """Every individual trial for one dimension, as (fraction, metric) pairs."""
    out = []
    for r in rows:
        if (r["analysis"] == "ofat" and r["id_mode"] == id_mode
                and r["safe_mode"] == safe_mode and r["dimension"] == dimension
                and str(r[metric]).strip() != ""):
            out.append((float(r["fraction"]), float(r[metric])))
    return sorted(out)


def mean_curve(points):
    """Mean recall at each fraction, as {fraction: mean_recall}."""
    buckets = {}
    for frac, rec in points:
        buckets.setdefault(frac, []).append(rec)
    return {f: sum(v) / len(v) for f, v in buckets.items()}


def main():
    rows = load(TRIALS_CSV)
    dims = []
    for r in rows:
        if r["analysis"] == "ofat" and r["dimension"] not in dims:
            dims.append(r["dimension"])
    id_modes = sorted({r["id_mode"] for r in rows})
    safe_modes = sorted({r["safe_mode"] for r in rows})

    for id_mode in id_modes:
        for safe_mode in safe_modes:
            print(f"\n=== id_mode={id_mode}  safe_mode={safe_mode} ===")

            print("\n  TREND  (Spearman, fraction degraded vs recall)")
            print(f"  {'dimension':12}{'n':>5}{'rho':>9}{'p':>12}   interpretation")
            curves = {}
            for d in dims:
                pts = ofat(rows, id_mode, safe_mode, d)
                if not pts:
                    continue
                curves[d] = mean_curve(pts)
                xs = [p[0] for p in pts]
                ys = [p[1] for p in pts]
                if spearmanr is None:
                    print(f"  {d:12}{len(pts):>5}{'n/a':>9}{'n/a':>12}   scipy not installed")
                    continue
                if len(set(ys)) < 2:
                    print(f"  {d:12}{len(pts):>5}{'—':>9}{'—':>12}   recall never changes")
                    continue
                rho, p = spearmanr(xs, ys)
                note = ("falls with damage" if rho < -0.3 else
                        "rises with damage" if rho > 0.3 else "no clear trend")
                print(f"  {d:12}{len(pts):>5}{rho:>9.3f}{p:>12.2e}   {note}")

            # A dimension may leave recall untouched and still move precision
            # (losing the response schema costs the tester its way of confirming
            # ownership, not its way of reaching the endpoint). Comparing recall
            # alone therefore reports such pairs as identical when they are not.
            pcurves = {}
            for d in dims:
                pts = ofat(rows, id_mode, safe_mode, d, metric="precision")
                if pts:
                    pcurves[d] = mean_curve(pts)

            print("\n  SEPARABILITY  (largest gap between mean curves)")
            print(f"  {'pair':29}{'recall':>9}{'precision':>12}")
            identical = []
            for a, b in itertools.combinations(sorted(curves), 2):
                shared = sorted(set(curves[a]) & set(curves[b]))
                if not shared:
                    continue
                rgap = max(abs(curves[a][f] - curves[b][f]) for f in shared)
                pgap = 0.0
                if a in pcurves and b in pcurves:
                    pshared = sorted(set(pcurves[a]) & set(pcurves[b]))
                    if pshared:
                        pgap = max(abs(pcurves[a][f] - pcurves[b][f]) for f in pshared)
                both_flat = rgap < 1e-9 and pgap < 1e-9
                flag = "  <-- INDISTINGUISHABLE" if both_flat else ""
                print(f"  {a:12} vs {b:12}{rgap:>9.3f}{pgap:>12.3f}{flag}")
                if both_flat:
                    identical.append((a, b))
            if identical:
                print(f"\n  {len(identical)} pair(s) are identical on BOTH recall and "
                      f"precision; the experiment cannot rank those dimensions.")
            else:
                print("\n  All dimension pairs are separable on recall, precision, "
                      "or both.")


if __name__ == "__main__":
    main()
