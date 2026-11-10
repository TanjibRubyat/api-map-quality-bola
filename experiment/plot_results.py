#!/usr/bin/env python3
"""
plot_results.py  -  turn results/experiment_results.csv into charts for the report.

Produces three figures in results/:
  figure_main.png    2x2 summary across the three id modes (seq, spread, uuid)
  figure_spread.png  the headline result: spread ids + owndata, all five
                     dimensions, recall and precision, with 95% CI bands
  figure_biased.png  biased vs random endpoint removal

How to read every x-axis in these figures: each point is a SEPARATE TEST. A fresh
copy of the full gold specification is damaged by the stated amount and then
tested. Points are not steps of one gradual process; the line only joins them so
the trend is easy to see.

A point is left out (and the line is broken) when the metric is undefined, e.g.
precision when the tester flagged nothing at all. Drawing a value there would
show a result that was never measured.

Run after run_experiment.py:
  python plot_results.py
"""

import csv
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CSV = os.path.join(ROOT, "results", "experiment_results.csv")
sys.path.insert(0, HERE)

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError:
    sys.exit("Please install matplotlib:  pip install matplotlib")

from degrade_spec import LADDER_ORDER  # noqa: E402

# Colour-blind-safe palette (Okabe-Ito).
C = {"blue": "#0072B2", "orange": "#E69F00", "green": "#009E73",
     "vermillion": "#D55E00", "purple": "#CC79A7", "grey": "#999999",
     "sky": "#56B4E9"}

ID_MODES = (("seq", C["blue"], "o", "seq ids (always 1, 2)"),
            ("spread", C["green"], "s", "spread ids (2..20)"),
            ("uuid", C["vermillion"], "^", "uuid ids"))

# Distinct colour AND marker AND line style per dimension, so lines that lie
# exactly on top of each other are still visible as separate series.
DIMS = (("examples",   C["vermillion"], "o", "-",  8),
        ("parameters", C["green"],      "s", "-",  7),
        ("endpoint",   C["purple"],     "D", "-",  6),
        ("security",   C["blue"],       "^", "--", 9),
        ("schema",     C["orange"],     "v", ":",  7))

X_PCT = "endpoints degraded per test (% of 24)"
LADDER_TICKS = ["0\ngold"] + [f"{i + 1}\n+{d}" for i, d in enumerate(LADDER_ORDER)]


def load():
    if not os.path.exists(CSV):
        sys.exit(f"Missing {CSV}. Run run_experiment.py first.")
    with open(CSV, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def sel(rows, **f):
    return [r for r in rows if all(str(r.get(k, "")) == str(v) for k, v in f.items())]


def _num(v):
    v = str(v).strip()
    return float(v) if v != "" else math.nan


def series(rows, xkey, ykey, cast=float):
    """X/Y for one series, sorted by X. An empty metric cell becomes NaN, so
    matplotlib breaks the line there instead of joining across the gap."""
    pts = sorted(rows, key=lambda r: cast(r[xkey]))
    return [cast(r[xkey]) for r in pts], [_num(r[ykey]) for r in pts]


def band(a, rows, xkey, metric, colour, scale=1.0):
    """Shade the 95% confidence interval, where the CSV carries one."""
    lo_k, hi_k = f"{metric}_ci_lo", f"{metric}_ci_hi"
    pts = sorted((r for r in rows if str(r.get(lo_k, "")).strip() != ""),
                 key=lambda r: float(r[xkey]))
    if len(pts) < 2:
        return
    xs = [float(r[xkey]) * scale for r in pts]
    a.fill_between(xs, [float(r[lo_k]) for r in pts], [float(r[hi_k]) for r in pts],
                   color=colour, alpha=0.15, linewidth=0)


def style(a, title, xlabel, ylabel):
    a.set_title(title)
    a.set_xlabel(xlabel)
    a.set_ylabel(ylabel)
    a.set_ylim(-0.05, 1.05)
    a.grid(alpha=0.3)


def dimension_panel(a, rows, id_mode, safe_mode, metric, title, ylabel):
    for dim, col, mk, ls, ms in DIMS:
        sub = sel(rows, analysis="ofat", dimension=dim, id_mode=id_mode,
                  safe_mode=safe_mode)
        if not sub:
            continue
        band(a, sub, "fraction", metric, col, scale=100)
        x, y = series(sub, "fraction", metric)
        a.plot([v * 100 for v in x], y, linestyle=ls, marker=mk, markersize=ms,
               color=col, label=dim, markerfacecolor="none", markeredgewidth=1.6)
    style(a, title, X_PCT, ylabel)
    a.legend(fontsize=8)


def figure_main(rows):
    fig, ax = plt.subplots(2, 2, figsize=(13, 10))

    # Panel 1: losing the parameter example, by id guessability.
    a = ax[0][0]
    for idm, col, mk, lab in ID_MODES:
        sub = sel(rows, analysis="ofat", dimension="examples", id_mode=idm,
                  safe_mode="deny")
        if not sub:
            continue
        band(a, sub, "fraction", "recall", col, scale=100)
        x, y = series(sub, "fraction", "recall")
        a.plot([v * 100 for v in x], y, "-", marker=mk, color=col, label=lab)
    style(a, "Missing example id: recall vs id guessability",
          "endpoints with their example id removed, per test (% of 24)",
          "recall (share of the 12 flaws found)")
    a.legend(fontsize=8)

    # Panel 2: cumulative ladder, recall.
    a = ax[0][1]
    for idm, col, mk, lab in ID_MODES:
        sub = sel(rows, analysis="ladder", id_mode=idm, safe_mode="deny")
        if not sub:
            continue
        x, y = series(sub, "level", "recall", cast=int)
        a.plot(x, y, "-", marker=mk, color=col, label=lab)
    style(a, "Cumulative degradation (ladder), recall",
          "ladder level (each level a separate test; damage stacks on all 24)",
          "recall")
    a.set_xticks(range(len(LADDER_TICKS)))
    a.set_xticklabels(LADDER_TICKS, fontsize=8)
    a.legend(fontsize=8)

    # Panel 3: which dimension hurts recall. spread is the id mode in which the
    # dimensions separate; in seq and uuid several curves coincide exactly.
    dimension_panel(ax[1][0], rows, "spread", "deny", "recall",
                    "Which dimension hurts recall (spread ids)", "recall")

    # Panel 4: cumulative ladder, precision (owndata, where false positives occur).
    a = ax[1][1]
    for idm, col, mk, lab in ID_MODES:
        sub = sel(rows, analysis="ladder", id_mode=idm, safe_mode="owndata")
        if not sub:
            continue
        x, y = series(sub, "level", "precision", cast=int)
        a.plot(x, y, "-", marker=mk, color=col, label=lab)
    style(a, "Cumulative degradation (ladder), precision, own-data mode",
          "ladder level (missing point = nothing flagged, precision undefined)",
          "precision (share of flags that were real)")
    a.set_xticks(range(len(LADDER_TICKS)))
    a.set_xticklabels(LADDER_TICKS, fontsize=8)
    a.legend(fontsize=8)

    fig.suptitle("BOLA detection vs OpenAPI specification quality", fontsize=14)
    fig.tight_layout()
    out = os.path.join(ROOT, "results", "figure_main.png")
    fig.savefig(out, dpi=130, bbox_inches="tight")
    plt.close(fig)
    print(f"Wrote {out}")


def figure_spread(rows):
    if not sel(rows, id_mode="spread", safe_mode="owndata"):
        print("Skipped figure_spread.png: no spread/owndata rows "
              "(run with --id-modes seq,spread,uuid).")
        return
    fig, ax = plt.subplots(1, 2, figsize=(13, 5))
    dimension_panel(ax[0], rows, "spread", "owndata", "recall",
                    "Recall by dimension", "recall (share of the 12 flaws found)")
    dimension_panel(ax[1], rows, "spread", "owndata", "precision",
                    "Precision by dimension",
                    "precision (share of flags that were real)")
    fig.suptitle("All five dimensions separate: spread ids, own-data safe mode "
                 "(shaded = 95% CI)", fontsize=13)
    fig.tight_layout()
    out = os.path.join(ROOT, "results", "figure_spread.png")
    fig.savefig(out, dpi=130, bbox_inches="tight")
    plt.close(fig)
    print(f"Wrote {out}")


def figure_biased(rows):
    fig, a = plt.subplots(figsize=(6.5, 4.8))
    for biased, col, mk, lab in ((False, C["grey"], "o", "random damage (mean of 10 runs)"),
                                 (True, C["vermillion"], "s",
                                  "biased: vulnerable endpoints chosen first")):
        sub = sel(rows, analysis="biased", dimension="endpoint", id_mode="seq",
                  safe_mode="deny", biased=biased)
        if not sub:
            continue
        band(a, sub, "fraction", "recall", col, scale=100)
        x, y = series(sub, "fraction", "recall")
        a.plot([v * 100 for v in x], y, "-", marker=mk, color=col, label=lab)
    style(a, "Biased vs random map damage (endpoint removal)",
          "endpoints removed per test (% of 24)", "recall")
    a.legend(fontsize=8)
    fig.tight_layout()
    out = os.path.join(ROOT, "results", "figure_biased.png")
    fig.savefig(out, dpi=130, bbox_inches="tight")
    plt.close(fig)
    print(f"Wrote {out}")


def main():
    rows = load()
    figure_main(rows)
    figure_spread(rows)
    figure_biased(rows)


if __name__ == "__main__":
    main()
