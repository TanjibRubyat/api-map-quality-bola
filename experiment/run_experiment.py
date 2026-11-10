#!/usr/bin/env python3
"""
run_experiment.py  -  the main experiment (v3).

Question: how much worse does BOLA detection get as the API map loses QUALITY,
which pieces of quality matter, and does it depend on the API (guessable vs
unguessable ids, and how safe endpoints behave)?

For each configuration (id mode x safe mode) it:
  - starts the target API with that configuration,
  - regenerates the matching gold map,
  - runs three analyses:
      ladder  : cumulative quality loss L0..L5 applied to ALL endpoints.
      ofat    : one dimension at a time, over a fraction sweep (0..1).
      biased  : endpoint/examples loss aimed preferentially at vulnerable
                endpoints, to test whether a "cliff" appears.
  - scores each run against ground truth: recall, precision, false positives,
    coverage.

Output: results/experiment_results.csv (one row per measured point).

Nothing needs to be running beforehand - this script starts and stops the API
itself.
"""

import argparse
import atexit
import csv
import json
import math
import os
import random
import signal
import statistics
import subprocess
import sys
import time

import urllib.request

try:                                    # exact t-based intervals when available
    from scipy.stats import t as _t_dist

    def _crit(n):
        return float(_t_dist.ppf(0.975, n - 1))
except ImportError:                     # fall back to the normal approximation
    def _crit(n):
        return 1.96

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
API_DIR = os.path.join(ROOT, "target-api")

# The id mode the repository should be left in once a run finishes. It matches
# the default in target-api/src/config/resources.js.
DEFAULT_ID_MODE = "seq"
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "tester"))

import bola_tester as bt                                      # noqa: E402
from degrade_spec import degrade, ladder, object_paths, DIMENSIONS  # noqa: E402


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def wait_for_health(base_url, timeout=20):
    url = f"{base_url}/api/login"
    body = json.dumps({"username": "alice", "password": "alice123"}).encode()
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            req = urllib.request.Request(url, data=body,
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=2) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.3)
    return False


def regen_spec(id_mode):
    env = dict(os.environ, ID_MODE=id_mode)
    subprocess.run(["node", "scripts/gen_meta.js"], cwd=API_DIR, env=env,
                   check=True, stdout=subprocess.DEVNULL)


def start_server(id_mode, safe_mode):
    env = dict(os.environ, ID_MODE=id_mode, SAFE_MODE=safe_mode)
    return subprocess.Popen(["node", "server.js"], cwd=API_DIR, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)


def stop_server(proc):
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except Exception:
        proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        pass


def score(summary, vuln, n_endpoints):
    det = set(summary["detected_vulnerable"])
    tp = len(det & vuln)
    fp = len(det - vuln)
    tested = set(summary["tested_endpoints"])
    recall = tp / len(vuln) if vuln else 1.0
    # Precision is UNDEFINED when the tester flagged nothing at all (tp+fp == 0).
    # Reporting 1.0 there would claim perfect precision for a run that made no
    # prediction, which inflates precision exactly in the collapsed conditions.
    # None is written to the CSV as an empty cell and skipped by the plots.
    precision = tp / (tp + fp) if (tp + fp) else None
    coverage = len(tested) / n_endpoints if n_endpoints else 0.0
    return recall, precision, fp, coverage


def avg(xs):
    return sum(xs) / len(xs) if xs else 0.0


def avg_defined(xs):
    """Mean of the defined values, or None if every value is undefined."""
    vals = [x for x in xs if x is not None]
    return (sum(vals) / len(vals)) if vals else None


def fmt(x, nd=3):
    """Round for the CSV, or an empty cell when the metric is undefined."""
    return round(x, nd) if x is not None else ""


def summarise(xs):
    """(mean, sd, ci_low, ci_high) over the DEFINED values in xs.

    Undefined values (None) are dropped rather than counted as 0 or 1, so a
    condition in which the tester flagged nothing contributes no false score.
    Returns all-None when nothing is defined. The interval is the 95% CI of the
    mean, using the t distribution when scipy is present."""
    vals = [x for x in xs if x is not None]
    if not vals:
        return None, None, None, None
    n = len(vals)
    mean = sum(vals) / n
    if n < 2:
        return mean, 0.0, mean, mean
    sd = statistics.stdev(vals)
    if sd == 0.0:
        return mean, 0.0, mean, mean
    half = _crit(n) * sd / math.sqrt(n)
    return mean, sd, mean - half, mean + half


def is_deterministic(fraction):
    """At 0% nothing is damaged and at 100% everything is, so the random choice
    has no effect. Repeating trials there just averages identical runs and
    inflates the apparent sample size."""
    return fraction <= 0.0 or fraction >= 1.0


def main():
    ap = argparse.ArgumentParser(description="Measure how map quality affects BOLA detection.")
    ap.add_argument("--base-url", default="http://localhost:3000")
    ap.add_argument("--trials", type=int, default=10, help="Random maps per fraction point.")
    ap.add_argument("--id-modes", default="seq,spread,uuid")
    ap.add_argument("--safe-modes", default="deny,owndata")
    ap.add_argument("--fractions", default="0,0.25,0.5,0.75,1.0")
    ap.add_argument("--out", default=os.path.join(ROOT, "results", "experiment_results.csv"))
    args = ap.parse_args()

    id_modes = [x.strip() for x in args.id_modes.split(",") if x.strip()]
    safe_modes = [x.strip() for x in args.safe_modes.split(",") if x.strip()]
    fractions = [float(x) for x in args.fractions.split(",") if x.strip()]

    # Each id mode regenerates openapi.json and ground_truth.json, so without
    # this the files are left in whichever mode happened to run last, and the
    # repository state depends on the loop order. Registered with atexit so it
    # also runs if the experiment aborts partway.
    atexit.register(regen_spec, DEFAULT_ID_MODE)

    rows = []
    trial_rows = []          # one row per individual run, before any averaging
    for id_mode in id_modes:
        regen_spec(id_mode)
        gold = load_json(os.path.join(API_DIR, "openapi.json"))
        gt = load_json(os.path.join(ROOT, "ground_truth.json"))["endpoints"]
        vuln = {k for k, v in gt.items() if v}
        n_obj = len(object_paths(gold))

        for safe_mode in safe_modes:
            proc = start_server(id_mode, safe_mode)
            if not wait_for_health(args.base_url):
                stop_server(proc)
                sys.exit(f"API did not start for id_mode={id_mode} safe_mode={safe_mode}")
            print(f"\n=== id_mode={id_mode}  safe_mode={safe_mode} "
                  f"(endpoints={n_obj}, vulnerable={len(vuln)}) ===")

            # --- Analysis 1: cumulative ladder (deterministic) ---
            for level in range(0, 6):
                s = bt.scan(ladder(gold, level), args.base_url)
                r, p, fp, cov = score(s, vuln, n_obj)
                rows.append(dict(id_mode=id_mode, safe_mode=safe_mode, analysis="ladder",
                                 dimension="cumulative", level=level, fraction="",
                                 biased="", trials=1, recall=round(r, 3),
                                 precision=fmt(p), false_positives=fp,
                                 coverage=round(cov, 3)))
            print("  ladder done")

            # --- Analysis 2: one dimension at a time, fraction sweep ---
            for dim in DIMENSIONS:
                for frac in fractions:
                    n_trials = 1 if is_deterministic(frac) else args.trials
                    rs, ps, fps, cvs = [], [], [], []
                    for t in range(n_trials):
                        spec, _ = degrade(gold, dim, frac, random.Random(t))
                        s = bt.scan(spec, args.base_url)
                        r, p, fp, cov = score(s, vuln, n_obj)
                        rs.append(r); ps.append(p); fps.append(fp); cvs.append(cov)
                        trial_rows.append(dict(
                            id_mode=id_mode, safe_mode=safe_mode, analysis="ofat",
                            dimension=dim, level="", fraction=frac, biased="",
                            trial=t, seed=t, recall=round(r, 4), precision=fmt(p, 4),
                            false_positives=fp, coverage=round(cov, 4)))
                    r_mean, r_sd, r_lo, r_hi = summarise(rs)
                    p_mean, p_sd, p_lo, p_hi = summarise(ps)
                    rows.append(dict(id_mode=id_mode, safe_mode=safe_mode, analysis="ofat",
                                     dimension=dim, level="", fraction=frac, biased="",
                                     trials=n_trials, recall=fmt(r_mean),
                                     recall_sd=fmt(r_sd), recall_ci_lo=fmt(r_lo),
                                     recall_ci_hi=fmt(r_hi),
                                     precision=fmt(p_mean), precision_sd=fmt(p_sd),
                                     precision_ci_lo=fmt(p_lo), precision_ci_hi=fmt(p_hi),
                                     false_positives=round(avg(fps), 2),
                                     coverage=round(avg(cvs), 3)))
                print(f"  ofat {dim} done")

            # --- Analysis 3: biased vs random damage (recall-driving dims) ---
            for dim in ("endpoint", "examples"):
                for biased in (False, True):
                    for frac in fractions:
                        n_trials = 1 if is_deterministic(frac) else args.trials
                        rs = []
                        for t in range(n_trials):
                            spec, _ = degrade(gold, dim, frac, random.Random(t),
                                              vulnerable_set=vuln, biased=biased)
                            s = bt.scan(spec, args.base_url)
                            r, _, _, _ = score(s, vuln, n_obj)
                            rs.append(r)
                            trial_rows.append(dict(
                                id_mode=id_mode, safe_mode=safe_mode, analysis="biased",
                                dimension=dim, level="", fraction=frac, biased=biased,
                                trial=t, seed=t, recall=round(r, 4), precision="",
                                false_positives="", coverage=""))
                        r_mean, r_sd, r_lo, r_hi = summarise(rs)
                        rows.append(dict(id_mode=id_mode, safe_mode=safe_mode,
                                         analysis="biased", dimension=dim, level="",
                                         fraction=frac, biased=biased, trials=n_trials,
                                         recall=fmt(r_mean), recall_sd=fmt(r_sd),
                                         recall_ci_lo=fmt(r_lo), recall_ci_hi=fmt(r_hi),
                                         precision="", false_positives="", coverage=""))
                print(f"  biased {dim} done")

            stop_server(proc)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    fields = ["id_mode", "safe_mode", "analysis", "dimension", "level", "fraction",
              "biased", "trials",
              "recall", "recall_sd", "recall_ci_lo", "recall_ci_hi",
              "precision", "precision_sd", "precision_ci_lo", "precision_ci_hi",
              "false_positives", "coverage"]
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, restval="")
        w.writeheader()
        w.writerows(rows)
    print(f"\nWrote {len(rows)} summary rows to {args.out}")

    # The raw per-trial data, before averaging. Keeping it means any later
    # analysis (trend tests, different intervals, re-plots) can be done without
    # re-running the whole experiment.
    trials_out = os.path.join(os.path.dirname(args.out), "experiment_trials.csv")
    tfields = ["id_mode", "safe_mode", "analysis", "dimension", "level", "fraction",
               "biased", "trial", "seed", "recall", "precision", "false_positives",
               "coverage"]
    with open(trials_out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=tfields, restval="")
        w.writeheader()
        w.writerows(trial_rows)
    print(f"Wrote {len(trial_rows)} per-trial rows to {trials_out}")


if __name__ == "__main__":
    main()
