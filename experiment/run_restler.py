"""Extension C: run Microsoft RESTler's namespace checker on degraded specifications.

RESTler sends each request as a victim user (bob) and replays it as an attacker
(alice). It reports a bug when the attacker gets any 2xx reply. This script runs
it on the same degraded specifications as the main experiment and scores the
result against the testbed's ground truth.

Conditions per id mode and safe mode (all deterministic, so each runs once):
  - the complete specification
  - each dimension removed from all 24 object endpoints
  - ladder levels 1 to 5

Requirements: Docker running, and the RESTler image built as "restler":
    git clone https://github.com/microsoft/restler-fuzzer.git
    cd restler-fuzzer && docker build -t restler .

Run from the project folder:
    python experiment/run_restler.py
Results: results/extension/restler_results.csv
"""
import argparse
import csv
import glob
import json
import os
import random
import re
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
API_DIR = os.path.join(ROOT, "target-api")
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "tester"))

from degrade_spec import degrade, ladder, object_paths, DIMENSIONS  # noqa: E402
from run_experiment import load_json, wait_for_health, regen_spec, stop_server, score  # noqa: E402

TOKENS_PY = '''print("{'app1': {}, 'app2': {}}")
print("Authorization: Bearer token-bob")
print("Authorization: Bearer token-alice")
'''
SETTINGS = {"checkers": {"namespacerule": {"trigger_on_dynamic_objects": True,
                                           "trigger_objects": ["/api/"]}}}
BUG_LINE = re.compile(r"GET (/api/[A-Za-z0-9_-]+)/[^\s\\]+ HTTP")


def start_server(id_mode, safe_mode, port):
    env = dict(os.environ, ID_MODE=id_mode, SAFE_MODE=safe_mode, PORT=str(port))
    kwargs = {}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    return subprocess.Popen(["node", "server.js"], cwd=API_DIR, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kwargs)


def run_restler(spec, workdir, image, port):
    """Run RESTler compile + fuzz-lean with the namespace checker on one spec.
    Returns (flagged endpoint keys, error message or "")."""
    if os.path.isdir(workdir):
        shutil.rmtree(workdir)
    os.makedirs(workdir)
    with open(os.path.join(workdir, "openapi.json"), "w", encoding="utf-8") as f:
        json.dump(spec, f, indent=2)
    with open(os.path.join(workdir, "tokens.py"), "w", encoding="utf-8") as f:
        f.write(TOKENS_PY)
    with open(os.path.join(workdir, "settings.json"), "w", encoding="utf-8") as f:
        json.dump(SETTINGS, f, indent=2)
    if not object_paths(spec):
        return set(), "no object endpoints in the specification"
    cmd = ("dotnet /RESTler/restler/Restler.dll compile --api_spec /work/openapi.json && "
           "dotnet /RESTler/restler/Restler.dll fuzz-lean --grammar_file /work/Compile/grammar.py "
           "--dictionary_file /work/Compile/dict.json --settings /work/settings.json "
           "--enable_checkers namespacerule --no_ssl --host host.docker.internal "
           f"--target_port {port} --token_refresh_command 'python3 /work/tokens.py' "
           "--token_refresh_interval 3600")
    proc = subprocess.run(["docker", "run", "--rm", "-v", f"{os.path.abspath(workdir)}:/work",
                           "-w", "/work", image, "sh", "-c", cmd],
                          capture_output=True, text=True)
    with open(os.path.join(workdir, "restler_output.txt"), "w", encoding="utf-8") as f:
        f.write(proc.stdout + "\n" + proc.stderr)
    flagged = set()
    for path in glob.glob(os.path.join(workdir, "**", "bug_buckets.txt"), recursive=True):
        text = open(path, encoding="utf-8", errors="replace").read()
        for m in BUG_LINE.finditer(text):
            flagged.add(f"GET {m.group(1)}/{{id}}")
    error = "" if proc.returncode == 0 else f"RESTler exit code {proc.returncode}"
    return flagged, error


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--id-modes", default="seq,spread,uuid")
    ap.add_argument("--safe-modes", default="deny,owndata")
    ap.add_argument("--port", type=int, default=3001)
    ap.add_argument("--image", default="restler")
    ap.add_argument("--out", default=os.path.join(ROOT, "results", "extension", "restler_results.csv"))
    ap.add_argument("--workdir", default=os.path.join(ROOT, "restler_runs"))
    args = ap.parse_args()

    truth = load_json(os.path.join(ROOT, "ground_truth.json"))["endpoints"]
    vuln = {k for k, v in truth.items() if v}
    n_endpoints = len(truth)
    base_url = f"http://localhost:{args.port}"
    rows = []
    os.makedirs(os.path.dirname(args.out), exist_ok=True)

    for id_mode in args.id_modes.split(","):
        regen_spec(id_mode)
        gold = load_json(os.path.join(API_DIR, "openapi.json"))
        conditions = [("baseline", "", 0, gold)]
        for dim in DIMENSIONS:
            spec, _ = degrade(gold, dim, 1.0, random.Random(0))
            conditions.append(("full_removal", dim, 1.0, spec))
        for level in range(1, 6):
            conditions.append(("ladder", "", level, ladder(gold, level)))
        for safe_mode in args.safe_modes.split(","):
            server = start_server(id_mode, safe_mode, args.port)
            try:
                if not wait_for_health(base_url):
                    sys.exit(f"testbed did not start on port {args.port}")
                for analysis, dim, level, spec in conditions:
                    name = f"{id_mode}_{safe_mode}_{analysis}_{dim or level}"
                    t0 = time.time()
                    flagged, error = run_restler(spec, os.path.join(args.workdir, name),
                                                 args.image, args.port)
                    flagged &= set(truth)  # score object endpoints only
                    documented = {f"GET {p}" for p in object_paths(spec)}
                    summary = {"detected_vulnerable": sorted(flagged),
                               "tested_endpoints": sorted(documented)}
                    recall, precision, fp, coverage = score(summary, vuln, n_endpoints)
                    rows.append({"id_mode": id_mode, "safe_mode": safe_mode, "analysis": analysis,
                                 "dimension": dim, "level": level, "tp": len(flagged & vuln),
                                 "fp": fp, "recall": round(recall, 3),
                                 "precision": "" if precision is None else round(precision, 3),
                                 "coverage": round(coverage, 3),
                                 "flagged": ";".join(sorted(flagged)), "error": error,
                                 "seconds": round(time.time() - t0, 1)})
                    print(f"{name:45} recall={recall:.3f} precision={rows[-1]['precision']!s:5} "
                          f"fp={fp} {error}", flush=True)
                    with open(args.out, "w", newline="", encoding="utf-8") as f:
                        w = csv.DictWriter(f, fieldnames=list(rows[0]))
                        w.writeheader()
                        w.writerows(rows)
            finally:
                stop_server(server)
    regen_spec("seq")
    print(f"\nWrote {len(rows)} rows to {args.out}")


if __name__ == "__main__":
    main()
