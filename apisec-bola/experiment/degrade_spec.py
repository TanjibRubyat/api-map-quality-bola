#!/usr/bin/env python3
"""
degrade_spec.py  -  make a damaged copy of an OpenAPI map.

Real-world API maps are often incomplete: some endpoints are missing because
developers added them to the live API but never updated the documentation.
This script imitates that by removing some object-level endpoints from a copy
of the map. The underlying API is never changed - only the map.

Usage (standalone):
  python degrade_spec.py --spec openapi.json --remove 2 --seed 1 --out bad.json
"""

import argparse
import copy
import json
import random


def object_paths(spec):
    """Object-level paths (those with an id), excluding login/me."""
    paths = []
    for path, methods in spec.get("paths", {}).items():
        if "{id}" not in path:
            continue
        if path in ("/api/login", "/api/me"):
            continue
        if "get" in methods:
            paths.append(path)
    return paths


def degrade(spec, remove_count, rng):
    """Return (damaged_spec, removed_paths). Removes `remove_count` object
    endpoints at random, keeping login/me and any non-object paths."""
    spec = copy.deepcopy(spec)
    candidates = object_paths(spec)
    remove_count = max(0, min(remove_count, len(candidates)))
    removed = rng.sample(candidates, remove_count)
    for p in removed:
        del spec["paths"][p]
    return spec, removed


def main():
    ap = argparse.ArgumentParser(description="Remove endpoints from an OpenAPI map to imitate an out-of-date map.")
    ap.add_argument("--spec", required=True)
    ap.add_argument("--remove", type=int, required=True, help="How many object endpoints to remove.")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    with open(args.spec, "r", encoding="utf-8") as f:
        spec = json.load(f)

    rng = random.Random(args.seed)
    damaged, removed = degrade(spec, args.remove, rng)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(damaged, f, indent=2)

    print(f"Removed {len(removed)} endpoint(s): {removed}")
    print(f"Damaged map written to {args.out}")


if __name__ == "__main__":
    main()
