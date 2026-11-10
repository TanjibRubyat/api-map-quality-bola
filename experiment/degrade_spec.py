#!/usr/bin/env python3
"""
degrade_spec.py  -  make a damaged copy of an OpenAPI map.

v3: the map is degraded by removing QUALITY from endpoints that stay listed,
not only by hiding whole endpoints. Real maps are usually present but
incomplete: they lack examples, response schemas, parameter docs or security
info. Each of these is a separate "quality dimension" we can remove.

Quality dimensions (each can be removed on its own):

  examples   : remove the example id on the parameter AND the example object in
               the response. A tester then has no sample id to try, so it must
               guess. Guessing works for small integer ids and fails for uuids.
  schema     : remove the response body schema (the object's field list). A
               tester can no longer learn which field names identify the owner,
               so it cannot confirm whether a 200 really leaked another user's
               object.
  security   : remove the security requirement and (optionally) the scheme. A
               spec-driven tester then does not know it must authenticate, so
               its requests are rejected (401) and the endpoint is not tested.
  parameters : remove the parameter list. A tester no longer knows there is an
               id to manipulate, so it cannot perform the BOLA test.
  endpoint   : remove the whole endpoint (the v2 "remove" damage). The most
               destructive case: the endpoint is invisible, so it is never
               tested.

The underlying API is NEVER changed - only the map.

Usage (standalone):
  python degrade_spec.py --spec openapi.json --dimension examples \\
      --fraction 0.5 --seed 1 --out bad.json
"""

import argparse
import copy
import json
import random
import re

DIMENSIONS = ("examples", "schema", "security", "parameters", "endpoint")

# The order used by the cumulative "ladder" (least to most destructive).
LADDER_ORDER = ("examples", "schema", "security", "parameters", "endpoint")


def object_paths(spec):
    """Object-level paths (those with an id placeholder), excluding login/me.
    Any placeholder name counts, so a real specification using "{userId}" is
    picked up as well as this testbed's "{id}"."""
    paths = []
    for path, methods in spec.get("paths", {}).items():
        if not re.search(r"\{[^}]+\}", path):
            continue
        if path in ("/api/login", "/api/me"):
            continue
        if "get" in methods:
            paths.append(path)
    return paths


def _op(spec, path):
    return spec["paths"][path]["get"]


def _strip_examples(op):
    """Remove the PARAMETER example(s) only.

    This dimension models losing the sample id a tester would try. The response
    example belongs to the `schema` dimension, because it is a second route to
    the same information the response schema carries (the field list, and so the
    owner field). Stripping it here as well made the two dimensions overlap.
    """
    for p in op.get("parameters", []) or []:
        p.pop("example", None)
        if isinstance(p.get("schema"), dict):
            p["schema"].pop("example", None)


def _strip_schema(op):
    """Remove everything that describes the response BODY.

    Both the response schema and the response example name the fields of the
    returned object, and bola_tester._owner_field_known() accepts either one as
    proof that it can identify the owner. Removing only the schema therefore
    left the example behind and the tester could still confirm ownership, so
    this dimension had no measurable effect. Both are removed together.
    """
    for resp in op.get("responses", {}).values():
        for mt in (resp.get("content", {}) or {}).values():
            mt.pop("schema", None)
            mt.pop("example", None)
            mt.pop("examples", None)


def _strip_security(op):
    """Remove the security requirement from this operation."""
    op.pop("security", None)


def _strip_parameters(op):
    """Remove the parameter list (so the id is no longer documented)."""
    op.pop("parameters", None)


def _apply_dimension(spec, path, dimension):
    """Apply one dimension's removal to a single endpoint, in place."""
    if dimension == "endpoint":
        del spec["paths"][path]
        return
    op = _op(spec, path)
    if dimension == "examples":
        _strip_examples(op)
    elif dimension == "schema":
        _strip_schema(op)
    elif dimension == "security":
        _strip_security(op)
    elif dimension == "parameters":
        _strip_parameters(op)
    else:
        raise ValueError(f"unknown dimension: {dimension}")


def _choose(paths, count, rng, vulnerable_set=None, biased=False):
    """Choose `count` paths to damage. If biased, prefer vulnerable endpoints."""
    count = max(0, min(count, len(paths)))
    if not biased or not vulnerable_set:
        return rng.sample(paths, count)
    # Biased: damage vulnerable endpoints first, then safe ones, shuffled within
    # each group so the choice is still reproducible but correlated with risk.
    vuln = [p for p in paths if f"GET {p}" in vulnerable_set]
    safe = [p for p in paths if f"GET {p}" not in vulnerable_set]
    rng.shuffle(vuln)
    rng.shuffle(safe)
    ordered = vuln + safe
    return ordered[:count]


def degrade(spec, dimension, fraction, rng, vulnerable_set=None, biased=False):
    """Return (damaged_spec, damaged_paths): apply `dimension` to `fraction` of
    the object endpoints, chosen (optionally biased toward vulnerable ones)."""
    spec = copy.deepcopy(spec)
    candidates = object_paths(spec)
    count = round(fraction * len(candidates))
    chosen = _choose(candidates, count, rng, vulnerable_set, biased)
    for p in chosen:
        _apply_dimension(spec, p, dimension)
    return spec, chosen


def ladder(spec, level):
    """Return a copy of the spec degraded to a cumulative LEVEL (0..5), applied
    to ALL object endpoints. Level 0 is the gold map; each level removes one
    more quality dimension from every endpoint, in LADDER_ORDER."""
    spec = copy.deepcopy(spec)
    if level <= 0:
        return spec
    dims = LADDER_ORDER[: min(level, len(LADDER_ORDER))]
    for path in object_paths(spec):
        for dim in dims:
            if dim == "endpoint":
                continue  # handle removal last, outside the per-op loop
            _apply_dimension(spec, path, dim)
    if level >= len(LADDER_ORDER):  # top level also removes the endpoints
        for path in object_paths(spec):
            del spec["paths"][path]
    return spec


def main():
    ap = argparse.ArgumentParser(description="Degrade the quality of an OpenAPI map.")
    ap.add_argument("--spec", required=True)
    ap.add_argument("--dimension", choices=DIMENSIONS, default="examples")
    ap.add_argument("--fraction", type=float, default=1.0,
                    help="Fraction of object endpoints to degrade (0..1).")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--biased", action="store_true",
                    help="Prefer damaging vulnerable endpoints (needs --ground-truth).")
    ap.add_argument("--ground-truth", default=None)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    with open(args.spec, "r", encoding="utf-8") as f:
        spec = json.load(f)

    vuln = None
    if args.ground_truth:
        with open(args.ground_truth, "r", encoding="utf-8") as f:
            gt = json.load(f)["endpoints"]
        vuln = {k for k, v in gt.items() if v}

    rng = random.Random(args.seed)
    damaged, chosen = degrade(spec, args.dimension, args.fraction, rng, vuln, args.biased)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(damaged, f, indent=2)

    print(f"Applied '{args.dimension}' to {len(chosen)} endpoint(s): {chosen}")
    print(f"Damaged map written to {args.out}")


if __name__ == "__main__":
    main()
