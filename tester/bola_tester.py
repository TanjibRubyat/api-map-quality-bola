#!/usr/bin/env python3
"""
bola_tester.py  -  a spec-driven BOLA (broken object level authorization) tester.

v3: this tester derives everything it needs from the OpenAPI map, so the QUALITY
of the map directly controls what it can do. For each object endpoint it needs
four things from the map:

  1. AUTH    - a documented security requirement, so it knows to authenticate.
               If none is documented, it sends no token, the server rejects the
               request (401), and the endpoint cannot be tested.
  2. ID      - a documented path parameter, so it knows there is an object id to
               manipulate. If none is documented, it cannot perform the test.
  3. A VALUE - an example id to try, or (if there is no example) a value it can
               guess from the parameter type. Small integers are guessable;
               uuids are not. So removing examples hurts most when ids are uuids.
  4. CONFIRM - a response schema/example that names the owner field, so it can
               check whether a 200 really returned ANOTHER user's object. Without
               it, the tester falls back to treating any 200 as a leak, which can
               cause false positives.

It authenticates as the ATTACKER only (default alice) and learns its own account
id from /api/me (its own identity, which any client knows). The victim's ids come
from the map's examples, not from a privileged feed - so map quality, not a cheat,
decides what it finds.

Usage:
  python bola_tester.py --spec openapi.json --base-url http://localhost:3000 \
      --attacker alice:alice123 --out results.json
"""

import argparse
import json
import re
import sys

try:
    import requests
except ImportError:
    sys.exit("Please install requests:  pip install requests")

OWNER_FIELD = "ownerId"        # the field that identifies an object's owner
GUESS_MAX = 10                 # upper bound when the map declares an integer id
BLIND_GUESS_MAX = 5            # smaller budget when no type is declared at all


def load_spec(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def login(base_url, username, password):
    r = requests.post(f"{base_url}/api/login",
                      json={"username": username, "password": password}, timeout=10)
    r.raise_for_status()
    return r.json()["token"]


def own_identity(base_url, token):
    """The attacker's own account id (its own identity, not a victim feed)."""
    r = requests.get(f"{base_url}/api/me",
                     headers={"Authorization": f"Bearer {token}"}, timeout=10)
    r.raise_for_status()
    return r.json().get("id")


def object_endpoints(spec):
    """Paths carrying an object id placeholder. Any placeholder name counts, not
    just the literal "{id}" — a real specification may use "{userId}" or
    "{order_id}", and those are object endpoints just the same."""
    found = []
    for path, methods in spec.get("paths", {}).items():
        if not re.search(r"\{[^}]+\}", path) or path in ("/api/login", "/api/me"):
            continue
        if "get" in methods:
            found.append(path)
    return found


def _id_param(op):
    """The documented path parameter, or None if the map does not document it."""
    for p in op.get("parameters", []) or []:
        if p.get("in") == "path":
            return p
    return None


def _example_id(param):
    if "example" in param:
        return param["example"]
    schema = param.get("schema") or {}
    return schema.get("example")  # may be None


def _owner_field_known(op):
    """True if the response schema or example names the owner field, so the
    tester knows how to confirm a real leak."""
    for resp in op.get("responses", {}).values():
        for mt in (resp.get("content", {}) or {}).values():
            schema = mt.get("schema") or {}
            props = schema.get("properties") or {}
            if OWNER_FIELD in props:
                return True
            ex = mt.get("example") or {}
            if isinstance(ex, dict) and OWNER_FIELD in ex:
                return True
    return False


def _fill(path, param_name, value):
    token = "{" + param_name + "}"
    if token in path:
        return path.replace(token, str(value))
    return re.sub(r"\{[^}]+\}", str(value), path, count=1)


def test_endpoint(base_url, path, op, attacker_token, own_id):
    """Try to read another user's object via this endpoint, using only what the
    map documents. Returns a dict with tested/reported/reason.

    Degradation is GRADED, not all-or-nothing. Two modelling decisions make it so:

    AUTH FALLBACK. If the map documents no security requirement, the tester does
    not simply give up. It has already authenticated to reach /api/me, so it
    holds a working credential. It tries the request unauthenticated first (as
    the map implies), and on a 401 it presents the credential it already holds.
    A real tester would not discard a working token because a document failed to
    mention it. So losing the `security` block costs an extra request, not the
    endpoint.

    PATH-TEMPLATE FALLBACK. If the map documents no parameter, the id is still
    visible in the path template itself ("/api/orders/{id}"). The tester reads it
    from there. What it loses with the parameter block is the id's TYPE and
    EXAMPLE, not the knowledge that an id exists. It must then guess blind, on a
    smaller budget, because it cannot tell an integer id from a uuid one.

    This makes the five quality dimensions differ in DEGREE:
      examples    -> keeps the type, so it can guess within that type
      parameters  -> loses the type too, so it guesses blind on a smaller budget
      security    -> recovered via the held credential
      schema      -> cannot confirm ownership, so precision suffers, not recall
      endpoint    -> total loss, the only true blackout
    """
    documented_auth = bool(op.get("security"))

    param = _id_param(op)
    in_path = re.search(r"\{([^}]+)\}", path)
    if param is None and in_path is None:
        return {"tested": False, "reported_vulnerable": False, "reason": "no_id_anywhere"}

    if param is not None:
        param_name = param.get("name", "id")
        example = _example_id(param)
        declared_type = (param.get("schema") or {}).get("type")
        id_source = "parameter"
    else:
        # The parameter block is gone, but the path template still names an id.
        param_name = in_path.group(1)
        example = None
        declared_type = None
        id_source = "path_template"

    if example is not None:
        candidates, strategy = [example], "example"
    elif declared_type == "integer":
        candidates = [i for i in range(1, GUESS_MAX + 1) if i != own_id]
        strategy = "typed_guess"
    elif declared_type is None:
        # No type documented at all: hedge with a small integer probe set.
        candidates = [i for i in range(1, BLIND_GUESS_MAX + 1) if i != own_id]
        strategy = "blind_guess"
    else:
        # A declared non-integer type (string/uuid) with no example: nothing to try.
        candidates, strategy = [], "no_strategy"

    if not candidates:
        return {"tested": False, "reported_vulnerable": False,
                "reason": f"unguessable_id:{id_source}"}

    can_confirm = _owner_field_known(op)
    auth_headers = {"Authorization": f"Bearer {attacker_token}"}
    used_fallback = False
    tested = False

    for cid in candidates:
        url = base_url + _fill(path, param_name, cid)
        try:
            r = requests.get(url, headers=(auth_headers if documented_auth else {}),
                             timeout=10)
            if r.status_code == 401 and not documented_auth:
                used_fallback = True
                r = requests.get(url, headers=auth_headers, timeout=10)
        except requests.RequestException as e:
            return {"tested": tested, "reported_vulnerable": False, "reason": f"error:{e}"}
        if r.status_code == 401:
            return {"tested": False, "reported_vulnerable": False, "reason": "unauthorized"}
        tested = True
        if r.status_code != 200:
            continue  # 403/404 -> not a leak for this candidate
        suffix = ":auth_fallback" if used_fallback else ""
        # Got an object back. Decide whether it is really someone else's.
        if can_confirm:
            try:
                owner = r.json().get(OWNER_FIELD)
            except ValueError:
                owner = None
            if owner is not None and owner != own_id:
                return {"tested": True, "reported_vulnerable": True,
                        "reason": f"leak_confirmed{suffix}"}
            # 200 but it is the caller's own object -> not a leak.
        else:
            # No way to confirm ownership -> any 200 is treated as a leak.
            return {"tested": True, "reported_vulnerable": True,
                    "reason": f"leak_unconfirmed{suffix}"}

    return {"tested": tested, "reported_vulnerable": False, "reason": f"no_leak:{strategy}"}


def scan(spec, base_url, attacker="alice:alice123", quiet=True):
    a_user, a_pass = attacker.split(":", 1)
    attacker_token = login(base_url, a_user, a_pass)
    own_id = own_identity(base_url, attacker_token)

    results = []
    for path in object_endpoints(spec):
        op = spec["paths"][path]["get"]
        outcome = test_endpoint(base_url, path, op, attacker_token, own_id)
        key = f"GET {path}"
        outcome["endpoint"] = key
        results.append(outcome)
        if not quiet:
            mark = "VULNERABLE" if outcome["reported_vulnerable"] else (
                "tested-safe" if outcome["tested"] else "NOT TESTED")
            print(f"  [{mark:12}] {key}  ({outcome['reason']})")

    return {
        "endpoints_in_map": len(results),
        "detected_vulnerable": [r["endpoint"] for r in results if r["reported_vulnerable"]],
        "tested_endpoints": [r["endpoint"] for r in results if r["tested"]],
        "results": results,
    }


def main():
    ap = argparse.ArgumentParser(description="Spec-driven BOLA tester.")
    ap.add_argument("--spec", required=True)
    ap.add_argument("--base-url", default="http://localhost:3000")
    ap.add_argument("--attacker", default="alice:alice123", help="user:password")
    ap.add_argument("--out", default=None)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    spec = load_spec(args.spec)
    summary = scan(spec, args.base_url, args.attacker, quiet=args.quiet)
    summary["spec"] = args.spec

    if not args.quiet:
        print(f"\nEndpoints in map    : {summary['endpoints_in_map']}")
        print(f"Endpoints tested    : {len(summary['tested_endpoints'])}")
        print(f"Flagged vulnerable  : {len(summary['detected_vulnerable'])}")

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

    return summary


if __name__ == "__main__":
    main()
