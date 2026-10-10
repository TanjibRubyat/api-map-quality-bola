#!/usr/bin/env python3
"""
bola_tester.py  -  a small BOLA (broken object level authorization) tester.

What it does, in plain terms:
  1. Reads an OpenAPI "map" file to find object-level endpoints (ones with an
     id in the path, e.g. /api/orders/{id}).
  2. Logs in as two users (an attacker and a victim).
  3. Asks the victim's account which object ids it owns.
  4. As the attacker, tries to read each of the victim's objects.
  5. If the server returns the victim's data (HTTP 200), that endpoint has a
     BOLA flaw. If it blocks the request (403/404), it is treated as safe.

The key point for the experiment: the tester can ONLY test endpoints that are
listed in the map it is given. If the map is incomplete, some flaws are never
tested, so they are missed.

Usage:
  python bola_tester.py --spec openapi.json --base-url http://localhost:3000 \
      --attacker alice:alice123 --victim bob:bob123 --out results.json
"""

import argparse
import json
import sys

try:
    import requests
except ImportError:
    sys.exit("Please install requests:  pip install requests")


def load_spec(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def login(base_url, username, password):
    r = requests.post(f"{base_url}/api/login",
                      json={"username": username, "password": password},
                      timeout=10)
    r.raise_for_status()
    return r.json()["token"]


def get_owned(base_url, token):
    """Ask /api/me what object ids this user owns."""
    r = requests.get(f"{base_url}/api/me",
                     headers={"Authorization": f"Bearer {token}"}, timeout=10)
    r.raise_for_status()
    data = r.json()
    return data  # {id, username, owns: {...}}


def object_endpoints(spec):
    """Return GET endpoints that take an id in the path, excluding login/me."""
    found = []
    for path, methods in spec.get("paths", {}).items():
        if "{id}" not in path:
            continue
        if path in ("/api/login", "/api/me"):
            continue
        if "get" in methods:
            found.append(path)
    return found


def victim_ids_for(path, victim):
    """Decide which of the victim's ids to try for a given endpoint."""
    owns = victim.get("owns", {})
    # /api/users/{id}/... uses the user's own id, not an object id.
    if "/users/{id}" in path:
        return [victim["id"]]
    # For /api/<resource>/{id}, use the victim's id for that resource if known.
    parts = [p for p in path.split("/") if p and p != "{id}"]
    if parts and parts[-1] in owns:
        return [owns[parts[-1]]]
    # Fallback: try every object id the victim owns.
    return list(owns.values())


def test_endpoint(base_url, path, attacker_token, victim):
    """As the attacker, try to read the victim's object(s) via this endpoint.
    Returns (vulnerable: bool, evidence: dict)."""
    for vid in victim_ids_for(path, victim):
        url = base_url + path.replace("{id}", str(vid))
        try:
            r = requests.get(url, headers={"Authorization": f"Bearer {attacker_token}"},
                             timeout=10)
        except requests.RequestException as e:
            return False, {"error": str(e)}
        if r.status_code == 200:
            # The attacker received the victim's object -> BOLA.
            return True, {"url": url, "status": 200, "leaked": r.text[:200]}
    return False, {"url": url, "status": r.status_code}


def scan(spec, base_url, attacker="alice:alice123", victim="bob:bob123", quiet=True):
    """Run the whole BOLA test against a given spec dict. Returns a summary.
    This is the reusable core, used by main() and by the experiment runner."""
    a_user, a_pass = attacker.split(":", 1)
    v_user, v_pass = victim.split(":", 1)

    attacker_token = login(base_url, a_user, a_pass)
    victim_token = login(base_url, v_user, v_pass)
    victim_info = get_owned(base_url, victim_token)

    endpoints = object_endpoints(spec)

    results = []
    for path in endpoints:
        vulnerable, evidence = test_endpoint(base_url, path, attacker_token, victim_info)
        key = f"GET {path}"
        results.append({"endpoint": key, "vulnerable": vulnerable, "evidence": evidence})
        if not quiet:
            mark = "VULNERABLE" if vulnerable else "safe"
            print(f"  [{mark:10}] {key}")

    return {
        "endpoints_in_map": len(endpoints),
        "detected_vulnerable": [r["endpoint"] for r in results if r["vulnerable"]],
        "results": results,
    }


def main():
    ap = argparse.ArgumentParser(description="Simple BOLA tester driven by an OpenAPI map.")
    ap.add_argument("--spec", required=True, help="Path to the OpenAPI map (json).")
    ap.add_argument("--base-url", default="http://localhost:3000")
    ap.add_argument("--attacker", default="alice:alice123", help="user:password")
    ap.add_argument("--victim", default="bob:bob123", help="user:password")
    ap.add_argument("--out", default=None, help="Optional path to write results JSON.")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    spec = load_spec(args.spec)
    summary = scan(spec, args.base_url, args.attacker, args.victim, quiet=args.quiet)
    summary["spec"] = args.spec

    if not args.quiet:
        print(f"\nEndpoints found in map : {summary['endpoints_in_map']}")
        print(f"BOLA flaws detected    : {len(summary['detected_vulnerable'])}")

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        if not args.quiet:
            print(f"Results written to     : {args.out}")

    return summary


if __name__ == "__main__":
    main()
