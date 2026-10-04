# API Map Quality vs BOLA Detection — Experiment Harness

A first working version for the MSc project:
**"What happens to API security testing when the API's map is wrong?"**

It measures how much worse automated "broken access" (BOLA) detection becomes
as the OpenAPI map gets more incomplete.

> ⚠️ The target API is **insecure on purpose**. Run it only on your own
> machine. Never put it on the public internet.

---

## What is in here

```
apisec-bola/
  target-api/        A small Node.js API to test against (the "victim" app)
    server.js          Has 3 BOLA-vulnerable and 3 safe endpoints, 2 users
    openapi.json       The full, correct "map" of the API
    package.json
  tester/
    bola_tester.py     The BOLA testing tool (reads the map, finds flaws)
    requirements.txt
  experiment/
    degrade_spec.py    Makes damaged copies of the map
    run_experiment.py  The main experiment: damage the map, measure detection
  ground_truth.json    The known truth: which endpoints really are vulnerable
  results/
    experiment_results.csv   Output table (created when you run the experiment)
```

## How the pieces fit together

1. The **target API** is the app we test. We already know which of its
   endpoints are vulnerable (written down in `ground_truth.json`).
2. The **tester** reads the map, logs in as two users (an attacker and a
   victim), and tries to make the attacker read the victim's data. If it
   succeeds, that endpoint has a BOLA flaw. The tester can only test endpoints
   that are listed in the map it is given.
3. The **experiment** removes more and more endpoints from the map, runs the
   tester each time, and records how many real flaws are still found.

## Requirements

- Node.js 18+ and npm
- Python 3.9+
- Python package: `requests`

## Setup

```bash
# 1. Install the API
cd target-api
npm install

# 2. Install the Python dependency
cd ../tester
pip install -r requirements.txt
```

## Running it

**Step 1 — start the target API** (leave it running in one terminal):

```bash
cd target-api
npm start
# -> Target API listening on http://localhost:3000
```

**Step 2 — run the tester once against the full map** (in a second terminal):

```bash
cd tester
python bola_tester.py --spec ../target-api/openapi.json
```

You should see 3 endpoints marked VULNERABLE and 3 marked safe.

**Step 3 — run the full experiment:**

```bash
cd experiment
python run_experiment.py --trials 40
```

This prints a table and writes `results/experiment_results.csv`. The table
shows, for each level of map damage, how many flaws were found on average and
the recall (flaws found ÷ flaws that exist).

## How to read the result

- **recall = 1.0** means every real flaw was found.
- **recall = 0.0** means every real flaw was missed.
- As the map loses endpoints, recall falls. The CSV is what you turn into the
  main chart for your report: *map completeness* (x-axis) vs *recall* (y-axis).

## Honest notes and next steps

- Right now the experiment removes endpoints **at random and evenly**. With
  even random removal, recall falls in a roughly straight line, because on
  average you lose vulnerable and safe endpoints at the same rate. This is the
  correct baseline, but it is the "obvious" result.
- **The interesting research is in realistic damage patterns.** For example:
  what if certain kinds of endpoints are more likely to be missing from the
  map? What if the map is wrong (lists an endpoint with the wrong method or
  path) rather than just missing entries? Those cases may show a sudden drop
  (a "cliff"), which would be a real finding. This is where to take the project
  after Harry approves the scope.
- The target API is deliberately small. Adding more endpoints and more fault
  types will make the measurements stronger.
- `OWASP ZAP` is intended as a comparison baseline (it will likely miss most
  BOLA flaws). That comparison is not automated yet.

## Credentials used by the demo

- alice / alice123
- bob / bob123
