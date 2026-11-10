# API Map Quality vs BOLA Detection — Experiment Harness (v5)

MSc project experiment:
**"What happens to API security testing when the API's map is wrong?"**

It measures how much worse automated "broken access" (BOLA) detection becomes as
the OpenAPI map loses **quality** — not just when whole endpoints go missing, but
when the parts that stay listed lose their examples, schemas, parameter docs, or
security info.

> ⚠️ The target API is **insecure on purpose**. Run it only on your own
> machine. Never put it on the public internet.

---

## What changed in v5 (the important part)

v4 added the per-trial data and `analyse_results.py`, and that analysis reported
two limitations which v4's own README already named. v5 removes both, so the
experiment can finally rank its dimensions.

1. **`schema` and `examples` no longer overlap.** The owner field was documented
   twice in the gold map, in the response schema and in the response example,
   and `bola_tester._owner_field_known()` accepts either. `_strip_schema()`
   removed only the schema, so the example survived, confirmation was never
   lost, and the dimension had no measurable effect. The response example now
   belongs to `schema` (both describe the response body) and `examples` means
   the **parameter** example only. Each dimension now maps to exactly one
   tester capability.

2. **`ID_MODE=spread` makes guessing partial.** In `seq` the victim id is always
   2, so a typed guess and a blind guess both always succeed. In `uuid` neither
   can ever succeed. Guessability was therefore binary and `examples`,
   `parameters` and `endpoint` produced identical recall curves. In `spread` the
   victim id runs over 2..20, which straddles both budgets, so a documented
   example always finds the object, a typed guess finds it when the id is <= 10,
   and a blind guess only when the id is <= 5.

Measured at full damage in `spread`, the three recall levels are now distinct:

| dimension removed | what the tester falls back on | recall |
| --- | --- | --- |
| none | the documented example | 1.000 |
| `examples` | a typed guess, budget 10 | 0.583 |
| `parameters` | a blind guess, budget 5 | 0.333 |
| `endpoint` | nothing | 0.000 |

And with `SAFE_MODE=owndata`, removing `schema` now drives precision down to
0.500 on its own, where in v4 no single dimension moved precision at all.

`analyse_results.py` also compares **precision** curves now, not just recall.
`schema` and `security` both leave recall at 1.000, so comparing recall alone
reported them as indistinguishable when they are not.

---

## What changed in v3

v2 only ever **hid whole endpoints** from the map, and the tester only read the
list of endpoints. So the result was almost arithmetic: recall fell in a straight
line equal to the fraction of endpoints still visible, and the three "damage
types" gave identical lines.

v3 fixes this in two ways:

1. **The map is degraded by losing quality**, dimension by dimension, on
   endpoints that stay listed (see "Quality dimensions" below).
2. **The tester now uses that quality.** It derives everything it needs from the
   map, so removing a piece of the map actually changes what it can do.

The result is no longer a single straight line. Different pieces of map quality
matter in different ways, and the effect depends on the API.

---

## The spec-driven tester: what it needs from the map

For each object endpoint, `tester/bola_tester.py` needs four things from the map.
Each one maps to a quality dimension that the experiment can remove:

| It needs… | …from the map | If it is missing |
| --- | --- | --- |
| to know it must **authenticate** | the `security` requirement | it tries unauthenticated, gets 401, then **retries with the credential it already holds** — one wasted request, no detection lost |
| a manipulable **object id** | the path **parameter**, else the path template | the `{id}` in the path still proves an id exists, so it keeps testing — but it loses the id's **type** and **example** |
| a **value to try** | the parameter **example**, else a guess from the type | small integers are guessable; uuids are not, so it is stuck |
| to **confirm a leak** | the response **schema/example** (owner field) | it treats any 200 as a leak → **false positives** |

Note the first two rows. Degradation is **graded, not all-or-nothing**: losing the
security block or the parameter block weakens the tester without blinding it.
Only deleting the endpoint is a true blackout. This matters because a tester that
gives up entirely makes every dimension look equally fatal, which is a property
of the tester rather than of the specification.

The tester authenticates as the **attacker only** (alice) and learns its own
account id from `/api/me` (its own identity, which any client knows). The
victim's ids come from the map's **examples**, not from a privileged feed. So map
quality — not a cheat — decides what it finds. This is the main realism fix over
v2, which read the victim's ids straight from `/api/me`.

**Modelling assumptions** (state these in the report): the reference tester is a
*spec-driven* tester, but it is not a naive one. Two fallbacks are deliberate and
must be declared, because they decide the results:

1. **Credential reuse.** It authenticates to reach `/api/me`, so it holds a
   working token. If an operation documents no security requirement, it tries
   unauthenticated first and presents the token on a 401. A real tester would not
   discard a working credential because a document failed to mention it.
2. **Path-template reading.** If an operation documents no parameter, it still
   reads the `{id}` placeholder out of the path string. What the parameter block
   provides is the id's *type* and *example*, not the fact that an id exists.

Everything else is derived from the map alone, so map quality remains the only
input. A configured commercial tool may behave differently — which is exactly why
a second, independent tool is the next step.

---

## Quality dimensions (what the experiment removes)

- **examples** — the example id on the **parameter**. The tester then has no
  sample id and must guess.
- **schema** — everything describing the response **body**: the schema (the
  field list) and the response example. Either one names the owner field, so
  both are removed together. The tester can then no longer confirm a real leak.
- **security** — the security requirement. The tester does not know it must
  authenticate, so its requests are rejected.
- **parameters** — the parameter list. The tester does not know there is an id
  to manipulate.
- **endpoint** — the whole endpoint (the v2 behaviour). The most destructive.

## Two API knobs (environment variables)

- `ID_MODE=seq` (default) → small, guessable integer ids (alice=1, bob=2).
  `ID_MODE=spread` → integers spread over 2..20, so the victim id straddles the
  tester's two guessing budgets (`GUESS_MAX=10`, `BLIND_GUESS_MAX=5`).
  `ID_MODE=uuid` → long, unguessable ids.
  Guessability is what makes "examples" and "parameters" matter, and `spread` is
  the only mode where they can be told apart — see "What changed in v5".
- `SAFE_MODE=deny` (default) → safe endpoints return 403.
  `SAFE_MODE=owndata` → safe endpoints return *your own* record with 200 (a real
  non-vulnerable pattern). This is what makes "schema" matter for precision.

---

## What is in here

```
apisec-bola/
  target-api/            The deliberately vulnerable Node.js API
    server.js              Entry point
    src/
      config/resources.js  The 24 resources (12 vulnerable, 12 safe) + id modes
      data/users.js        Two users (alice, bob)
      data/store.js        In-memory objects
      middleware/auth.js   Bearer-token check
      controllers/         login/me and the get-by-id (BOLA) logic + safe modes
      routes/              URL -> controller wiring
    scripts/gen_meta.js    Generates the RICH gold openapi.json + ground_truth.json
    openapi.json           The complete, correct "gold" map
  tester/
    bola_tester.py         The spec-driven BOLA tester
  experiment/
    degrade_spec.py        Removes quality (examples/schema/security/parameters/endpoint)
    run_experiment.py      The main experiment (starts/stops the API itself)
    plot_results.py        Draws the charts
    analyse_results.py     Trend test + separability test over the per-trial data
  ground_truth.json        Which endpoints really are vulnerable
  results/
    experiment_results.csv Averaged table, with SD and 95% confidence intervals
    experiment_trials.csv  Every individual run, before averaging
    figure_main.png        2x2 summary across seq, spread and uuid ids
    figure_spread.png      Headline: spread + owndata, all five dimensions, recall and precision
    figure_biased.png      Biased-vs-random damage chart
```

## Requirements

- Node.js 18+ and npm
- Python 3.9+ with `requests` (tester), `matplotlib` (plots) and `scipy`
  (statistics). scipy is optional: without it the confidence intervals fall back
  to a normal approximation and the trend test is skipped.

## Setup

```bash
cd target-api && npm install
pip install requests matplotlib
```

## Running it

The experiment starts and stops the API itself, so you do **not** need to run the
server by hand:

```bash
cd experiment
python run_experiment.py --trials 10
python plot_results.py
python analyse_results.py
```

The default `--id-modes` is `seq,spread,uuid`, so this command reproduces every
figure, including the `spread` results.

**Reading the charts.** Every point is a separate test: a fresh copy of the full
specification is damaged by the stated amount, then tested. Points are not steps
of one gradual process; the line only joins them to show the trend. A missing
point means the metric is undefined there (for precision: nothing was flagged).
Shaded bands are 95% confidence intervals over the repeated runs.

This writes `results/experiment_results.csv`, `results/experiment_trials.csv` and
the charts, then prints the statistics.

Two notes on the numbers. Points where the tester flagged nothing at all leave
precision **blank**, not 1.0 — precision is undefined when there are no
predictions, and printing 1.0 there draws a recovery that never happened.
Fractions 0 and 1.0 run a single trial, because nothing is random at those
points and repeating them only inflates the apparent sample size.

`run_experiment.py` regenerates the spec for each id mode, and restores the
default `seq` spec when it exits, so the repository is not left in whichever mode
happened to run last.

To run the tester once by hand against the gold map:

```bash
cd target-api && npm start          # terminal 1
cd tester && python bola_tester.py --spec ../target-api/openapi.json   # terminal 2
```

## Findings so far

- **Examples matter for recall only when ids are unguessable.** With integer ids
  the tester guesses and recall stays at 1.0 even with no examples; with uuid ids
  recall falls straight to 0 as examples are removed.
- **Documented security barely matters to a tester that holds a credential.**
  Once credential reuse is modelled, removing the `security` block costs one
  wasted request and no detections. This is a result about testers, not about
  specifications: a tool that gives up without a documented scheme will report
  the security block as critical, and that reflects its own design.
- **The parameter block costs type and example, not reachability.** The `{id}`
  in the path survives, so the tester keeps probing — just blind.
- **`schema` drives precision on its own (fixed in v5).** `ownerId` was recorded
  twice in the gold spec, in the response schema and in the response example,
  and removing only the schema left the example behind, so confirmation was
  never lost and the dimension looked inert. The response example now belongs to
  `schema`. With `SAFE_MODE=owndata`, removing `schema` alone takes precision
  from 1.000 to 0.500: the tester reaches every endpoint, cannot tell whose
  object it was handed, and flags all 12 safe endpoints as leaks.
- **Guessability is no longer binary (fixed in v5).** In `seq` the victim id is
  always 2, so any guess works; in `uuid` no guess ever works. Dimensions
  therefore either fully recovered or fully failed, and `examples`, `parameters`
  and `endpoint` produced identical recall curves. `ID_MODE=spread` puts the
  victim id over 2..20, between the typed budget of 10 and the blind budget of
  5, so the three dimensions now separate cleanly at 0.583, 0.333 and 0.000.
  **The ranking only exists in `spread`.** In `seq` and `uuid` the curves still
  coincide, and that is a property of those id spaces rather than of the
  dimensions.
- **Blind guessing can be worse than useless.** In `uuid` + `owndata` at ladder
  level 4, coverage is 1.0, recall is 0.0 and precision is 0.0: the tester probes
  every endpoint, finds none of the 12 real flaws, and reports 12 that do not
  exist.
- **Biased damage makes a cliff.** When damage is aimed at the vulnerable
  endpoints first, recall falls faster than under random damage.

## Next steps

- **A third id mode, guessable but not trivially so** (e.g. random integers over
  a wide range). This is the blocker for separating the dimensions, and no
  further tester change will fix it.
- Add a second, independent tool (e.g. Akto or LeakRadar) so the finding is not
  about this reference tester alone.
- Randomise the ladder order and average over permutations, so the cumulative
  analysis reports each dimension's contribution rather than the fixed order in
  `LADDER_ORDER`.
- Optional: calibrate the quality dimensions against real public OpenAPI specs.

## Credentials used by the demo

- alice / alice123 (attacker)
- bob / bob123 (victim)
