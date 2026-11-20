# Extension results (added after the final-results tag)

These files do not change the frozen results in results/experiment_*.csv.

- owner_inference_*.csv: the same experiment in owndata mode, run with
  OWNER_INFERENCE=1 so the tester looks for its own user id in replies when the
  map documents no owner field.
      OWNER_INFERENCE=1 python experiment/run_experiment.py --safe-modes owndata --out results/extension/owner_inference_results.csv
- public_spec_survey_*.csv: see analysis/spec_survey/README.md.
