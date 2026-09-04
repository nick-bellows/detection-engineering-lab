# Authentication anomaly baseline

> Status: **planned — no code exists in this directory.** Only the schema of the synthetic
> input (`data/synthetic_auth_schema.csv`) is committed. Gated on all five catalog entries
> reaching `validated`; listed in `docs/future-work.md`.

This is a supplementary comparison to the validated rule pipeline, not the project's critical path.

## Proposed experiment

- Use synthetic authentication events with documented generation rules.
- Fit an isolation-forest baseline on a training period without labeled attack claims.
- Evaluate against held-out synthetic anomalies and ordinary but unusual behavior.
- Report precision, recall, false-positive rate, alert volume, and threshold sensitivity.
- Compare what the model surfaces with what deterministic detections explain better.

## Required features and cautions

Candidate features include login hour, source novelty, destination novelty, failure rate, geographic impossibility in synthetic coordinates, and account privilege. Avoid raw usernames as predictive features. Clearly state that synthetic evaluation does not establish production performance.

Do not begin this milestone until the five rule catalog entries have reached `validated`.

