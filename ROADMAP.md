# Roadmap

Last verified: 2026-09-02

## Handoff snapshot

| Field | Current state |
| --- | --- |
| Lifecycle | `GATED` - fixture-validated, not telemetry-validated |
| Portfolio role | Supporting detection engineering, CI, security, and evidence-discipline project |
| Current evidence | Five Sigma rules, compiled targets, synthetic fixtures, validation matrix, tests, and documentation |
| Validation boundary | No claim that the rules have fired on retained real Windows/Sysmon telemetry |

Do not change `fixture-validated` to `validated` because rules compile or fixture tests pass. The isolated-VM procedure in `telemetry/atomic-test-plan.md` is the next credibility gate.

## Current milestone - static detection explorer

Goal: make the current evidence useful to a recruiter without exposing a SIEM or overstating validation.

### Work

1. Generate a GitHub Pages catalog from `detections/catalog.yml`, `detections/compiled/manifest.json`, rule metadata, and `evidence/evidence-manifest.csv`.
2. Support filtering by ATT&CK technique, log source, target platform, severity, and exact lifecycle status.
3. For each rule, show the source Sigma, compiled query variants, test fixture, documented blind spots, validation record, and code link.
4. Make missing compiled targets and missing telemetry evidence visually explicit.
5. Add a recruiter route that explains one rule end to end in under two minutes.

### Acceptance criteria

- The site is generated from repository sources and fails CI on catalog/status drift.
- Every rule remains labeled `fixture-validated` until a sanitized, hashed telemetry artifact and validation log prove otherwise.
- No raw sensitive logs, real endpoint identifiers, credentials, or runnable offensive commands are published through the site.
- Logged-out Pages, mobile layout, keyboard access, contrast, and links are checked.

## Hosting decision

Use GitHub Pages only. Vercel adds no value, and Replit would encourage a fake interactive SIEM surface. Do not expose Elasticsearch/Kibana, Falcon, a webhook sink, or any laboratory host to the internet.

## Next engineering milestone - isolated VM validation

When Nick explicitly chooses the setup session, execute only the approved Atomic tests inside a disposable offline Windows VM, collect the expected Sysmon/Security events, sanitize and hash retained evidence, exercise each rule, record failures, and update the validation matrix mechanically. A partial or negative result is acceptable and must be published honestly.

All additional variants, LogScale work, ML ideas, and enrichment remain unscheduled in `docs/future-work.md`.

## Stop conditions

- Never execute Atomic tests on the host or a non-disposable machine.
- Never infer production false-positive rates from fixtures.
- Never publish raw host telemetry or secrets.
- Do not add an ML detector before the base telemetry validation gate.

## Verification before changing status

Run the repository quality checks, compile all supported targets, validate catalog/evidence drift, secret-scan tracked files, and inspect the published site logged out. A green CI run proves repository automation, not real endpoint validation.
