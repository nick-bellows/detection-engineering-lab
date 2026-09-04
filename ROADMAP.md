# Roadmap

Last verified: 2026-09-04

## Handoff snapshot

| Field | Current state |
| --- | --- |
| Lifecycle | `GATED` - fixture-validated, not telemetry-validated |
| Portfolio role | Supporting detection engineering, CI, security, and evidence-discipline project |
| Current evidence | Five Sigma rules, compiled targets, synthetic fixtures, validation matrix, tests, documentation, and a generated evidence explorer |
| Published site | GitHub Pages (`main`, `/docs`), live at <https://nick-bellows.github.io/detection-engineering-lab/>; loaded logged out and link-checked 2026-09-04 |
| CI | 8 jobs green on `main` (lint, mypy strict, unit, catalog gate with the VM gate asserted failing, compile drift, status/explorer drift, live SIEM, gitleaks) |
| Validation boundary | No claim that the rules have fired on retained real Windows/Sysmon telemetry |

Do not change `fixture-validated` to `validated` because rules compile or fixture tests pass. The isolated-VM procedure in `telemetry/atomic-test-plan.md` is the next credibility gate.

## Completed repository milestone - static detection explorer

Goal: make the current evidence useful to a recruiter without exposing a SIEM or overstating validation.

### Delivered

1. `docs/index.html` is generated from `detections/catalog.yml`, the compiled manifest, Sigma rule metadata, the validation matrix, and documented blind spots.
2. Recruiters can filter all five rules by ATT&CK technique, log source, target platform, severity, and exact lifecycle status.
3. Each card links source Sigma, compiled variants, positive and negative fixtures, live-Elasticsearch test, evidence manifest, and full write-up.
4. Unsupported LogScale targets and missing host-telemetry validation are visually explicit on every applicable card.
5. The page opens with a two-minute DET-001 route and contains no raw sensitive telemetry or runnable payloads.
6. `scripts/render_explorer.py --check` runs locally and in CI so the published artifact cannot drift from the evidence sources.

GitHub Pages is enabled (source `main`, path `/docs`) and the explorer is live at <https://nick-bellows.github.io/detection-engineering-lab/>. On 2026-09-04 it was loaded logged out (HTTP 200) and every card link resolves to a `blob/main` path in this repository. The page claims nothing beyond the repository evidence.

### Acceptance criteria

- The site is generated from repository sources and fails CI on catalog/status drift.
- Every rule remains labeled `fixture-validated` until a sanitized, hashed telemetry artifact and validation log prove otherwise.
- No raw sensitive logs, real endpoint identifiers, credentials, or runnable offensive commands are published through the site.
- Logged-out load and links: checked 2026-09-04. Mobile layout, keyboard access, and contrast are designed in (single-column grid, skip link, visible focus outline, light/dark colour scheme) but have not been checked by hand on a device.

## Hosting decision

Use GitHub Pages only. Vercel adds no value, and Replit would encourage a fake interactive SIEM surface. Do not expose Elasticsearch/Kibana, Falcon, a webhook sink, or any laboratory host to the internet.

## Known dependency boundary

The 2026-09-02 local `pip-audit` pass found `PYSEC-2026-2447` in pySigma's
`diskcache==5.6.3` dependency; no fixed release was listed. The issue requires an attacker
to write a cache directory that a victim later deserializes. This repository does not call
DiskCache directly, persist a shared cache, or deploy the compiler as a service; CI runs in
an ephemeral workspace. Keep the exact pySigma toolchain pinned for compiled-query
reproducibility, monitor upstream for a fixed release, and do not use attacker-writable cache
state. This is a bounded acceptance, not a claim that the dependency has no vulnerability.

## Next engineering milestone - isolated VM validation

When Nick explicitly chooses the setup session, execute only the approved Atomic tests inside a disposable offline Windows VM, collect the expected Sysmon/Security events, sanitize and hash retained evidence, exercise each rule, record failures, and update the validation matrix mechanically. A partial or negative result is acceptable and must be published honestly.

The per-detection test records (Atomic GUIDs, privileges, prerequisites, expected source events, cleanup, negative controls, and the promotion steps) are already written in `telemetry/atomic-test-plan.md`; only the fields a run produces are blank.

All additional variants, LogScale work, ML ideas, and enrichment remain unscheduled in `docs/future-work.md`.

## Stop conditions

- Never execute Atomic tests on the host or a non-disposable machine.
- Never infer production false-positive rates from fixtures.
- Never publish raw host telemetry or secrets.
- Do not add an ML detector before the base telemetry validation gate.

## Verification before changing status

Run the repository quality checks, compile all supported targets, validate catalog/evidence drift, secret-scan tracked files, and inspect the published site logged out. A green CI run proves repository automation, not real endpoint validation.
