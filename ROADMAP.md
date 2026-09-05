# Roadmap

Last verified: 2026-09-04

## Handoff snapshot

| Field | Current state |
| --- | --- |
| Lifecycle | `GATED` - fixture-validated, not telemetry-validated |
| Portfolio role | Supporting detection engineering, CI, security, and evidence-discipline project |
| Current evidence | Five Sigma rules, compiled targets, synthetic fixtures, validation matrix, tests, documentation, and a generated evidence explorer |
| Published site | GitHub Pages (`main`, `/docs`), live at <https://nick-bellows.github.io/detection-engineering-lab/>; loaded logged out and link-checked 2026-09-04 |
| CI | 8 jobs green on `main` (lint, mypy strict, unit, catalog gate with the VM gate asserted failing, compile drift, status/explorer drift, live Elasticsearch query test, gitleaks) |
| Release | Tag `v0.1.0` on the 2026-09-04 finalization commit |
| External review | Two independent tool-assisted reviews on 2026-09-04; both recommend advancing the repository for junior detection-engineering screens. Their confirmed findings are the work items R1–R14 below |
| Validation boundary | No claim that the rules have fired on retained real Windows/Sysmon telemetry |

Do not change `fixture-validated` to `validated` because rules compile or fixture tests pass. The isolated-VM procedure in `telemetry/atomic-test-plan.md` is the credibility gate, and Milestone B must land before the first promotion.

## Completed

### 2026-08-29 - fixture-validated release

Five Sigma rules compiled to Elastic (5/5) and CrowdStrike LogScale (3/5, two recorded gaps), proven on a live Elasticsearch 8.19.20 in CI against synthetic positive and negative-control fixtures; lifecycle gates; hashed evidence manifest; mutation proofs in `docs/validation-log.md`.

### 2026-09-02 - static detection explorer

`docs/index.html` is generated from the catalog, compiled manifest, rule metadata, validation matrix, and write-ups; filterable by technique, log source, platform, severity, and lifecycle; every card links source, compiled variants, fixtures, the live test, the manifest, and the write-up; unsupported targets and missing host validation are explicit on every card; `render_explorer.py --check` runs locally and in CI. On 2026-09-04 an external reviewer confirmed the deployed page byte-identical to the tracked file, no horizontal overflow on mobile, keyboard order starting at the skip link, visible focus on every control, and zero automated WCAG A/AA violations. Manual screen-reader testing has not been done.

### 2026-09-04 - finalization for review

README points at the live explorer; `telemetry/atomic-test-plan.md` holds one filled record per detection (Atomic GUIDs, privileges, prerequisites, expected events, cleanup, negative controls, promotion steps) with every run-time field marked not run; `evidence/README.md` explains manifest generation and sanitisation; `scripts/run_checks.ps1` checks every native exit code; tag `v0.1.0`.

## Path to completion

Three milestones, in order. **Claude Code** items need no approval beyond the milestone itself. **Owner** items need Nick's hands, a decision, or an approval before they can happen. Each item keeps its review ID so a commit can name what it closes.

### Milestone A - truth and wording pass

Who: Claude Code, unattended. Effort: about 2 hours. Changes no rule, fixture, query, or lifecycle state.

Goal: every claim in the README, status image, explorer, and logs is exactly what the code does.

| ID | Item | Acceptance |
| --- | --- | --- |
| R1 | README opening says each rule is compiled to Elastic and LogScale. State Elastic 5/5 and LogScale 3/5 with two recorded gaps in the first paragraph | The first screen states 3/5 |
| R2 | Rename "Live SIEM" to "live Elastic query replay" in the status image, the CI job name, README, DESIGN, and write-ups. The test calls Elasticsearch search directly; no Kibana rule executes | No label describes the search test as SIEM execution; `render_status_svg.py --check` green after regeneration |
| R3 | README map says "pinned image digests"; compose and CI pull by tag. Say "pin by tag, verify by digest" and point the validation log at `lab/README.md`, not `lab/compose.yml` | No document claims compose or CI pin by digest |
| R4a | README says CI fails if the published page drifts. CI detects drift; publication is not gated. Say so until R4b lands | README and this file say what is true |
| R5 | This file said "no runnable offensive commands" while the explorer links fixtures that contain comsvcs and ProcDump command lines. The policy is: no payload binaries, no execution, no secrets, no raw telemetry | Wording matches what the fixtures contain |
| R6 | Pydantic is a dependency and a listed skill but nothing imports it; `LoadedRule.falsepositives` and `CompiledRule.supports` are unused. Remove all three | `git grep pydantic` is empty; ruff and mypy green |
| R7 | `run_checks.ps1` prints "All local checks passed" after skipping the live tests and never runs gitleaks. The summary names what was skipped and says gitleaks is CI-only | Summary line lists skipped steps |
| R8 | Explorer blind spots end mid-sentence because the parser reads the first physical line of a wrapped bullet | No card ends mid-sentence; `render_explorer.py --check` green after regeneration |
| R9 | `.gitleaks.toml` allowlists the whole `.env.example` path. Allowlist the two dummy values instead | A fake secret added to `.env.example` is caught |
| R10 | CI downloads the gitleaks tarball without a checksum. Verify SHA-256 before extraction | The job fails on a checksum mismatch |

### Milestone B - mechanical promotion gate

Who: Claude Code, after the Owner approves the design defaults in the decisions table. Effort: about 1 day. The catalog stays `fixture-validated` throughout and `--require-validated` keeps failing.

Goal: `--require-validated` cannot be satisfied by labels. Today it accepts any non-empty strings; a reviewer passed it with fake IDs.

| ID | Item | Default design (Owner approves or overrides) |
| --- | --- | --- |
| R11 | Strengthen `validate_catalog.py --require-validated` | `positive_test_id` and `negative_test_id` must be UUIDs listed in that detection's fixture `meta.yml`; `evidence_ids` must name manifest rows of type `vm-telemetry` (one POS, one NEG) whose SHA-256 matches a file under `evidence/`; the matrix VM columns (`atomic_test_id`, `host_snapshot`, `sensor_config_id`, `alert_observed_on_host` = yes, `validated_on`) must be filled and agree with the catalog. Negative tests: fake IDs, missing files, wrong hashes, mismatched matrix rows |
| R12 | Derive display facts instead of copying them | Fixture counts in the status image and explorer come from the fixture files; a test fails when the matrix count disagrees. `siem_result` stays a recorded value but must cite the CI run ID present in the manifest. Manifest rows written by the generator carry `generated` in the review column; `yes` is reserved for hand-added rows. The renderer docstring lists its real inputs |
| R13 | Reconcile the triage CLI with the catalog | Unknown `detection_id` exits 2. `attack_ids` come from the catalog entry; a caller value that differs is reported as a mismatch. `severity` must equal the rule's `level` or is recorded as `severity_override` with both values. The original payload is carried through as `source_alert`. `docs/DESIGN.md` updated; a test per rejection |
| R14 | Compiler unit test and coverage floor | A unit test feeds a stub Falcon output without `#event_simpleName` and asserts `unsupported`; `--cov-fail-under=70` in CI |
| R4b | Gate publication on the quality workflow | A Pages deploy job that `needs:` all eight quality jobs; Pages source switched to "GitHub Actions" in repository settings (Owner action); wording restored to "CI gates publication" |

### Milestone C - isolated-VM validation

Who: Owner-gated. Effort: 2 to 4 focused days. The only milestone that changes the lifecycle. The procedure is `telemetry/atomic-test-plan.md`.

Claude Code can prepare, before any VM exists:

| ID | Item | Acceptance |
| --- | --- | --- |
| C1 | `scripts/ingest_vm_export.py`: load a Winlogbeat file export into the lab Elasticsearch through the Windows/Sysmon ingest pipelines, run one detection's compiled query, print hits against the expected event IDs | Works against a synthetic export shaped like Winlogbeat output |
| C2 | `scripts/sanitize_evidence.py`: apply the `evidence/README.md` rules to an export (hostnames, users, IPs, SIDs) and refuse to emit anything that looks like a dump path or a credential | Unit tests with seeded identifiers |
| C3 | `build_evidence_manifest.py` preserves `vm-telemetry` and `screenshot` rows (R11 depends on it) | `--check` stays green with a hand-added VM row |
| C4 | A matrix filler that writes the VM columns from a run record so the matrix is never hand-edited | Round-trips the current matrix unchanged |

Owner must:

| ID | Item |
| --- | --- |
| C5 | Build the disposable guest: Windows evaluation ISO on the `D:` drive, VirtualBox host-only network, `clean-base` and `sensors-installed` snapshots, a reviewed Sysmon configuration, audit policy, Winlogbeat with file output (plan, "Environment baseline") |
| C6 | Run the named Atomic tests, negative control first, per record; export; clean up; revert |
| C7 | Review the sanitised evidence before it is committed; dump files never leave the VM |
| C8 | Approve each promotion. The commit that promotes the last rule removes the inverted CI step and `test_vm_validated_gate_is_still_enforced`; partial promotion keeps both |
| C9 | Accept a partial or negative outcome as a publishable result |

### After completion (unscheduled)

Tracked in `docs/future-work.md`: a `pip-audit` CI job and a lock file; bump the two actions to their Node-24 majors; a GitHub Release for `v0.1.0`; vendor citations for the researched false positives; hand-written Falcon queries for DET-004/005; the DET-002 Sysmon-10 variant; the `ml/` baseline (after `validated`).

## Owner decisions and approvals

| # | Decision | Needed before |
| --- | --- | --- |
| 1 | Milestone A may run unattended, or Nick edits tone afterwards | A |
| 2 | R11 gate requirements as listed, or amended | B |
| 3 | R13 behaviour: reject unknown detections (default) or warn; record severity overrides (default) or reject them | B |
| 4 | Coverage floor value: 70 (default) | B |
| 5 | R4b: switch the Pages source to GitHub Actions (repository settings change) | B |
| 6 | Windows evaluation build and Sysmon configuration for the guest | C |
| 7 | Run the tests and review the sanitised evidence | C |
| 8 | Approve each promotion to `validated` | C |

## Hosting decision

Use GitHub Pages only. Vercel adds no value, and Replit would encourage a fake interactive SIEM surface. Do not expose Elasticsearch/Kibana, Falcon, a webhook sink, or any laboratory host to the internet.

## Site content policy

The published site contains no payload binaries, no execution path, no secrets, and no raw host telemetry. It does link the synthetic fixtures, which carry Atomic-derived command-line shapes; those are detection test data, not tooling, and appear in the public Atomic Red Team catalog.

## Known dependency boundary

The 2026-09-02 local `pip-audit` pass found `PYSEC-2026-2447` in pySigma's
`diskcache==5.6.3` dependency; no fixed release was listed. The issue requires an attacker
to write a cache directory that a victim later deserializes. This repository does not call
DiskCache directly, persist a shared cache, or deploy the compiler as a service; CI runs in
an ephemeral workspace. Keep the exact pySigma toolchain pinned for compiled-query
reproducibility, monitor upstream for a fixed release, and do not use attacker-writable cache
state. This is a bounded acceptance, not a claim that the dependency has no vulnerability.

## Stop conditions

- Never execute Atomic tests on the host or a non-disposable machine.
- Never infer production false-positive rates from fixtures.
- Never publish raw host telemetry, dump files, or secrets.
- Never promote to `validated` as polish; Milestone B lands before the first promotion.
- Keep the inverted CI step and its test until the last rule is promoted.
- Do not add an ML detector before the base telemetry validation gate.

## Verification before changing status

Run the repository quality checks, compile all supported targets, validate catalog/evidence drift, secret-scan tracked files, and inspect the published site logged out. A green CI run proves repository automation, not real endpoint validation.
