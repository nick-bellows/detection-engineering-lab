# How this lab is built and gated

The one place the lifecycle, the compile targets, the validation matrix, and the enrichment
contract are defined. The README points here rather than restating any of it.

## Lifecycle

`catalog.yml` is the source of truth for a detection's state. The states, in order:

| State | Means |
| --- | --- |
| `planned` | Hypothesis and telemetry requirements are not finalised. |
| `implemented` | The Sigma source rule exists and compiles. |
| `fixture-validated` | The compiled Elastic query returned the positive fixture and stayed silent on the negative-control fixture on a **live Elasticsearch**, both fixtures labelled synthetic. Says nothing about telemetry generation on a real host. |
| `validated` | The Atomic Red Team test ran in an isolated VM, the source event was ingested, the alert fired, the negative control did not, and sanitised evidence is retained. |
| `retired` | Kept for history, excluded from deployment. |

Two gates enforce the boundary between "the query works" and "the telemetry was generated":

- `python scripts/validate_catalog.py --strict` — every detection is at least `fixture-validated`:
  a rule file, both compile targets (or a recorded gap), both fixtures with metadata, a write-up,
  and a resolved ATT&CK version.
- `python scripts/validate_catalog.py --require-validated` — every detection is `validated`. This
  is expected to fail until the isolated-VM run happens, and `tests/test_catalog.py` asserts that it
  fails, so the boundary cannot be erased by accident. The CI `catalog` job inverts its exit code.

## Compile targets

Rules live in `detections/rules/` as `det-NNN-<slug>.yml` (the compiler derives `DET-NNN` from the
filename). `python scripts/compile_rules.py` regenerates `detections/compiled/`; CI fails on drift.

| Target | Pipeline | Executed against telemetry? |
| --- | --- | --- |
| Elastic — Lucene, DSL, Kibana SIEM rule | `sysmon_pipeline() + ecs_windows()` | Yes — `tests/live/test_siem.py` |
| CrowdStrike LogScale — CQL | `crowdstrike_falcon_pipeline()` | No — compiled only; there is no LogScale instance in the lab |

When the Falcon pipeline has no mapping for a logsource it passes the Windows field names through
untouched. The compiler treats a query without `#event_simpleName` as **unsupported** and records
the reason in `detections/compiled/manifest.json` rather than committing a query that could never
match. That is why LogScale coverage is 3 of 5 (`registry_set` and Security 4624 have no mapping).

## Validation matrix

`telemetry/validation-matrix.csv` has one row per detection, in two column groups that must not be
confused:

- **Fixture columns** (`positive_fixture_id` … `fixture_validated_on`) are filled — the evidence
  behind `fixture-validated`.
- **VM columns** (`atomic_test_id`, `host_snapshot`, `sensor_config_id`, `alert_observed_on_host`,
  `validated_on`) are `INPUT_REQUIRED_VM_RUN` / `not_run`; only the isolated-VM run
  (`telemetry/atomic-test-plan.md`) fills them. `atomic_accessed_on` records when the Atomic catalog
  was read to pick the tests, not a run.

Before a detection may become `validated`, its VM run must record: the audit policy and sensor
configuration; host and sensor versions; source event IDs and field mapping; the Atomic test ID and
access date; preconditions, expected artefacts, cleanup and rollback; the positive-test timestamp
window; the negative-control definition; SIEM ingestion confirmation; and the sanitised fixture and
evidence IDs. An absent alert only means something if the source event was actually generated and
ingested.

## Change workflow

1. Create or update the Sigma source rule and record the reason and expected behaviour change.
2. `scripts/compile_rules.py` to regenerate both targets; inspect the queries.
3. Replay the sanitised positive and negative fixtures (`pytest -m siem`).
4. Re-run the controlled VM test when the source-telemetry assumptions changed.
5. Update the write-up, `catalog.yml`, and the validation matrix.
6. Retire rather than silently delete a detection: record its replacement, the reason, the last
   validated version, and any coverage gap introduced.

Review each rule against: which exact source events and fields it needs; whether the logic keys on
malicious behaviour rather than a common tool name; what benign admin or software produces similar
events; whether a nearby representation bypasses it; and whether the alert carries host, user,
process lineage, and a usable next step.

## Alert enrichment

`detection-lab triage <alert.json>` validates the alert against `automation/triage-contract.json`
and returns an analyst-ready record: a transparent priority score, the ATT&CK technique context
(name, tactics, URL, version), the rule's own `falsepositives` list, and recommended first checks. It
preserves the original alert and its enrichment version, and takes **no** automated response
action — it never contains, disables, or blocks an account. It is a SOAR-shaped contract, not an
incident-response platform.
