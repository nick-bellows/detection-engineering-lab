# Detection lifecycle

## File naming

Rules live in `rules/` as `det-NNN-<slug>.yml` (the compiler derives `DET-NNN` from the
filename). `catalog.yml` is the source of truth for lifecycle status and validation references;
`compiled/` holds the pySigma output for each target and is regenerated with
`python scripts/compile_rules.py` (CI fails on drift).

## Statuses

- `planned`: hypothesis and telemetry requirements are not finalized.
- `implemented`: source rule exists and compiles.
- `fixture-validated`: the compiled Elastic query returned the positive fixture and stayed silent on
  the negative-control fixture on a **live Elasticsearch**, with both fixtures labelled synthetic.
  Says nothing about telemetry generation on a real host.
- `validated`: the Atomic Red Team test ran in an isolated VM, the resulting source event was
  ingested, the alert fired, the negative control did not, and sanitised evidence is retained.
- `retired`: retained for history and excluded from deployment.

`python scripts/validate_catalog.py --strict` gates on `fixture-validated`;
`--require-validated` gates on `validated` and is expected to fail until the VM run happens.

## Compile targets

| Target | Pipeline | Executed? |
| --- | --- | --- |
| Elastic (Lucene, DSL, Kibana SIEM rule) | `sysmon_pipeline() + ecs_windows()` | Yes — `tests/live/test_siem.py` |
| CrowdStrike LogScale (CQL) | `crowdstrike_falcon_pipeline()` | No — compiled only; no LogScale in the lab |

When the Falcon pipeline has no mapping for a logsource it passes Windows field names through
untouched. The compiler treats a query without `#event_simpleName` as **unsupported** and records
the reason in `compiled/manifest.json` instead of committing a query that could never match.

## Review questions

1. Which exact source events and fields are required?
2. Is the logic tied to malicious behavior or merely a common tool/process name?
3. What benign administrators or software produce similar events?
4. Can the rule be bypassed through a nearby representation?
5. Does the alert include host, user, process lineage, and a usable next step?
