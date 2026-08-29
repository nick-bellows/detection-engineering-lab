# Validation log

A check that has never failed proves nothing. This log records, per gate, the deliberate
mutation that made it fail and the restored result. Dates are UTC.

## 2026-08-29 — first fixture-validated run

Environment: Elasticsearch 8.19.20 (`sha256:e4797708…bef52`) in `lab/compose.yml`, Python 3.13.7,
pySigma 1.5.0 / backend-elasticsearch 2.1.1 / backend-crowdstrike 3.0.0 / pipeline-sysmon 2.0.0 /
pipeline-windows 2.0.0.

| Gate | Baseline | Mutation | Observed | Restored |
| --- | --- | --- | --- | --- |
| `test_query_returns_exactly_its_own_positives[DET-002]` | pass | Rule: `MiniDump` → `MiniDumpX`, recompiled | **fail** — `DET-002 missed positives: ['FIX-DET-002-POS-08']` | pass |
| `test_query_returns_exactly_its_own_positives[DET-002]` and `test_no_negative_control_fires_anywhere` | pass | Negative control 1: `-ma notepad.exe` → `-ma lsass.exe` | **fail** — `DET-002 fired on negatives: ['FIX-DET-002-NEG-11']` (2 tests red) | pass |
| `compile_rules.py --check` | pass | Rule `level: critical` → `high` without recompiling | **fail** — `DRIFT: differs: manifest.json` | pass |
| `test_case_variants_depend_on_the_index_mapping` | pass | (no mutation needed — the test itself asserts a miss on the stock mapping) | pass: uppercase `-ENC` and `/Create` fixtures hit on the lab mapping and miss on `wildcard` | — |

Final state after restoration: `pytest -m siem` → 8 passed; `compile_rules.py --check` → clean.

## Defects found on the way

1. **Falcon pipeline silently passes unmapped logsources through.** First compile produced
   `TargetObject=… Details=…` and `EventID=4624 LogonType=10` as "LogScale queries" for DET-004 and
   DET-005 — Windows field names with no `#event_simpleName` filter. The compiler now treats a
   query without that marker as `unsupported` and records the reason in `compiled/manifest.json`.
   Result: 3/5 rules compile to LogScale, honestly.
2. **`-` in the DET-005 IP filter would have broken the query.** Winlogbeat drops `IpAddress: -`
   before `source.ip`, and a `-` term against an `ip` field is a parse error. Removed from the Sigma
   source with the reason in the rule description.
3. **Bind-mounted Elasticsearch data on Docker Desktop for Windows.** Every shard went `UNASSIGNED`
   after the first bulk index with `AccessDeniedException` on segment refresh. Switched the lab to a
   named volume; the CI path (service container) was never affected.
4. **Readiness is not "port open".** A fresh 8.x node returns 401 for a few seconds while it
   bootstraps its security index; `scripts/wait_for_es.py` waits for an authenticated 200.
5. **Stale compiled files survived a recompile.** `write_outputs` now removes anything under
   `detections/compiled/` that the current compile does not own, so the drift check and the
   committed tree agree.
