# Isolated detection lab

`compose.yml` provides a localhost-bound Elasticsearch (and, behind the `ui` profile, Kibana). It
does not create or secure the Windows telemetry VM — that is the step to `validated`, described in
`../telemetry/atomic-test-plan.md`.

## Pinned images (verified 2026-08-29)

| Image | Digest |
| --- | --- |
| `docker.elastic.co/elasticsearch/elasticsearch:8.19.20` | `sha256:e4797708584bd0df7c746b33a6640d243018a0ae8c8b088391c6f4675a3bef52` |
| `docker.elastic.co/kibana/kibana:8.19.20` | `sha256:bdbe9b2af8d999919475effb0d65c00e993f2898dd13aebe98c76882c53bb13b` |

`STACK_VERSION` in `.env` selects the tag; compare `docker images --digests` with the table before
trusting a fresh pull.

## Start

```powershell
Copy-Item lab/.env.example lab/.env          # lab-only passwords; .env is gitignored
docker compose -f lab/compose.yml up -d      # Elasticsearch only
$env:DETECTION_LAB_ES_URL = "http://127.0.0.1:9200"
$env:DETECTION_LAB_ES_PASSWORD = (Get-Content lab/.env | Select-String '^ELASTIC_PASSWORD=').ToString().Split('=')[1]
python scripts/wait_for_es.py
pytest -m siem
```

Ports bind to `127.0.0.1` only. Security is on (basic auth as `elastic`) with TLS explicitly
disabled on the HTTP layer — right for a disposable loopback lab, wrong for anything shared.

Data lives in the named volume `detection-lab-es-data`, not a host bind mount: on Docker Desktop
for Windows a bind mount fails Lucene's segment refresh with `AccessDeniedException` and every shard
goes `UNASSIGNED` after the first bulk index (found 2026-08-29). Reset with
`docker compose -f lab/compose.yml down -v`.

## Kibana (optional)

```powershell
docker compose -f lab/compose.yml --profile ui up -d
```

Kibana needs the `kibana_system` password set to `KIBANA_PASSWORD` first
(`POST /_security/user/kibana_system/_password` as `elastic`). That step is documented rather than
scripted because it is not on the test path; the committed `detections/compiled/elastic/*.siem_rule.ndjson`
files are the artefacts you would import into Security → Rules.

## What the fixture index is

`index-mapping.json` is the body `tests/live/test_siem.py` creates the fixture index with. Field
names follow ECS as the Elastic Windows/Sysmon integrations ship them. One deliberate divergence:
the string fields Sigma `contains` targets (command lines, registry paths and data,
`winlog.event_data.*`) are keyword fields with a lowercase normalizer so the compiled Lucene query
keeps Sigma's case-insensitive semantics. The stock integration maps `process.command_line` as
`wildcard` (case-sensitive); `test_case_variants_depend_on_the_index_mapping` shows what that costs.

## Before the VM step

1. Create an isolated Windows VM with no bridged access to production networks.
2. Snapshot the clean VM before installing Sysmon (a reviewed configuration) and a shipper.
3. Document the Windows build, audit policy, Sysmon configuration, collector, and time sync.
4. Decide how the VM reaches only the lab Elasticsearch.
5. Run one Atomic test per detection from `telemetry/atomic-test-plan.md`, export the events,
   sanitise, hash into `evidence/`, and fill the VM columns of `telemetry/validation-matrix.csv`.

## Teardown

`docker compose -f lab/compose.yml stop` keeps the volume; `down -v` removes it. Preserve anything
the validation matrix or evidence manifest references before removing state.
