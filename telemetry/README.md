# Telemetry workspace

`raw/` and `normalized/` are ignored. Public fixtures are synthetic and live under
`tests/fixtures/telemetry/<DET-ID>/` with a `meta.yml` that records the sensor assumption, the
Atomic Red Team tests whose command shapes the events model, and the notes a reviewer needs.

## validation-matrix.csv

One row per detection. The columns split into two groups that must not be confused:

- **Fixture columns** (`positive_fixture_id` … `fixture_validated_on`) are filled. They record the
  live-Elasticsearch run of the compiled query against the synthetic fixtures — the evidence behind
  the `fixture-validated` status.
- **VM columns** (`atomic_test_id`, `host_snapshot`, `sensor_config_id`, `alert_observed_on_host`,
  `validated_on`) are `INPUT_REQUIRED_VM_RUN` / `not_run`. They can only be filled by executing the
  Atomic tests in an isolated VM and exporting the resulting events (`atomic-test-plan.md`). The
  `atomic_accessed_on` date records when the Atomic catalog was read to pick the tests, not a run.

`python scripts/validate_catalog.py --require-validated` fails until the VM columns are real, and
`tests/test_catalog.py::test_vm_validated_gate_is_still_enforced` asserts that it does.

## Required per detection before `validated`

- Audit policy and sensor configuration
- Host and sensor version
- Source event identifiers and field mapping
- Atomic test identifier and access date
- Preconditions, expected artifacts, cleanup, and rollback
- Positive test timestamp window
- Negative control definition
- SIEM ingestion/index confirmation
- Sanitized fixture and evidence identifiers

If the source event was not generated or ingested, an absent alert does not establish that the rule
failed.
