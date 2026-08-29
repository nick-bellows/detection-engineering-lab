$ErrorActionPreference = "Stop"

# Mirrors .github/workflows/quality.yml job for job. The `siem` step needs the lab
# Elasticsearch: `docker compose -f lab/compose.yml up -d` and lab/.env first.

ruff check src tests scripts
ruff format --check src tests scripts
mypy src
pytest --cov=detection_lab --cov-report=term-missing
python scripts/compile_rules.py --check
python scripts/render_status_svg.py --check
python scripts/validate_catalog.py --strict
python scripts/build_evidence_manifest.py --check

# The VM-validated gate must still fail (no Atomic run yet); mirror the CI assertion.
python scripts/validate_catalog.py --require-validated
if ($LASTEXITCODE -eq 0) { throw "--require-validated passed without VM evidence" }

if ($env:DETECTION_LAB_ES_URL) {
    python scripts/wait_for_es.py
    pytest -m siem
} else {
    Write-Host "DETECTION_LAB_ES_URL not set; skipping the live-SIEM tests (pytest -m siem)."
}

