$ErrorActionPreference = "Stop"

# Mirrors .github/workflows/quality.yml job for job. The `siem` step needs the lab
# Elasticsearch: `docker compose -f lab/compose.yml up -d` and lab/.env first.
#
# Windows PowerShell does not stop on a native command's non-zero exit code, so every
# step checks $LASTEXITCODE itself and the first failure stops the script by name.

function Invoke-Step {
    param([Parameter(Mandatory)][string]$Command)
    Write-Host ""
    Write-Host ">> $Command"
    Invoke-Expression $Command
    if ($LASTEXITCODE -ne 0) { throw "FAILED (exit $LASTEXITCODE): $Command" }
}

Invoke-Step "ruff check src tests scripts"
Invoke-Step "ruff format --check src tests scripts"
Invoke-Step "mypy src"
Invoke-Step "pytest --cov=detection_lab --cov-report=term-missing"
Invoke-Step "python scripts/compile_rules.py --check"
Invoke-Step "python scripts/render_status_svg.py --check"
Invoke-Step "python scripts/render_explorer.py --check"
Invoke-Step "python scripts/validate_catalog.py --strict"
Invoke-Step "python scripts/build_evidence_manifest.py --check"

# The VM-validated gate must still fail (no Atomic run yet); mirror the CI assertion.
Write-Host ""
Write-Host ">> python scripts/validate_catalog.py --require-validated   (expected to FAIL)"
python scripts/validate_catalog.py --require-validated
if ($LASTEXITCODE -eq 0) { throw "--require-validated passed without VM evidence" }
Write-Host "OK: the VM-validated gate still fails, as it must until the isolated-VM run."

if ($env:DETECTION_LAB_ES_URL) {
    Invoke-Step "python scripts/wait_for_es.py"
    Invoke-Step "pytest -m siem"
} else {
    Write-Host ""
    Write-Host "DETECTION_LAB_ES_URL not set; skipping the live-SIEM tests (pytest -m siem)."
}

Write-Host ""
Write-Host "All local checks passed."
exit 0
