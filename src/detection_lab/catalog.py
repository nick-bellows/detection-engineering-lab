"""Detection lifecycle catalog: schema, gates, and validation.

``detections/catalog.yml`` is the source of truth for each detection's state.
Lifecycle and gates are defined in ``docs/DESIGN.md``; the two gates here are
``strict`` (>= fixture-validated) and ``require_validated`` (VM-validated, expected
to fail until the isolated-VM run, which a test asserts).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
CATALOG_PATH = ROOT / "detections" / "catalog.yml"
FIXTURE_ROOT = ROOT / "tests" / "fixtures" / "telemetry"

STATUS_ORDER: tuple[str, ...] = (
    "planned",
    "implemented",
    "fixture-validated",
    "validated",
    "retired",
)
STATUS_RANK = {status: rank for rank, status in enumerate(STATUS_ORDER)}
COMPILE_TARGETS: tuple[str, ...] = ("elastic", "crowdstrike_logscale")
UNSUPPORTED = "unsupported"
EXPECTED_DETECTION_COUNT = 5

DETECTION_ID = re.compile(r"^DET-\d{3}$")
ATTACK_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
FIXTURE_ID = re.compile(r"^FIX-DET-\d{3}-(POS|NEG)$")


def load_catalog(path: Path = CATALOG_PATH) -> dict[str, Any]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TypeError(f"catalog at {path} is not a mapping")
    return payload


def rule_false_positives(detection_id: str, path: Path = CATALOG_PATH) -> tuple[str, ...]:
    """The `falsepositives` list from the detection's own Sigma rule (empty if unknown)."""
    for item in load_catalog(path).get("detections", []):
        rule_path = item.get("rule_path")
        if item.get("detection_id") == detection_id and isinstance(rule_path, str):
            rule = yaml.safe_load((ROOT / rule_path).read_text(encoding="utf-8")) or {}
            return tuple(str(fp) for fp in rule.get("falsepositives", []))
    return ()


def fixture_path(detection_id: str, kind: str) -> Path:
    """Path convention for telemetry fixtures: tests/fixtures/telemetry/<DET>/<kind>.ndjson."""
    return FIXTURE_ROOT / detection_id / f"{kind}.ndjson"


def _rank(status: object) -> int:
    return STATUS_RANK.get(str(status), -1)


def _check_fixture_validated(item: dict[str, Any], detection_id: str, errors: list[str]) -> None:
    for kind, field in (("positive", "positive_fixture_id"), ("negative", "negative_fixture_id")):
        fixture_id = item.get(field)
        if not isinstance(fixture_id, str) or not FIXTURE_ID.fullmatch(fixture_id):
            errors.append(
                f"{detection_id}: fixture-validated detection needs {field} (FIX-DET-NNN-POS/NEG)"
            )
            continue
        if fixture_id != f"FIX-{detection_id}-{'POS' if kind == 'positive' else 'NEG'}":
            errors.append(
                f"{detection_id}: {field} {fixture_id!r} does not belong to this detection"
            )
        if not fixture_path(detection_id, kind).is_file():
            errors.append(
                f"{detection_id}: missing fixture file {fixture_path(detection_id, kind)}"
            )
        meta = fixture_path(detection_id, "meta").with_suffix(".yml")
        if not meta.is_file():
            errors.append(f"{detection_id}: missing fixture metadata {meta}")

    compiled = item.get("compiled")
    if not isinstance(compiled, dict):
        errors.append(f"{detection_id}: fixture-validated detection needs a `compiled` mapping")
    else:
        for target in COMPILE_TARGETS:
            value = compiled.get(target)
            if value == UNSUPPORTED:
                continue
            if not isinstance(value, str) or not (ROOT / value).is_file():
                errors.append(
                    f"{detection_id}: compiled.{target} must be an existing path or {UNSUPPORTED!r}"
                )
        if compiled.get("elastic") == UNSUPPORTED:
            errors.append(
                f"{detection_id}: the Elastic target is the tested one and cannot be unsupported"
            )

    writeup = item.get("writeup_path")
    if not isinstance(writeup, str) or not (ROOT / writeup).is_file():
        errors.append(f"{detection_id}: fixture-validated detection needs an existing writeup_path")


def validate_catalog(
    *,
    strict: bool = False,
    require_validated: bool = False,
    path: Path = CATALOG_PATH,
) -> list[str]:
    """Return a list of problems; an empty list means the catalog passes the requested gate."""
    payload = load_catalog(path)
    errors: list[str] = []
    seen_detection_ids: set[str] = set()
    seen_attack_ids: set[str] = set()
    detections = payload.get("detections", [])
    if len(detections) != EXPECTED_DETECTION_COUNT:
        errors.append(
            f"expected {EXPECTED_DETECTION_COUNT} portfolio detections, found {len(detections)}"
        )
    for item in detections:
        detection_id = str(item.get("detection_id", ""))
        attack_id = str(item.get("attack_id", ""))
        status = item.get("status")
        if not DETECTION_ID.fullmatch(detection_id):
            errors.append(f"invalid detection ID: {detection_id!r}")
        if detection_id in seen_detection_ids:
            errors.append(f"duplicate detection ID: {detection_id}")
        seen_detection_ids.add(detection_id)
        if not ATTACK_ID.fullmatch(attack_id):
            errors.append(f"{detection_id}: invalid ATT&CK ID {attack_id!r}")
        if attack_id in seen_attack_ids:
            errors.append(f"duplicate ATT&CK ID: {attack_id}")
        seen_attack_ids.add(attack_id)
        if status not in STATUS_RANK:
            errors.append(f"{detection_id}: invalid status {status!r}")
            continue
        rank = _rank(status)
        if rank >= STATUS_RANK["implemented"]:
            rule_path = item.get("rule_path")
            if not isinstance(rule_path, str) or not (ROOT / rule_path).is_file():
                errors.append(f"{detection_id}: {status} detection requires an existing rule_path")
        if rank >= STATUS_RANK["fixture-validated"]:
            _check_fixture_validated(item, detection_id, errors)
        if status == "validated":
            for field in ("positive_test_id", "negative_test_id"):
                if not item.get(field):
                    errors.append(f"{detection_id}: validated detection missing {field}")
            if not item.get("evidence_ids"):
                errors.append(f"{detection_id}: validated detection missing evidence IDs")
        if strict and rank < STATUS_RANK["fixture-validated"]:
            errors.append(f"{detection_id}: strict gate requires at least fixture-validated status")
        if require_validated and status != "validated":
            errors.append(f"{detection_id}: VM-validated gate requires validated status")
    if (strict or require_validated) and str(payload.get("attack_version", "")).startswith(
        "INPUT_REQUIRED"
    ):
        errors.append("release gates require a verified ATT&CK version")
    return errors
