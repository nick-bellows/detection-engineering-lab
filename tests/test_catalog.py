from pathlib import Path

import pytest

from detection_lab.catalog import STATUS_ORDER, validate_catalog


def test_catalog_is_structurally_valid() -> None:
    assert validate_catalog() == []


def test_strict_gate_passes_for_fixture_validated_portfolio() -> None:
    # Every detection has a rule, both compile targets (or a recorded gap), both
    # fixtures, a writeup, and a resolved ATT&CK version.
    assert validate_catalog(strict=True) == []


def test_vm_validated_gate_is_still_enforced() -> None:
    # The Atomic-in-VM run has not happened. If this ever passes without evidence
    # rows and Atomic test IDs in the catalog, the boundary has been erased.
    errors = validate_catalog(require_validated=True)
    assert errors
    assert all("VM-validated gate" in e for e in errors)


def test_lifecycle_order_is_explicit() -> None:
    assert STATUS_ORDER.index("fixture-validated") < STATUS_ORDER.index("validated")


@pytest.mark.parametrize(
    ("mutation", "expected_fragment"),
    [
        ("status: fixture-validated\n    rule_path: null", "requires an existing rule_path"),
        ("compiled:\n      elastic: unsupported", "cannot be unsupported"),
    ],
)
def test_gate_rejects_broken_entries(tmp_path: Path, mutation: str, expected_fragment: str) -> None:
    # Mutate the real catalog and confirm the validator objects. A gate that never
    # fails is not a gate.
    source = Path(__file__).resolve().parents[1] / "detections" / "catalog.yml"
    text = source.read_text(encoding="utf-8")
    key, _, replacement = mutation.partition("\n")
    assert key in text, f"mutation target {key!r} not found; the test is stale"
    if replacement:
        # Replace the first line matching `key` and the line after it.
        head, _, tail = text.partition(key)
        tail = tail.split("\n", 2)[2] if tail.count("\n") >= 2 else ""
        text = head + mutation + "\n" + tail
    else:
        text = text.replace(key, mutation, 1)
    broken = tmp_path / "catalog.yml"
    broken.write_text(text, encoding="utf-8")
    errors = validate_catalog(strict=True, path=broken)
    assert any(expected_fragment in e for e in errors), errors
