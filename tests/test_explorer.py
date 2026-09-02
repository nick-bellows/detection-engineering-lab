from __future__ import annotations

from detection_lab.explorer import OUTPUT, render_explorer


def test_explorer_contains_every_detection_and_evidence_boundary() -> None:
    markup = render_explorer()
    for number in range(1, 6):
        assert f"DET-{number:03d}" in markup
    assert markup.count('class="detection"') == 5
    assert "fixture-validated means" in markup
    assert "no production false-positive rate is claimed" in markup
    assert "VM validation remains pending" in markup


def test_explorer_links_source_compiled_fixture_and_validation_evidence() -> None:
    markup = render_explorer()
    assert "detections/rules/det-001" in markup
    assert "detections/compiled/elastic/DET-001.lucene" in markup
    assert "tests/fixtures/telemetry/DET-001/positive.ndjson" in markup
    assert "tests/live/test_siem.py" in markup
    assert "evidence/evidence-manifest.csv" in markup
    assert "recorded gap" in markup


def test_committed_explorer_matches_sources() -> None:
    assert OUTPUT.read_text(encoding="utf-8") == render_explorer()
