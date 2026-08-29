import json
from pathlib import Path

import pytest

from detection_lab.cli import EXIT_INVALID_INPUT, main

FIXTURE_ALERT = Path(__file__).resolve().parent / "fixtures" / "alerts" / "synthetic_alert.json"


def test_triage_prints_enriched_record(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["triage", str(FIXTURE_ALERT), "--critical-host", "LAB-WIN-01"])
    assert code == 0
    record = json.loads(capsys.readouterr().out)
    assert record["alert"]["alert_id"] == "SYN-ALERT-001"
    assert record["priority_score"] == 50  # medium 40 + critical asset 10
    assert record["attack_context"][0]["id"] == "T1059.001"
    assert record["attack_context"][0]["attack_version"] == "19.2"
    # The rule's own falsepositives travel with the alert so the analyst sees them.
    assert any("encoded" in fp.lower() for fp in record["known_false_positives"])
    assert record["enrichment_version"] == "0.2.0"


def test_triage_rejects_alert_missing_required_field(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    broken = json.loads(FIXTURE_ALERT.read_text(encoding="utf-8"))
    del broken["host"]
    path = tmp_path / "broken.json"
    path.write_text(json.dumps(broken), encoding="utf-8")
    assert main(["triage", str(path)]) == EXIT_INVALID_INPUT
    assert "invalid alert" in capsys.readouterr().err


def test_triage_rejects_unknown_severity(tmp_path: Path) -> None:
    broken = json.loads(FIXTURE_ALERT.read_text(encoding="utf-8"))
    broken["severity"] = "urgent"
    path = tmp_path / "broken.json"
    path.write_text(json.dumps(broken), encoding="utf-8")
    assert main(["triage", str(path)]) == EXIT_INVALID_INPUT


def test_rules_lists_five_entries(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["rules"]) == 0
    out = capsys.readouterr().out
    assert out.count("DET-0") == 5
    assert "crowdstrike_logscale=unsupported" in out
    assert "attack_version=19.2" in out
