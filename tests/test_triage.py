from detection_lab.automation import Alert, enrich_alert


def test_enrichment_is_transparent_and_bounded() -> None:
    alert = Alert(
        alert_id="SYN-ALERT-001",
        detection_id="DET-001",
        title="Synthetic behavior alert",
        severity="medium",
        host="LAB-WIN-01",
        user="LAB\\synthetic-admin",
        attack_ids=("T1059.001",),
    )
    enriched = enrich_alert(
        alert,
        critical_hosts={"LAB-WIN-01"},
        privileged_users={"LAB\\synthetic-admin"},
    )
    assert enriched.priority_score == 60
    assert "critical asset context" in enriched.reasons
    assert "privileged identity context" in enriched.reasons
    assert enriched.recommended_checks


def test_enrichment_does_not_exceed_100() -> None:
    alert = Alert("A", "DET-001", "Synthetic", "critical", "H", "U")
    assert enrich_alert(alert, critical_hosts={"H"}, privileged_users={"U"}).priority_score == 100
