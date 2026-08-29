from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from detection_lab.attack import technique
from detection_lab.catalog import rule_false_positives

Severity = Literal["low", "medium", "high", "critical"]


@dataclass(frozen=True, slots=True)
class Alert:
    alert_id: str
    detection_id: str
    title: str
    severity: Severity
    host: str
    user: str
    attack_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class TechniqueContext:
    id: str
    name: str
    tactics: tuple[str, ...]
    url: str
    attack_version: str


@dataclass(frozen=True, slots=True)
class EnrichedAlert:
    alert: Alert
    priority_score: int
    reasons: tuple[str, ...]
    recommended_checks: tuple[str, ...]
    attack_context: tuple[TechniqueContext, ...] = ()
    known_false_positives: tuple[str, ...] = ()
    enrichment_version: str = "0.2.0"


SEVERITY_SCORE: dict[Severity, int] = {
    "low": 20,
    "medium": 40,
    "high": 65,
    "critical": 85,
}


def enrich_alert(
    alert: Alert,
    *,
    critical_hosts: set[str] | None = None,
    privileged_users: set[str] | None = None,
) -> EnrichedAlert:
    """Add transparent context; no automated response action is taken.

    The priority score is deliberately simple and fully explained by ``reasons``. The
    ATT&CK context comes from the bundled technique table and the false-positive list
    from the detection's own Sigma rule, so the analyst sees what the rule author
    already expected to be noisy.
    """

    score = SEVERITY_SCORE[alert.severity]
    reasons = [f"base severity: {alert.severity}"]
    if alert.host in (critical_hosts or set()):
        score += 10
        reasons.append("critical asset context")
    if alert.user in (privileged_users or set()):
        score += 10
        reasons.append("privileged identity context")
    score = min(score, 100)

    context: list[TechniqueContext] = []
    for attack_id in alert.attack_ids:
        found = technique(attack_id)
        if found is None:
            reasons.append(f"no bundled ATT&CK context for {attack_id}")
            continue
        context.append(
            TechniqueContext(
                id=found.id,
                name=found.name,
                tactics=found.tactics,
                url=found.url,
                attack_version=found.attack_version,
            )
        )

    checks = (
        "Confirm the source event and process/user timeline.",
        "Review related alerts on the same host and identity.",
        "Validate whether the activity matches an approved administrative change.",
        "Compare against the rule's known false positives before escalating.",
    )
    return EnrichedAlert(
        alert=alert,
        priority_score=score,
        reasons=tuple(reasons),
        recommended_checks=checks,
        attack_context=tuple(context),
        known_false_positives=rule_false_positives(alert.detection_id),
    )
