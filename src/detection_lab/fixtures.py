"""Synthetic telemetry fixtures: ECS-shaped documents under tests/fixtures/telemetry/.

Every document carries a ``labels`` block naming the fixture, the detection it
belongs to, whether it is a positive or a negative control, and a short case name.
The per-detection ``meta.yml`` records the sensor assumption, the Atomic Red Team
tests whose command shapes the events model, and the notes a reviewer needs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from detection_lab.catalog import FIXTURE_ROOT

KINDS: tuple[str, ...] = ("positive", "negative")


@dataclass(frozen=True, slots=True)
class FixtureDoc:
    detection_id: str
    fixture_id: str
    expected: str  # positive | negative
    case: str
    doc_id: str
    body: dict[str, Any]


def load_fixture_docs(root: Path = FIXTURE_ROOT) -> list[FixtureDoc]:
    docs: list[FixtureDoc] = []
    for det_dir in sorted(root.glob("DET-*")):
        for kind in KINDS:
            path = det_dir / f"{kind}.ndjson"
            if not path.is_file():
                continue
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                body = json.loads(line)
                labels = body["labels"]
                if labels["expected"] != kind:
                    raise ValueError(f"{path}: label {labels['expected']!r} in a {kind} file")
                if labels["detection_id"] != det_dir.name:
                    raise ValueError(f"{path}: detection_id {labels['detection_id']!r}")
                docs.append(
                    FixtureDoc(
                        detection_id=str(labels["detection_id"]),
                        fixture_id=str(labels["fixture_id"]),
                        expected=str(labels["expected"]),
                        case=str(labels["case"]),
                        doc_id=str(labels["doc_id"]),
                        body=body,
                    )
                )
    return docs


__all__ = ["KINDS", "FixtureDoc", "load_fixture_docs"]
