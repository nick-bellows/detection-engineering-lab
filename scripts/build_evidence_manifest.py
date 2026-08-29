"""Regenerate evidence/evidence-manifest.csv from the artefacts the catalog points at.

    python scripts/build_evidence_manifest.py            rewrite the manifest
    python scripts/build_evidence_manifest.py --check    fail if any hash or row differs

Every fixture-validated detection contributes its Sigma rule, its compiled Elastic query,
its compiled LogScale query when one exists, and both telemetry fixtures. Rows of type
`ci-run` (a URL, no hash) are preserved from the existing manifest because they are added
by hand after a green run.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import sys
from datetime import UTC, datetime
from pathlib import Path

from detection_lab.catalog import ROOT, UNSUPPORTED, fixture_path, load_catalog

MANIFEST = ROOT / "evidence" / "evidence-manifest.csv"
FIELDS = [
    "evidence_id",
    "detection_id",
    "captured_at_utc",
    "type",
    "sanitized_path",
    "description",
    "sha256",
    "reviewed",
]


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def existing_rows() -> list[dict[str, str]]:
    if not MANIFEST.is_file():
        return []
    with MANIFEST.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def generated_rows(captured_at: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for item in load_catalog().get("detections", []):
        det = str(item["detection_id"])
        if str(item.get("status")) not in {"fixture-validated", "validated"}:
            continue
        artefacts: list[tuple[str, str, Path, str]] = [
            ("RULE", "sigma-rule", ROOT / str(item["rule_path"]), "Sigma source rule"),
            (
                "LUCENE",
                "compiled-query",
                ROOT / str(item["compiled"]["elastic"]),
                "Elastic Lucene query compiled by pySigma (sysmon + ecs_windows pipelines)",
            ),
            (
                "FIX-POS",
                "telemetry-fixture",
                fixture_path(det, "positive"),
                "Synthetic positive events (ECS-shaped); proven to match on live Elasticsearch",
            ),
            (
                "FIX-NEG",
                "telemetry-fixture",
                fixture_path(det, "negative"),
                "Synthetic negative-control events; proven silent on live Elasticsearch",
            ),
        ]
        logscale = item["compiled"].get("crowdstrike_logscale")
        if isinstance(logscale, str) and logscale != UNSUPPORTED:
            artefacts.insert(
                2,
                (
                    "CQL",
                    "compiled-query",
                    ROOT / logscale,
                    "CrowdStrike LogScale query compiled by pySigma (falcon pipeline); not executed",
                ),
            )
        for suffix, kind, path, description in artefacts:
            rows.append(
                {
                    "evidence_id": f"EV-{det}-{suffix}",
                    "detection_id": det,
                    "captured_at_utc": captured_at,
                    "type": kind,
                    "sanitized_path": path.relative_to(ROOT).as_posix(),
                    "description": description,
                    "sha256": sha256_of(path),
                    "reviewed": "yes",
                }
            )
    return rows


def render(rows: list[dict[str, str]]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=FIELDS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def merged_rows(captured_at: str | None) -> list[dict[str, str]]:
    current = existing_rows()
    by_id = {row["evidence_id"]: row for row in current}
    kept = [row for row in current if row["type"] == "ci-run"]
    stamp = captured_at or datetime.now(UTC).strftime("%Y-%m-%dT%H:%MZ")
    fresh = []
    for row in generated_rows(stamp):
        previous = by_id.get(row["evidence_id"])
        if previous and previous["sha256"] == row["sha256"]:
            row["captured_at_utc"] = previous[
                "captured_at_utc"
            ]  # unchanged artefact keeps its date
        fresh.append(row)
    return fresh + kept


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the evidence manifest")
    parser.add_argument("--check", action="store_true", help="fail if the manifest is stale")
    parser.add_argument("--captured-at", help="override the capture timestamp (UTC)")
    args = parser.parse_args()
    text = render(merged_rows(args.captured_at))
    if args.check:
        current = MANIFEST.read_text(encoding="utf-8") if MANIFEST.is_file() else ""
        if current != text:
            print("Evidence manifest is stale; run `python scripts/build_evidence_manifest.py`.")
            return 1
        print("Evidence manifest matches the artefacts.")
        return 0
    MANIFEST.write_text(text, encoding="utf-8", newline="\n")
    print(f"Wrote {MANIFEST.relative_to(ROOT)} ({text.count(chr(10)) - 1} rows).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
