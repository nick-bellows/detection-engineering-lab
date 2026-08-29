import csv
import hashlib
from pathlib import Path

from detection_lab.catalog import ROOT, load_catalog

MANIFEST = ROOT / "evidence" / "evidence-manifest.csv"


def rows() -> list[dict[str, str]]:
    with MANIFEST.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def test_every_hashed_evidence_row_matches_its_file() -> None:
    checked = 0
    for row in rows():
        if row["type"] == "ci-run":
            continue
        path = ROOT / row["sanitized_path"]
        assert path.is_file(), row["evidence_id"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == row["sha256"], row["evidence_id"]
        assert row["reviewed"] == "yes", row["evidence_id"]
        checked += 1
    assert checked >= 20  # 5 rules x (rule + lucene + 2 fixtures) + 3 cql


def test_every_fixture_validated_detection_has_evidence_rows() -> None:
    ids = {row["evidence_id"] for row in rows()}
    for item in load_catalog()["detections"]:
        if item["status"] not in {"fixture-validated", "validated"}:
            continue
        det = item["detection_id"]
        for suffix in ("RULE", "LUCENE", "FIX-POS", "FIX-NEG"):
            assert f"EV-{det}-{suffix}" in ids, f"{det} missing {suffix}"
        if item["compiled"]["crowdstrike_logscale"] != "unsupported":
            assert f"EV-{det}-CQL" in ids


def test_evidence_ids_referenced_by_writeups_exist() -> None:
    ids = {row["evidence_id"] for row in rows()}
    for writeup in sorted((ROOT / "docs" / "detections").glob("DET-*.md")):
        text = writeup.read_text(encoding="utf-8")
        referenced = {
            token.strip("`,.") for token in text.split() if token.strip("`,.").startswith("EV-DET-")
        }
        assert referenced, writeup.name
        missing = referenced - ids
        assert not missing, f"{writeup.name} references unknown evidence {sorted(missing)}"


def test_manifest_lives_under_evidence_policy() -> None:
    assert (Path(ROOT) / "evidence" / "README.md").is_file()
