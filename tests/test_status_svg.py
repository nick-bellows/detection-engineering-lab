import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from render_status_svg import SVG_PATH, render

from detection_lab.catalog import load_catalog


def test_committed_svg_matches_a_fresh_render() -> None:
    assert SVG_PATH.is_file(), "run scripts/render_status_svg.py"
    assert SVG_PATH.read_text(encoding="utf-8") == render()


def test_every_detection_appears_in_the_svg() -> None:
    svg = render()
    for item in load_catalog()["detections"]:
        assert str(item["detection_id"]) in svg
        assert str(item["attack_id"]) in svg


def test_svg_marks_the_two_logscale_gaps() -> None:
    # DET-004 (registry_set) and DET-005 (4624) have no Falcon mapping; the card must say so.
    assert render().count(">gap<") == 2


def test_svg_is_self_contained_and_labelled() -> None:
    svg = render()
    assert svg.startswith("<svg") and "<title" in svg and "<desc" in svg
    assert 'fill="#fcfcfb"' in svg  # own background, so it reads on light and dark
