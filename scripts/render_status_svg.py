"""Render docs/assets/status-matrix.svg from the catalog, compile manifest, and matrix.

    python scripts/render_status_svg.py          regenerate the SVG
    python scripts/render_status_svg.py --check   fail if the committed SVG is out of date

The SVG is a self-contained light card (its own background, dark ink), so it reads the
same on GitHub's light and dark themes. Every cell carries a word or count, so meaning
never depends on colour alone; the status hues are the dataviz status palette. The
Markdown table in the README is the accessible fallback.
"""

from __future__ import annotations

import argparse
import csv
import sys
from dataclasses import dataclass
from html import escape

from detection_lab.catalog import ROOT, UNSUPPORTED, load_catalog

SVG_PATH = ROOT / "docs" / "assets" / "status-matrix.svg"
MATRIX_PATH = ROOT / "telemetry" / "validation-matrix.csv"

# dataviz status palette, used as light tints (bg) + a readable ink, so the card is
# theme-independent and each state also carries a word.
OK = ("#e6f4e6", "#0a7a0a")  # good
GAP = ("#fce8df", "#b5471f")  # serious
PENDING = ("#fdf1d6", "#8a6410")  # warning
COUNT = ("#eef1f6", "#1c5cab")  # neutral-blue for a present count
NEUTRAL_INK = "#0b0b0b"
MUTED_INK = "#52514e"
CARD_BG = "#fcfcfb"
GRID = "#e4e3df"

COLUMNS: tuple[tuple[str, int], ...] = (
    ("Detection", 78),
    ("ATT&CK", 92),
    ("Elastic", 78),
    ("LogScale", 84),
    ("Pos fx", 58),
    ("Neg fx", 58),
    ("Live SIEM", 92),
    ("VM validated", 112),
)
PAD = 18
ROW_H = 30
HEADER_H = 30
TITLE_H = 30
CAPTION_H = 52


@dataclass(frozen=True, slots=True)
class Cell:
    text: str
    fill: str
    ink: str


def _matrix_rows() -> dict[str, dict[str, str]]:
    with MATRIX_PATH.open(encoding="utf-8", newline="") as handle:
        return {row["detection_id"]: row for row in csv.DictReader(handle)}


def _row_cells(item: dict[str, object], matrix: dict[str, str]) -> list[Cell]:
    compiled = item.get("compiled") or {}
    elastic = (
        Cell("compiled", *OK)
        if compiled.get("elastic") not in (None, UNSUPPORTED)
        else Cell("—", *GAP)
    )
    logscale = (
        Cell("compiled", *OK)
        if compiled.get("crowdstrike_logscale") not in (None, UNSUPPORTED)
        else Cell("gap", *GAP)
    )
    pos = Cell(str(matrix.get("positive_events", "?")), *COUNT)
    neg = Cell(str(matrix.get("negative_events", "?")), *COUNT)
    siem = Cell("pass", *OK) if matrix.get("siem_result") == "pass" else Cell("—", *GAP)
    vm = Cell("validated", *OK) if item.get("status") == "validated" else Cell("pending", *PENDING)
    return [
        Cell(str(item["detection_id"]), CARD_BG, NEUTRAL_INK),
        Cell(str(item["attack_id"]), CARD_BG, MUTED_INK),
        elastic,
        logscale,
        pos,
        neg,
        siem,
        vm,
    ]


def render() -> str:
    catalog = load_catalog()
    matrix = _matrix_rows()
    detections = catalog.get("detections", [])
    width = PAD * 2 + sum(w for _, w in COLUMNS)
    height = PAD * 2 + TITLE_H + HEADER_H + ROW_H * len(detections) + CAPTION_H

    parts: list[str] = []
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" font-family="-apple-system,Segoe UI,Roboto,sans-serif" '
        f'role="img" aria-labelledby="t d">'
    )
    parts.append('<title id="t">Detection status matrix</title>')
    parts.append(
        f'<desc id="d">Per-detection state for {len(detections)} rules: Elastic and CrowdStrike '
        f"LogScale compile targets, positive and negative fixture counts, the live-Elasticsearch "
        f"test result, and the pending VM-validated step. Generated from catalog.yml.</desc>"
    )
    parts.append(
        f'<rect x="0" y="0" width="{width}" height="{height}" rx="10" fill="{CARD_BG}" '
        f'stroke="{GRID}"/>'
    )
    parts.append(
        f'<text x="{PAD}" y="{PAD + 18}" font-size="15" font-weight="600" fill="{NEUTRAL_INK}">'
        f"Detection status "
        f'<tspan font-weight="400" fill="{MUTED_INK}">— generated from catalog.yml</tspan></text>'
    )

    x_positions: list[int] = []
    x = PAD
    for _, w in COLUMNS:
        x_positions.append(x)
        x += w
    header_y = PAD + TITLE_H
    for (label, w), cx in zip(COLUMNS, x_positions, strict=True):
        parts.append(
            f'<text x="{cx + w // 2}" y="{header_y + 20}" font-size="11" font-weight="600" '
            f'text-anchor="middle" fill="{MUTED_INK}">{escape(label)}</text>'
        )

    for r, item in enumerate(detections):
        row_y = header_y + HEADER_H + r * ROW_H
        for cell, (_, w), cx in zip(
            _row_cells(item, matrix.get(str(item["detection_id"]), {})),
            COLUMNS,
            x_positions,
            strict=True,
        ):
            if cell.fill != CARD_BG:
                parts.append(
                    f'<rect x="{cx + 3}" y="{row_y + 4}" width="{w - 6}" height="{ROW_H - 8}" '
                    f'rx="5" fill="{cell.fill}"/>'
                )
            weight = "600" if cell.fill == CARD_BG else "500"
            parts.append(
                f'<text x="{cx + w // 2}" y="{row_y + ROW_H // 2 + 4}" font-size="11.5" '
                f'font-weight="{weight}" text-anchor="middle" fill="{cell.ink}">{escape(cell.text)}</text>'
            )

    caption_y = header_y + HEADER_H + ROW_H * len(detections) + 20
    parts.append(
        f'<text x="{PAD}" y="{caption_y}" font-size="10.5" fill="{MUTED_INK}">'
        f"green = proven &#183; orange = recorded gap (Falcon pipeline) &#183; "
        f"amber = pending the isolated-VM run.</text>"
    )
    parts.append(
        f'<text x="{PAD}" y="{caption_y + 15}" font-size="10.5" fill="{MUTED_INK}">'
        f"Live SIEM = tests/live/test_siem.py on Elasticsearch 8.19.20. "
        f"Pos/Neg fx = synthetic positive / negative-control fixtures.</text>"
    )
    parts.append("</svg>")
    return "\n".join(parts) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Render the detection status SVG")
    parser.add_argument("--check", action="store_true", help="fail if the committed SVG is stale")
    args = parser.parse_args()
    svg = render()
    if args.check:
        current = SVG_PATH.read_text(encoding="utf-8") if SVG_PATH.is_file() else ""
        if current != svg:
            print("docs/assets/status-matrix.svg is out of date; run scripts/render_status_svg.py")
            return 1
        print("Status matrix SVG matches the catalog.")
        return 0
    SVG_PATH.parent.mkdir(parents=True, exist_ok=True)
    SVG_PATH.write_text(svg, encoding="utf-8", newline="\n")
    print(f"Wrote {SVG_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
