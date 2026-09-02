"""Generate a recruiter-facing detection catalog from repository evidence."""

from __future__ import annotations

import csv
import html
import json
import re
from pathlib import Path
from typing import Any

import yaml

from detection_lab.catalog import ROOT, load_catalog

OUTPUT = ROOT / "docs" / "index.html"
GITHUB = "https://github.com/nick-bellows/detection-engineering-lab/blob/main"


def _read_csv(path: Path, key: str) -> dict[str, dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return {row[key]: row for row in csv.DictReader(handle)}


def _link(path: str, label: str) -> str:
    escaped_path = html.escape(path, quote=True)
    return f'<a href="{GITHUB}/{escaped_path}">{html.escape(label)}</a>'


def _first_blind_spot(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    match = re.search(r"^## Blind spots\s*$\n(.*?)(?=^## |\Z)", text, re.MULTILINE | re.DOTALL)
    if not match:
        return "See the write-up for documented blind spots."
    lines = [line.strip() for line in match.group(1).splitlines() if line.strip()]
    first = next((line[2:] for line in lines if line.startswith("- ")), lines[0])
    plain = re.sub(r"[`*_]", "", first)
    return plain[:420] + ("…" if len(plain) > 420 else "")


def _options(values: set[str]) -> str:
    return "".join(
        f'<option value="{html.escape(value, quote=True)}">{html.escape(value)}</option>'
        for value in sorted(values)
    )


def _card(
    item: dict[str, Any],
    manifest: dict[str, Any],
    matrix: dict[str, str],
) -> str:
    detection_id = str(item["detection_id"])
    rule_path = str(item["rule_path"])
    writeup_path = str(item["writeup_path"])
    rule = yaml.safe_load((ROOT / rule_path).read_text(encoding="utf-8"))
    logsource = rule.get("logsource") or {}
    platform = str(logsource.get("product", "unknown"))
    source = str(logsource.get("category") or logsource.get("service") or "unknown")
    severity = str(rule.get("level", "unknown"))
    status = str(item["status"])
    technique = str(item["technique"])

    compiled = manifest["rules"][detection_id]
    target_rows: list[str] = []
    for target, label in (("elastic", "Elastic"), ("crowdstrike_logscale", "LogScale")):
        outputs = compiled["outputs"].get(target, [])
        if outputs:
            links = ", ".join(
                _link(f"detections/compiled/{path}", Path(path).suffix.lstrip(".") or "query")
                for path in outputs
            )
            qualifier = (
                "executed with synthetic fixtures"
                if target == "elastic"
                else "compiled; not executed"
            )
            target_rows.append(f"<li><strong>{label}:</strong> {links} ({qualifier})</li>")
        else:
            reason = compiled.get("unsupported", {}).get(
                target, "unsupported by the selected pipeline"
            )
            target_rows.append(
                f'<li><strong>{label}:</strong> <span class="gap">recorded gap</span> — '
                f"{html.escape(reason)}</li>"
            )

    positive = matrix.get("positive_events", "?")
    negative = matrix.get("negative_events", "?")
    return f"""
<article id="{html.escape(detection_id, quote=True)}" class="detection" data-technique="{html.escape(technique, quote=True)}"
 data-logsource="{html.escape(source, quote=True)}" data-platform="{html.escape(platform, quote=True)}"
 data-severity="{html.escape(severity, quote=True)}" data-status="{html.escape(status, quote=True)}">
  <div class="card-head">
    <div><span class="id">{html.escape(detection_id)}</span><span class="status">{html.escape(status)}</span></div>
    <span class="severity">{html.escape(severity)} severity</span>
  </div>
  <h2>{html.escape(str(rule["title"]))}</h2>
  <p class="meta">{html.escape(str(item["attack_id"]))} · {html.escape(technique)} · {html.escape(platform)} / {html.escape(source)}</p>
  <p>{html.escape(str(rule.get("description", "")).strip())}</p>
  <div class="proof"><strong>What is proven:</strong> the Elastic query returned {positive} synthetic positive fixtures and none of this rule's {negative} negative controls in the live-Elasticsearch CI test.</div>
  <div class="pending"><strong>What is not proven:</strong> no retained Windows/Sysmon host telemetry exists; VM validation remains pending.</div>
  <details>
    <summary>Inspect implementation and limits</summary>
    <h3>Source and compiled targets</h3>
    <ul><li><strong>Sigma:</strong> {_link(rule_path, "source rule")}</li>{"".join(target_rows)}</ul>
    <h3>Fixtures and validation</h3>
    <ul>
      <li>{_link(f"tests/fixtures/telemetry/{detection_id}/positive.ndjson", f"{positive} synthetic positives")}</li>
      <li>{_link(f"tests/fixtures/telemetry/{detection_id}/negative.ndjson", f"{negative} negative controls")}</li>
      <li>{_link("tests/live/test_siem.py", "live-Elasticsearch test")}; result: {html.escape(matrix.get("siem_result", "not recorded"))}</li>
      <li>{_link("evidence/evidence-manifest.csv", "hashed evidence manifest")}</li>
    </ul>
    <h3>Representative blind spot</h3>
    <p>{html.escape(_first_blind_spot(ROOT / writeup_path))}</p>
    <p>{_link(writeup_path, "Read the complete detection write-up")}</p>
  </details>
</article>"""


def render_explorer() -> str:
    catalog = load_catalog()
    manifest = json.loads(
        (ROOT / "detections" / "compiled" / "manifest.json").read_text(encoding="utf-8")
    )
    matrix = _read_csv(ROOT / "telemetry" / "validation-matrix.csv", "detection_id")
    detections = catalog["detections"]
    cards = "".join(_card(item, manifest, matrix[str(item["detection_id"])]) for item in detections)

    techniques = {str(item["technique"]) for item in detections}
    rules = [
        yaml.safe_load((ROOT / str(item["rule_path"])).read_text(encoding="utf-8"))
        for item in detections
    ]
    platforms = {str(rule["logsource"].get("product", "unknown")) for rule in rules}
    sources = {
        str(rule["logsource"].get("category") or rule["logsource"].get("service") or "unknown")
        for rule in rules
    }
    severities = {str(rule.get("level", "unknown")) for rule in rules}
    statuses = {str(item["status"]) for item in detections}

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="Five fixture-validated Sigma detections with compiled queries, synthetic controls, documented gaps, and explicit validation boundaries.">
<title>Detection Engineering Lab — evidence explorer</title>
<style>
:root {{ color-scheme: light dark; --page:#0b1016; --surface:#131b24; --line:#293644; --ink:#eef4f8; --muted:#a7b6c2; --blue:#65b5ff; --green:#65d89a; --amber:#ffc861; --red:#ff8a78; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--page); color:var(--ink); font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif; }}
a {{ color:var(--blue); }} :focus-visible {{ outline:3px solid var(--amber); outline-offset:3px; }}
.wrap {{ max-width:1120px; margin:auto; padding:0 20px; }}
header {{ padding:48px 0 30px; border-bottom:1px solid var(--line); }}
h1 {{ margin:4px 0 10px; font-size:clamp(30px,5vw,46px); }} h2 {{ font-size:19px; line-height:1.3; }} h3 {{ font-size:14px; margin:18px 0 5px; }}
.eyebrow,.meta,.boundary {{ color:var(--muted); }} .lede {{ max-width:76ch; font-size:18px; }}
.route {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(210px,1fr)); gap:10px; margin:24px 0; }}
.route div,.detection {{ background:var(--surface); border:1px solid var(--line); border-radius:10px; padding:16px; }}
.route strong {{ display:block; color:var(--green); }}
.filters {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(145px,1fr)); gap:10px; padding:24px 0 12px; }}
label {{ color:var(--muted); font-size:12px; }} select {{ display:block; width:100%; margin-top:4px; padding:8px; border:1px solid var(--line); border-radius:6px; background:var(--surface); color:var(--ink); }}
#count {{ color:var(--muted); margin:0 0 14px; }} .cards {{ display:grid; gap:14px; padding-bottom:36px; }}
.card-head {{ display:flex; justify-content:space-between; gap:10px; }} .id {{ font:600 13px ui-monospace,monospace; }}
.status,.severity {{ font-size:12px; border:1px solid var(--line); border-radius:999px; padding:3px 8px; margin-left:8px; }}
.proof,.pending {{ padding:9px 11px; margin:10px 0; border-left:3px solid var(--green); background:#0e1918; }}
.pending {{ border-color:var(--amber); background:#1b1710; }} .gap {{ color:var(--red); font-weight:600; }}
summary {{ cursor:pointer; color:var(--blue); }} footer {{ border-top:1px solid var(--line); padding:26px 0 44px; color:var(--muted); }}
.skip {{ position:absolute; left:-9999px; top:8px; background:var(--surface); padding:8px; }} .skip:focus {{ left:8px; }}
@media (prefers-reduced-motion:reduce) {{ * {{ scroll-behavior:auto !important; }} }}
</style>
</head>
<body>
<a class="skip" href="#catalog">Skip to catalog</a>
<header><div class="wrap">
  <div class="eyebrow">Portfolio reference implementation · synthetic fixtures · no production telemetry</div>
  <h1>Detection Engineering Lab</h1>
  <p class="lede">Five Sigma detections compiled to Elastic and, where supported, CrowdStrike LogScale. The explorer makes the test evidence and missing host-validation evidence equally visible.</p>
  <div class="route" aria-label="Two-minute reviewer route">
    <div><strong>1 · Read one rule</strong><a href="#DET-001">DET-001 PowerShell</a> explains the signal and its blind spot.</div>
    <div><strong>2 · Inspect the proof</strong><a href="{GITHUB}/tests/live/test_siem.py">The SIEM test</a> asserts exact synthetic positives and zero negative controls.</div>
    <div><strong>3 · Check the boundary</strong><a href="{GITHUB}/telemetry/atomic-test-plan.md">The isolated-VM plan</a> remains intentionally unexecuted.</div>
  </div>
</div></header>
<main id="catalog" class="wrap">
  <div class="filters" aria-label="Detection filters">
    <label>Technique<select data-filter="technique"><option value="">All</option>{_options(techniques)}</select></label>
    <label>Log source<select data-filter="logsource"><option value="">All</option>{_options(sources)}</select></label>
    <label>Platform<select data-filter="platform"><option value="">All</option>{_options(platforms)}</select></label>
    <label>Severity<select data-filter="severity"><option value="">All</option>{_options(severities)}</select></label>
    <label>Lifecycle<select data-filter="status"><option value="">All</option>{_options(statuses)}</select></label>
  </div>
  <p id="count" role="status">Showing {len(detections)} of {len(detections)} detections</p>
  <div class="cards">{cards}</div>
  <noscript><p>Filtering requires JavaScript; all five detection cards remain visible.</p></noscript>
</main>
<footer><div class="wrap"><strong>Evidence boundary:</strong> fixture-validated means compiled queries were exercised on Elasticsearch with synthetic events. It does not mean the rules fired on telemetry generated by a real Windows host, and no production false-positive rate is claimed.</div></footer>
<script>
(() => {{
  const controls = [...document.querySelectorAll("[data-filter]")];
  const cards = [...document.querySelectorAll(".detection")];
  const count = document.getElementById("count");
  function apply() {{
    let visible = 0;
    for (const card of cards) {{
      const show = controls.every(control => !control.value || card.dataset[control.dataset.filter] === control.value);
      card.hidden = !show;
      if (show) visible += 1;
    }}
    count.textContent = `Showing ${{visible}} of ${{cards.length}} detections`;
  }}
  controls.forEach(control => control.addEventListener("change", apply));
}})();
</script>
</body>
</html>
"""


def write_explorer(check: bool = False) -> int:
    markup = render_explorer()
    current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.is_file() else ""
    if check:
        if current != markup:
            raise RuntimeError("docs/index.html is stale; run scripts/render_explorer.py")
        return 0
    OUTPUT.write_text(markup, encoding="utf-8", newline="\n")
    return 0
