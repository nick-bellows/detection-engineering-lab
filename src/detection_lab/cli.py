"""`detection-lab` command line.

detection-lab triage <alert.json>     validate an alert against automation/triage-contract.json
                                      and print the analyst-ready triage record as JSON
detection-lab rules                   list rules with their compile targets and fixture counts
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

import jsonschema

from detection_lab.automation import Alert, enrich_alert
from detection_lab.catalog import ROOT, load_catalog

CONTRACT_PATH = ROOT / "automation" / "triage-contract.json"
EXIT_INVALID_INPUT = 2


def load_alert(path: Path) -> Alert:
    payload: Any = json.loads(path.read_text(encoding="utf-8"))
    schema = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    jsonschema.validate(payload, schema)
    return Alert(
        alert_id=str(payload["alert_id"]),
        detection_id=str(payload["detection_id"]),
        title=str(payload["title"]),
        severity=payload["severity"],
        host=str(payload["host"]),
        user=str(payload["user"]),
        attack_ids=tuple(str(a) for a in payload.get("attack_ids", [])),
    )


def cmd_triage(args: argparse.Namespace) -> int:
    path = Path(args.alert)
    try:
        alert = load_alert(path)
    except (OSError, json.JSONDecodeError, jsonschema.ValidationError, KeyError) as error:
        print(f"invalid alert {path}: {error}", file=sys.stderr)
        return EXIT_INVALID_INPUT
    enriched = enrich_alert(
        alert,
        critical_hosts=set(args.critical_host or ()),
        privileged_users=set(args.privileged_user or ()),
    )
    print(json.dumps(asdict(enriched), indent=2, ensure_ascii=False))
    return 0


def cmd_rules(_: argparse.Namespace) -> int:
    catalog = load_catalog()
    for item in catalog.get("detections", []):
        compiled = item.get("compiled") or {}
        targets = ", ".join(
            f"{t}={'ok' if compiled.get(t) not in (None, 'unsupported') else 'unsupported'}"
            for t in ("elastic", "crowdstrike_logscale")
        )
        print(f"{item['detection_id']}  {item['attack_id']:<10} {item['status']:<18} {targets}")
    print(f"attack_version={catalog.get('attack_version')}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="detection-lab", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    triage = sub.add_parser("triage", help="enrich one alert JSON file")
    triage.add_argument("alert", help="path to an alert JSON matching the triage contract")
    triage.add_argument("--critical-host", action="append", help="host treated as critical")
    triage.add_argument("--privileged-user", action="append", help="user treated as privileged")
    triage.set_defaults(func=cmd_triage)

    rules = sub.add_parser("rules", help="list catalog entries and compile targets")
    rules.set_defaults(func=cmd_rules)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result: int = args.func(args)
    return result


if __name__ == "__main__":
    sys.exit(main())
