from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path
from typing import Any

import yaml

# Concrete submodules rather than package re-exports: pySigma's __init__ files
# re-export without __all__, which mypy --strict treats as private.
from sigma.backends.crowdstrike.logscale import LogScaleBackend
from sigma.backends.elasticsearch.elasticsearch_lucene import LuceneBackend
from sigma.exceptions import SigmaError
from sigma.pipelines.crowdstrike.crowdstrike import crowdstrike_falcon_pipeline
from sigma.pipelines.elasticsearch.windows import ecs_windows
from sigma.pipelines.sysmon.sysmon import sysmon_pipeline
from sigma.rule import SigmaRule

ROOT = Path(__file__).resolve().parents[3]
RULES_DIR = ROOT / "detections" / "rules"
COMPILED_DIR = ROOT / "detections" / "compiled"
MANIFEST_PATH = COMPILED_DIR / "manifest.json"

COMPILE_TARGETS: tuple[str, ...] = ("elastic", "crowdstrike_logscale")
TARGET_DIRS = {"elastic": "elastic", "crowdstrike_logscale": "crowdstrike-logscale"}
PINNED_PACKAGES = (
    "pysigma",
    "pysigma-backend-elasticsearch",
    "pysigma-backend-crowdstrike",
    "pysigma-pipeline-sysmon",
    "pysigma-pipeline-windows",
)
RULE_FILENAME = re.compile(r"^det-(\d{3})-[a-z0-9-]+\.yml$")
# Every query the Falcon pipeline actually translated carries this event filter.
FALCON_EVENT_MARKER = "#event_simpleName"


@dataclass(frozen=True, slots=True)
class LoadedRule:
    detection_id: str
    path: Path
    text: str
    sha256: str
    title: str
    logsource: str
    falsepositives: tuple[str, ...]

    def parse(self) -> SigmaRule:
        # A fresh SigmaRule per backend: pySigma applies a processing pipeline to the
        # rule object in place, so one parsed rule cannot feed two pipelines.
        return SigmaRule.from_yaml(self.text)


@dataclass(frozen=True, slots=True)
class CompiledRule:
    detection_id: str
    rule_path: str
    rule_sha256: str
    title: str
    outputs: dict[str, str] = field(default_factory=dict)  # relative path -> content
    unsupported: dict[str, str] = field(default_factory=dict)  # target -> reason

    def supports(self, target: str) -> bool:
        return target not in self.unsupported


def _detection_id_from_filename(path: Path) -> str:
    match = RULE_FILENAME.fullmatch(path.name)
    if not match:
        raise ValueError(f"rule filename {path.name!r} must look like det-NNN-<slug>.yml")
    return f"DET-{match.group(1)}"


def load_rules(rules_dir: Path = RULES_DIR) -> list[LoadedRule]:
    rules: list[LoadedRule] = []
    for path in sorted(rules_dir.glob("det-*.yml")):
        text = path.read_text(encoding="utf-8")
        payload = yaml.safe_load(text)
        if not isinstance(payload, dict):
            raise TypeError(f"{path} is not a mapping")
        logsource = payload.get("logsource") or {}
        rules.append(
            LoadedRule(
                detection_id=_detection_id_from_filename(path),
                path=path,
                text=text,
                sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
                title=str(payload.get("title", "")),
                logsource="/".join(f"{k}={v}" for k, v in sorted(logsource.items())),
                falsepositives=tuple(str(fp) for fp in payload.get("falsepositives", [])),
            )
        )
    return rules


def _elastic_backend() -> LuceneBackend:
    # Sysmon first (category -> EventID/Channel), then ECS field names.
    return LuceneBackend(processing_pipeline=sysmon_pipeline() + ecs_windows())


def _logscale_backend() -> LogScaleBackend:
    return LogScaleBackend(processing_pipeline=crowdstrike_falcon_pipeline())


def _render_error(error: Exception) -> str:
    return f"{type(error).__name__}: {error}"


def compile_rule(rule: LoadedRule) -> CompiledRule:
    outputs: dict[str, str] = {}
    unsupported: dict[str, str] = {}
    stem = rule.detection_id

    elastic_dir = TARGET_DIRS["elastic"]
    try:
        backend = _elastic_backend()
        lucene = backend.convert_rule(rule.parse(), output_format="default")
        outputs[f"{elastic_dir}/{stem}.lucene"] = "\n".join(lucene) + "\n"
        dsl = _elastic_backend().convert_rule(rule.parse(), output_format="dsl_lucene")
        outputs[f"{elastic_dir}/{stem}.dsl.json"] = _stable_json(dsl)
        siem = _elastic_backend().convert_rule(rule.parse(), output_format="siem_rule_ndjson")
        # The backend returns one dict per rule for this format; serialise deterministically.
        outputs[f"{elastic_dir}/{stem}.siem_rule.ndjson"] = (
            "\n".join(json.dumps(item, sort_keys=True, ensure_ascii=False) for item in siem) + "\n"
        )
    except SigmaError as error:
        unsupported["elastic"] = _render_error(error)

    logscale_dir = TARGET_DIRS["crowdstrike_logscale"]
    try:
        cql = "\n".join(_logscale_backend().convert_rule(rule.parse(), output_format="default"))
        if FALCON_EVENT_MARKER not in cql:
            # The Falcon pipeline does not raise for a logsource it has no mapping for; it
            # passes the Windows field names through untouched. That is not a Falcon query,
            # so it is recorded as a gap rather than committed as if it were one.
            unsupported["crowdstrike_logscale"] = (
                "NoLogsourceMapping: crowdstrike_falcon_pipeline has no event mapping for "
                f"logsource {rule.logsource}; field names passed through untranslated"
            )
        else:
            outputs[f"{logscale_dir}/{stem}.cql"] = cql + "\n"
    except SigmaError as error:
        unsupported["crowdstrike_logscale"] = _render_error(error)

    return CompiledRule(
        detection_id=rule.detection_id,
        rule_path=rule.path.relative_to(ROOT).as_posix(),
        rule_sha256=rule.sha256,
        title=rule.title,
        outputs=outputs,
        unsupported=unsupported,
    )


def _stable_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def backend_versions() -> dict[str, str]:
    return {name: metadata.version(name) for name in PINNED_PACKAGES}


def compile_all(rules_dir: Path = RULES_DIR) -> list[CompiledRule]:
    return [compile_rule(rule) for rule in load_rules(rules_dir)]


def render_outputs(compiled: list[CompiledRule]) -> dict[str, str]:
    """Every file the compile step owns, as relative path -> content (manifest included)."""
    files: dict[str, str] = {}
    manifest: dict[str, Any] = {
        "generated_with": backend_versions(),
        "rules": {},
    }
    for item in compiled:
        for rel_path, content in item.outputs.items():
            files[rel_path] = content
        by_target: dict[str, list[str]] = {target: [] for target in COMPILE_TARGETS}
        for rel_path in sorted(item.outputs):
            target = next(t for t, d in TARGET_DIRS.items() if rel_path.startswith(d + "/"))
            by_target[target].append(rel_path)
        manifest["rules"][item.detection_id] = {
            "rule_path": item.rule_path,
            "rule_sha256": item.rule_sha256,
            "title": item.title,
            "outputs": by_target,
            "unsupported": dict(sorted(item.unsupported.items())),
        }
    files[MANIFEST_PATH.relative_to(COMPILED_DIR).as_posix()] = _stable_json(manifest)
    return files


def write_outputs(files: Mapping[str, str], compiled_dir: Path = COMPILED_DIR) -> list[Path]:
    """Write every compiled file and remove anything under compiled_dir the compile no longer owns."""
    written: list[Path] = []
    for rel_path, content in sorted(files.items()):
        target = compiled_dir / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", newline="\n")
        written.append(target)
    expected = set(files)
    for existing in sorted(compiled_dir.rglob("*")):
        if existing.is_file() and existing.relative_to(compiled_dir).as_posix() not in expected:
            existing.unlink()
    return written


def drift(files: Mapping[str, str], compiled_dir: Path = COMPILED_DIR) -> list[str]:
    """Differences between freshly compiled output and what is committed."""
    problems: list[str] = []
    for rel_path, content in sorted(files.items()):
        target = compiled_dir / rel_path
        if not target.is_file():
            problems.append(f"missing: {rel_path}")
        elif target.read_text(encoding="utf-8") != content:
            problems.append(f"differs: {rel_path}")
    expected = set(files)
    for existing in sorted(compiled_dir.rglob("*")):
        if existing.is_file():
            rel = existing.relative_to(compiled_dir).as_posix()
            if rel not in expected:
                problems.append(f"stale: {rel}")
    return problems
