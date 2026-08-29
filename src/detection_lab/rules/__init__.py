"""Sigma rule loading and compilation to the two SIEM targets.

Every rule under ``detections/rules/`` is compiled to

* Elastic (Lucene query string, DSL, and a Kibana SIEM rule) through the Sysmon and
  ECS-Windows processing pipelines, and
* CrowdStrike LogScale (CQL) through the Falcon pipeline.

Compiled output is committed under ``detections/compiled/`` and drift-checked: if a
rule or a backend version changes without the compiled text being regenerated, CI
fails. A logsource the Falcon pipeline cannot express is recorded as ``unsupported``
with the pySigma error text rather than being papered over.
"""

from detection_lab.rules.compiler import (
    COMPILE_TARGETS,
    CompiledRule,
    LoadedRule,
    compile_all,
    compile_rule,
    load_rules,
    render_outputs,
)

__all__ = [
    "COMPILE_TARGETS",
    "CompiledRule",
    "LoadedRule",
    "compile_all",
    "compile_rule",
    "load_rules",
    "render_outputs",
]
