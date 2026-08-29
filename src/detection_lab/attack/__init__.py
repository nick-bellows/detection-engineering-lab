"""Bundled MITRE ATT&CK technique context (see techniques.yml for source and terms)."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

import yaml


@dataclass(frozen=True, slots=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]
    url: str
    attack_version: str
    accessed_at_utc: str


@lru_cache(maxsize=1)
def load_techniques() -> dict[str, Technique]:
    text = resources.files(__package__).joinpath("techniques.yml").read_text(encoding="utf-8")
    payload = yaml.safe_load(text)
    version = str(payload["attack_version"])
    accessed = str(payload["accessed_at_utc"])
    techniques = {
        str(item["id"]): Technique(
            id=str(item["id"]),
            name=str(item["name"]),
            tactics=tuple(str(t) for t in item["tactics"]),
            url=str(item["url"]),
            attack_version=version,
            accessed_at_utc=accessed,
        )
        for item in payload["techniques"]
    }
    return techniques


def technique(attack_id: str) -> Technique | None:
    return load_techniques().get(attack_id)


__all__ = ["Technique", "load_techniques", "technique"]
