from __future__ import annotations

import json
import os
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from detection_lab.fixtures import FixtureDoc, load_fixture_docs

ROOT = Path(__file__).resolve().parents[1]
INDEX_MAPPING = ROOT / "lab" / "index-mapping.json"


@pytest.fixture(scope="session")
def fixture_docs() -> list[FixtureDoc]:
    docs = load_fixture_docs()
    assert docs, "no telemetry fixtures found"
    return docs


@pytest.fixture(scope="session")
def index_mapping() -> dict[str, Any]:
    body = json.loads(INDEX_MAPPING.read_text(encoding="utf-8"))
    body.pop("_comment", None)
    return body


@pytest.fixture(scope="session")
def es_client() -> Iterator[Any]:
    url = os.environ.get("DETECTION_LAB_ES_URL")
    if not url:
        pytest.skip("DETECTION_LAB_ES_URL not set; live-SIEM tests need a running Elasticsearch")
    from elasticsearch import Elasticsearch

    password = os.environ.get("DETECTION_LAB_ES_PASSWORD")
    client = Elasticsearch(
        url,
        basic_auth=("elastic", password) if password else None,
        request_timeout=60,
    )
    info = client.info()
    assert str(info["version"]["number"]).startswith("8."), info["version"]
    yield client
    client.close()


@pytest.fixture
def scratch_index(es_client: Any) -> Iterator[str]:
    name = f"detection-lab-fixtures-{uuid.uuid4().hex[:12]}"
    yield name
    es_client.indices.delete(index=name, ignore_unavailable=True)
