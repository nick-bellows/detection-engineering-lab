"""Live-SIEM validation: every compiled Elastic query against every synthetic fixture.

Runs only with DETECTION_LAB_ES_URL set (see lab/README.md for the compose lab and
.github/workflows/quality.yml for the CI service container). Three claims are checked:

1. every positive fixture of DET-N is returned by DET-N's compiled query;
2. no negative-control fixture of ANY detection is returned by ANY query;
3. each query returns exactly its own positives -- nothing else in the corpus.

A fourth test documents a deployment caveat rather than a rule property: under the
stock Elastic mapping (process.command_line as `wildcard`, case-sensitive) the
compiled query misses case variants that Sigma semantics say it should catch.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from detection_lab.fixtures import FixtureDoc
from detection_lab.rules.compiler import COMPILED_DIR, TARGET_DIRS

pytestmark = pytest.mark.siem

ELASTIC_DIR = COMPILED_DIR / TARGET_DIRS["elastic"]


def compiled_queries() -> dict[str, dict[str, Any]]:
    queries: dict[str, dict[str, Any]] = {}
    for path in sorted(ELASTIC_DIR.glob("DET-*.dsl.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert len(payload) == 1, f"{path}: expected one query"
        queries[path.name.split(".")[0]] = payload[0]["query"]
    assert len(queries) == 5, sorted(queries)
    return queries


def index_docs(es: Any, index: str, mapping: dict[str, Any], docs: list[FixtureDoc]) -> None:
    es.indices.create(index=index, settings=mapping["settings"], mappings=mapping["mappings"])
    operations: list[dict[str, Any]] = []
    for doc in docs:
        operations.append({"index": {"_index": index, "_id": doc.doc_id}})
        operations.append(doc.body)
    response = es.bulk(operations=operations, refresh="wait_for")
    assert not response["errors"], [
        item for item in response["items"] if "error" in item.get("index", {})
    ]


def hits(es: Any, index: str, query: dict[str, Any]) -> set[str]:
    response = es.search(index=index, query=query, size=1000, _source=False)
    return {hit["_id"] for hit in response["hits"]["hits"]}


@pytest.fixture(scope="module")
def corpus(es_client: Any, index_mapping: dict[str, Any], fixture_docs: list[FixtureDoc]) -> Any:
    index = "detection-lab-fixtures-corpus"
    es_client.indices.delete(index=index, ignore_unavailable=True)
    index_docs(es_client, index, index_mapping, fixture_docs)
    yield index
    es_client.indices.delete(index=index, ignore_unavailable=True)


@pytest.mark.parametrize("detection_id", ["DET-001", "DET-002", "DET-003", "DET-004", "DET-005"])
def test_query_returns_exactly_its_own_positives(
    es_client: Any, corpus: str, fixture_docs: list[FixtureDoc], detection_id: str
) -> None:
    query = compiled_queries()[detection_id]
    found = hits(es_client, corpus, query)
    positives = {
        d.doc_id
        for d in fixture_docs
        if d.detection_id == detection_id and d.expected == "positive"
    }
    negatives = {d.doc_id for d in fixture_docs if d.expected == "negative"}
    assert positives, "a detection with no positive fixture proves nothing"
    assert positives <= found, f"{detection_id} missed positives: {sorted(positives - found)}"
    assert not (found & negatives), (
        f"{detection_id} fired on negatives: {sorted(found & negatives)}"
    )
    assert found == positives, f"{detection_id} also returned: {sorted(found - positives)}"


def test_no_negative_control_fires_anywhere(
    es_client: Any, corpus: str, fixture_docs: list[FixtureDoc]
) -> None:
    negatives = {d.doc_id for d in fixture_docs if d.expected == "negative"}
    fired: dict[str, set[str]] = {}
    for detection_id, query in compiled_queries().items():
        overlap = hits(es_client, corpus, query) & negatives
        if overlap:
            fired[detection_id] = overlap
    assert not fired, fired


def stock_style_mapping(mapping: dict[str, Any]) -> dict[str, Any]:
    """The lab mapping with command lines as case-sensitive `wildcard`, like the stock integration."""
    variant = json.loads(json.dumps(mapping))
    process = variant["mappings"]["properties"]["process"]["properties"]
    process["command_line"] = {"type": "wildcard"}
    process["parent"]["properties"]["command_line"] = {"type": "wildcard"}
    return variant


def test_case_variants_depend_on_the_index_mapping(
    es_client: Any,
    scratch_index: str,
    index_mapping: dict[str, Any],
    fixture_docs: list[FixtureDoc],
) -> None:
    # Fixtures that the lab mapping catches only because it lowercases command lines.
    lab_only = [d for d in fixture_docs if d.case.endswith("lab-mapping-only")]
    ordinary = [
        d
        for d in fixture_docs
        if d.detection_id in {"DET-001", "DET-003"}
        and d.expected == "positive"
        and not d.case.endswith("lab-mapping-only")
    ]
    assert lab_only and ordinary
    index_docs(es_client, scratch_index, stock_style_mapping(index_mapping), lab_only + ordinary)
    queries = compiled_queries()
    for doc in ordinary:
        assert doc.doc_id in hits(es_client, scratch_index, queries[doc.detection_id]), doc.case
    for doc in lab_only:
        # Documented blind spot: on the stock mapping the compiled query is case-sensitive.
        assert doc.doc_id not in hits(es_client, scratch_index, queries[doc.detection_id]), (
            f"{doc.case} matched on the stock mapping; update the DET writeup and remove the caveat"
        )


def test_fixture_files_are_labelled_synthetic() -> None:
    for meta in sorted(
        Path(__file__).resolve().parents[1].glob("fixtures/telemetry/DET-*/meta.yml")
    ):
        text = meta.read_text(encoding="utf-8")
        assert "synthetic: true" in text, meta
        assert "no third-party telemetry" in text, meta
