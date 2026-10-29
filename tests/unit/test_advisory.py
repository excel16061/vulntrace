"""Unit tests for advisory fixture loading and normalization."""

import json

import pytest
from pydantic import ValidationError as PydanticValidationError

from vulntrace.config import FIXTURES_DIR
from vulntrace.ingestion.advisory import Advisory, load_advisory_fixture
from vulntrace.security import ValidationError


def _write(tmp_path, payload):
    path = tmp_path / "advisory.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _base_payload():
    return {
        "advisory_id": "TEST-0001",
        "cve_id": "CVE-2026-0001",
        "summary": "Test record",
        "source": "unit-test",
        "repository_url": "https://github.com/example/project",
        "fix_reference": {"type": "commit", "value": "b" * 40},
        "affected_versions": ["1.0.0"],
        "fixed_version": "1.0.1",
        "published": "2026-01-01T00:00:00Z",
    }


def test_bundled_synthetic_fixture_loads_and_is_hashed():
    advisory = load_advisory_fixture(FIXTURES_DIR / "synthetic_advisory.json")
    assert advisory.advisory_id == "SYN-DEMO-0001"
    assert advisory.validation_status == "partial"  # cve_id is intentionally null
    assert "cve_id" in advisory.missing_fields
    assert len(advisory.source_sha256) == 64
    assert advisory.source_ref == "synthetic_advisory.json"


def test_missing_fields_are_listed_not_invented(tmp_path):
    payload = _base_payload()
    payload["cve_id"] = None
    payload["fixed_version"] = None
    advisory = load_advisory_fixture(_write(tmp_path, payload), base_dir=tmp_path)
    assert advisory.cve_id is None
    assert set(advisory.missing_fields) == {"cve_id", "fixed_version"}
    assert advisory.validation_status == "partial"


def test_complete_record_is_validated(tmp_path):
    advisory = load_advisory_fixture(_write(tmp_path, _base_payload()), base_dir=tmp_path)
    assert advisory.validation_status == "validated"
    assert advisory.missing_fields == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("advisory_id", "x"),  # too short
        ("advisory_id", "../../etc"),  # traversal-looking identifier
        ("cve_id", "CVE-26-1"),  # malformed CVE
        ("repository_url", "http://github.com/example/project"),  # not https
        ("repository_url", "https://127.0.0.1/repo"),  # loopback literal
        ("source_url", "https://localhost/advisory"),  # local host
    ],
)
def test_invalid_values_are_rejected(tmp_path, field, value):
    payload = _base_payload()
    payload[field] = value
    if field == "source_url":
        payload[field] = value
    with pytest.raises(ValidationError):
        load_advisory_fixture(_write(tmp_path, payload), base_dir=tmp_path)


def test_unknown_fields_are_rejected(tmp_path):
    payload = _base_payload()
    payload["exploit_command"] = "rm -rf /"
    with pytest.raises(ValidationError):
        load_advisory_fixture(_write(tmp_path, payload), base_dir=tmp_path)


def test_fixture_may_not_set_retrieval_time(tmp_path):
    payload = _base_payload()
    payload["retrieved_at"] = "2020-01-01T00:00:00Z"
    with pytest.raises(ValidationError):
        load_advisory_fixture(_write(tmp_path, payload), base_dir=tmp_path)


def test_model_is_immutable(tmp_path):
    advisory = load_advisory_fixture(_write(tmp_path, _base_payload()), base_dir=tmp_path)
    assert isinstance(advisory, Advisory)
    with pytest.raises(PydanticValidationError):  # frozen model rejects assignment
        advisory.advisory_id = "OTHER-1"  # type: ignore[misc]
