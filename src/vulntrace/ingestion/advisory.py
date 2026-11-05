"""Normalized advisory schema and offline fixture import.

Missing fields are recorded in ``missing_fields`` and are never filled with guesses.
The SHA-256 of the raw fixture bytes is kept so the source can be verified later.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic import ValidationError as PydanticValidationError

from vulntrace.config import FIXTURES_DIR, MAX_FIXTURE_BYTES
from vulntrace.security import (
    ValidationError,
    ensure_within,
    validate_commit_sha,
    validate_cve,
    validate_git_ref,
    validate_identifier,
    validate_public_https_url,
    validate_repository_url,
)

_TRACKED_OPTIONAL_FIELDS = (
    "cve_id",
    "summary",
    "published",
    "affected_versions",
    "fixed_version",
    "repository_url",
    "fix_reference",
)


class FixReference(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    type: Literal["tag", "commit"]
    value: str

    @model_validator(mode="after")
    def _check_value(self) -> FixReference:
        if self.type == "commit":
            validate_commit_sha(self.value)
        else:
            validate_git_ref(self.value)
        return self


class Advisory(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    advisory_id: str
    cve_id: str | None = None
    summary: str | None = Field(default=None, max_length=2000)
    source: str = Field(min_length=1, max_length=100)
    source_url: str | None = None
    published: datetime | None = None
    modified: datetime | None = None
    ecosystem: str | None = Field(default=None, max_length=50)
    package: str | None = Field(default=None, max_length=200)
    affected_versions: list[str] = Field(default_factory=list, max_length=100)
    fixed_version: str | None = Field(default=None, max_length=100)
    reference_urls: list[str] = Field(default_factory=list, max_length=50)
    repository_url: str | None = None
    fix_reference: FixReference | None = None
    retrieved_at: datetime
    source_sha256: str
    source_ref: str
    validation_status: Literal["validated", "partial"]
    missing_fields: list[str] = Field(default_factory=list)

    @field_validator("advisory_id")
    @classmethod
    def _advisory_id(cls, value: str) -> str:
        return validate_identifier(value)

    @field_validator("cve_id")
    @classmethod
    def _cve(cls, value: str | None) -> str | None:
        return None if value is None else validate_cve(value)

    @field_validator("source_url")
    @classmethod
    def _source_url(cls, value: str | None) -> str | None:
        return None if value is None else validate_public_https_url(value)

    @field_validator("reference_urls")
    @classmethod
    def _reference_urls(cls, value: list[str]) -> list[str]:
        return [validate_public_https_url(v) for v in value]

    @field_validator("repository_url")
    @classmethod
    def _repository_url(cls, value: str | None) -> str | None:
        return None if value is None else validate_repository_url(value)

    @field_validator("affected_versions")
    @classmethod
    def _versions(cls, value: list[str]) -> list[str]:
        for item in value:
            if not isinstance(item, str) or len(item) > 100:
                raise ValueError("affected version entries must be short strings")
        return value


def _summarize_errors(exc: PydanticValidationError) -> str:
    # Report field locations and messages only; never echo input values.
    return "; ".join(
        f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()
    )


def load_advisory_fixture(path: Path | str, base_dir: Path = FIXTURES_DIR) -> Advisory:
    """Load and validate an advisory JSON fixture from inside ``base_dir``. No network access."""
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = base_dir / candidate
    resolved = ensure_within(base_dir, candidate)
    if not resolved.is_file():
        raise ValidationError("advisory fixture not found")
    if resolved.stat().st_size > MAX_FIXTURE_BYTES:
        raise ValidationError("advisory fixture exceeds the size limit")

    raw = resolved.read_bytes()
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError("advisory fixture is not valid UTF-8 JSON") from exc
    if not isinstance(data, dict):
        raise ValidationError("advisory fixture must be a JSON object")
    if "retrieved_at" in data:
        raise ValidationError("fixtures must not set retrieved_at; it is recorded at import")

    missing = [name for name in _TRACKED_OPTIONAL_FIELDS if data.get(name) in (None, [], "")]
    payload = {
        **data,
        "retrieved_at": datetime.now(UTC),
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "source_ref": resolved.relative_to(base_dir.resolve()).as_posix(),
        "validation_status": "validated" if not missing else "partial",
        "missing_fields": missing,
    }
    try:
        return Advisory.model_validate(payload)
    except PydanticValidationError as exc:
        raise ValidationError(f"advisory failed validation: {_summarize_errors(exc)}") from exc
