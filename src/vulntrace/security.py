"""Input validation, path safety, URL checks and secret redaction.

Every value that originates outside the program (advisory JSON, URLs, git refs,
test identifiers, file paths) is untrusted and is validated here before use.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from vulntrace.config import MAX_URL_LENGTH


class ValidationError(ValueError):
    """Raised when untrusted input fails validation. Messages never echo full inputs."""


_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
_LOCAL_REPO_RE = re.compile(r"^local://[A-Za-z0-9_-]{1,64}$")
_NODE_ID_RE = re.compile(r"^[A-Za-z0-9_]{1,80}\.py::[A-Za-z_][A-Za-z0-9_]{0,120}$")

_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"), "[REDACTED_TOKEN]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_KEY]"),
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/-]+=*"), "Bearer [REDACTED]"),
    (re.compile(r"(?i)(password|passwd|token|secret|api[_-]?key)(\s*[=:]\s*)\S+"), r"\1\2[REDACTED]"),
]

_BLOCKED_HOSTNAMES = frozenset({"localhost", "localhost.localdomain"})
_BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".test", ".invalid")


def validate_identifier(value: object) -> str:
    if not isinstance(value, str) or not _IDENTIFIER_RE.fullmatch(value):
        raise ValidationError("identifier must be 3-128 characters of letters, digits, '.', '_' or '-'")
    return value


def validate_cve(value: object) -> str:
    if not isinstance(value, str) or not _CVE_RE.fullmatch(value):
        raise ValidationError("CVE identifier must match CVE-YYYY-NNNN+")
    return value


def validate_commit_sha(value: object) -> str:
    if not isinstance(value, str) or not _SHA_RE.fullmatch(value):
        raise ValidationError("commit must be a full 40-character lowercase SHA-1")
    return value


def validate_git_ref(value: object) -> str:
    """Accept only simple ref names. Leading '-' (option injection) is rejected by the regex."""
    if not isinstance(value, str) or not _REF_RE.fullmatch(value) or ".." in value:
        raise ValidationError("git ref contains disallowed characters")
    return value


def validate_node_id(value: object, test_file: str) -> str:
    """Accept only pytest node ids of the form <file>.py::<test_name> for the approved file."""
    if not isinstance(value, str) or not _NODE_ID_RE.fullmatch(value):
        raise ValidationError("test node id has an invalid format")
    if not value.startswith(f"{test_file}::"):
        raise ValidationError("test node id does not belong to the approved test file")
    return value


def validate_repository_url(value: object) -> str:
    """Accept fixture-local repositories (local://name) or public https repository URLs."""
    if not isinstance(value, str):
        raise ValidationError("repository URL must be a string")
    if _LOCAL_REPO_RE.fullmatch(value):
        return value
    return validate_public_https_url(value)


def safe_relative_path(value: str) -> PurePosixPath:
    """Return a relative POSIX path with no traversal, absolute roots or control characters."""
    if not isinstance(value, str) or not value or len(value) > 260:
        raise ValidationError("path is empty or too long")
    if "\x00" in value or "\\" in value:
        raise ValidationError("path contains forbidden characters")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part == ".." for part in path.parts):
        raise ValidationError("path must be relative and must not traverse upwards")
    if not path.parts:
        raise ValidationError("path is empty")
    return path


def ensure_within(base: Path, candidate: Path) -> Path:
    """Resolve both paths (following symlinks) and require the candidate to live under base."""
    base_resolved = base.resolve()
    candidate_resolved = candidate.resolve()
    try:
        candidate_resolved.relative_to(base_resolved)
    except ValueError as exc:
        raise ValidationError("path escapes its allowed directory") from exc
    return candidate_resolved


def validate_public_https_url(value: object) -> str:
    """Require https and a non-local, non-private host literal.

    DNS is not resolved here, so DNS rebinding is not addressed. Online fetching is
    intentionally not part of this milestone; see docs/threat_model.md.
    """
    if not isinstance(value, str) or len(value) > MAX_URL_LENGTH:
        raise ValidationError("URL is missing or too long")
    parts = urlsplit(value)
    if parts.scheme != "https" or not parts.hostname:
        raise ValidationError("URL must use https and include a host")
    if parts.username or parts.password:
        raise ValidationError("URL must not embed credentials")
    host = parts.hostname.lower()
    if host in _BLOCKED_HOSTNAMES or host.endswith(_BLOCKED_SUFFIXES):
        raise ValidationError("URL host is local or reserved")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None and (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    ):
        raise ValidationError("URL host is a private or reserved address")
    return value


def redact(text: str) -> str:
    """Remove token-like strings from text before it is logged or reported."""
    redacted = text
    for pattern, replacement in _SECRET_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted
