"""Evidence model: explicit statuses, allowed transitions and a pure derivation function.

Status meanings (see docs/methodology.md for the full rules):

- UNKNOWN: no repository revision was resolved.
- INSUFFICIENT_EVIDENCE: evidence exists but does not support a stronger status.
- CANDIDATE_FIX: a commit is suggested but not explicitly referenced by the advisory.
- PATCH_IDENTIFIED: the advisory explicitly references a fix commit; no test evidence yet.
- TEST_FAILED_ON_VULNERABLE_REVISION: the selected test fails on the vulnerable revision.
- TEST_PASSED_ON_PATCHED_REVISION: the selected test passes on the patched revision, but
  there is no vulnerable-revision evidence. A pass alone does not establish a fix.
- VERIFIED_FOR_TESTED_CASE: the test fails on the vulnerable revision and passes on the
  patched revision, consistently across repeated runs. Applies only to that test.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class EvidenceStatus(StrEnum):
    UNKNOWN = "UNKNOWN"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    CANDIDATE_FIX = "CANDIDATE_FIX"
    PATCH_IDENTIFIED = "PATCH_IDENTIFIED"
    TEST_FAILED_ON_VULNERABLE_REVISION = "TEST_FAILED_ON_VULNERABLE_REVISION"
    TEST_PASSED_ON_PATCHED_REVISION = "TEST_PASSED_ON_PATCHED_REVISION"
    VERIFIED_FOR_TESTED_CASE = "VERIFIED_FOR_TESTED_CASE"


class RunOutcome(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    INFRASTRUCTURE_ERROR = "infrastructure_error"
    TIMEOUT = "timeout"


class AssociationKind(StrEnum):
    EXPLICIT_REFERENCE = "explicit_reference"
    CANDIDATE = "candidate"


_S = EvidenceStatus

# Allowed moves when an analysis is re-run or new evidence arrives.
ALLOWED_TRANSITIONS: dict[EvidenceStatus, frozenset[EvidenceStatus]] = {
    _S.UNKNOWN: frozenset({_S.INSUFFICIENT_EVIDENCE, _S.CANDIDATE_FIX}),
    _S.INSUFFICIENT_EVIDENCE: frozenset({_S.CANDIDATE_FIX, _S.PATCH_IDENTIFIED}),
    _S.CANDIDATE_FIX: frozenset({_S.PATCH_IDENTIFIED, _S.INSUFFICIENT_EVIDENCE}),
    _S.PATCH_IDENTIFIED: frozenset(
        {_S.TEST_FAILED_ON_VULNERABLE_REVISION, _S.TEST_PASSED_ON_PATCHED_REVISION, _S.INSUFFICIENT_EVIDENCE}
    ),
    _S.TEST_FAILED_ON_VULNERABLE_REVISION: frozenset({_S.VERIFIED_FOR_TESTED_CASE, _S.INSUFFICIENT_EVIDENCE}),
    _S.TEST_PASSED_ON_PATCHED_REVISION: frozenset(
        {_S.TEST_FAILED_ON_VULNERABLE_REVISION, _S.INSUFFICIENT_EVIDENCE}
    ),
    _S.VERIFIED_FOR_TESTED_CASE: frozenset({_S.INSUFFICIENT_EVIDENCE}),
}


def is_allowed_transition(source: EvidenceStatus, target: EvidenceStatus) -> bool:
    return target in ALLOWED_TRANSITIONS.get(source, frozenset())


@dataclass(frozen=True)
class FixAssociation:
    kind: AssociationKind
    source: str


@dataclass
class EvidenceRecord:
    repository_revision: str | None
    fix_association: FixAssociation | None
    vulnerable_outcomes: list[str] = field(default_factory=list)
    patched_outcomes: list[str] = field(default_factory=list)


_INFRA = {RunOutcome.INFRASTRUCTURE_ERROR, RunOutcome.TIMEOUT}


def derive_status(ev: EvidenceRecord) -> tuple[EvidenceStatus, list[str]]:
    """Derive the status and the human-readable reasons from recorded evidence.

    The function is pure: the same evidence always yields the same status.
    """
    if ev.repository_revision is None:
        return _S.UNKNOWN, ["No repository revision was resolved."]
    if ev.fix_association is None:
        return _S.INSUFFICIENT_EVIDENCE, ["The advisory does not reference a fix commit."]
    if ev.fix_association.kind == AssociationKind.CANDIDATE:
        return _S.CANDIDATE_FIX, [
            "The fix commit is a candidate only; it is not explicitly referenced by the advisory."
        ]

    vulnerable = [RunOutcome(o) for o in ev.vulnerable_outcomes]
    patched = [RunOutcome(o) for o in ev.patched_outcomes]

    if any(o in _INFRA for o in vulnerable + patched):
        return _S.INSUFFICIENT_EVIDENCE, [
            "At least one run hit an infrastructure error or timeout; results are not interpretable."
        ]
    if not vulnerable and not patched:
        return _S.PATCH_IDENTIFIED, [
            "The advisory explicitly references the fix commit; no test runs were recorded."
        ]
    if not vulnerable:
        if all(o == RunOutcome.PASSED for o in patched):
            return _S.TEST_PASSED_ON_PATCHED_REVISION, [
                "The test passes on the patched revision but was not shown to fail "
                "on the vulnerable revision.",
            ]
        return _S.INSUFFICIENT_EVIDENCE, ["The test does not pass consistently on the patched revision."]

    if not all(o == RunOutcome.FAILED for o in vulnerable):
        return _S.INSUFFICIENT_EVIDENCE, [
            "The test does not fail consistently on the vulnerable revision, "
            "so it cannot distinguish the revisions."
        ]
    if not patched:
        return _S.TEST_FAILED_ON_VULNERABLE_REVISION, [
            "The test fails on the vulnerable revision; the patched revision was not tested."
        ]
    if all(o == RunOutcome.PASSED for o in patched):
        return _S.VERIFIED_FOR_TESTED_CASE, [
            "The test fails on the vulnerable revision and passes on the patched revision in every run. "
            "This applies only to the selected test and does not show the software is secure.",
        ]
    return _S.INSUFFICIENT_EVIDENCE, [
        "The test still fails or is inconsistent on the patched revision."
    ]
