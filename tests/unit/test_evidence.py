"""Unit tests for the evidence derivation rules and transition table."""

from vulntrace.analysis.evidence import (
    AssociationKind,
    EvidenceRecord,
    EvidenceStatus,
    FixAssociation,
    derive_status,
    is_allowed_transition,
)

EXPLICIT = FixAssociation(kind=AssociationKind.EXPLICIT_REFERENCE, source="test")
CANDIDATE = FixAssociation(kind=AssociationKind.CANDIDATE, source="test")
REV = "a" * 40


def _ev(assoc=EXPLICIT, rev=REV, vuln=(), patched=()):
    return EvidenceRecord(
        repository_revision=rev,
        fix_association=assoc,
        vulnerable_outcomes=list(vuln),
        patched_outcomes=list(patched),
    )


def test_no_revision_is_unknown():
    status, _ = derive_status(_ev(rev=None))
    assert status is EvidenceStatus.UNKNOWN


def test_no_association_is_insufficient():
    status, _ = derive_status(_ev(assoc=None))
    assert status is EvidenceStatus.INSUFFICIENT_EVIDENCE


def test_candidate_association_is_candidate_fix_even_with_passing_tests():
    status, _ = derive_status(_ev(assoc=CANDIDATE, vuln=["failed"], patched=["passed"]))
    assert status is EvidenceStatus.CANDIDATE_FIX


def test_explicit_reference_without_runs_is_patch_identified():
    status, _ = derive_status(_ev())
    assert status is EvidenceStatus.PATCH_IDENTIFIED


def test_pass_on_patched_only_is_not_a_fix():
    status, reasons = derive_status(_ev(patched=["passed", "passed", "passed"]))
    assert status is EvidenceStatus.TEST_PASSED_ON_PATCHED_REVISION
    assert any("not shown to fail" in r for r in reasons)


def test_fail_on_vulnerable_only_is_recorded_as_such():
    status, _ = derive_status(_ev(vuln=["failed", "failed"]))
    assert status is EvidenceStatus.TEST_FAILED_ON_VULNERABLE_REVISION


def test_fail_then_pass_in_every_run_is_verified_for_tested_case():
    status, reasons = derive_status(
        _ev(vuln=["failed"] * 3, patched=["passed"] * 3)
    )
    assert status is EvidenceStatus.VERIFIED_FOR_TESTED_CASE
    assert any("does not show the software is secure" in r for r in reasons)


def test_test_passing_on_vulnerable_does_not_distinguish():
    status, _ = derive_status(_ev(vuln=["passed"] * 3, patched=["passed"] * 3))
    assert status is EvidenceStatus.INSUFFICIENT_EVIDENCE


def test_inconsistent_vulnerable_runs_are_insufficient():
    status, _ = derive_status(_ev(vuln=["failed", "passed"], patched=["passed"] * 2))
    assert status is EvidenceStatus.INSUFFICIENT_EVIDENCE


def test_still_failing_on_patched_is_insufficient():
    status, _ = derive_status(_ev(vuln=["failed"] * 2, patched=["failed"] * 2))
    assert status is EvidenceStatus.INSUFFICIENT_EVIDENCE


def test_infrastructure_error_blocks_any_conclusion():
    status, _ = derive_status(
        _ev(vuln=["failed", "infrastructure_error"], patched=["passed", "passed"])
    )
    assert status is EvidenceStatus.INSUFFICIENT_EVIDENCE


def test_timeout_blocks_any_conclusion():
    status, _ = derive_status(_ev(vuln=["failed"], patched=["timeout"]))
    assert status is EvidenceStatus.INSUFFICIENT_EVIDENCE


def test_transition_table_allows_documented_moves():
    assert is_allowed_transition(EvidenceStatus.UNKNOWN, EvidenceStatus.CANDIDATE_FIX)
    assert is_allowed_transition(
        EvidenceStatus.TEST_FAILED_ON_VULNERABLE_REVISION, EvidenceStatus.VERIFIED_FOR_TESTED_CASE
    )


def test_verified_cannot_jump_back_to_patch_identified():
    assert not is_allowed_transition(
        EvidenceStatus.VERIFIED_FOR_TESTED_CASE, EvidenceStatus.PATCH_IDENTIFIED
    )


def test_passing_on_patched_cannot_skip_to_verified():
    assert not is_allowed_transition(
        EvidenceStatus.TEST_PASSED_ON_PATCHED_REVISION, EvidenceStatus.VERIFIED_FOR_TESTED_CASE
    )
