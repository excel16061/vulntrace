"""Analysis pipeline: advisory + local repository -> evidence record and verification runs.

Steps:
1. Resolve the advisory's fix reference to a commit (explicit reference only).
2. Infer the vulnerable revision as the fix commit's first parent (labelled as inference).
3. Summarise the patch (changed files and line counts).
4. Export both revisions via git (no symlinks, no submodules, no unsafe paths).
5. Run the approved test file repeatedly on each revision.
6. Derive the evidence status from the recorded outcomes.
"""

from __future__ import annotations

import platform
import tempfile
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path
from typing import Any

from vulntrace import __version__
from vulntrace.analysis.evidence import (
    AssociationKind,
    EvidenceRecord,
    FixAssociation,
    derive_status,
)
from vulntrace.config import MAX_REPEATS, TEST_TIMEOUT_SECONDS
from vulntrace.ingestion.advisory import Advisory
from vulntrace.repositories.gitops import (
    changed_files,
    export_tree,
    parent_commit,
    resolve_commit,
)
from vulntrace.security import ValidationError, validate_commit_sha
from vulntrace.verification.runner import ApprovalRequiredError, TestRun, run_tests

LIMITATIONS = [
    "Results cover one selected test file and one local environment.",
    "Repeated runs here are expected to agree; repeat counts do not measure real-project flakiness.",
    "The vulnerable revision is inferred as the first parent of the fix commit, not checked "
    "against affected-version metadata.",
    "Test execution uses subprocess isolation and a temporary directory. "
    "It is not a container, VM or security sandbox.",
]


@dataclass(frozen=True)
class AnalysisConfig:
    repo_path: Path
    test_file: str = "test_path_guard.py"
    node_ids: tuple[str, ...] | None = None
    repeats: int = 3
    approved: bool = False
    timeout_seconds: int = TEST_TIMEOUT_SECONDS


def _pytest_version() -> str:
    try:
        return metadata.version("pytest")
    except metadata.PackageNotFoundError:
        return "unknown"


def _outcomes(runs: list[TestRun], label: str) -> list[str]:
    return [r.outcome for r in runs if r.revision_label == label]


def analyze(advisory: Advisory, cfg: AnalysisConfig) -> dict[str, Any]:
    """Run the full pipeline and return a JSON-serialisable result dictionary."""
    if not cfg.approved:
        raise ApprovalRequiredError("analysis executes repository-provided tests; approval is required")
    if not 1 <= cfg.repeats <= MAX_REPEATS:
        raise ValueError(f"repeats must be between 1 and {MAX_REPEATS}")

    repo = cfg.repo_path.resolve()
    if not (repo / ".git").exists():
        raise ValidationError("path is not a git repository")

    fix_ref = advisory.fix_reference
    association: FixAssociation | None = None
    fixed_sha: str | None = None
    vulnerable_sha: str | None = None
    patch_files: list[dict[str, Any]] = []
    additions = deletions = 0
    unsafe_skipped = 0
    runs: list[TestRun] = []

    if fix_ref is not None:
        fixed_sha = (
            validate_commit_sha(fix_ref.value)
            if fix_ref.type == "commit"
            else resolve_commit(repo, fix_ref.value)
        )
        association = FixAssociation(
            kind=AssociationKind.EXPLICIT_REFERENCE,
            source=f"advisory fix_reference ({fix_ref.type}: {fix_ref.value})",
        )
        vulnerable_sha = parent_commit(repo, fixed_sha)
        summary = changed_files(repo, vulnerable_sha, fixed_sha)
        patch_files = [
            {"path": f.path, "status": f.status, "additions": f.additions, "deletions": f.deletions}
            for f in summary.files
        ]
        additions, deletions = summary.additions, summary.deletions
        unsafe_skipped = summary.unsafe_paths_skipped

        with tempfile.TemporaryDirectory(prefix="vt-analysis-") as tmp:
            vulnerable_dir = Path(tmp) / "vulnerable"
            patched_dir = Path(tmp) / "patched"
            export_tree(repo, vulnerable_sha, vulnerable_dir)
            export_tree(repo, fixed_sha, patched_dir)
            for index in range(cfg.repeats):
                for label, directory in (("vulnerable", vulnerable_dir), ("patched", patched_dir)):
                    runs.append(
                        run_tests(
                            directory,
                            revision_label=label,
                            run_index=index,
                            test_file=cfg.test_file,
                            node_ids=list(cfg.node_ids) if cfg.node_ids else None,
                            approved=True,
                            timeout_seconds=cfg.timeout_seconds,
                        )
                    )

    evidence = EvidenceRecord(
        repository_revision=fixed_sha,
        fix_association=association,
        vulnerable_outcomes=_outcomes(runs, "vulnerable"),
        patched_outcomes=_outcomes(runs, "patched"),
    )
    status, reasons = derive_status(evidence)

    missing = list(advisory.missing_fields)
    missing_default = [
        "Affected version ranges are not mapped to repository commits by this tool.",
        "Coverage of the vulnerability class depends on the tests supplied in the repository.",
    ]
    if advisory.cve_id is None:
        missing_default.insert(0, "No CVE identifier is available for this record.")

    return {
        "analysis_id": uuid.uuid4().hex,
        "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "tool_version": __version__,
        "advisory": advisory.model_dump(mode="json"),
        "repository": {
            "name": repo.name,
            "kind": "local",
            "fixed_commit": fixed_sha,
            "vulnerable_commit": vulnerable_sha,
            "vulnerable_commit_basis": "inferred: first parent of the fix commit",
        },
        "fix_association": (
            {"kind": association.kind.value, "source": association.source} if association else None
        ),
        "patch": {
            "files": patch_files,
            "files_changed": len(patch_files),
            "additions": additions,
            "deletions": deletions,
            "unsafe_paths_skipped": unsafe_skipped,
        },
        "test": {
            "file": cfg.test_file,
            "selected": list(cfg.node_ids) if cfg.node_ids else [f"all tests in {cfg.test_file}"],
            "repeats": cfg.repeats,
        },
        "runs": [r.to_dict() for r in runs],
        "evidence_status": status.value,
        "status_reasons": reasons,
        "missing_evidence": missing + missing_default,
        "limitations": list(LIMITATIONS),
        "environment": {
            "python": platform.python_version(),
            "pytest": _pytest_version(),
            "platform": platform.system(),
        },
    }
