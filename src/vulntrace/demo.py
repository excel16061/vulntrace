"""Offline synthetic demonstration.

Builds a temporary git repository with two commits (a vulnerable revision and a patched
revision, tagged as the advisory's fix reference), then analyzes it twice:

1. Primary: the full regression test file. Expected: VERIFIED_FOR_TESTED_CASE.
2. Negative control: only a test that passes on both revisions. Expected: INSUFFICIENT_EVIDENCE.

No network access is used.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Any

from vulntrace.analysis.pipeline import AnalysisConfig, analyze
from vulntrace.config import EXAMPLES_DIR, FIXTURES_DIR, RESULTS_DIR
from vulntrace.ingestion.advisory import load_advisory_fixture
from vulntrace.reporting.report import write_reports
from vulntrace.repositories.gitops import commit_all, create_tag, init_repository
from vulntrace.security import validate_git_ref

DEMO_TAG = "vt-synthetic-fixed"
CONTROL_NODE = "test_path_guard.py::test_normal_relative_path_allowed"


def build_demo_repository(repo: Path) -> None:
    """Create the two-commit synthetic repository inside ``repo`` (must be empty)."""
    init_repository(repo)
    shutil.copyfile(EXAMPLES_DIR / "synthetic_vulnerable" / "safe_join.py", repo / "safe_join.py")
    shutil.copyfile(EXAMPLES_DIR / "synthetic_tests" / "test_path_guard.py", repo / "test_path_guard.py")
    commit_all(repo, "Synthetic vulnerable revision")

    (repo / "safe_join.py").unlink()
    shutil.copyfile(EXAMPLES_DIR / "synthetic_patched" / "safe_join.py", repo / "safe_join.py")
    commit_all(repo, "Synthetic patched revision")

    validate_git_ref(DEMO_TAG)
    create_tag(repo, DEMO_TAG)


def _summary(result: dict[str, Any]) -> dict[str, Any]:
    runs = result["runs"]
    return {
        "analysis_id": result["analysis_id"],
        "evidence_status": result["evidence_status"],
        "vulnerable_outcomes": [r["outcome"] for r in runs if r["revision_label"] == "vulnerable"],
        "patched_outcomes": [r["outcome"] for r in runs if r["revision_label"] == "patched"],
        "selected_tests": result["test"]["selected"],
    }


def run_synthetic_demo(output_dir: Path = RESULTS_DIR / "demo") -> dict[str, Any]:
    """Run both analyses and write reports under ``output_dir``. Returns a summary dict."""
    advisory = load_advisory_fixture(FIXTURES_DIR / "synthetic_advisory.json")

    with tempfile.TemporaryDirectory(prefix="vt-demo-") as tmp:
        repo = Path(tmp) / "synthetic-pathutil"
        repo.mkdir()
        build_demo_repository(repo)
        primary = analyze(advisory, AnalysisConfig(repo_path=repo, repeats=3, approved=True))
        control = analyze(
            advisory,
            AnalysisConfig(repo_path=repo, node_ids=(CONTROL_NODE,), repeats=3, approved=True),
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    primary_paths = write_reports(primary, output_dir / "primary")
    control_paths = write_reports(control, output_dir / "control")

    summary = {
        "primary": _summary(primary),
        "control": _summary(control),
        "outputs": {
            "primary_json": primary_paths["json"].relative_to(output_dir).as_posix(),
            "primary_markdown": primary_paths["markdown"].relative_to(output_dir).as_posix(),
            "control_json": control_paths["json"].relative_to(output_dir).as_posix(),
            "control_markdown": control_paths["markdown"].relative_to(output_dir).as_posix(),
        },
    }
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary
