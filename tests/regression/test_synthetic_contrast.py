"""Regression check: the synthetic vulnerable and patched files produce contrasting outcomes.

This runs the approved test file directly against each example directory, without git, so
it isolates the test runner from the repository layer.
"""

import shutil

from vulntrace.config import EXAMPLES_DIR
from vulntrace.verification.runner import run_tests


def _revision(tmp_path, name):
    rev = tmp_path / name
    rev.mkdir()
    shutil.copyfile(EXAMPLES_DIR / "synthetic_tests" / "test_path_guard.py", rev / "test_path_guard.py")
    src = EXAMPLES_DIR / ("synthetic_vulnerable" if name == "vulnerable" else "synthetic_patched")
    shutil.copyfile(src / "safe_join.py", rev / "safe_join.py")
    return rev


def test_vulnerable_revision_fails_traversal_and_absolute_tests(tmp_path):
    run = run_tests(
        _revision(tmp_path, "vulnerable"),
        revision_label="vulnerable",
        run_index=0,
        test_file="test_path_guard.py",
        approved=True,
    )
    assert run.outcome == "failed"
    by_name = {c.name.split(".")[-1]: c.outcome for c in run.test_cases}
    assert by_name["test_normal_relative_path_allowed"] == "passed"
    assert by_name["test_parent_traversal_rejected"] == "failed"
    assert by_name["test_absolute_path_rejected"] == "failed"


def test_patched_revision_passes_all_tests(tmp_path):
    run = run_tests(
        _revision(tmp_path, "patched"),
        revision_label="patched",
        run_index=0,
        test_file="test_path_guard.py",
        approved=True,
    )
    assert run.outcome == "passed"
    assert all(c.outcome == "passed" for c in run.test_cases)
    assert len(run.test_cases) == 3
