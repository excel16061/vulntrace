"""Integration test: the full offline demonstration on the synthetic repository."""

import json

from vulntrace.demo import CONTROL_NODE, run_synthetic_demo


def test_demo_produces_expected_contrasting_outcomes(tmp_path):
    summary = run_synthetic_demo(output_dir=tmp_path)

    primary = summary["primary"]
    assert primary["evidence_status"] == "VERIFIED_FOR_TESTED_CASE"
    assert primary["vulnerable_outcomes"] == ["failed", "failed", "failed"]
    assert primary["patched_outcomes"] == ["passed", "passed", "passed"]

    control = summary["control"]
    assert control["selected_tests"] == [CONTROL_NODE]
    assert control["evidence_status"] == "INSUFFICIENT_EVIDENCE"
    assert control["vulnerable_outcomes"] == ["passed", "passed", "passed"]


def test_demo_writes_json_and_markdown_reports(tmp_path):
    run_synthetic_demo(output_dir=tmp_path)
    report = json.loads((tmp_path / "primary" / "report.json").read_text(encoding="utf-8"))
    assert report["evidence_status"] == "VERIFIED_FOR_TESTED_CASE"
    assert report["repository"]["fixed_commit"] and len(report["repository"]["fixed_commit"]) == 40
    assert report["patch"]["files_changed"] == 1
    assert any(f["path"] == "safe_join.py" for f in report["patch"]["files"])

    markdown = (tmp_path / "primary" / "report.md").read_text(encoding="utf-8")
    assert "VERIFIED_FOR_TESTED_CASE" in markdown
    assert "does not show the software is secure" in markdown
    assert "%" not in markdown  # no unsupported confidence percentages
    assert str(tmp_path) not in markdown  # no local filesystem paths in the report


def test_reports_contain_no_local_paths_in_json(tmp_path):
    run_synthetic_demo(output_dir=tmp_path)
    raw = (tmp_path / "primary" / "report.json").read_text(encoding="utf-8")
    assert "/tmp" not in raw  # noqa: S108 - asserting absence of a temp path
    assert "/home/" not in raw
