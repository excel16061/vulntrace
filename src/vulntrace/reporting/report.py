"""Evidence report writer (JSON and Markdown).

Sections separate recorded facts, tool observations, inferences and unknowns. The report
never states a confidence percentage and never labels the software as safe.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from vulntrace import __version__

DISCLAIMER = (
    "This report describes evidence for the selected test case only. It does not show that "
    "the software is secure or free of other vulnerabilities."
)


def _md_escape(text: object) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_markdown(result: dict[str, Any]) -> str:
    adv = result["advisory"]
    repo = result["repository"]
    test = result["test"]
    runs = result["runs"]
    lines: list[str] = []
    add = lines.append

    add(f"# VulnTrace evidence report: {_md_escape(adv['advisory_id'])}")
    add("")
    add(f"- Analysis ID: `{result['analysis_id']}`")
    add(f"- Created (UTC): {result['created_at']}")
    add(f"- Tool version: {result.get('tool_version', __version__)}")
    add("")
    add(f"> {DISCLAIMER}")
    add("")

    add("## Final evidence status")
    add("")
    add(f"**{result['evidence_status']}**")
    add("")
    for reason in result["status_reasons"]:
        add(f"- {_md_escape(reason)}")
    add("")

    add("## 1. Confirmed facts (recorded by the tool)")
    add("")
    add(f"- Advisory source: {_md_escape(adv['source'])}")
    add(f"- Advisory source reference: `{_md_escape(adv['source_ref'])}`")
    add(f"- Source SHA-256: `{adv['source_sha256']}`")
    add(f"- Retrieved (UTC): {adv['retrieved_at']}")
    add(f"- Advisory validation status: {adv['validation_status']}")
    add(f"- Repository: {_md_escape(repo['name'])} ({repo['kind']})")
    add(f"- Fixed-revision commit: `{repo['fixed_commit']}`")
    add("")
    if result["fix_association"]:
        add(f"- Fix association kind: `{result['fix_association']['kind']}`")
        add(f"- Fix association source: {_md_escape(result['fix_association']['source'])}")
        add("")
    patch = result["patch"]
    add(
        f"Patch summary: {patch['files_changed']} file(s) changed, "
        f"+{patch['additions']} / -{patch['deletions']} lines."
    )
    if patch["unsafe_paths_skipped"]:
        add(f"{patch['unsafe_paths_skipped']} path(s) were skipped for safety.")
    add("")
    if patch["files"]:
        add("| Path | Status | Additions | Deletions |")
        add("|---|---|---|---|")
        for f in patch["files"]:
            add(
                f"| {_md_escape(f['path'])} | {f['status']} | "
                f"{'-' if f['additions'] is None else f['additions']} | "
                f"{'-' if f['deletions'] is None else f['deletions']} |"
            )
        add("")

    add("## 2. Tool-generated observations")
    add("")
    selected = _md_escape(", ".join(test["selected"]))
    add(f"Test selection: {selected} (repeats per revision: {test['repeats']})")
    add("")
    if runs:
        add("| Revision | Run | Outcome | Exit code | Duration (s) |")
        add("|---|---|---|---|---|")
        for r in runs:
            add(
                f"| {r['revision_label']} | {r['run_index'] + 1} | {r['outcome']} | "
                f"{'-' if r['exit_code'] is None else r['exit_code']} | {r['duration_seconds']} |"
            )
        add("")
        for label in ("vulnerable", "patched"):
            counts = Counter(r["outcome"] for r in runs if r["revision_label"] == label)
            if counts:
                add(f"- {label} revision outcomes: {dict(counts)}")
        add("")
        last = runs[-1]
        cases = [c for c in last["test_cases"] if c["outcome"] != "passed"]
        if cases:
            add("Failing or erroring test cases in the last recorded run:")
            for c in cases:
                add(f"- `{_md_escape(c['name'])}`: {c['outcome']}")
            add("")
    else:
        add("No test runs were recorded.")
        add("")

    add("## 3. Inferences")
    add("")
    add(
        f"- The vulnerable revision `{repo['vulnerable_commit']}` is inferred as the first parent "
        "of the fix commit. It was not checked against affected-version metadata."
    )
    add(
        "- The fix association relies on the advisory's explicit reference. This tool did not "
        "independently verify the advisory's claim."
    )
    add("")

    add("## 4. Unknown or missing evidence")
    add("")
    for item in result["missing_evidence"]:
        add(f"- {_md_escape(item)}")
    add("")

    add("## 5. Environment and limitations")
    add("")
    env = result["environment"]
    add(f"- Python {env['python']}, pytest {env['pytest']}, platform {env['platform']}")
    for item in result["limitations"]:
        add(f"- {_md_escape(item)}")
    add("")

    add("## 6. Reproducibility")
    add("")
    add("Run the offline demonstration from a source checkout:")
    add("")
    add("```bash")
    add("make install")
    add("make demo")
    add("```")
    add("")
    return "\n".join(lines)


def render_json(result: dict[str, Any]) -> str:
    return json.dumps(result, indent=2, sort_keys=True) + "\n"


def write_reports(result: dict[str, Any], out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "report.json"
    md_path = out_dir / "report.md"
    json_path.write_text(render_json(result), encoding="utf-8")
    md_path.write_text(render_markdown(result), encoding="utf-8")
    return {"json": json_path, "markdown": md_path}
