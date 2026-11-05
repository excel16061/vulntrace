"""Controlled regression test runner.

Runs a single approved test file (optionally restricted to named node ids) in a copy of a
revision, inside a fresh temporary directory, with a minimal environment, a timeout, and
no shell. This is subprocess isolation, not a security sandbox (see docs/threat_model.md).
"""

from __future__ import annotations

import importlib.metadata
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from defusedxml import ElementTree

from vulntrace.config import MAX_TEST_OUTPUT_CHARS, TEST_TIMEOUT_SECONDS
from vulntrace.security import (
    ValidationError,
    redact,
    safe_relative_path,
    validate_node_id,
)

_TEST_FILE_NAME_MAX = 80


class ApprovalRequiredError(PermissionError):
    """Repository-provided tests may run only after explicit approval."""


class RunnerError(RuntimeError):
    """The runner refused or could not prepare a test run."""


@dataclass(frozen=True)
class TestCaseResult:
    name: str
    outcome: str


@dataclass
class TestRun:
    revision_label: str
    run_index: int
    outcome: str
    exit_code: int | None
    duration_seconds: float
    test_cases: list[TestCaseResult] = field(default_factory=list)
    command: list[str] = field(default_factory=list)
    python_version: str = ""
    pytest_version: str = ""
    stdout_tail: str = ""
    stderr_tail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _validate_test_file(test_file: str) -> str:
    rel = safe_relative_path(test_file)
    name = rel.name
    if len(rel.parts) != 1 or not name.startswith("test_") or not name.endswith(".py"):
        raise ValidationError("test file must be a top-level test_*.py file")
    if len(name) > _TEST_FILE_NAME_MAX + len("test_.py"):
        raise ValidationError("test file name is too long")
    return name


def _check_no_symlinks(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_symlink():
            raise RunnerError("symbolic links are not allowed in a test revision")


def _parse_junit(path: Path) -> list[TestCaseResult]:
    tree = ElementTree.parse(path)
    cases: list[TestCaseResult] = []
    for case in tree.getroot().iter("testcase"):
        name = f"{case.get('classname', '')}.{case.get('name', '')}".strip(".")
        tags = {child.tag for child in case}
        if "failure" in tags:
            outcome = "failed"
        elif "error" in tags:
            outcome = "infrastructure_error"
        elif "skipped" in tags:
            outcome = "skipped"
        else:
            outcome = "passed"
        cases.append(TestCaseResult(name=name, outcome=outcome))
    return cases


def _tail(data: bytes, local_paths: list[str]) -> str:
    """Decode, scrub local filesystem paths and secrets, and keep only the last part."""
    text = data.decode("utf-8", "replace")
    for path in sorted(set(local_paths), key=len, reverse=True):
        if path:
            text = text.replace(path, "<local>")
    text = redact(text)
    return text[-MAX_TEST_OUTPUT_CHARS:]


def run_tests(
    source_dir: Path,
    *,
    revision_label: str,
    run_index: int,
    test_file: str,
    node_ids: list[str] | None = None,
    approved: bool = False,
    timeout_seconds: int = TEST_TIMEOUT_SECONDS,
) -> TestRun:
    """Run the approved test file (or selected node ids) against a copy of source_dir."""
    if not approved:
        raise ApprovalRequiredError("repository-provided tests require explicit approval")
    if not source_dir.is_dir():
        raise RunnerError("revision directory does not exist")

    file_name = _validate_test_file(test_file)
    if not (source_dir / file_name).is_file():
        raise RunnerError("approved test file is missing from the revision")

    targets: list[str]
    if node_ids:
        targets = [validate_node_id(n, file_name) for n in node_ids]
    else:
        targets = [file_name]

    _check_no_symlinks(source_dir)

    # Logical command recorded in reports: no local filesystem paths.
    logical_command = ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider", *targets]

    with tempfile.TemporaryDirectory(prefix="vt-run-") as tmp:
        work = Path(tmp) / "revision"
        junit = Path(tmp) / "junit.xml"
        shutil.copytree(source_dir, work, symlinks=False)
        local_paths = [tmp, str(work), str(source_dir), sys.executable, str(Path.cwd())]

        cmd = [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            f"--junitxml={junit}",
            "--rootdir",
            str(work),
            *targets,
        ]
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": tmp,
            "TMPDIR": tmp,
            "LANG": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "PYTHONNOUSERSITE": "1",
        }

        pytest_version = _pytest_version()
        python_version = platform.python_version()
        started = time.monotonic()
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, shell=False, sandboxed cwd and env
                cmd,
                cwd=work,
                env=env,
                capture_output=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return TestRun(
                revision_label=revision_label,
                run_index=run_index,
                outcome="timeout",
                exit_code=None,
                duration_seconds=round(time.monotonic() - started, 3),
                command=logical_command,
                python_version=python_version,
                pytest_version=pytest_version,
            )
        duration = round(time.monotonic() - started, 3)

        cases = _parse_junit(junit) if junit.is_file() else []
        if proc.returncode == 0:
            outcome = "passed"
        elif proc.returncode == 1:
            outcome = "failed"
        else:
            outcome = "infrastructure_error"
        if not cases and outcome in {"passed", "failed"}:
            outcome = "infrastructure_error"
        if any(c.outcome == "infrastructure_error" for c in cases):
            outcome = "infrastructure_error"

        return TestRun(
            revision_label=revision_label,
            run_index=run_index,
            outcome=outcome,
            exit_code=proc.returncode,
            duration_seconds=duration,
            test_cases=cases,
            command=logical_command,
            python_version=python_version,
            pytest_version=pytest_version,
            stdout_tail=_tail(proc.stdout, local_paths),
            stderr_tail=_tail(proc.stderr, local_paths),
        )


def _pytest_version() -> str:
    try:
        return importlib.metadata.version("pytest")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"
