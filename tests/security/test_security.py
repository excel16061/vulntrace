"""Security tests for the highest-risk input and execution paths."""

import os
import subprocess
from pathlib import Path

import pytest

from vulntrace.ingestion.advisory import load_advisory_fixture
from vulntrace.repositories.gitops import (
    GitError,
    UnsafeRepositoryError,
    commit_all,
    export_tree,
    init_repository,
    resolve_commit,
    run_git,
)
from vulntrace.security import (
    ValidationError,
    redact,
    safe_relative_path,
    validate_git_ref,
    validate_node_id,
    validate_public_https_url,
)
from vulntrace.verification.runner import ApprovalRequiredError, RunnerError, run_tests

# ---- path handling -------------------------------------------------------

@pytest.mark.parametrize(
    "bad",
    ["../secrets.txt", "a/../../b", "/etc/passwd", "C:\\Windows\\x", "a\x00b", "", "a\\..\\b"],
)
def test_safe_relative_path_rejects_traversal_and_special_paths(bad):
    with pytest.raises(ValidationError):
        safe_relative_path(bad)


def test_safe_relative_path_accepts_nested_relative_path():
    assert str(safe_relative_path("pkg/mod/file.py")) == "pkg/mod/file.py"


def test_fixture_outside_fixtures_directory_is_rejected(tmp_path):
    outside = tmp_path / "evil.json"
    outside.write_text("{}", encoding="utf-8")
    with pytest.raises(ValidationError):
        load_advisory_fixture(outside, base_dir=tmp_path / "fixtures")


def test_fixture_symlink_escaping_directory_is_rejected(tmp_path):
    base = tmp_path / "fixtures"
    base.mkdir()
    target = tmp_path / "secret.json"
    target.write_text("{}", encoding="utf-8")
    link = base / "link.json"
    os.symlink(target, link)
    with pytest.raises(ValidationError):
        load_advisory_fixture(link, base_dir=base)


def test_oversized_fixture_is_rejected(tmp_path):
    big = tmp_path / "big.json"
    big.write_bytes(b"{" + b" " * 1_100_000 + b"}")
    with pytest.raises(ValidationError):
        load_advisory_fixture(big, base_dir=tmp_path)


# ---- URLs ----------------------------------------------------------------

@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/x",
        "https://localhost/x",
        "https://127.0.0.1/x",
        "https://10.0.0.5/x",
        "https://169.254.169.254/latest/meta-data",
        "https://[::1]/x",
        "https://user:pass@example.com/x",
        "file:///etc/passwd",
        "https://printer.internal/x",
        "https://" + "a" * 2100 + ".com/",
    ],
)
def test_url_validation_blocks_local_private_and_non_https(url):
    with pytest.raises(ValidationError):
        validate_public_https_url(url)


def test_public_https_url_is_accepted():
    assert validate_public_https_url("https://github.com/owner/repo") == "https://github.com/owner/repo"


# ---- git refs and subcommands -------------------------------------------

@pytest.mark.parametrize("ref", ["--upload-pack=/bin/sh", "-x", "a..b", "$(id)", "x;rm", "a b"])
def test_git_refs_that_look_like_options_or_shell_are_rejected(ref):
    with pytest.raises(ValidationError):
        validate_git_ref(ref)


def test_disallowed_git_subcommand_is_refused(tmp_path):
    repo = tmp_path / "r"
    init_repository(repo)
    with pytest.raises(GitError):
        run_git(repo, "push", ["origin"])
    with pytest.raises(GitError):
        run_git(repo, "config", ["--list"], write=False)


def test_resolve_commit_refuses_option_injection(tmp_path):
    repo = tmp_path / "r"
    init_repository(repo)
    with pytest.raises(ValidationError):
        resolve_commit(repo, "--output=/tmp/pwned")


# ---- repository export ---------------------------------------------------

def test_export_refuses_symlinks(tmp_path):
    repo = tmp_path / "r"
    init_repository(repo)
    (repo / "ok.txt").write_text("ok", encoding="utf-8")
    os.symlink("/etc/passwd", repo / "link")
    commit_all(repo, "symlink revision")
    sha = run_git(repo, "rev-parse", ["HEAD"]).decode().strip()
    with pytest.raises(UnsafeRepositoryError):
        export_tree(repo, sha, tmp_path / "out")
    assert not (tmp_path / "out" / "link").exists()


# ---- secrets and redaction ----------------------------------------------

def test_redact_removes_token_like_values():
    text = "ghp_" + "A" * 36 + " and password=hunter2 and Bearer abc.def"
    cleaned = redact(text)
    assert "ghp_AAAA" not in cleaned
    assert "hunter2" not in cleaned
    assert "abc.def" not in cleaned


# ---- test execution approval and selection ------------------------------

def _tiny_revision(tmp_path: Path) -> Path:
    rev = tmp_path / "rev"
    rev.mkdir()
    (rev / "test_tiny.py").write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    return rev


def test_runner_refuses_without_approval(tmp_path):
    with pytest.raises(ApprovalRequiredError):
        run_tests(_tiny_revision(tmp_path), revision_label="x", run_index=0, test_file="test_tiny.py")


@pytest.mark.parametrize(
    "bad_file",
    ["../test_tiny.py", "sub/test_tiny.py", "tiny.py", "test_tiny.sh", "/abs/test_tiny.py"],
)
def test_runner_rejects_unapproved_test_file_names(tmp_path, bad_file):
    with pytest.raises((ValidationError, RunnerError)):
        run_tests(
            _tiny_revision(tmp_path),
            revision_label="x",
            run_index=0,
            test_file=bad_file,
            approved=True,
        )


def test_runner_rejects_node_id_injection(tmp_path):
    with pytest.raises(ValidationError):
        run_tests(
            _tiny_revision(tmp_path),
            revision_label="x",
            run_index=0,
            test_file="test_tiny.py",
            node_ids=["test_tiny.py::test_ok; rm -rf /"],
            approved=True,
        )


def test_node_id_must_belong_to_approved_file():
    with pytest.raises(ValidationError):
        validate_node_id("other_file.py::test_ok", "test_tiny.py")


def test_runner_refuses_revision_containing_symlink(tmp_path):
    rev = _tiny_revision(tmp_path)
    os.symlink("/etc", rev / "etc_link")
    with pytest.raises(RunnerError):
        run_tests(rev, revision_label="x", run_index=0, test_file="test_tiny.py", approved=True)


def test_runner_does_not_inherit_secret_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("VT_SECRET_TEST_VALUE", "should-not-leak")
    rev = tmp_path / "rev"
    rev.mkdir()
    (rev / "test_env.py").write_text(
        "import os\n\ndef test_env():\n    assert 'VT_SECRET_TEST_VALUE' not in os.environ\n",
        encoding="utf-8",
    )
    run = run_tests(rev, revision_label="x", run_index=0, test_file="test_env.py", approved=True)
    assert run.outcome == "passed"


def test_runner_timeout_is_reported_not_raised(tmp_path):
    rev = tmp_path / "rev"
    rev.mkdir()
    (rev / "test_slow.py").write_text(
        "import time\n\ndef test_slow():\n    time.sleep(30)\n", encoding="utf-8"
    )
    run = run_tests(
        rev, revision_label="x", run_index=0, test_file="test_slow.py", approved=True, timeout_seconds=1
    )
    assert run.outcome == "timeout"
    assert run.exit_code is None


def test_git_is_available_for_security_tests():
    # Guard so a missing git binary fails loudly instead of silently skipping security checks.
    subprocess.run(["git", "--version"], check=True, capture_output=True)
