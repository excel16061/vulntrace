"""Wrapper around the git CLI.

Rules enforced here:
- Only allowlisted subcommands run (read-only set by default; a separate write set is
  used only by the synthetic demo builder).
- Arguments are passed as a list with shell=False.
- Hooks, global and system git config are disabled.
- Output size and runtime are bounded.
- Exported trees refuse symlinks, submodules and unsafe paths.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from vulntrace.config import (
    GIT_TIMEOUT_SECONDS,
    MAX_EXPORT_BYTES,
    MAX_EXPORT_FILES,
    MAX_GIT_OUTPUT_BYTES,
)
from vulntrace.security import (
    ValidationError,
    ensure_within,
    safe_relative_path,
    validate_commit_sha,
    validate_git_ref,
)

READ_ONLY_SUBCOMMANDS = frozenset({"rev-parse", "diff", "ls-tree", "cat-file"})
WRITE_SUBCOMMANDS = frozenset({"init", "add", "commit", "tag"})
_ALLOWED_EXPORT_MODES = frozenset({"100644", "100755"})


class GitError(RuntimeError):
    """A git command failed or was refused. Messages omit git's stderr to avoid leaking paths."""


class UnsafeRepositoryError(RuntimeError):
    """The repository contains entries that this tool refuses to export."""


@dataclass(frozen=True)
class ChangedFile:
    path: str
    status: str
    additions: int | None
    deletions: int | None


@dataclass(frozen=True)
class PatchSummary:
    files: tuple[ChangedFile, ...]
    unsafe_paths_skipped: int

    @property
    def additions(self) -> int:
        return sum(f.additions or 0 for f in self.files)

    @property
    def deletions(self) -> int:
        return sum(f.deletions or 0 for f in self.files)


def _clean_env() -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
    }


def run_git(
    repo: Path,
    subcommand: str,
    args: list[str],
    *,
    write: bool = False,
    timeout: int = GIT_TIMEOUT_SECONDS,
) -> bytes:
    """Run an allowlisted git subcommand and return raw stdout bytes."""
    allowed = WRITE_SUBCOMMANDS if write else READ_ONLY_SUBCOMMANDS
    if subcommand not in allowed:
        raise GitError(f"git subcommand not allowed: {subcommand}")
    for arg in args:
        if not isinstance(arg, str) or "\x00" in arg:
            raise GitError("git arguments must be NUL-free strings")

    prefix = ["git", "-c", "core.hooksPath=/dev/null", "--no-pager", "-C", str(repo)]
    if write:
        prefix += [
            "-c", "user.name=VulnTrace Demo",
            "-c", "user.email=demo@example.invalid",
            "-c", "commit.gpgsign=false",
        ]
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, shell=False
            [*prefix, subcommand, *args],
            capture_output=True,
            timeout=timeout,
            check=False,
            env=_clean_env(),
        )
    except subprocess.TimeoutExpired as exc:
        raise GitError(f"git {subcommand} timed out") from exc
    if proc.returncode != 0:
        raise GitError(f"git {subcommand} failed (exit {proc.returncode})")
    if len(proc.stdout) > MAX_GIT_OUTPUT_BYTES:
        raise GitError(f"git {subcommand} output exceeded limit")
    return proc.stdout


def resolve_commit(repo: Path, ref: str) -> str:
    """Resolve a validated ref (tag or branch name) to a full commit SHA."""
    validate_git_ref(ref)
    out = run_git(repo, "rev-parse", ["--verify", "--quiet", f"{ref}^{{commit}}"])
    sha = out.decode("ascii", "replace").strip()
    return validate_commit_sha(sha)


def parent_commit(repo: Path, sha: str) -> str:
    """Return the first parent of a commit. Raises GitError when there is none."""
    validate_commit_sha(sha)
    out = run_git(repo, "rev-parse", ["--verify", "--quiet", f"{sha}^"])
    return validate_commit_sha(out.decode("ascii", "replace").strip())


def changed_files(repo: Path, parent: str, commit: str) -> PatchSummary:
    """Summarise files changed between two commits (renames disabled for simplicity)."""
    validate_commit_sha(parent)
    validate_commit_sha(commit)

    status_raw = run_git(
        repo, "diff", ["--name-status", "--no-renames", "-z", parent, commit]
    )
    tokens = [t for t in status_raw.split(b"\0") if t]
    statuses: dict[str, str] = {}
    order: list[str] = []
    unsafe = 0
    for i in range(0, len(tokens) - 1, 2):
        status = tokens[i].decode("ascii", "replace")[:1]
        raw_path = tokens[i + 1].decode("utf-8", "replace")
        try:
            safe_relative_path(raw_path)
        except ValidationError:
            unsafe += 1
            continue
        statuses[raw_path] = status
        order.append(raw_path)

    numstat_raw = run_git(
        repo, "diff", ["--numstat", "--no-renames", "-z", parent, commit]
    )
    counts: dict[str, tuple[int | None, int | None]] = {}
    for record in numstat_raw.split(b"\0"):
        if not record:
            continue
        adds_b, _, rest = record.partition(b"\t")
        dels_b, _, path_b = rest.partition(b"\t")
        path = path_b.decode("utf-8", "replace")
        additions = None if adds_b == b"-" else int(adds_b)
        deletions = None if dels_b == b"-" else int(dels_b)
        counts[path] = (additions, deletions)

    files = tuple(
        ChangedFile(
            path=p,
            status=statuses[p],
            additions=counts.get(p, (None, None))[0],
            deletions=counts.get(p, (None, None))[1],
        )
        for p in order
    )
    return PatchSummary(files=files, unsafe_paths_skipped=unsafe)


def export_tree(repo: Path, commit: str, dest: Path) -> list[str]:
    """Write the regular files of a commit into dest. Returns the exported relative paths."""
    validate_commit_sha(commit)
    dest.mkdir(parents=True, exist_ok=True)
    listing = run_git(repo, "ls-tree", ["-r", "-z", "--full-tree", commit])

    entries: list[tuple[str, str]] = []
    for record in listing.split(b"\0"):
        if not record:
            continue
        meta, _, path_b = record.partition(b"\t")
        fields = meta.decode("ascii", "replace").split(" ")
        if len(fields) != 3:
            raise UnsafeRepositoryError("unexpected tree entry format")
        mode, object_type, obj = fields
        if mode == "120000":
            raise UnsafeRepositoryError("symbolic links are not exported")
        if mode == "160000":
            raise UnsafeRepositoryError("submodules are not exported")
        if mode not in _ALLOWED_EXPORT_MODES or object_type != "blob":
            raise UnsafeRepositoryError("unsupported tree entry")
        try:
            rel = safe_relative_path(path_b.decode("utf-8"))
        except (UnicodeDecodeError, ValidationError) as exc:
            raise UnsafeRepositoryError("unsafe path in repository tree") from exc
        entries.append((str(rel), obj))

    if len(entries) > MAX_EXPORT_FILES:
        raise UnsafeRepositoryError("repository exceeds the export file limit")

    total = 0
    exported: list[str] = []
    for rel_str, obj in entries:
        data = run_git(repo, "cat-file", ["blob", obj])
        total += len(data)
        if total > MAX_EXPORT_BYTES:
            raise UnsafeRepositoryError("repository exceeds the export size limit")
        target = dest.joinpath(*rel_str.split("/"))
        ensure_within(dest, target)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        exported.append(rel_str)
    return exported


def init_repository(repo: Path) -> None:
    repo.mkdir(parents=True, exist_ok=True)
    run_git(repo, "init", ["-q"], write=True)


def commit_all(repo: Path, message: str) -> None:
    run_git(repo, "add", ["-A"], write=True)
    run_git(repo, "commit", ["-q", "-m", message], write=True)


def create_tag(repo: Path, name: str) -> None:
    validate_git_ref(name)
    run_git(repo, "tag", [name], write=True)
