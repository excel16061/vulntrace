# Threat model

## Assets

- The analysis host and the user's files.
- Integrity of the evidence records and reports.
- Confidentiality of any credentials that could appear in advisories, repositories or test output.

## Untrusted inputs

- Advisory JSON (fields, identifiers, URLs, version strings).
- Git repositories: tree entries, paths, file contents, symlinks, submodules, hooks, and test code.
- Test output, which may contain paths or secrets.
- Command-line arguments.

## Controls implemented

| Risk | Control | Where |
|---|---|---|
| Advisory injects shell or option text | Strict regex for identifiers, refs and node ids; `shell=False`; argument lists | `security.py`, `gitops.py`, `runner.py` |
| Path traversal in fixtures or repository paths | `ensure_within` after resolving symlinks; `safe_relative_path` rejects `..`, absolute and backslash paths | `security.py`, `advisory.py`, `gitops.py` |
| Symlink escape from a repository | Export refuses `120000` entries; test run refuses symlinks | `gitops.py`, `runner.py` |
| Git option injection (for example `--upload-pack`) | Ref validation rejects leading `-`; only allowlisted subcommands | `security.py`, `gitops.py` |
| Git hooks or global config executing code | `core.hooksPath=/dev/null`; `GIT_CONFIG_GLOBAL` and `GIT_CONFIG_NOSYSTEM` set | `gitops.py` |
| Running untrusted tests without consent | `approved=True` is required; `ApprovalRequiredError` otherwise | `runner.py`, `pipeline.py` |
| Test code hanging the tool | Subprocess timeout reported as `timeout` | `runner.py` |
| Leaking the environment to test code | Minimal environment; a test checks a secret variable is absent | `runner.py`, `tests/security` |
| Secrets in logs or reports | Token and password patterns redacted; local paths replaced by `<local>` | `security.py`, `runner.py` |
| SSRF through advisory URLs (future online mode) | https only; private, loopback, link-local and reserved literals rejected; local hostnames blocked | `security.py` |
| Oversized inputs | Fixture size, git output, export size and file-count limits | `config.py` and call sites |

## Limits and residual risk

- **Subprocess isolation is not a sandbox.** Test code runs as the same user with the same filesystem
  access. It can read and write any file that user can, and it can make network connections. Do not
  run repositories you do not trust. Containers or VMs would be needed for a real boundary.
- DNS is not resolved in URL validation, so DNS rebinding is not addressed. This matters only when
  online fetching is added.
- Resource limits (memory, CPU, process count) are not enforced yet.
- The demonstration does not fetch anything from the network.
- Advisory and repository content is treated as data. Advisory text is never executed.

## Out of scope

Scanning third-party systems, exploiting services, and automatically executing repository code are not
part of this project and are not supported.
