# Architecture plan (Phase 2, design only)

Status: **proposal, not implemented.** Nothing in this document has been run. Each component is marked
with its current state: `exists` (implemented and tested in Milestone 1), `planned` (designed here),
or `blocked` (needs data or an environment the project does not yet have).

## 1. Principles

1. Keep working code. Existing modules are extended, not renamed, unless a rename is needed for the
   target layout and covered by tests.
2. Every status and every value in a report traces to a recorded source: an advisory file hash, a git
   object, a test run log, or an explicit user decision.
3. Untrusted input (advisories, repositories, test code) never reaches a shell. Untrusted test code runs
   only inside a sandbox that is verified to be active. If it is not verified, the run is refused.
4. The deterministic engine decides status. Nothing optional (including any language model) can set
   `VERIFIED_FOR_TESTED_CASE`.

## 2. Module map

| Target module | Current file | State | Change |
|---|---|---|---|
| `vulntrace.ingestion.advisory` | `ingestion/advisory.py` | exists | Add `source` kinds for OSV records. Keep the fixture loader. |
| `vulntrace.collection.osv` | — | planned | Parse OSV JSON (from file in Phase 3). Online fetch is a later, optional step with allowlisted hosts. |
| `vulntrace.collection.nvd` | — | blocked | Needs NVD API access. Not planned until a data source is available. |
| `vulntrace.git.repository` | `repositories/gitops.py` | exists | Keep the allowlisted wrapper. Add `is_ancestor`, `tags_containing`, `merge_base`. |
| `vulntrace.git.revision_validator` | — | planned | Replaces the first-parent assumption (section 4). |
| `vulntrace.git.patch` | `repositories/gitops.py` (`changed_files`) | exists | Add changed function names for Python files (section 6). |
| `vulntrace.verification.discovery` | — | planned | Finds candidate test files that mention the fixed path or CVE. |
| `vulntrace.verification.runner` | `verification/runner.py` | exists | Keep. Execution moves behind the sandbox interface. |
| `vulntrace.sandbox` | — | planned | Interface plus Docker implementation (section 5). |
| `vulntrace.analysis.evidence` | `analysis/evidence.py` | exists | Add statuses from section 3. Keep the existing seven. |
| `vulntrace.analysis.pipeline` | `analysis/pipeline.py` | exists | Use the validator and sandbox. Support multiple fix commits. |
| `vulntrace.reporting` | `reporting/report.py` | exists | Add per-CVE summary and experiment summary. |
| `vulntrace.evaluation` | — | planned | Baselines and metrics (Phase 6). |
| `vulntrace.cli` | — | planned | `analyze`, `validate-dataset`, `report` first. Other commands only when implemented. |
| `vulntrace.api`, `dashboard/` | — | not planned | Out of scope until the CLI and evaluation are stable. |

## 3. Status model

Keep the existing names. Add the following, each with a required evidence rule:

| Status | Required evidence |
|---|---|
| `REVISION_VALIDATED` | Vulnerable and patched revisions both pass section 4 checks. |
| `REVISION_UNVERIFIED` | A revision could not be validated. The report names the failed check. |
| `REGRESSION_TEST_FAILED_ON_VULNERABLE` | Existing `TEST_FAILED_ON_VULNERABLE_REVISION` renamed in reports, with the same rules. |
| `REGRESSION_TEST_PASSED_ON_PATCHED` | Existing `TEST_PASSED_ON_PATCHED_REVISION` renamed in reports. |
| `INVALID_TEST` | The test passes on the vulnerable revision, or does not reference the vulnerable code path. |
| `ENVIRONMENT_FAILURE` | Setup, dependency installation, or sandbox failure. Not a test result. |
| `INCONCLUSIVE` | Runs disagree, or timeouts occurred. |
| `PARTIAL_EVIDENCE` | Some evidence present, not enough for a verification claim. |

Compatibility: the existing names stay as the stored value. The report also prints the new name. No
existing report field is removed. `VERIFIED_FOR_TESTED_CASE` keeps its current meaning: the same test
fails on the validated vulnerable revision and passes on the validated patched revision, in every run.

## 4. Revision validation (replaces "first parent")

For a fix commit `F`, the candidate vulnerable revisions are the parents of `F`. A merge commit has
several parents. Each candidate is checked:

1. **Ancestry:** `F` is reachable from the candidate, and the candidate is an ancestor of `F`
   (`git merge-base --is-ancestor`). Otherwise the candidate is rejected.
2. **Affected range:** if the advisory gives OSV `introduced`/`fixed` events, the candidate's version
   (nearest reachable tag) must fall inside an affected range. If no tag is reachable, the check returns
   `unknown`, not `pass`.
3. **Release context:** the fix's first release tag, if any, must be later than the candidate's
   version. This confirms the candidate predates the fix release.
4. **Multiple candidates:** all candidates that pass checks 1 to 3 are tested. A candidate that fails is
   listed in the report with the failed check. No candidate is substituted silently.

Output of this stage is a list: `{candidate_sha, checks: {ancestry, affected_range, release_context},
result: pass|fail|unknown, reason}`. If no candidate passes, the status is `REVISION_UNVERIFIED`.

Backports: a fix present on several branches yields several `F` values. Each is analyzed separately and
the report lists them together.

## 5. Sandbox (replaces "subprocess only" for untrusted code)

Current behavior: `runner.py` runs tests as a subprocess with a clean environment and a timeout. The
documentation already says this is not a sandbox. The plan:

- **Interface:** `Sandbox.run(revision_dir, command, limits) -> RunResult`. The command is a fixed argv
  built by the runner. The sandbox never accepts a shell string.
- **Docker implementation (planned, untested):** one disposable container per run, with flags such as
  `--network none`, `--read-only`, `--user 65534:65534`, `--cap-drop ALL`,
  `--security-opt no-new-privileges`, `--memory`, `--cpus`, `--pids-limit`, a `tmpfs` for `/tmp`, and
  the revision mounted read-only. No host credentials and no host paths other than the revision copy
  are mounted.
- **Verification before use:** the sandbox runs a probe (for example, an attempt to reach an external
  address that must fail, and a write to the read-only mount that must fail) before any real test.
  If the probe does not behave as expected, the run is refused with `ENVIRONMENT_FAILURE`.
- **Fallback:** the subprocess runner remains available only with `--unsafe-local` and a report line
  stating that the run had no sandbox. It is never the default.
- **Limits of this design:** a container is not a complete boundary against a determined kernel exploit.
  Reports state this. The threat model is updated accordingly.

## 6. Source-level comparison

- Changed files and line counts (exists).
- For Python files: changed top-level functions and classes, found with the standard library `ast`
  module on both revisions. Output is names and line ranges only. No code is executed.
- A changed file with no changed function is reported as "non-code change" rather than hidden.

## 7. Dataset path

1. OSV JSON files (supplied by the user in Phase 3) are parsed into `Advisory` records. Each record keeps
   its raw file hash, source id, and retrieval time.
2. Fix references of type `FIX` in the OSV record give candidate commit URLs. A URL is accepted only if
   its host is on an allowlist (`github.com`) and it contains a full 40-character SHA.
3. Each candidate case gets a manifest entry with the fields from the prompt. `validation_status` starts
   as `PENDING` and changes only through the validator and the test runs.
4. Cases that fail validation are kept in the manifest with the reason. They are excluded from the
   verified set, not deleted.

## 8. Phase 3 scope (after review)

Only these, each with tests:

1. OSV JSON parser and normalization (no network).
2. Revision validator (section 4), with synthetic repositories for: multiple parents, a backport, and an
   unreachable candidate.
3. Test discovery for a given fixed path.
4. Extend the evidence engine statuses (section 3) with unit tests for each rule.

Explicitly out of Phase 3: Docker, online fetching, the 10-CVE selection, and evaluation.

## 9. Risks specific to this design

- Affected-range data in OSV is incomplete for some ecosystems. Those cases fall to `unknown`, which
  lowers coverage. This is a measured result, not something to hide.
- Tags may be missing or not follow semantic versions. Release-context checks then return `unknown`.
- Docker availability on the user's machine is unconfirmed. Phase 4 cannot be tested until it is.
