# Limitations

## Current implementation (Milestone 1)

- **Synthetic evidence only.** The only executed analysis uses a synthetic repository with a deliberate
  path-traversal flaw. The results show that the pipeline behaves as designed. They say nothing about
  real vulnerabilities.
- **Not implemented yet:** REST API, Streamlit dashboard, SQLite persistence, online advisory import,
  Semgrep integration, Docker files, CITATION.cff, the real-case dataset, baseline and ablations.
- **Fix association is taken from the advisory.** The tool does not independently verify that the
  referenced commit fixes the vulnerability. The `CANDIDATE_FIX` path exists but is not produced by
  any pipeline yet.
- **Vulnerable revision is inferred.** It is the fix commit's first parent. Affected-version ranges are
  not mapped to commits.
- **Test selection is manual.** The analyst must choose the test file and node ids. The tool does not
  discover tests that cover the vulnerability.
- **Coverage is limited to the supplied tests.** A `VERIFIED_FOR_TESTED_CASE` status says nothing about
  other paths, other variants of the bug, or other vulnerabilities.
- **Single environment.** Runs use the local Python and pytest. Dependency environments of real
  projects are not reproduced.
- **Repeat runs are weak evidence here.** A deterministic example always agrees with itself.
- **Not a sandbox.** See [threat_model.md](threat_model.md).
- **Platform.** Developed and tested on Linux with Python 3.13. CI targets 3.12 but has not run.
- **Timestamps.** Times are recorded in UTC from the system clock. No time source is verified.

## Research limitations (to address before any claim)

- No sample of real public cases has been assembled, so no linkage or verification rate exists.
- No baseline has been implemented, so no comparison exists.
- Results from prototype tests, synthetic experiments and real cases must be reported separately.
- Publication details are not yet verified (see [references.md](references.md)).
