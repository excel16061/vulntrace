# Methodology

## Status of this document

This document defines the intended evaluation design. **No real-world evaluation has been run.** The
only results so far come from the offline synthetic demonstration, which is a functionality check and
not evidence about real vulnerabilities.

## Research question and hypothesis

- Primary: can an evidence-linked pipeline make publicly documented fixes easier to verify than
  reviewing advisory metadata and existing tests alone?
- Hypothesis (to be tested): linking advisory metadata, repository history, patch information and test
  outcomes produces more traceable verification results than reviewing advisory metadata alone.

## Pipeline (as implemented)

1. Load an advisory fixture, validate fields, hash the raw bytes and record missing fields.
2. Resolve the advisory's explicit fix reference (tag or commit) to a commit SHA. Only explicit
   references are used. Commit messages are never used to infer a fix.
3. Infer the vulnerable revision as the fix commit's first parent. The report labels this as an
   inference.
4. Summarise the patch: changed files, change type and line counts.
5. Export both revisions with `git ls-tree` and `git cat-file`. Refuse symlinks and submodules.
6. Run the approved test file `N` times per revision, interleaving the revisions.
7. Derive the status with the pure function in `analysis/evidence.py`.

## Status rules

| Condition (checked in order) | Status |
|---|---|
| No revision resolved | `UNKNOWN` |
| No explicit fix reference | `INSUFFICIENT_EVIDENCE` |
| Only a candidate association | `CANDIDATE_FIX` |
| Any infrastructure error or timeout | `INSUFFICIENT_EVIDENCE` |
| Explicit reference, no runs | `PATCH_IDENTIFIED` |
| Only patched runs, all pass | `TEST_PASSED_ON_PATCHED_REVISION` |
| Vulnerable runs not all failing | `INSUFFICIENT_EVIDENCE` (test does not distinguish) |
| Vulnerable runs all failing, no patched runs | `TEST_FAILED_ON_VULNERABLE_REVISION` |
| Vulnerable all failing, patched all passing | `VERIFIED_FOR_TESTED_CASE` |
| Vulnerable all failing, patched not all passing | `INSUFFICIENT_EVIDENCE` |

Allowed moves when a case is re-analysed are listed in `ALLOWED_TRANSITIONS` and tested in
`tests/unit/test_evidence.py`.

## Metrics (defined, not yet computed on real cases)

Each metric will be reported with its denominator. Let `C` be the set of candidate cases that pass the
inclusion criteria below.

1. Advisory-to-repository linkage rate: `|{c in C : repository resolved}| / |C|`
2. Advisory-to-fix linkage rate: `|{c in C : explicit fix commit resolved}| / |C|`
3. Usable-test-evidence rate: `|{c in C : at least one test file runs without infrastructure error}| / |C|`
4. Verification rate: `|{c in C : status = VERIFIED_FOR_TESTED_CASE}| / |C|`
5. Consistency: for each case, the share of repeated runs that agree with the modal outcome on each revision.
6. Failure causes: counts of analysis failures grouped by documented cause.
7. Manual effort: minutes spent validating each association, recorded by hand.

Uncertainty intervals (for example, Wilson intervals) and any comparison test will be stated only when
computed. Prototype tests, synthetic experiments and real-case results will be reported separately.

## Baseline (planned)

The baseline is manual review of advisory metadata and existing test outcomes, without the linked
evidence workflow. The same cases will be used for both methods. Disagreements will be recorded.

## Inclusion criteria (planned)

A case is eligible if: it has a public advisory with a traceable source; a source repository is
identifiable; the affected version or revision is identifiable; a fix commit or tag is identifiable, or
the reason no fix was found is documented; and there is enough evidence to assess part of the pipeline.
Cases will not be chosen for how well they fit the system.

## Repeated runs

The synthetic demonstration uses three runs per revision. In a deterministic synthetic example, runs
are expected to agree. Repeat counts on real projects will measure nondeterminism only when the
selected tests have real variability.
