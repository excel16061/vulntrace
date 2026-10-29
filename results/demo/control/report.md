# VulnTrace evidence report: SYN-DEMO-0001

- Analysis ID: `3e8dcb42b7fb4523966f5a4eb2d4ec24`
- Created (UTC): 2026-10-29T00:32:49+00:00
- Tool version: 0.1.0

> This report describes evidence for the selected test case only. It does not show that the software is secure or free of other vulnerabilities.

## Final evidence status

**INSUFFICIENT_EVIDENCE**

- The test does not fail consistently on the vulnerable revision, so it cannot distinguish the revisions.

## 1. Confirmed facts (recorded by the tool)

- Advisory source: synthetic-demo
- Advisory source reference: `synthetic_advisory.json`
- Source SHA-256: `d10df9f5fd6ce147bce26f02d453f77a106705e9dd38f6f7304710a0c484462a`
- Retrieved (UTC): 2026-10-29T00:32:45.988284Z
- Advisory validation status: partial
- Repository: synthetic-pathutil (local)
- Fixed-revision commit: `e52b3833fde6b028e63f831e72d82df048b65166`

- Fix association kind: `explicit_reference`
- Fix association source: advisory fix_reference (tag: vt-synthetic-fixed)

Patch summary: 1 file(s) changed, +12 / -4 lines.

| Path | Status | Additions | Deletions |
|---|---|---|---|
| safe_join.py | M | 12 | 4 |

## 2. Tool-generated observations

Test selection: test_path_guard.py::test_normal_relative_path_allowed (repeats per revision: 3)

| Revision | Run | Outcome | Exit code | Duration (s) |
|---|---|---|---|---|
| vulnerable | 1 | passed | 0 | 0.251 |
| patched | 1 | passed | 0 | 0.272 |
| vulnerable | 2 | passed | 0 | 0.256 |
| patched | 2 | passed | 0 | 0.255 |
| vulnerable | 3 | passed | 0 | 0.251 |
| patched | 3 | passed | 0 | 0.253 |

- vulnerable revision outcomes: {'passed': 3}
- patched revision outcomes: {'passed': 3}

## 3. Inferences

- The vulnerable revision `37b6d134792b86796cdfd63fa24eb759abeaa3f1` is inferred as the first parent of the fix commit. It was not checked against affected-version metadata.
- The fix association relies on the advisory's explicit reference. This tool did not independently verify the advisory's claim.

## 4. Unknown or missing evidence

- cve_id
- No CVE identifier is available for this record.
- Affected version ranges are not mapped to repository commits by this tool.
- Coverage of the vulnerability class depends on the tests supplied in the repository.

## 5. Environment and limitations

- Python 3.15.1, pytest 9.1.1, platform Darwin
- Results cover one selected test file and one local environment.
- Repeated runs here are expected to agree; repeat counts do not measure real-project flakiness.
- The vulnerable revision is inferred as the first parent of the fix commit, not checked against affected-version metadata.
- Test execution uses subprocess isolation and a temporary directory. It is not a container, VM or security sandbox.

## 6. Reproducibility

Run the offline demonstration from a source checkout:

```bash
make install
make demo
```
