# Data provenance

## Datasets in this repository

| File | Origin | Kind | License |
|---|---|---|---|
| `data/fixtures/synthetic_advisory.json` | Written for this project | Synthetic advisory record. `cve_id` is null on purpose. | MIT (project license) |
| `examples/synthetic_vulnerable/safe_join.py` | Written for this project | Intentionally vulnerable example | MIT |
| `examples/synthetic_patched/safe_join.py` | Written for this project | Patched example | MIT |
| `examples/synthetic_tests/test_path_guard.py` | Written for this project | Regression test | MIT |

SHA-256 hashes for these files are in `data/manifests/synthetic_manifest.json`. To check them:

```bash
sha256sum data/fixtures/synthetic_advisory.json examples/synthetic_*/safe_join.py examples/synthetic_tests/test_path_guard.py
```

## Real-world data

None yet. When real public advisories are added, each record must document: the source URL, the
retrieval date, the raw file hash, the license or terms of the source, and any manual changes. No
entries will be invented or filled from memory.

## Provenance rules for future data

- Keep the raw source bytes, or their hash and reference, alongside the normalized record.
- Mark fields that are missing in the source as missing. Do not infer them.
- Record the reviewer and the date for each manual validation.
