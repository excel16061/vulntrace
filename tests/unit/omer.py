"""Check that the synthetic dataset files still match their recorded SHA-256 hashes.

Run it explicitly, since pytest only collects test_*.py files by default:
    pytest tests/unit/omer.py
"""

import hashlib
import json

from vulntrace.config import PROJECT_ROOT


def test_synthetic_manifest_hashes_match_files():
    manifest = json.loads(
        (PROJECT_ROOT / "data" / "manifests" / "synthetic_manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["files"], "manifest lists no files"
    for rel_path, expected in manifest["files"].items():
        actual = hashlib.sha256((PROJECT_ROOT / rel_path).read_bytes()).hexdigest()
        assert actual == expected, f"hash mismatch for {rel_path}"
