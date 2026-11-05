"""SYNTHETIC EXAMPLE: intentionally vulnerable revision used for demonstrations only.

This helper is not a real vulnerability record. It does not reject parent-directory
traversal ("..") or absolute paths, which is the flaw the regression test detects.
"""

import os


def safe_join(base: str, user_path: str) -> str:
    return os.path.normpath(os.path.join(base, user_path))
