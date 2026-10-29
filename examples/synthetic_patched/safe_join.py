"""SYNTHETIC EXAMPLE: patched revision used for demonstrations only.

Rejects absolute paths and parent-directory traversal, and checks the joined result stays
under the base directory.
"""

import os


def safe_join(base: str, user_path: str) -> str:
    if os.path.isabs(user_path):
        raise ValueError("absolute paths are not allowed")
    if ".." in user_path.replace("\\", "/").split("/"):
        raise ValueError("path traversal is not allowed")
    base_norm = os.path.normpath(base)
    joined = os.path.normpath(os.path.join(base_norm, user_path))
    if not joined.startswith(base_norm + os.sep):
        raise ValueError("path escapes base directory")
    return joined
