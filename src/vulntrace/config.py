"""Project-wide paths and limits.

Paths assume a source checkout (src/ layout). They are not meant for wheel installs.
"""

from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
FIXTURES_DIR = PROJECT_ROOT / "data" / "fixtures"
EXAMPLES_DIR = PROJECT_ROOT / "examples"
RESULTS_DIR = PROJECT_ROOT / "results"

MAX_FIXTURE_BYTES = 1_000_000
MAX_URL_LENGTH = 2_048
MAX_GIT_OUTPUT_BYTES = 20_000_000
MAX_EXPORT_FILES = 500
MAX_EXPORT_BYTES = 5_000_000
MAX_TEST_OUTPUT_CHARS = 4_000
GIT_TIMEOUT_SECONDS = 30
TEST_TIMEOUT_SECONDS = 60
MAX_REPEATS = 10
