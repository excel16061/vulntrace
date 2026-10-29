"""SYNTHETIC regression test for the synthetic safe_join example.

- test_normal_relative_path_allowed passes on both revisions (does not distinguish them).
- test_parent_traversal_rejected and test_absolute_path_rejected fail on the vulnerable
  revision and pass on the patched revision.
"""

import pytest
from safe_join import safe_join


def test_normal_relative_path_allowed():
    assert safe_join("/srv/data", "reports/a.txt") == "/srv/data/reports/a.txt"


def test_parent_traversal_rejected():
    with pytest.raises(ValueError):
        safe_join("/srv/data", "../etc/passwd")


def test_absolute_path_rejected():
    with pytest.raises(ValueError):
        safe_join("/srv/data", "/etc/passwd")
