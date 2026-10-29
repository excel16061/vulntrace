

from __future__ import annotations

import sys

from vulntrace.config import RESULTS_DIR
from vulntrace.demo import run_synthetic_demo


def main() -> int:
    output_dir = RESULTS_DIR / "demo"
    summary = run_synthetic_demo(output_dir=output_dir)
    primary, control = summary["primary"], summary["control"]
    print("VulnTrace synthetic demonstration (offline)")
    print(f"  primary  status: {primary['evidence_status']}")
    print(f"           vulnerable runs: {primary['vulnerable_outcomes']}")
    print(f"           patched runs:    {primary['patched_outcomes']}")
    print(f"  control  status: {control['evidence_status']}")
    print(f"           selected: {control['selected_tests']}")
    print(f"           vulnerable runs: {control['vulnerable_outcomes']}")
    print(f"Reports written to: {output_dir.relative_to(RESULTS_DIR.parent)}")
    expected = primary["evidence_status"] == "VERIFIED_FOR_TESTED_CASE" and (
        control["evidence_status"] == "INSUFFICIENT_EVIDENCE"
    )
    if not expected:
        print("Unexpected outcome; see the reports for details.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
