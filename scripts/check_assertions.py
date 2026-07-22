"""
check_assertions.py - Run every formal assertion in alloy/predicates.als and report
which ones hold, exiting non-zero if any is violated.

USAGE:
python scripts/check_assertions.py --repo-root .
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

_SCRIPTS_DIR = Path(__file__).parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

import alloy_checks

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the Alloy model's formal assertions and report violations.",
    )
    parser.add_argument("--repo-root", default=".")
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    tmp_dir = Path(tempfile.mkdtemp(prefix="check_assertions_"))

    results = alloy_checks.run_check_commands(repo_root, tmp_dir)

    violated = []
    for name in alloy_checks.CHECK_NAMES:
        status = "VIOLATED" if results[name] else "holds"
        print(f"  {name}: {status}")
        if results[name]:
            violated.append(name)

    print()
    if violated:
        print(f"{len(violated)} assertion(s) violated: {', '.join(violated)}")
        sys.exit(1)
    print(f"All {len(alloy_checks.CHECK_NAMES)} assertions hold.")


if __name__ == "__main__":
    main()
