"""Compile every Sigma rule to the Elastic and CrowdStrike LogScale targets.

python scripts/compile_rules.py          regenerate detections/compiled/
python scripts/compile_rules.py --check  fail if committed output differs from a fresh compile
"""

from __future__ import annotations

import argparse
import sys

from detection_lab.rules.compiler import (
    COMPILED_DIR,
    compile_all,
    drift,
    render_outputs,
    write_outputs,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Compile Sigma rules to SIEM targets")
    parser.add_argument("--check", action="store_true", help="report drift instead of writing")
    args = parser.parse_args()

    compiled = compile_all()
    files = render_outputs(compiled)
    for item in compiled:
        gaps = ", ".join(f"{t} ({r.split(':', 1)[0]})" for t, r in item.unsupported.items())
        print(
            f"{item.detection_id}: {len(item.outputs)} output(s)"
            + (f"; unsupported: {gaps}" if gaps else "")
        )

    if args.check:
        problems = drift(files)
        for problem in problems:
            print(f"DRIFT: {problem}")
        if problems:
            print("Compiled output is out of date; run `python scripts/compile_rules.py`.")
            return 1
        print("Compiled output matches the rules and pinned backends.")
        return 0

    written = write_outputs(files)
    print(
        f"Wrote {len(written)} file(s) under {COMPILED_DIR.relative_to(COMPILED_DIR.parents[1])}."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
