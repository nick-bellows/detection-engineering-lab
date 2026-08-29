"""Thin CLI over detection_lab.catalog.validate_catalog.

python scripts/validate_catalog.py                 structural checks only
python scripts/validate_catalog.py --strict        every detection >= fixture-validated
python scripts/validate_catalog.py --require-validated
                                                   every detection VM-validated (expected
                                                   to fail until the Atomic run happens)
"""

from __future__ import annotations

import argparse
import sys

from detection_lab.catalog import validate_catalog


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate the detection lifecycle catalog")
    parser.add_argument("--strict", action="store_true", help="require >= fixture-validated")
    parser.add_argument(
        "--require-validated", action="store_true", help="require VM-validated status"
    )
    args = parser.parse_args()
    errors = validate_catalog(strict=args.strict, require_validated=args.require_validated)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    gate = "VM-validated" if args.require_validated else "strict" if args.strict else "structural"
    print(f"Detection catalog passes the {gate} gate.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
