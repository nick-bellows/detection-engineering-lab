"""Render or verify the static detection evidence explorer."""

from __future__ import annotations

import argparse

from detection_lab.explorer import write_explorer


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail when docs/index.html is stale")
    return write_explorer(parser.parse_args().check)


if __name__ == "__main__":
    raise SystemExit(main())
