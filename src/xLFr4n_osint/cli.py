"""Compatibility alias for an accidental legacy package-path variant.

The canonical CLI lives in :mod:`xlfr4n_osint.cli`.
"""

from xlfr4n_osint.cli import build_parser, build_registry, main

__all__ = ["build_parser", "build_registry", "main"]


if __name__ == "__main__":
    raise SystemExit(main())
