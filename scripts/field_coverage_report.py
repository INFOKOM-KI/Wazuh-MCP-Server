#!/usr/bin/env python3
"""W0 field-coverage baseline report. No network, no runtime imports.

Usage:
  python3 scripts/field_coverage_report.py
  python3 scripts/field_coverage_report.py --strict
  python3 scripts/field_coverage_report.py --csv /tmp/field_coverage.csv

--strict exits 2 while any grandfathered baseline debt remains, which is the
post-W2/W4 CI target. --csv writes the full leaf-level and reference-level table.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests import field_coverage_lib as cov


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="W0 field-coverage baseline report")
    parser.add_argument("--strict", action="store_true",
                        help="exit 2 while any baseline debt remains")
    parser.add_argument("--csv", metavar="PATH",
                        help="also write the full leaf/reference table as CSV")
    parser.add_argument("--capability-csv", metavar="PATH",
                        help="also write the per-leaf handling-capability table as CSV")
    args = parser.parse_args(argv)

    manifest = cov.load_manifest()
    index = cov.load_template_index()
    refs = cov.scan_references()
    fixture_errors = cov.validate_fixture(manifest, index)
    result = cov.validate_references(manifest, index, refs, strict=args.strict)
    overlay = cov.load_overlay()
    rows = cov.derive_capabilities(index, overlay, manifest)
    capability_errors = cov.validate_capabilities(overlay, index, manifest, rows)
    print(cov.build_report(manifest, index, refs, fixture_errors, result))
    print(cov.render_capability_summary(rows))
    if capability_errors:
        print("\ncapability model issues:")
        for code, message in capability_errors:
            print(f"  [{code}] {message}")
    if args.csv:
        cov.write_csv(Path(args.csv), index, refs, manifest)
        print(f"\ncsv written: {args.csv}")
    if args.capability_csv:
        cov.write_capability_csv(Path(args.capability_csv), rows)
        print(f"capability csv written: {args.capability_csv}")
    return 0 if not (fixture_errors or result.errors or capability_errors) else 2


if __name__ == "__main__":
    sys.exit(main())
