#!/usr/bin/env python3
"""Run many GCP validation checks and write one consolidated Excel report.

Examples
--------
  # validate every implemented check against a Prowler OCSF export
  python run_all.py --project my-proj --prowler prowler-output.ocsf.json -o report.xlsx

  # only Cloud SQL, and actually probe internet exposure
  python run_all.py -p my-proj --service cloudsql --enable-exposure-probe

  # just list what is implemented
  python run_all.py --list
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gcpval.cli import add_common_args, context_from_args, print_check_result  # noqa: E402
from gcpval.excel_report import write_report  # noqa: E402
from gcpval.runner import discover_check_classes, run_checks  # noqa: E402


def main() -> None:
    p = add_common_args(argparse.ArgumentParser(
        description="Cross-validate Prowler GCP findings with independent checks"))
    p.add_argument("--service", help="only run checks for this service (e.g. cloudsql)")
    p.add_argument("--check", action="append", default=[],
                   help="only run specific check id(s); repeatable")
    p.add_argument("--list", action="store_true", help="list discovered checks and exit")
    args = p.parse_args()

    classes = discover_check_classes("checks", service=args.service)
    if args.check:
        wanted = set(args.check)
        classes = [c for c in classes if c.check_id in wanted]

    if args.list:
        for c in classes:
            print(f"{c.check_id:<70} {c.service}")
        print(f"\ntotal: {len(classes)} checks")
        return

    if not classes:
        print("No checks matched. Try --list.")
        return

    ctx = context_from_args(args)
    print(f"Running {len(classes)} check(s) against project '{ctx.project or '(ADC default)'}'"
          f"{' with Prowler comparison' if len(ctx.prowler) else ''} ...")
    results = run_checks(classes, ctx)
    for r in results:
        print_check_result(r)
    counts = write_report(results, args.out)
    print(f"\nWrote {args.out}")
    print(f"Summary: {counts}")


if __name__ == "__main__":
    main()
