"""Shared command-line plumbing for run_all.py and for running a single check file."""
from __future__ import annotations

import argparse
import os
from typing import List

from .context import ValidationContext
from .excel_report import write_report
from .models import CheckResult, Method, METHOD_LABELS


def add_common_args(p: argparse.ArgumentParser) -> argparse.ArgumentParser:
    p.add_argument("--project", "-p",
                   default=os.environ.get("GCP_PROJECT") or os.environ.get("GOOGLE_CLOUD_PROJECT", ""),
                   help="GCP project id (defaults to $GCP_PROJECT / key-file / ADC project)")
    p.add_argument("--key-file", "-k",
                   default=os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", ""),
                   help="Path to a service-account JSON key file "
                        "(defaults to $GOOGLE_APPLICATION_CREDENTIALS; else uses gcloud ADC)")
    p.add_argument("--prowler", default="",
                   help="Path to a Prowler GCP output file (OCSF .json or .csv) to compare against")
    p.add_argument("--out", "-o", default="gcp_validation_report.xlsx",
                   help="Output .xlsx path")
    p.add_argument("--log-window-days", type=int, default=90,
                   help="Look-back window for method 3 (Cloud Audit Logs)")
    p.add_argument("--enable-exposure-probe", action="store_true",
                   help="Allow method 5 to make real outbound network connections")
    p.add_argument("--probe-timeout", type=float, default=4.0)
    p.add_argument("--evidence-dir", "--screenshots", dest="evidence_dir", default="",
                   help="Write a per-finding PNG audit evidence image into this directory")
    p.add_argument("--evidence-findings-only", action="store_true",
                   help="Only produce evidence images for likely false positives/negatives")
    p.add_argument("--verbose", "-v", action="store_true")
    return p


def context_from_args(args: argparse.Namespace) -> ValidationContext:
    project = args.project
    key_file = getattr(args, "key_file", "")
    # If no project was given, fall back to the project_id inside the key file.
    if not project and key_file:
        try:
            import json
            with open(key_file, "r", encoding="utf-8") as fh:
                project = json.load(fh).get("project_id", "") or ""
        except (OSError, ValueError):
            pass
    return ValidationContext.create(
        project=project,
        prowler_path=args.prowler,
        key_file=key_file,
        log_window_days=args.log_window_days,
        enable_exposure_probe=args.enable_exposure_probe,
        probe_timeout=args.probe_timeout,
        verbose=args.verbose,
    )


def print_check_result(result: CheckResult) -> None:
    print(f"\n=== {result.check_id}  ({result.service}/{result.severity}) ===")
    print(f"    {result.hub_link}")
    if result.error:
        print(f"    ! {result.error}")
    if not result.resources:
        print("    (no resources evaluated)")
    for rr in result.resources:
        pw = rr.prowler_status.value if rr.prowler_status else "-"
        line = "  • {name:<30} prowler={pw:<6} consensus={cons:<6} {agree}".format(
            name=(rr.resource_name or rr.resource_id)[:30], pw=pw,
            cons=rr.consensus().value, agree=rr.agreement(),
        )
        print(line)
        for method, label in METHOD_LABELS.items():
            mr = rr.methods.get(method)
            if mr:
                print(f"        {label:<20} {mr.verdict.value:<6} {mr.detail}")


def deeplink_fn_for(ctx):
    from .deeplinks import console_link
    return lambda cr, rr: console_link(cr, rr, ctx.project)


def emit_outputs(ctx, results, args) -> dict:
    """Write the Excel report (with console-link column) and, if requested, the
    per-finding audit evidence images."""
    dl = deeplink_fn_for(ctx)
    counts = write_report(results, args.out, deeplink_fn=dl)
    print(f"Wrote {args.out}")
    ev_dir = getattr(args, "evidence_dir", "")
    if ev_dir:
        from .evidence import write_evidence_images
        n = write_evidence_images(
            results, ev_dir, provider="GCP",
            scope_label=f"project: {ctx.project or '(ADC default)'}",
            deeplink_fn=dl, only_findings=getattr(args, "evidence_findings_only", False))
        print(f"Wrote {n} evidence image(s) to {ev_dir}")
    return counts


def run_single(check_cls) -> None:
    """Entry point used by each per-control file's __main__ block."""
    p = add_common_args(argparse.ArgumentParser(
        description=f"Validate Prowler check '{check_cls.check_id}'"))
    args = p.parse_args()
    ctx = context_from_args(args)
    result = check_cls().run(ctx)
    print_check_result(result)
    counts = emit_outputs(ctx, [result], args)
    print(f"Summary: {counts}")
