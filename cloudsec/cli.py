from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console

from cloudsec import __version__, report
from cloudsec.ai import analyze
from cloudsec.models import Severity

console = Console(stderr=True)


def _write(args, rep):
    report.to_terminal(rep)
    for path, fn in ((args.json, report.to_json), (args.markdown, report.to_markdown), (args.html, report.to_html)):
        if path:
            Path(path).write_text(fn(rep), encoding="utf-8")
            console.print(f"wrote {path}")


def _filter(findings, min_sev):
    floor = Severity(min_sev).weight
    return [f for f in findings if f.severity.weight >= floor]


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="cloudsec", description="AI-powered cloud security engine")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--json"); sp.add_argument("--markdown"); sp.add_argument("--html")
        sp.add_argument("--no-ai", action="store_true", help="skip AI; rule-based analysis only")
        sp.add_argument("--min-severity", default="INFO", choices=[s.value for s in Severity])
        sp.add_argument("--fail-on", choices=[s.value for s in Severity], help="exit 2 if any finding >= severity")

    a = sub.add_parser("aws", help="scan an AWS account (read-only)")
    a.add_argument("--profile"); a.add_argument("--region", default="ap-south-1")
    a.add_argument("--all-regions", action="store_true")
    a.add_argument("--services", help="comma list, e.g. s3,iam,ec2,rds,kms,cloudtrail,guardduty")
    common(a)
    t = sub.add_parser("iac", help="scan Terraform files"); t.add_argument("path"); common(t)
    d = sub.add_parser("dashboard", help="serve a JSON report on 127.0.0.1")
    d.add_argument("report"); d.add_argument("--port", type=int, default=8000)
    args = p.parse_args(argv)

    if args.cmd == "dashboard":
        from cloudsec.dashboard import serve
        serve(args.report, args.port)
        return 0

    errors: list[str] = []
    if args.cmd == "aws":
        from cloudsec.scanner import list_regions, make_session, scan
        session = make_session(args.profile, args.region)
        regions = list_regions(session) if args.all_regions else [args.region]
        services = set(args.services.split(",")) if args.services else None
        findings, errors = scan(session, regions, services)
    else:
        from cloudsec.iac import scan_path
        findings = scan_path(args.path)

    findings = _filter(findings, args.min_severity)
    if args.no_ai:
        from cloudsec.ai import rule_based
        rule_based(findings); mode_ai = "rules"
    else:
        mode_ai = analyze(findings)
    rep = report.build(findings, args.cmd, mode_ai, errors)
    _write(args, rep)
    if args.fail_on and any(f.severity.weight >= Severity(args.fail_on).weight for f in findings):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
