from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from rich.console import Console
from rich.table import Table

from cloudsec.models import Finding, security_score

SEV_STYLE = {"CRITICAL": "bold white on red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim"}


def _sorted(findings):
    return sorted(findings, key=lambda f: ((f.ai or {}).get("priority", 9999), -f.severity.weight))


def build(findings: list[Finding], mode: str, analysis: str, errors: list[str] | None = None) -> dict:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "mode": mode, "analysis": analysis, "score": security_score(findings),
        "summary": counts, "errors": errors or [],
        "findings": [f.to_dict() for f in _sorted(findings)],
    }


def to_terminal(report: dict, console: Console | None = None) -> None:
    console = console or Console()
    console.print(f"[bold]Security score:[/bold] {report['score']}/100  "
                  f"(mode={report['mode']}, analysis={report['analysis']})")
    t = Table(show_lines=False)
    for c in ("#", "Severity", "Check", "Title", "Resource", "Region"):
        t.add_column(c)
    for i, f in enumerate(report["findings"], 1):
        t.add_row(str(i), f"[{SEV_STYLE[f['severity']]}]{f['severity']}[/]", f["check_id"], f["title"],
                  f["resource"], f["region"])
    console.print(t)
    for e in report["errors"]:
        console.print(f"[dim]warning: {e}[/dim]")


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2, default=str)


def to_markdown(report: dict) -> str:
    lines = ["# Cloud Security Report", "",
             f"- Generated: {report['generated_at']}", f"- Mode: {report['mode']}",
             f"- Analysis: {report['analysis']}", f"- **Security score: {report['score']}/100**", "",
             "| Severity | Count |", "|---|---|"]
    for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if report["summary"].get(s):
            lines.append(f"| {s} | {report['summary'][s]} |")
    lines.append("")
    for i, f in enumerate(report["findings"], 1):
        ai = f.get("ai") or {}
        lines += [f"## {i}. [{f['severity']}] {f['title']}", "",
                  f"- **Check:** `{f['check_id']}`  **Resource:** `{f['resource']}`  **Region:** {f['region']}",
                  f"- **Compliance:** {', '.join(f['compliance'])}", "",
                  f"**Why it matters:** {ai.get('explanation', f['description'])}", ""]
        if ai.get("attack_scenario"):
            lines += [f"**Attack scenario:** {ai['attack_scenario']}", ""]
        lines.append("**Remediation:**")
        lines += [f"{n}. {s}" for n, s in enumerate(ai.get("remediation_steps") or [f["remediation"]], 1)]
        lines.append("")
        if ai.get("cli_fix"):
            lines += ["```bash", ai["cli_fix"], "```", ""]
        if ai.get("terraform_fix"):
            lines += ["```hcl", ai["terraform_fix"], "```", ""]
    return "\n".join(lines)


def to_html(report: dict) -> str:
    rows = "".join(
        f"<tr class='{f['severity'].lower()}'><td>{i}</td><td>{f['severity']}</td><td>{html.escape(f['check_id'])}</td>"
        f"<td>{html.escape(f['title'])}</td><td><code>{html.escape(f['resource'])}</code></td>"
        f"<td>{html.escape((f.get('ai') or {}).get('explanation', f['description']))}</td>"
        f"<td>{html.escape('; '.join((f.get('ai') or {}).get('remediation_steps') or [f['remediation']]))}</td></tr>"
        for i, f in enumerate(report["findings"], 1))
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Cloud Security Report</title>
<style>body{{font-family:system-ui,sans-serif;margin:2rem}}table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #ddd;padding:6px;vertical-align:top;font-size:14px}}.critical td:nth-child(2){{background:#b00;color:#fff}}
.high td:nth-child(2){{background:#e55;color:#fff}}.medium td:nth-child(2){{background:#fc3}}.low td:nth-child(2){{background:#9cf}}
.score{{font-size:2.5rem;font-weight:700}}</style></head><body>
<h1>Cloud Security Report</h1><div class="score">{report['score']}/100</div>
<p>Generated {report['generated_at']} &middot; mode {report['mode']} &middot; analysis {report['analysis']}</p>
<table><tr><th>#</th><th>Severity</th><th>Check</th><th>Title</th><th>Resource</th><th>Why</th><th>Fix</th></tr>{rows}</table>
</body></html>"""
