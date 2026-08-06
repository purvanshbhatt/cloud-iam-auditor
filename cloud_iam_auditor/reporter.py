"""Report renderers: Rich terminal table + machine-readable JSON."""

from __future__ import annotations

import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .base import Finding, Severity

SEVERITY_STYLE = {
    Severity.LOW: ("bold white", "LOW"),
    Severity.MEDIUM: ("bold yellow", "MEDIUM"),
    Severity.HIGH: ("bold red", "HIGH"),
    Severity.CRITICAL: ("bold bright_red on black", "CRITICAL"),
}


class Reporter:
    """Renders findings either as a Rich table or JSON object."""

    def __init__(self, console: Console | None = None, color: bool = True) -> None:
        # Use safe_box=True so Rich never emits Unicode box-drawing chars that
        # can crash on Windows cp1252/cp437 consoles when output is redirected.
        self.console = console or Console(
            no_color=not color,
            force_terminal=color or None,
            safe_box=True,
            soft_wrap=False,
        )

    def render_table(self, findings: list[Finding], source: str) -> None:
        if not findings:
            self.console.print(
                Panel(
                    Text.from_markup(
                        "[bold green][OK][/bold green] "
                        "No findings: policy passes all registered rules."
                    ),
                    title=f"Audit: {source}",
                    border_style="green",
                )
            )
            return

        table = Table(
            title=f"IAM Audit Report - {source}",
            show_lines=True,
            border_style="bright_blue",
            title_style="bold",
        )
        table.add_column("#", style="dim", width=4)
        table.add_column("Cloud", width=6)
        table.add_column("Rule", style="bold cyan", width=9)
        table.add_column("Severity", width=12)
        table.add_column("Title", width=38)
        table.add_column("Stmt", width=4, justify="right")
        table.add_column("Framework refs", width=42)
        table.add_column("Remediation", width=56)

        for i, f in enumerate(sorted(findings, key=lambda x: -x.severity.weight), start=1):
            sev_style, sev_label = SEVERITY_STYLE[f.severity]
            refs = "\n".join(f.framework_refs) if f.framework_refs else "-"
            cloud = f.provider.value.upper() if f.provider else "?"
            table.add_row(
                str(i),
                cloud,
                f.rule_id,
                Text(sev_label, style=sev_style),
                f.title,
                str(f.statement_index),
                refs,
                f.remediation,
            )
        self.console.print(table)

        critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in findings if f.severity == Severity.HIGH)
        medium = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f in findings if f.severity == Severity.LOW)
        aws_count = sum(1 for f in findings if f.provider and f.provider.value == "aws")
        gcp_count = sum(1 for f in findings if f.provider and f.provider.value == "gcp")
        summary = (
            f"[bold]Summary[/bold] - [bold bright_red]{critical} critical[/bold bright_red], "
            f"[bold red]{high} high[/bold red], "
            f"[bold yellow]{medium} medium[/bold yellow], "
            f"[bold white]{low} low[/bold white]"
            f"  |  AWS: {aws_count}, GCP: {gcp_count}"
        )
        self.console.print(Panel(Text.from_markup(summary), border_style="bright_blue"))

    def render_json(self, findings: list[Finding], source: str) -> str:
        by_provider: dict[str, int] = {}
        for f in findings:
            key = f.provider.value if f.provider else "unknown"
            by_provider[key] = by_provider.get(key, 0) + 1
        payload = {
            "summary": {
                "source": source,
                "total": len(findings),
                "by_provider": by_provider,
                "critical": sum(1 for f in findings if f.severity == Severity.CRITICAL),
                "high": sum(1 for f in findings if f.severity == Severity.HIGH),
                "medium": sum(1 for f in findings if f.severity == Severity.MEDIUM),
                "low": sum(1 for f in findings if f.severity == Severity.LOW),
            },
            "findings": [f.to_dict() for f in findings],
        }
        return json.dumps(payload, indent=2, sort_keys=True)

    def print_json(self, findings: list[Finding], source: str) -> None:
        # Print raw JSON via sys.stdout (NOT Console.print) so ANSI styling
        # never leaks into machine-readable output for CI pipelines.
        import sys
        sys.stdout.write(self.render_json(findings, source))
        sys.stdout.write("\n")
