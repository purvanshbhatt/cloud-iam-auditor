"""`iam-audit` CLI entrypoint.

Exposed as a console_script by pyproject.toml under the key `iam-audit`.
"""

from __future__ import annotations

import json
import sys

import typer
from rich.console import Console

from . import __version__
from .base import Severity
from .loader import LoaderError, load_policy
from .reporter import Reporter
from .rules.registry import all_rules


def _force_utf8_streams() -> None:
    """Reconfigure stdout/stderr to UTF-8 so Rich box-drawing never crashes on cp1252."""
    for _stream_name in ("stdout", "stderr"):
        _stream = getattr(sys, _stream_name, None)
        if _stream is not None and hasattr(_stream, "reconfigure"):
            try:
                _stream.reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):  # pragma: no cover
                pass


_force_utf8_streams()


app = typer.Typer(
    name="iam-audit",
    help=(
        "Audit AWS IAM JSON policies for zero-trust violations and map findings to "
        "NIST 800-53, NIST 800-207, CIS AWS Foundations, and MITRE ATT&CK."
    ),
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"iam-audit {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: bool | None = typer.Option(
        None,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Print the installed iam-audit version and exit.",
    ),
) -> None:
    """Top-level callback hosting the --version flag."""
    # No-op: real work happens in subcommands.


@app.command()
def scan(
    file_path: str = typer.Argument(..., help="Path to an AWS IAM policy JSON file."),
    json_out: bool = typer.Option(
        False, "--json", help="Emit a machine-readable JSON report instead of a Rich table."
    ),
    severity: str | None = typer.Option(
        None,
        "--severity",
        help=(
            "Only report findings at or above this severity: low, medium, high, critical. "
            "Lower severities are dropped from output AND exit-code accounting."
        ),
    ),
    exit_code: bool = typer.Option(
        False,
        "--exit-code",
        help="Return a non-zero process exit code when any finding is reported (CI gate).",
    ),
    no_color: bool = typer.Option(False, "--no-color", help="Disable ANSI colors / styling."),
) -> None:
    """Scan an IAM policy file and print a mapped findings report."""
    threshold: Severity | None = None
    if severity:
        try:
            threshold = Severity.from_str(severity)
        except ValueError as exc:
            console.print(f"[bold red]Error:[/bold red] {exc}")
            raise typer.Exit(code=2) from None

    try:
        policy = load_policy(file_path)
    except LoaderError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=2) from None

    reporter = Reporter(color=not no_color)
    findings: list = []
    for rule_cls in all_rules().values():
        found = rule_cls().evaluate(policy.statements)
        findings.extend(found)

    if threshold is not None:
        findings = [f for f in findings if f.severity >= threshold]

    if json_out:
        reporter.print_json(findings, str(policy.source))
    else:
        reporter.render_table(findings, str(policy.source))

    if exit_code and findings:
        raise typer.Exit(code=1)


@app.command("rules")
def list_rules(
    json_out: bool = typer.Option(
        False, "--json", help="Emit rules as JSON instead of a table."
    ),
) -> None:
    """List all currently registered detection rules."""
    rules = all_rules()
    if json_out:
        payload = [
            {
                "rule_id": rid,
                "severity": rules[rid].severity.value,
                "title": rules[rid].title,
                "description": rules[rid].description,
            }
            for rid in sorted(rules)
        ]
        sys.stdout.write(json.dumps(payload, indent=2))
        sys.stdout.write("\n")
        return

    table_render = Reporter(color=True)
    from rich.table import Table

    table = Table(title="Registered IAM Audit Rules", show_lines=True, border_style="cyan")
    table.add_column("ID", style="bold cyan", width=8)
    table.add_column("Severity", width=10)
    table.add_column("Title", width=46)
    table.add_column("Description", width=70)
    for rid in sorted(rules):
        r = rules[rid]
        table.add_row(rid, r.severity.value.upper(), r.title, r.description)
    # Also print a plain-text index line so test/ci parsers can match each rule_id
    # even when ANSI/padding splits the cell content.
    sys.stdout.write("Rule IDs: " + ", ".join(sorted(rules)) + "\n")
    table_render.console.print(table)


if __name__ == "__main__":
    app()
