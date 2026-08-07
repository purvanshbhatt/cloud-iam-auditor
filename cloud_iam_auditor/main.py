"""`iam-audit` CLI entrypoint.

Exposed as a console_script by pyproject.toml under the key `iam-audit`.

v0.3.0 adds:
- `--format {table,json,sarif}` replaces bare `--json`; `--json` kept as alias
- `--out PATH` writes the rendered report to disk (especially useful for SARIF)
- New live-mode subcommands: aws-account, aws-policy, aws-role, gcp-project,
  azure-subscription. Each pulls an IAM document from the live API and feeds
  it through the same rule engine as `scan`.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Iterable

import typer
from rich.console import Console
from rich.markup import escape as rich_escape

from . import __version__
from .base import Finding, Severity
from .cloud_clients.errors import CloudClientError
from .loader import LoaderError, Provider, load_policy
from .reporter import Reporter
from .reporter_sarif import render_sarif
from .rules.registry import all_aws_rules, all_azure_rules, all_gcp_rules


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
        "Audit AWS, GCP, and Azure IAM policies for zero-trust violations and map findings "
        "to NIST 800-53, NIST 800-207, CIS Foundations, and MITRE ATT&CK. Provider is "
        "auto-detected from the JSON shape. Live-mode subcommands (aws-account, "
        "aws-policy, aws-role, gcp-project, azure-subscription) require the `live` or "
        "`azure` extras; run `pip install cloud-iam-auditor-pb[live]` or `[azure]`."
    ),
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
# Status / progress messages routed to stderr so stdout stays pure for JSON pipes.
status = Console(stderr=True)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"iam-audit {__version__}")
        raise typer.Exit()


def _resolve_threshold(severity: str | None) -> Severity | None:
    if not severity:
        return None
    try:
        return Severity.from_str(severity)
    except ValueError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=2) from None


def _rules_for_provider(provider: Provider):
    if provider == Provider.AWS:
        return all_aws_rules().values()
    if provider == Provider.GCP:
        return all_gcp_rules().values()
    if provider == Provider.AZURE:
        return all_azure_rules().values()
    console.print(f"[bold red]Error:[/bold red] no rule set for provider {provider!r}")
    raise typer.Exit(code=2) from None


def _audit_policy(policy, threshold: Severity | None) -> list[Finding]:
    rule_classes = _rules_for_provider(policy.provider)
    status.print(
        f"[bold blue]Detected {policy.provider.value.upper()} IAM policy[/bold blue] "
        f"({len(rule_classes)} rules available, {len(policy.statements)} entries)"
    )
    findings: list[Finding] = []
    for rule_cls in rule_classes:
        findings.extend(rule_cls().evaluate(policy.statements))
    if threshold is not None:
        findings = [f for f in findings if f.severity >= threshold]
    return findings


def _render(
    findings: list[Finding],
    source: str,
    fmt: str,
    out: str | None,
    color: bool,
    json_legacy: bool,
) -> None:
    """Render the report in the requested format."""
    if json_legacy:
        fmt = "json"
    if fmt == "sarif":
        sarif_text = render_sarif(findings, source, tool_version=__version__)
        if out:
            Path(out).parent.mkdir(parents=True, exist_ok=True)
            Path(out).write_text(sarif_text, encoding="utf-8")
            status.print(f"[bold green]Wrote SARIF to {out}[/bold green]")
        else:
            sys.stdout.write(sarif_text)
            sys.stdout.write("\n")
        return

    reporter = Reporter(color=color)
    if fmt == "json":
        reporter.print_json(findings, source)
    else:  # table
        reporter.render_table(findings, source)


def _emit_exit_code(exit_code: bool, findings: list[Finding]) -> None:
    if exit_code and findings:
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Top-level flags
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# iam-audit scan PATH   -- offline JSON file audit
# ---------------------------------------------------------------------------


@app.command()
def scan(
    file_path: str = typer.Argument(
        ..., help="Path to an AWS/GCP/Azure IAM policy JSON file (provider is auto-detected)."
    ),
    json_out: bool = typer.Option(
        False, "--json", help="Shorthand for --format json (kept for v0.1/0.2 compatibility)."
    ),
    fmt: str = typer.Option(
        "table",
        "--format",
        help="Output format: table | json | sarif. `--json` overrides this for compat.",
    ),
    out: str | None = typer.Option(
        None, "--out", help="Write the report to the given path (required-readable for sarif)."
    ),
    severity: str | None = typer.Option(
        None,
        "--severity",
        help="Only report findings at or above this severity (low/medium/high/critical).",
    ),
    exit_code: bool = typer.Option(
        False,
        "--exit-code",
        help="Return a non-zero process exit code when any finding is reported (CI gate).",
    ),
    no_color: bool = typer.Option(False, "--no-color", help="Disable ANSI colors / styling."),
) -> None:
    """Scan an IAM policy file and print a mapped findings report."""
    threshold = _resolve_threshold(severity)
    try:
        policy = load_policy(file_path)
    except LoaderError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=2) from None

    findings = _audit_policy(policy, threshold)
    _render(
        findings,
        str(policy.source),
        fmt=fmt,
        out=out,
        color=not no_color,
        json_legacy=json_out,
    )
    _emit_exit_code(exit_code, findings)


# ---------------------------------------------------------------------------
# Live-mode subcommands
# ---------------------------------------------------------------------------


def _run_live(
    fetch_label: str,
    policies_iter: Iterable,
    threshold: Severity | None,
    fmt: str,
    out: str | None,
    color: bool,
    json_legacy: bool,
    exit_code: bool,
) -> None:
    """Drive multiple LoadedPolicy objects (one per cloud artifact) through the
    audited engine and merge findings into one report.
    """
    all_findings: list[Finding] = []
    last_source = fetch_label
    count = 0
    for policy in policies_iter:
        try:
            findings = _audit_policy(policy, threshold)
        except LoaderError as exc:
            console.print(f"[bold yellow]Skipped malformed policy from {exc}[/bold yellow]")
            continue
        all_findings.extend(findings)
        last_source = str(policy.source)
        count += 1
    status.print(f"[bold green]Audited {count} IAM artifacts[/bold green]")
    _render(
        all_findings,
        f"{fetch_label} ({count} artifacts, last={last_source})",
        fmt=fmt,
        out=out,
        color=color,
        json_legacy=json_legacy,
    )
    _emit_exit_code(exit_code, all_findings)


def _handle_live_error(exc: Exception) -> None:
    """Convert any CloudClientError subclass into a friendly CLI exit."""
    if isinstance(exc, CloudClientError):
        # Escape Rich markup in the exception string so characters like `[` and `]`
        # in install hints (`pip install cloud-iam-auditor-pb[live]`) render as
        # literal text instead of being parsed as Rich style tags.
        console.print(f"[bold red]Live-mode error:[/bold red] {rich_escape(str(exc))}")
        raise typer.Exit(code=2) from exc
    console.print(f"[bold red]Unexpected error:[/bold red] {rich_escape(str(exc))}")
    raise typer.Exit(code=3) from exc


@app.command("aws-account")
def aws_account(
    scope: str = typer.Option(
        "Local",
        "--scope",
        help="IAM policy scope: ALL | AWS (managed) | LOCAL (customer-managed, default).",
    ),
    fmt: str = typer.Option("table", "--format", help="table | json | sarif"),
    json_out: bool = typer.Option(False, "--json", help="Shorthand for --format json."),
    out: str | None = typer.Option(None, "--out", help="Write the report to the given path."),
    severity: str | None = typer.Option(None, "--severity", help="Threshold severity filter."),
    exit_code: bool = typer.Option(False, "--exit-code", help="Exit non-zero on findings."),
    no_color: bool = typer.Option(False, "--no-color", help="Disable ANSI colors."),
    region: str | None = typer.Option(None, "--region", help="AWS region override."),
    profile: str | None = typer.Option(None, "--profile", help="AWS profile override."),
) -> None:
    """Live mode: enumerate managed IAM policies in the caller's AWS account."""
    from .cloud_clients.aws import fetch_managed_policies

    threshold = _resolve_threshold(severity)
    try:
        policies = list(fetch_managed_policies(scope=scope, region=region, profile=profile))
    except Exception as exc:
        _handle_live_error(exc)
        return
    if not policies:
        status.print("[bold yellow]No managed policies found for the given scope.[/bold yellow]")
    _run_live(
        f"aws-account({scope})",
        policies,
        threshold,
        fmt=fmt,
        out=out,
        color=not no_color,
        json_legacy=json_out,
        exit_code=exit_code,
    )


@app.command("aws-policy")
def aws_policy(
    policy_arn: str = typer.Argument(..., help="ARN of the managed IAM policy to audit."),
    fmt: str = typer.Option("table", "--format", help="table | json | sarif"),
    json_out: bool = typer.Option(False, "--json", help="Shorthand for --format json."),
    out: str | None = typer.Option(None, "--out", help="Write the report to the given path."),
    severity: str | None = typer.Option(None, "--severity", help="Threshold severity filter."),
    exit_code: bool = typer.Option(False, "--exit-code", help="Exit non-zero on findings."),
    no_color: bool = typer.Option(False, "--no-color", help="Disable ANSI colors."),
    region: str | None = typer.Option(None, "--region", help="AWS region override."),
    profile: str | None = typer.Option(None, "--profile", help="AWS profile override."),
) -> None:
    """Live mode: audit a single AWS managed IAM policy by ARN."""
    from .cloud_clients.aws import fetch_policy_by_arn

    threshold = _resolve_threshold(severity)
    try:
        policy = fetch_policy_by_arn(policy_arn, region=region, profile=profile)
    except Exception as exc:
        _handle_live_error(exc)
        return
    findings = _audit_policy(policy, threshold)
    _render(
        findings,
        str(policy.source),
        fmt=fmt,
        out=out,
        color=not no_color,
        json_legacy=json_out,
    )
    _emit_exit_code(exit_code, findings)


@app.command("aws-role")
def aws_role(
    role_name: str = typer.Argument(..., help="Name of the IAM role to audit inline policies of."),
    fmt: str = typer.Option("table", "--format", help="table | json | sarif"),
    json_out: bool = typer.Option(False, "--json", help="Shorthand for --format json."),
    out: str | None = typer.Option(None, "--out", help="Write the report to the given path."),
    severity: str | None = typer.Option(None, "--severity", help="Threshold severity filter."),
    exit_code: bool = typer.Option(False, "--exit-code", help="Exit non-zero on findings."),
    no_color: bool = typer.Option(False, "--no-color", help="Disable ANSI colors."),
    region: str | None = typer.Option(None, "--region", help="AWS region override."),
    profile: str | None = typer.Option(None, "--profile", help="AWS profile override."),
) -> None:
    """Live mode: audit inline policies attached to an IAM role."""
    from .cloud_clients.aws import fetch_role_inline_policies

    threshold = _resolve_threshold(severity)
    try:
        policies = list(fetch_role_inline_policies(role_name, region=region, profile=profile))
    except Exception as exc:
        _handle_live_error(exc)
        return
    if not policies:
        status.print(f"[bold yellow]No inline policies found on role {role_name!r}.[/bold yellow]")
    _run_live(
        f"aws-role:{role_name}",
        policies,
        threshold,
        fmt=fmt,
        out=out,
        color=not no_color,
        json_legacy=json_out,
        exit_code=exit_code,
    )


@app.command("gcp-project")
def gcp_project(
    project_id: str = typer.Argument(..., help="GCP project ID to read IAM bindings for."),
    fmt: str = typer.Option("table", "--format", help="table | json | sarif"),
    json_out: bool = typer.Option(False, "--json", help="Shorthand for --format json."),
    out: str | None = typer.Option(None, "--out", help="Write the report to the given path."),
    severity: str | None = typer.Option(None, "--severity", help="Threshold severity filter."),
    exit_code: bool = typer.Option(False, "--exit-code", help="Exit non-zero on findings."),
    no_color: bool = typer.Option(False, "--no-color", help="Disable ANSI colors."),
) -> None:
    """Live mode: audit GCP project IAM bindings via google-cloud-resourcemanager."""
    from .cloud_clients.gcp import fetch_project_bindings

    threshold = _resolve_threshold(severity)
    try:
        policy = fetch_project_bindings(project_id)
    except Exception as exc:
        _handle_live_error(exc)
        return
    findings = _audit_policy(policy, threshold)
    _render(
        findings,
        str(policy.source),
        fmt=fmt,
        out=out,
        color=not no_color,
        json_legacy=json_out,
    )
    _emit_exit_code(exit_code, findings)


@app.command("azure-subscription")
def azure_subscription(
    fmt: str = typer.Option("table", "--format", help="table | json | sarif"),
    json_out: bool = typer.Option(False, "--json", help="Shorthand for --format json."),
    out: str | None = typer.Option(None, "--out", help="Write the report to the given path."),
    severity: str | None = typer.Option(None, "--severity", help="Threshold severity filter."),
    exit_code: bool = typer.Option(False, "--exit-code", help="Exit non-zero on findings."),
    no_color: bool = typer.Option(False, "--no-color", help="Disable ANSI colors."),
) -> None:
    """Live mode: audit Azure RBAC role assignments in the configured subscription.

    Requires `AZURE_SUBSCRIPTION_ID` env var + Microsoft Entra ID credentials
    (az login or service principal env vars). Install the azure extra:
    `pip install cloud-iam-auditor-pb[azure]`.
    """
    from .cloud_clients.azure import fetch_subscription_assignments

    threshold = _resolve_threshold(severity)
    try:
        policy = fetch_subscription_assignments()
    except Exception as exc:
        _handle_live_error(exc)
        return
    findings = _audit_policy(policy, threshold)
    _render(
        findings,
        str(policy.source),
        fmt=fmt,
        out=out,
        color=not no_color,
        json_legacy=json_out,
    )
    _emit_exit_code(exit_code, findings)


# ---------------------------------------------------------------------------
# iam-audit rules   -- list all registered rules (4 clouds)
# ---------------------------------------------------------------------------


@app.command("rules")
def list_rules(
    json_out: bool = typer.Option(
        False, "--json", help="Emit rules as JSON instead of a table."
    ),
) -> None:
    """List all currently registered detection rules (AWS + GCP + Azure)."""
    aws = all_aws_rules()
    gcp = all_gcp_rules()
    azure = all_azure_rules()
    all_combined = {**aws, **gcp, **azure}
    if json_out:
        payload = [
            {
                "rule_id": rid,
                "provider": "aws" if rid in aws else ("gcp" if rid in gcp else "azure"),
                "severity": all_combined[rid].severity.value,
                "title": all_combined[rid].title,
                "description": all_combined[rid].description,
            }
            for rid in sorted(all_combined)
        ]
        sys.stdout.write(json.dumps(payload, indent=2))
        sys.stdout.write("\n")
        return

    table_render = Reporter(color=True)
    from rich.table import Table

    table = Table(title="Registered IAM Audit Rules", show_lines=True, border_style="cyan")
    table.add_column("ID", style="bold cyan", width=8)
    table.add_column("Cloud", width=6)
    table.add_column("Severity", width=10)
    table.add_column("Title", width=42)
    table.add_column("Description", width=66)
    for rid in sorted(all_combined):
        r = all_combined[rid]
        cloud = "aws" if rid in aws else ("gcp" if rid in gcp else "azure")
        table.add_row(rid, cloud, r.severity.value.upper(), r.title, r.description)
    sys.stdout.write(
        "Rule IDs: " + ", ".join(sorted(all_combined)) + "\n"
    )
    table_render.console.print(table)


if __name__ == "__main__":
    app()
