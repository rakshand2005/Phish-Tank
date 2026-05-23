"""
Container Security Scanner — CLI Entry Point.

Orchestrates the full scanning pipeline:
    integrity → SBOM → CVE matching → layer attribution

Usage:
    scanner scan nginx:1.14
    scanner scan nginx:1.14 --output json
    scanner scan nginx:1.14 --fail-on CRITICAL
    scanner integrity nginx:1.14
"""

from __future__ import annotations

import json
import logging
import sys

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from scanner import __version__
from scanner.models import ScanResult
from scanner.integrity import verify_image
from scanner.sbom import generate_sbom, get_packages
from scanner.matcher import check_db_freshness, update_db, scan_cves, parse_cve_matches
from scanner.layers import get_layer_metadata, attribute_cves_to_layers, generate_fix_suggestions

console = Console()
logger = logging.getLogger("scanner")


def _setup_logging(verbose: bool) -> None:
    """Configure logging based on verbosity."""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def _parse_image_name(image: str) -> tuple[str, str]:
    """Split image reference into name and tag."""
    if "@sha256:" in image:
        parts = image.split("@")
        return parts[0], "sha256:" + parts[1].split(":")[1][:12]
    if ":" in image and "/" not in image.split(":")[-1]:
        parts = image.rsplit(":", 1)
        return parts[0], parts[1]
    return image, "latest"


def _severity_color(severity: str) -> str:
    """Map severity to Rich color."""
    return {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "UNKNOWN": "dim",
    }.get(severity, "white")


def _print_banner() -> None:
    """Print the scanner banner."""
    banner = Text()
    banner.append("🛡️  Container Security Scanner", style="bold cyan")
    banner.append(f"  v{__version__}", style="dim")
    console.print(Panel(banner, border_style="cyan", box=box.ROUNDED))


def _print_integrity_results(result: ScanResult) -> None:
    """Print integrity check results."""
    integrity = result.integrity

    table = Table(
        title="🔐 Integrity Checks",
        box=box.SIMPLE_HEAVY,
        title_style="bold white",
    )
    table.add_column("Check", style="cyan", min_width=25)
    table.add_column("Status", justify="center", min_width=10)
    table.add_column("Details", style="dim")

    checks = [
        ("Cosign Signature", integrity.image_signed, integrity.signature_warning),
        ("SBOM Attestation (SLSA)", integrity.sbom_attested, integrity.attestation_warning),
        ("Digest Pinning", integrity.digest_pinned, integrity.digest_warning),
        ("Typosquat Check", not integrity.typosquat_risk, integrity.typosquat_warning),
    ]

    for name, passed, warning in checks:
        status = Text("✅ PASS", style="green") if passed else Text("⚠️  WARN", style="yellow")
        details = warning or "OK"
        # Truncate long details for table display
        if len(details) > 60:
            details = details[:57] + "..."
        table.add_row(name, status, details)

    console.print(table)
    console.print()


def _print_db_freshness(result: ScanResult) -> None:
    """Print DB freshness info."""
    db = result.db_freshness
    if db.is_stale:
        console.print(f"  [yellow]{db.warning}[/yellow]")
    else:
        console.print(
            f"  [green]✅ Vulnerability DB is fresh[/green] "
            f"[dim](age: {db.db_age_hours:.1f}h)[/dim]"
        )
    console.print()


def _print_summary(result: ScanResult) -> None:
    """Print scan summary with severity counts."""
    counts = result.severity_counts

    summary = Table(
        title=f"📊 Scan Summary: {result.image}:{result.tag}",
        box=box.ROUNDED,
        title_style="bold white",
    )
    summary.add_column("Metric", style="cyan")
    summary.add_column("Value", justify="right")

    summary.add_row("Total Packages", str(result.total_packages))
    summary.add_row("Total CVEs", str(len(result.cves)))
    summary.add_row("Fixable CVEs", str(result.fixable_count))
    summary.add_row(
        "Critical",
        Text(str(counts["CRITICAL"]), style="bold red" if counts["CRITICAL"] else "green"),
    )
    summary.add_row(
        "High",
        Text(str(counts["HIGH"]), style="red" if counts["HIGH"] else "green"),
    )
    summary.add_row("Medium", str(counts["MEDIUM"]))
    summary.add_row("Low", str(counts["LOW"]))

    console.print(summary)
    console.print()


def _print_cve_table(result: ScanResult, show_layers: bool = False) -> None:
    """Print the CVE findings as a Rich table."""
    if not result.cves:
        console.print("  [green]✅ No vulnerabilities found![/green]\n")
        return

    table = Table(
        title="🔍 Vulnerability Findings",
        box=box.SIMPLE_HEAVY,
        title_style="bold white",
        show_lines=True,
    )
    table.add_column("CVE ID", style="bold", min_width=18)
    table.add_column("Severity", justify="center", min_width=10)
    table.add_column("Package", min_width=15)
    table.add_column("Installed", min_width=10)
    table.add_column("Fixed", min_width=10)

    if show_layers:
        table.add_column("Layer", style="dim", min_width=25)

    for cve in result.cves:
        severity_text = Text(cve.severity, style=_severity_color(cve.severity))
        fixed = cve.fixed_version or Text("No fix", style="dim italic")

        row = [
            cve.cve_id,
            severity_text,
            cve.package,
            cve.installed_version,
            str(fixed),
        ]

        if show_layers:
            layer_text = cve.layer_command or "Unknown"
            if len(layer_text) > 40:
                layer_text = layer_text[:37] + "..."
            row.append(layer_text)

        table.add_row(*row)

    console.print(table)
    console.print()


def _print_fix_suggestions(result: ScanResult) -> None:
    """Print fix suggestions for fixable CVEs."""
    fixable = [c for c in result.cves if c.fix_suggestion]
    if not fixable:
        return

    console.print(
        Panel(
            "[bold]💡 Fix Suggestions[/bold]",
            border_style="green",
            box=box.ROUNDED,
        )
    )

    for cve in fixable[:10]:  # Show top 10 suggestions
        console.print(f"  [bold]{cve.cve_id}[/bold] ({cve.severity})")
        for line in cve.fix_suggestion.split("\n"):
            console.print(f"    {line}")
        console.print()


def _print_layer_breakdown(result: ScanResult) -> None:
    """Print a breakdown of CVEs by layer."""
    layers_with_cves = [l for l in result.layers if l.cve_count > 0]
    if not layers_with_cves:
        return

    table = Table(
        title="📦 Layer Breakdown",
        box=box.SIMPLE_HEAVY,
        title_style="bold white",
    )
    table.add_column("#", style="dim", justify="right")
    table.add_column("Layer Command", min_width=40)
    table.add_column("CVEs", justify="center", style="bold")

    for i, layer in enumerate(layers_with_cves, 1):
        cmd = layer.command if len(layer.command) <= 50 else layer.command[:47] + "..."
        cve_style = "red" if layer.cve_count >= 5 else "yellow" if layer.cve_count >= 1 else "green"
        table.add_row(
            str(i),
            cmd,
            Text(str(layer.cve_count), style=cve_style),
        )

    console.print(table)
    console.print()


# ─── CLI Commands ───────────────────────────────────────────────────────

@click.group()
@click.version_option(version=__version__, prog_name="scanner")
def cli():
    """🛡️  Container Security Scanner — SBOM Generation & CVE Matching"""
    pass


@cli.command()
@click.argument("image")
@click.option("--output", "-o", type=click.Choice(["terminal", "json"]), default="terminal",
              help="Output format.")
@click.option("--fail-on", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
              default=None, help="Exit with code 1 if CVEs of this severity or higher are found.")
@click.option("--layers/--no-layers", default=True,
              help="Include layer-by-layer CVE attribution.")
@click.option("--update-db/--no-update-db", default=False,
              help="Update Trivy DB before scanning.")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging.")
def scan(image: str, output: str, fail_on: str, layers: bool, update_db_flag: bool, verbose: bool):
    """
    Scan a Docker image for vulnerabilities.

    Runs the full pipeline: integrity check → SBOM generation → CVE matching → layer attribution.

    Examples:

        scanner scan nginx:1.14

        scanner scan nginx:1.14 --output json

        scanner scan nginx:1.14 --fail-on CRITICAL
    """
    _setup_logging(verbose)
    image_name, tag = _parse_image_name(image)

    if output == "terminal":
        _print_banner()
        console.print(f"  Scanning: [bold cyan]{image}[/bold cyan]\n")

    # ── Step 1: Integrity Checks ──
    if output == "terminal":
        with console.status("[bold cyan]Running integrity checks..."):
            integrity = verify_image(image)
    else:
        integrity = verify_image(image)

    if integrity.typosquat_risk:
        console.print(f"  [bold red]🚨 {integrity.typosquat_warning}[/bold red]")
        if not click.confirm("  Continue anyway?", default=False):
            raise SystemExit(1)

    # ── Step 2: DB Freshness Check ──
    if output == "terminal":
        with console.status("[bold cyan]Checking vulnerability database..."):
            db_freshness = check_db_freshness()
    else:
        db_freshness = check_db_freshness()

    if update_db_flag or db_freshness.is_stale:
        if output == "terminal":
            with console.status("[bold cyan]Updating vulnerability database..."):
                update_db()
                db_freshness = check_db_freshness()
        else:
            update_db()
            db_freshness = check_db_freshness()

    # ── Step 3: SBOM Generation ──
    if output == "terminal":
        with console.status("[bold cyan]Generating SBOM (this may take a minute)..."):
            sbom = generate_sbom(image)
            packages = get_packages(sbom)
    else:
        sbom = generate_sbom(image)
        packages = get_packages(sbom)

    # ── Step 4: CVE Matching ──
    if output == "terminal":
        with console.status("[bold cyan]Scanning for vulnerabilities..."):
            trivy_json = scan_cves(image)
            cves = parse_cve_matches(trivy_json)
    else:
        trivy_json = scan_cves(image)
        cves = parse_cve_matches(trivy_json)

    # ── Step 5: Layer Attribution ──
    layer_infos = []
    if layers:
        if output == "terminal":
            with console.status("[bold cyan]Analyzing image layers..."):
                try:
                    layer_infos = get_layer_metadata(image)
                    cves = attribute_cves_to_layers(cves, layer_infos)
                    cves = generate_fix_suggestions(cves, layer_infos)
                except RuntimeError as e:
                    logger.warning("Layer analysis skipped: %s", e)
                    if output == "terminal":
                        console.print(f"  [yellow]⚠️  Layer analysis skipped: {e}[/yellow]\n")
        else:
            try:
                layer_infos = get_layer_metadata(image)
                cves = attribute_cves_to_layers(cves, layer_infos)
                cves = generate_fix_suggestions(cves, layer_infos)
            except RuntimeError:
                pass

    # ── Build Result ──
    result = ScanResult(
        image=image_name,
        tag=tag,
        integrity=integrity,
        db_freshness=db_freshness,
        total_packages=len(packages),
        packages=packages,
        cves=cves,
        layers=layer_infos,
    )

    # ── Output ──
    if output == "json":
        click.echo(result.to_json())
    else:
        _print_integrity_results(result)
        _print_db_freshness(result)
        _print_summary(result)
        _print_cve_table(result, show_layers=layers)
        _print_layer_breakdown(result)
        _print_fix_suggestions(result)

        # Final verdict
        if result.has_critical:
            console.print(
                Panel(
                    "[bold red]🚨 CRITICAL vulnerabilities found! Pipeline should be BLOCKED.[/bold red]",
                    border_style="red",
                    box=box.HEAVY,
                )
            )
        else:
            console.print(
                Panel(
                    "[bold green]✅ No critical vulnerabilities. Pipeline can proceed.[/bold green]",
                    border_style="green",
                    box=box.HEAVY,
                )
            )

    # ── CI Gate ──
    if fail_on:
        severity_levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        threshold_idx = severity_levels.index(fail_on)
        blocking_severities = set(severity_levels[: threshold_idx + 1])

        blocking_cves = [c for c in cves if c.severity in blocking_severities]
        if blocking_cves:
            if output == "terminal":
                console.print(
                    f"\n  [bold red]CI GATE: Exiting with code 1 — "
                    f"{len(blocking_cves)} CVE(s) at {fail_on} or above.[/bold red]\n"
                )
            sys.exit(1)

    sys.exit(0)


@cli.command()
@click.argument("image")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging.")
def integrity(image: str, verbose: bool):
    """
    Run integrity checks only (no vulnerability scan).

    Checks: Cosign signature, SBOM attestation, digest pinning, typosquat.

    Example:

        scanner integrity nginx:1.14
    """
    _setup_logging(verbose)
    _print_banner()

    console.print(f"  Checking integrity: [bold cyan]{image}[/bold cyan]\n")

    with console.status("[bold cyan]Running integrity checks..."):
        result = verify_image(image)

    # Print results using a temporary ScanResult
    temp_result = ScanResult(
        image=image.split(":")[0],
        tag=image.split(":")[-1] if ":" in image else "latest",
        integrity=result,
        db_freshness=__import__("scanner.models", fromlist=["DBFreshnessResult"]).DBFreshnessResult(),
    )
    _print_integrity_results(temp_result)

    if result.passed:
        console.print("  [bold green]✅ All integrity checks passed.[/bold green]\n")
    else:
        console.print("  [bold red]🚨 Integrity issues detected.[/bold red]\n")
        sys.exit(1)


def main():
    """Entry point for the CLI."""
    cli()


if __name__ == "__main__":
    main()
