"""
Container Security Scanner — CLI Entry Point.

Orchestrates the full scanning pipeline:
    integrity → SBOM → CVE matching → scoring → layer attribution

Usage:
    scanner scan nginx:1.14
    scanner scan nginx:1.14 --output json
    scanner scan nginx:1.14 --fail-on CRITICAL
    scanner integrity nginx:1.14
    scanner fix nginx:1.14
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.columns import Columns
from rich.layout import Layout
from rich.rule import Rule
from rich import box

from scanner import __version__
from scanner.models import ScanResult
from scanner.integrity import verify_image
from scanner.sbom import generate_sbom, get_packages
from scanner.matcher import check_db_freshness, update_db as _update_trivy_db, scan_cves, parse_cve_matches
from scanner.layers import get_layer_metadata, attribute_cves_to_layers, generate_fix_suggestions
from scanner.scoring import enrich_and_score, gate_decision
from scanner.remediate import (
    reconstruct_dockerfile,
    build_remediation_plan,
    generate_patched_dockerfile,
    print_remediation_report,
    save_patched_dockerfile,
)

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


def _severity_block(severity: str) -> str:
    """Return a colored block character for severity bar charts."""
    colors = {
        "CRITICAL": "red",
        "HIGH": "#ff6b6b",
        "MEDIUM": "#ffd43b",
        "LOW": "#74c0fc",
    }
    return colors.get(severity, "white")


def _print_banner() -> None:
    """Print the scanner banner with ASCII art."""
    art = Text()
    art.append("\n")
    art.append("   ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ \n", style="bold cyan")
    art.append("   ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗\n", style="bold cyan")
    art.append("   ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝\n", style="cyan")
    art.append("   ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗\n", style="cyan")
    art.append("   ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║\n", style="bold blue")
    art.append("   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝\n", style="bold blue")
    art.append("\n")
    art.append("   🛡️  Container Security Scanner", style="bold white")
    art.append(f"  v{__version__}\n", style="dim")
    art.append("   SBOM Generation · CVE Matching · Auto-Remediation\n", style="dim italic")
    console.print(Panel(art, border_style="cyan", box=box.DOUBLE))


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
    """Print scan summary with severity counts and visual bar chart."""
    counts = result.severity_counts
    total_cves = len(result.cves)

    # ── Stats Table ──
    summary = Table(
        title=f"📊 Scan Summary: {result.image}:{result.tag}",
        box=box.ROUNDED,
        title_style="bold white",
        border_style="cyan",
    )
    summary.add_column("Metric", style="cyan", min_width=20)
    summary.add_column("Value", justify="right", min_width=10)

    summary.add_row("Total Packages", str(result.total_packages))
    summary.add_row("Total CVEs", Text(str(total_cves), style="bold" if total_cves else "green"))
    summary.add_row("Fixable CVEs", Text(str(result.fixable_count), style="green"))
    summary.add_row(
        "Critical",
        Text(str(counts["CRITICAL"]), style="bold red" if counts["CRITICAL"] else "green"),
    )
    summary.add_row(
        "High",
        Text(str(counts["HIGH"]), style="red" if counts["HIGH"] else "green"),
    )
    summary.add_row("Medium", Text(str(counts["MEDIUM"]), style="yellow" if counts["MEDIUM"] else "green"))
    summary.add_row("Low", Text(str(counts["LOW"]), style="blue" if counts["LOW"] else "green"))

    console.print(summary)
    console.print()

    # ── Severity Bar Chart ──
    if total_cves > 0:
        _print_severity_bar_chart(counts, total_cves)


def _print_severity_bar_chart(counts: dict[str, int], total: int) -> None:
    """Print a horizontal bar chart of CVE severity distribution."""
    max_bar_width = 40
    max_count = max(counts.values()) if any(counts.values()) else 1

    chart = Table(
        title="📈 Severity Distribution",
        box=box.SIMPLE,
        title_style="bold white",
        show_header=False,
        padding=(0, 1),
    )
    chart.add_column("Severity", style="bold", min_width=10, justify="right")
    chart.add_column("Bar", min_width=45)
    chart.add_column("Count", justify="right", min_width=8)
    chart.add_column("%", justify="right", min_width=6)

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = counts.get(sev, 0)
        if count == 0 and sev in ("LOW",):
            continue  # skip zero-count LOW to reduce clutter
        bar_len = int((count / max_count) * max_bar_width) if max_count else 0
        bar_len = max(bar_len, 1) if count > 0 else 0
        color = _severity_block(sev)

        bar = Text()
        bar.append("█" * bar_len, style=color)
        bar.append("░" * (max_bar_width - bar_len), style="dim")

        pct = f"{(count / total * 100):.0f}%" if total else "0%"

        sev_text = Text(sev, style=_severity_color(sev))
        chart.add_row(sev_text, bar, str(count), pct)

    console.print(chart)
    console.print()


def _print_risk_gauge(cves: list) -> None:
    """
    Print a visual risk score gauge for the overall scan.

    Shows the highest priority score as a visual meter.
    """
    if not cves:
        return

    # Get the highest priority score
    max_score = max(
        (getattr(c, "priority_score", 0.0) for c in cves),
        default=0.0,
    )

    # Build the gauge
    gauge_width = 50
    filled = int((max_score / 10.0) * gauge_width)
    filled = min(filled, gauge_width)

    # Color based on score
    if max_score >= 8.0:
        gauge_color = "bold red"
        label = "CRITICAL RISK"
    elif max_score >= 6.0:
        gauge_color = "red"
        label = "HIGH RISK"
    elif max_score >= 3.5:
        gauge_color = "yellow"
        label = "MEDIUM RISK"
    else:
        gauge_color = "green"
        label = "LOW RISK"

    gauge = Text()
    gauge.append("  Risk Score: ", style="bold")
    gauge.append(f"{max_score:.1f}", style=gauge_color)
    gauge.append("/10  ", style="dim")
    gauge.append("[", style="dim")
    gauge.append("█" * filled, style=gauge_color)
    gauge.append("░" * (gauge_width - filled), style="dim")
    gauge.append("]  ", style="dim")
    gauge.append(label, style=gauge_color)

    console.print(Panel(gauge, border_style="dim", box=box.ROUNDED))
    console.print()


def _print_score_breakdown(cves: list) -> None:
    """Print top scored CVEs with their score breakdown."""
    scored = [c for c in cves if hasattr(c, "score_breakdown")]
    if not scored:
        return

    # Show top 5
    top = scored[:5]

    table = Table(
        title="🎯 Top Risk CVEs (Priority Score Breakdown)",
        box=box.SIMPLE_HEAVY,
        title_style="bold white",
        show_lines=True,
    )
    table.add_column("CVE ID", style="bold", min_width=18)
    table.add_column("Score", justify="center", min_width=8)
    table.add_column("Breakdown", min_width=50)

    for cve in top:
        score = cve.priority_score
        if score >= 8.0:
            score_style = "bold red"
        elif score >= 6.0:
            score_style = "red"
        elif score >= 3.5:
            score_style = "yellow"
        else:
            score_style = "green"

        table.add_row(
            cve.cve_id,
            Text(f"{score:.2f}", style=score_style),
            cve.score_breakdown(),
        )

    console.print(table)
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
    table.add_column("Priority", justify="center", min_width=10)  # ✅ new scoring column
    table.add_column("KEV", justify="center", min_width=6)        # ✅ new KEV flag column

    if show_layers:
        table.add_column("Layer", style="dim", min_width=25)

    for cve in result.cves:
        severity_text = Text(cve.severity, style=_severity_color(cve.severity))
        fixed = cve.fixed_version or Text("No fix", style="dim italic")

        # ScoredCVE has priority_score and in_kev; CVEMatch falls back safely
        priority = f"{cve.priority_score:.2f}" if hasattr(cve, "priority_score") else "—"
        kev_flag = Text("YES", style="bold red") if getattr(cve, "in_kev", False) else Text("—", style="dim")

        row = [
            cve.cve_id,
            severity_text,
            cve.package,
            cve.installed_version,
            str(fixed),
            priority,
            kev_flag,
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

    for cve in fixable[:10]:
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


# ─── CLI Commands ────────────────────────────────────────────────────────────

@click.group()
@click.version_option(version=__version__, prog_name="phishnet")
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
def scan(image: str, output: str, fail_on: str, layers: bool, update_db: bool, verbose: bool):
    """
    Scan a Docker image for vulnerabilities.

    Runs the full pipeline: integrity → SBOM → CVE matching → scoring → layer attribution.

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

    if update_db or db_freshness.is_stale:
        if output == "terminal":
            with console.status("[bold cyan]Updating vulnerability database..."):
                _update_trivy_db()
                db_freshness = check_db_freshness()
        else:
            _update_trivy_db()
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

    # ── Step 4.5: Risk Scoring (CVSS + EPSS + CISA KEV) ──
    # ✅ BUG 3 + 4 FIXED: enrich_and_score is called HERE, inside scan(),
    #    after cves exists, and gate_decision is also inside scan() so
    #    it fires AFTER layer attribution — not at module level.
    if output == "terminal":
        with console.status("[bold cyan]Enriching CVEs with EPSS and CISA KEV scores..."):
            cves = enrich_and_score(cves)
    else:
        cves = enrich_and_score(cves)

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
        _print_risk_gauge(cves)
        _print_score_breakdown(cves)
        _print_cve_table(result, show_layers=layers)
        _print_layer_breakdown(result)
        _print_fix_suggestions(result)

        # ── Scan timestamp ──
        console.print(Rule(style="dim"))
        console.print(
            f"  [dim]Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]"
        )
        console.print()

        if result.has_critical:
            console.print(
                Panel(
                    "[bold red]🚨 CRITICAL vulnerabilities found! Pipeline should be BLOCKED.\n"
                    "    Run [bold white]scanner fix {image}[/bold white] to auto-generate a patched Dockerfile.[/bold red]",
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

    # ── CI Gate: priority-score based (replaces old severity-only gate) ──
    exit_code, reason = gate_decision(cves)
    if exit_code:
        if output == "terminal":
            console.print(
                f"\n  [bold red]CI GATE BLOCKED: {reason}[/bold red]\n"
            )
        sys.exit(1)

    # ── Legacy --fail-on gate (kept for backwards compatibility) ──
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


@cli.command(name="fix")
@click.argument("image")
@click.option("--output-dir", "-d", default=".",
              help="Directory to write the patched Dockerfile.")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging.")
def fix_command(image: str, output_dir: str, verbose: bool):
    """
    Auto-remediate a vulnerable Docker image.

    Runs a full vulnerability scan, then generates a patched Dockerfile
    that fixes all remediable CVEs. The patched Dockerfile is displayed
    in the terminal and saved to disk.

    Examples:

        scanner fix nginx:1.14

        scanner fix nginx:1.14 --output-dir ./patched
    """
    _setup_logging(verbose)
    _print_banner()

    console.print(f"  🔧 Auto-remediating: [bold cyan]{image}[/bold cyan]\n")

    # ── Step 1: Full scan pipeline ──
    with console.status("[bold cyan]Running integrity checks..."):
        integrity = verify_image(image)

    with console.status("[bold cyan]Checking vulnerability database..."):
        db_freshness = check_db_freshness()

    with console.status("[bold cyan]Generating SBOM..."):
        sbom = generate_sbom(image)
        packages = get_packages(sbom)

    with console.status("[bold cyan]Scanning for vulnerabilities..."):
        trivy_json = scan_cves(image)
        cves = parse_cve_matches(trivy_json)

    with console.status("[bold cyan]Enriching CVEs with EPSS and CISA KEV..."):
        cves = enrich_and_score(cves)

    with console.status("[bold cyan]Analyzing image layers..."):
        try:
            layer_infos = get_layer_metadata(image)
            cves = attribute_cves_to_layers(cves, layer_infos)
            cves = generate_fix_suggestions(cves, layer_infos)
        except RuntimeError as e:
            logger.warning("Layer analysis skipped: %s", e)
            layer_infos = []

    # ── Show scan summary ──
    image_name, tag = _parse_image_name(image)
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
    _print_summary(result)
    _print_risk_gauge(cves)

    if not cves:
        console.print(
            Panel(
                "[bold green]✅ No vulnerabilities found! No remediation needed.[/bold green]",
                border_style="green",
                box=box.ROUNDED,
            )
        )
        sys.exit(0)

    # ── Step 2: Generate remediation ──
    console.print(Rule("[bold magenta]🔧 Auto-Remediation[/bold magenta]", style="magenta"))
    console.print()

    with console.status("[bold magenta]Reconstructing Dockerfile from image history..."):
        dockerfile_lines = reconstruct_dockerfile(image)

    with console.status("[bold magenta]Building remediation plan..."):
        plan = build_remediation_plan(image, cves, dockerfile_lines)

    with console.status("[bold magenta]Generating patched Dockerfile..."):
        patched_content = generate_patched_dockerfile(plan)

    # ── Step 3: Display results ──
    print_remediation_report(plan, patched_content)

    # ── Step 4: Save to disk ──
    saved_path = save_patched_dockerfile(patched_content, output_dir)
    console.print(
        Panel(
            f"[bold green]✅ Patched Dockerfile saved to: {saved_path}[/bold green]\n"
            f"\n"
            f"   [dim]Next steps:[/dim]\n"
            f"   [cyan]1.[/cyan] Review the patched Dockerfile\n"
            f"   [cyan]2.[/cyan] Build: [bold]docker build -f {saved_path} -t {image_name}:patched .[/bold]\n"
            f"   [cyan]3.[/cyan] Re-scan: [bold]scanner scan {image_name}:patched[/bold]\n"
            f"   [cyan]4.[/cyan] Compare results to verify CVE reduction",
            border_style="green",
            box=box.DOUBLE,
        )
    )


def main():
    """Entry point for the CLI."""
    cli()


if __name__ == "__main__":
    main()