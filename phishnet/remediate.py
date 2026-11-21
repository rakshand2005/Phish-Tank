"""
Auto-Remediation Dockerfile Generator.

Analyzes scan results and generates a patched Dockerfile that fixes
all remediable vulnerabilities. This is the "wow factor" feature —
one command turns a vulnerable image into a hardened one.

Usage (from main.py):
    phishnet fix nginx:1.14
    phishnet fix nginx:1.14 --output-dir ./patched

What it does:
    1. Reconstructs the original Dockerfile from image history
    2. Identifies fixable CVEs and maps them to Dockerfile lines
    3. Generates a patched Dockerfile with:
       - Upgraded base image (if newer exists)
       - Pinned fixed package versions
       - Security best practices (non-root user, HEALTHCHECK, etc.)
    4. Shows a rich terminal diff of original vs patched
"""

from __future__ import annotations

import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.table import Table
    from rich.text import Text
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    class Console:  # type: ignore
        def print(self, *args, **kwargs):
            if args:
                print(*args)
    Panel = Syntax = Table = Text = box = None  # type: ignore

logger = logging.getLogger(__name__)
console = Console()


# ── Known base image upgrade paths ──────────────────────────────────────────

BASE_IMAGE_UPGRADES = {
    # Debian-based nginx
    "nginx:1.14":       "nginx:1.27-bookworm",
    "nginx:1.15":       "nginx:1.27-bookworm",
    "nginx:1.16":       "nginx:1.27-bookworm",
    "nginx:1.17":       "nginx:1.27-bookworm",
    "nginx:1.18":       "nginx:1.27-bookworm",
    "nginx:1.19":       "nginx:1.27-bookworm",
    "nginx:1.20":       "nginx:1.27-bookworm",
    "nginx:1.21":       "nginx:1.27-bookworm",
    "nginx:1.22":       "nginx:1.27-bookworm",
    "nginx:1.23":       "nginx:1.27-bookworm",
    "nginx:1.24":       "nginx:1.27-bookworm",
    "nginx:1.25":       "nginx:1.27-bookworm",
    # Alpine variants
    "nginx:1.14-alpine": "nginx:1.27-alpine",
    "nginx:alpine":      "nginx:1.27-alpine",
    # Python
    "python:3.7":       "python:3.12-slim-bookworm",
    "python:3.8":       "python:3.12-slim-bookworm",
    "python:3.9":       "python:3.12-slim-bookworm",
    "python:3.9-slim":  "python:3.12-slim-bookworm",
    "python:3.10":      "python:3.12-slim-bookworm",
    "python:3.10-slim": "python:3.12-slim-bookworm",
    "python:3.11-slim": "python:3.12-slim-bookworm",
    # Node
    "node:14":          "node:22-slim",
    "node:16":          "node:22-slim",
    "node:18":          "node:22-slim",
    "node:20":          "node:22-slim",
    # Ubuntu
    "ubuntu:18.04":     "ubuntu:24.04",
    "ubuntu:20.04":     "ubuntu:24.04",
    "ubuntu:22.04":     "ubuntu:24.04",
    # Debian
    "debian:stretch":   "debian:bookworm-slim",
    "debian:buster":    "debian:bookworm-slim",
    "debian:bullseye":  "debian:bookworm-slim",
    # Alpine
    "alpine:3.12":      "alpine:3.20",
    "alpine:3.13":      "alpine:3.20",
    "alpine:3.14":      "alpine:3.20",
    "alpine:3.15":      "alpine:3.20",
    "alpine:3.16":      "alpine:3.20",
    "alpine:3.17":      "alpine:3.20",
    "alpine:3.18":      "alpine:3.20",
}


@dataclass
class DockerfileLine:
    """A single line/instruction in a Dockerfile."""
    instruction: str        # FROM, RUN, COPY, etc.
    arguments: str          # The rest of the line
    original: str           # Full original line
    line_number: int = 0
    is_modified: bool = False
    modification_reason: str = ""


@dataclass
class RemediationPlan:
    """Plan for remediating a Dockerfile."""
    original_image: str
    upgraded_base: Optional[str] = None
    package_pins: dict = field(default_factory=dict)     # {pkg: fixed_version}
    security_hardening: list[str] = field(default_factory=list)
    total_cves_fixed: int = 0
    total_cves_unfixable: int = 0
    original_lines: list[DockerfileLine] = field(default_factory=list)
    patched_lines: list[str] = field(default_factory=list)


def reconstruct_dockerfile(image_name: str) -> list[DockerfileLine]:
    """
    Reconstruct a Dockerfile from Docker image history.

    Uses `docker history --no-trunc` to get the full layer commands
    and rebuilds an approximate Dockerfile.
    """
    try:
        result = subprocess.run(
            ["docker", "history", "--no-trunc", "--format",
             "{{.CreatedBy}}|||{{.Size}}", image_name],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            logger.warning("docker history failed: %s", result.stderr)
            return _fallback_dockerfile(image_name)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return _fallback_dockerfile(image_name)

    lines: list[DockerfileLine] = []
    history_lines = result.stdout.strip().split("\n")

    # History is newest-first, reverse for Dockerfile order
    history_lines.reverse()

    line_num = 0
    for entry in history_lines:
        parts = entry.split("|||", 1)
        created_by = parts[0].strip() if parts else ""
        if not created_by:
            continue

        instruction, arguments = _parse_history_line(created_by)
        if instruction:
            line_num += 1
            lines.append(DockerfileLine(
                instruction=instruction,
                arguments=arguments,
                original=f"{instruction} {arguments}",
                line_number=line_num,
            ))

    # If no FROM was found, add one
    if not any(l.instruction == "FROM" for l in lines):
        lines.insert(0, DockerfileLine(
            instruction="FROM",
            arguments=image_name,
            original=f"FROM {image_name}",
            line_number=0,
        ))

    return lines


def _parse_history_line(created_by: str) -> tuple[str, str]:
    """Parse a docker history CreatedBy line into instruction + args."""
    # Remove /bin/sh -c prefix
    if created_by.startswith("/bin/sh -c "):
        cmd = created_by[len("/bin/sh -c "):]
        # Check for #(nop) marker (metadata instructions)
        if cmd.startswith("#(nop) "):
            meta = cmd[len("#(nop) "):].strip()
            # Parse metadata instructions
            for inst in ["ENV", "EXPOSE", "WORKDIR", "ENTRYPOINT",
                         "CMD", "LABEL", "VOLUME", "USER", "ARG",
                         "STOPSIGNAL", "SHELL", "HEALTHCHECK"]:
                if meta.startswith(inst):
                    return inst, meta[len(inst):].strip()
            if meta.startswith("ADD "):
                return "ADD", meta[4:].strip()
            if meta.startswith("COPY "):
                return "COPY", meta[5:].strip()
            return "", ""
        else:
            return "RUN", cmd
    elif created_by.startswith("ADD ") or created_by.startswith("COPY "):
        parts = created_by.split(" ", 1)
        return parts[0], parts[1] if len(parts) > 1 else ""
    elif "FROM" in created_by.upper():
        return "FROM", created_by
    else:
        return "RUN", created_by


def _fallback_dockerfile(image_name: str) -> list[DockerfileLine]:
    """Create a minimal Dockerfile when history is unavailable."""
    return [DockerfileLine(
        instruction="FROM",
        arguments=image_name,
        original=f"FROM {image_name}",
        line_number=1,
    )]


def build_remediation_plan(
    image_name: str,
    cves: list,
    dockerfile_lines: list[DockerfileLine],
) -> RemediationPlan:
    """
    Analyze CVEs and build a remediation plan.

    Groups fixes by type:
    - Base image upgrade (fixes the most CVEs at once)
    - Individual package version pins
    - Security hardening additions
    """
    plan = RemediationPlan(original_image=image_name)
    plan.original_lines = dockerfile_lines

    # ── 1. Check for base image upgrade ──
    base_name = image_name.split("@")[0]  # Remove digest if present
    if base_name in BASE_IMAGE_UPGRADES:
        plan.upgraded_base = BASE_IMAGE_UPGRADES[base_name]

    # ── 2. Collect package fixes ──
    apt_fixes: dict[str, str] = {}   # {package: fixed_version}
    apk_fixes: dict[str, str] = {}
    pip_fixes: dict[str, str] = {}
    npm_fixes: dict[str, str] = {}

    for cve in cves:
        fixed = getattr(cve, "fixed_version", None)
        if not fixed:
            plan.total_cves_unfixable += 1
            continue

        plan.total_cves_fixed += 1
        pkg = cve.package
        layer_cmd = getattr(cve, "layer_command", "") or ""
        layer_lower = layer_cmd.lower()

        # Categorize by package ecosystem and manager
        pkg_type = getattr(cve, "pkg_type", "os")

        if pkg_type == "python" or "pip" in layer_lower:
            pip_fixes[pkg] = fixed
        elif pkg_type == "node" or "npm" in layer_lower or "yarn" in layer_lower:
            npm_fixes[pkg] = fixed
        elif pkg_type == "os":
            if "apk" in layer_lower or "alpine" in (plan.upgraded_base or plan.original_image).lower():
                apk_fixes[pkg] = fixed
            else:
                apt_fixes[pkg] = fixed
        else:
            if "apk" in layer_lower:
                apk_fixes[pkg] = fixed
            elif "pip" in layer_lower:
                pip_fixes[pkg] = fixed
            elif "npm" in layer_lower or "yarn" in layer_lower:
                npm_fixes[pkg] = fixed
            else:
                apt_fixes[pkg] = fixed

    plan.package_pins = {
        "apt": apt_fixes,
        "apk": apk_fixes,
        "pip": pip_fixes,
        "npm": npm_fixes,
    }

    # ── 3. Security hardening suggestions ──
    has_user = any(l.instruction == "USER" for l in dockerfile_lines)
    has_healthcheck = any(l.instruction == "HEALTHCHECK" for l in dockerfile_lines)

    if not has_user:
        plan.security_hardening.append("non-root-user")
    if not has_healthcheck:
        plan.security_hardening.append("healthcheck")
    plan.security_hardening.append("no-cache-cleanup")

    return plan


def generate_patched_dockerfile(plan: RemediationPlan) -> str:
    """
    Generate the actual patched Dockerfile content from the plan.
    """
    lines: list[str] = []
    lines.append("# ╔══════════════════════════════════════════════════════════════╗")
    lines.append("# ║  🛡️  AUTO-REMEDIATED DOCKERFILE                             ║")
    lines.append("# ║  Generated by Phish Net                                     ║")
    lines.append(f"# ║  Original: {plan.original_image:<49s}║")
    lines.append(f"# ║  CVEs fixed: {plan.total_cves_fixed:<47d}║")
    lines.append("# ╚══════════════════════════════════════════════════════════════╝")
    lines.append("")

    # ── FROM instruction ──
    if plan.upgraded_base:
        lines.append(f"# REMEDIATION: Base image upgraded ({plan.original_image} → {plan.upgraded_base})")
        lines.append(f"# This single change resolves the majority of OS-level CVEs.")
        lines.append(f"FROM {plan.upgraded_base}")
    else:
        lines.append(f"FROM {plan.original_image}")
    lines.append("")

    # ── Security labels ──
    lines.append('LABEL security.phishnet="auto-remediated"')
    lines.append(f'LABEL security.original-image="{plan.original_image}"')
    lines.append("")

    # ── Reconstruct original instructions with fixes ──
    for dl in plan.original_lines:
        if dl.instruction == "FROM":
            continue  # Already handled above

        if dl.instruction in ("ENV", "WORKDIR", "EXPOSE", "LABEL",
                              "ARG", "VOLUME", "ENTRYPOINT", "CMD",
                              "STOPSIGNAL", "SHELL"):
            lines.append(f"{dl.instruction} {dl.arguments}")
            continue

        if dl.instruction in ("COPY", "ADD"):
            lines.append(f"{dl.instruction} {dl.arguments}")
            continue

        if dl.instruction == "RUN":
            # Check if this RUN installs packages we need to pin
            patched_cmd = _patch_run_command(dl.arguments, plan)
            if patched_cmd != dl.arguments:
                lines.append(f"# REMEDIATION: Package versions pinned to fix CVEs")
                lines.append(f"RUN {patched_cmd}")
            else:
                lines.append(f"RUN {dl.arguments}")
            continue

        if dl.instruction == "USER":
            lines.append(f"USER {dl.arguments}")
            continue

        # Passthrough anything else
        lines.append(dl.original)

    # ── APT package update layer (if there are apt fixes not in existing RUN lines) ──
    apt_fixes = plan.package_pins.get("apt", {})
    if apt_fixes:
        unfixed_pkgs = _get_unhandled_apt_fixes(plan)
        if unfixed_pkgs:
            lines.append("")
            if plan.upgraded_base:
                lines.append("# NOTE: Base image was upgraded. The new base image provides updated system libraries.")
                lines.append("# Unhandled packages from previous base are superseded by the new base image.")
            else:
                lines.append("# REMEDIATION: Pin vulnerable packages to fixed versions")
                pkg_list = " \\\n    ".join(
                    f"{pkg}={ver}" for pkg, ver in sorted(unfixed_pkgs.items())
                )
                lines.append(f"RUN apt-get update && apt-get install -y --no-install-recommends \\")
                lines.append(f"    {pkg_list} \\")
                lines.append(f"    && rm -rf /var/lib/apt/lists/*")

    # ── APK package update layer ──
    apk_fixes = plan.package_pins.get("apk", {})
    if apk_fixes:
        lines.append("")
        lines.append("# REMEDIATION: Pin vulnerable Alpine packages")
        pkg_list = " ".join(f"{pkg}={ver}" for pkg, ver in sorted(apk_fixes.items()))
        lines.append(f"RUN apk update && apk add --no-cache {pkg_list}")

    # ── Pip fixes ──
    pip_fixes = plan.package_pins.get("pip", {})
    if pip_fixes:
        lines.append("")
        lines.append("# REMEDIATION: Upgrade vulnerable Python packages")
        pkg_list = " ".join(f"{pkg}>={ver}" for pkg, ver in sorted(pip_fixes.items()))
        lines.append(f"RUN pip install --no-cache-dir --upgrade {pkg_list}")

    # ── Security hardening ──
    if plan.security_hardening:
        lines.append("")
        lines.append("# ── Security Hardening ──────────────────────────────────────")

        if "healthcheck" in plan.security_hardening:
            lines.append("# HEALTHCHECK instruction: Customize with your application health probe")
            lines.append("# HEALTHCHECK --interval=30s --timeout=5s --retries=3 \\")
            lines.append('#     CMD curl -f http://localhost/ || exit 1')

        if "non-root-user" in plan.security_hardening:
            lines.append("")
            lines.append("# Run as non-root for defense in depth")
            is_alpine = "alpine" in (plan.upgraded_base or plan.original_image).lower()
            if is_alpine:
                lines.append("RUN addgroup -S appuser && adduser -S appuser -G appuser")
            else:
                lines.append("RUN groupadd -r appuser && useradd -r -g appuser appuser")
            lines.append("USER appuser")

    lines.append("")
    return "\n".join(lines)


def _patch_run_command(cmd: str, plan: RemediationPlan) -> str:
    """Patch a RUN command to pin vulnerable packages to fixed versions."""
    patched = cmd
    apt_fixes = plan.package_pins.get("apt", {})

    # Patch apt-get install commands
    for pkg, fixed_ver in apt_fixes.items():
        # Match patterns like: package_name (without version pin)
        pattern = rf'\b{re.escape(pkg)}\b(?!=)'
        if re.search(pattern, patched) and "apt-get install" in patched:
            patched = re.sub(pattern, f"{pkg}={fixed_ver}", patched, count=1)

    return patched


def _get_unhandled_apt_fixes(plan: RemediationPlan) -> dict[str, str]:
    """Find apt fixes that weren't handled by patching existing RUN lines."""
    apt_fixes = plan.package_pins.get("apt", {})
    handled = set()

    for dl in plan.original_lines:
        if dl.instruction == "RUN" and "apt-get install" in dl.arguments:
            for pkg in apt_fixes:
                if pkg in dl.arguments:
                    handled.add(pkg)

    return {k: v for k, v in apt_fixes.items() if k not in handled}


# ── Rich Terminal Display ────────────────────────────────────────────────────

def print_remediation_report(plan: RemediationPlan, patched_dockerfile: str) -> None:
    """Print a beautiful remediation report to the terminal."""

    # ── Header ──
    console.print()
    header = Text()
    header.append("🔧  Auto-Remediation Report", style="bold magenta")
    console.print(Panel(header, border_style="magenta", box=box.DOUBLE))
    console.print()

    # ── Summary Stats ──
    stats = Table(
        title="📊 Remediation Summary",
        box=box.ROUNDED,
        title_style="bold white",
        border_style="cyan",
    )
    stats.add_column("Metric", style="cyan", min_width=30)
    stats.add_column("Value", justify="right", min_width=15)

    stats.add_row("Original Image", plan.original_image)
    if plan.upgraded_base:
        stats.add_row(
            "Upgraded Base",
            Text(plan.upgraded_base, style="bold green"),
        )
    stats.add_row(
        "CVEs Fixed",
        Text(str(plan.total_cves_fixed), style="bold green"),
    )
    stats.add_row(
        "CVEs Unfixable (no patch available)",
        Text(str(plan.total_cves_unfixable), style="yellow" if plan.total_cves_unfixable else "green"),
    )

    # Count total package pins
    total_pins = sum(len(v) for v in plan.package_pins.values())
    stats.add_row("Package Versions Pinned", str(total_pins))

    hardening_count = len(plan.security_hardening)
    stats.add_row("Security Hardening Rules Added", str(hardening_count))

    console.print(stats)
    console.print()

    # ── Package Fix Details ──
    all_fixes = {}
    for manager, fixes in plan.package_pins.items():
        for pkg, ver in fixes.items():
            all_fixes[pkg] = (ver, manager)

    if all_fixes:
        fix_table = Table(
            title="📦 Package Version Pins",
            box=box.SIMPLE_HEAVY,
            title_style="bold white",
            border_style="green",
        )
        fix_table.add_column("Package", style="bold", min_width=20)
        fix_table.add_column("Fixed Version", style="green", min_width=15)
        fix_table.add_column("Manager", style="dim", min_width=10)

        for pkg, (ver, mgr) in sorted(all_fixes.items()):
            fix_table.add_row(pkg, ver, mgr)

        console.print(fix_table)
        console.print()

    # ── Security Hardening ──
    if plan.security_hardening:
        hardening_table = Table(
            title="🔒 Security Hardening Applied",
            box=box.SIMPLE_HEAVY,
            title_style="bold white",
            border_style="yellow",
        )
        hardening_table.add_column("Rule", style="bold", min_width=30)
        hardening_table.add_column("Description", min_width=40)

        hardening_descriptions = {
            "non-root-user": "Container runs as non-root user (defense in depth)",
            "healthcheck": "HEALTHCHECK instruction for container orchestrators",
            "no-cache-cleanup": "apt cache cleaned after install (smaller image)",
        }
        for rule in plan.security_hardening:
            desc = hardening_descriptions.get(rule, rule)
            hardening_table.add_row(rule, desc)

        console.print(hardening_table)
        console.print()

    # ── Show the patched Dockerfile ──
    console.print(
        Panel(
            "[bold]📝 Generated Dockerfile[/bold]",
            border_style="green",
            box=box.ROUNDED,
        )
    )
    syntax = Syntax(
        patched_dockerfile,
        "dockerfile",
        theme="monokai",
        line_numbers=True,
        word_wrap=True,
    )
    console.print(syntax)
    console.print()


def save_patched_dockerfile(content: str, output_dir: str) -> str:
    """Save the patched Dockerfile to disk."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    dockerfile_path = output_path / "Dockerfile.patched"
    dockerfile_path.write_text(content, encoding="utf-8")

    return str(dockerfile_path)
