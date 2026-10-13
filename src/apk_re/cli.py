"""Command-line interface for Android RE Toolkit."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from . import __version__
from .analyzer import APKAnalyzer
from .decompiler import Decompiler
from .report import generate_html, generate_json
from .utils import ensure_dir

console = Console()


def setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(levelname)s: %(message)s",
    )


@click.group()
@click.version_option(__version__, prog_name="apk-re")
def main():
    """Android RE Toolkit – Professional APK Reverse Engineering for Security Research."""
    pass


@main.command()
@click.argument("apk", type=click.Path(exists=True, dir_okay=False))
@click.option("--report", type=click.Choice(["none", "json", "html", "both"]), default="none",
              help="Generate report format")
@click.option("-o", "--output", type=click.Path(), default=None,
              help="Output file path for report")
@click.option("--decompile", is_flag=True, help="Also run jadx + apktool (if installed)")
@click.option("--output-dir", type=click.Path(), default="./re_output",
              help="Directory for decompilation output")
@click.option("-v", "--verbose", is_flag=True, help="Verbose logging")
def analyze(apk: str, report: str, output: str | None, decompile: bool, output_dir: str, verbose: bool):
    """Run full static analysis on an APK."""
    setup_logging(verbose)

    console.print(Panel.fit(
        f"[bold cyan]Android RE Toolkit v{__version__}[/]\n"
        f"Analyzing: [yellow]{apk}[/]",
        border_style="cyan",
    ))

    try:
        analyzer = APKAnalyzer(apk)
        result = analyzer.analyze()
    except Exception as e:
        console.print(f"[bold red]Analysis failed:[/] {e}")
        sys.exit(1)

    # Pretty console summary
    _print_summary(result)

    # Reports
    if report in ("json", "both"):
        out = output or f"{Path(apk).stem}_report.json"
        if report == "both" and output:
            out = str(Path(output).with_suffix(".json"))
        path = generate_json(result, out)
        console.print(f"[green]✓[/] JSON report → [bold]{path}[/]")

    if report in ("html", "both"):
        out = output or f"{Path(apk).stem}_report.html"
        if report == "both" and output:
            out = str(Path(output).with_suffix(".html"))
        path = generate_html(result, out)
        console.print(f"[green]✓[/] HTML report → [bold]{path}[/]")

    # Optional decompilation
    if decompile:
        console.print("\n[bold]Decompilation[/]")
        dec = Decompiler(apk, output_dir)
        results = dec.run_all()
        for tool, path in results.items():
            if path:
                console.print(f"[green]✓[/] {tool} → {path}")
            else:
                console.print(f"[yellow]•[/] {tool} skipped (not found or failed)")


@main.command()
@click.argument("apk", type=click.Path(exists=True, dir_okay=False))
def info(apk: str):
    """Quick info only (no deep analysis)."""
    from androguard.core.apk import APK
    from .utils import file_hashes

    a = APK(apk)
    h = file_hashes(apk)

    table = Table(title="APK Quick Info", box=box.ROUNDED, show_header=False)
    table.add_column("Field", style="cyan")
    table.add_column("Value")

    table.add_row("Package", a.get_package() or "—")
    table.add_row("App Name", a.get_app_name() or "—")
    table.add_row("Version", f"{a.get_androidversion_name()} ({a.get_androidversion_code()})")
    table.add_row("Min SDK", str(a.get_min_sdk_version() or "—"))
    table.add_row("Target SDK", str(a.get_target_sdk_version() or "—"))
    table.add_row("Size", f"{h['size'] / 1024 / 1024:.2f} MB")
    table.add_row("SHA256", h["sha256"])
    table.add_row("Permissions", str(len(a.get_permissions() or [])))
    table.add_row("Activities", str(len(a.get_activities() or [])))

    console.print(table)


def _print_summary(result):
    """Rich console summary."""
    table = Table(title="Analysis Summary", box=box.ROUNDED)
    table.add_column("Item", style="cyan", width=22)
    table.add_column("Value")

    table.add_row("Package", result.package_name)
    table.add_row("App Name", result.app_name or "—")
    table.add_row("Version", f"{result.version_name} ({result.version_code})")
    table.add_row("SDK", f"min={result.min_sdk}  target={result.target_sdk}")
    table.add_row("Size", f"{result.size_bytes / 1024 / 1024:.2f} MB")
    table.add_row("SHA256", result.sha256[:32] + "…")

    danger = len(result.dangerous_permissions)
    table.add_row(
        "Permissions",
        f"{len(result.permissions)} total  "
        f"[{'red' if danger else 'green'}]{danger} dangerous[/]",
    )
    table.add_row("Exported Components", str(len(result.exported_components)))
    table.add_row("DEX / Classes / Methods", f"{result.dex_count} / {result.class_count} / {result.method_count}")
    table.add_row("Native Libraries", str(len(result.native_libs)))
    table.add_row(
        "Debuggable",
        "[red]YES[/]" if result.is_debuggable else "[green]NO[/]",
    )
    table.add_row(
        "Potential Secrets",
        f"[red]{len(result.secrets)}[/]" if result.secrets else "0",
    )

    console.print(table)

    if result.dangerous_permissions:
        console.print("\n[bold red]Dangerous Permissions:[/]")
        for p in result.dangerous_permissions:
            console.print(f"  • {p}")

    if result.secrets:
        console.print("\n[bold yellow]Potential Secrets (sample):[/]")
        for s in result.secrets[:8]:
            console.print(f"  • [{s['type']}] {s['value'][:80]}")


if __name__ == "__main__":
    main()
