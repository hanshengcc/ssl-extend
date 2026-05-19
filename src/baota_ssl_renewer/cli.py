from __future__ import annotations

import argparse
import sys
from datetime import datetime

from rich.console import Console
from rich.prompt import Confirm
from rich.table import Table

from .config import load_config
from .models import SiteInfo
from .renewer import renew_all, scan_panels, should_attempt_renew, summarize_skips

console = Console()


def _configure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            reconfigure(encoding="utf-8")


def _date(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d") if value else "-"


def _domains(site: SiteInfo) -> str:
    hosts = [domain.host for domain in site.domains]
    return "\n".join(hosts[:5]) + ("\n..." if len(hosts) > 5 else "")


def render_sites(sites: list[SiteInfo]) -> None:
    table = Table(title="宝塔站点证书")
    table.add_column("#", justify="right")
    table.add_column("Panel")
    table.add_column("Site")
    table.add_column("Domains")
    table.add_column("SSL")
    table.add_column("Expires")
    table.add_column("Renewable")

    for index, site in enumerate(sites, start=1):
        allowed, reason = should_attempt_renew(site)
        ssl_state = "LE" if site.ssl.is_lets_encrypt else site.ssl.provider or site.ssl.issuer or "-"
        table.add_row(
            str(index),
            site.panel,
            site.name,
            _domains(site),
            ssl_state,
            _date(site.ssl.not_after),
            "yes" if allowed else reason,
        )
    console.print(table)


def render_errors(errors: list[str]) -> None:
    for error in errors:
        console.print(f"[red]Error:[/] {error}")


def render_renew_results(results) -> None:
    table = Table(title="续签结果")
    table.add_column("Panel")
    table.add_column("Site")
    table.add_column("Status")
    table.add_column("Included domains")
    table.add_column("Skipped domains")
    table.add_column("Message")
    for result in results:
        table.add_row(
            result.panel,
            result.site,
            "ok" if result.ok else "failed",
            "\n".join(result.included_domains) or "-",
            summarize_skips(result.skipped_domains) or "-",
            result.message,
        )
    console.print(table)


def command_scan(args: argparse.Namespace) -> int:
    configs = load_config(args.config)
    result = scan_panels(configs)
    render_errors(result.errors)
    render_sites(result.sites)
    return 1 if result.errors and not result.sites else 0


def command_renew(args: argparse.Namespace) -> int:
    configs = load_config(args.config)
    scan = scan_panels(configs)
    render_errors(scan.errors)
    render_sites(scan.sites)
    targets = [site for site in scan.sites if should_attempt_renew(site)[0]]
    if not targets:
        console.print("[yellow]No renewable Let's Encrypt sites found.[/]")
        return 1
    if args.dry_run:
        console.print("[cyan]Dry-run mode: probing webroot only; renewal requests will not be submitted.[/]")
    results = renew_all(configs, targets, dry_run=args.dry_run)
    render_renew_results(results)
    return 0 if all(result.ok for result in results) else 1


def command_interactive(args: argparse.Namespace) -> int:
    configs = load_config(args.config)
    scan = scan_panels(configs)
    render_errors(scan.errors)
    if not scan.sites:
        console.print("[red]No sites loaded.[/]")
        return 1
    render_sites(scan.sites)
    targets = [site for site in scan.sites if should_attempt_renew(site)[0]]
    if not targets:
        console.print("[yellow]No renewable Let's Encrypt sites found.[/]")
        return 1
    console.print(f"[cyan]Ready to renew {len(targets)} site(s). Webroot probing will run before each renewal.[/]")
    if not Confirm.ask("一键续签全部可续签站点?", default=False):
        console.print("Cancelled.")
        return 0
    results = renew_all(configs, targets, dry_run=False)
    render_renew_results(results)
    return 0 if all(result.ok for result in results) else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="baota-ssl-renewer", description="宝塔证书续签器")
    parser.add_argument("--config", default="baota.ini", help="Path to baota.ini")
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="Scan panels and print SSL status")
    scan.add_argument("--config", default="baota.ini", help="Path to baota.ini")

    renew = subparsers.add_parser("renew", help="Probe webroot and renew all renewable sites")
    renew.add_argument("--config", default="baota.ini", help="Path to baota.ini")
    renew.add_argument("--dry-run", action="store_true", help="Probe only; do not submit renewal")
    return parser


def main(argv: list[str] | None = None) -> int:
    _configure_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            return command_scan(args)
        if args.command == "renew":
            return command_renew(args)
        return command_interactive(args)
    except KeyboardInterrupt:
        console.print("\nCancelled.")
        return 130
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Error:[/] {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
