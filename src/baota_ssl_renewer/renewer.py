from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .bt_api import BaotaApiError, BaotaClient
from .models import PanelConfig, ProbeResult, RenewResult, SiteInfo
from .webroot import WebrootProber

ScanProgress = Callable[[str, PanelConfig, SiteInfo | None], None]
RenewProgress = Callable[[str, SiteInfo, RenewResult | None], None]


@dataclass
class ScanResult:
    sites: list[SiteInfo] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def scan_panels(configs: list[PanelConfig], progress: ScanProgress | None = None) -> ScanResult:
    result = ScanResult()
    for config in configs:
        if progress:
            progress("panel_start", config, None)
        try:
            with BaotaClient(config) as client:
                sites = client.load_sites()
                result.sites.extend(sites)
                if progress:
                    for site in sites:
                        progress("site_loaded", config, site)
        except BaotaApiError as exc:
            result.errors.append(str(exc))
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"{config.name}: {exc}")
        finally:
            if progress:
                progress("panel_done", config, None)
    return result


def should_attempt_renew(site: SiteInfo) -> tuple[bool, str]:
    if not site.ssl.enabled:
        return False, "SSL is not enabled or status is unavailable"
    if not site.ssl.is_lets_encrypt:
        return False, "not a Let's Encrypt certificate"
    if not site.domains:
        return False, "site has no domains"
    return True, "ok"


def renew_site(config: PanelConfig, site: SiteInfo, dry_run: bool = False) -> RenewResult:
    allowed, reason = should_attempt_renew(site)
    if not allowed:
        return RenewResult(panel=config.name, site=site.name, ok=False, message=reason)

    with BaotaClient(config) as client:
        prober = WebrootProber(client)
        probes = prober.probe_site(site)
        valid_domains = [probe.domain for probe in probes if probe.ok]
        skipped = [probe for probe in probes if not probe.ok]
        if not valid_domains:
            return RenewResult(
                panel=config.name,
                site=site.name,
                ok=False,
                message="no domain passed webroot probe",
                skipped_domains=skipped,
            )
        if dry_run:
            return RenewResult(
                panel=config.name,
                site=site.name,
                ok=True,
                message="dry-run: renewal not submitted",
                included_domains=valid_domains,
                skipped_domains=skipped,
            )
        try:
            body = client.renew_lets_ssl(site, valid_domains)
        except BaotaApiError as exc:
            return RenewResult(
                panel=config.name,
                site=site.name,
                ok=False,
                message=str(exc),
                included_domains=valid_domains,
                skipped_domains=skipped,
            )
        message = str(body.get("msg") or body.get("message") or "renew request submitted")
        return RenewResult(
            panel=config.name,
            site=site.name,
            ok=True,
            message=message,
            included_domains=valid_domains,
            skipped_domains=skipped,
        )


def renew_all(
    configs: list[PanelConfig],
    sites: list[SiteInfo],
    dry_run: bool = False,
    progress: RenewProgress | None = None,
) -> list[RenewResult]:
    by_panel = {config.name: config for config in configs}
    results: list[RenewResult] = []
    for site in sites:
        if progress:
            progress("site_start", site, None)
        config = by_panel.get(site.panel)
        if not config:
            result = RenewResult(panel=site.panel, site=site.name, ok=False, message="panel config missing")
            results.append(result)
            if progress:
                progress("site_done", site, result)
            continue
        result = renew_site(config, site, dry_run=dry_run)
        results.append(result)
        if progress:
            progress("site_done", site, result)
    return results


def summarize_skips(probes: list[ProbeResult]) -> str:
    if not probes:
        return ""
    return "; ".join(f"{probe.domain}: {probe.reason}" for probe in probes)
