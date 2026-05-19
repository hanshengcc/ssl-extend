from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_address
from typing import Callable

from .bt_api import BaotaApiError, BaotaClient, NoRenewableCertificateError
from .models import DomainBindingStatus, PanelConfig, ProbeResult, RenewResult, SiteInfo, SitePlan, StatusSummary
from .webroot import WebrootProber

ScanProgress = Callable[[str, PanelConfig, SiteInfo | None], None]
RenewProgress = Callable[[str, SiteInfo, RenewResult | None], None]
ProbeProgress = Callable[[str, SiteInfo, ProbeResult | None], None]


class FatalProgramError(RuntimeError):
    """Raised when the batch should stop because later sites will hit the same API/logic error."""


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
    if not site.domains:
        return False, "site has no domains"
    if not site.ssl.enabled:
        return True, "ok"
    if not site.ssl.is_supported_free_ca:
        return False, "not a supported free certificate provider"
    return True, "ok"


def _domain_set(values: list[str]) -> set[str]:
    return {value.strip().lower() for value in values if value.strip()}


def _domain_matches_certificate(host: str, cert_domain: str) -> bool:
    host = host.lower()
    cert_domain = cert_domain.lower()
    if host == cert_domain:
        return True
    if not cert_domain.startswith("*."):
        return False
    suffix = cert_domain[1:]
    return host.endswith(suffix) and host.count(".") == cert_domain.count(".")


def _domain_bound_by_certificate(host: str, cert_domains: set[str]) -> bool:
    return any(_domain_matches_certificate(host, cert_domain) for cert_domain in cert_domains)


def build_domain_statuses(sites: list[SiteInfo], probes: dict[tuple[str, str, str], ProbeResult] | None = None) -> list[DomainBindingStatus]:
    statuses: list[DomainBindingStatus] = []
    probes = probes or {}
    for site in sites:
        cert_domains = _domain_set(site.ssl.domains)
        for domain in site.domains:
            host = domain.host.lower()
            probe = probes.get((site.panel, site.name, host))
            statuses.append(
                DomainBindingStatus(
                    panel=site.panel,
                    site=site.name,
                    domain=host,
                    certificate_bound=_domain_bound_by_certificate(host, cert_domains),
                    webroot_ok=probe.ok if probe else None,
                    webroot_reason=probe.reason if probe else None,
                )
            )
    return statuses


def summarize_statuses(sites: list[SiteInfo], statuses: list[DomainBindingStatus]) -> StatusSummary:
    site_domain_count = len(statuses)
    certificate_domain_count = sum(len(_domain_set(site.ssl.domains)) for site in sites)
    bound_count = sum(1 for status in statuses if status.certificate_bound)
    unbound_count = site_domain_count - bound_count
    webroot_ok_count = sum(1 for status in statuses if status.webroot_ok is True)
    webroot_failed_count = sum(1 for status in statuses if status.webroot_ok is False)
    return StatusSummary(
        site_count=len(sites),
        site_domain_count=site_domain_count,
        certificate_domain_count=certificate_domain_count,
        certificate_bound_domain_count=bound_count,
        certificate_unbound_domain_count=unbound_count,
        webroot_ok_count=webroot_ok_count,
        webroot_failed_count=webroot_failed_count,
    )


def probe_sites(
    configs: list[PanelConfig],
    sites: list[SiteInfo],
    progress: ProbeProgress | None = None,
) -> dict[tuple[str, str, str], ProbeResult]:
    by_panel = {config.name: config for config in configs}
    results: dict[tuple[str, str, str], ProbeResult] = {}
    for site in sites:
        if progress:
            progress("site_start", site, None)
        config = by_panel.get(site.panel)
        if not config:
            if progress:
                progress("site_done", site, None)
            continue
        with BaotaClient(config) as client:
            prober = WebrootProber(client)
            for probe in prober.probe_site(site):
                results[(site.panel, site.name, probe.domain.lower())] = probe
                if progress:
                    progress("domain_done", site, probe)
        if progress:
            progress("site_done", site, None)
    return results


def _is_ip_host(host: str) -> bool:
    try:
        ip_address(host)
    except ValueError:
        return False
    return True


def _filter_provider_domains(site: SiteInfo, domains: list[str]) -> tuple[list[str], list[ProbeResult]]:
    if not site.ssl.is_litessl:
        return domains, []
    allowed: list[str] = []
    skipped: list[ProbeResult] = []
    for domain in domains:
        if _is_ip_host(domain):
            skipped.append(ProbeResult(domain=domain, ok=False, reason="LiteSSL does not support IP certificates"))
        else:
            allowed.append(domain)
    return allowed, skipped


def _any_valid_domain_unbound(site: SiteInfo, domains: list[str]) -> bool:
    cert_domains = _domain_set(site.ssl.domains)
    return any(not _domain_bound_by_certificate(domain, cert_domains) for domain in domains)


def _is_fatal_program_error(exc: Exception) -> bool:
    if not isinstance(exc, BaotaApiError):
        return False
    message = str(exc).lower()
    fatal_markers = (
        "http 404 for /acme",
        "http 404 for /site",
        "指定参数无效",
        "invalid parameter",
        "invalid param",
        "接口不存在",
        "not include certificate",
        "did not include certificate",
        "non-json response",
    )
    return any(marker in message for marker in fatal_markers)


def plan_site(site: SiteInfo, probes: list[ProbeResult]) -> SitePlan:
    allowed, reason = should_attempt_renew(site)
    if not allowed:
        return SitePlan(panel=site.panel, site=site.name, action="skip", message=reason)
    valid_domains, provider_skipped = _filter_provider_domains(site, [probe.domain for probe in probes if probe.ok])
    skipped = [probe for probe in probes if not probe.ok]
    skipped.extend(provider_skipped)
    if not valid_domains:
        return SitePlan(
            panel=site.panel,
            site=site.name,
            action="skip",
            message="no domain passed webroot probe",
            skipped_domains=skipped,
        )
    action = "issue" if _any_valid_domain_unbound(site, valid_domains) else "renew"
    message = "issue certificate for accessible uncovered domains" if action == "issue" else "renew existing certificate"
    return SitePlan(
        panel=site.panel,
        site=site.name,
        action=action,
        message=message,
        included_domains=valid_domains,
        skipped_domains=skipped,
    )


def plan_sites(sites: list[SiteInfo], probes: dict[tuple[str, str, str], ProbeResult]) -> list[SitePlan]:
    plans: list[SitePlan] = []
    for site in sites:
        site_probes = [
            probe
            for domain in site.domains
            if (probe := probes.get((site.panel, site.name, domain.host.lower()))) is not None
        ]
        plans.append(plan_site(site, site_probes))
    return plans


def renew_site(
    config: PanelConfig,
    site: SiteInfo,
    dry_run: bool = False,
    probes: list[ProbeResult] | None = None,
) -> RenewResult:
    allowed, reason = should_attempt_renew(site)
    if not allowed:
        return RenewResult(panel=config.name, site=site.name, ok=False, message=reason)

    with BaotaClient(config) as client:
        if probes is None:
            prober = WebrootProber(client)
            probes = prober.probe_site(site)
        valid_domains, provider_skipped = _filter_provider_domains(site, [probe.domain for probe in probes if probe.ok])
        skipped = [probe for probe in probes if not probe.ok]
        skipped.extend(provider_skipped)
        if not valid_domains:
            return RenewResult(
                panel=config.name,
                site=site.name,
                ok=False,
                message="no domain passed webroot probe",
                skipped_domains=skipped,
            )
        if dry_run:
            action = "issue" if _any_valid_domain_unbound(site, valid_domains) else "renew"
            return RenewResult(
                panel=config.name,
                site=site.name,
                ok=True,
                message=f"dry-run: would {action} certificate",
                included_domains=valid_domains,
                skipped_domains=skipped,
            )
        try:
            ca = site.ssl.renewable_ca or "letsencrypt"
            if _any_valid_domain_unbound(site, valid_domains):
                body = client.issue_free_ssl(site, valid_domains, ca)
                action = "issue"
            else:
                try:
                    body = client.renew_free_ssl(site, valid_domains, ca)
                    action = "renew"
                except NoRenewableCertificateError:
                    body = client.issue_free_ssl(site, valid_domains, ca)
                    action = "issue"
        except Exception as exc:  # noqa: BLE001 - classify batch-fatal API/logic errors separately.
            if _is_fatal_program_error(exc):
                raise FatalProgramError(str(exc)) from exc
            return RenewResult(
                panel=config.name,
                site=site.name,
                ok=False,
                message=str(exc),
                included_domains=valid_domains,
                skipped_domains=skipped,
            )
        default_message = "certificate issue request submitted" if action == "issue" else "renew request submitted"
        message = str(body.get("msg") or body.get("message") or default_message)
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
    probes: dict[tuple[str, str, str], ProbeResult] | None = None,
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
        site_probes = None
        if probes is not None:
            site_probes = [
                probe
                for domain in site.domains
                if (probe := probes.get((site.panel, site.name, domain.host.lower()))) is not None
            ]
        result = renew_site(config, site, dry_run=dry_run, probes=site_probes)
        results.append(result)
        if progress:
            progress("site_done", site, result)
    return results


def apply_sites_sequential(
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
        try:
            result = renew_site(config, site, dry_run=dry_run)
        except FatalProgramError as exc:
            result = RenewResult(
                panel=config.name,
                site=site.name,
                ok=False,
                message=f"fatal program/API error: {exc}",
            )
            results.append(result)
            if progress:
                progress("site_done", site, result)
            break
        results.append(result)
        if progress:
            progress("site_done", site, result)
    return results


def summarize_skips(probes: list[ProbeResult]) -> str:
    if not probes:
        return ""
    return "; ".join(f"{probe.domain}: {probe.reason}" for probe in probes)


def set_https_all(
    configs: list[PanelConfig],
    sites: list[SiteInfo],
    enabled: bool,
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
        elif dry_run:
            action = "enable force HTTPS" if enabled else "disable force HTTPS"
            result = RenewResult(panel=site.panel, site=site.name, ok=True, message=f"dry-run: would {action}")
        else:
            try:
                with BaotaClient(config) as client:
                    body = client.set_force_https(site, enabled)
                result = RenewResult(
                    panel=site.panel,
                    site=site.name,
                    ok=True,
                    message=str(body.get("msg") or body.get("message") or "updated"),
                )
            except BaotaApiError as exc:
                result = RenewResult(panel=site.panel, site=site.name, ok=False, message=str(exc))
        results.append(result)
        if progress:
            progress("site_done", site, result)
    return results
