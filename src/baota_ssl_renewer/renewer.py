from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_address
from typing import Callable, Iterator

from .acme_client import ACME_DIRECTORY_URLS
from .bt_api import BaotaApiError, BaotaClient, NoRenewableCertificateError
from .models import DomainBindingStatus, PanelConfig, ProbeResult, RenewResult, SiteInfo, SitePlan, StatusSummary
from .webroot import WebrootProber

ScanProgress = Callable[[str, PanelConfig, SiteInfo | None], None]
RenewProgress = Callable[[str, SiteInfo, RenewResult | None], None]
ProbeProgress = Callable[[str, SiteInfo, ProbeResult | None], None]

DEFAULT_CA_FALLBACK_ORDER = ("buypass", "letsencrypt", "litessl", "zerossl", "google", "sslcom")


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


def _domain_in_filter(host: str, domain_filter: set[str]) -> bool:
    host = host.strip().lower()
    return any(host == domain or host.endswith(f".{domain}") for domain in domain_filter)


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


def _is_ca_rate_limit_error(exc: Exception) -> bool:
    if not isinstance(exc, BaotaApiError):
        return False
    message = str(exc).lower()
    rate_limit_markers = (
        "429",
        "rate limit",
        "rate limited",
        "too many certificates",
        "too many orders",
        "too many requests",
        "too many failed authorizations",
        "retry-after",
        "限速",
        "频率",
        "配额",
        "次数过多",
        "请求过多",
    )
    return any(marker in message for marker in rate_limit_markers)


def _default_ca_fallbacks(primary_ca: str, config: PanelConfig) -> list[str]:
    if config.ca_fallbacks:
        return list(config.ca_fallbacks)
    return [
        ca
        for ca in DEFAULT_CA_FALLBACK_ORDER
        if ca != primary_ca and ca in ACME_DIRECTORY_URLS
    ]


def _ca_candidates(primary: str | None, site: SiteInfo, config: PanelConfig, ca_fallbacks: list[str] | None) -> list[str]:
    primary_ca = (primary or site.ssl.renewable_ca or config.default_ca).strip().lower()
    fallback_candidates = ca_fallbacks if ca_fallbacks is not None else _default_ca_fallbacks(primary_ca, config)
    candidates = [primary_ca, *fallback_candidates]
    ordered: list[str] = []
    for candidate in candidates:
        ca = candidate.strip().lower()
        if ca and ca not in ordered:
            ordered.append(ca)
    return ordered or ["letsencrypt"]


def _apply_with_ca_fallbacks(
    client: BaotaClient,
    site: SiteInfo,
    valid_domains: list[str],
    candidates: list[str],
) -> tuple[dict, str, str, list[str]]:
    attempts: list[str] = []
    should_issue = _any_valid_domain_unbound(site, valid_domains)
    for index, candidate in enumerate(candidates):
        try:
            if should_issue:
                body = client.issue_free_ssl(site, valid_domains, candidate)
                return body, "issue", candidate, attempts
            try:
                body = client.renew_free_ssl(site, valid_domains, candidate)
                return body, "renew", candidate, attempts
            except NoRenewableCertificateError:
                body = client.issue_free_ssl(site, valid_domains, candidate)
                return body, "issue", candidate, attempts
        except Exception as exc:  # noqa: BLE001
            if _is_fatal_program_error(exc):
                raise FatalProgramError(str(exc)) from exc
            if not _is_ca_rate_limit_error(exc) or index == len(candidates) - 1:
                raise
            attempts.append(f"{candidate}: {exc}")
    raise BaotaApiError("no ACME CA candidate was attempted")


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
    domain_filter: set[str] | None = None,
    ca: str | None = None,
    ca_fallbacks: list[str] | None = None,
) -> RenewResult:
    allowed, reason = should_attempt_renew(site)
    if not allowed:
        return RenewResult(panel=config.name, site=site.name, ok=False, message=reason)

    with BaotaClient(config) as client:
        if probes is None:
            prober = WebrootProber(client)
            probes = prober.probe_site(site, domain_filter=domain_filter)
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
            body, action, selected_ca, ca_attempts = _apply_with_ca_fallbacks(
                client,
                site,
                valid_domains,
                _ca_candidates(ca, site, config, ca_fallbacks),
            )
        except Exception as exc:  # noqa: BLE001 - classify batch-fatal API/logic errors separately.
            if isinstance(exc, FatalProgramError):
                raise
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
        if ca_attempts:
            message = f"{message} (CA fallback: {' -> '.join([attempt.split(':', 1)[0] for attempt in ca_attempts] + [selected_ca])})"
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


def scan_and_apply_sequential(
    configs: list[PanelConfig],
    dry_run: bool = False,
    progress: RenewProgress | None = None,
    domain_filter: set[str] | None = None,
    ca: str | None = None,
    ca_fallbacks: list[str] | None = None,
) -> tuple[list[RenewResult], list[str]]:
    """Stream scan → probe → renew: each site is processed as soon as its metadata is ready."""
    results: list[RenewResult] = []
    errors: list[str] = []
    for config in configs:
        try:
            with BaotaClient(config) as client:
                for site in client.iter_sites():
                    if domain_filter and not any(_domain_in_filter(d.host, domain_filter) for d in site.domains):
                        continue
                    if not should_attempt_renew(site)[0]:
                        continue
                    if progress:
                        progress("site_start", site, None)
                    try:
                        result = renew_site(
                            config,
                            site,
                            dry_run=dry_run,
                            domain_filter=domain_filter,
                            ca=ca,
                            ca_fallbacks=ca_fallbacks,
                        )
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
                        return results, errors
                    results.append(result)
                    if progress:
                        progress("site_done", site, result)
        except BaotaApiError as exc:
            errors.append(str(exc))
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{config.name}: {exc}")
    return results, errors


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
