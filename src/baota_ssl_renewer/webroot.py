from __future__ import annotations

import secrets
from concurrent.futures import ThreadPoolExecutor
from pathlib import PurePosixPath

import httpx

from .bt_api import BaotaClient
from .models import DomainInfo, ProbeResult, SiteInfo


def _join_remote(*parts: str) -> str:
    path = PurePosixPath(parts[0])
    for part in parts[1:]:
        path = path / part
    return str(path)


def _domain_in_filter(host: str, domain_filter: set[str]) -> bool:
    host = host.strip().lower()
    return any(host == domain or host.endswith(f".{domain}") for domain in domain_filter)


class WebrootProber:
    def __init__(self, client: BaotaClient, timeout: float = 10.0):
        self.client = client
        self.timeout = timeout

    def probe_site(self, site: SiteInfo, domain_filter: set[str] | None = None) -> list[ProbeResult]:
        domains = [d for d in site.domains if domain_filter is None or _domain_in_filter(d.host, domain_filter)]
        if len(domains) <= 1:
            return [self.probe_domain(site, d) for d in domains]
        config = self.client.config
        timeout = self.timeout

        def _probe_one(domain: DomainInfo) -> ProbeResult:
            with BaotaClient(config) as client:
                return WebrootProber(client, timeout).probe_domain(site, domain)

        with ThreadPoolExecutor(max_workers=min(len(domains), 5)) as executor:
            return list(executor.map(_probe_one, domains))

    def probe_domain(self, site: SiteInfo, domain: DomainInfo) -> ProbeResult:
        host = domain.host
        if not host:
            return ProbeResult(domain=domain.name, ok=False, reason="empty domain")
        if domain.is_wildcard:
            return ProbeResult(domain=host, ok=False, reason="wildcard requires DNS-01")
        if domain.port != 80:
            return ProbeResult(domain=host, ok=False, reason=f"domain is bound to port {domain.port}, not 80")
        if not site.path:
            return ProbeResult(domain=host, ok=False, reason="site webroot path is empty")

        token = f"bt-renewer-{secrets.token_hex(16)}"
        expected = f"{token}.ok"
        challenge_dir = _join_remote(site.path, ".well-known", "acme-challenge")
        challenge_path = _join_remote(challenge_dir, token)
        url = f"http://{host}/.well-known/acme-challenge/{token}"

        try:
            self.client.create_dir(_join_remote(site.path, ".well-known"))
            self.client.create_dir(challenge_dir)
            self.client.create_file(challenge_path)
            self.client.save_file(challenge_path, expected)
        except Exception as exc:  # noqa: BLE001
            return ProbeResult(domain=host, ok=False, reason=f"cannot write challenge: {exc}", url=url)

        try:
            # ACME HTTP-01 may follow HTTP -> HTTPS redirects. Existing certificates can be
            # expired while renewing, so do not fail the probe on HTTPS certificate validity.
            with httpx.Client(timeout=self.timeout, follow_redirects=True, verify=False) as http:
                response = http.get(url)
            if response.status_code != 200:
                return ProbeResult(domain=host, ok=False, reason=f"HTTP {response.status_code}", url=url)
            actual = response.text.strip()
            if actual != expected:
                return ProbeResult(domain=host, ok=False, reason="challenge content mismatch", url=url)
            return ProbeResult(domain=host, ok=True, reason="ok", url=url)
        except Exception as exc:  # noqa: BLE001
            return ProbeResult(domain=host, ok=False, reason=f"probe failed: {exc}", url=url)
        finally:
            try:
                self.client.delete_file(challenge_path)
            except Exception:
                pass
