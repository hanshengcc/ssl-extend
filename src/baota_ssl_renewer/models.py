from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class PanelConfig:
    name: str
    url: str
    api_key: str
    verify_ssl: bool = True
    timeout: float = 15.0
    default_ca: str = "letsencrypt"
    ca_fallbacks: tuple[str, ...] = ()
    acme_directory_url: str | None = None
    acme_eab_kid: str | None = None
    acme_eab_hmac_key: str | None = None


@dataclass(frozen=True)
class DomainInfo:
    name: str
    port: int = 80

    @property
    def host(self) -> str:
        return self.name.split(":", 1)[0].strip()

    @property
    def is_wildcard(self) -> bool:
        return self.host.startswith("*.")


@dataclass
class SslInfo:
    enabled: bool = False
    provider: str | None = None
    issuer: str | None = None
    not_after: datetime | None = None
    domains: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    def _provider_text(self) -> str:
        raw_values = [
            self.raw.get("issuer"),
            self.raw.get("brand"),
            self.raw.get("ca"),
            self.raw.get("cert_type"),
            self.raw.get("auth_type"),
        ]
        return " ".join(str(v).lower() for v in (self.provider, self.issuer, *raw_values) if v)

    def _contains_provider(self, *markers: str) -> bool:
        values = self._provider_text()
        return any(marker in values for marker in markers)

    @property
    def is_lets_encrypt(self) -> bool:
        return self._contains_provider("let's encrypt", "lets encrypt", "letsencrypt")

    @property
    def is_litessl(self) -> bool:
        return self._contains_provider("litessl", "trustasia", "trust asia")

    @property
    def is_zerossl(self) -> bool:
        return self._contains_provider("zerossl", "zero ssl")

    @property
    def is_buypass(self) -> bool:
        return self._contains_provider("buypass", "buypass go")

    @property
    def is_google_trust_services(self) -> bool:
        return self._contains_provider("google trust services", "gts", "google")

    @property
    def is_sslcom(self) -> bool:
        return self._contains_provider("ssl.com", "sslcom")

    @property
    def renewable_ca(self) -> str | None:
        if self.is_litessl:
            return "litessl"
        if self.is_lets_encrypt:
            return "letsencrypt"
        if self.is_zerossl:
            return "zerossl"
        if self.is_buypass:
            return "buypass"
        if self.is_google_trust_services:
            return "google"
        if self.is_sslcom:
            return "sslcom"
        return None

    @property
    def is_supported_free_ca(self) -> bool:
        return self.renewable_ca is not None


@dataclass
class SiteInfo:
    panel: str
    id: int
    name: str
    path: str
    domains: list[DomainInfo] = field(default_factory=list)
    ssl: SslInfo = field(default_factory=SslInfo)


@dataclass(frozen=True)
class ProbeResult:
    domain: str
    ok: bool
    reason: str
    url: str | None = None


@dataclass
class RenewResult:
    panel: str
    site: str
    ok: bool
    message: str
    included_domains: list[str] = field(default_factory=list)
    skipped_domains: list[ProbeResult] = field(default_factory=list)


@dataclass
class SitePlan:
    panel: str
    site: str
    action: str
    message: str
    included_domains: list[str] = field(default_factory=list)
    skipped_domains: list[ProbeResult] = field(default_factory=list)


@dataclass(frozen=True)
class DomainBindingStatus:
    panel: str
    site: str
    domain: str
    certificate_bound: bool
    webroot_ok: bool | None = None
    webroot_reason: str | None = None


@dataclass(frozen=True)
class StatusSummary:
    site_count: int
    site_domain_count: int
    certificate_domain_count: int
    certificate_bound_domain_count: int
    certificate_unbound_domain_count: int
    webroot_ok_count: int = 0
    webroot_failed_count: int = 0
