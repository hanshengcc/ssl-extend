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
    raw: dict = field(default_factory=dict)

    @property
    def is_lets_encrypt(self) -> bool:
        values = " ".join(
            str(v).lower()
            for v in (self.provider, self.issuer, self.raw.get("issuer"), self.raw.get("brand"))
            if v
        )
        return "let's encrypt" in values or "lets encrypt" in values or "letsencrypt" in values


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
