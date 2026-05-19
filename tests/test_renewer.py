from baota_ssl_renewer.models import DomainInfo, SiteInfo, SslInfo
from baota_ssl_renewer.renewer import build_domain_statuses, summarize_statuses
from baota_ssl_renewer.renewer import _filter_provider_domains, should_attempt_renew


def test_should_attempt_renew_requires_lets_encrypt() -> None:
    site = SiteInfo(
        panel="p",
        id=1,
        name="example.com",
        path="/www/wwwroot/example.com",
        domains=[DomainInfo("example.com")],
        ssl=SslInfo(enabled=True, issuer="DigiCert"),
    )

    allowed, reason = should_attempt_renew(site)

    assert allowed is False
    assert reason == "not a supported free certificate provider"


def test_should_attempt_renew_allows_lets_encrypt() -> None:
    site = SiteInfo(
        panel="p",
        id=1,
        name="example.com",
        path="/www/wwwroot/example.com",
        domains=[DomainInfo("example.com")],
        ssl=SslInfo(enabled=True, issuer="Let's Encrypt"),
    )

    allowed, reason = should_attempt_renew(site)

    assert allowed is True
    assert reason == "ok"


def test_should_attempt_renew_allows_litessl() -> None:
    site = SiteInfo(
        panel="p",
        id=1,
        name="example.com",
        path="/www/wwwroot/example.com",
        domains=[DomainInfo("example.com")],
        ssl=SslInfo(enabled=True, provider="LiteSSL"),
    )

    allowed, reason = should_attempt_renew(site)

    assert allowed is True
    assert reason == "ok"


def test_litessl_skips_ip_domains() -> None:
    site = SiteInfo(
        panel="p",
        id=1,
        name="example.com",
        path="/www/wwwroot/example.com",
        ssl=SslInfo(enabled=True, provider="LiteSSL"),
    )

    allowed, skipped = _filter_provider_domains(site, ["example.com", "192.0.2.1"])

    assert allowed == ["example.com"]
    assert skipped[0].domain == "192.0.2.1"
    assert skipped[0].reason == "LiteSSL does not support IP certificates"


def test_status_summary_counts_bound_and_unbound_domains() -> None:
    sites = [
        SiteInfo(
            panel="p",
            id=1,
            name="example.com",
            path="/www/wwwroot/example.com",
            domains=[DomainInfo("example.com"), DomainInfo("www.example.com")],
            ssl=SslInfo(enabled=True, issuer="Let's Encrypt", domains=["example.com"]),
        )
    ]

    statuses = build_domain_statuses(sites)
    summary = summarize_statuses(sites, statuses)

    assert summary.site_count == 1
    assert summary.site_domain_count == 2
    assert summary.certificate_domain_count == 1
    assert summary.certificate_bound_domain_count == 1
    assert summary.certificate_unbound_domain_count == 1


def test_status_treats_wildcard_certificate_as_bound() -> None:
    sites = [
        SiteInfo(
            panel="p",
            id=1,
            name="example.com",
            path="/www/wwwroot/example.com",
            domains=[DomainInfo("www.example.com"), DomainInfo("deep.www.example.com")],
            ssl=SslInfo(enabled=True, issuer="Let's Encrypt", domains=["*.example.com"]),
        )
    ]

    statuses = build_domain_statuses(sites)

    assert statuses[0].certificate_bound is True
    assert statuses[1].certificate_bound is False
