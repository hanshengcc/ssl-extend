from baota_ssl_renewer.models import DomainInfo, SiteInfo, SslInfo
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
