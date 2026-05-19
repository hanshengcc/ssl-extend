from baota_ssl_renewer.models import DomainInfo, SiteInfo, SslInfo
from baota_ssl_renewer.renewer import should_attempt_renew


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
    assert reason == "not a Let's Encrypt certificate"


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
