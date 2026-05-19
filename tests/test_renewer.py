from baota_ssl_renewer.models import DomainInfo, ProbeResult, SiteInfo, SslInfo
from baota_ssl_renewer.renewer import build_domain_statuses, summarize_statuses
from baota_ssl_renewer.renewer import _filter_provider_domains, apply_sites_sequential, renew_site, should_attempt_renew
from baota_ssl_renewer.models import PanelConfig
from baota_ssl_renewer.bt_api import BaotaApiError, NoRenewableCertificateError


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


def test_should_attempt_renew_allows_sites_without_ssl() -> None:
    site = SiteInfo(
        panel="p",
        id=1,
        name="example.com",
        path="/www/wwwroot/example.com",
        domains=[DomainInfo("example.com")],
        ssl=SslInfo(enabled=False),
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


def test_renew_site_dry_run_uses_preflight_probe_results() -> None:
    site = SiteInfo(
        panel="p",
        id=1,
        name="example.com",
        path="/www/wwwroot/example.com",
        domains=[DomainInfo("example.com")],
        ssl=SslInfo(enabled=True, issuer="Let's Encrypt"),
    )

    result = renew_site(
        PanelConfig(name="p", url="https://panel.example.com", api_key="secret"),
        site,
        dry_run=True,
        probes=[ProbeResult(domain="example.com", ok=True, reason="ok")],
    )

    assert result.ok is True
    assert result.included_domains == ["example.com"]
    assert result.message == "dry-run: would issue certificate"


def test_renew_site_issues_new_certificate_when_no_renewable(monkeypatch) -> None:
    class FakeClient:
        def __init__(self, _config):
            self.issued_domains = None

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def renew_free_ssl(self, _site, _domains, _ca):
            raise NoRenewableCertificateError("server1: 当前没有可以续订的证书!")

        def issue_free_ssl(self, _site, domains, _ca):
            self.issued_domains = domains
            return {"status": True, "msg": "issued"}

    monkeypatch.setattr("baota_ssl_renewer.renewer.BaotaClient", FakeClient)
    site = SiteInfo(
        panel="p",
        id=1,
        name="example.com",
        path="/www/wwwroot/example.com",
        domains=[DomainInfo("example.com"), DomainInfo("bad.example.com")],
        ssl=SslInfo(enabled=True, issuer="Let's Encrypt"),
    )

    result = renew_site(
        PanelConfig(name="p", url="https://panel.example.com", api_key="secret"),
        site,
        probes=[
            ProbeResult(domain="example.com", ok=True, reason="ok"),
            ProbeResult(domain="bad.example.com", ok=False, reason="HTTP 404"),
        ],
    )

    assert result.ok is True
    assert result.message == "issued"
    assert result.included_domains == ["example.com"]
    assert result.skipped_domains[0].domain == "bad.example.com"


def test_renew_site_issues_new_certificate_when_valid_domain_is_unbound(monkeypatch) -> None:
    class FakeClient:
        renewed = False

        def __init__(self, _config):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def renew_free_ssl(self, _site, _domains, _ca):
            self.renewed = True
            return {"status": True, "msg": "renewed"}

        def issue_free_ssl(self, _site, domains, _ca):
            return {"status": True, "msg": f"issued:{','.join(domains)}"}

    monkeypatch.setattr("baota_ssl_renewer.renewer.BaotaClient", FakeClient)
    site = SiteInfo(
        panel="p",
        id=1,
        name="example.com",
        path="/www/wwwroot/example.com",
        domains=[DomainInfo("example.com"), DomainInfo("www.example.com")],
        ssl=SslInfo(enabled=True, issuer="Let's Encrypt", domains=["example.com"]),
    )

    result = renew_site(
        PanelConfig(name="p", url="https://panel.example.com", api_key="secret"),
        site,
        probes=[
            ProbeResult(domain="example.com", ok=True, reason="ok"),
            ProbeResult(domain="www.example.com", ok=True, reason="ok"),
        ],
    )

    assert result.ok is True
    assert result.message == "issued:example.com,www.example.com"
    assert result.included_domains == ["example.com", "www.example.com"]


def test_apply_sites_sequential_continues_after_site_failure(monkeypatch) -> None:
    class FakeProber:
        def __init__(self, _client):
            pass

        def probe_site(self, site, domain_filter=None):
            return [ProbeResult(domain=domain.host, ok=True, reason="ok") for domain in site.domains]

    class FakeClient:
        def __init__(self, _config):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def renew_free_ssl(self, site, _domains, _ca):
            if site.name == "bad.example.com":
                raise NoRenewableCertificateError("no renewable")
            return {"status": True, "msg": f"renewed:{site.name}"}

        def issue_free_ssl(self, site, domains, _ca):
            if site.name == "bad.example.com":
                raise Exception("boom")
            return {"status": True, "msg": f"issued:{site.name}:{','.join(domains)}"}

    monkeypatch.setattr("baota_ssl_renewer.renewer.BaotaClient", FakeClient)
    monkeypatch.setattr("baota_ssl_renewer.renewer.WebrootProber", FakeProber)
    sites = [
        SiteInfo(
            panel="p",
            id=1,
            name="bad.example.com",
            path="/www/wwwroot/bad.example.com",
            domains=[DomainInfo("bad.example.com")],
            ssl=SslInfo(enabled=True, issuer="Let's Encrypt", domains=["bad.example.com"]),
        ),
        SiteInfo(
            panel="p",
            id=2,
            name="ok.example.com",
            path="/www/wwwroot/ok.example.com",
            domains=[DomainInfo("ok.example.com")],
            ssl=SslInfo(enabled=True, issuer="Let's Encrypt", domains=["ok.example.com"]),
        ),
    ]

    results = apply_sites_sequential(
        [PanelConfig(name="p", url="https://panel.example.com", api_key="secret")],
        sites,
        dry_run=False,
    )

    assert len(results) == 2
    assert results[0].ok is False
    assert results[1].ok is True
    assert results[1].message == "renewed:ok.example.com"


def test_apply_sites_sequential_stops_after_fatal_program_error(monkeypatch) -> None:
    class FakeProber:
        def __init__(self, _client):
            pass

        def probe_site(self, site, domain_filter=None):
            return [ProbeResult(domain=domain.host, ok=True, reason="ok") for domain in site.domains]

    class FakeClient:
        def __init__(self, _config):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def renew_free_ssl(self, _site, _domains, _ca):
            raise NoRenewableCertificateError("no renewable")

        def issue_free_ssl(self, _site, _domains, _ca):
            raise BaotaApiError("server1: 指定参数无效")

    monkeypatch.setattr("baota_ssl_renewer.renewer.BaotaClient", FakeClient)
    monkeypatch.setattr("baota_ssl_renewer.renewer.WebrootProber", FakeProber)
    sites = [
        SiteInfo(
            panel="p",
            id=1,
            name="bad.example.com",
            path="/www/wwwroot/bad.example.com",
            domains=[DomainInfo("bad.example.com")],
            ssl=SslInfo(enabled=True, issuer="Let's Encrypt", domains=["bad.example.com"]),
        ),
        SiteInfo(
            panel="p",
            id=2,
            name="never-run.example.com",
            path="/www/wwwroot/never-run.example.com",
            domains=[DomainInfo("never-run.example.com")],
            ssl=SslInfo(enabled=True, issuer="Let's Encrypt", domains=["never-run.example.com"]),
        ),
    ]

    results = apply_sites_sequential(
        [PanelConfig(name="p", url="https://panel.example.com", api_key="secret")],
        sites,
        dry_run=False,
    )

    assert len(results) == 1
    assert results[0].ok is False
    assert "fatal program/API error" in results[0].message
    assert "指定参数无效" in results[0].message
