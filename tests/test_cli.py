import argparse

from baota_ssl_renewer.cli import _filter_sites_by_domain, _parse_ca_fallbacks, _parse_domain_filter
from baota_ssl_renewer.models import DomainInfo, SiteInfo


def test_parse_domain_filter_accepts_repeated_and_comma_separated_values() -> None:
    args = argparse.Namespace(domain=["example.com,www.example.net"], domains="api.example.org")

    assert _parse_domain_filter(args) == {"example.com", "www.example.net", "api.example.org"}


def test_parse_ca_fallbacks_accepts_repeated_and_comma_separated_values() -> None:
    args = argparse.Namespace(ca_fallback=["buypass,zerossl", "google"])

    assert _parse_ca_fallbacks(args) == ["buypass", "zerossl", "google"]


def test_filter_sites_by_domain_matches_across_panels_and_subdomains() -> None:
    sites = [
        SiteInfo(
            panel="a",
            id=1,
            name="a-site",
            path="/www/a",
            domains=[DomainInfo("example.com"), DomainInfo("other.com")],
        ),
        SiteInfo(
            panel="b",
            id=2,
            name="b-site",
            path="/www/b",
            domains=[DomainInfo("www.example.com")],
        ),
    ]

    filtered = _filter_sites_by_domain(sites, {"example.com"})

    assert [(site.panel, [domain.host for domain in site.domains]) for site in filtered] == [
        ("a", ["example.com"]),
        ("b", ["www.example.com"]),
    ]
