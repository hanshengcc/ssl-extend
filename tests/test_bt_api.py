import hashlib

import respx
from httpx import Response

import pytest

from baota_ssl_renewer.bt_api import NoRenewableCertificateError, baota_token
from baota_ssl_renewer.bt_api import BaotaClient
from baota_ssl_renewer.models import PanelConfig, SiteInfo


def test_baota_token() -> None:
    timestamp = 1_700_000_000
    api_key = "secret"

    actual_time, token = baota_token(api_key, timestamp)

    key_md5 = hashlib.md5(api_key.encode("utf-8")).hexdigest()
    expected = hashlib.md5(f"{timestamp}{key_md5}".encode("utf-8")).hexdigest()
    assert actual_time == timestamp
    assert token == expected


def test_client_url_preserves_panel_path_prefix() -> None:
    client = BaotaClient(
        PanelConfig(
            name="server1",
            url="https://panel.example.com/secret-entry",
            api_key="secret",
        )
    )

    try:
        assert client._url("/data?action=getData&table=sites") == (
            "https://panel.example.com/secret-entry/data?action=getData&table=sites"
        )
    finally:
        client.close()


def test_normalize_ssl_extracts_certificate_domains() -> None:
    client = BaotaClient(PanelConfig(name="server1", url="https://panel.example.com", api_key="secret"))

    try:
        ssl = client._normalize_ssl({"cert_data": {"issuer": "Let's Encrypt", "dns": ["example.com", "www.example.com"]}})
    finally:
        client.close()

    assert ssl.domains == ["example.com", "www.example.com"]


@respx.mock
def test_renew_free_ssl_sends_litessl_ca() -> None:
    route = respx.post("https://panel.example.com/ssl?action=renew_lets_ssl").mock(
        return_value=Response(200, json={"status": True, "msg": "ok"})
    )
    client = BaotaClient(PanelConfig(name="server1", url="https://panel.example.com", api_key="secret"))

    try:
        body = client.renew_free_ssl(
            SiteInfo(panel="server1", id=7, name="example.com", path="/www/wwwroot/example.com"),
            ["example.com"],
            "litessl",
        )
    finally:
        client.close()

    assert body["status"] is True
    request_body = route.calls.last.request.content.decode()
    assert "ca=litessl" in request_body
    assert "auth_type=http" in request_body


@respx.mock
def test_renew_free_ssl_stops_when_no_renewable_certificate() -> None:
    route = respx.post("https://panel.example.com/ssl?action=renew_lets_ssl").mock(
        return_value=Response(200, json={"status": False, "msg": "当前没有可以续订的证书!"})
    )
    create_route = respx.post("https://panel.example.com/site?action=CreateLet").mock(
        return_value=Response(404)
    )
    client = BaotaClient(PanelConfig(name="server1", url="https://panel.example.com", api_key="secret"))

    try:
        with pytest.raises(NoRenewableCertificateError, match="当前没有可以续订的证书"):
            client.renew_free_ssl(
                SiteInfo(panel="server1", id=7, name="example.com", path="/www/wwwroot/example.com"),
                ["example.com"],
                "letsencrypt",
            )
    finally:
        client.close()

    assert route.called
    assert not create_route.called


@respx.mock
def test_issue_free_ssl_applies_cert_then_sets_ssl() -> None:
    apply_route = respx.post("https://panel.example.com/acme?action=apply_cert_api").mock(
        return_value=Response(200, json={"status": True, "cert": "CERT", "key": "KEY"})
    )
    setssl_route = respx.post("https://panel.example.com/site?action=SetSSL").mock(
        return_value=Response(200, json={"status": True, "msg": "saved"})
    )
    client = BaotaClient(PanelConfig(name="server1", url="https://panel.example.com", api_key="secret"))

    try:
        body = client.issue_free_ssl(
            SiteInfo(panel="server1", id=7, name="example.com", path="/www/wwwroot/example.com"),
            ["example.com", "www.example.com"],
            "letsencrypt",
        )
    finally:
        client.close()

    assert body["msg"] == "certificate issued and installed"
    apply_body = apply_route.calls.last.request.content.decode()
    assert "domains=%5B%22example.com%22%2C%22www.example.com%22%5D" in apply_body
    assert "auth_type=http" in apply_body
    assert "auto_to=7" in apply_body
    assert "auto_wildcard=0" in apply_body
    assert "id=7" in apply_body
    setssl_body = setssl_route.calls.last.request.content.decode()
    assert "siteName=example.com" in setssl_body
    assert "key=KEY" in setssl_body
    assert "csr=CERT" in setssl_body


@respx.mock
def test_set_force_https_enable_and_disable() -> None:
    enable_route = respx.post("https://panel.example.com/site?action=HttpToHttps").mock(
        return_value=Response(200, json={"status": True, "msg": "enabled"})
    )
    disable_route = respx.post("https://panel.example.com/site?action=CloseToHttps").mock(
        return_value=Response(200, json={"status": True, "msg": "disabled"})
    )
    client = BaotaClient(PanelConfig(name="server1", url="https://panel.example.com", api_key="secret"))
    site = SiteInfo(panel="server1", id=7, name="example.com", path="/www/wwwroot/example.com")

    try:
        assert client.set_force_https(site, True)["msg"] == "enabled"
        assert client.set_force_https(site, False)["msg"] == "disabled"
    finally:
        client.close()

    assert "siteName=example.com" in enable_route.calls.last.request.content.decode()
    assert "siteName=example.com" in disable_route.calls.last.request.content.decode()
