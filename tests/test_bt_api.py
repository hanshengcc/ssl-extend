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
def test_issue_free_ssl_uses_createlet_endpoint() -> None:
    route = respx.post("https://panel.example.com/ssl?action=CreateLet").mock(
        return_value=Response(200, json={"status": True, "msg": "issued"})
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

    assert body["msg"] == "issued"
    request_body = route.calls.last.request.content.decode()
    assert "siteName=example.com" in request_body
    assert "domains=example.com%2Cwww.example.com" in request_body
    assert "auth_type=http" in request_body
