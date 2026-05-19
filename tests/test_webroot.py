import respx
from httpx import Response

from baota_ssl_renewer.models import DomainInfo, SiteInfo
from baota_ssl_renewer.webroot import WebrootProber


class FakeClient:
    def __init__(self) -> None:
        self.saved: dict[str, str] = {}

    def create_dir(self, path: str) -> None:
        pass

    def create_file(self, path: str) -> None:
        self.saved[path] = ""

    def save_file(self, path: str, body: str) -> None:
        self.saved[path] = body

    def delete_file(self, path: str) -> None:
        self.saved.pop(path, None)


@respx.mock
def test_probe_follows_https_redirect_without_validating_certificate() -> None:
    site = SiteInfo(
        panel="p",
        id=1,
        name="example.com",
        path="/www/wwwroot/example.com",
        domains=[DomainInfo("example.com")],
    )
    client = FakeClient()
    prober = WebrootProber(client)  # type: ignore[arg-type]

    def challenge_response(request):
        token = request.url.path.rsplit("/", 1)[-1]
        return Response(200, text=f"{token}.ok")

    def redirect_response(request):
        return Response(301, headers={"Location": str(request.url).replace("http://", "https://", 1)})

    respx.get(url__regex=r"http://example\.com/\.well-known/acme-challenge/.+").mock(
        side_effect=redirect_response
    )
    respx.get(url__regex=r"https://example\.com/\.well-known/acme-challenge/.+").mock(
        side_effect=challenge_response
    )

    result = prober.probe_domain(site, DomainInfo("example.com"))

    assert result.ok is True
