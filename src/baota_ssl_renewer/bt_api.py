from __future__ import annotations

import hashlib
import time
from datetime import datetime
from typing import Any
from urllib.parse import urljoin

import httpx

from .models import DomainInfo, PanelConfig, SiteInfo, SslInfo


class BaotaApiError(RuntimeError):
    pass


def baota_token(api_key: str, request_time: int | None = None) -> tuple[int, str]:
    timestamp = request_time if request_time is not None else int(time.time())
    key_md5 = hashlib.md5(api_key.encode("utf-8")).hexdigest()
    token = hashlib.md5(f"{timestamp}{key_md5}".encode("utf-8")).hexdigest()
    return timestamp, token


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _parse_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y/%m/%d %H:%M:%S", "%Y/%m/%d"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def _normalize_domain(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text.startswith("dns:"):
        text = text[4:].strip()
    return text


def _split_domain_text(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, list):
        return [_normalize_domain(item) for item in value if _normalize_domain(item)]
    text = str(value)
    for separator in ("\n", ";", "|"):
        text = text.replace(separator, ",")
    return [_normalize_domain(part) for part in text.split(",") if _normalize_domain(part)]


def _extract_ssl_domains(data: dict[str, Any], cert: dict[str, Any]) -> list[str]:
    domains: list[str] = []
    keys = (
        "dns",
        "domains",
        "domain",
        "sans",
        "san",
        "subjectAltName",
        "subject_alt_name",
        "notAfter_dns",
    )
    for source in (cert, data):
        for key in keys:
            domains.extend(_split_domain_text(source.get(key)))
    return sorted(set(domains))


def _looks_existing_file_error(message: str) -> bool:
    lower = message.lower()
    return any(marker in lower for marker in ("exist", "already", "已存在", "存在"))


class BaotaClient:
    def __init__(self, config: PanelConfig):
        self.config = config
        self._client = httpx.Client(
            verify=config.verify_ssl,
            timeout=config.timeout,
            follow_redirects=True,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "BaotaClient":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def post(self, path: str, data: dict[str, Any] | None = None, *, raise_api_error: bool = True) -> Any:
        timestamp, token = baota_token(self.config.api_key)
        payload = {
            "request_time": timestamp,
            "request_token": token,
        }
        if data:
            payload.update(data)

        try:
            response = self._client.post(self._url(path), data=payload)
        except httpx.RemoteProtocolError as exc:
            raise BaotaApiError(
                f"{self.config.name}: illegal request line. Check whether panel url uses the correct "
                "scheme (http vs https), port, and any required panel entrance path."
            ) from exc
        except httpx.RequestError as exc:
            raise BaotaApiError(f"{self.config.name}: {exc}") from exc
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise BaotaApiError(f"{self.config.name}: HTTP {response.status_code} for {path}") from exc

        try:
            body = response.json()
        except ValueError as exc:
            raise BaotaApiError(f"{self.config.name}: non-JSON response from {path}") from exc

        if raise_api_error and isinstance(body, dict) and body.get("status") is False:
            msg = body.get("msg") or body.get("message") or "request failed"
            raise BaotaApiError(f"{self.config.name}: {msg}")
        return body

    def _url(self, path: str) -> str:
        base = self.config.url.rstrip("/") + "/"
        return urljoin(base, path.lstrip("/"))

    def list_sites(self) -> list[SiteInfo]:
        body = self.post(
            "/data?action=getData&table=sites",
            {"p": 1, "limit": 10000, "type": -1, "order": "id desc"},
        )
        rows = body.get("data", []) if isinstance(body, dict) else []
        sites: list[SiteInfo] = []
        for row in rows:
            site_id = _as_int(row.get("id"))
            name = str(row.get("name") or row.get("ps") or "").strip()
            if not site_id or not name:
                continue
            sites.append(
                SiteInfo(
                    panel=self.config.name,
                    id=site_id,
                    name=name,
                    path=str(row.get("path") or "").strip(),
                )
            )
        return sites

    def list_domains(self, site_id: int) -> list[DomainInfo]:
        body = self.post("/data?action=getData&table=domain", {"search": site_id, "list": "true"})
        rows = body if isinstance(body, list) else body.get("data", []) if isinstance(body, dict) else []
        domains: list[DomainInfo] = []
        for row in rows:
            name = str(row.get("name") or "").strip()
            if not name:
                continue
            domains.append(DomainInfo(name=name, port=_as_int(row.get("port"), 80)))
        return domains

    def get_ssl(self, site: SiteInfo) -> SslInfo:
        candidates = [
            ("/site?action=GetSSL", {"siteName": site.name, "id": site.id}),
            ("/ssl?action=GetSSLInfo", {"siteName": site.name, "id": site.id}),
        ]
        last_error: Exception | None = None
        for path, payload in candidates:
            try:
                body = self.post(path, payload)
                return self._normalize_ssl(body)
            except Exception as exc:  # noqa: BLE001 - endpoint compatibility probing.
                last_error = exc
        return SslInfo(enabled=False, raw={"error": str(last_error) if last_error else "unavailable"})

    def _normalize_ssl(self, body: Any) -> SslInfo:
        data = body.get("data", body) if isinstance(body, dict) else {}
        if not isinstance(data, dict):
            return SslInfo(enabled=False, raw={"response": body})

        cert = data.get("cert_data") if isinstance(data.get("cert_data"), dict) else data
        issuer = cert.get("issuer") or cert.get("issuer_name") or cert.get("subject")
        provider = cert.get("brand") or cert.get("type") or cert.get("auth_type")
        not_after = (
            cert.get("notAfter")
            or cert.get("not_after")
            or cert.get("endtime")
            or cert.get("end_time")
            or cert.get("due_time")
        )
        enabled = bool(data.get("status", True)) and bool(data)
        return SslInfo(
            enabled=enabled,
            provider=str(provider) if provider else None,
            issuer=str(issuer) if issuer else None,
            not_after=_parse_datetime(not_after),
            domains=_extract_ssl_domains(data, cert),
            raw=data,
        )

    def load_sites(self) -> list[SiteInfo]:
        sites = self.list_sites()
        for site in sites:
            site.domains = self.list_domains(site.id)
            site.ssl = self.get_ssl(site)
        return sites

    def save_file(self, path: str, body: str) -> None:
        self.post("/files?action=SaveFileBody", {"path": path, "data": body, "encoding": "utf-8"})

    def create_file(self, path: str) -> None:
        body = self.post("/files?action=CreateFile", {"path": path}, raise_api_error=False)
        if isinstance(body, dict) and body.get("status") is False:
            msg = str(body.get("msg") or body.get("message") or "")
            if not _looks_existing_file_error(msg):
                raise BaotaApiError(f"{self.config.name}: {msg or 'create file failed'}")

    def create_dir(self, path: str) -> None:
        body = self.post("/files?action=CreateDir", {"path": path}, raise_api_error=False)
        if isinstance(body, dict) and body.get("status") is False:
            msg = str(body.get("msg") or body.get("message") or "")
            if not _looks_existing_file_error(msg):
                raise BaotaApiError(f"{self.config.name}: {msg or 'create directory failed'}")

    def delete_file(self, path: str) -> None:
        self.post("/files?action=DeleteFile", {"path": path})

    def renew_free_ssl(self, site: SiteInfo, domains: list[str], ca: str) -> dict[str, Any]:
        joined_domains = ",".join(domains)
        ca_payload = {"ca": ca, "auth_type": "http"}
        attempts = [
            (
                "/ssl?action=renew_lets_ssl",
                {"siteName": site.name, "domains": joined_domains, "id": site.id, **ca_payload},
            ),
            (
                "/ssl?action=renew_lets_ssl",
                {"siteName": site.name, "domain": joined_domains, "id": site.id, **ca_payload},
            ),
            (
                "/site?action=CreateLet",
                {"siteName": site.name, "domains": joined_domains, "id": site.id, **ca_payload},
            ),
            (
                "/site?action=CreateLet",
                {"siteName": site.name, "domain": joined_domains, "id": site.id, **ca_payload},
            ),
        ]
        errors: list[str] = []
        for path, payload in attempts:
            try:
                body = self.post(path, payload)
            except Exception as exc:  # noqa: BLE001 - try known endpoint variants.
                errors.append(str(exc))
                continue
            if isinstance(body, dict) and body.get("status") is False:
                errors.append(str(body.get("msg") or body))
                continue
            return body if isinstance(body, dict) else {"response": body}
        raise BaotaApiError("; ".join(errors) or "renew endpoint unavailable")

    def renew_lets_ssl(self, site: SiteInfo, domains: list[str]) -> dict[str, Any]:
        return self.renew_free_ssl(site, domains, "letsencrypt")
