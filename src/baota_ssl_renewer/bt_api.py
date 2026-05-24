from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime
from pathlib import PurePosixPath
from typing import Any, Iterator
from urllib.parse import urljoin

import httpx

from .acme_client import ACME_DIRECTORY_URLS, ACME_PROVIDERS_REQUIRING_EAB, AcmeClient, AcmeError
from .models import DomainInfo, PanelConfig, SiteInfo, SslInfo


class BaotaApiError(RuntimeError):
    pass


class NoRenewableCertificateError(BaotaApiError):
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


def _looks_no_renewable_certificate_error(message: str) -> bool:
    lower = message.lower()
    return any(
        marker in lower
        for marker in (
            "没有可以续订",
            "没有可续订",
            "no renewable",
            "nothing to renew",
            "not renewable",
        )
    )


def _find_first_value(data: Any, keys: set[str]) -> str | None:
    if isinstance(data, dict):
        for key, value in data.items():
            if key.lower() in keys and value:
                return str(value)
        for value in data.values():
            found = _find_first_value(value, keys)
            if found:
                return found
    elif isinstance(data, list):
        for item in data:
            found = _find_first_value(item, keys)
            if found:
                return found
    return None


def _extract_cert_pair(body: Any) -> tuple[str, str]:
    key = _find_first_value(body, {"key", "private_key", "privkey", "ssl_key"})
    cert = _find_first_value(body, {"cert", "certificate", "fullchain", "full_chain", "pem", "csr"})
    if not key or not cert:
        raise BaotaApiError("ACME response did not include certificate and private key")
    return cert, key


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
            raise BaotaApiError(f"{self.config.name}: HTTP {response.status_code} for {response.url}") from exc

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
        try:
            body = self.post("/site?action=GetSSL", {"siteName": site.name, "id": site.id})
            return self._normalize_ssl(body)
        except Exception as exc:  # noqa: BLE001
            return SslInfo(enabled=False, raw={"error": str(exc)})

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
        return list(self.iter_sites())

    def iter_sites(self) -> Iterator[SiteInfo]:
        for site in self.list_sites():
            site.domains = self.list_domains(site.id)
            site.ssl = self.get_ssl(site)
            yield site

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
        try:
            body = self.post(
                "/ssl?action=renew_lets_ssl",
                {"siteName": site.name, "domains": ",".join(domains), "id": site.id, "ca": ca, "auth_type": "http"},
            )
        except BaotaApiError as exc:
            if _looks_no_renewable_certificate_error(str(exc)):
                raise NoRenewableCertificateError(str(exc)) from exc
            raise
        return body if isinstance(body, dict) else {"response": body}

    def issue_free_ssl(self, site: SiteInfo, domains: list[str], ca: str) -> dict[str, Any]:
        body = self.apply_cert(site, domains, ca)
        cert, key = _extract_cert_pair(body)
        setssl_body = self.set_ssl(site, cert=cert, key=key)
        return {"status": True, "msg": "certificate issued and installed", "apply": body, "set_ssl": setssl_body}

    def apply_cert(self, site: SiteInfo, domains: list[str], ca: str) -> dict[str, Any]:
        if not site.path:
            raise BaotaApiError(f"{self.config.name}: site {site.name!r} has no webroot path configured")

        ca_name = ca.lower()
        directory_url = self.config.acme_directory_url or ACME_DIRECTORY_URLS.get(ca_name)
        if not directory_url:
            supported = ", ".join(sorted(ACME_DIRECTORY_URLS))
            raise BaotaApiError(f"{self.config.name}: unsupported ACME CA {ca!r}. Supported: {supported}")
        if ca_name in ACME_PROVIDERS_REQUIRING_EAB and (
            not self.config.acme_eab_kid or not self.config.acme_eab_hmac_key
        ):
            raise BaotaApiError(
                f"{self.config.name}: {ca_name} requires acme_eab_kid and acme_eab_hmac_key in baota.ini"
            )
        site_path = site.path

        def _challenge_file(token: str) -> str:
            return str(PurePosixPath(site_path) / ".well-known" / "acme-challenge" / token)

        def place_challenge(_domain: str, token: str, key_auth: str) -> None:
            well_known = str(PurePosixPath(site_path) / ".well-known")
            challenge_dir = str(PurePosixPath(well_known) / "acme-challenge")
            self.create_dir(well_known)
            self.create_dir(challenge_dir)
            self.create_file(_challenge_file(token))
            self.save_file(_challenge_file(token), key_auth)

        def remove_challenge(_domain: str, token: str) -> None:
            self.delete_file(_challenge_file(token))

        try:
            with AcmeClient(
                directory_url,
                eab_kid=self.config.acme_eab_kid,
                eab_hmac_key=self.config.acme_eab_hmac_key,
            ) as acme:
                cert_pem, key_pem = acme.issue_certificate(domains, place_challenge, remove_challenge)
        except AcmeError as exc:
            raise BaotaApiError(f"{self.config.name}: ACME certificate issuance failed: {exc}") from exc

        return {"cert": cert_pem, "key": key_pem}

    def set_ssl(self, site: SiteInfo, cert: str, key: str) -> dict[str, Any]:
        body = self.post(
            "/site?action=SetSSL",
            {"type": -1, "siteName": site.name, "key": key, "csr": cert},
        )
        return body if isinstance(body, dict) else {"response": body}

    def set_force_https(self, site: SiteInfo, enabled: bool) -> dict[str, Any]:
        action = "HttpToHttps" if enabled else "CloseToHttps"
        body = self.post(f"/site?action={action}", {"siteName": site.name, "id": site.id})
        return body if isinstance(body, dict) else {"response": body}

    def renew_lets_ssl(self, site: SiteInfo, domains: list[str]) -> dict[str, Any]:
        return self.renew_free_ssl(site, domains, "letsencrypt")
