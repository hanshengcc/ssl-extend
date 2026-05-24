from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Callable

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

ACME_DIRECTORY_URLS: dict[str, str] = {
    "letsencrypt": "https://acme-v02.api.letsencrypt.org/directory",
    "letsencrypt-staging": "https://acme-staging-v02.api.letsencrypt.org/directory",
    "litessl": "https://acme-v02.api.letsencrypt.org/directory",
    "buypass": "https://api.buypass.com/acme/directory",
    "buypass-staging": "https://api.test4.buypass.no/acme/directory",
    "zerossl": "https://acme.zerossl.com/v2/DV90",
    "google": "https://dv.acme-v02.api.pki.goog/directory",
    "sslcom": "https://acme.ssl.com/sslcom-dv-rsa",
}

ACME_PROVIDERS_REQUIRING_EAB: set[str] = {"zerossl", "google", "sslcom"}


class AcmeError(RuntimeError):
    pass


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def _jwk(key: ec.EllipticCurvePrivateKey) -> dict:
    pub = key.public_key()
    nums = pub.public_numbers()
    size = (pub.key_size + 7) // 8
    return {
        "crv": "P-256",
        "kty": "EC",
        "x": _b64url(nums.x.to_bytes(size, "big")),
        "y": _b64url(nums.y.to_bytes(size, "big")),
    }


def _thumbprint(key: ec.EllipticCurvePrivateKey) -> str:
    canonical = json.dumps(_jwk(key), separators=(",", ":"), sort_keys=True)
    return _b64url(hashlib.sha256(canonical.encode()).digest())


def _jws(key: ec.EllipticCurvePrivateKey, header: dict, payload: dict | None) -> dict:
    protected = _b64url(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = "" if payload is None else _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{protected}.{payload_b64}".encode()
    der_sig = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    size = (key.public_key().key_size + 7) // 8
    raw_sig = r.to_bytes(size, "big") + s.to_bytes(size, "big")
    return {"protected": protected, "payload": payload_b64, "signature": _b64url(raw_sig)}


def _build_csr(domains: list[str], key: ec.EllipticCurvePrivateKey) -> bytes:
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domains[0])]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(d) for d in domains]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.DER)


class AcmeClient:
    def __init__(
        self,
        directory_url: str,
        timeout: float = 30.0,
        eab_kid: str | None = None,
        eab_hmac_key: str | None = None,
    ):
        self.directory_url = directory_url
        self.eab_kid = eab_kid
        self.eab_hmac_key = eab_hmac_key
        self._http = httpx.Client(timeout=timeout, follow_redirects=True)
        self._directory: dict | None = None
        self._nonce: str | None = None
        self._kid: str | None = None
        self._account_key = ec.generate_private_key(ec.SECP256R1())

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "AcmeClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _get_directory(self) -> dict:
        if self._directory is None:
            resp = self._http.get(self.directory_url)
            resp.raise_for_status()
            self._directory = resp.json()
        return self._directory

    def _get_nonce(self) -> str:
        if self._nonce:
            nonce, self._nonce = self._nonce, None
            return nonce
        directory = self._get_directory()
        resp = self._http.head(directory["newNonce"])
        resp.raise_for_status()
        return resp.headers["Replay-Nonce"]

    def _post(self, url: str, payload: dict | None, use_jwk: bool = False) -> httpx.Response:
        nonce = self._get_nonce()
        header: dict = {"alg": "ES256", "nonce": nonce, "url": url}
        if use_jwk:
            header["jwk"] = _jwk(self._account_key)
        else:
            header["kid"] = self._kid
        body = _jws(self._account_key, header, payload)
        resp = self._http.post(url, json=body, headers={"Content-Type": "application/jose+json"})
        if replay_nonce := resp.headers.get("Replay-Nonce"):
            self._nonce = replay_nonce
        return resp

    def _post_ok(self, url: str, payload: dict | None, use_jwk: bool = False) -> dict:
        resp = self._post(url, payload, use_jwk=use_jwk)
        try:
            data = resp.json()
        except Exception:
            data = {}
        if not resp.is_success:
            detail = data.get("detail") or data.get("type") or f"HTTP {resp.status_code}"
            raise AcmeError(f"ACME {resp.status_code}: {detail}")
        return data

    def _external_account_binding(self, new_account_url: str) -> dict:
        if not self.eab_kid or not self.eab_hmac_key:
            raise AcmeError("External Account Binding is required but acme_eab_kid/acme_eab_hmac_key is missing")
        protected = _b64url(
            json.dumps(
                {"alg": "HS256", "kid": self.eab_kid, "url": new_account_url},
                separators=(",", ":"),
            ).encode()
        )
        payload = _b64url(json.dumps(_jwk(self._account_key), separators=(",", ":")).encode())
        try:
            hmac_key = _b64url_decode(self.eab_hmac_key)
        except Exception:
            hmac_key = self.eab_hmac_key.encode()
        signature = hmac.new(hmac_key, f"{protected}.{payload}".encode(), hashlib.sha256).digest()
        return {"protected": protected, "payload": payload, "signature": _b64url(signature)}

    def _register(self) -> None:
        directory = self._get_directory()
        payload = {"termsOfServiceAgreed": True}
        if self.eab_kid or self.eab_hmac_key:
            payload["externalAccountBinding"] = self._external_account_binding(directory["newAccount"])
        resp = self._post(directory["newAccount"], payload, use_jwk=True)
        if replay_nonce := resp.headers.get("Replay-Nonce"):
            self._nonce = replay_nonce
        if resp.status_code not in (200, 201):
            try:
                detail = resp.json().get("detail") or f"HTTP {resp.status_code}"
            except Exception:
                detail = f"HTTP {resp.status_code}"
            raise AcmeError(f"Account registration failed: {detail}")
        self._kid = resp.headers.get("Location") or ""

    def _poll(self, url: str, target_status: str, timeout: float, interval: float) -> dict:
        deadline = time.monotonic() + timeout
        while True:
            resp = self._http.get(url)
            resp.raise_for_status()
            data = resp.json()
            status = data.get("status", "")
            if status == target_status:
                return data
            if status in ("invalid", "revoked", "expired"):
                challenges = data.get("challenges", [])
                errors = [ch.get("error", {}).get("detail", "") for ch in challenges if ch.get("error")]
                detail = "; ".join(e for e in errors if e) or status
                raise AcmeError(f"ACME status {status}: {detail}")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AcmeError(f"Timed out waiting for {target_status} (current: {status})")
            time.sleep(min(interval, remaining))

    def issue_certificate(
        self,
        domains: list[str],
        place_challenge: Callable[[str, str, str], None],
        remove_challenge: Callable[[str, str], None],
    ) -> tuple[str, str]:
        """Issue a certificate for `domains` using HTTP-01 challenges.

        `place_challenge(domain, token, key_auth)` must write `key_auth` to
        `/.well-known/acme-challenge/<token>` on the webroot for that domain.

        `remove_challenge(domain, token)` must delete that file (called in finally).

        Returns (cert_pem, key_pem).
        """
        self._register()
        directory = self._get_directory()

        resp = self._post(
            directory["newOrder"],
            {"identifiers": [{"type": "dns", "value": d} for d in domains]},
        )
        if replay_nonce := resp.headers.get("Replay-Nonce"):
            self._nonce = replay_nonce
        if resp.status_code not in (200, 201):
            try:
                detail = resp.json().get("detail") or f"HTTP {resp.status_code}"
            except Exception:
                detail = f"HTTP {resp.status_code}"
            raise AcmeError(f"New order failed: {detail}")
        order_url = resp.headers.get("Location") or ""
        order = resp.json()

        placed: list[tuple[str, str]] = []
        try:
            for authz_url in order.get("authorizations", []):
                authz_resp = self._http.get(authz_url)
                authz_resp.raise_for_status()
                authz = authz_resp.json()
                domain = authz["identifier"]["value"]
                if authz.get("status") == "valid":
                    continue
                challenge = next(
                    (ch for ch in authz.get("challenges", []) if ch["type"] == "http-01"),
                    None,
                )
                if challenge is None:
                    raise AcmeError(f"No http-01 challenge available for {domain}")
                token = challenge["token"]
                key_auth = f"{token}.{_thumbprint(self._account_key)}"
                place_challenge(domain, token, key_auth)
                placed.append((domain, token))
                self._post_ok(challenge["url"], {})
                self._poll(authz_url, "valid", timeout=90.0, interval=2.0)
        finally:
            for domain, token in placed:
                try:
                    remove_challenge(domain, token)
                except Exception:
                    pass

        cert_key = ec.generate_private_key(ec.SECP256R1())
        csr_der = _build_csr(domains, cert_key)
        order_data = self._post_ok(order["finalize"], {"csr": _b64url(csr_der)})

        cert_url = order_data.get("certificate")
        if not cert_url:
            final = self._poll(order_url, "valid", timeout=120.0, interval=3.0)
            cert_url = final.get("certificate")
        if not cert_url:
            raise AcmeError("Order completed but no certificate URL in response")

        cert_resp = self._http.get(cert_url, headers={"Accept": "application/pem-certificate-chain"})
        cert_resp.raise_for_status()
        cert_pem = cert_resp.text

        key_pem = cert_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ).decode()

        return cert_pem, key_pem
