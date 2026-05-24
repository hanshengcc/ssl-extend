from pathlib import Path

from baota_ssl_renewer.config import load_config


def test_load_multiple_panels(tmp_path: Path) -> None:
    config = tmp_path / "baota.ini"
    config.write_text(
        """
[panel.a]
url = https://a.example.com:8888/
api_key = key-a
verify_ssl = false

[panel.b]
url = https://b.example.com:8888
api_key = key-b
timeout = 3
default_ca = buypass
ca_fallbacks = letsencrypt, zerossl
acme_directory_url = https://acme.example.com/directory
acme_eab_kid = kid
acme_eab_hmac_key = hmac-key
""".strip(),
        encoding="utf-8",
    )

    panels = load_config(config)

    assert [panel.name for panel in panels] == ["a", "b"]
    assert panels[0].url == "https://a.example.com:8888"
    assert panels[0].verify_ssl is False
    assert panels[1].timeout == 3
    assert panels[1].default_ca == "buypass"
    assert panels[1].ca_fallbacks == ("letsencrypt", "zerossl")
    assert panels[1].acme_directory_url == "https://acme.example.com/directory"
    assert panels[1].acme_eab_kid == "kid"
    assert panels[1].acme_eab_hmac_key == "hmac-key"
