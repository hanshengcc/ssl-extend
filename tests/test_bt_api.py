import hashlib

from baota_ssl_renewer.bt_api import baota_token


def test_baota_token() -> None:
    timestamp = 1_700_000_000
    api_key = "secret"

    actual_time, token = baota_token(api_key, timestamp)

    key_md5 = hashlib.md5(api_key.encode("utf-8")).hexdigest()
    expected = hashlib.md5(f"{timestamp}{key_md5}".encode("utf-8")).hexdigest()
    assert actual_time == timestamp
    assert token == expected
