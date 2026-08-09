import pytest

from tokbuff_sso.peers import PeerConfig, parse_peers

KEY = "k" * 16


def test_parse_valid_list():
    peers = parse_peers(
        f'[{{"name": "forum", "base_url": "https://forum.tokbuff.com", "api_key": "{KEY}"}}]'
    )
    assert peers[0].name == "forum"
    assert peers[0].base_url == "https://forum.tokbuff.com"


def test_parse_rejects_duplicate_names():
    raw = (
        f'[{{"name": "a", "base_url": "https://a.com", "api_key": "{KEY}"}},'
        f'{{"name": "a", "base_url": "https://b.com", "api_key": "{KEY}"}}]'
    )
    with pytest.raises(ValueError):
        parse_peers(raw)


def test_parse_rejects_non_http_url():
    with pytest.raises(ValueError):
        parse_peers(f'[{{"name": "a", "base_url": "file:///etc/passwd", "api_key": "{KEY}"}}]')


def test_parse_rejects_empty_api_key():
    with pytest.raises(ValueError):
        parse_peers('[{"name": "a", "base_url": "https://a.com", "api_key": ""}]')


def test_parse_rejects_non_json():
    with pytest.raises(ValueError):
        parse_peers("not-json")


def test_parse_rejects_empty_list():
    with pytest.raises(ValueError):
        parse_peers("[]")
