import pytest
import httpx

from tokbuff_sso.client import PeerClient, PeerUnavailable
from tokbuff_sso.peers import PeerConfig

KEY = "k" * 16


async def test_email_exists(httpx_mock):
    peer = PeerConfig("forum", "https://forum.tokbuff.com", KEY)
    httpx_mock.add_response(json={"exists": True})
    client = PeerClient(peer, timeout=2.0)
    assert await client.email_exists("a@b.com") is True
    req = httpx_mock.get_request()
    assert req.headers["x-sso-api-key"] == KEY
    assert "email=a%40b.com" in str(req.url)


async def test_email_exists_false(httpx_mock):
    peer = PeerConfig("forum", "https://forum.tokbuff.com", KEY)
    httpx_mock.add_response(json={"exists": False})
    assert await PeerClient(peer).email_exists("a@b.com") is False


async def test_unreachable_raises_peer_unavailable(httpx_mock):
    peer = PeerConfig("forum", "https://forum.tokbuff.com", KEY)
    httpx_mock.add_exception(httpx.ConnectError("conn refused"))
    with pytest.raises(PeerUnavailable):
        await PeerClient(peer, timeout=1.0).email_exists("a@b.com")


async def test_non_200_raises_peer_unavailable(httpx_mock):
    peer = PeerConfig("forum", "https://forum.tokbuff.com", KEY)
    httpx_mock.add_response(status_code=500)
    with pytest.raises(PeerUnavailable):
        await PeerClient(peer).email_exists("a@b.com")


async def test_fetch_password_meta_ok(httpx_mock):
    peer = PeerConfig("forum", "https://forum.tokbuff.com", KEY)
    httpx_mock.add_response(
        json={
            "hash": "$2b$12$abcdefghijklmnopqrstuvwxyz0123456789",
            "changed_at": "2026-08-11T00:00:00+00:00",
            "source": "manual",
        }
    )
    meta = await PeerClient(peer, timeout=2.0).fetch_password_meta("a@b.com")
    assert meta.hash.startswith("$2b$")
    assert meta.changed_at == "2026-08-11T00:00:00+00:00"
    assert meta.source == "manual"
    req = httpx_mock.get_request()
    assert req.headers["x-sso-api-key"] == KEY
    assert "password-meta" in str(req.url)
    assert "email=a%40b.com" in str(req.url)


async def test_fetch_password_meta_nullable_fields(httpx_mock):
    peer = PeerConfig("forum", "https://forum.tokbuff.com", KEY)
    httpx_mock.add_response(json={"hash": "$2b$12$saltandhashvalue"})
    meta = await PeerClient(peer).fetch_password_meta("a@b.com")
    assert meta.hash == "$2b$12$saltandhashvalue"
    assert meta.changed_at is None
    assert meta.source == "manual"


async def test_fetch_password_meta_404_raises_peer_unavailable(httpx_mock):
    """Legacy peer (v0.1.1, no endpoint) → 404 → PeerUnavailable → fail-open."""
    peer = PeerConfig("forum", "https://forum.tokbuff.com", KEY)
    httpx_mock.add_response(status_code=404)
    with pytest.raises(PeerUnavailable):
        await PeerClient(peer).fetch_password_meta("a@b.com")


async def test_fetch_password_meta_empty_hash_raises(httpx_mock):
    peer = PeerConfig("forum", "https://forum.tokbuff.com", KEY)
    httpx_mock.add_response(json={"hash": ""})
    with pytest.raises(PeerUnavailable):
        await PeerClient(peer).fetch_password_meta("a@b.com")


async def test_fetch_password_meta_network_error_raises(httpx_mock):
    peer = PeerConfig("forum", "https://forum.tokbuff.com", KEY)
    httpx_mock.add_exception(httpx.ConnectError("conn refused"))
    with pytest.raises(PeerUnavailable):
        await PeerClient(peer).fetch_password_meta("a@b.com")
