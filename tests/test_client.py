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
    assert "a@b.com" in str(req.url)


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
