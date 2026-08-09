import httpx
import pytest
from litestar import Litestar

from tokbuff_sso.litestar import SsoConfig, SsoPlugin
from tokbuff_sso.ticket import sign_ticket

SECRET = "s" * 32
KEY = "k" * 16


def _build_app(provision_calls=None, issue_calls=None, find_calls=None):
    async def provisioner(email):
        return _fake_provision(email, provision_calls)

    async def token_issuer(uid):
        return _fake_issue(uid, issue_calls)

    finder = None
    if find_calls is not None:
        async def finder(email):
            return _fake_find(email, find_calls)

    cfg = SsoConfig(
        ticket_secret=SECRET,
        peer_name="tokbuff",
        peers=[
            {"name": "forum", "base_url": "https://forum.tokbuff.com", "api_key": KEY},
        ],
        cookie_domain=".tokbuff.com",
        provisioner=provisioner,
        token_issuer=token_issuer,
        finder=finder,
    )
    return Litestar(plugins=[SsoPlugin(cfg)])


def _fake_provision(email, calls):
    if calls is not None:
        calls.append(("provision", email))
    return "local-1"


def _fake_issue(uid, calls):
    if calls is not None:
        calls.append(("issue", uid))
    return {"access_token": "tok", "user_id": uid}


def _fake_find(email, calls):
    if calls is not None:
        calls.append(("find", email))
    return "local-1" if email == "a@b.com" else None


async def test_exchange_without_cookie_401():
    app = _build_app()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://tokbuff.com"
    ) as c:
        r = await c.post("/api/v1/auth/sso-exchange")
    assert r.status_code == 401


async def test_exchange_with_valid_ticket_logs_in():
    calls = []
    app = _build_app(provision_calls=calls)
    token = sign_ticket("a@b.com", "forum", "u-9", ttl=900, secret=SECRET)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://tokbuff.com"
    ) as c:
        c.cookies.set("tokbuff_sso_ticket", token, domain=".tokbuff.com")
        r = await c.post("/api/v1/auth/sso-exchange")
    assert r.status_code == 200
    assert r.json()["access_token"] == "tok"
    assert ("provision", "a@b.com") in calls  # JIT because finder returns None


async def test_exchange_with_query_ticket_logs_in():
    """URL 跳转携带的 ticket（query 参数）也应能自动登录。"""
    calls = []
    app = _build_app(provision_calls=calls)
    token = sign_ticket("a@b.com", "forum", "u-9", ttl=900, secret=SECRET)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://tokbuff.com"
    ) as c:
        r = await c.post(f"/api/v1/auth/sso-exchange?sso_ticket={token}")
    assert r.status_code == 200
    assert r.json()["access_token"] == "tok"
    assert ("provision", "a@b.com") in calls


async def test_exchange_with_existing_user_no_provision():
    calls = []
    app = _build_app(provision_calls=calls, find_calls=calls)
    token = sign_ticket("a@b.com", "forum", "u-9", ttl=900, secret=SECRET)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://tokbuff.com"
    ) as c:
        c.cookies.set("tokbuff_sso_ticket", token, domain=".tokbuff.com")
        r = await c.post("/api/v1/auth/sso-exchange")
    assert r.status_code == 200
    assert ("find", "a@b.com") in calls
    assert not any(c[0] == "provision" for c in calls)


async def test_exchange_rejects_self_issued_ticket():
    app = _build_app()
    token = sign_ticket("a@b.com", "tokbuff", "u-9", ttl=900, secret=SECRET)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://tokbuff.com"
    ) as c:
        c.cookies.set("tokbuff_sso_ticket", token, domain=".tokbuff.com")
        r = await c.post("/api/v1/auth/sso-exchange")
    assert r.status_code == 401


async def test_exchange_with_forged_ticket_401():
    app = _build_app()
    token = sign_ticket("a@b.com", "forum", "u-9", ttl=900, secret="x" * 32)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://tokbuff.com"
    ) as c:
        c.cookies.set("tokbuff_sso_ticket", token, domain=".tokbuff.com")
        r = await c.post("/api/v1/auth/sso-exchange")
    assert r.status_code == 401


async def test_email_exists_requires_api_key():
    app = _build_app()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://tokbuff.com"
    ) as c:
        r = await c.get("/api/v1/auth/sso/email-exists", params={"email": "a@b.com"})
    assert r.status_code == 401


async def test_email_exists_with_key():
    find_calls = []
    app = _build_app(find_calls=find_calls)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://tokbuff.com"
    ) as c:
        r = await c.get(
            "/api/v1/auth/sso/email-exists",
            params={"email": "a@b.com"},
            headers={"X-SSO-API-Key": KEY},
        )
    assert r.status_code == 200
    assert r.json() == {"exists": True}
    assert ("find", "a@b.com") in find_calls


async def test_email_exists_with_key_not_found():
    find_calls = []
    app = _build_app(find_calls=find_calls)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://tokbuff.com"
    ) as c:
        r = await c.get(
            "/api/v1/auth/sso/email-exists",
            params={"email": "nobody@b.com"},
            headers={"X-SSO-API-Key": KEY},
        )
    assert r.status_code == 200
    assert r.json() == {"exists": False}


async def test_email_exists_bad_email_400():
    app = _build_app()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://tokbuff.com"
    ) as c:
        r = await c.get(
            "/api/v1/auth/sso/email-exists",
            params={"email": "not-an-email"},
            headers={"X-SSO-API-Key": KEY},
        )
    assert r.status_code == 400


def test_plugin_rejects_short_secret():
    async def provisioner(email):
        return "u"

    async def token_issuer(uid):
        return {}

    cfg = SsoConfig(
        ticket_secret="short",
        peer_name="tokbuff",
        peers=[],
        provisioner=provisioner,
        token_issuer=token_issuer,
    )
    with pytest.raises(ValueError):
        SsoPlugin(cfg)


def test_plugin_rejects_self_in_peers():
    async def provisioner(email):
        return "u"

    async def token_issuer(uid):
        return {}

    cfg = SsoConfig(
        ticket_secret=SECRET,
        peer_name="tokbuff",
        peers=[{"name": "tokbuff", "base_url": "https://tokbuff.com", "api_key": KEY}],
        provisioner=provisioner,
        token_issuer=token_issuer,
    )
    with pytest.raises(ValueError):
        SsoPlugin(cfg)
