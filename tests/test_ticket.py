import base64
import json
import time

import pytest

from tokbuff_sso.ticket import TicketError, sign_ticket, verify_ticket

SECRET = "s" * 32


def test_sign_verify_roundtrip():
    token = sign_ticket("a@b.com", "forum", "u-1", ttl=900, secret=SECRET)
    t = verify_ticket(token, SECRET, allowed_issuers={"forum", "tokbuff"})
    assert t.email == "a@b.com" and t.issuer == "forum" and t.subject == "u-1"


def test_wrong_secret_rejected():
    token = sign_ticket("a@b.com", "forum", "u-1", ttl=900, secret=SECRET)
    with pytest.raises(TicketError):
        verify_ticket(token, "x" * 32, allowed_issuers={"forum"})


def test_unknown_issuer_rejected():
    token = sign_ticket("a@b.com", "evil", "u-1", ttl=900, secret=SECRET)
    with pytest.raises(TicketError):
        verify_ticket(token, SECRET, allowed_issuers={"forum"})


def test_expired_rejected():
    token = sign_ticket("a@b.com", "forum", "u-1", ttl=-10, secret=SECRET)
    with pytest.raises(TicketError):
        verify_ticket(token, SECRET, allowed_issuers={"forum"})


def test_tampered_payload_rejected():
    token = sign_ticket("a@b.com", "forum", "u-1", ttl=900, secret=SECRET)
    parts = token.split(".")
    payload = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
    payload["email"] = "evil@b.com"
    tampered = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    with pytest.raises(TicketError):
        verify_ticket(f"{tampered}.{parts[1]}", SECRET, allowed_issuers={"forum"})


def test_short_secret_rejected_at_sign():
    with pytest.raises(ValueError):
        sign_ticket("a@b.com", "forum", "u-1", ttl=900, secret="short")


def test_iat_in_future_rejected():
    now = int(time.time())
    token = sign_ticket("a@b.com", "forum", "u-1", ttl=900, secret=SECRET)
    # 手工构造未来 iat 的合法签名 payload
    payload = {"email": "a@b.com", "iss": "forum", "sub": "u-1", "iat": now + 600, "exp": now + 1500}
    raw = json.dumps(payload, separators=(",", ":")).encode()
    import hmac
    import hashlib
    sig = hmac.new(SECRET.encode(), raw, hashlib.sha256).hexdigest()
    forged = f"{base64.urlsafe_b64encode(raw).rstrip(b'=').decode()}.{sig}"
    with pytest.raises(TicketError):
        verify_ticket(forged, SECRET, allowed_issuers={"forum"})
