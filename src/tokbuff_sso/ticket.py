"""SSO ticket signing/verification. Pure stdlib (hmac + base64 + json)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass


class TicketError(ValueError):
    """Invalid/expired/forged ticket."""


@dataclass(frozen=True)
class SSOTicket:
    email: str
    issuer: str
    subject: str
    issued_at: int
    expires_at: int


_MIN_SECRET_BYTES = 32


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sign_ticket(
    email: str, issuer: str, subject: str, *, ttl: int, secret: str,
) -> str:
    if len(secret) < _MIN_SECRET_BYTES:
        raise ValueError("ticket_secret must be >= 32 bytes")
    now = int(time.time())
    payload = {
        "email": email,
        "iss": issuer,
        "sub": str(subject),
        "iat": now,
        "exp": now + ttl,
    }
    raw = json.dumps(payload, separators=(",", ":")).encode()
    sig = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    return f"{_b64url(raw)}.{sig}"


def verify_ticket(
    token: str, secret: str, *, allowed_issuers: set[str],
) -> SSOTicket:
    try:
        raw_b64, sig = token.split(".")
        raw = _b64url_decode(raw_b64)
    except Exception as exc:
        raise TicketError("malformed ticket") from exc
    expected = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        raise TicketError("bad signature")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise TicketError("bad payload") from exc
    now = int(time.time())
    if payload.get("exp", 0) <= now:
        raise TicketError("ticket expired")
    if payload.get("iat", 0) > now + 60:
        raise TicketError("ticket issued in future")
    if payload.get("iss") not in allowed_issuers:
        raise TicketError("unknown issuer")
    email = str(payload.get("email", "")).strip().lower()
    if not email or "@" not in email:
        raise TicketError("bad email")
    return SSOTicket(
        email=email,
        issuer=str(payload["iss"]),
        subject=str(payload["sub"]),
        issued_at=int(payload["iat"]),
        expires_at=int(payload["exp"]),
    )
