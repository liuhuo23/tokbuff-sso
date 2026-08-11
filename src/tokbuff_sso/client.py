"""Outbound peer API client (email-exists check, password-meta sync)."""
from __future__ import annotations

from dataclasses import dataclass

import httpx

from tokbuff_sso.peers import PeerConfig


class PeerUnavailable(Exception):
    """Peer down/timeout/non-2xx — callers decide fail-open."""


@dataclass(frozen=True)
class PasswordMeta:
    """Peer-side password metadata for cross-site password sync.

    The bcrypt hash string is portable between sites (self-contained
    cost/salt), so a JIT-provisioned account can adopt the issuer's hash
    and the user can log in manually with the same password on both sites.
    """

    hash: str
    changed_at: str | None = None  # ISO8601 UTC; None = unknown/legacy
    source: str = "manual"  # manual | sso_jit | sso_synced


class PeerClient:
    def __init__(self, peer: PeerConfig, timeout: float = 5.0) -> None:
        self._peer = peer
        self._timeout = timeout

    async def email_exists(self, email: str) -> bool:
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(
                    f"{self._peer.base_url}/api/v1/auth/sso/email-exists",
                    params={"email": email},
                    headers={"X-SSO-API-Key": self._peer.api_key},
                )
        except httpx.HTTPError as exc:
            raise PeerUnavailable(str(exc)) from exc
        if resp.status_code != 200:
            raise PeerUnavailable(f"peer returned {resp.status_code}")
        return bool(resp.json().get("exists"))

    async def fetch_password_meta(self, email: str) -> PasswordMeta:
        """Fetch the peer's password metadata for an email.

        Raises PeerUnavailable on network errors and any non-200 response
        (including 404 from peers that have not upgraded to v0.2.0) — callers
        treat that as fail-open and fall back to a random-password account.
        """
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(
                    f"{self._peer.base_url}/api/v1/auth/sso/password-meta",
                    params={"email": email},
                    headers={"X-SSO-API-Key": self._peer.api_key},
                )
        except httpx.HTTPError as exc:
            raise PeerUnavailable(str(exc)) from exc
        if resp.status_code != 200:
            raise PeerUnavailable(f"peer returned {resp.status_code}")
        data = resp.json()
        h = str(data.get("hash") or "").strip()
        if not h:
            raise PeerUnavailable("peer returned empty password hash")
        return PasswordMeta(
            hash=h,
            changed_at=(
                str(data["changed_at"]).strip()
                if data.get("changed_at") is not None
                else None
            ),
            source=str(data.get("source") or "manual").strip() or "manual",
        )
