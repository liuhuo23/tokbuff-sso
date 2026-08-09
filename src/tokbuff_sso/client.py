"""Outbound peer API client (email-exists check)."""
from __future__ import annotations

import httpx

from tokbuff_sso.peers import PeerConfig


class PeerUnavailable(Exception):
    """Peer down/timeout/non-2xx — callers decide fail-open."""


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
