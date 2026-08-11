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


def _unwrap_payload(data: dict) -> dict:
    """兼容两种对端响应格式：裸格式 {"hash":...} 与包装格式 {"code":0,"data":{...}}。

    部分站点（如主站 tokbuff）有全局响应包装中间件，所有端点返回
    {"code":0,"message":"","data":{...}}；共享库早期版本只认裸格式，
    导致解析到空 hash（"peer returned empty password hash"）。
    """
    if isinstance(data, dict) and isinstance(data.get("data"), dict):
        return data["data"]
    return data


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
        payload = _unwrap_payload(resp.json())
        return bool(payload.get("exists"))

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
        payload = _unwrap_payload(resp.json())
        h = str(payload.get("hash") or "").strip()
        if not h:
            raise PeerUnavailable("peer returned empty password hash")
        return PasswordMeta(
            hash=h,
            changed_at=(
                str(payload["changed_at"]).strip()
                if payload.get("changed_at") is not None
                else None
            ),
            source=str(payload.get("source") or "manual").strip() or "manual",
        )


    async def push_password_meta(
        self,
        email: str,
        hash: str,
        changed_at: str | None,
        source: str = "manual",
    ) -> bool:
        """Push this user's password metadata to the peer for adoption.

        Returns True when the peer adopted (200), False when it rejected
        (e.g. 409 — peer's own password is newer). Raises PeerUnavailable
        on network errors.
        """
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    f"{self._peer.base_url}/api/v1/auth/sso/password-push",
                    json={
                        "email": email,
                        "hash": hash,
                        "changed_at": changed_at,
                        "source": source,
                    },
                    headers={"X-SSO-API-Key": self._peer.api_key},
                )
        except httpx.HTTPError as exc:
            raise PeerUnavailable(str(exc)) from exc
        return resp.status_code == 200
