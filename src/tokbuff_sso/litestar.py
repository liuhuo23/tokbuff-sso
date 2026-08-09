"""Litestar plugin: register sso-exchange + email-exists endpoints."""
from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from litestar import Request, Response, get, post
from litestar.config.app import AppConfig
from litestar.exceptions import HTTPException
from litestar.params import FromQuery
from litestar.plugins import InitPluginProtocol

from tokbuff_sso.peers import PeerConfig, parse_peers
from tokbuff_sso.ticket import TicketError, sign_ticket, verify_ticket

logger = logging.getLogger(__name__)

COOKIE_NAME = "tokbuff_sso_ticket"

EmailOrNone = Callable[[str], Awaitable[str | None]]  # finder: email -> local user id
Provisioner = Callable[[str], Awaitable[str]]  # email -> local user id (create if needed)
TokenIssuer = Callable[[str], Awaitable[dict[str, Any]]]  # user id -> token response dict


@dataclass
class SsoConfig:
    ticket_secret: str
    peer_name: str
    peers: list[PeerConfig | dict]
    provisioner: Provisioner
    token_issuer: TokenIssuer
    finder: EmailOrNone | None = None
    cookie_domain: str = ".tokbuff.com"
    cookie_name: str = COOKIE_NAME
    ticket_ttl_seconds: int = 900
    exchange_path: str = "/api/v1/auth/sso-exchange"
    email_exists_path: str = "/api/v1/auth/sso/email-exists"


class SsoPlugin(InitPluginProtocol):
    def __init__(self, config: SsoConfig) -> None:
        if len(config.ticket_secret) < 32:
            raise ValueError("ticket_secret must be >= 32 bytes (fail-closed)")
        if not config.peer_name.strip():
            raise ValueError("peer_name is required")
        self.config = config
        self._peers = {
            p.name: p for p in (
                p if isinstance(p, PeerConfig) else PeerConfig(**p) for p in config.peers
            )
        }
        if config.peer_name in self._peers:
            raise ValueError(f"peer_name {config.peer_name!r} must not be in peers list")

    def on_app_init(self, app_config: AppConfig) -> AppConfig:
        cfg = self.config
        peers = self._peers

        @post(cfg.exchange_path)
        async def exchange(request: Request) -> Response[dict[str, Any]]:
            token = request.cookies.get(cfg.cookie_name)
            if not token:
                raise HTTPException(status_code=401, detail="no sso ticket")
            try:
                ticket = verify_ticket(
                    token,
                    cfg.ticket_secret,
                    allowed_issuers=set(peers),  # other sites only
                )
            except TicketError as exc:
                logger.warning("sso exchange rejected: %s", exc)
                raise HTTPException(
                    status_code=401, detail="invalid sso ticket"
                ) from exc
            if ticket.issuer == cfg.peer_name:
                raise HTTPException(
                    status_code=401, detail="self-issued ticket rejected"
                )
            # find existing, else JIT provision
            uid = None
            if cfg.finder is not None:
                uid = await cfg.finder(ticket.email)
            if uid is None:
                uid = await cfg.provisioner(ticket.email)
            result = await cfg.token_issuer(uid)
            resp = Response(result, status_code=200)
            resp.delete_cookie(cfg.cookie_name, path="/", domain=cfg.cookie_domain)
            return resp

        @get(cfg.email_exists_path)
        async def email_exists(
            request: Request, email: FromQuery[str]
        ) -> dict[str, bool]:
            key = request.headers.get("x-sso-api-key", "")
            if not any(key == p.api_key for p in peers.values()):
                raise HTTPException(status_code=401, detail="unauthorized")
            if not email or "@" not in email:
                raise HTTPException(status_code=400, detail="bad email")
            found = None
            if cfg.finder is not None:
                found = await cfg.finder(email.strip().lower())
            return {"exists": found is not None}

        app_config.route_handlers.extend([exchange, email_exists])
        return app_config


__all__ = ["COOKIE_NAME", "SsoConfig", "SsoPlugin", "sign_ticket"]
