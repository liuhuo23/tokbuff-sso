"""Peer registry parsing with strict validation (public-repo hardening)."""
from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class PeerConfig:
    name: str
    base_url: str
    api_key: str


_MIN_API_KEY_LENGTH = 16


def parse_peers(raw: str) -> list[PeerConfig]:
    try:
        items = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("SSO_PEERS is not valid JSON") from exc
    if not isinstance(items, list) or not items:
        raise ValueError("SSO_PEERS must be a non-empty list")
    peers: list[PeerConfig] = []
    seen: set[str] = set()
    for item in items:
        name = str(item.get("name", "")).strip()
        base_url = str(item.get("base_url", "")).strip().rstrip("/")
        api_key = str(item.get("api_key", "")).strip()
        if not name or name in seen:
            raise ValueError(f"SSO_PEERS: duplicate or empty name {name!r}")
        parsed = urlparse(base_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(f"SSO_PEERS: invalid base_url {base_url!r}")
        if len(api_key) < _MIN_API_KEY_LENGTH:
            raise ValueError(f"SSO_PEERS: api_key for {name!r} too short")
        seen.add(name)
        peers.append(PeerConfig(name=name, base_url=base_url, api_key=api_key))
    return peers
