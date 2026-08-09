"""Minimal integration example (each site ~30 lines)."""
from litestar import Litestar

from tokbuff_sso.litestar import SsoConfig, SsoPlugin


async def finder(email: str) -> str | None:
    # e.g. SELECT id FROM users WHERE email = $1
    return None


async def provision(email: str) -> str:
    # e.g. INSERT INTO users (email, hashed_password) VALUES ($1, random())
    return "user-123"


async def issue(uid: str) -> dict:
    # e.g. {"access_token": jwt.encode({"sub": uid}, SECRET)}
    return {"access_token": f"tok-{uid}", "user_id": uid}


app = Litestar(plugins=[SsoPlugin(SsoConfig(
    ticket_secret=open("/run/secrets/sso_ticket_secret").read().strip(),
    peer_name="my-site",
    peers=[{"name": "forum", "base_url": "https://forum.tokbuff.com", "api_key": "k" * 16}],
    provisioner=provision,
    token_issuer=issue,
    finder=finder,
))])

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
