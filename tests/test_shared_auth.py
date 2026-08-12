import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.schema import CreateTable

from tokbuff_sso.shared_auth import (
    AuthHistory,
    SharedAuthClient,
    SharedAuthConfig,
    SharedAuthError,
    SharedUser,
    ensure_database,
)

CONFIG = SharedAuthConfig(
    database_url="sqlite+aiosqlite://",
    site="test-site",
)


@pytest.fixture
async def client():
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        poolclass=StaticPool,
    )
    c = SharedAuthClient(CONFIG, engine=engine)
    await c.ensure_schema()
    yield c
    await c.close()


async def test_ensure_schema_idempotent(client):
    await client.ensure_schema()  # 第二次执行不报错


async def test_upsert_creates_user_with_version_1(client):
    user, created = await client.upsert_user(
        "Alice@Example.com", "$2b$hash-a", changed_at=None
    )
    assert created is True
    assert user.email == "alice@example.com"  # 归一化小写
    assert user.password_version == 1
    assert user.status == "active"

    again = await client.get_user("alice@example.com")
    assert again is not None
    assert again.password_hash == "$2b$hash-a"


async def test_upsert_existing_bumps_version(client):
    await client.upsert_user("bob@example.com", "hash-1")
    user, created = await client.upsert_user("bob@example.com", "hash-2")
    assert created is False
    assert user.password_version == 2
    assert user.password_hash == "hash-2"

    # 再次改密 → version 3
    user, _ = await client.upsert_user("bob@example.com", "hash-3")
    assert user.password_version == 3


async def test_upsert_requires_hash(client):
    with pytest.raises(SharedAuthError):
        await client.upsert_user("x@example.com", "")


async def test_record_auth_and_revoke(client):
    user, _ = await client.upsert_user("carol@example.com", "hash-1")
    hid = await client.record_auth(
        user.id,
        jti="jti-abc",
        password_version=user.password_version,
        ip="1.2.3.4",
        user_agent="pytest/1.0",
    )
    assert hid > 0

    await client.revoke_auth(hid)
    # 再查一次确认 revoked_at 已置
    async with client._session_factory() as session:
        record = await session.get(AuthHistory, hid)
        assert record is not None
        assert record.site == "test-site"
        assert record.revoked_at is not None


def test_users_table_pg_ddl_matches_plan():
    """计划 DDL（docs 任务 2.1）关键约束必须出现在 PG 方言 DDL 中。"""
    ddl = str(CreateTable(SharedUser.__table__).compile(dialect=postgresql.dialect()))
    assert "CREATE TABLE users" in ddl
    assert "email" in ddl and "UNIQUE" in ddl
    assert "password_version" in ddl
    assert "password_changed_at" in ddl
    assert "status" in ddl


def test_auth_history_table_pg_ddl_matches_plan():
    ddl = str(
        CreateTable(AuthHistory.__table__).compile(dialect=postgresql.dialect())
    )
    assert "CREATE TABLE auth_history" in ddl
    assert "user_id" in ddl and "REFERENCES users" in ddl
    assert "token_jti" in ddl
    assert "password_version" in ddl
    assert "revoked_at" in ddl
    assert "user_agent" in ddl


@pytest.mark.parametrize(
    "bad",
    ["", "MyDB;DROP", "a b", "1abc", "x" * 64],
)
def test_ensure_database_rejects_bad_names(bad):
    with pytest.raises(ValueError):
        import asyncio

        asyncio.run(ensure_database("postgresql://u:p@localhost/postgres", bad))
