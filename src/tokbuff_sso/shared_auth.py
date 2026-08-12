"""Shared auth database (``tokbuff_user``) for the tokbuff family sites.

跨站共享认证库：``users``（全站唯一密码） + ``auth_history``（授权审计/会话版本）。

两站接入方式（引入并配置即天然集成）：

1. 配置 ``SHARED_AUTH_DATABASE_URL`` 指向共享库（如
   ``postgresql+asyncpg://user:pass@host:5432/tokbuff_user``）
2. 启动时调用 :func:`ensure_database`（可选，自动建库）与 :func:`ensure_schema`
   （幂等建表，模型即 DDL，无需手工迁移）
3. 登录/改密/注册路径通过 :class:`SharedAuthClient` 读写共享库

共享库不可用时所有操作抛 :class:`SharedAuthError`，由调用方按
fail-open / fail-closed 策略决定行为（默认建议 fail-open：不影响本站登录）。
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, Text, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

logger = logging.getLogger(__name__)

_DB_NAME_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


class SharedAuthError(Exception):
    """共享库不可达/操作失败 — 调用方决定 fail-open 或 fail-closed。"""


class Base(DeclarativeBase):
    pass


_Pk = BigInteger().with_variant(Integer, "sqlite")


class SharedUser(Base):
    """认证核心：全站唯一密码（email → password_hash + version）。"""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(_Pk, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    password_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default="1"
    )
    password_changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    status: Mapped[str] = mapped_column(
        Text, nullable=False, default="active", server_default="active"
    )


class AuthHistory(Base):
    """授权历史：审计 + 会话版本（阶段3 按 password_version 作废旧会话）。"""

    __tablename__ = "auth_history"

    id: Mapped[int] = mapped_column(_Pk, primary_key=True, autoincrement=True)
    user_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("users.id"), nullable=True
    )
    site: Mapped[str] = mapped_column(Text, nullable=False)
    token_jti: Mapped[str] = mapped_column(Text, nullable=False)
    password_version: Mapped[int] = mapped_column(Integer, nullable=False)
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    ip: Mapped[str | None] = mapped_column(Text, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)


@dataclass(frozen=True)
class SharedAuthConfig:
    """共享库连接配置。

    ``database_url`` 使用 SQLAlchemy async 格式
    （``postgresql+asyncpg://...``）；``site`` 为本站标识，写入
    ``auth_history.site``（如 ``forum`` / ``main``）。
    """

    database_url: str
    site: str


async def ensure_database(admin_database_url: str, db_name: str) -> bool:
    """确保数据库存在（幂等）；返回是否新建。

    ``admin_database_url`` 指向维护库（如 ``postgresql://user:pass@host/postgres``，
    需有 CREATEDB 权限）。库名严格校验（^[a-z_][a-z0-9_]{0,62}$），防注入。
    """
    if not _DB_NAME_RE.match(db_name):
        raise ValueError(f"invalid database name: {db_name!r}")
    import asyncpg  # 仅建库路径需要

    conn = await asyncpg.connect(admin_database_url)
    try:
        exists = await conn.fetchval(
            "SELECT 1 FROM pg_database WHERE datname = $1", db_name
        )
        if exists:
            return False
        await conn.execute(f'CREATE DATABASE "{db_name}"')
        logger.info("created shared auth database %r", db_name)
        return True
    finally:
        await conn.close()


class SharedAuthClient:
    """共享认证库客户端：建表 + 用户/审计读写封装。

    ``engine`` 可注入（测试用 sqlite）；默认按 ``config.database_url`` 创建
    async engine（``pool_pre_ping`` 自动剔除失效连接）。
    """

    def __init__(
        self, config: SharedAuthConfig, engine: AsyncEngine | None = None
    ) -> None:
        self.config = config
        self._engine = engine or create_async_engine(
            config.database_url,
            pool_pre_ping=True,
            pool_timeout=5,
            # asyncpg 连接超时：共享库网络黑洞时快速失败（fail-open 不拖慢登录）
            connect_args={"timeout": 5},
        )
        self._session_factory = async_sessionmaker(
            self._engine, class_=AsyncSession, expire_on_commit=False
        )

    async def close(self) -> None:
        await self._engine.dispose()

    async def ensure_schema(self) -> None:
        """幂等建表（CREATE TABLE IF NOT EXISTS，模型即 DDL）。"""
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def get_user(self, email: str) -> SharedUser | None:
        """按 email 读取共享用户（登录验证用）。"""
        async with self._session_factory() as session:
            return await session.scalar(
                select(SharedUser).where(SharedUser.email == email.strip().lower())
            )

    async def upsert_user(
        self, email: str, password_hash: str, changed_at: datetime | None = None
    ) -> tuple[SharedUser, bool]:
        """改密/重置/注册双写：存在则更新 hash + version+1，否则插入（version=1）。

        返回 ``(user, created)``。``changed_at`` 缺省为当前 UTC 时间。

        并发安全：version 递增用原子 UPDATE（``password_version+1``），
        避免读-改-写竞态丢失递增；并发插入冲突时回退到 UPDATE。
        """
        email = email.strip().lower()
        if not password_hash:
            raise SharedAuthError("password_hash is required")
        changed_at = changed_at or datetime.now(timezone.utc)

        def _bump():
            return (
                update(SharedUser)
                .where(SharedUser.email == email)
                .values(
                    password_hash=password_hash,
                    password_changed_at=changed_at,
                    password_version=SharedUser.password_version + 1,
                )
                .returning(SharedUser.id)
            )

        async with self._session_factory() as session:
            # 已存在：原子 UPDATE（version+1）
            row = (await session.execute(_bump())).scalar_one_or_none()
            if row is not None:
                await session.commit()
                user = await session.scalar(
                    select(SharedUser).where(SharedUser.email == email)
                )
                return user, False
            # 不存在：插入 version=1；并发插入撞 unique 时回滚改走 UPDATE
            session.add(
                SharedUser(
                    email=email,
                    password_hash=password_hash,
                    password_version=1,
                    password_changed_at=changed_at,
                )
            )
            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()
                row = (await session.execute(_bump())).scalar_one_or_none()
                if row is None:  # pragma: no cover - 理论不可达
                    raise SharedAuthError(f"upsert failed for {email!r}")
                await session.commit()
            user = await session.scalar(
                select(SharedUser).where(SharedUser.email == email)
            )
            return user, True

    async def record_auth(
        self,
        user_id: int,
        jti: str,
        password_version: int,
        ip: str | None = None,
        user_agent: str | None = None,
    ) -> int:
        """登录成功双写 auth_history（审计先行），返回记录 id。"""
        async with self._session_factory() as session:
            record = AuthHistory(
                user_id=user_id,
                site=self.config.site,
                token_jti=jti,
                password_version=password_version,
                issued_at=datetime.now(timezone.utc),
                ip=ip,
                user_agent=user_agent,
            )
            session.add(record)
            await session.commit()
            return record.id

    async def revoke_auth(self, history_id: int) -> None:
        """登出/会话作废：置 revoked_at。"""
        async with self._session_factory() as session:
            record = await session.get(AuthHistory, history_id)
            if record is not None:
                record.revoked_at = datetime.now(timezone.utc)
                await session.commit()


__all__ = [
    "AuthHistory",
    "Base",
    "SharedAuthClient",
    "SharedAuthConfig",
    "SharedAuthError",
    "SharedUser",
    "ensure_database",
]
