# tokbuff-sso

Cross-site SSO for tokbuff family sites (tokbuff.com, forum.tokbuff.com, ...).

## 共享认证库（v0.4.0+）

跨站共享认证库 `tokbuff_user`：`users`（全站唯一密码）+ `auth_history`（授权审计/会话版本）。
两站引入并配置即可天然集成，无需手工执行 DDL。

```python
from tokbuff_sso import (
    SharedAuthClient, SharedAuthConfig, ensure_database,
)

# 1.（可选）库不存在时自动建库：连维护库执行 CREATE DATABASE，需 CREATEDB 权限
await ensure_database("postgresql://user:pass@host:5432/postgres", "tokbuff_user")

# 2. 客户端：幂等建表 + 读写
client = SharedAuthClient(SharedAuthConfig(
    database_url="postgresql+asyncpg://user:pass@host:5432/tokbuff_user",
    site="forum",   # 本站标识，写入 auth_history.site
))
await client.ensure_schema()        # CREATE TABLE IF NOT EXISTS（模型即 DDL）
user, created = await client.upsert_user("a@b.com", "$2b$...")  # 改密/注册双写，version+1
await client.record_auth(user.id, jti, user.password_version, ip="...", user_agent="...")
```

- 登录验证：`get_user(email)` 取 `password_hash` + `password_version`，bcrypt 校验由调用方完成
- 失败策略：共享库不可用时抛 `SharedAuthError`，调用方按 fail-open / fail-closed 决定
- 模型即 DDL：`ensure_schema()` 幂等建表，schema 演进随 tokbuff-sso 版本升级

## 安全要求（公开仓库，请勿提交真实密钥）

- 本仓库**不含任何真实密钥**；所有 secret 由各站运行时环境注入
- `ticket_secret` 必须 >= 32 字节随机值，缺失/过短时插件拒绝启动
- 密钥泄露处置：立即轮换 `ticket_secret`（所有站点同步更新）
- 不要将 `.env`、`*.pem`、`*.key` 等文件加入 git
