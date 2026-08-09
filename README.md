# tokbuff-sso

Cross-site SSO for tokbuff family sites (tokbuff.com, forum.tokbuff.com, ...).

## 安全要求（公开仓库，请勿提交真实密钥）

- 本仓库**不含任何真实密钥**；所有 secret 由各站运行时环境注入
- `ticket_secret` 必须 >= 32 字节随机值，缺失/过短时插件拒绝启动
- 密钥泄露处置：立即轮换 `ticket_secret`（所有站点同步更新）
- 不要将 `.env`、`*.pem`、`*.key` 等文件加入 git
