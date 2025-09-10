# 用户与权限管理改造说明（注册 + 2FA + Casbin RBAC）

本次改造目标：

- 提供完整的“用户注册 → 登录”流程；
- 支持 TOTP 2FA（二次验证，兼容 Google Authenticator 等）；
- 引入 Casbin 做 RBAC 访问控制，支持 viewer / administrator 两种角色；
- 与现有接口风格保持兼容，尽量减小改动面。

## 主要改动

- 新增数据库表 `users`（SQLite）：
  - 字段：`username`、`email`、`password_hash`、`role`（默认 viewer）、`twofa_enabled`、`totp_secret`、`created_at/updated_at/last_login_at`。
  - 对应代码：`internal/database/database.go`（AppUser 结构与 CRUD）。

- 用户管理（后端包：`internal/auth`）：
  - 注册：`auth.Register(username, password, email)`
  - 登录：`auth.Authenticate({ username, password, otp? })`（启用 2FA 的用户必须提供 `otp`）
  - 2FA：`StartTOTPSetup` / `EnableTOTP` / `DisableTOTP`
  - 启动时自动创建 `admin`，并为演示种子 `user1`/`test`（默认 viewer）。

- 2FA（TOTP）：基于 `github.com/pquerna/otp/totp` 实现。

- RBAC（Casbin）：
  - 模型：`configs/casbin_model.conf`
  - 策略：`configs/casbin_policy.csv`
  - `administrator` 允许访问 `/api/v1/web/*` 所有读写；`viewer` 仅允许只读下载/列表等。
  - 新增鉴权中间件：`internal/middleware/authorize.go`，在敏感写操作路由上启用。

## 新增/变更的接口

- `POST /api/v1/web/auth/register`：用户注册
  - 请求：`{ "username": string, "password": string, "email"?: string }`
  - 结果：注册成功

- `POST /api/v1/web/auth/login`：用户登录
  - 请求：`{ "username": string, "password": string, "otp"?: string }`
  - 返回：`{ token, expires_in, user: { username, role } }`
  - 若账号已启用 2FA，必须提交 `otp` 才能登录成功。

- 2FA 相关（需登录）：
  - `POST /api/v1/web/auth/2fa/setup` → 返回 `{ secret, otpauth_url }`
  - `POST /api/v1/web/auth/2fa/enable` → 入参 `{ code: "123456" }`
  - `POST /api/v1/web/auth/2fa/disable`

## 管理端：用户管理（GitLab 风格）

- 前端页面：`/admin/users`（Next.js App Router）
  - 文件：`frontend/app/admin/users/page.tsx` + `frontend/components/admin/user-management.tsx`
  - 功能：
    - 列表：用户名 / 邮箱 / 角色（viewer/administrator）/ 状态（pending/active/suspended）/ 2FA / 最近登录
    - 操作：Approve（批准）、Suspend（冻结）、切换 2FA（禁用/启用）、修改角色
  - 权限：仅管理员（`administrator` 或用户名 `admin`）可访问

- 后端接口（Web 命名空间，需管理员）：
  - `GET  /api/v1/web/admin/users`：获取用户列表
  - `PATCH /api/v1/web/admin/users/{username}`：更新用户（角色/2FA）
  - `POST /api/v1/web/admin/users/{username}/approve`：批准（user_roles.status=active）
  - `POST /api/v1/web/admin/users/{username}/suspend`：冻结（status=suspended）
  - `POST /api/v1/web/admin/users/{username}/2fa/disable`：强制关闭 2FA

说明：新注册用户默认放入 `user_roles.status=pending`，管理员在用户管理页审批为 `active` 后正式生效。

## 路由授权（Casbin）

以下敏感写操作已接入 `middleware.RequireAuthorization`（Casbin Enforce）：

- `/api/v1/web/upload`、`/api/v1/web/files/{id}/delete|restore|purge`、`/api/v1/web/recycle-bin/clear`、`/api/v1/web/versions/{type}/{versionId}/tags`、`/api/v1/web/packages/upload/*`；
- `/api/v1/admin/**` 下的 API Key 管理、用量、用户管理等；
- `internal/handler/analytics.go` 的增强分析接口。

策略默认：

```
p, administrator, /api/v1/web/*, (GET|POST|PUT|PATCH|DELETE)
p, viewer, /api/v1/web/health*, GET
p, viewer, /api/v1/web/files/list, GET
p, viewer, /api/v1/web/files/versions/*, GET
p, viewer, /api/v1/web/files/*, GET
```

如需放开或新增权限，可调整 `configs/casbin_policy.csv` 并重启。

## 兼容性与后续工作

- 前端现有登录表单仍可用；如需兼容 2FA，可在登录时增加 `otp` 输入框（仅当后端返回需要 2FA 时提示）。
- 生产建议：
  - 将现有内存 Token 机制升级为 JWT 或持久化会话；
  - 邮件确认 / 找回密码 / 记住我等可逐步接入 Authboss 模块；
  - 审计与风控可与现有数据库日志（`api_usage_logs` 等）打通。

## Authboss 引入（预接入）

- 已引入依赖并提供最小化适配：
  - 代码：`internal/auth/authboss.go`, `internal/auth/authboss_store.go`
  - 使用 `users` 表作为 `Authboss` 的后端存储（实现了最小 `UserStorer`）。
- 当前未切换前端登录流程到 Authboss（避免一次性变更过大）。如需启用：
  - 在服务器启动处调用 `auth.InitAuthboss()` 并在路由挂载 `/authboss`；
  - 配置 `Session/Cookie` 存储与视图（或 JSON 渲染），开启所需模块（register/auth/confirm/recover/remember 等）；
  - 前端登录/注册改造为 Authboss 流程后，可逐步移除自定义的 JSON 登录逻辑。
