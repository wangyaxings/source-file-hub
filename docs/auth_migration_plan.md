# 认证系统迁移到 Authboss — 计划与改进

本计划基于当前代码与文档现状，统一到 Authboss 的基于会话的认证模型，清理历史遗留，收敛 2FA 与 RBAC 使用方式，并在文档与测试侧完成一致性收敛。

参考与关联文档：
- docs/auth.md
- docs/auth_refactor.md
- docs/2fa-best-practices.md
- docs/architecture.md
- docs/security-improvements.md
- docs/api-guide.md

## 背景与目标

- 历史曾同时存在 JWT/Token 与 Authboss 会话两套机制，导致前后端与文档不一致、2FA 路由不统一。
- 目标：仅保留 Authboss 会话认证，前端完全依赖 Cookie，2FA 与 RBAC 一致化，文档与测试对齐。

## 现状问题（摘要）

- 前端 `frontend/lib/api.ts` 已基本改为基于 Cookie 的会话，但 2FA 路由存在不一致（`/auth/2fa/totp/*` 与 `/auth/ab/2fa/totp/*` 同时被引用）。
- 中间件 `internal/middleware/auth.go` 已统一为 Authboss 会话加载，但部分文档仍描述 JWT。
- `internal/handler/handler.go` 的自定义 2FA 路由命名与文档、前端存在差异（`setup/confirm/remove` vs `start/enable/disable`）。
- `docs/api-guide.md` 仍以 Bearer/JWT 为主，与 `docs/auth.md` 不一致。
- 测试侧历史 JWT 字段/说明仍有残留（个别注释与示例配置）。

## 范围与非目标

- 范围：认证与 2FA 流程统一、路由与文档一致性、测试收敛、开发者指南更新。
- 非目标：改动 API Key 公共接口语义、重写前端 UI 逻辑、引入非必要的模块替换。

## 迁移策略（高层）

- 仅保留 Authboss 会话认证；前端所有请求 `credentials: 'include'`；后端仅读取 Authboss session。
- 保留“自定义 Web 包装”的 2FA 路由，并统一命名为：
  - `POST /api/v1/web/auth/2fa/totp/setup`
  - `POST /api/v1/web/auth/2fa/totp/confirm`
  - `POST /api/v1/web/auth/2fa/totp/remove`
  与当前后端实现一致（参考 `internal/handler/handler.go`）。
- 文档统一：`docs/auth.md`、`docs/api-guide.md` 与前端 `frontend/lib/api.ts` 的命名、路径保持一致。

## 路线图与任务清单

### 阶段一：立即收敛（本周）

- 2FA 路由统一（代码与文档一致）：
  - 确认并固定使用 `setup/confirm/remove` 三个端点。
  - 修正前端 `frontend/lib/api.ts` 仍指向 `/auth/ab/2fa/totp/remove` 的调用为 `/auth/2fa/totp/remove`。
  - 更新 `docs/auth.md` 中 2FA 路由示例为 `setup/confirm/remove`。
- 文档一致化：
  - 在 `docs/api-guide.md` 顶部加入“已迁移至基于会话的认证”的告知与指向 `docs/auth.md` 的链接；逐步替换 JWT 章节为 Cookie 会话说明。
  - 本文移除历史内嵌的整段 API Guide（本文件专注“迁移计划”，API 详解由 `docs/auth.md` 与 `docs/api-guide.md` 承担）。
- 测试核查：
  - 清点测试中遗留 JWT 字段/注释，按会话模型修正（`tests/**/*`）。

验收标准：
- `frontend/lib/api.ts` 的 2FA 三个方法均命中 `setup/confirm/remove`；`/auth/ab/2fa/...` 不再被前端调用。
- `docs/auth.md` 与 `docs/api-guide.md` 关于登录、登出、获取用户、2FA 的路径与返回格式一致且无 JWT 提法。

### 阶段二：历史清理与文档完善（下周）

- 代码清理：
  - 移除/归档任何 JWT/Token 相关常量、注释、示例（如仍存在）。
- 文档完善：
  - `docs/2fa-best-practices.md` 与 `docs/auth.md` 的文案统一用语（“2FA 设置/确认/移除”）。
  - `docs/architecture.md` 的“登录序列”“中间件顺序”与现状一致，无 JWT 描述。
- 测试与样例：
  - 在 `tests/auth/auth_test.go`、`tests/middleware/middleware_test.go` 覆盖基于会话的未登录 → 登录 → 失效流程；覆盖 2FA 开启后的分支（若已有，补齐断言）。

验收标准：
- 仓库内 `rg -n "JWT|token"` 仅在 API Key 或无关上下文出现；认证相关不再出现 Legacy 残留。
- 2FA 文档、代码与前端命名保持完全一致；Mermaid 时序图与真实接口匹配。

### 阶段三：可选增强（后续）

- 若未来完全交由 Authboss 自带的 TOTP 路由处理：
  - 评估并迁移自定义 `/auth/2fa/totp/*` 到 `/auth/ab/2fa/totp/*`，并更新前端与文档。
  - 完成后删除自定义 2FA 包装端点，减少维护面。

## 变更清单（面向提交）

- 前端
  - `frontend/lib/api.ts`：统一 2FA 三个端点为 `setup/confirm/remove`，仅使用 `/api/v1/web/auth/2fa/totp/*`。
- 后端
  - `internal/handler/handler.go`：确认 2FA 路由实现与上述命名一致；如已一致，仅补充注释与文档指引。
  - `internal/middleware/auth.go`：已统一为 Authboss，会话校验逻辑无需再兼容 Token。
- 文档
  - `docs/auth.md`：登录/登出/用户信息/2FA（setup/confirm/remove）统一示例。
  - `docs/api-guide.md`：移除 JWT 描述，改为 Cookie 会话；在过渡期间添加显著“已弃用 JWT”标识。
  - `docs/2fa-best-practices.md`：对应用语与路由名同步。

## 风险与回滚

- 风险：前后端路由名称不一致导致 2FA 操作失败；API 文档与实现不一致导致集成方误用。
- 缓解：灰度环境先验证；在 PR 中附带端到端验证用例与截图；保留旧路由短期兼容（如必要），同时在日志中打 Deprecation 告警。
- 回滚：如线上异常，恢复旧前端 2FA 调用与旧文档链接；后续重新按以上步骤推进。

## 验收检查表

- 功能
  - [ ] 会话登录/登出与 `/api/v1/web/auth/me` 正常。
  - [ ] 2FA `setup/confirm/remove` 全链路可用且前后端一致。
- 安全
  - [ ] Cookie 标志（HttpOnly/Secure/SameSite）与 HTTPS 重定向生效。
  - [ ] 禁止未登录访问受保护资源；`pending/suspended` 用户按策略拦截。
- 代码/文档
  - [ ] 认证相关不再出现 Legacy JWT/Token 残留。
  - [ ] `docs/auth.md`、`docs/api-guide.md`、`docs/2fa-best-practices.md` 一致。
  - [ ] 本文不再夹带 API Guide 详情，专注“计划与落地”。

## 时间与产出

- 本周：完成阶段一，提交前端与文档修复 PR；补充必要测试。
- 下周：完成阶段二，清理历史与文档对齐；补齐测试断言与覆盖率。

## 参考

- internal/middleware/auth.go
- internal/handler/handler.go
- frontend/lib/api.ts
- docs/auth.md
- docs/2fa-best-practices.md
- docs/architecture.md
- docs/security-improvements.md
- docs/api-guide.md

