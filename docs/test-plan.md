# Test Plan — Secure File Hub

This plan captures critical test points and maps them to unit tests. Tests use Go `httptest` and in-memory/temporary SQLite.

## Scope

- Middleware
  - CORS headers + OPTIONS preflight
  - HTTPS redirect behavior (enable/disable)
  - Auth middleware unauthorized behavior (basic path)

- Web Handlers
  - `GET /api/v1/web/auth/me` with/without user context
  - `POST /api/v1/web/auth/change-password` success and failure (wrong old password)
  - Download handler basic validations (invalid path, 404)

- Database
  - `CreateOrUpdateUserRole` and `GetUserRole` default/fallback
  - `UpdateUserPassword` and `GetUser`

## Test Data

- Temporary DB created per test suite in a temp directory.
- Users: `alice` (viewer) with initial password; role record active.

## Mapping to Test Files

- `internal/handler/handler_test.go`
  - `TestMeHandler_Unauthorized`
  - `TestMeHandler_WithUser`
  - `TestChangePassword_Success`
  - `TestChangePassword_WrongOldPassword`

- `internal/middleware/cors_test.go`
  - `TestCORS_Preflight`
  - `TestHTTPSRedirect_Redirects`
  - `TestHTTPSRedirect_Disabled`

- `internal/database/database_test.go`
  - `TestUserRole_CreateGet`
  - `TestUser_UpdatePassword`

## Execution

- Run all: `scripts/test.sh` (Linux/macOS) or `scripts/test.ps1` (Windows)
- Flags: race detector, coverage profile, clean environment (`DISABLE_HTTPS_REDIRECT=true` during tests)

