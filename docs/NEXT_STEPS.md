# Secure File Hub â€?Next Steps Roadmap

This document tracks the remaining improvements, migrations, and tests to complete the refactor and harden the system. Itâ€™s designed as a practical checklist you can work through incrementally.

## Status Snapshot

- [x] Phase 1 â€?Config loader (YAML + env), wire server to config

## Backend Work

### A. Error Handling & Validation

- [x] Replace writeErrorResponse with writeErrorWithCode in remaining handlers
  - [x] Files
    - [x] restoreFileHandler â€?structured codes for not found and DB errors
    - [x] purgeFileHandler â€?structured codes for not found and DB errors
    - [x] uploadFileHandler â€?perâ€‘field details and size/type/format codes
  - [x] Users (admin endpoints)
    - [x] updateUserHandler â€?add codes for invalid role, invalid input
    - [x] updateUserRoleHandler â€?VALIDATION_ERROR per field, USER_NOT_FOUND, etc.
    - [x] approveUserHandler / suspendUserHandler â€?convert DB errors to INTERNAL_ERROR
    - [x] disableUser2FAHandler / enableUser2FAHandler â€?add USER_NOT_FOUND
    - [x] resetUserPasswordHandler â€?structured error codes
  - [x] Admin analytics â€?consistent codes
  - [x] Admin API keys â€?finish structured codes
    - [x] updateAPIKeyStatusHandler â€?replace writeErrorResponse; add INVALID_STATUS/INTERNAL_ERROR codes
    - [x] regenerateAPIKeyHandler â€?replace writeErrorResponse; add API_KEY_NOT_FOUND/INTERNAL_ERROR; structured warnings on policy sync
    - [x] downloadAPIKeyHandler â€?replace writeErrorResponse; return API_KEY_NOT_FOUND with expiry hint
- [x] Validation helpers
  - [x] `internal/presentation/http/validation` for common patterns:
    - [x] Pagination (page, limit bounds)
    - [x] Role/status validators (reuse `apikey.ValidatePermissions` where applicable)
    - [ ] File type/extension mapping
  - [x] Uniformly return `VALIDATION_ERROR` with `details` per field

### B. Repository & Usecase Enhancements

- [ ] API Key update â€?repo returns updated entity (optional optimization)
  - [ ] Repo: `UpdateReturning(id, upd) (*entities.APIKey, error)`
  - [ ] Usecase: consume and return updated entity to handler
  - [ ] Handler: eliminate extra GetByID
- [ ] File repository
  - [ ] Add DB method for file versions pagination (optionally)
  - [ ] Add soft delete / restore / purge batch APIs (optional)

### F. API Key Expiry Semantics

- [ ] Support clearing expiry via update handler
  - [ ] Accept expires_at: "" (empty string) or expires_at: null to clear expiration
  - [ ] Wire through usecase to set expires_at to NULL in DB
  - [ ] Add tests for set, update, and clear flows
### C. Controllers & DI Wiring

- [ ] Centralize all controllers in DI container
  - [ ] Add APIKey controller (optional) and move logic from handlers gradually
  - [ ] Update route wiring to pass DI controllers (stop perâ€‘request constructors)

### D. Observability & Security

- [ ] Request ID
  - [x] Middleware added â€?ensure `request_id` attached to all structured error responses
  - [ ] Add `request_id` to structured logs (logger wrappers)
  - [ ] Structured logging
  - [ ] Add log helpers that include `code`, `request_id`, `actor`
  - [ ] Admin endpoints logging
    - [x] listAPIKeysHandler â€?InfoCtx on success including `count`
    - [x] listUsersHandler â€?InfoCtx on success including `count/page/limit`
    - [x] updateAPIKeyStatusHandler â€?WarnCtx/ErrorCtx on failures; InfoCtx on success
    - [x] regenerateAPIKeyHandler â€?WarnCtx/ErrorCtx for policy sync; InfoCtx on success
    - [x] downloadAPIKeyHandler â€?WarnCtx on expired/missing temp key; InfoCtx on success
    - [x] Analytics handlers â€?InfoCtx on success; WarnCtx/ErrorCtx on validation/DB errors
  - [x] Web/file handlers logging â€?InfoCtx on success; WarnCtx/ErrorCtx on errors (upload/list/versions/delete/restore/purge/recycle-bin)
- [ ] Rate limiting (optional)
  - [ ] Middleware with config toggles (per IP and/or per route)
- [ ] Upload limits (followâ€‘up)
  - [ ] Enforce content type, MIME sniffing for upload

### E. Server/Middleware Test Suite (existing failures)

- [ ] Investigate failing server/middleware tests
  - [ ] CORS header expectations vs. new middlewares order
  - [ ] HTTPS redirect test expecting 401 vs. 301 (adjust test harness to set `DISABLE_HTTPS_REDIRECT=true` like integration tests)
  - [ ] Middleware suite duplicates (redeclared test names) â€?deduplicate/rename

---

## Database & Migration

- [ ] Add migration scripts if schema evolves (e.g., new index for files filtering)
- [ ] Ensure nonâ€‘blocking migrations for prod data (use transactional PRAGMA changes)

---

## Frontend Work

### A. Pagination & UX
 
 - [x] Files list â€?use `{count, page, limit}` to render pagination UI
 - [x] Persist filters (fileType) in URL query
 - [x] Prevalidate uploads (size/type) clientâ€‘side; map server error codes to userâ€‘friendly toasts

### B. Error Handling

- [x] Centralize API error handling
  - [x] Map codes to messages (INVALID_FILE_TYPE, PAYLOAD_TOO_LARGE, USER_NOT_FOUND, etc.)
  - [x] Display `request_id` for support (e.g., appended in error toast)

### C. Admin â€?API Keys & Users
- [x] Add utils helper: isoToDatetimeLocal + datetimeLocalToISO for datetime-local inputs (used by admin edit dialog)
- [x] Prepare Clear expiry UI in edit dialog (disabled until backend supports clearing)

- [x] API Key update dialog â€?reflect updated fields immediately (UI implemented; updates state from response)
- [x] API Key regenerate flow â€?show oneâ€‘time key with download link; warn on loss (UI implemented in web admin; includes copy + download)
- [x] Admin users â€?respond to structured codes in UI

### D. Admin â€?Analytics & Audit Logs

- [x] Replace remaining `fetch` with `apiClient.request` in analytics charts and audit logs panel; unify toasts via `mapApiErrorToMessage` (export now uses `apiClient.downloadBinary` helper)

---

## Testing Plan

### A. Unit Tests

- [x] APIKeyUseCase: Update (permissions + policy refresh), Regenerate (via create/disable combo)
- [x] FileUseCase: ListWithPagination (count/page math)
- [ ] UserUseCase: BuildMePayload â€?covers roles/quotas/two_fa fields
- [ ] Validation helpers: perâ€‘field `details`
- [ ] Error mapping: tests for `writeErrorWithCode`

### B. Integration Tests

- [ ] API key endpoints (create, update, regenerate, list, get)
- [ ] Files endpoints (list with pagination & filter, delete/restore/purge)
- [ ] Admin user endpoints (approve/suspend/role update)
- [ ] Error contract verification (codes + `request_id` in errors)
- [ ] Sweep legacy endpoints in tests to current routes; remove/replace where no equivalent exists
- [x] Analytics validation errors (custom range invalid/too long/ordering) with `details.request_id` and `details.max_days` asserts

### C. E2E/Smoke (Optional)

- [ ] Login â†?2FA: setup/verify; validate enforced flows
- [ ] Upload file â†?list versions â†?restore/purge roundâ€‘trip
- [ ] API key create â†?use â†?regenerate/disable

### D. Test Environment

- [x] Ensure tests set/unset `DISABLE_HTTPS_REDIRECT` where needed (server/middleware)
- [ ] Seed DB users/roles consistently via helpers

---

## DevOps & Deployment

- [ ] Config docs: update `configs/app.yaml.example` with new toggles (rate limiting, CORS)
- [ ] CI pipeline: `go vet`, `staticcheck`, unit + integration suites, race detector for critical packages
- [ ] Release checklist: DB backups, rollback steps, feature flags for new error contract

---

## Whatâ€™s Next (Optional)

- Admin logging:
  - [ ] Add InfoCtx to list API keys/users on success with counts.
  - [ ] Add WarnCtx/ErrorCtx to other admin endpoints (`downloadAPIKeyHandler`, `regenerateAPIKeyHandler`, `updateAPIKeyStatusHandler`) where helpful.
- Integration tests:
  - [ ] Sweep all legacy endpoints to current routes; where no equivalent exists, remove/replace.
  - [x] Normalize CORS and HTTPS Redirect tests to set/unset `DISABLE_HTTPS_REDIRECT` at test start where applicable.
- Frontend:
  - [ ] Convert remaining admin components (analytics, audit logs panel) from `fetch` to `apiClient.request` and unify toasts.

---

## API Error Codes (Reference)

Common codes to standardize:

- VALIDATION_ERROR â€?Input parsing/validation failed
- INVALID_FILE_TYPE â€?Unknown/unsupported fileType
- INVALID_FILE_FORMAT â€?Extension/type mismatch
- PAYLOAD_TOO_LARGE â€?Upload exceeds limit
- USER_NOT_FOUND â€?Target user does not exist
- API_KEY_NOT_FOUND â€?Target API key does not exist
- INVALID_PERMISSION â€?Invalid API key permissions
- INVALID_STATUS â€?Invalid status field
- FILE_NOT_FOUND â€?File not found
- INTERNAL_ERROR â€?Generic server error

---

## How to Continue (Suggested Order)

1) Error rollout: finish structured codes across admin user + file endpoints
2) Frontend: plug pagination UI + error code handling with request_id surfacing
3) Observability: add request_id to logs; standardize log helpers
4) Tests: stabilize middleware/server suites, then add integration tests listed above
5) Optional: repo.UpdateReturning â†?usecase/handler returns updated entity without extra GetByID

---

## Commands & Tips

- Build: `go build ./...`
- Unit tests (new suites): `go test ./tests/usecases -v`
- Full tests: `DISABLE_HTTPS_REDIRECT=true go test ./...`
- Lint (suggestion): add `golangci-lint run` to CI

---

## Ownership & Review

- Backend: repositories, usecases, middleware â€?(Owner: Backend)
- Frontend: pagination/error UX â€?(Owner: Frontend)
- Tests: unit/integration â€?(Owner: QA/Backend)
- DevOps: CI, observability â€?(Owner: DevOps)

> Keep changes incremental; aim for small PRs per endpoint/per area.



