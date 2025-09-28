package handler

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"secure-file-hub/internal/apikey"
	"secure-file-hub/internal/auth"
	"secure-file-hub/internal/authz"
	"secure-file-hub/internal/database"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

// Admin handler functions
func handleAdminListAPIKeys(w http.ResponseWriter, r *http.Request) {
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", "databaseNotAvailable")
		return
	}
	keys, err := db.GetAllAPIKeys()
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: map[string]interface{}{
		"keys":  keys,
		"count": len(keys),
	}})
}

func handleAdminCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Role        string   `json:"role"`
		Permissions []string `json:"permissions"`
		ExpiresAt   string   `json:"expires_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", invalidRequestBody)
		return
	}
	if req.Name == "" || req.Role == "" {
		writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", "name and role are required")
		return
	}
	if !apikey.ValidatePermissions(req.Permissions) {
		writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid permissions")
		return
	}
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", "databaseNotAvailable")
		return
	}

	existingKeys, err := db.GetAllAPIKeys()
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to check existing API keys")
		return
	}
	for _, key := range existingKeys {
		if key.Name == req.Name {
			writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", "API key name already exists")
			return
		}
	}

	fullKey, keyHash, err := apikey.GenerateAPIKey("sk")
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to generate API key")
		return
	}

	var expiresAtPtr *time.Time
	if strings.TrimSpace(req.ExpiresAt) != "" {
		if t, err := time.Parse(time.RFC3339, req.ExpiresAt); err == nil {
			expiresAtPtr = &t
		}
	}

	rec := &database.APIKey{
		ID:          apikey.GenerateAPIKeyID(),
		Name:        req.Name,
		Description: req.Description,
		KeyHash:     keyHash,
		Role:        req.Role,
		Permissions: req.Permissions,
		Status:      "active",
		ExpiresAt:   expiresAtPtr,
		UsageCount:  0,
	}
	if err := db.CreateAPIKey(rec); err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to save API key")
		return
	}

	_ = authz.CreateAPIKeyPolicies(rec.ID, rec.Permissions)

	rec.Key = fullKey
	writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: map[string]interface{}{
		"api_key":      rec,
		"download_url": "",
	}})
}

func handleAdminUpdateAPIKeyStatus(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var req struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || id == "" || req.Status == "" {
		writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", "id and status required")
		return
	}
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", "databaseNotAvailable")
		return
	}
	if err := db.UpdateAPIKeyStatus(id, req.Status); err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSONResponse(w, http.StatusOK, Response{Success: true, Message: "status updated"})
}

func handleAdminUpdateAPIKey(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if id == "" {
		writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", "id required")
		return
	}

	req, err := parseUpdateAPIKeyRequest(r)
	if err != nil {
		writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", "databaseNotAvailable")
		return
	}

	expiresAt, clearExpiry, err := parseExpiresAt(req.ExpiresAt)
	if err != nil {
		writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	if err := validateUpdateAPIKeyRequest(req, id, db); err != nil {
		writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	if err := updateAPIKeyInDatabase(db, id, req, expiresAt, clearExpiry); err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	response := buildUpdateAPIKeyResponse(db, id)
	writeJSONResponse(w, http.StatusOK, response)
}

func parseUpdateAPIKeyRequest(r *http.Request) (struct {
	Name        *string   `json:"name"`
	Description *string   `json:"description"`
	Permissions *[]string `json:"permissions"`
	ExpiresAt   *string   `json:"expires_at"`
}, error) {
	var req struct {
		Name        *string   `json:"name"`
		Description *string   `json:"description"`
		Permissions *[]string `json:"permissions"`
		ExpiresAt   *string   `json:"expires_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return req, fmt.Errorf("invalid request body")
	}
	return req, nil
}

func parseExpiresAt(expiresAtStr *string) (*time.Time, bool, error) {
	if expiresAtStr == nil {
		return nil, false, nil
	}

	if strings.TrimSpace(*expiresAtStr) == "" {
		return nil, true, nil
	}

	t, err := time.Parse(time.RFC3339, *expiresAtStr)
	if err != nil {
		return nil, false, fmt.Errorf("invalid expires_at format")
	}

	return &t, false, nil
}

func validateUpdateAPIKeyRequest(req struct {
	Name        *string   `json:"name"`
	Description *string   `json:"description"`
	Permissions *[]string `json:"permissions"`
	ExpiresAt   *string   `json:"expires_at"`
}, id string, db *database.Database) error {
	if req.Permissions != nil {
		if !apikey.ValidatePermissions(*req.Permissions) {
			return fmt.Errorf("invalid permissions")
		}
	}

	if req.Name != nil {
		existingKeys, err := db.GetAllAPIKeys()
		if err != nil {
			return fmt.Errorf("failed to check existing API keys")
		}
		for _, key := range existingKeys {
			if key.ID != id && key.Name == *req.Name {
				return fmt.Errorf("API key name already exists")
			}
		}
	}

	return nil
}

func updateAPIKeyInDatabase(db *database.Database, id string, req struct {
	Name        *string   `json:"name"`
	Description *string   `json:"description"`
	Permissions *[]string `json:"permissions"`
	ExpiresAt   *string   `json:"expires_at"`
}, expiresAt *time.Time, clearExpiry bool) error {
	if err := db.UpdateAPIKeyFields(id, req.Name, req.Description, req.Permissions, expiresAt, clearExpiry); err != nil {
		return err
	}

	if req.Permissions != nil {
		_ = authz.RemoveAllAPIKeyPolicies(id)
		_ = authz.CreateAPIKeyPolicies(id, *req.Permissions)
	}

	return nil
}

func buildUpdateAPIKeyResponse(db *database.Database, id string) Response {
	rec, err := db.GetAPIKeyByID(id)
	if err != nil {
		return Response{Success: true}
	}
	return Response{Success: true, Data: map[string]interface{}{"api_key": rec}}
}

func handleAdminDeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if id == "" {
		writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", "id required")
		return
	}
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", "databaseNotAvailable")
		return
	}
	_ = authz.RemoveAllAPIKeyPolicies(id)
	if err := db.DeleteAPIKey(id); err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSONResponse(w, http.StatusOK, Response{Success: true, Message: "deleted"})
}

func handleAdminUsageLogs(w http.ResponseWriter, r *http.Request) {
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", "databaseNotAvailable")
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	offset, _ := strconv.Atoi(q.Get("offset"))
	if offset < 0 {
		offset = 0
	}

	filters := database.APIUsageLogFilters{
		UserID:   q.Get("userId"),
		FileID:   q.Get("fileId"),
		APIKey:   q.Get("apiKey"),
		Method:   q.Get("method"),
		Endpoint: q.Get("endpoint"),
		TimeFrom: q.Get("timeFrom"),
		TimeTo:   q.Get("timeTo"),
	}

	if filters.APIKey != "" || filters.Method != "" || filters.Endpoint != "" || filters.TimeFrom != "" || filters.TimeTo != "" || filters.UserID != "" || filters.FileID != "" {
		logs, err := db.GetAPIUsageLogsFiltered(filters, limit, offset)
		if err != nil {
			writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
			return
		}

		totalCount, err := db.GetAPIUsageLogsCountFiltered(filters)
		if err != nil {
			writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
			return
		}

		writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: map[string]interface{}{"logs": logs, "items": logs, "count": totalCount}})
	} else {

		logs, err := db.GetAPIUsageLogs("", "", limit, offset)
		if err != nil {
			writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
			return
		}

		totalCount, err := db.GetAPIUsageLogsCount("", "")
		if err != nil {
			writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
			return
		}

		writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: map[string]interface{}{"logs": logs, "items": logs, "count": totalCount}})
	}
}

func handleAdminAnalytics(w http.ResponseWriter, r *http.Request) {
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", "databaseNotAvailable")
		return
	}
	q := r.URL.Query()

	now := time.Now().UTC()
	start := now.Add(-7 * 24 * time.Hour)
	end := now

	if s := strings.TrimSpace(getFirstNonEmpty(q.Get("start"), q.Get("startDate"))); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			start = t
		}
	}
	if e := strings.TrimSpace(getFirstNonEmpty(q.Get("end"), q.Get("endDate"))); e != "" {
		if t, err := time.Parse(time.RFC3339, e); err == nil {
			end = t
		}
	}

	if tr := strings.TrimSpace(q.Get("timeRange")); tr != "" {
		switch strings.ToLower(tr) {
		case "24h":
			start = now.Add(-24 * time.Hour)
		case "7d":
			start = now.Add(-7 * 24 * time.Hour)
		case "30d":
			start = now.Add(-30 * 24 * time.Hour)
		}
	}

	apiKeyFilter := strings.TrimSpace(getFirstNonEmpty(q.Get("api_key_id"), q.Get("apiKey")))
	userFilter := strings.TrimSpace(getFirstNonEmpty(q.Get("user_id"), q.Get("user")))
	data, err := db.GetAnalyticsData(database.AnalyticsTimeRange{Start: start, End: end}, apiKeyFilter, userFilter)
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: data})
}

func getFirstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func handleAdminGetUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["id"]

	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "databaseNotInitialized")
		return
	}

	user, err := db.GetUser(userID)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			writeErrorWithCode(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found")
		} else {
			writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get user: "+err.Error())
		}
		return
	}

	userRole, err := db.GetUserRole(userID)
	if err != nil {
		userRole = &database.UserRole{
			UserID: userID,
			Role:   "viewer",
			Status: "active",
		}
	}

	response := Response{
		Success: true,
		Data: map[string]interface{}{
			"id":            user.Username,
			"username":      user.Username,
			"email":         user.Email,
			"role":          userRole.Role,
			"status":        userRole.Status,
			"twofa_enabled": user.TwoFAEnabled,
			"last_login":    user.LastLoginAt,
			"created_at":    user.CreatedAt,
		},
	}

	writeJSONResponse(w, http.StatusOK, response)
}

func handleAdminListUsers(w http.ResponseWriter, r *http.Request) {
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", "databaseNotAvailable")
		return
	}

	users, err := db.ListUsers()
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	queryParams := parseUserListQueryParams(r)
	filteredUsers := filterAndPaginateUsers(users, queryParams, db)
	response := buildUserListResponse(filteredUsers, queryParams)

	writeJSONResponse(w, http.StatusOK, response)
}

type userListQueryParams struct {
	query        string
	statusFilter string
	page         int
	limit        int
}

func parseUserListQueryParams(r *http.Request) userListQueryParams {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	statusFilter := strings.TrimSpace(r.URL.Query().Get("status"))
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))

	if page <= 0 {
		page = 1
	}
	if limit <= 0 {
		limit = 20
	}

	return userListQueryParams{
		query:        q,
		statusFilter: statusFilter,
		page:         page,
		limit:        limit,
	}
}

type userRow struct {
	UserID    string `json:"user_id"`
	Email     string `json:"email,omitempty"`
	Role      string `json:"role"`
	Status    string `json:"status"`
	TwoFA     bool   `json:"two_fa"`
	LastLogin string `json:"last_login,omitempty"`
}

func filterAndPaginateUsers(users []database.AppUser, params userListQueryParams, db *database.Database) []userRow {
	list := make([]userRow, 0, len(users))

	for _, u := range users {
		row := buildUserRow(u, db)
		if !matchesUserFilters(row, params) {
			continue
		}
		list = append(list, row)
	}

	return paginateUserList(list, params)
}

func buildUserRow(user database.AppUser, db *database.Database) userRow {
	ur, _ := db.GetUserRole(user.Username)
	row := userRow{
		UserID: user.Username,
		Email:  user.Email,
		Role:   user.Role,
		Status: "active",
		TwoFA:  user.TwoFAEnabled,
	}

	if ur != nil && ur.Status != "" {
		row.Status = ur.Status
	}

	if user.LastLoginAt != nil {
		row.LastLogin = user.LastLoginAt.Format(time.RFC3339)
	}

	return row
}

func matchesUserFilters(row userRow, params userListQueryParams) bool {
	if params.query != "" {
		query := strings.ToLower(params.query)
		if !strings.Contains(strings.ToLower(row.UserID), query) &&
			!strings.Contains(strings.ToLower(row.Email), query) {
			return false
		}
	}

	if params.statusFilter != "" && params.statusFilter != "all" && row.Status != params.statusFilter {
		return false
	}

	return true
}

func paginateUserList(list []userRow, params userListQueryParams) []userRow {
	total := len(list)
	start := (params.page - 1) * params.limit
	if start > total {
		start = total
	}
	end := start + params.limit
	if end > total {
		end = total
	}

	if start >= total {
		return []userRow{}
	}

	return list[start:end]
}

func buildUserListResponse(filteredUsers []userRow, params userListQueryParams) Response {
	total := len(filteredUsers)
	return Response{
		Success: true,
		Data: map[string]interface{}{
			"users": filteredUsers,
			"count": total,
			"total": total,
			"page":  params.page,
			"limit": params.limit,
		},
	}
}

func handleAdminCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username  string `json:"username"`
		Email     string `json:"email"`
		Role      string `json:"role"`
		MustReset bool   `json:"must_reset"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" {
		writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", "username required")
		return
	}
	if req.Role == "" {
		req.Role = "viewer"
	}
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", "databaseNotAvailable")
		return
	}
	if _, err := db.GetUser(req.Username); err == nil {
		writeErrorWithCode(w, http.StatusBadRequest, "CONFLICT", "user already exists")
		return
	}

	tmp, _ := apikey.GenerateRandomString(16)

	hashed, _ := bcrypt.GenerateFromPassword([]byte(tmp), bcrypt.DefaultCost)
	if err := db.CreateUser(&database.AppUser{Username: req.Username, Email: req.Email, PasswordHash: string(hashed), Role: req.Role}); err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	_ = db.CreateOrUpdateUserRole(&database.UserRole{UserID: req.Username, Role: req.Role, Status: "pending", QuotaDaily: -1, QuotaMonthly: -1})
	writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: map[string]interface{}{
		"initial_password": tmp,
	}})
}

func handleAdminApproveUser(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["id"]
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", "databaseNotAvailable")
		return
	}
	ur, _ := db.GetUserRole(username)
	if ur == nil {
		ur = &database.UserRole{UserID: username, Role: "viewer"}
	}
	ur.Status = "active"
	if err := db.CreateOrUpdateUserRole(ur); err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSONResponse(w, http.StatusOK, Response{Success: true})
}

func handleAdminSuspendUser(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["id"]
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", "databaseNotAvailable")
		return
	}
	ur, _ := db.GetUserRole(username)
	if ur == nil {
		ur = &database.UserRole{UserID: username, Role: "viewer"}
	}
	ur.Status = "suspended"
	if err := db.CreateOrUpdateUserRole(ur); err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSONResponse(w, http.StatusOK, Response{Success: true})
}

func handleAdminEnable2FA(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["id"]
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", "databaseNotAvailable")
		return
	}
	if err := db.SetUser2FA(username, true, ""); err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSONResponse(w, http.StatusOK, Response{Success: true})
}

func handleAdminDisable2FA(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["id"]
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", "databaseNotAvailable")
		return
	}
	if err := db.SetUser2FA(username, false, ""); err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSONResponse(w, http.StatusOK, Response{Success: true})
}

func handleAdminResetPassword(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["id"]
	if username == "" {
		writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", "id required")
		return
	}
	tmp, _ := apikey.GenerateRandomString(16)
	if err := auth.SetPassword(username, tmp); err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: map[string]interface{}{"username": username, "temporary_password": tmp}})
}

func handleAdminPatchUser(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["id"]
	if username == "" {
		writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", "id required")
		return
	}
	var req struct {
		Role         *string `json:"role"`
		TwoFAEnabled *bool   `json:"twofa_enabled"`
		Reset2FA     *bool   `json:"reset_2fa"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", invalidRequestBody)
		return
	}
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", "databaseNotAvailable")
		return
	}

	if req.Role != nil {
		appUser, err := db.GetUser(username)
		if err == nil {
			appUser.Role = *req.Role
			_ = db.UpdateUser(appUser)
		}
		ur, _ := db.GetUserRole(username)
		if ur == nil {
			ur = &database.UserRole{UserID: username}
		}
		ur.Role = *req.Role
		_ = db.CreateOrUpdateUserRole(ur)
	}
	if req.TwoFAEnabled != nil {
		_ = db.SetUser2FA(username, *req.TwoFAEnabled, "")
	}
	if req.Reset2FA != nil && *req.Reset2FA {
		_ = db.SetUser2FA(username, false, "")
	}
	writeJSONResponse(w, http.StatusOK, Response{Success: true})
}

// CleanupExpiredTempKeys cleans up expired temporary keys
func CleanupExpiredTempKeys() {
	log.Printf("CleanupExpiredTempKeys: placeholder implementation - no expired keys to clean")
}
