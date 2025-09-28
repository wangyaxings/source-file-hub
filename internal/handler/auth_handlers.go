package handler

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"secure-file-hub/internal/application/usecases"
	"secure-file-hub/internal/auth"
	"secure-file-hub/internal/authz"
	"secure-file-hub/internal/database"

	ab "github.com/aarondl/authboss/v3"
)

// Authentication utility functions
func loadUserFromDatabaseImpl(username string) (*auth.User, error) {
	db := database.GetDatabase()
	if db == nil {
		return nil, fmt.Errorf("database not available")
	}

	appUser, err := db.GetUser(username)
	if err != nil {
		return nil, err
	}

	return &auth.User{
		Username:     appUser.Username,
		Role:         appUser.Role,
		Email:        appUser.Email,
		TwoFAEnabled: appUser.TwoFAEnabled,
	}, nil
}

func checkUserStatusImpl(username string) error {
	db := database.GetDatabase()
	if db == nil {
		return fmt.Errorf("database not available")
	}

	userRole, err := db.GetUserRole(username)
	if err != nil {
		defaultRole := &database.UserRole{
			UserID: username,
			Role:   "viewer",
			Status: "active",
		}
		if err := db.CreateOrUpdateUserRole(defaultRole); err != nil {
			log.Printf("Warning: Failed to create default role for %s: %v", username, err)
		}
		return nil
	}

	if userRole.Status == "suspended" {
		return fmt.Errorf("ACCOUNT_SUSPENDED")
	}

	if userRole.Status == "pending" {
		userRole.Status = "active"
		if err := db.CreateOrUpdateUserRole(userRole); err != nil {
			log.Printf("Warning: Failed to activate user %s: %v", username, err)
		}
	}

	return nil
}

// Authentication handler implementations
func handleMe(w http.ResponseWriter, r *http.Request) {
	if username, ok := ab.GetSession(r, ab.SessionKey); ok && username != "" {
		user, err := loadUserFromDatabaseImpl(username)
		if err != nil {
			writeErrorWithCode(w, http.StatusUnauthorized, "USER_NOT_FOUND", "User not found in database")
			return
		}

		if err := checkUserStatusImpl(user.Username); err != nil {
			writeErrorWithCode(w, http.StatusUnauthorized, "ACCOUNT_SUSPENDED", err.Error())
			return
		}

		if db := database.GetDatabase(); db != nil {
			_ = db.SetUserLastLogin(user.Username, time.Now())
		}

		payload := usecases.NewUserUseCase().BuildMePayload(user.Username, user.Role, user.TwoFAEnabled)
		writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: map[string]interface{}{
			"user": payload,
		}})
		return
	}

	writeErrorWithCode(w, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
}

func handleCheckPermission(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Resource string `json:"resource"`
		Action   string `json:"action"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", invalidRequestBody, map[string]interface{}{"field": "body", "error": err.Error()})
		return
	}

	userCtx := r.Context().Value("user")
	if userCtx == nil {
		writeErrorWithCode(w, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	user, ok := userCtx.(*auth.User)
	if !ok {
		writeErrorWithCode(w, http.StatusUnauthorized, "UNAUTHORIZED", "Invalid user context")
		return
	}

	allowed, err := authz.CheckPermission(user.Role, req.Resource, req.Action)
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to check permission")
		return
	}

	writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"success":  true,
		"allowed":  allowed,
		"resource": req.Resource,
		"action":   req.Action,
		"role":     user.Role,
	})
}

func handleCheckMultiplePermissions(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Permissions []struct {
			Resource string `json:"resource"`
			Action   string `json:"action"`
		} `json:"permissions"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", invalidRequestBody, map[string]interface{}{"field": "body", "error": err.Error()})
		return
	}

	userCtx := r.Context().Value("user")
	if userCtx == nil {
		writeErrorWithCode(w, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	user, ok := userCtx.(*auth.User)
	if !ok {
		writeErrorWithCode(w, http.StatusUnauthorized, "UNAUTHORIZED", "Invalid user context")
		return
	}

	resultMap := make(map[string]bool, len(req.Permissions))

	for _, perm := range req.Permissions {
		allowed, err := authz.CheckPermission(user.Role, perm.Resource, perm.Action)
		if err != nil {
			writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to check permission")
			return
		}
		key := perm.Resource + ":" + perm.Action
		resultMap[key] = allowed
	}

	writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"results": resultMap,
		"role":    user.Role,
	})
}

func handleGetDefaultUsers(w http.ResponseWriter, r *http.Request) {
	users := auth.GetDefaultUsers()

	response := Response{
		Success: true,
		Message: "Default test users list",
		Data: map[string]interface{}{
			"users": users,
			"note":  "These are pre-configured test users, you can use these accounts for login testing",
		},
	}

	writeJSONResponse(w, http.StatusOK, response)
}
