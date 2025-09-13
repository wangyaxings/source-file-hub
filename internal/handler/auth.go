package handler

import (
	"encoding/json"
	"net/http"
	"secure-file-hub/internal/auth"
	"secure-file-hub/internal/authz"
)

// PermissionCheckRequest represents a permission check request
type PermissionCheckRequest struct {
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

// PermissionCheckResponse represents a permission check response
type PermissionCheckResponse struct {
	Success bool   `json:"success"`
	Allowed bool   `json:"allowed"`
	Error   string `json:"error,omitempty"`
}

// MultiplePermissionCheckRequest represents multiple permission check request
type MultiplePermissionCheckRequest struct {
	Permissions []PermissionCheckRequest `json:"permissions"`
}

// MultiplePermissionCheckResponse represents multiple permission check response
type MultiplePermissionCheckResponse struct {
	Success bool            `json:"success"`
	Results map[string]bool `json:"results"`
	Error   string          `json:"error,omitempty"`
}

// checkPermissionHandler handles single permission check requests
func checkPermissionHandler(w http.ResponseWriter, r *http.Request) {
	var req PermissionCheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Get user from context
	userCtx := r.Context().Value("user")
	if userCtx == nil {
		http.Error(w, "UNAUTHORIZED", http.StatusUnauthorized)
		return
	}
	user, ok := userCtx.(*auth.User)
	if !ok {
		http.Error(w, "UNAUTHORIZED", http.StatusUnauthorized)
		return
	}

	// Check permission using Casbin
	allowed, err := authz.CheckPermission(user.Role, req.Resource, req.Action)
	if err != nil {
		response := PermissionCheckResponse{
			Success: false,
			Allowed: false,
			Error:   err.Error(),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	response := PermissionCheckResponse{
		Success: true,
		Allowed: allowed,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// checkMultiplePermissionsHandler handles multiple permission check requests
func checkMultiplePermissionsHandler(w http.ResponseWriter, r *http.Request) {
	var req MultiplePermissionCheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Get user from context
	userCtx := r.Context().Value("user")
	if userCtx == nil {
		http.Error(w, "UNAUTHORIZED", http.StatusUnauthorized)
		return
	}
	user, ok := userCtx.(*auth.User)
	if !ok {
		http.Error(w, "UNAUTHORIZED", http.StatusUnauthorized)
		return
	}

	// Check all permissions
	results := make(map[string]bool)
	for _, perm := range req.Permissions {
		key := perm.Resource + ":" + perm.Action
		allowed, err := authz.CheckPermission(user.Role, perm.Resource, perm.Action)
		if err != nil {
			results[key] = false
		} else {
			results[key] = allowed
		}
	}

	response := MultiplePermissionCheckResponse{
		Success: true,
		Results: results,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// TOTP 2FA handlers

func startTOTPHandler(w http.ResponseWriter, r *http.Request) {
	userCtx := r.Context().Value("user")
	if userCtx == nil {
		writeErrorResponse(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	u, ok := userCtx.(*auth.User)
	if !ok {
		writeErrorResponse(w, http.StatusUnauthorized, "Invalid user context")
		return
	}

	secret, otpauthURL, err := auth.StartTOTPSetup(u.Username, "Secure File Hub")
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to start TOTP setup: "+err.Error())
		return
	}

	writeJSONResponse(w, http.StatusOK, Response{
		Success: true,
		Data: map[string]string{
			"secret":      secret,
			"otpauth_url": otpauthURL,
		},
	})
}

func enableTOTPHandler(w http.ResponseWriter, r *http.Request) {
	userCtx := r.Context().Value("user")
	if userCtx == nil {
		writeErrorResponse(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	u, ok := userCtx.(*auth.User)
	if !ok {
		writeErrorResponse(w, http.StatusUnauthorized, "Invalid user context")
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid request format")
		return
	}

	if err := auth.EnableTOTP(u.Username, req.Code); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Failed to enable TOTP: "+err.Error())
		return
	}

	writeJSONResponse(w, http.StatusOK, Response{Success: true, Message: "TOTP enabled successfully"})
}

func disableTOTPHandler(w http.ResponseWriter, r *http.Request) {
	userCtx := r.Context().Value("user")
	if userCtx == nil {
		writeErrorResponse(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	u, ok := userCtx.(*auth.User)
	if !ok {
		writeErrorResponse(w, http.StatusUnauthorized, "Invalid user context")
		return
	}

	if err := auth.DisableTOTP(u.Username); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to disable TOTP: "+err.Error())
		return
	}

	writeJSONResponse(w, http.StatusOK, Response{Success: true, Message: "TOTP disabled successfully"})
}
