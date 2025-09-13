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

// TOTP 2FA handlers removed. 2FA is handled by Authboss under /api/v1/web/auth/ab/2fa/totp/*
