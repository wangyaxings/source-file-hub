package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	ab "github.com/aarondl/authboss/v3"
	"github.com/aarondl/authboss/v3/otp/twofactor/totp2fa"
	"github.com/pquerna/otp/totp"

	"secure-file-hub/internal/auth"
)

// TOTPJSONShimMiddleware provides JSON responses for Authboss TOTP setup/confirm endpoints.
// It ensures frontend can retrieve the secret even when Authboss returns empty bodies or redirects.
func TOTPJSONShimMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isTOTPPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Session safety: clear conflicting sessions
		clearConflictingSession(w, r)

		if !wantsJSON(r) {
			next.ServeHTTP(w, r)
			return
		}

		handleTOTPRequest(w, r, next)
	})
}

// isTOTPPath checks if the request path is a TOTP endpoint
func isTOTPPath(path string) bool {
	return strings.HasPrefix(path, "/api/v1/web/auth/ab/2fa/totp/")
}

// wantsJSON checks if the client prefers JSON responses
func wantsJSON(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "application/json") ||
		strings.Contains(r.Header.Get("Content-Type"), "application/json")
}

// handleTOTPRequest routes TOTP requests to appropriate handlers
func handleTOTPRequest(w http.ResponseWriter, r *http.Request, next http.Handler) {
	path := r.URL.Path

	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/setup"):
		handleTOTPSetup(w, r)
	case r.Method == http.MethodGet && strings.HasSuffix(path, "/confirm"):
		handleTOTPConfirm(w, r)
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/validate"):
		handleTOTPValidate(w, r)
	default:
		next.ServeHTTP(w, r)
	}
}

func buildOTPAuthURL(issuer, label, secret string) string {
	return "otpauth://totp/" + url.PathEscape(issuer) + ":" + url.PathEscape(label) +
		"?issuer=" + url.QueryEscape(issuer) + "&secret=" + url.QueryEscape(secret)
}

const (
	contentTypeJSON = "application/json"
	contentType     = "Content-Type"
)

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set(contentType, contentTypeJSON)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// getUserInfo extracts user information from request context
func getUserInfo(r *http.Request) (label string, issuer string) {
	issuer = "Secure File Hub"
	if auth.AB != nil && auth.AB.Config.Modules.TOTP2FAIssuer != "" {
		issuer = auth.AB.Config.Modules.TOTP2FAIssuer
	}

	label = "user"
	if uctx := r.Context().Value("user"); uctx != nil {
		if u, ok := uctx.(*auth.User); ok {
			if u.Email != "" {
				label = u.Email
			} else if u.Username != "" {
				label = u.Username
			}
		}
	}
	return label, issuer
}

// ensureAuthenticatedSession checks if user has valid authenticated session
func ensureAuthenticatedSession(r *http.Request) (string, bool) {
	if pid, ok := ab.GetSession(r, ab.SessionKey); ok && pid != "" {
		return pid, true
	}
	return "", false
}

// clearConflictingSession removes conflicting full-auth session when pending PID differs
func clearConflictingSession(w http.ResponseWriter, r *http.Request) {
	if currentPID, okCur := ab.GetSession(r, ab.SessionKey); okCur && currentPID != "" {
		if pendingPID, okPend := ab.GetSession(r, totp2fa.SessionTOTPPendingPID); okPend && pendingPID != "" {
			if currentPID != pendingPID {
				ab.DelSession(w, ab.SessionKey)
				ab.DelSession(w, ab.Session2FA)
			}
		}
	}
}

// handleTOTPViolations manages TOTP validation failures and cooldowns
func handleTOTPViolations(w http.ResponseWriter, r *http.Request, attempts int) int {
	const maxAttempts = 5
	const cooldownSeconds = 5

	newAttempts := attempts + 1
	ab.PutSession(w, "totp_attempts", strconv.Itoa(newAttempts))

	// Apply cooldown
	if cooldownSeconds > 0 {
		until := time.Now().Add(time.Duration(cooldownSeconds) * time.Second).Unix()
		ab.PutSession(w, "totp_cooldown_until", strconv.FormatInt(until, 10))
	}

	// Check if max attempts reached
	if newAttempts >= maxAttempts {
		if auth.AB != nil {
			ab.DelAllSession(w, auth.AB.Config.Storage.SessionStateWhitelistKeys)
			ab.DelKnownSession(w)
			ab.DelKnownCookie(w)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"success": false,
			"error":   "Too many 2FA failures. Please login again.",
			"code":    "2FA_TOO_MANY_ATTEMPTS",
		})
		return -1 // Signal that response has been sent
	}

	return newAttempts
}

// resetTOTPSessionData clears TOTP-related session data after successful validation
func resetTOTPSessionData(w http.ResponseWriter, pid string) {
	ab.DelSession(w, "totp_attempts")
	ab.DelSession(w, "totp_cooldown_until")
	ab.PutSession(w, ab.SessionKey, pid)
	ab.PutSession(w, ab.Session2FA, "totp")
	ab.DelSession(w, ab.SessionHalfAuthKey)
	ab.DelSession(w, totp2fa.SessionTOTPPendingPID)
	ab.DelSession(w, totp2fa.SessionTOTPSecret)
}

// handleTOTPSetup handles TOTP setup requests
func handleTOTPSetup(w http.ResponseWriter, r *http.Request) {
	// Require authenticated session
	_, authenticated := ensureAuthenticatedSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Generate a new TOTP secret
	label, issuer := getUserInfo(r)
	key, err := totp.Generate(totp.GenerateOpts{Issuer: issuer, AccountName: label})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"success": false,
			"error":   "Failed to generate TOTP secret",
		})
		return
	}

	secret := key.Secret()
	// Store secret in Authboss session so /confirm can validate
	ab.PutSession(w, totp2fa.SessionTOTPSecret, secret)

	otpauthURL := buildOTPAuthURL(issuer, label, secret)
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"data": map[string]string{
			"secret":      secret,
			"otpauth_url": otpauthURL,
		},
	})
}

// handleTOTPConfirm handles TOTP confirm requests
func handleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	_, authenticated := ensureAuthenticatedSession(r)
	if !authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Return the secret from session as JSON
	if secret, ok := ab.GetSession(r, totp2fa.SessionTOTPSecret); ok && secret != "" {
		label, issuer := getUserInfo(r)
		otpauthURL := buildOTPAuthURL(issuer, label, secret)
		writeJSON(w, http.StatusOK, map[string]any{
			"success": true,
			"data": map[string]string{
				"totp_secret": secret,
				"secret":      secret,
				"otpauth_url": otpauthURL,
			},
		})
		return
	}

	// If no secret is present, let Authboss handle the error/redirect
	http.Error(w, "Not Found", http.StatusNotFound)
}

// handleTOTPValidate handles TOTP validation requests
func handleTOTPValidate(w http.ResponseWriter, r *http.Request) {
	// Validate PID and user
	result := validatePIDAndUser(r)
	if !result.success {
		writeJSON(w, result.statusCode, result.response)
		return
	}

	// Validate TOTP secret
	result = validateTOTPSecret(result.pid, r.Context())
	if !result.success {
		writeJSON(w, result.statusCode, result.response)
		return
	}

	// Check cooldown
	if isInCooldown(r) {
		retryAfter := getCooldownRetryAfter(r)
		writeJSON(w, http.StatusOK, map[string]any{
			"success":     false,
			"error":       "Too many recent attempts. Please wait.",
			"code":        "2FA_COOLDOWN",
			"retry_after": retryAfter,
		})
		return
	}

	// Validate TOTP code
	result = validateTOTPCode(r, result.secret)
	if !result.success {
		if !handleInvalidCode(w, r) {
			return // Response already sent
		}
		writeJSON(w, result.statusCode, result.response)
		return
	}

	// Success: set sessions to full-auth with 2FA flag and clear pending
	resetTOTPSessionData(w, result.pid)
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"message": "2FA validation successful",
	})
}

// validationResult represents the result of validation operations
type validationResult struct {
	success    bool
	pid        string
	secret     string
	statusCode int
	response   map[string]any
}

// validatePIDAndUser validates PID and loads user
func validatePIDAndUser(r *http.Request) validationResult {
	pid, err := determinePID(r)
	if err != nil {
		return validationResult{
			success:    false,
			statusCode: http.StatusUnauthorized,
			response: map[string]any{
				"success": false,
				"error":   "Unauthorized",
			},
		}
	}

	_, err = loadUser(r.Context(), pid)
	if err != nil {
		return validationResult{
			success:    false,
			statusCode: http.StatusUnauthorized,
			response: map[string]any{
				"success": false,
				"error":   "User not found",
			},
		}
	}

	return validationResult{
		success: true,
		pid:     pid,
	}
}

// validateTOTPSecret validates TOTP secret exists and is valid
func validateTOTPSecret(pid string, ctx context.Context) validationResult {
	abUser, err := loadUser(ctx, pid)
	if err != nil {
		return validationResult{
			success:    false,
			statusCode: http.StatusInternalServerError,
			response: map[string]any{
				"success": false,
				"error":   "Failed to load user",
			},
		}
	}

	secret, err := getTOTPSecret(abUser)
	if err != nil {
		return validationResult{
			success:    false,
			statusCode: http.StatusInternalServerError,
			response: map[string]any{
				"success": false,
				"error":   err.Error(),
			},
		}
	}

	if secret == "" {
		return validationResult{
			success:    false,
			statusCode: http.StatusOK,
			response: map[string]any{
				"success": false,
				"error":   "2FA not enabled",
			},
		}
	}

	return validationResult{
		success: true,
		pid:     pid,
		secret:  secret,
	}
}

// validateTOTPCode validates the provided TOTP code
func validateTOTPCode(r *http.Request, secret string) validationResult {
	code, err := extractCode(r)
	if err != nil {
		return validationResult{
			success:    false,
			statusCode: http.StatusOK,
			response: map[string]any{
				"success": false,
				"error":   "Missing code",
			},
		}
	}

	if !totp.Validate(code, secret) {
		return validationResult{
			success:    false,
			statusCode: http.StatusOK,
			response: map[string]any{
				"success": false,
				"error":   "Invalid 2FA code",
				"code":    "INVALID_2FA_CODE",
			},
		}
	}

	return validationResult{success: true}
}

// determinePID determines which PID to use for validation
func determinePID(r *http.Request) (string, error) {
	currentPID, okCur := ab.GetSession(r, ab.SessionKey)
	pendingPID, okPend := ab.GetSession(r, totp2fa.SessionTOTPPendingPID)

	switch {
	case okCur && okPend && currentPID == pendingPID:
		return currentPID, nil
	case okPend:
		return pendingPID, nil
	case okCur:
		return currentPID, nil
	default:
		return "", errors.New("no valid session")
	}
}

// loadUser loads user from authboss storage
func loadUser(ctx context.Context, pid string) (ab.User, error) {
	if auth.AB == nil || auth.AB.Config.Storage.Server == nil {
		return nil, errors.New("server not ready")
	}

	return auth.AB.Config.Storage.Server.Load(ctx, pid)
}

// getTOTPSecret extracts TOTP secret from user
func getTOTPSecret(abUser ab.User) (string, error) {
	type totpUser interface{ GetTOTPSecretKey() string }
	u, ok := abUser.(totpUser)
	if !ok {
		return "", errors.New("invalid user type")
	}

	return u.GetTOTPSecretKey(), nil
}

// isInCooldown checks if user is in cooldown period
func isInCooldown(r *http.Request) bool {
	untilStr, ok := ab.GetSession(r, "totp_cooldown_until")
	if !ok || untilStr == "" {
		return false
	}

	untilUnix, err := strconv.ParseInt(untilStr, 10, 64)
	if err != nil {
		return false
	}

	now := time.Now().Unix()
	return now < untilUnix
}

// getCooldownRetryAfter calculates retry after seconds
func getCooldownRetryAfter(r *http.Request) int {
	untilStr, ok := ab.GetSession(r, "totp_cooldown_until")
	if !ok || untilStr == "" {
		return 0
	}

	untilUnix, err := strconv.ParseInt(untilStr, 10, 64)
	if err != nil {
		return 0
	}

	now := time.Now().Unix()
	if now < untilUnix {
		return int(untilUnix - now)
	}
	return 0
}

// extractCode extracts the TOTP code from request
func extractCode(r *http.Request) (string, error) {
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "application/json") {
		var m map[string]string
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &m)
		code := strings.TrimSpace(m["code"])
		r.Body = io.NopCloser(bytes.NewReader(b))
		return code, nil
	}

	_ = r.ParseForm()
	code := strings.TrimSpace(r.FormValue("code"))
	return code, nil
}

// handleInvalidCode handles invalid TOTP code attempts
func handleInvalidCode(w http.ResponseWriter, r *http.Request) bool {
	attempts := getCurrentAttempts(r)
	return handleTOTPViolations(w, r, attempts) != -1
}

// getCurrentAttempts gets current TOTP attempts from session
func getCurrentAttempts(r *http.Request) int {
	if aStr, ok := ab.GetSession(r, "totp_attempts"); ok && aStr != "" {
		if v, err := strconv.Atoi(aStr); err == nil {
			return v
		}
	}
	return 0
}
