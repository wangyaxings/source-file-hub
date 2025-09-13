package middleware

import (
    "bytes"
    "encoding/json"
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
        path := r.URL.Path

        // Only handle the authboss TOTP endpoints mounted under /api/v1/web/auth/ab
        if !strings.HasPrefix(path, "/api/v1/web/auth/ab/2fa/totp/") {
            next.ServeHTTP(w, r)
            return
        }

        // Session safety: if there's a pending TOTP user different from current session user,
        // clear full-auth session to avoid validating as the wrong user (e.g., stale admin session).
        if currentPID, okCur := ab.GetSession(r, ab.SessionKey); okCur && currentPID != "" {
            if pendingPID, okPend := ab.GetSession(r, totp2fa.SessionTOTPPendingPID); okPend && pendingPID != "" {
                if currentPID != pendingPID {
                    // Remove the conflicting full-auth session so Authboss validate() uses pendingPID.
                    ab.DelSession(w, ab.SessionKey)
                    ab.DelSession(w, ab.Session2FA)
                }
            }
        }

        // Prefer JSON flow; if client doesn't want JSON, fall through
        wantsJSON := strings.Contains(r.Header.Get("Accept"), "application/json") ||
            strings.Contains(r.Header.Get("Content-Type"), "application/json")

        switch {
        case r.Method == http.MethodPost && strings.HasSuffix(path, "/setup") && wantsJSON:
            // Require authenticated session (Authboss should set this on login)
            if pid, ok := ab.GetSession(r, ab.SessionKey); !ok || pid == "" {
                // Let Authboss handle unauthenticated flow (redirect/json error)
                next.ServeHTTP(w, r)
                return
            }
            // Generate a new TOTP secret and store it in the session for Authboss to use on confirm.
            issuer := "Secure File Hub"
            if auth.AB != nil && auth.AB.Config.Modules.TOTP2FAIssuer != "" {
                issuer = auth.AB.Config.Modules.TOTP2FAIssuer
            }

            // Account label: prefer email, fallback to username
            label := "user"
            if uctx := r.Context().Value("user"); uctx != nil {
                if u, ok := uctx.(*auth.User); ok {
                    if u.Email != "" {
                        label = u.Email
                    } else if u.Username != "" {
                        label = u.Username
                    }
                }
            }

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
                    "secret":       secret,
                    "otpauth_url":  otpauthURL,
                },
            })
            return

        case r.Method == http.MethodGet && strings.HasSuffix(path, "/confirm") && wantsJSON:
            if pid, ok := ab.GetSession(r, ab.SessionKey); !ok || pid == "" {
                next.ServeHTTP(w, r)
                return
            }
            // Return the secret from session as JSON so the frontend can render QR without HTML views.
            if secret, ok := ab.GetSession(r, totp2fa.SessionTOTPSecret); ok && secret != "" {
                issuer := "Secure File Hub"
                label := "user"
                if auth.AB != nil && auth.AB.Config.Modules.TOTP2FAIssuer != "" {
                    issuer = auth.AB.Config.Modules.TOTP2FAIssuer
                }
                if uctx := r.Context().Value("user"); uctx != nil {
                    if u, ok := uctx.(*auth.User); ok {
                        if u.Email != "" {
                            label = u.Email
                        } else if u.Username != "" {
                            label = u.Username
                        }
                    }
                }
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
            next.ServeHTTP(w, r)
            return

        case r.Method == http.MethodPost && strings.HasSuffix(path, "/validate") && wantsJSON:
            // Perform validation ourselves to provide reliable JSON result
            // Determine the PID to validate: prefer full-auth if it matches pending, else pending
            currentPID, okCur := ab.GetSession(r, ab.SessionKey)
            pendingPID, okPend := ab.GetSession(r, totp2fa.SessionTOTPPendingPID)
            pid := ""
            switch {
            case okCur && okPend && currentPID == pendingPID:
                pid = currentPID
            case okPend:
                pid = pendingPID
            case okCur:
                pid = currentPID
            default:
                writeJSON(w, http.StatusUnauthorized, map[string]any{ "success": false, "error": "Unauthorized" })
                return
            }

            if auth.AB == nil || auth.AB.Config.Storage.Server == nil {
                writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "error": "Server not ready"})
                return
            }
            abUser, err := auth.AB.Config.Storage.Server.Load(r.Context(), pid)
            if err != nil {
                writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "error": "User not found"})
                return
            }
            // Interface to access TOTP secret and last code if available
            type totpUser interface{ GetTOTPSecretKey() string }
            u, ok := abUser.(totpUser)
            if !ok {
                writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "error": "Invalid user type"})
                return
            }
            secret := u.GetTOTPSecretKey()
            if secret == "" {
                writeJSON(w, http.StatusOK, map[string]any{"success": false, "error": "2FA not enabled"})
                return
            }

            // Throttling / lockout controls (per-session)
            constMaxAttempts := 5
            constCooldownAfterFailSeconds := 5
            // constLockoutMinutes := 2 // reserved for future use

            // Cooldown check
            if untilStr, ok := ab.GetSession(r, "totp_cooldown_until"); ok && untilStr != "" {
                if untilUnix, err := strconv.ParseInt(untilStr, 10, 64); err == nil {
                    now := time.Now().Unix()
                    if now < untilUnix {
                        retryAfter := int(untilUnix - now)
                        writeJSON(w, http.StatusOK, map[string]any{
                            "success":     false,
                            "error":       "Too many recent attempts. Please wait.",
                            "code":        "2FA_COOLDOWN",
                            "retry_after": retryAfter,
                        })
                        return
                    }
                }
            }

            // Read code from JSON or form
            var code string
            ct := r.Header.Get("Content-Type")
            if strings.Contains(ct, "application/json") {
                var m map[string]string
                b, _ := io.ReadAll(r.Body)
                _ = json.Unmarshal(b, &m)
                code = strings.TrimSpace(m["code"])
                // restore body for any downstream usage
                r.Body = io.NopCloser(bytes.NewReader(b))
            } else {
                _ = r.ParseForm()
                code = strings.TrimSpace(r.FormValue("code"))
            }
            if code == "" {
                writeJSON(w, http.StatusOK, map[string]any{"success": false, "error": "Missing code"})
                return
            }

            if !totp.Validate(code, secret) {
                // Increment attempts
                attempts := 0
                if aStr, ok := ab.GetSession(r, "totp_attempts"); ok && aStr != "" {
                    if v, err := strconv.Atoi(aStr); err == nil {
                        attempts = v
                    }
                }
                attempts++
                ab.PutSession(w, "totp_attempts", strconv.Itoa(attempts))

                // Apply cooldown
                if constCooldownAfterFailSeconds > 0 {
                    until := time.Now().Add(time.Duration(constCooldownAfterFailSeconds) * time.Second).Unix()
                    ab.PutSession(w, "totp_cooldown_until", strconv.FormatInt(until, 10))
                }

                // Lockout and force re-login
                if attempts >= constMaxAttempts {
                    // Clear sessions and force full re-login
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
                    return
                }

                writeJSON(w, http.StatusOK, map[string]any{
                    "success": false,
                    "error":   "Invalid 2FA code",
                    "code":    "INVALID_2FA_CODE",
                })
                return
            }

            // Success: set sessions to full-auth with 2FA flag and clear pending
            // Reset attempts/cooldown on success
            ab.DelSession(w, "totp_attempts")
            ab.DelSession(w, "totp_cooldown_until")
            ab.PutSession(w, ab.SessionKey, pid)
            ab.PutSession(w, ab.Session2FA, "totp")
            ab.DelSession(w, ab.SessionHalfAuthKey)
            ab.DelSession(w, totp2fa.SessionTOTPPendingPID)
            ab.DelSession(w, totp2fa.SessionTOTPSecret)

            writeJSON(w, http.StatusOK, map[string]any{"success": true, "message": "2FA validation successful"})
            return
        }

        next.ServeHTTP(w, r)
    })
}

func buildOTPAuthURL(issuer, label, secret string) string {
    return "otpauth://totp/" + url.PathEscape(issuer) + ":" + url.PathEscape(label) +
        "?issuer=" + url.QueryEscape(issuer) + "&secret=" + url.QueryEscape(secret)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(status)
    _ = json.NewEncoder(w).Encode(body)
}

// captureResponseWriter buffers the response for inspection.
type captureResponseWriter struct {
    HeaderMap  http.Header
    Body       bytes.Buffer
    StatusCode int
}

func (c *captureResponseWriter) Header() http.Header { return c.HeaderMap }
func (c *captureResponseWriter) Write(b []byte) (int, error) { return c.Body.Write(b) }
func (c *captureResponseWriter) WriteHeader(statusCode int) { c.StatusCode = statusCode }
