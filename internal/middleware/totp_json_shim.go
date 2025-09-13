package middleware

import (
    "encoding/json"
    "net/http"
    "net/url"
    "strings"

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
