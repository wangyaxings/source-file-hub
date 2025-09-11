package auth

import (
    "os"

    ab "github.com/aarondl/authboss/v3"
    _ "github.com/aarondl/authboss/v3/auth"
    "github.com/aarondl/authboss/v3/defaults"
    _ "github.com/aarondl/authboss/v3/logout"
    "github.com/aarondl/authboss/v3/otp/twofactor/totp2fa"
)

var AB *ab.Authboss

// InitAuthboss prepares a minimal Authboss instance. It is not mounted by default
// to avoid disrupting existing JSON/Bearer flows. Mount points may be added later
// under /authboss if desired.
func InitAuthboss() (*ab.Authboss, error) {
    if AB != nil {
        return AB, nil
    }
    a := ab.New()
    // Mount Authboss under /api/v1/web/auth/ab to avoid route collisions
    // Note: Mount should be empty when using StripPrefix in server.go
    a.Config.Paths.Mount = ""
    a.Config.Paths.RootURL = "https://127.0.0.1:30000"
    a.Config.Paths.AuthLoginOK = "/api/v1/web/auth/me"
    a.Config.Storage.Server = UserStorer{}

    // Client state (session + cookie)
    a.Config.Storage.SessionState = newCookieStateRW("ab_session", false)
    a.Config.Storage.CookieState = newCookieStateRW("ab_cookie", true)

    // Router and rendering (JSON)
    a.Config.Core.Router = defaults.NewRouter()
    renderer := defaults.JSONRenderer{}
    a.Config.Core.ViewRenderer = renderer
    a.Config.Core.Responder = defaults.NewResponder(renderer)
    a.Config.Core.Redirector = defaults.NewRedirector(renderer, ab.FormValueRedirect)
    a.Config.Core.ErrorHandler = defaults.NewErrorHandler(defaults.NewLogger(os.Stdout))
    a.Config.Core.BodyReader = defaults.NewHTTPBodyReader(true, true) // username, JSON
    a.Config.Core.Logger = defaults.NewLogger(os.Stdout)
    a.Config.Core.Hasher = ab.NewBCryptHasher(12)

    // OTP / TOTP
    a.Config.Modules.TOTP2FAIssuer = "Secure File Hub"

    // Initialize only imported modules (auth, logout, totp2fa)
    if err := a.Init(); err != nil {
        return nil, err
    }
    // Setup TOTP module
    t := &totp2fa.TOTP{Authboss: a}
    if err := t.Setup(); err != nil {
        return nil, err
    }
    AB = a
    return a, nil
}
