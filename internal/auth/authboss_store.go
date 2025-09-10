package auth

import (
    "context"
    "errors"

    ab "github.com/aarondl/authboss/v3"
    "github.com/aarondl/authboss/v3/otp/twofactor"
    "github.com/aarondl/authboss/v3/otp/twofactor/totp2fa"
    "secure-file-hub/internal/database"
)

// ABUser is a minimal authboss user adapter backed by AppUser
type ABUser struct {
    Username      string
    Password      string
    Email         string
    TOTPSecret    string
    TOTPLastCode  string
    RecoveryCodes string
}

// Authboss AuthableUser interface
func (u *ABUser) GetPID() string               { return u.Username }
func (u *ABUser) GetPassword() string          { return u.Password }
func (u *ABUser) PutPID(pid string)            { u.Username = pid }
func (u *ABUser) PutPassword(pw string)        { u.Password = pw }

// Optionally support email
func (u *ABUser) GetEmail() string      { return u.Email }
func (u *ABUser) PutEmail(e string)     { u.Email = e }

// twofactor.User
func (u *ABUser) GetRecoveryCodes() string { return u.RecoveryCodes }
func (u *ABUser) PutRecoveryCodes(c string) { u.RecoveryCodes = c }

// totp2fa.User
func (u *ABUser) GetTOTPSecretKey() string { return u.TOTPSecret }
func (u *ABUser) PutTOTPSecretKey(s string) { u.TOTPSecret = s }

// totp2fa.UserOneTime optional
func (u *ABUser) GetTOTPLastCode() string { return u.TOTPLastCode }
func (u *ABUser) PutTOTPLastCode(c string) { u.TOTPLastCode = c }

// UserStorer implements ab.ServerStorer
type UserStorer struct{}

func (s UserStorer) Load(ctx context.Context, key string) (ab.User, error) {
    db := database.GetDatabase()
    if db == nil {
        return nil, errors.New("database not available")
    }
    u, err := db.GetUser(key)
    if err != nil {
        return nil, ab.ErrUserNotFound
    }
    return &ABUser{Username: u.Username, Password: u.PasswordHash, Email: u.Email, TOTPSecret: u.TOTPSecret, TOTPLastCode: u.TOTPLastCode, RecoveryCodes: u.RecoveryCodes}, nil
}

func (s UserStorer) Save(ctx context.Context, user ab.User) error {
    db := database.GetDatabase()
    if db == nil {
        return errors.New("database not available")
    }
    // Support various user interfaces
    var au *ABUser
    switch v := user.(type) {
    case *ABUser:
        au = v
    case twofactor.User:
        // Build from interface methods minimally
        tmp := &ABUser{}
        tmp.PutPID(v.GetPID())
        tmp.PutEmail(v.GetEmail())
        au = tmp
    default:
        return errors.New("invalid user type")
    }
    // Upsert minimal fields
    current, err := db.GetUser(au.Username)
    if err != nil {
        return db.CreateUser(&database.AppUser{Username: au.Username, Email: au.Email, PasswordHash: au.Password, Role: "viewer"})
    }
    current.Email = au.Email
    if au.Password != "" {
        current.PasswordHash = au.Password
    }
    // TOTP/Recovery fields
    if au.TOTPSecret != "" {
        current.TOTPSecret = au.TOTPSecret
    }
    if au.TOTPLastCode != "" {
        current.TOTPLastCode = au.TOTPLastCode
    }
    if au.RecoveryCodes != "" {
        current.RecoveryCodes = au.RecoveryCodes
    }
    return db.UpdateUser(current)
}

func (s UserStorer) New(ctx context.Context) ab.User { return &ABUser{} }

// Ensure interfaces
var _ ab.ServerStorer = UserStorer{}
var _ ab.CreatingServerStorer = UserStorer{}
var _ twofactor.User = (*ABUser)(nil)
var _ totp2fa.User = (*ABUser)(nil)
var _ totp2fa.UserOneTime = (*ABUser)(nil)

// Create implements CreatingServerStorer
func (s UserStorer) Create(ctx context.Context, user ab.User) error {
    db := database.GetDatabase()
    if db == nil {
        return errors.New("database not available")
    }
    au, ok := user.(*ABUser)
    if !ok {
        return errors.New("invalid user type")
    }
    if _, err := db.GetUser(au.Username); err == nil {
        return ab.ErrUserFound
    }
    return db.CreateUser(&database.AppUser{
        Username:      au.Username,
        Email:         au.Email,
        PasswordHash:  au.Password,
        Role:          "viewer",
        TOTPSecret:    au.TOTPSecret,
        TOTPLastCode:  au.TOTPLastCode,
        RecoveryCodes: au.RecoveryCodes,
    })
}
