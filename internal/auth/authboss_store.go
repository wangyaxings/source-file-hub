package auth

import (
	"context"
	"errors"

	"secure-file-hub/internal/database"

	ab "github.com/aarondl/authboss/v3"
	"github.com/aarondl/authboss/v3/otp/twofactor"
	"github.com/aarondl/authboss/v3/otp/twofactor/totp2fa"
)

// ABUser is a minimal authboss user adapter backed by AppUser
type ABUser struct {
	Username      string
	Password      string
	Email         string
	TOTPSecret    string
	TOTPLastCode  string
	RecoveryCodes string
	TwoFAEnabled  bool
}

// Authboss AuthableUser interface
func (u *ABUser) GetPID() string        { return u.Username }
func (u *ABUser) GetPassword() string   { return u.Password }
func (u *ABUser) PutPID(pid string)     { u.Username = pid }
func (u *ABUser) PutPassword(pw string) { u.Password = pw }

// Optionally support email
func (u *ABUser) GetEmail() string  { return u.Email }
func (u *ABUser) PutEmail(e string) { u.Email = e }

// twofactor.User
func (u *ABUser) GetRecoveryCodes() string  { return u.RecoveryCodes }
func (u *ABUser) PutRecoveryCodes(c string) { u.RecoveryCodes = c }

// totp2fa.User
func (u *ABUser) GetTOTPSecretKey() string  { return u.TOTPSecret }
func (u *ABUser) PutTOTPSecretKey(s string) { u.TOTPSecret = s }

// totp2fa.UserOneTime optional
func (u *ABUser) GetTOTPLastCode() string  { return u.TOTPLastCode }
func (u *ABUser) PutTOTPLastCode(c string) { u.TOTPLastCode = c }

// Check if user needs to complete 2FA setup
func (u *ABUser) Needs2FASetup() bool {
	return u.TwoFAEnabled && u.TOTPSecret == ""
}

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
	return &ABUser{
		Username:      u.Username,
		Password:      u.PasswordHash,
		Email:         u.Email,
		TOTPSecret:    u.TOTPSecret,
		TOTPLastCode:  u.TOTPLastCode,
		RecoveryCodes: u.RecoveryCodes,
		TwoFAEnabled:  u.TwoFAEnabled,
	}, nil
}

func (s UserStorer) Save(ctx context.Context, user ab.User) error {
    db := database.GetDatabase()
    if db == nil {
        return errors.New("database not available")
    }
    // Normalize to *ABUser for persistence
    var au *ABUser
    switch v := user.(type) {
    case *ABUser:
        au = v
    default:
        tmp := &ABUser{}
        // Core fields
        tmp.PutPID(v.GetPID())
        if authable, ok := any(v).(ab.AuthableUser); ok {
            tmp.PutPassword(authable.GetPassword())
        }
        // Optional email
        if withEmail, ok := any(v).(interface{ GetEmail() string }); ok {
            tmp.PutEmail(withEmail.GetEmail())
        }
        // Two-factor recovery codes
        if tfu, ok := any(v).(twofactor.User); ok {
            tmp.PutRecoveryCodes(tfu.GetRecoveryCodes())
        }
        // TOTP secret and last one-time code
        if tu, ok := any(v).(totp2fa.User); ok {
            tmp.PutTOTPSecretKey(tu.GetTOTPSecretKey())
        }
        if tou, ok := any(v).(totp2fa.UserOneTime); ok {
            tmp.PutTOTPLastCode(tou.GetTOTPLastCode())
        }
        au = tmp
    }

    // Upsert minimal fields
    current, err := db.GetUser(au.Username)
    if err != nil {
        // Create user record
        if createErr := db.CreateUser(&database.AppUser{Username: au.Username, Email: au.Email, PasswordHash: au.Password, Role: "viewer"}); createErr != nil {
            return createErr
        }
        // Create user role record with active status
        _ = db.CreateOrUpdateUserRole(&database.UserRole{
            UserID:       au.Username,
            Role:         "viewer",
            Permissions:  []string{"read"},
            QuotaDaily:   -1,
            QuotaMonthly: -1,
            Status:       "active",
        })
        return nil
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

	// Create user record
	if err := db.CreateUser(&database.AppUser{
		Username:      au.Username,
		Email:         au.Email,
		PasswordHash:  au.Password,
		Role:          "viewer",
		TOTPSecret:    au.TOTPSecret,
		TOTPLastCode:  au.TOTPLastCode,
		RecoveryCodes: au.RecoveryCodes,
	}); err != nil {
		return err
	}

	// Create user role record with active status
	_ = db.CreateOrUpdateUserRole(&database.UserRole{
		UserID:       au.Username,
		Role:         "viewer",
		Permissions:  []string{"read"},
		QuotaDaily:   -1,
		QuotaMonthly: -1,
		Status:       "active",
	})

	return nil
}
