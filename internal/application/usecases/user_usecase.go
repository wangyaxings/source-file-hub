package usecases

import (
    "secure-file-hub/internal/database"
)

type UserUseCase struct{}

func NewUserUseCase() *UserUseCase { return &UserUseCase{} }

// BuildMePayload assembles the user payload used by /auth/me
func (uuc *UserUseCase) BuildMePayload(username, role string, fallbackTwoFA bool) map[string]interface{} {
    payload := map[string]interface{}{"username": username, "role": role}
    if db := database.GetDatabase(); db != nil {
        if ur, err := db.GetUserRole(username); err == nil && ur != nil {
            if ur.Status != "" { payload["status"] = ur.Status }
            payload["permissions"] = ur.Permissions
            payload["quota_daily"] = ur.QuotaDaily
            payload["quota_monthly"] = ur.QuotaMonthly
        }
        if appUser, err := db.GetUser(username); err == nil && appUser != nil {
            payload["two_fa"] = appUser.TwoFAEnabled
            payload["totp_secret"] = appUser.TOTPSecret != ""
            payload["two_fa_enabled"] = appUser.TwoFAEnabled
        }
    }
    if _, ok := payload["two_fa"]; !ok {
        payload["two_fa"] = fallbackTwoFA
    }
    return payload
}

