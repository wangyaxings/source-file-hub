package entities

import "time"

type User struct {
    Username     string
    Email        string
    Role         string
    TwoFAEnabled bool
    CreatedAt    time.Time
    UpdatedAt    time.Time
    LastLoginAt  *time.Time
}

