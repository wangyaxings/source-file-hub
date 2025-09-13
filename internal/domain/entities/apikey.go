package entities

import "time"

type APIKey struct {
    ID          string
    Name        string
    Description string
    Key         string // Only present on creation
    Role        string
    Permissions []string
    Status      string
    ExpiresAt   *time.Time
    UsageCount  int64
    LastUsedAt  *time.Time
    CreatedAt   time.Time
    UpdatedAt   time.Time
}

