package repositories

import (
    "time"
    "secure-file-hub/internal/domain/entities"
)

type APIKeyRepository interface {
    Create(key *entities.APIKey, keyHash string) error
    GetByID(id string) (*entities.APIKey, error)
    ListAll() ([]entities.APIKey, error)
    UpdateStatus(id, status string) error
    Delete(id string) error
    Update(id string, upd APIKeyUpdate) error
    UpdateReturning(id string, upd APIKeyUpdate) (*entities.APIKey, error)
}

type APIKeyUpdate struct {
    Name        *string
    Description *string
    Permissions *[]string
    ExpiresAt   *time.Time
    ClearExpires bool
}
