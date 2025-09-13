package repositories

import "secure-file-hub/internal/domain/entities"

type APIKeyRepository interface {
    Create(key *entities.APIKey, keyHash string) error
    GetByID(id string) (*entities.APIKey, error)
    ListAll() ([]entities.APIKey, error)
    UpdateStatus(id, status string) error
    Delete(id string) error
}

