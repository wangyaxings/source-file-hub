package usecases

import (
    "time"

    "secure-file-hub/internal/apikey"
    "secure-file-hub/internal/domain/entities"
    "secure-file-hub/internal/domain/repositories"
)

type APIKeyUseCase struct {
    repo repositories.APIKeyRepository
}

func NewAPIKeyUseCase(r repositories.APIKeyRepository) *APIKeyUseCase {
    return &APIKeyUseCase{repo: r}
}

// Create generates and stores a new API key; returns the entity with full key value populated.
func (uc *APIKeyUseCase) Create(name, description, role string, permissions []string, expiresAt *time.Time) (*entities.APIKey, error) {
    fullKey, keyHash, err := apikey.GenerateAPIKey("sk")
    if err != nil {
        return nil, err
    }
    now := time.Now()
    ent := &entities.APIKey{
        ID:          apikey.GenerateAPIKeyID(),
        Name:        name,
        Description: description,
        Key:         fullKey,
        Role:        role,
        Permissions: permissions,
        Status:      "active",
        ExpiresAt:   expiresAt,
        UsageCount:  0,
        CreatedAt:   now,
        UpdatedAt:   now,
    }
    if err := uc.repo.Create(ent, keyHash); err != nil {
        return nil, err
    }
    return ent, nil
}

// List returns API keys, optionally filtering by role, with masked key values.
func (uc *APIKeyUseCase) List(role string) ([]entities.APIKey, error) {
    all, err := uc.repo.ListAll()
    if err != nil { return nil, err }
    if role == "" { return all, nil }
    out := make([]entities.APIKey, 0, len(all))
    for _, k := range all {
        if k.Role == role { out = append(out, k) }
    }
    return out, nil
}

func (uc *APIKeyUseCase) UpdateStatus(id, status string) error {
    return uc.repo.UpdateStatus(id, status)
}

func (uc *APIKeyUseCase) Delete(id string) error {
    return uc.repo.Delete(id)
}

func (uc *APIKeyUseCase) GetByID(id string) (*entities.APIKey, error) {
    return uc.repo.GetByID(id)
}
