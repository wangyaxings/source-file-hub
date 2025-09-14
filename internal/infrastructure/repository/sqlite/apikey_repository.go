package sqlite

import (
    dbpkg "secure-file-hub/internal/database"
    "secure-file-hub/internal/domain/entities"
    "secure-file-hub/internal/domain/repositories"
    "secure-file-hub/internal/apikey"
)

type APIKeyRepo struct{}

var _ repositories.APIKeyRepository = (*APIKeyRepo)(nil)

func NewAPIKeyRepo() *APIKeyRepo { return &APIKeyRepo{} }

func mapDBToEntity(k *dbpkg.APIKey) *entities.APIKey {
    if k == nil { return nil }
    return &entities.APIKey{
        ID:          k.ID,
        Name:        k.Name,
        Description: k.Description,
        Key:         func() string { if k.Key != "" { return k.Key } ; return apikey.MaskAPIKey(k.KeyHash) }(),
        Role:        k.Role,
        Permissions: k.Permissions,
        Status:      k.Status,
        ExpiresAt:   k.ExpiresAt,
        UsageCount:  k.UsageCount,
        LastUsedAt:  k.LastUsedAt,
        CreatedAt:   k.CreatedAt,
        UpdatedAt:   k.UpdatedAt,
    }
}

func (r *APIKeyRepo) Create(key *entities.APIKey, keyHash string) error {
    db := dbpkg.GetDatabase()
    if db == nil { return ErrDBUnavailable }
    return db.CreateAPIKey(&dbpkg.APIKey{
        ID:          key.ID,
        Name:        key.Name,
        Description: key.Description,
        KeyHash:     keyHash,
        Key:         key.Key,
        Role:        key.Role,
        Permissions: key.Permissions,
        Status:      key.Status,
        ExpiresAt:   key.ExpiresAt,
        UsageCount:  key.UsageCount,
        LastUsedAt:  key.LastUsedAt,
        CreatedAt:   key.CreatedAt,
        UpdatedAt:   key.UpdatedAt,
    })
}

func (r *APIKeyRepo) GetByID(id string) (*entities.APIKey, error) {
    db := dbpkg.GetDatabase()
    if db == nil { return nil, ErrDBUnavailable }
    k, err := db.GetAPIKeyByID(id)
    if err != nil { return nil, err }
    return mapDBToEntity(k), nil
}

func (r *APIKeyRepo) ListAll() ([]entities.APIKey, error) {
    db := dbpkg.GetDatabase()
    if db == nil { return nil, ErrDBUnavailable }
    ks, err := db.GetAllAPIKeys()
    if err != nil { return nil, err }
    out := make([]entities.APIKey, 0, len(ks))
    for i := range ks {
        out = append(out, *mapDBToEntity(&ks[i]))
    }
    return out, nil
}

func (r *APIKeyRepo) UpdateStatus(id, status string) error {
    db := dbpkg.GetDatabase()
    if db == nil { return ErrDBUnavailable }
    return db.UpdateAPIKeyStatus(id, status)
}

func (r *APIKeyRepo) Delete(id string) error {
    db := dbpkg.GetDatabase()
    if db == nil { return ErrDBUnavailable }
    return db.DeleteAPIKey(id)
}

func (r *APIKeyRepo) Update(id string, upd repositories.APIKeyUpdate) error {
    db := dbpkg.GetDatabase()
    if db == nil { return ErrDBUnavailable }
    return db.UpdateAPIKeyFields(id, upd.Name, upd.Description, upd.Permissions, upd.ExpiresAt)
}

func (r *APIKeyRepo) UpdateReturning(id string, upd repositories.APIKeyUpdate) (*entities.APIKey, error) {
    if err := r.Update(id, upd); err != nil { return nil, err }
    return r.GetByID(id)
}
