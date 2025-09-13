package di

import (
    "database/sql"

    "secure-file-hub/internal/domain/repositories"
    repo "secure-file-hub/internal/infrastructure/repository/sqlite"
)

// Container provides a simple DI skeleton to be expanded in later phases.
type Container struct {
    DB *sql.DB

    Users   repositories.UserRepository
    Files   repositories.FileRepository
    APIKeys repositories.APIKeyRepository
}

func New(db *sql.DB) *Container {
    return &Container{
        DB:      db,
        Users:   repo.NewUserRepo(),
        Files:   repo.NewFileRepo(),
        APIKeys: repo.NewAPIKeyRepo(),
    }
}
