package di

import (
    "database/sql"

    "secure-file-hub/internal/application/usecases"
    fc "secure-file-hub/internal/presentation/http/controllers"
    "secure-file-hub/internal/domain/repositories"
    repo "secure-file-hub/internal/infrastructure/repository/sqlite"
)

// Container provides app-wide singletons for repos/usecases/controllers.
type Container struct {
    DB *sql.DB

    // Repositories
    Users   repositories.UserRepository
    Files   repositories.FileRepository
    APIKeys repositories.APIKeyRepository

    // Usecases
    FileUC   *usecases.FileUseCase
    APIKeyUC *usecases.APIKeyUseCase
    UserUC   *usecases.UserUseCase

    // Controllers
    FileController *fc.FileController
}

func New(db *sql.DB) *Container {
    c := &Container{
        DB:      db,
        Users:   repo.NewUserRepo(),
        Files:   repo.NewFileRepo(),
        APIKeys: repo.NewAPIKeyRepo(),
    }
    // Build usecases
    c.FileUC = usecases.NewFileUseCase(c.Files)
    c.APIKeyUC = usecases.NewAPIKeyUseCase(c.APIKeys)
    c.UserUC = usecases.NewUserUseCase()
    // Build controllers
    c.FileController = fc.NewFileController(c.FileUC)
    return c
}
