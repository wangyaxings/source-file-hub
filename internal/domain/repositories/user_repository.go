package repositories

import "secure-file-hub/internal/domain/entities"

type UserRepository interface {
    GetByUsername(username string) (*entities.User, error)
    Create(user *entities.User, passwordHash string) error
    Update(user *entities.User) error
}

