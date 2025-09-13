package sqlite

import (
    dbpkg "secure-file-hub/internal/database"
    "secure-file-hub/internal/domain/entities"
    "secure-file-hub/internal/domain/repositories"
)

type UserRepo struct{}

var _ repositories.UserRepository = (*UserRepo)(nil)

func NewUserRepo() *UserRepo { return &UserRepo{} }

func (r *UserRepo) GetByUsername(username string) (*entities.User, error) {
    db := dbpkg.GetDatabase()
    if db == nil { return nil, ErrDBUnavailable }
    u, err := db.GetUser(username)
    if err != nil { return nil, err }
    return &entities.User{
        Username:     u.Username,
        Email:        u.Email,
        Role:         u.Role,
        TwoFAEnabled: u.TwoFAEnabled,
        CreatedAt:    u.CreatedAt,
        UpdatedAt:    u.UpdatedAt,
        LastLoginAt:  u.LastLoginAt,
    }, nil
}

func (r *UserRepo) Create(user *entities.User, passwordHash string) error {
    db := dbpkg.GetDatabase()
    if db == nil { return ErrDBUnavailable }
    return db.CreateUser(&dbpkg.AppUser{
        Username:     user.Username,
        Email:        user.Email,
        PasswordHash: passwordHash,
        Role:         user.Role,
        TwoFAEnabled: user.TwoFAEnabled,
        CreatedAt:    user.CreatedAt,
        UpdatedAt:    user.UpdatedAt,
    })
}

func (r *UserRepo) Update(user *entities.User) error {
    db := dbpkg.GetDatabase()
    if db == nil { return ErrDBUnavailable }
    return db.UpdateUser(&dbpkg.AppUser{
        Username:     user.Username,
        Email:        user.Email,
        Role:         user.Role,
        TwoFAEnabled: user.TwoFAEnabled,
        CreatedAt:    user.CreatedAt,
        UpdatedAt:    user.UpdatedAt,
        LastLoginAt:  user.LastLoginAt,
    })
}

