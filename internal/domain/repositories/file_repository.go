package repositories

import "secure-file-hub/internal/domain/entities"

type FileRepository interface {
    GetByID(id string) (*entities.File, error)
    Insert(record *entities.File) error
    List(offset, limit int) ([]entities.File, int, error)
}

