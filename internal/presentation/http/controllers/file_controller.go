package controllers

import (
    "secure-file-hub/internal/application/usecases"
    "secure-file-hub/internal/domain/entities"
)

type FileController struct {
    uc *usecases.FileUseCase
}

func NewFileController(uc *usecases.FileUseCase) *FileController {
    return &FileController{uc: uc}
}

func (c *FileController) List(fileType string) ([]entities.File, error) {
    return c.uc.List(fileType)
}

func (c *FileController) Versions(fileType, originalName string) ([]entities.File, error) {
    return c.uc.Versions(fileType, originalName)
}

func (c *FileController) ListWithPagination(fileType string, page, limit int) ([]entities.File, int, error) {
    return c.uc.ListWithPagination(fileType, page, limit)
}
