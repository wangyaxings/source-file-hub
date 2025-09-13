package usecases

import (
    "os"

    "secure-file-hub/internal/database"
    "secure-file-hub/internal/domain/entities"
    "secure-file-hub/internal/domain/repositories"
)

type FileUseCase struct {
    files repositories.FileRepository
}

func NewFileUseCase(files repositories.FileRepository) *FileUseCase {
    return &FileUseCase{files: files}
}

// List returns files optionally filtered by type and refreshes existence flags on missing files.
func (uc *FileUseCase) List(fileType string) ([]entities.File, error) {
    all, _, err := uc.files.List(0, 0)
    if err != nil {
        return nil, err
    }
    out := make([]entities.File, 0, len(all))
    for _, f := range all {
        if fileType != "" && f.FileType != fileType {
            continue
        }
        if _, err := os.Stat(f.FilePath); err != nil {
            // best-effort to update existence flag using legacy helper
            if db := database.GetDatabase(); db != nil {
                _ = db.CheckFileExists(f.ID)
            }
        }
        out = append(out, f)
    }
    return out, nil
}

func (uc *FileUseCase) Versions(fileType, originalName string) ([]entities.File, error) {
    return uc.files.GetVersions(fileType, originalName)
}
