package sqlite

import (
    dbpkg "secure-file-hub/internal/database"
    "secure-file-hub/internal/domain/entities"
    "secure-file-hub/internal/domain/repositories"
)

type FileRepo struct{}

var _ repositories.FileRepository = (*FileRepo)(nil)

func NewFileRepo() *FileRepo { return &FileRepo{} }

func toEntity(rec dbpkg.FileRecord) entities.File {
    return entities.File{
        ID:            rec.ID,
        OriginalName:  rec.OriginalName,
        VersionedName: rec.VersionedName,
        FileType:      rec.FileType,
        FilePath:      rec.FilePath,
        Size:          rec.Size,
        Description:   rec.Description,
        Uploader:      rec.Uploader,
        UploadTime:    rec.UploadTime,
        Version:       rec.Version,
        IsLatest:      rec.IsLatest,
        Status:        string(rec.Status),
    }
}

// Minimal implementations that map to existing database methods.
func (r *FileRepo) GetByID(id string) (*entities.File, error) {
    db := dbpkg.GetDatabase()
    if db == nil { return nil, ErrDBUnavailable }
    rec, err := db.GetFileRecordByID(id)
    if err != nil { return nil, err }
    if rec == nil { return nil, nil }
    e := toEntity(*rec)
    return &e, nil
}

func (r *FileRepo) Insert(record *entities.File) error {
    db := dbpkg.GetDatabase()
    if db == nil { return ErrDBUnavailable }
    // Map to database.FileRecord
    fr := dbpkg.FileRecord{
        ID:            record.ID,
        OriginalName:  record.OriginalName,
        VersionedName: record.VersionedName,
        FileType:      record.FileType,
        FilePath:      record.FilePath,
        Size:          record.Size,
        Description:   record.Description,
        Uploader:      record.Uploader,
        UploadTime:    record.UploadTime,
        Version:       record.Version,
        IsLatest:      record.IsLatest,
        Status:        dbpkg.FileStatus(record.Status),
    }
    return db.InsertFileRecord(&fr)
}

func (r *FileRepo) List(offset, limit int) ([]entities.File, int, error) {
    db := dbpkg.GetDatabase()
    if db == nil { return nil, 0, ErrDBUnavailable }
    recs, total, err := db.ListFilesWithPagination(offset, limit)
    if err != nil { return nil, 0, err }
    out := make([]entities.File, 0, len(recs))
    for _, rec := range recs {
        out = append(out, toEntity(rec))
    }
    return out, total, nil
}

func (r *FileRepo) ListByType(fileType string, offset, limit int) ([]entities.File, int, error) {
    db := dbpkg.GetDatabase()
    if db == nil { return nil, 0, ErrDBUnavailable }
    recs, total, err := db.ListFilesWithPaginationByType(fileType, offset, limit)
    if err != nil { return nil, 0, err }
    out := make([]entities.File, 0, len(recs))
    for _, rec := range recs {
        out = append(out, toEntity(rec))
    }
    return out, total, nil
}

func (r *FileRepo) GetVersions(fileType, originalName string) ([]entities.File, error) {
    db := dbpkg.GetDatabase()
    if db == nil { return nil, ErrDBUnavailable }
    recs, err := db.GetFileVersions(fileType, originalName)
    if err != nil { return nil, err }
    out := make([]entities.File, 0, len(recs))
    for _, rec := range recs {
        out = append(out, toEntity(rec))
    }
    return out, nil
}
