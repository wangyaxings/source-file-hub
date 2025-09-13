package entities

import "time"

type File struct {
    ID           string
    OriginalName string
    VersionedName string
    FileType     string
    FilePath     string
    Size         int64
    Description  string
    Uploader     string
    UploadTime   time.Time
    Version      int
    IsLatest     bool
    Status       string
}

