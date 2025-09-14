package usecases

import (
    "testing"
    "time"

    "secure-file-hub/internal/application/usecases"
    repo "secure-file-hub/internal/infrastructure/repository/sqlite"
    "secure-file-hub/internal/database"
    "secure-file-hub/tests/helpers"
)

func TestFileUseCase_ListWithPagination(t *testing.T) {
    helpers.SetupTestEnvironment(t)
    db := database.GetDatabase()
    if db == nil { t.Fatal("db nil") }

    // Insert 3 test files
    for i := 1; i <= 3; i++ {
        rec := &database.FileRecord{
            ID:            helpers.GenerateRandomID(8),
            OriginalName:  "f.txt",
            VersionedName: "f_v1.txt",
            FileType:      "roadmap",
            FilePath:      "downloads/x.txt",
            Size:          100,
            Description:   "test",
            Uploader:      "tester",
            UploadTime:    time.Now(),
            Version:       1,
            IsLatest:      true,
            Status:        database.FileStatusActive,
            FileExists:    true,
            CreatedAt:     time.Now(),
            UpdatedAt:     time.Now(),
        }
        if err := db.InsertFileRecord(rec); err != nil { t.Fatalf("insert: %v", err) }
    }

    uc := usecases.NewFileUseCase(repo.NewFileRepo())
    items, total, err := uc.ListWithPagination("", 1, 2)
    if err != nil { t.Fatalf("list: %v", err) }
    if total < 3 { t.Fatalf("expected total >= 3, got %d", total) }
    if len(items) != 2 { t.Fatalf("expected 2 items, got %d", len(items)) }

    items2, _, err := uc.ListWithPagination("roadmap", 2, 2)
    if err != nil { t.Fatalf("list2: %v", err) }
    if len(items2) == 0 { t.Fatalf("expected items on page 2") }
}

