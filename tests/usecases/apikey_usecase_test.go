package usecases

import (
    "testing"
    "time"

    "secure-file-hub/internal/application/usecases"
    repo "secure-file-hub/internal/infrastructure/repository/sqlite"
    "secure-file-hub/tests/helpers"
)

func TestAPIKeyUseCase_UpdateAndRegenerate(t *testing.T) {
    helpers.SetupTestEnvironment(t)

    uc := usecases.NewAPIKeyUseCase(repo.NewAPIKeyRepo())

    // Create key
    key, err := uc.Create("test-key", "desc", "api_user", []string{"read"}, nil)
    if err != nil { t.Fatalf("create key: %v", err) }

    // Update permissions and expiry
    exp := time.Now().Add(24 * time.Hour)
    patch := usecases.APIKeyUpdatePatch{Permissions: &[]string{"read", "download"}, ExpiresAt: &exp}
    if _, err := uc.Update(key.ID, patch); err != nil { t.Fatalf("update: %v", err) }

    // Verify update
    updated, err := uc.GetByID(key.ID)
    if err != nil || updated == nil { t.Fatalf("get updated: %v", err) }
    if len(updated.Permissions) != 2 { t.Fatalf("permissions not updated: %+v", updated.Permissions) }

    // Regenerate: create new and disable old
    // Use handler-like steps via usecase
    newKey, err := uc.Create(updated.Name, "Regenerated API key", updated.Role, updated.Permissions, updated.ExpiresAt)
    if err != nil { t.Fatalf("regenerate create: %v", err) }
    if newKey.Key == "" { t.Fatalf("expected new key value") }
    if err := uc.UpdateStatus(key.ID, "disabled"); err != nil { t.Fatalf("disable old: %v", err) }
}
