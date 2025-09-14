package integration

import (
    "encoding/json"
    "fmt"
    "net/http"
    "net/http/httptest"
    "testing"
    "time"

    "secure-file-hub/internal/database"
    "secure-file-hub/internal/handler"
    "secure-file-hub/internal/server"
    "secure-file-hub/tests/helpers"
)

func TestFiles_ListWithPagination_AndErrorContract(t *testing.T) {
    // Setup
    _ = helpers.SetupTestEnvironment(t)
    srv := server.New()
    handler.RegisterRoutes(srv.Router)

    // Create user and login to get session cookie
    _ = helpers.CreateTestUser(t, "alice", "password123", "viewer")
    cookie := helpers.LoginAndGetSessionCookie(t, srv.Router, "alice", "password123")

    // Seed some roadmap file records to ensure pagination has data
    db := database.GetDatabase()
    if db == nil { t.Fatalf("db not initialized") }
    now := time.Now()
    for i := 0; i < 12; i++ {
        id := fmt.Sprintf("file_%d_%d", now.UnixNano()+int64(i), i)
        rec := &database.FileRecord{
            ID:            id,
            OriginalName:  "roadmap.tsv",
            VersionedName: fmt.Sprintf("roadmap_v%d.tsv", i+1),
            FileType:      "roadmap",
            FilePath:      fmt.Sprintf("downloads/roadmaps/v%02d/roadmap_v%02d.tsv", i+1, i+1),
            Size:          1024,
            Description:   "seeded",
            Uploader:      "alice",
            UploadTime:    now,
            Version:       i+1,
            IsLatest:      true,
            Status:        database.FileStatusActive,
            FileExists:    true,
            CreatedAt:     now,
            UpdatedAt:     now,
        }
        if err := db.InsertFileRecord(rec); err != nil { t.Fatalf("insert file: %v", err) }
    }

    // 1) Pagination contract
    req := httptest.NewRequest(http.MethodGet, "/api/v1/web/files/list?type=roadmap&page=1&limit=10", nil)
    req.AddCookie(cookie)
    rr := httptest.NewRecorder()
    srv.Router.ServeHTTP(rr, req)
    if rr.Code != http.StatusOK {
        t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
    }
    var body map[string]interface{}
    if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
        t.Fatalf("invalid json: %v", err)
    }
    data := body["data"].(map[string]interface{})
    if _, ok := data["count"]; !ok { t.Fatalf("missing count in response") }
    if _, ok := data["page"]; !ok { t.Fatalf("missing page in response") }
    if _, ok := data["limit"]; !ok { t.Fatalf("missing limit in response") }

    // 2) Error contract: upload without file should return structured VALIDATION_ERROR + request_id
    // Use a user with upload permissions
    _ = helpers.CreateTestUser(t, "uploader", "password123", "administrator")
    uploadCookie := helpers.LoginAndGetSessionCookie(t, srv.Router, "uploader", "password123")
    badReq := httptest.NewRequest(http.MethodPost, "/api/v1/web/upload", nil)
    badReq.AddCookie(uploadCookie)
    badRR := httptest.NewRecorder()
    srv.Router.ServeHTTP(badRR, badReq)
    if badRR.Code != http.StatusBadRequest {
        t.Fatalf("expected 400, got %d body=%s", badRR.Code, badRR.Body.String())
    }
    var errBody map[string]interface{}
    _ = json.Unmarshal(badRR.Body.Bytes(), &errBody)
    if errBody["code"] != "VALIDATION_ERROR" {
        t.Fatalf("expected code=VALIDATION_ERROR, got %v", errBody["code"])
    }
    if details, ok := errBody["details"].(map[string]interface{}); !ok || details["request_id"] == nil {
        t.Fatalf("expected details.request_id present, got %v", errBody["details"])
    }
}
