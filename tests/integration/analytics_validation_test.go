package integration

import (
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "os"
    "testing"
    "time"

    "secure-file-hub/internal/handler"
    "secure-file-hub/internal/server"
    "secure-file-hub/tests/helpers"
)

// setupAnalyticsServer creates a test server and returns session cookie for an admin user
func setupAnalyticsServer(t *testing.T) (*server.Server, *http.Cookie) {
    // Disable HTTPS redirect for tests
    oldHTTPSRedirect := os.Getenv("DISABLE_HTTPS_REDIRECT")
    os.Setenv("DISABLE_HTTPS_REDIRECT", "true")
    t.Cleanup(func() {
        if oldHTTPSRedirect == "" {
            os.Unsetenv("DISABLE_HTTPS_REDIRECT")
        } else {
            os.Setenv("DISABLE_HTTPS_REDIRECT", oldHTTPSRedirect)
        }
    })

    helpers.SetupTestEnvironment(t)

    srv := server.New()
    if srv == nil { t.Fatal("Failed to create server") }
    handler.RegisterRoutes(srv.Router)

    // Create admin user and login
    _ = helpers.CreateTestUser(t, "admin_analytics", "password123", "administrator")
    cookie := helpers.LoginAndGetSessionCookie(t, srv.Router, "admin_analytics", "password123")
    return srv, cookie
}

func TestAnalytics_ValidationErrors(t *testing.T) {
    srv, cookie := setupAnalyticsServer(t)

    cases := []struct{
        name string
        path string
    }{
        {"invalid_start_date", "/api/v1/web/admin/analytics/data?timeRange=custom&startDate=bad-start"},
        {"invalid_end_date", "/api/v1/web/admin/analytics/data?timeRange=custom&endDate=bad-end"},
        {"end_before_start", "/api/v1/web/admin/analytics/data?timeRange=custom&startDate=2025-09-14T10:00:00Z&endDate=2025-09-14T09:00:00Z"},
    }

    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            req := httptest.NewRequest(http.MethodGet, tc.path, nil)
            req.AddCookie(cookie)
            rr := httptest.NewRecorder()
            srv.Router.ServeHTTP(rr, req)

            if rr.Code != http.StatusBadRequest {
                t.Fatalf("expected 400, got %d; body=%s", rr.Code, rr.Body.String())
            }
            var body map[string]interface{}
            _ = json.Unmarshal(rr.Body.Bytes(), &body)
            if body["code"] != "VALIDATION_ERROR" {
                t.Fatalf("expected code=VALIDATION_ERROR, got %v", body["code"])
            }
            // details.request_id should be present for tracing
            if details, ok := body["details"].(map[string]interface{}); !ok || details["request_id"] == nil {
                t.Fatalf("expected details.request_id present, got %v", body["details"])
            }
        })
    }

    // > 90 days range should be rejected with max_days detail
    start := time.Now().AddDate(0, 0, -100).UTC().Format(time.RFC3339)
    end := time.Now().UTC().Format(time.RFC3339)
    req := httptest.NewRequest(http.MethodGet, "/api/v1/web/admin/analytics/data?timeRange=custom&startDate="+start+"&endDate="+end, nil)
    req.AddCookie(cookie)
    rr := httptest.NewRecorder()
    srv.Router.ServeHTTP(rr, req)
    if rr.Code != http.StatusBadRequest {
        t.Fatalf(">90d expected 400, got %d; body=%s", rr.Code, rr.Body.String())
    }
    var body map[string]interface{}
    _ = json.Unmarshal(rr.Body.Bytes(), &body)
    if body["code"] != "VALIDATION_ERROR" {
        t.Fatalf(">90d expected code=VALIDATION_ERROR, got %v", body["code"])
    }
    if details, ok := body["details"].(map[string]interface{}); !ok || details["max_days"] == nil {
        t.Fatalf(">90d expected details.max_days present, got %v", body["details"])
    }
}
