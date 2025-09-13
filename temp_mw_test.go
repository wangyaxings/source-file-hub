package middleware

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"secure-file-hub/internal/auth"
	"secure-file-hub/internal/middleware"
	"secure-file-hub/tests/helpers"
)

func TestCORS_Preflight(t *testing.T) {
	h := middleware.CorsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/web/health", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for OPTIONS, got %d", rr.Code)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got == "" {
		t.Fatalf("expected CORS headers, got none")
	}
}

func TestHTTPSRedirect_Redirects(t *testing.T) {
	os.Unsetenv("DISABLE_HTTPS_REDIRECT")
	h := middleware.HTTPSRedirectMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "http://localhost:9001/api/v1/web/health", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusMovedPermanently {
		t.Fatalf("expected 301 redirect, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if loc == "" || loc[:5] != "https" {
		t.Fatalf("expected https Location, got %q", loc)
	}
}

func TestHTTPSRedirect_Disabled(t *testing.T) {
	t.Setenv("DISABLE_HTTPS_REDIRECT", "true")
	h := middleware.HTTPSRedirectMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "http://localhost:9001/api/v1/web/health", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 when disabled, got %d", rr.Code)
	}
}

// TestCORS_AllowedOrigins tests CORS with specific allowed origins
func TestCORS_AllowedOrigins(t *testing.T) {
	h := middleware.CorsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Test with allowed origin
	req := httptest.NewRequest(http.MethodGet, "/api/v1/web/health", nil)
	req.Header.Set("Origin", "https://example.com")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	// Check CORS headers
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got == "" {
		t.Fatalf("expected CORS headers, got none")
	}
}

// TestCORS_Methods tests CORS with different HTTP methods
func TestCORS_Methods(t *testing.T) {
	h := middleware.CorsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	methods := []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions}

	for _, method := range methods {
		req := httptest.NewRequest(method, "/api/v1/web/health", nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200 for %s, got %d", method, rr.Code)
		}
	}
}

// TestLoggingMiddleware tests logging middleware
func TestLoggingMiddleware(t *testing.T) {
	h := middleware.LoggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/web/health", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	if rr.Body.String() != "test response" {
		t.Fatalf("expected 'test response', got '%s'", rr.Body.String())
	}
}

// TestAuthMiddleware_Unauthorized tests auth middleware with no token
func TestAuthMiddleware_Unauthorized(t *testing.T) {
	h := middleware.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/web/protected", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

// TestAuthMiddleware_Authorized tests auth middleware with valid token
func TestAuthMiddleware_Authorized(t *testing.T) {
	config := helpers.SetupTestEnvironment(t)
	_ = config

	// Create test user
	user := helpers.CreateTestUser(t, "testuser", "password123", "viewer")
	_ = user

	// Create auth user for context
	authUser := &auth.User{
		Username: "testuser",
		Role:     "viewer",
	}

	h := middleware.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if user is in context
		ctxUser := r.Context().Value("user")
		if ctxUser == nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/web/protected", nil)
	req = helpers.AddAuthContext(req, authUser)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

// TestAPIKeyAuthMiddleware_Unauthorized tests API key auth middleware with no key
func TestAPIKeyAuthMiddleware_Unauthorized(t *testing.T) {
	h := middleware.APIKeyAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/public/files", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

// TestAPIKeyAuthMiddleware_InvalidKey tests API key auth middleware with invalid key
func TestAPIKeyAuthMiddleware_InvalidKey(t *testing.T) {
	config := helpers.SetupTestEnvironment(t)
	_ = config

	h := middleware.APIKeyAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/public/files", nil)
	req.Header.Set("X-API-Key", "invalid_key")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

// TestAPIKeyAuthMiddleware_ValidKey tests API key auth middleware with valid key
func TestAPIKeyAuthMiddleware_ValidKey(t *testing.T) {
	config := helpers.SetupTestEnvironment(t)
	_ = config

	// Create test user and API key
	user := helpers.CreateTestUser(t, "testuser", "password123", "viewer")
	apiKey := helpers.CreateTestAPIKey(t, user.Username, "test_key", []string{"read"})

	h := middleware.APIKeyAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if API key is in context
		ctxKey := r.Context().Value("api_key")
		if ctxKey == nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/public/files", nil)
	req.Header.Set("X-API-Key", apiKey.KeyHash) // Use the original key value
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

// TestRequirePermission_Authorized tests permission middleware with authorized user
func TestRequirePermission_Authorized(t *testing.T) {
	config := helpers.SetupTestEnvironment(t)
	_ = config

	// Create test user
	helpers.CreateTestUser(t, "testuser", "password123", "admin")

	// Create auth user for context
	authUser := &auth.User{
		Username: "testuser",
		Role:     "admin",
	}

	h := middleware.RequirePermission("read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/web/files", nil)
	req = helpers.AddAuthContext(req, authUser)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

// TestRequirePermission_Unauthorized tests permission middleware with unauthorized user
func TestRequirePermission_Unauthorized(t *testing.T) {
	config := helpers.SetupTestEnvironment(t)
	_ = config

	// Create test user with limited permissions
	user := helpers.CreateTestUser(t, "testuser", "password123", "viewer")
	_ = user

	// Create auth user for context
	authUser := &auth.User{
		Username: "testuser",
		Role:     "viewer",
	}

	h := middleware.RequirePermission("admin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/web/admin", nil)
	req = helpers.AddAuthContext(req, authUser)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

// TestRequireAuthorization tests authorization middleware
func TestRequireAuthorization(t *testing.T) {
	config := helpers.SetupTestEnvironment(t)
	_ = config

	// Create test user
	user := helpers.CreateTestUser(t, "testuser", "password123", "viewer")
	_ = user

	// Create auth user for context
	authUser := &auth.User{
		Username: "testuser",
		Role:     "viewer",
	}

	h := middleware.RequireAuthorization(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/web/protected", nil)
	req = helpers.AddAuthContext(req, authUser)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

// TestRequireAuthorization_Unauthorized tests authorization middleware without auth
func TestRequireAuthorization_Unauthorized(t *testing.T) {
	h := middleware.RequireAuthorization(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/web/protected", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

// TestAPILoggingMiddleware tests API logging middleware
func TestAPILoggingMiddleware(t *testing.T) {
	config := helpers.SetupTestEnvironment(t)
	_ = config

	// Create test user and API key
	user := helpers.CreateTestUser(t, "testuser", "password123", "viewer")
	apiKey := helpers.CreateTestAPIKey(t, user.Username, "test_key", []string{"read"})

	h := middleware.APILoggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/public/files", nil)
	req.Header.Set("X-API-Key", apiKey.KeyHash)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	if rr.Body.String() != "test response" {
		t.Fatalf("expected 'test response', got '%s'", rr.Body.String())
	}
}

// TestRateLimitMiddleware tests rate limiting middleware
func TestRateLimitMiddleware(t *testing.T) {
	helpers.SetupTestEnvironment(t)
	t.Skip("RateLimitMiddleware function not implemented in middleware package")
}

// TestSecurityHeadersMiddleware tests security headers middleware
func TestSecurityHeadersMiddleware(t *testing.T) {
	helpers.SetupTestEnvironment(t)
	t.Skip("SecurityHeadersMiddleware function not implemented in middleware package")
}

// TestRequestIDMiddleware tests request ID middleware
func TestRequestIDMiddleware(t *testing.T) {
	helpers.SetupTestEnvironment(t)
	t.Skip("RequestIDMiddleware function not implemented in middleware package")
}

// TestTimeoutMiddleware tests timeout middleware
func TestTimeoutMiddleware(t *testing.T) {
	helpers.SetupTestEnvironment(t)
	t.Skip("TimeoutMiddleware function not implemented in middleware package")
}

// TestRecoveryMiddleware tests panic recovery middleware
func TestRecoveryMiddleware(t *testing.T) {
	helpers.SetupTestEnvironment(t)
	t.Skip("RecoveryMiddleware function not implemented in middleware package")
}

// TestMiddlewareChain tests multiple middleware chaining
func TestMiddlewareChain(t *testing.T) {
	helpers.SetupTestEnvironment(t)

	// Chain available middleware (CORS and Logging)
	h := middleware.CorsMiddleware(
		middleware.LoggingMiddleware(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("chained response"))
			}),
		),
	)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/web/health", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	if rr.Body.String() != "chained response" {
		t.Fatalf("expected 'chained response', got '%s'", rr.Body.String())
	}

	// Check that CORS headers are present
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got == "" {
		t.Error("expected CORS headers")
	}
}

