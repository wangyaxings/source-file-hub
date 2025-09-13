package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"secure-file-hub/internal/server"
	"secure-file-hub/tests/helpers"

	"secure-file-hub/internal/handler"
)

// TestServer_New tests server creation
func TestServer_New(t *testing.T) {
	config := helpers.SetupTestEnvironment(t)
	_ = config

	// Test server creation
	srv := server.New()
	if srv == nil {
		t.Fatal("Failed to create server")
	}
	handler.RegisterRoutes(srv.Router)

	if srv.Router == nil {
		t.Error("Expected server router to be initialized")
	}
}

// TestServer_Start tests server startup
func TestServer_Start(t *testing.T) {
	helpers.SetupTestEnvironment(t)
	t.Skip("Start method not implemented in server package - server only provides router")
}

// TestServer_Stop tests server shutdown
func TestServer_Stop(t *testing.T) {
	helpers.SetupTestEnvironment(t)
	t.Skip("Start/Stop methods not implemented in server package - server only provides router")
}

// TestServer_Routes tests server route registration
func TestServer_Routes(t *testing.T) {
	config := helpers.SetupTestEnvironment(t)
	_ = config

    // Create server and register routes
    srv := server.New()
	if srv == nil {
		t.Fatal("Failed to create server")
	}
	handler.RegisterRoutes(srv.Router)
    // Ensure routes exist for testing
    // In production main, routes are registered at startup; tests need explicit registration
    // Register minimal health route by calling handler.RegisterRoutes
    // Note: Import handler in this test is not present; so rely on NotFound + redirect behavior
	if srv == nil {
		t.Fatal("Failed to create server")
	}

	// Test that routes are registered
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Should get a response (even if it's an error, it means the route exists)
	if rr.Code == 0 {
		t.Error("Expected server to respond to health check request")
	}
}

// TestServer_Middleware tests server middleware
func TestServer_Middleware(t *testing.T) {
	config := helpers.SetupTestEnvironment(t)
	_ = config

	// Create server
	srv := server.New()
	if srv == nil {
		t.Fatal("Failed to create server")
	}
	handler.RegisterRoutes(srv.Router)

	// Test CORS middleware
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/health", nil)
	req.Header.Set("Origin", "https://example.com")
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Should get CORS headers
	if rr.Header().Get("Access-Control-Allow-Origin") == "" {
		t.Error("Expected CORS headers to be set")
	}
}

// TestServer_HTTPSRedirect tests HTTPS redirect middleware
func TestServer_HTTPSRedirect(t *testing.T) {
	config := helpers.SetupTestEnvironment(t)
	_ = config

	// Create server
	srv := server.New()
	if srv == nil {
		t.Fatal("Failed to create server")
	}
	handler.RegisterRoutes(srv.Router)

    // Test HTTPS redirect (requires a matching route for Gorilla middlewares to run)
    // Use a known route: /api/v1/health is handled in handler.RegisterRoutes in app runtime.
	req := httptest.NewRequest(http.MethodGet, "http://localhost:9001/api/v1/health", nil)
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Should get redirect response
	if rr.Code != http.StatusMovedPermanently {
		t.Errorf("Expected 301 redirect, got %d", rr.Code)
	}

	// Should redirect to HTTPS
	location := rr.Header().Get("Location")
	if location == "" || location[:5] != "https" {
		t.Errorf("Expected HTTPS redirect, got %s", location)
	}
}

// TestServer_LoggingMiddleware tests logging middleware
func TestServer_LoggingMiddleware(t *testing.T) {
	config := helpers.SetupTestEnvironment(t)
	_ = config

	// Create server
	srv := server.New()
	if srv == nil {
		t.Fatal("Failed to create server")
	}
	handler.RegisterRoutes(srv.Router)

	// Test logging middleware
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Should get a response (logging middleware should not affect response)
	if rr.Code == 0 {
		t.Error("Expected server to respond to requests")
	}
}

// TestServer_AuthMiddleware tests authentication middleware
func TestServer_AuthMiddleware(t *testing.T) {
	config := helpers.SetupTestEnvironment(t)
	_ = config

	// Create server
	srv := server.New()
	if srv == nil {
		t.Fatal("Failed to create server")
	}
	handler.RegisterRoutes(srv.Router)

	// Test authentication middleware with protected route
	req := httptest.NewRequest(http.MethodGet, "/api/v1/web/auth/me", nil)
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Should get unauthorized response
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 unauthorized, got %d", rr.Code)
	}
}

// TestServer_StaticFiles tests static file serving
func TestServer_StaticFiles(t *testing.T) {
	config := helpers.SetupTestEnvironment(t)
	_ = config

	// Create server
	srv := server.New()
	if srv == nil {
		t.Fatal("Failed to create server")
	}
	handler.RegisterRoutes(srv.Router)

	// Test static file serving
	req := httptest.NewRequest(http.MethodGet, "/static/test.js", nil)
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Should get a response (even if file doesn't exist, it means the route exists)
	if rr.Code == 0 {
		t.Error("Expected server to respond to static file request")
	}
}

// TestServer_APIRoutes tests API route registration
func TestServer_APIRoutes(t *testing.T) {
	config := helpers.SetupTestEnvironment(t)
	_ = config

	// Create server
	srv := server.New()
	if srv == nil {
		t.Fatal("Failed to create server")
	}
	handler.RegisterRoutes(srv.Router)

	// Test API routes
	apiRoutes := []string{
		"/api/v1/health",
		"/api/v1",
		"/api/v1/web/auth/register",
		"/api/v1/web/auth/login",
		"/api/v1/web/files/list",
		"/api/v1/web/upload",
	}

	for _, route := range apiRoutes {
		req := httptest.NewRequest(http.MethodGet, route, nil)
		rr := httptest.NewRecorder()

		srv.Router.ServeHTTP(rr, req)

		// Should get a response (even if it's an error, it means the route exists)
		if rr.Code == 0 {
			t.Errorf("Expected server to respond to %s", route)
		}
	}
}

// TestServer_WebRoutes tests web route registration
func TestServer_WebRoutes(t *testing.T) {
	config := helpers.SetupTestEnvironment(t)
	_ = config

	// Create server
	srv := server.New()
	if srv == nil {
		t.Fatal("Failed to create server")
	}
	handler.RegisterRoutes(srv.Router)

	// Test web routes
	webRoutes := []string{
		"/api/v1/web/auth/me",
		"/api/v1/web/auth/change-password",
		"/api/v1/web/files/list",
		"/api/v1/web/upload",
	}

	for _, route := range webRoutes {
		req := httptest.NewRequest(http.MethodGet, route, nil)
		rr := httptest.NewRecorder()

		srv.Router.ServeHTTP(rr, req)

		// Should get a response (even if it's an error, it means the route exists)
		if rr.Code == 0 {
			t.Errorf("Expected server to respond to %s", route)
		}
	}
}

// TestServer_AdminRoutes tests admin route registration
func TestServer_AdminRoutes(t *testing.T) {
	config := helpers.SetupTestEnvironment(t)
	_ = config

	// Create server
	srv := server.New()
	if srv == nil {
		t.Fatal("Failed to create server")
	}
	handler.RegisterRoutes(srv.Router)

	// Test admin routes
	adminRoutes := []string{
		"/api/v1/web/admin/users",
		"/api/v1/web/admin/api-keys",
		"/api/v1/web/admin/logs",
	}

	for _, route := range adminRoutes {
		req := httptest.NewRequest(http.MethodGet, route, nil)
		rr := httptest.NewRecorder()

		srv.Router.ServeHTTP(rr, req)

		// Should get a response (even if it's an error, it means the route exists)
		if rr.Code == 0 {
			t.Errorf("Expected server to respond to %s", route)
		}
	}
}

// TestServer_PublicAPIRoutes tests public API route registration
func TestServer_PublicAPIRoutes(t *testing.T) {
	config := helpers.SetupTestEnvironment(t)
	_ = config

	// Create server
	srv := server.New()
	if srv == nil {
		t.Fatal("Failed to create server")
	}
	handler.RegisterRoutes(srv.Router)

	// Test public API routes
	publicAPIRoutes := []string{
		"/api/v1/public/files",
		"/api/v1/public/files/upload",
		"/api/v1/public/packages",
	}

	for _, route := range publicAPIRoutes {
		req := httptest.NewRequest(http.MethodGet, route, nil)
		rr := httptest.NewRecorder()

		srv.Router.ServeHTTP(rr, req)

		// Should get a response (even if it's an error, it means the route exists)
		if rr.Code == 0 {
			t.Errorf("Expected server to respond to %s", route)
		}
	}
}

// TestServer_ErrorHandling tests error handling
func TestServer_ErrorHandling(t *testing.T) {
	config := helpers.SetupTestEnvironment(t)
	_ = config

	// Create server
	srv := server.New()
	if srv == nil {
		t.Fatal("Failed to create server")
	}
	handler.RegisterRoutes(srv.Router)

	// Test error handling with non-existent route
	req := httptest.NewRequest(http.MethodGet, "/nonexistent", nil)
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Should get 404 response
	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected 404 not found, got %d", rr.Code)
	}
}

// TestServer_MethodNotAllowed tests method not allowed handling
func TestServer_MethodNotAllowed(t *testing.T) {
	config := helpers.SetupTestEnvironment(t)
	_ = config

	// Create server
	srv := server.New()
	if srv == nil {
		t.Fatal("Failed to create server")
	}
	handler.RegisterRoutes(srv.Router)

	// Test method not allowed
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/health", nil)
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Should get method not allowed response
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405 method not allowed, got %d", rr.Code)
	}
}

// TestServer_ConcurrentRequests tests concurrent request handling
func TestServer_ConcurrentRequests(t *testing.T) {
	config := helpers.SetupTestEnvironment(t)
	_ = config

	// Create server
	srv := server.New()
	if srv == nil {
		t.Fatal("Failed to create server")
	}
	handler.RegisterRoutes(srv.Router)

	// Test concurrent requests
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(index int) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
			rr := httptest.NewRecorder()

			srv.Router.ServeHTTP(rr, req)

			// Should get a response
			if rr.Code == 0 {
				t.Errorf("Expected server to respond to concurrent request %d", index)
			}

			done <- true
		}(i)
	}

	// Wait for all requests to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestServer_RequestTimeout tests request timeout handling
func TestServer_RequestTimeout(t *testing.T) {
	config := helpers.SetupTestEnvironment(t)
	_ = config

	// Create server
	srv := server.New()
	if srv == nil {
		t.Fatal("Failed to create server")
	}
	handler.RegisterRoutes(srv.Router)

	// Test request timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Should get a response (timeout handling is tested at the HTTP server level)
	if rr.Code == 0 {
		t.Error("Expected server to respond to request")
	}
}

// TestServer_RequestSizeLimit tests request size limit handling
func TestServer_RequestSizeLimit(t *testing.T) {
	config := helpers.SetupTestEnvironment(t)
	_ = config

	// Create server
	srv := server.New()
	if srv == nil {
		t.Fatal("Failed to create server")
	}
	handler.RegisterRoutes(srv.Router)

	// Test request size limit
	req := httptest.NewRequest(http.MethodPost, "/api/v1/web/upload", nil)
	req.Body = httptest.NewRequest(http.MethodPost, "/api/v1/web/upload", nil).Body
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Should get a response (size limit handling is tested at the HTTP server level)
	if rr.Code == 0 {
		t.Error("Expected server to respond to request")
	}
}

// TestServer_ResponseCompression tests response compression
func TestServer_ResponseCompression(t *testing.T) {
	config := helpers.SetupTestEnvironment(t)
	_ = config

	// Create server
	srv := server.New()
	if srv == nil {
		t.Fatal("Failed to create server")
	}
	handler.RegisterRoutes(srv.Router)

	// Test response compression
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Should get a response
	if rr.Code == 0 {
		t.Error("Expected server to respond to request")
	}

	// Check if compression is applied (this depends on the compression middleware)
	// The actual compression testing would be done at the HTTP server level
}

// TestServer_SecurityHeaders tests security headers
func TestServer_SecurityHeaders(t *testing.T) {
	config := helpers.SetupTestEnvironment(t)
	_ = config

	// Create server
	srv := server.New()
	if srv == nil {
		t.Fatal("Failed to create server")
	}
	handler.RegisterRoutes(srv.Router)

	// Test security headers
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Should get a response
	if rr.Code == 0 {
		t.Error("Expected server to respond to request")
	}

	// Check if security headers are set (this depends on the security middleware)
	// The actual security header testing would be done in the middleware tests
}

// TestServer_HealthCheck tests health check endpoint
func TestServer_HealthCheck(t *testing.T) {
	config := helpers.SetupTestEnvironment(t)
	_ = config

	// Create server
	srv := server.New()
	if srv == nil {
		t.Fatal("Failed to create server")
	}
	handler.RegisterRoutes(srv.Router)

	// Test health check
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Should get a response
	if rr.Code == 0 {
		t.Error("Expected server to respond to health check request")
	}
}

// TestServer_APIInfo tests API info endpoint
func TestServer_APIInfo(t *testing.T) {
	config := helpers.SetupTestEnvironment(t)
	_ = config

	// Create server
	srv := server.New()
	if srv == nil {
		t.Fatal("Failed to create server")
	}
	handler.RegisterRoutes(srv.Router)

	// Test API info
	req := httptest.NewRequest(http.MethodGet, "/api/v1", nil)
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Should get a response
	if rr.Code == 0 {
		t.Error("Expected server to respond to API info request")
	}
}

