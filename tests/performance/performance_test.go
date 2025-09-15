package performance

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"testing"
	"time"

	"secure-file-hub/internal/database"
	"secure-file-hub/tests/helpers"
)

// BenchmarkHealthHandler benchmarks the health check endpoint
func BenchmarkHealthHandler(b *testing.B) {
	srv := helpers.CreateTestServer(&testing.T{})

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
			rr := httptest.NewRecorder()
			srv.Router.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				b.Errorf("Expected status 200, got %d", rr.Code)
			}
		}
	})
}

// BenchmarkPermissionCheck benchmarks permission check operations
func BenchmarkPermissionCheck(b *testing.B) {
	srv := helpers.CreateTestServer(&testing.T{})

	// Create test user
	user := helpers.CreateTestUser(&testing.T{}, "benchuser", "BenchPassword123!", "viewer")
	cookie := helpers.LoginAndGetSessionCookie(&testing.T{}, srv.Router, user.Username, "BenchPassword123!")

	permissionData := map[string]string{
		"resource": "files",
		"action":   "read",
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := helpers.CreateTestRequest(&testing.T{}, http.MethodPost, "/api/v1/web/auth/check-permission", permissionData, nil)
			req.AddCookie(cookie)
			rr := httptest.NewRecorder()
			srv.Router.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				b.Errorf("Expected status 200, got %d", rr.Code)
			}
		}
	})
}

// BenchmarkFileUpload benchmarks file upload operations
func BenchmarkFileUpload(b *testing.B) {
	srv := helpers.CreateTestServer(&testing.T{})

	// Create test user
	user := helpers.CreateTestUser(&testing.T{}, "uploadbenchuser", "UploadBench123!", "admin")
	cookie := helpers.LoginAndGetSessionCookie(&testing.T{}, srv.Router, user.Username, "UploadBench123!")

	fileContent := "This is a benchmark test file"

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			filename := fmt.Sprintf("benchmark_%d.tsv", time.Now().UnixNano())
			req := helpers.CreateMultipartRequest(&testing.T{}, "/api/v1/web/upload", filename, fileContent, map[string]string{
				"fileType":    "roadmap",
				"description": "Benchmark test file",
			})
			req.AddCookie(cookie)
			rr := httptest.NewRecorder()
			srv.Router.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				b.Errorf("Expected status 200, got %d", rr.Code)
			}
		}
	})
}

// BenchmarkFileList benchmarks file list operations
func BenchmarkFileList(b *testing.B) {
	srv := helpers.CreateTestServer(&testing.T{})

	// Create test user
	user := helpers.CreateTestUser(&testing.T{}, "listbenchuser", "ListBench123!", "viewer")
	cookie := helpers.LoginAndGetSessionCookie(&testing.T{}, srv.Router, user.Username, "ListBench123!")

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/web/files/list", nil)
			req.AddCookie(cookie)
			rr := httptest.NewRecorder()
			srv.Router.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				b.Errorf("Expected status 200, got %d", rr.Code)
			}
		}
	})
}

// TestConcurrentUsers tests concurrent user operations
func TestConcurrentUsers(t *testing.T) {
	srv := helpers.CreateTestServer(t)

	// Create multiple test users
	userCount := 50
	users := make([]struct {
		user   *database.AppUser
		cookie *http.Cookie
	}, userCount)

	for i := 0; i < userCount; i++ {
		username := fmt.Sprintf("concurrentuser%d", i)
		password := "Concurrent123!"
		user := helpers.CreateTestUser(t, username, password, "viewer")
		cookie := helpers.LoginAndGetSessionCookie(t, srv.Router, username, password)
		users[i] = struct {
			user   *database.AppUser
			cookie *http.Cookie
		}{user, cookie}
	}

	// Test concurrent operations
	var wg sync.WaitGroup
	concurrency := 10

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			// Each worker performs multiple operations
			for j := 0; j < 10; j++ {
				userIndex := (workerID*10 + j) % userCount
				user := users[userIndex]

				// Test permission check
				permissionData := map[string]string{
					"resource": "files",
					"action":   "read",
				}

				req := helpers.CreateTestRequest(t, http.MethodPost, "/api/v1/web/auth/check-permission", permissionData, nil)
				req.AddCookie(user.cookie)
				rr := httptest.NewRecorder()
				srv.Router.ServeHTTP(rr, req)

				if rr.Code != http.StatusOK {
					t.Errorf("Worker %d, operation %d: Expected status 200, got %d", workerID, j, rr.Code)
				}

				// Test file list
				req = httptest.NewRequest(http.MethodGet, "/api/v1/web/files/list", nil)
				req.AddCookie(user.cookie)
				rr = httptest.NewRecorder()
				srv.Router.ServeHTTP(rr, req)

				if rr.Code != http.StatusOK {
					t.Errorf("Worker %d, operation %d: Expected status 200 for file list, got %d", workerID, j, rr.Code)
				}
			}
		}(i)
	}

	wg.Wait()
}

// TestMemoryUsage tests memory usage under load
func TestMemoryUsage(t *testing.T) {
	srv := helpers.CreateTestServer(t)

	// Get initial memory stats
	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)

	// Create test user
	user := helpers.CreateTestUser(t, "memoryuser", "Memory123!", "admin")
	cookie := helpers.LoginAndGetSessionCookie(t, srv.Router, user.Username, "Memory123!")

	// Perform many operations
	operations := 1000
	for i := 0; i < operations; i++ {
		// Test permission check
		permissionData := map[string]string{
			"resource": "files",
			"action":   "read",
		}

		req := helpers.CreateTestRequest(t, http.MethodPost, "/api/v1/web/auth/check-permission", permissionData, nil)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		srv.Router.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Operation %d: Expected status 200, got %d", i, rr.Code)
		}

		// Force garbage collection every 100 operations
		if i%100 == 0 {
			runtime.GC()
		}
	}

	// Get final memory stats
	runtime.GC()
	runtime.ReadMemStats(&m2)

	// Calculate memory usage
	memoryUsed := m2.Alloc - m1.Alloc
	memoryPerOperation := memoryUsed / uint64(operations)

	t.Logf("Memory usage: %d bytes total, %d bytes per operation", memoryUsed, memoryPerOperation)

	// Memory usage should be reasonable (less than 1KB per operation)
	if memoryPerOperation > 1024 {
		t.Errorf("Memory usage per operation (%d bytes) is too high", memoryPerOperation)
	}
}

// TestResponseTime tests response times under load
func TestResponseTime(t *testing.T) {
	srv := helpers.CreateTestServer(t)

	// Create test user
	user := helpers.CreateTestUser(t, "responsetimeuser", "ResponseTime123!", "viewer")
	cookie := helpers.LoginAndGetSessionCookie(t, srv.Router, user.Username, "ResponseTime123!")

	// Test different endpoints
	endpoints := []struct {
		name   string
		url    string
		method string
		body   interface{}
	}{
		{"Health", "/api/v1/health", http.MethodGet, nil},
		{"PermissionCheck", "/api/v1/web/auth/check-permission", http.MethodPost, map[string]string{
			"resource": "files",
			"action":   "read",
		}},
		{"FileList", "/api/v1/web/files/list", http.MethodGet, nil},
	}

	for _, endpoint := range endpoints {
		t.Run(endpoint.name, func(t *testing.T) {
			var totalTime time.Duration
			iterations := 100

			for i := 0; i < iterations; i++ {
				start := time.Now()

				var req *http.Request
				if endpoint.body != nil {
					req = helpers.CreateTestRequest(t, endpoint.method, endpoint.url, endpoint.body, nil)
					req.AddCookie(cookie)
				} else {
					req = httptest.NewRequest(endpoint.method, endpoint.url, nil)
					if endpoint.name != "Health" {
						req.AddCookie(cookie)
					}
				}

				rr := httptest.NewRecorder()
				srv.Router.ServeHTTP(rr, req)

				elapsed := time.Since(start)
				totalTime += elapsed

				if rr.Code != http.StatusOK {
					t.Errorf("Expected status 200, got %d", rr.Code)
				}
			}

			avgTime := totalTime / time.Duration(iterations)
			t.Logf("Average response time for %s: %v", endpoint.name, avgTime)

			// Response time should be reasonable (less than 100ms)
			if avgTime > 100*time.Millisecond {
				t.Errorf("Average response time for %s (%v) is too slow", endpoint.name, avgTime)
			}
		})
	}
}

// TestConcurrentFileOperations tests concurrent file operations
func TestConcurrentFileOperations(t *testing.T) {
	srv := helpers.CreateTestServer(t)

	// Create test user
	user := helpers.CreateTestUser(t, "concurrentfileuser", "ConcurrentFile123!", "admin")
	cookie := helpers.LoginAndGetSessionCookie(t, srv.Router, user.Username, "ConcurrentFile123!")

	// Test concurrent file uploads
	concurrency := 20
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			fileContent := fmt.Sprintf("Concurrent file content %d", index)
			filename := fmt.Sprintf("concurrent_%d.tsv", index)

			req := helpers.CreateMultipartRequest(t, "/api/v1/web/upload", filename, fileContent, map[string]string{
				"fileType":    "roadmap",
				"description": fmt.Sprintf("Concurrent test file %d", index),
			})
			req.AddCookie(cookie)
			rr := httptest.NewRecorder()
			srv.Router.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("Concurrent upload %d failed with status %d", index, rr.Code)
			}
		}(i)
	}

	wg.Wait()
}

// TestStressTest performs a stress test with high concurrency
func TestStressTest(t *testing.T) {
	srv := helpers.CreateTestServer(t)

	// Create test user
	user := helpers.CreateTestUser(t, "stressuser", "Stress123!", "viewer")
	cookie := helpers.LoginAndGetSessionCookie(t, srv.Router, user.Username, "Stress123!")

	// High concurrency stress test
	concurrency := 100
	operationsPerWorker := 10
	var wg sync.WaitGroup

	start := time.Now()

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for j := 0; j < operationsPerWorker; j++ {
				// Mix of different operations
				switch j % 3 {
				case 0:
					// Permission check
					permissionData := map[string]string{
						"resource": "files",
						"action":   "read",
					}
					req := helpers.CreateTestRequest(t, http.MethodPost, "/api/v1/web/auth/check-permission", permissionData, nil)
					req.AddCookie(cookie)
					rr := httptest.NewRecorder()
					srv.Router.ServeHTTP(rr, req)

					if rr.Code != http.StatusOK {
						t.Errorf("Worker %d, operation %d: Permission check failed with status %d", workerID, j, rr.Code)
					}

				case 1:
					// File list
					req := httptest.NewRequest(http.MethodGet, "/api/v1/web/files/list", nil)
					req.AddCookie(cookie)
					rr := httptest.NewRecorder()
					srv.Router.ServeHTTP(rr, req)

					if rr.Code != http.StatusOK {
						t.Errorf("Worker %d, operation %d: File list failed with status %d", workerID, j, rr.Code)
					}

				case 2:
					// Health check
					req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
					rr := httptest.NewRecorder()
					srv.Router.ServeHTTP(rr, req)

					if rr.Code != http.StatusOK {
						t.Errorf("Worker %d, operation %d: Health check failed with status %d", workerID, j, rr.Code)
					}
				}
			}
		}(i)
	}

	wg.Wait()

	elapsed := time.Since(start)
	totalOperations := concurrency * operationsPerWorker
	opsPerSecond := float64(totalOperations) / elapsed.Seconds()

	t.Logf("Stress test completed: %d operations in %v (%.2f ops/sec)", totalOperations, elapsed, opsPerSecond)

	// Should handle at least 1000 operations per second
	if opsPerSecond < 1000 {
		t.Errorf("Performance too low: %.2f ops/sec (expected at least 1000)", opsPerSecond)
	}
}

// BenchmarkDatabaseOperations benchmarks database operations
func BenchmarkDatabaseOperations(b *testing.B) {
	// This would benchmark direct database operations
	// For now, we'll benchmark through HTTP endpoints

	srv := helpers.CreateTestServer(&testing.T{})
	user := helpers.CreateTestUser(&testing.T{}, "dbbenchuser", "DbBench123!", "viewer")
	cookie := helpers.LoginAndGetSessionCookie(&testing.T{}, srv.Router, user.Username, "DbBench123!")

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Test file list (database operation)
			req := httptest.NewRequest(http.MethodGet, "/api/v1/web/files/list", nil)
			req.AddCookie(cookie)
			rr := httptest.NewRecorder()
			srv.Router.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				b.Errorf("Expected status 200, got %d", rr.Code)
			}
		}
	})
}
