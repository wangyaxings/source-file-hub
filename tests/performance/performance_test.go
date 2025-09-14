package performance

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"secure-file-hub/internal/server"
	"secure-file-hub/tests/helpers"
)

// setupPerformanceTestServer creates a test server for performance testing
func setupPerformanceTestServer(t testing.TB) *server.Server {
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

	// Create server
	srv := server.New()
	if srv == nil {
		t.Fatal("Failed to create server")
	}

	return srv
}

// BenchmarkHealthCheck benchmarks the health check endpoint
func BenchmarkHealthCheck(b *testing.B) {
	srv := setupPerformanceTestServer(b)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		srv.Router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			b.Fatalf("Health check failed: %d", rr.Code)
		}
	}
}

// BenchmarkFileUpload benchmarks file upload performance
func BenchmarkFileUpload(b *testing.B) {
	srv := setupPerformanceTestServer(b)

	// Create test user
	user := helpers.CreateTestUser(b, "perfuser", "PerfUser123!", "admin")
	cookie := helpers.LoginAndGetSessionCookie(b, srv.Router, user.Username, "PerfUser123!")

	// Create test file content
	fileContent := "Performance test file content"
	req := helpers.CreateMultipartRequest(b, "/api/v1/web/upload", "perf_test.tsv", fileContent, map[string]string{
		"fileType":    "roadmap",
		"description": "Performance test",
	})
	req.AddCookie(cookie)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		srv.Router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			b.Fatalf("File upload failed: %d", rr.Code)
		}
	}
}

// BenchmarkFileList benchmarks file listing performance
func BenchmarkFileList(b *testing.B) {
	srv := setupPerformanceTestServer(b)

	// Create test user
	user := helpers.CreateTestUser(b, "listuser", "ListUser123!", "viewer")
	cookie := helpers.LoginAndGetSessionCookie(b, srv.Router, user.Username, "ListUser123!")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/web/files/list", nil)
	req.AddCookie(cookie)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		srv.Router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			b.Fatalf("File list failed: %d", rr.Code)
		}
	}
}

// BenchmarkAuthentication benchmarks authentication performance
func BenchmarkAuthentication(b *testing.B) {
	srv := setupPerformanceTestServer(b)

	// Create test user
	user := helpers.CreateTestUser(b, "authuser", "AuthUser123!", "viewer")

	loginData := map[string]string{
		"username": user.Username,
		"password": "AuthUser123!",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := helpers.CreateTestRequest(b, http.MethodPost, "/api/v1/web/auth/ab/login", loginData, nil)
		rr := httptest.NewRecorder()
		srv.Router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK && rr.Code != http.StatusFound && rr.Code != http.StatusTemporaryRedirect {
			b.Fatalf("Authentication failed: %d", rr.Code)
		}
	}
}

// BenchmarkConcurrentRequests benchmarks concurrent request handling
func BenchmarkConcurrentRequests(b *testing.B) {
	srv := setupPerformanceTestServer(b)

	// Create test user
	user := helpers.CreateTestUser(b, "concurrentuser", "ConcurrentUser123!", "viewer")
	_ = helpers.LoginAndGetSessionCookie(b, srv.Router, user.Username, "ConcurrentUser123!")

	concurrency := 10
	_ = b.N / concurrency

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
		for pb.Next() {
			rr := httptest.NewRecorder()
			srv.Router.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				b.Fatalf("Concurrent request failed: %d", rr.Code)
			}
		}
	})
}

// BenchmarkMemoryUsage benchmarks memory usage during operations
func BenchmarkMemoryUsage(b *testing.B) {
	srv := setupPerformanceTestServer(b)

	// Create test user
	user := helpers.CreateTestUser(b, "memuser", "MemUser123!", "admin")
	cookie := helpers.LoginAndGetSessionCookie(b, srv.Router, user.Username, "MemUser123!")

	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Perform file upload
		fileContent := fmt.Sprintf("Memory test file %d", i)
		req := helpers.CreateMultipartRequest(b, "/api/v1/web/upload", fmt.Sprintf("mem_test_%d.tsv", i), fileContent, map[string]string{
			"fileType":    "roadmap",
			"description": fmt.Sprintf("Memory test %d", i),
		})
		req.AddCookie(cookie)

		rr := httptest.NewRecorder()
		srv.Router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			b.Fatalf("Memory test upload failed: %d", rr.Code)
		}
	}

	runtime.GC()
	runtime.ReadMemStats(&m2)

	b.ReportMetric(float64(m2.Alloc-m1.Alloc), "bytes/op")
	b.ReportMetric(float64(m2.Mallocs-m1.Mallocs), "mallocs/op")
}

// TestPerformance_LoadTest performs a load test with multiple concurrent users
func TestPerformance_LoadTest(t *testing.T) {
	srv := setupPerformanceTestServer(t)

	// Create multiple test users
	users := make([]struct {
		username string
		password string
		cookie   *http.Cookie
	}, 10)

	for i := 0; i < 10; i++ {
		username := fmt.Sprintf("loaduser%d", i)
		password := "LoadUser123!"
		helpers.CreateTestUser(t, username, password, "viewer")
		cookie := helpers.LoginAndGetSessionCookie(t, srv.Router, username, password)
		users[i] = struct {
			username string
			password string
			cookie   *http.Cookie
		}{username, password, cookie}
	}

	// Load test parameters
	concurrency := 50
	requestsPerUser := 20
	totalRequests := concurrency * requestsPerUser

	start := time.Now()
	var wg sync.WaitGroup
	successCount := 0
	var mu sync.Mutex

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(userIndex int) {
			defer wg.Done()

			user := users[userIndex%len(users)]
			for j := 0; j < requestsPerUser; j++ {
				req := httptest.NewRequest(http.MethodGet, "/api/v1/web/auth/me", nil)
				req.AddCookie(user.cookie)
				rr := httptest.NewRecorder()

				srv.Router.ServeHTTP(rr, req)

				mu.Lock()
				if rr.Code == http.StatusOK {
					successCount++
				}
				mu.Unlock()
			}
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(start)

	// Calculate metrics
	rps := float64(totalRequests) / elapsed.Seconds()
	successRate := float64(successCount) / float64(totalRequests) * 100

	t.Logf("Load Test Results:")
	t.Logf("  Total Requests: %d", totalRequests)
	t.Logf("  Successful Requests: %d", successCount)
	t.Logf("  Success Rate: %.2f%%", successRate)
	t.Logf("  Requests per Second: %.2f", rps)
	t.Logf("  Total Time: %v", elapsed)
	t.Logf("  Average Response Time: %v", elapsed/time.Duration(totalRequests))

	// Performance assertions
	if successRate < 95 {
		t.Errorf("Success rate too low: %.2f%%", successRate)
	}
	if rps < 100 {
		t.Errorf("Requests per second too low: %.2f", rps)
	}
}

// TestPerformance_StressTest performs a stress test with high load
func TestPerformance_StressTest(t *testing.T) {
	srv := setupPerformanceTestServer(t)

	// Create test user
	user := helpers.CreateTestUser(t, "stressuser", "StressUser123!", "admin")
	_ = helpers.LoginAndGetSessionCookie(t, srv.Router, user.Username, "StressUser123!")

	// Stress test parameters
	concurrency := 100
	duration := 30 * time.Second

	start := time.Now()
	var wg sync.WaitGroup
	requestCount := 0
	errorCount := 0
	var mu sync.Mutex

	// Start stress test
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for time.Since(start) < duration {
				req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
				rr := httptest.NewRecorder()

				srv.Router.ServeHTTP(rr, req)

				mu.Lock()
				requestCount++
				if rr.Code != http.StatusOK {
					errorCount++
				}
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	elapsed := time.Since(start)

	// Calculate metrics
	rps := float64(requestCount) / elapsed.Seconds()
	errorRate := float64(errorCount) / float64(requestCount) * 100

	t.Logf("Stress Test Results:")
	t.Logf("  Total Requests: %d", requestCount)
	t.Logf("  Errors: %d", errorCount)
	t.Logf("  Error Rate: %.2f%%", errorRate)
	t.Logf("  Requests per Second: %.2f", rps)
	t.Logf("  Duration: %v", elapsed)

	// Stress test assertions
	if errorRate > 5 {
		t.Errorf("Error rate too high: %.2f%%", errorRate)
	}
	if rps < 50 {
		t.Errorf("Requests per second too low under stress: %.2f", rps)
	}
}

// TestPerformance_FileUploadStress tests file upload under stress
func TestPerformance_FileUploadStress(t *testing.T) {
	srv := setupPerformanceTestServer(t)

	// Create test user
	user := helpers.CreateTestUser(t, "uploadstressuser", "UploadStress123!", "admin")
	cookie := helpers.LoginAndGetSessionCookie(t, srv.Router, user.Username, "UploadStress123!")

	// Stress test parameters
	concurrency := 20
	uploadsPerGoroutine := 5

	start := time.Now()
	var wg sync.WaitGroup
	successCount := 0
	errorCount := 0
	var mu sync.Mutex

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			for j := 0; j < uploadsPerGoroutine; j++ {
				fileContent := fmt.Sprintf("Stress upload test %d-%d", index, j)
				req := helpers.CreateMultipartRequest(t, "/api/v1/web/upload",
					fmt.Sprintf("stress_test_%d_%d.tsv", index, j), fileContent, map[string]string{
						"fileType":    "roadmap",
						"description": fmt.Sprintf("Stress test %d-%d", index, j),
					})
				req.AddCookie(cookie)

				rr := httptest.NewRecorder()
				srv.Router.ServeHTTP(rr, req)

				mu.Lock()
				if rr.Code == http.StatusOK {
					successCount++
				} else {
					errorCount++
				}
				mu.Unlock()
			}
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(start)

	totalUploads := concurrency * uploadsPerGoroutine
	uploadRate := float64(totalUploads) / elapsed.Seconds()
	successRate := float64(successCount) / float64(totalUploads) * 100

	t.Logf("File Upload Stress Test Results:")
	t.Logf("  Total Uploads: %d", totalUploads)
	t.Logf("  Successful Uploads: %d", successCount)
	t.Logf("  Failed Uploads: %d", errorCount)
	t.Logf("  Success Rate: %.2f%%", successRate)
	t.Logf("  Uploads per Second: %.2f", uploadRate)
	t.Logf("  Total Time: %v", elapsed)

	// Stress test assertions
	if successRate < 90 {
		t.Errorf("Upload success rate too low: %.2f%%", successRate)
	}
	if uploadRate < 5 {
		t.Errorf("Upload rate too low: %.2f", uploadRate)
	}
}

// TestPerformance_MemoryLeak tests for memory leaks during extended operation
func TestPerformance_MemoryLeak(t *testing.T) {
	srv := setupPerformanceTestServer(t)

	// Create test user
	user := helpers.CreateTestUser(t, "leakuser", "LeakUser123!", "admin")
	_ = helpers.LoginAndGetSessionCookie(t, srv.Router, user.Username, "LeakUser123!")

	// Memory leak test parameters
	iterations := 1000
	measureInterval := 100

	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)

	for i := 0; i < iterations; i++ {
		// Perform various operations
		req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
		rr := httptest.NewRecorder()
		srv.Router.ServeHTTP(rr, req)

		if i%measureInterval == 0 {
			runtime.GC()
			runtime.ReadMemStats(&m2)

			if i > 0 {
				memGrowth := m2.Alloc - m1.Alloc
				t.Logf("Iteration %d: Memory growth: %d bytes", i, memGrowth)

				// Check for excessive memory growth
				if memGrowth > 10*1024*1024 { // 10MB
					t.Errorf("Potential memory leak detected: %d bytes growth at iteration %d", memGrowth, i)
				}
			}
			m1 = m2
		}
	}

	runtime.GC()
	runtime.ReadMemStats(&m2)
	finalMemGrowth := m2.Alloc - m1.Alloc

	t.Logf("Memory Leak Test Results:")
	t.Logf("  Total Iterations: %d", iterations)
	t.Logf("  Final Memory Growth: %d bytes", finalMemGrowth)
	t.Logf("  Average Growth per Iteration: %.2f bytes", float64(finalMemGrowth)/float64(iterations))

	if finalMemGrowth > 50*1024*1024 { // 50MB
		t.Errorf("Excessive memory growth detected: %d bytes", finalMemGrowth)
	}
}
