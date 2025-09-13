package middleware

import (
    "net/http"
    "os"
    "strings"
)

// CorsMiddleware CORS中间件
func CorsMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        origin := r.Header.Get("Origin")
        if origin != "" {
            // When credentials are involved, echo back the Origin (not *)
            w.Header().Set("Access-Control-Allow-Origin", origin)
            w.Header().Set("Vary", "Origin")
            w.Header().Set("Access-Control-Allow-Credentials", "true")
        } else {
            // Non CORS or same-origin
            w.Header().Set("Access-Control-Allow-Origin", "*")
        }
        w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        // Allow common headers and X-Requested-With for AJAX
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Accept")
        // Expose minimal headers if needed by client
        w.Header().Set("Access-Control-Expose-Headers", "Content-Type")

        if r.Method == http.MethodOptions {
            w.WriteHeader(http.StatusOK)
            return
        }

        next.ServeHTTP(w, r)
    })
}

// HTTPSRedirectMiddleware redirects HTTP requests to HTTPS
func HTTPSRedirectMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if HTTPS enforcement is disabled
		if os.Getenv("DISABLE_HTTPS_REDIRECT") == "true" {
			next.ServeHTTP(w, r)
			return
		}

		// Check if request is already HTTPS
		if r.TLS != nil {
			next.ServeHTTP(w, r)
			return
		}

		// Check for X-Forwarded-Proto header (for load balancers/proxies)
		if proto := r.Header.Get("X-Forwarded-Proto"); proto == "https" {
			next.ServeHTTP(w, r)
			return
		}

		// Check for X-Forwarded-SSL header
		if ssl := r.Header.Get("X-Forwarded-SSL"); ssl == "on" {
			next.ServeHTTP(w, r)
			return
		}

		// Redirect to HTTPS
		host := r.Host
		if host == "" {
			host = "localhost:8443"
		}

		// Replace port 9001 with 8443 if present
		if strings.Contains(host, ":9001") {
			host = strings.Replace(host, ":9001", ":8443", 1)
		} else if !strings.Contains(host, ":") {
			// If no port specified, add HTTPS port
			host = host + ":8443"
		}

		httpsURL := "https://" + host + r.RequestURI

		w.Header().Set("Location", httpsURL)
		w.WriteHeader(http.StatusMovedPermanently)
		w.Write([]byte("Moved Permanently. Please use HTTPS."))
	})
}
