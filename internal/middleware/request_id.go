package middleware

import (
    "context"
    "crypto/rand"
    "encoding/hex"
    "net/http"
)

type ctxKey string

const RequestIDKey ctxKey = "request_id"

func generateRequestID() string {
    b := make([]byte, 16)
    if _, err := rand.Read(b); err != nil { return "req-unknown" }
    return hex.EncodeToString(b)
}

// RequestIDMiddleware attaches a request_id to context and response header.
func RequestIDMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        reqID := r.Header.Get("X-Request-ID")
        if reqID == "" { reqID = generateRequestID() }
        w.Header().Set("X-Request-ID", reqID)
        ctx := context.WithValue(r.Context(), RequestIDKey, reqID)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

