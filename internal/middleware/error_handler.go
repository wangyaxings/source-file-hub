package middleware

import (
    "encoding/json"
    "log"
    "net/http"

    derrors "secure-file-hub/internal/domain/errors"
)

// ErrorHandlerMiddleware recovers from panics and writes unified JSON errors.
func ErrorHandlerMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        defer func() {
            if rec := recover(); rec != nil {
                switch v := rec.(type) {
                case derrors.DomainError:
                    writeJSONError(w, http.StatusBadRequest, v)
                case error:
                    log.Printf("panic: %v", v)
                    writeJSONError(w, http.StatusInternalServerError, derrors.ErrInternal)
                default:
                    log.Printf("panic: %#v", v)
                    writeJSONError(w, http.StatusInternalServerError, derrors.ErrInternal)
                }
            }
        }()
        next.ServeHTTP(w, r)
    })
}

func writeJSONError(w http.ResponseWriter, status int, derr derrors.DomainError) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(status)
    _ = json.NewEncoder(w).Encode(map[string]interface{}{
        "success": false,
        "error":   derr.Message,
        "code":    derr.Code,
        "details": derr.Details,
    })
}

