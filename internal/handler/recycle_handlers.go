package handler

import (
	"fmt"
	"log"
	"net/http"

	"secure-file-hub/internal/auth"
	"secure-file-hub/internal/database"
	"secure-file-hub/internal/logger"
	"secure-file-hub/internal/middleware"
)

// Recycle bin handler implementations
func handleGetRecycleBin(w http.ResponseWriter, r *http.Request) {
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", databaseNotInitialized)
		return
	}

	items, err := db.GetRecycleBinItems()
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get recycle bin items: "+err.Error())
		if l := logger.GetLogger(); l != nil {
			l.ErrorCtx(logger.EventError, "recyclebin_query_failed", map[string]interface{}{"error": err.Error()}, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r))
		}
		return
	}

	response := Response{
		Success: true,
		Message: "Recycle bin retrieved successfully",
		Data: map[string]interface{}{
			"items": items,
			"count": len(items),
		},
	}

	writeJSONResponse(w, http.StatusOK, response)
	if l := logger.GetLogger(); l != nil {
		l.InfoCtx(logger.EventAPIRequest, "recyclebin_success", map[string]interface{}{"count": len(items)}, "", r.Context().Value(middleware.RequestIDKey), getActor(r))
	}
}

func handleClearRecycleBin(w http.ResponseWriter, r *http.Request) {
	var purgedBy string
	if userCtx := r.Context().Value("user"); userCtx != nil {
		if user, ok := userCtx.(*auth.User); ok {
			purgedBy = user.Username
		} else {
			purgedBy = "unknown"
		}
	} else {
		purgedBy = "unknown"
	}

	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", databaseNotInitialized)
		return
	}

	items, err := db.GetRecycleBinItems()
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get recycle bin items: "+err.Error())
		if l := logger.GetLogger(); l != nil {
			l.ErrorCtx(logger.EventError, "clear_recyclebin_query_failed", map[string]interface{}{"error": err.Error()}, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r))
		}
		return
	}

	purgedCount := 0
	for _, item := range items {
		if err := db.PermanentlyDeleteFile(item.ID, purgedBy); err != nil {
			log.Printf("Failed to purge file %s: %v", item.ID, err)
		} else {
			purgedCount++
		}
	}

	response := Response{
		Success: true,
		Message: fmt.Sprintf("Recycle bin cleared: %d files purged", purgedCount),
		Data: map[string]interface{}{
			"purged_count": purgedCount,
		},
	}

	writeJSONResponse(w, http.StatusOK, response)
	if l := logger.GetLogger(); l != nil {
		l.InfoCtx(logger.EventAPIRequest, "clear_recyclebin_success", map[string]interface{}{"purged_count": purgedCount, "by": purgedBy}, "", r.Context().Value(middleware.RequestIDKey), getActor(r))
	}
}
