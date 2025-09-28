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
	purgedBy := extractPurgedByUser(r)

	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", databaseNotInitialized)
		return
	}

	items, err := getRecycleBinItemsForClear(db, w, r)
	if err != nil {
		return
	}

	purgedCount := performBulkPurge(db, items, purgedBy)
	sendClearRecycleBinResponse(w, r, purgedCount, purgedBy)
}

func extractPurgedByUser(r *http.Request) string {
	if userCtx := r.Context().Value("user"); userCtx != nil {
		if user, ok := userCtx.(*auth.User); ok {
			return user.Username
		}
	}
	return "unknown"
}

func getRecycleBinItemsForClear(db *database.Database, w http.ResponseWriter, r *http.Request) ([]database.RecycleBinItem, error) {
	items, err := db.GetRecycleBinItems()
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get recycle bin items: "+err.Error())
		if l := logger.GetLogger(); l != nil {
			l.ErrorCtx(logger.EventError, "clear_recyclebin_query_failed", map[string]interface{}{"error": err.Error()}, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r))
		}
		return nil, err
	}
	return items, nil
}

func performBulkPurge(db *database.Database, items []database.RecycleBinItem, purgedBy string) int {
	purgedCount := 0
	for _, item := range items {
		if err := db.PermanentlyDeleteFile(item.ID, purgedBy); err != nil {
			log.Printf("Failed to purge file %s: %v", item.ID, err)
		} else {
			purgedCount++
		}
	}
	return purgedCount
}

func sendClearRecycleBinResponse(w http.ResponseWriter, r *http.Request, purgedCount int, purgedBy string) {
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
