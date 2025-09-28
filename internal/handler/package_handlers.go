package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"secure-file-hub/internal/database"
	"github.com/gorilla/mux"
)

// Package handler implementations
func handleListPackages(w http.ResponseWriter, r *http.Request) {
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", "Database not available")
		return
	}

	q := r.URL.Query()
	tenant := strings.TrimSpace(q.Get("tenant"))
	ptype := strings.TrimSpace(q.Get("type"))
	search := strings.TrimSpace(q.Get("q"))
	page, _ := strconv.Atoi(q.Get("page"))
	limit, _ := strconv.Atoi(q.Get("limit"))

	items, total, err := db.ListPackages(tenant, ptype, search, page, limit)
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	data := map[string]interface{}{
		"items": items,
		"count": total,
		"page": func() int {
			if page > 0 {
				return page
			}
			return 1
		}(),
		"limit": func() int {
			if limit > 0 {
				return limit
			}
			return 50
		}(),
	}
	writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: data})
}

func handleUpdatePackageRemark(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	packageID := vars["id"]

	var req struct {
		Remark string `json:"remark"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body", map[string]interface{}{"field": "body", "error": err.Error()})
		return
	}

	response := Response{
		Success: true,
		Message: "Package remark updated successfully",
		Data: map[string]interface{}{
			"package_id": packageID,
			"remark":     req.Remark,
		},
	}

	writeJSONResponse(w, http.StatusOK, response)
}
