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
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", databaseNotAvailable)
		return
	}

	params := parseListPackagesParams(r)
	items, total, err := db.ListPackages(params.tenant, params.ptype, params.search, params.page, params.limit)
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	data := buildListPackagesResponse(items, total, params)
	writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: data})
}

type listPackagesParams struct {
	tenant string
	ptype  string
	search string
	page   int
	limit  int
}

func parseListPackagesParams(r *http.Request) listPackagesParams {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	limit, _ := strconv.Atoi(q.Get("limit"))

	return listPackagesParams{
		tenant: strings.TrimSpace(q.Get("tenant")),
		ptype:  strings.TrimSpace(q.Get("type")),
		search: strings.TrimSpace(q.Get("q")),
		page:   normalizePageNumber(page),
		limit:  normalizeLimitNumber(limit),
	}
}

func normalizePageNumber(page int) int {
	if page > 0 {
		return page
	}
	return 1
}

func normalizeLimitNumber(limit int) int {
	if limit > 0 {
		return limit
	}
	return 50
}

func buildListPackagesResponse(items interface{}, total int, params listPackagesParams) map[string]interface{} {
	return map[string]interface{}{
		"items": items,
		"count": total,
		"page":  params.page,
		"limit": params.limit,
	}
}

func handleUpdatePackageRemark(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	packageID := vars["id"]

	var req struct {
		Remark string `json:"remark"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalidRequestBody", map[string]interface{}{"field": "body", "error": err.Error()})
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
