package handler

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"secure-file-hub/internal/database"
	"secure-file-hub/internal/logger"
	"secure-file-hub/internal/middleware"

	"github.com/gorilla/mux"
)

// Version handler implementations
func handleGetVersionManifest(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ft := strings.ToLower(vars["type"])
	vid := vars["versionId"]
	if ft != "roadmap" && ft != "recommendation" {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid type", map[string]interface{}{"field": "type", "allowed": []string{"roadmap", "recommendation"}})
		return
	}
	if vid == "" {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "versionId required", map[string]interface{}{"field": "versionId"})
		return
	}
	baseDir := filepath.Join("downloads", ft+"s", vid)
	manifestPath := filepath.Join(baseDir, "manifest.json")
	if b, err := os.ReadFile(manifestPath); err == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b)
		return
	}
	writeErrorWithCode(w, http.StatusNotFound, "FILE_NOT_FOUND", "Manifest not found")
}

func handleGetVersionsList(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ft := strings.ToLower(vars["type"])
	if ft != "roadmap" && ft != "recommendation" {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid type", map[string]interface{}{"field": "type", "allowed": []string{"roadmap", "recommendation"}})
		return
	}
	baseDir := filepath.Join("downloads", ft+"s")
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: map[string]interface{}{"versions": []interface{}{}}})
		return
	}
	list := []interface{}{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}

		mpath := filepath.Join(baseDir, e.Name(), "manifest.json")
		if m, err := readJSONFileGeneric(mpath); err == nil {
			date := ""
			if b, ok := m["build"].(map[string]interface{}); ok {
				if t, ok2 := b["time"].(string); ok2 {
					date = t
				}
			}

			var tags interface{} = m["version_tags"]
			if db := database.GetDatabase(); db != nil {
				if versionID, ok := m["version_id"].(string); ok {
					if dbTags, err := db.GetVersionTags(ft, versionID); err == nil && len(dbTags) > 0 {
						tags = dbTags
					}
				}
			}

			list = append(list, map[string]interface{}{
				"version_id": m["version_id"],
				"tags":       tags,
				"status":     "active",
				"date":       date,
			})
		}
	}
	writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: map[string]interface{}{"versions": list}})
}

func handleUpdateVersionTags(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ft := strings.ToLower(vars["type"]) // roadmap or recommendation
	vid := vars["versionId"]

	if ft != "roadmap" && ft != "recommendation" {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "type must be 'roadmap' or 'recommendation'", map[string]interface{}{"field": "type", "allowed": []string{"roadmap", "recommendation"}})
		return
	}
	if vid == "" {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "versionId required", map[string]interface{}{"field": "versionId"})
		return
	}

	var body struct {
		Tags []string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", invalidRequestBody)
		return
	}

	for i := range body.Tags {
		body.Tags[i] = strings.TrimSpace(body.Tags[i])
	}

	filteredTags := []string{}
	for _, tag := range body.Tags {
		if strings.TrimSpace(tag) != "" {
			filteredTags = append(filteredTags, strings.TrimSpace(tag))
		}
	}

	db := database.GetDatabase()
	if db != nil {
		if err := db.UpsertVersionTags(ft, vid, filteredTags); err != nil {
			if l := logger.GetLogger(); l != nil {
				l.ErrorCtx(logger.EventError, "update_version_tags_db_failed",
					map[string]interface{}{"error": err.Error(), "file_type": ft, "version_id": vid},
					"INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r))
			}
		}
	}

	baseDir := filepath.Join("downloads", ft+"s", vid)
	manifestPath := filepath.Join(baseDir, "manifest.json")

	manifest, err := readJSONFileGeneric(manifestPath)
	if err != nil {
		writeErrorWithCode(w, http.StatusNotFound, "FILE_NOT_FOUND", "Version manifest not found")
		return
	}

	manifest["version_tags"] = filteredTags

	if err := writeJSONFileGeneric(manifestPath, manifest); err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update version tags")
		return
	}

	writeJSONResponse(w, http.StatusOK, Response{Success: true, Message: "Version tags updated successfully"})
}
