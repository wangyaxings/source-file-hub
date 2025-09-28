package handler

import (
	"encoding/json"
	"fmt"
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
	fileType := strings.ToLower(vars["type"])

	if err := validateFileType(fileType); err != nil {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error(), map[string]interface{}{"field": "type"})
		return
	}

	versions, err := getVersionsList(fileType)
	if err != nil {
		writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: map[string]interface{}{"versions": []interface{}{}}})
		return
	}

	writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: map[string]interface{}{"versions": versions}})
}

func validateFileType(fileType string) error {
	validTypes := []string{"roadmap", "recommendation"}
	for _, validType := range validTypes {
		if fileType == validType {
			return nil
		}
	}
	return fmt.Errorf("invalid type, allowed: %v", validTypes)
}

func getVersionsList(fileType string) ([]interface{}, error) {
	baseDir := filepath.Join("downloads", fileType+"s")
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return nil, err
	}

	var versions []interface{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		versionInfo, err := processVersionEntry(baseDir, entry.Name(), fileType)
		if err != nil {
			continue // Skip invalid entries
		}

		versions = append(versions, versionInfo)
	}

	return versions, nil
}

func processVersionEntry(baseDir, versionID, fileType string) (map[string]interface{}, error) {
	manifestPath := filepath.Join(baseDir, versionID, "manifest.json")
	manifest, err := readJSONFileGeneric(manifestPath)
	if err != nil {
		return nil, err
	}

	versionInfo := extractVersionInfo(manifest)
	tags := getVersionTags(fileType, manifest, versionID)

	return map[string]interface{}{
		"version_id": manifest["version_id"],
		"tags":       tags,
		"status":     "active",
		"date":       versionInfo.date,
	}, nil
}

func extractVersionInfo(manifest map[string]interface{}) struct{ date string } {
	date := ""
	if build, ok := manifest["build"].(map[string]interface{}); ok {
		if timeStr, ok := build["time"].(string); ok {
			date = timeStr
		}
	}
	return struct{ date string }{date: date}
}

func getVersionTags(fileType string, manifest map[string]interface{}, versionID string) interface{} {
	if tags, exists := manifest["version_tags"]; exists {
		if db := database.GetDatabase(); db != nil {
			if dbTags, err := db.GetVersionTags(fileType, versionID); err == nil && len(dbTags) > 0 {
				return dbTags
			}
		}
		return tags
	}
	return nil
}

func handleUpdateVersionTags(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	fileType := strings.ToLower(vars["type"])
	versionID := vars["versionId"]

	if err := validateUpdateVersionTagsParams(fileType, versionID); err != nil {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error(), map[string]interface{}{"field": "params"})
		return
	}

	tags, err := parseAndValidateTags(r)
	if err != nil {
		writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	if err := updateVersionTagsInDB(fileType, versionID, tags, r); err != nil {
		if l := logger.GetLogger(); l != nil {
			l.ErrorCtx(logger.EventError, "update_version_tags_db_failed",
				map[string]interface{}{"error": err.Error(), "file_type": fileType, "version_id": versionID},
				"INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r))
		}
	}

	if err := updateVersionTagsInFile(fileType, versionID, tags); err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update version tags")
		return
	}

	writeJSONResponse(w, http.StatusOK, Response{Success: true, Message: "Version tags updated successfully"})
}

func validateUpdateVersionTagsParams(fileType, versionID string) error {
	if err := validateFileType(fileType); err != nil {
		return fmt.Errorf("invalid file type: %v", err)
	}
	if versionID == "" {
		return fmt.Errorf("versionId required")
	}
	return nil
}

func parseAndValidateTags(r *http.Request) ([]string, error) {
	var body struct {
		Tags []string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("invalid request body")
	}

	return filterValidTags(body.Tags), nil
}

func filterValidTags(tags []string) []string {
	var filtered []string
	for _, tag := range tags {
		trimmed := strings.TrimSpace(tag)
		if trimmed != "" {
			filtered = append(filtered, trimmed)
		}
	}
	return filtered
}

func updateVersionTagsInDB(fileType, versionID string, tags []string, r *http.Request) error {
	db := database.GetDatabase()
	if db == nil {
		return nil // Database not available, skip DB update
	}

	err := db.UpsertVersionTags(fileType, versionID, tags)
	if err != nil && logger.GetLogger() != nil {
		logger.GetLogger().ErrorCtx(logger.EventError, "update_version_tags_db_failed",
			map[string]interface{}{"error": err.Error(), "file_type": fileType, "version_id": versionID},
			"INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r))
	}
	return err
}

func updateVersionTagsInFile(fileType, versionID string, tags []string) error {
	baseDir := filepath.Join("downloads", fileType+"s", versionID)
	manifestPath := filepath.Join(baseDir, "manifest.json")

	manifest, err := readJSONFileGeneric(manifestPath)
	if err != nil {
		return fmt.Errorf("version manifest not found")
	}

	manifest["version_tags"] = tags
	return writeJSONFileGeneric(manifestPath, manifest)
}
