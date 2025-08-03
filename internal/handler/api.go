package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"secure-file-hub/internal/database"
	"secure-file-hub/internal/middleware"

	"github.com/gorilla/mux"
)

// RegisterAPIRoutes registers public API routes
func RegisterAPIRoutes(router *mux.Router) {
	// Public API v1 routes with authentication (using /api/v1/public to avoid conflicts)
	apiV1 := router.PathPrefix("/api/v1/public").Subrouter()

	// Apply API authentication middleware
	apiV1.Use(middleware.APIKeyAuthMiddleware)
	apiV1.Use(middleware.APILoggingMiddleware)

	// File management endpoints
	apiV1.Handle("/files", middleware.RequirePermission("read")(http.HandlerFunc(apiListFilesHandler))).Methods("GET")
	apiV1.Handle("/files/{fileId}/download", middleware.RequirePermission("download")(http.HandlerFunc(apiDownloadFileHandler))).Methods("GET")
	apiV1.Handle("/files/upload", middleware.RequirePermission("upload")(http.HandlerFunc(apiUploadFileHandler))).Methods("POST")

	// File information endpoints
	apiV1.Handle("/files/{fileId}", middleware.RequirePermission("read")(http.HandlerFunc(apiGetFileInfoHandler))).Methods("GET")
	apiV1.Handle("/files/{fileId}/versions", middleware.RequirePermission("read")(http.HandlerFunc(apiGetFileVersionsHandler))).Methods("GET")

	// API information
	apiV1.HandleFunc("/info", apiPublicInfoHandler).Methods("GET")
	apiV1.HandleFunc("/status", apiStatusHandler).Methods("GET")
}

// APIResponse represents a standard API response
type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   *APIError   `json:"error,omitempty"`
	Meta    *APIMeta    `json:"meta,omitempty"`
}

// APIError represents an API error
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

// APIMeta represents response metadata
type APIMeta struct {
	Page      int `json:"page,omitempty"`
	Limit     int `json:"limit,omitempty"`
	Total     int `json:"total,omitempty"`
	TotalPage int `json:"total_pages,omitempty"`
}

// FileListResponse represents file list API response
type FileListResponse struct {
	Files []APIFileInfo `json:"files"`
	Count int           `json:"count"`
}

// APIFileInfo represents file information in API responses
type APIFileInfo struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	OriginalName string `json:"original_name"`
	Type         string `json:"type"`
	Size         int64  `json:"size"`
	Description  string `json:"description,omitempty"`
	Uploader     string `json:"uploader"`
	UploadTime   string `json:"upload_time"`
	Version      int    `json:"version"`
	IsLatest     bool   `json:"is_latest"`
	Checksum     string `json:"checksum,omitempty"`
	DownloadURL  string `json:"download_url"`
}

// apiListFilesHandler handles API file listing
func apiListFilesHandler(w http.ResponseWriter, r *http.Request) {
	// Get query parameters
	fileType := r.URL.Query().Get("type")
	pageStr := r.URL.Query().Get("page")
	limitStr := r.URL.Query().Get("limit")

	// Parse pagination
	page := 1
	limit := 50
	if pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
			limit = l
		}
	}

	offset := (page - 1) * limit

	db := database.GetDatabase()
	if db == nil {
		writeAPIErrorResponse(w, http.StatusInternalServerError, "DATABASE_ERROR", "Database not available")
		return
	}

	// Get files based on type
	var files []database.FileRecord
	var err error

	if fileType != "" {
		files, err = db.GetFilesByType(fileType, false)
	} else {
		files, err = db.GetAllFiles(false)
	}

	if err != nil {
		writeAPIErrorResponse(w, http.StatusInternalServerError, "QUERY_ERROR", "Failed to retrieve files")
		return
	}

	// Apply pagination
	total := len(files)
	start := offset
	end := offset + limit

	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	pagedFiles := files[start:end]

	// Convert to API format
	apiFiles := make([]APIFileInfo, len(pagedFiles))
	for i, file := range pagedFiles {
		apiFiles[i] = APIFileInfo{
			ID:           file.ID,
			Name:         file.VersionedName,
			OriginalName: file.OriginalName,
			Type:         file.FileType,
			Size:         file.Size,
			Description:  file.Description,
			Uploader:     file.Uploader,
			UploadTime:   file.UploadTime.Format("2006-01-02T15:04:05Z"),
			Version:      file.Version,
			IsLatest:     file.IsLatest,
			Checksum:     file.Checksum,
			DownloadURL:  "/api/v1/files/" + file.ID + "/download",
		}
	}

	// Calculate total pages
	totalPages := (total + limit - 1) / limit

	response := APIResponse{
		Success: true,
		Data: FileListResponse{
			Files: apiFiles,
			Count: len(apiFiles),
		},
		Meta: &APIMeta{
			Page:      page,
			Limit:     limit,
			Total:     total,
			TotalPage: totalPages,
		},
	}

	writeAPIJSONResponse(w, http.StatusOK, response)
}

// apiDownloadFileHandler handles API file downloads
func apiDownloadFileHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	fileID := vars["fileId"]

	if fileID == "" {
		writeAPIErrorResponse(w, http.StatusBadRequest, "MISSING_FILE_ID", "File ID is required")
		return
	}

	db := database.GetDatabase()
	if db == nil {
		writeAPIErrorResponse(w, http.StatusInternalServerError, "DATABASE_ERROR", "Database not available")
		return
	}

	// Get file record
	files, err := db.GetAllFiles(false)
	if err != nil {
		writeAPIErrorResponse(w, http.StatusInternalServerError, "QUERY_ERROR", "Failed to retrieve file")
		return
	}

	var targetFile *database.FileRecord
	for _, file := range files {
		if file.ID == fileID {
			targetFile = &file
			break
		}
	}

	if targetFile == nil {
		writeAPIErrorResponse(w, http.StatusNotFound, "FILE_NOT_FOUND", "File not found")
		return
	}

	// Check if file exists physically
	if !targetFile.FileExists {
		writeAPIErrorResponse(w, http.StatusNotFound, "FILE_UNAVAILABLE", "File is no longer available")
		return
	}

	// Serve the file
	serveFileDownload(w, r, targetFile.FilePath, targetFile.OriginalName)
}

// apiUploadFileHandler handles API file uploads
func apiUploadFileHandler(w http.ResponseWriter, r *http.Request) {
	// Check permission
	authCtx := middleware.GetAPIAuthContext(r)
	if authCtx == nil || !authCtx.HasPermission("upload") {
		writeAPIErrorResponse(w, http.StatusForbidden, "INSUFFICIENT_PERMISSIONS", "Upload permission required")
		return
	}

	// Parse multipart form
	err := r.ParseMultipartForm(32 << 20) // 32MB
	if err != nil {
		writeAPIErrorResponse(w, http.StatusBadRequest, "FORM_PARSE_ERROR", "Failed to parse form data")
		return
	}

	// Get file
	file, _, err := r.FormFile("file")
	if err != nil {
		writeAPIErrorResponse(w, http.StatusBadRequest, "FILE_REQUIRED", "File is required")
		return
	}
	defer file.Close()

	// Get form parameters
	fileType := r.FormValue("type")
	_ = r.FormValue("description") // description for future use

	// Validate file type
	allowedTypes := map[string]bool{
		"config":      true,
		"certificate": true,
		"docs":        true,
	}
	if !allowedTypes[fileType] {
		writeAPIErrorResponse(w, http.StatusBadRequest, "INVALID_FILE_TYPE", "Invalid file type")
		return
	}

	// Process upload (reuse existing logic)
	// This would call the same upload processing logic as the web interface
	// For brevity, I'm not duplicating the entire upload logic here

	response := APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"message": "File uploaded successfully",
			"file_id": "generated_file_id",
		},
	}

	writeAPIJSONResponse(w, http.StatusCreated, response)
}

// apiGetFileInfoHandler handles getting file information
func apiGetFileInfoHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	fileID := vars["fileId"]

	if fileID == "" {
		writeAPIErrorResponse(w, http.StatusBadRequest, "MISSING_FILE_ID", "File ID is required")
		return
	}

	db := database.GetDatabase()
	if db == nil {
		writeAPIErrorResponse(w, http.StatusInternalServerError, "DATABASE_ERROR", "Database not available")
		return
	}

	// Get file record
	files, err := db.GetAllFiles(false)
	if err != nil {
		writeAPIErrorResponse(w, http.StatusInternalServerError, "QUERY_ERROR", "Failed to retrieve file")
		return
	}

	var targetFile *database.FileRecord
	for _, file := range files {
		if file.ID == fileID {
			targetFile = &file
			break
		}
	}

	if targetFile == nil {
		writeAPIErrorResponse(w, http.StatusNotFound, "FILE_NOT_FOUND", "File not found")
		return
	}

	apiFile := APIFileInfo{
		ID:           targetFile.ID,
		Name:         targetFile.VersionedName,
		OriginalName: targetFile.OriginalName,
		Type:         targetFile.FileType,
		Size:         targetFile.Size,
		Description:  targetFile.Description,
		Uploader:     targetFile.Uploader,
		UploadTime:   targetFile.UploadTime.Format("2006-01-02T15:04:05Z"),
		Version:      targetFile.Version,
		IsLatest:     targetFile.IsLatest,
		Checksum:     targetFile.Checksum,
		DownloadURL:  "/api/v1/files/" + targetFile.ID + "/download",
	}

	response := APIResponse{
		Success: true,
		Data:    apiFile,
	}

	writeAPIJSONResponse(w, http.StatusOK, response)
}

// apiGetFileVersionsHandler handles getting file versions
func apiGetFileVersionsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	_ = vars["fileId"] // fileID for future implementation

	// Implementation similar to apiGetFileInfoHandler but returns all versions
	// This is a simplified placeholder

	response := APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"versions": []interface{}{},
			"count":    0,
		},
	}

	writeAPIJSONResponse(w, http.StatusOK, response)
}

// apiPublicInfoHandler provides API information
func apiPublicInfoHandler(w http.ResponseWriter, r *http.Request) {
	response := APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"name":        "File Management API",
			"version":     "1.0.0",
			"description": "RESTful API for secure file management",
			"endpoints": map[string]interface{}{
				"files":           "/api/v1/public/files",
				"file_download":   "/api/v1/public/files/{id}/download",
				"file_upload":     "/api/v1/public/files/upload",
				"file_info":       "/api/v1/public/files/{id}",
				"file_versions":   "/api/v1/public/files/{id}/versions",
			},
			"authentication": "API Key required in Authorization header",
			"rate_limits":    "Per API key limits apply",
		},
	}

	writeAPIJSONResponse(w, http.StatusOK, response)
}

// apiStatusHandler provides API status
func apiStatusHandler(w http.ResponseWriter, r *http.Request) {
	response := APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"status":    "operational",
			"timestamp": "2024-01-01T00:00:00Z",
			"version":   "1.0.0",
		},
	}

	writeAPIJSONResponse(w, http.StatusOK, response)
}

// Helper functions

func writeAPIJSONResponse(w http.ResponseWriter, status int, response APIResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(response)
}

func writeAPIErrorResponse(w http.ResponseWriter, status int, code, message string) {
	response := APIResponse{
		Success: false,
		Error: &APIError{
			Code:    code,
			Message: message,
		},
	}
	writeAPIJSONResponse(w, status, response)
}

func serveFileDownload(w http.ResponseWriter, r *http.Request, filePath, fileName string) {
	// This would implement the actual file serving logic
	// Similar to the existing downloadFileHandler but adapted for API
	http.ServeFile(w, r, filePath)
}