package handler

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"secure-file-hub/internal/application/usecases"
	"secure-file-hub/internal/auth"
	"secure-file-hub/internal/database"
	"secure-file-hub/internal/domain/entities"
	repo "secure-file-hub/internal/infrastructure/repository/sqlite"
	"secure-file-hub/internal/logger"
	"secure-file-hub/internal/middleware"
	fc "secure-file-hub/internal/presentation/http/controllers"

	"github.com/gorilla/mux"
)

// File-related utility functions
func calculateFileChecksum(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func convertToFileInfo(record database.FileRecord) FileInfo {
	return FileInfo{
		ID:           record.ID,
		FileName:     record.VersionedName,
		OriginalName: record.OriginalName,
		FileType:     record.FileType,
		Size:         record.Size,
		Description:  record.Description,
		UploadTime:   record.UploadTime,
		Version:      record.Version,
		IsLatest:     record.IsLatest,
		Uploader:     record.Uploader,
		Path:         record.FilePath,
		Checksum:     record.Checksum,
	}
}

func convertEntityToFileInfo(entity entities.File) FileInfo {
	return FileInfo{
		ID:           entity.ID,
		FileName:     entity.VersionedName,
		OriginalName: entity.OriginalName,
		FileType:     entity.FileType,
		Size:         entity.Size,
		Description:  entity.Description,
		UploadTime:   entity.UploadTime,
		Version:      entity.Version,
		IsLatest:     entity.IsLatest,
		Uploader:     entity.Uploader,
		Path:         entity.FilePath,
	}
}

func isAllowedPath(path string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}

	downloadDir, err := filepath.Abs("downloads")
	if err != nil {
		return false
	}

	return strings.HasPrefix(absPath, downloadDir)
}

func getContentType(fileName string) string {
	ext := strings.ToLower(filepath.Ext(fileName))
	switch ext {
	case ".tsv":
		return "text/tab-separated-values"
	case ".xlsx":
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	case ".zip":
		return "application/zip"
	default:
		return "application/octet-stream"
	}
}

func isValidFileExtension(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	validExts := map[string]bool{
		".tsv":  true, // Roadmap
		".xlsx": true, // Recommendation
	}
	return validExts[ext]
}

func generateFileID() string {
	return fmt.Sprintf("file_%d_%d", time.Now().UnixNano(), os.Getpid())
}

func generateVersionedFileName(fileType, originalName string) (string, int, error) {
	db := database.GetDatabase()
	if db == nil {
		return "", 0, fmt.Errorf("database not initialized")
	}

	query := `
		SELECT COALESCE(MAX(version), 0) as max_version
		FROM files
		WHERE file_type = ? AND original_name = ? AND status != 'purged'
	`

	var maxVersion int
	err := db.GetDB().QueryRow(query, fileType, originalName).Scan(&maxVersion)
	if err != nil && err != sql.ErrNoRows {
		return "", 0, fmt.Errorf("failed to query max version: %v", err)
	}

	version := maxVersion + 1

	ext := filepath.Ext(originalName)
	baseName := strings.TrimSuffix(originalName, ext)
	versionedName := fmt.Sprintf("%s_v%d%s", baseName, version, ext)

	return versionedName, version, nil
}

func writeWebVersionArtifacts(fileType, versionID, storedName, targetPath, checksum string, tags []string) error {
	if fileType != "roadmap" && fileType != "recommendation" {
		return nil
	}

	baseDir := filepath.Dir(targetPath)
	manifestPath := filepath.Join(baseDir, "manifest.json")

	manifest := map[string]interface{}{
		"version_id":   versionID,
		"version_tags": tags,
		"build": map[string]interface{}{
			"time":   time.Now().UTC().Format(time.RFC3339),
			"commit": "",
		},
		"artifact": map[string]interface{}{
			"file_name": storedName,
			"path":      targetPath,
			"sha256":    checksum,
			"size":      fileSizeSafe(targetPath),
		},
		"schema_version":   "1.0",
		"breaking_changes": []string{},
	}
	if err := writeJSONFileGeneric(manifestPath, manifest); err != nil {
		return err
	}

	db := database.GetDatabase()
	if db != nil {
		if err := db.UpsertVersionTags(fileType, versionID, tags); err != nil {
			log.Printf("Warning: Failed to save version tags to database: %v", err)
		}
	}

	return nil
}

func writeJSONFileGeneric(path string, v interface{}) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func fileSizeSafe(path string) int64 {
	if fi, err := os.Stat(path); err == nil {
		return fi.Size()
	}
	return 0
}

func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

func getActor(r *http.Request) string {
	if userCtx := r.Context().Value("user"); userCtx != nil {
		if user, ok := userCtx.(*auth.User); ok {
			return user.Username
		}
	}
	return "anonymous"
}

func readJSONFileGeneric(path string) (map[string]interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// File handler implementations
func handleFileDownload(w http.ResponseWriter, r *http.Request) {
	filePath := strings.TrimPrefix(r.URL.Path, "/api/v1/web/files/")

	if filePath == "" {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "File path cannot be empty", map[string]interface{}{"field": "path"})
		return
	}

	if strings.Contains(filePath, "..") || strings.HasPrefix(filePath, "/") {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid file path", map[string]interface{}{"field": "path", "reason": "path traversal or absolute path"})
		return
	}

	var fullPath string
	if strings.HasPrefix(filePath, "downloads/") {
		fullPath = filePath
	} else {
		fullPath = filepath.Join("downloads", filePath)
	}

	if !isAllowedPath(fullPath) {
		writeErrorWithCodeDetails(w, http.StatusForbidden, "INVALID_PERMISSION", "File path not allowed", map[string]interface{}{"path": fullPath})
		return
	}

	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		log.Printf("File not found: %s", fullPath)
		writeErrorWithCode(w, http.StatusNotFound, "FILE_NOT_FOUND", "File not found")
		return
	}

	file, err := os.Open(fullPath)
	if err != nil {
		log.Printf("Error opening file %s: %v", fullPath, err)
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Cannot open file")
		return
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		log.Printf("Error getting file info for %s: %v", fullPath, err)
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Cannot get file info")
		return
	}

	fileName := filepath.Base(filePath)

	contentType := getContentType(fileName)

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", fileName))
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", fileInfo.Size()))
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	_, err = io.Copy(w, file)
	if err != nil {
		log.Printf("Error writing file to response: %v", err)
		return
	}

	log.Printf("File %s downloaded successfully by %s", filePath, r.RemoteAddr)

	if l := logger.GetLogger(); l != nil {
		var userInfo map[string]interface{}
		if userCtx := r.Context().Value("user"); userCtx != nil {
			if user, ok := userCtx.(*auth.User); ok {
				userInfo = map[string]interface{}{
					"username": user.Username,
					"role":     user.Role,
				}
			}
		}
		if rid := r.Context().Value(middleware.RequestIDKey); rid != nil {
			if userInfo == nil {
				userInfo = map[string]interface{}{}
			}
			userInfo["request_id"] = rid
		}
		l.LogFileDownload(filePath, r.RemoteAddr, fileInfo.Size(), userInfo)
	}
}

func handleFileUpload(w http.ResponseWriter, r *http.Request) {
	err := r.ParseMultipartForm(128 << 20) // 128MB
	if err != nil {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "Failed to parse form", map[string]interface{}{"field": "form", "error": err.Error()})
		if l := logger.GetLogger(); l != nil {
			l.WarnCtx(logger.EventError, "upload_parse_form_failed", map[string]interface{}{"error": err.Error()}, "VALIDATION_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r))
		}
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "Failed to get file", map[string]interface{}{"field": "file", "error": err.Error()})
		if l := logger.GetLogger(); l != nil {
			l.WarnCtx(logger.EventError, "upload_missing_file", map[string]interface{}{"error": err.Error()}, "VALIDATION_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r))
		}
		return
	}
	defer file.Close()

	if header.Size > maxUploadBytes {
		writeErrorWithCodeDetails(w, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "Uploaded file exceeds the maximum allowed size", map[string]interface{}{"field": "file", "max_bytes": maxUploadBytes, "actual_bytes": header.Size})
		if l := logger.GetLogger(); l != nil {
			l.WarnCtx(logger.EventError, "upload_too_large", map[string]interface{}{"actual_bytes": header.Size, "max_bytes": maxUploadBytes}, "PAYLOAD_TOO_LARGE", r.Context().Value(middleware.RequestIDKey), getActor(r))
		}
		return
	}

	fileType := r.FormValue("fileType")
	description := r.FormValue("description")

	rawTags := r.FormValue("versionTags")
	var versionTags []string
	if strings.TrimSpace(rawTags) != "" {
		parts := strings.Split(rawTags, ",")
		for _, p := range parts {
			t := strings.TrimSpace(p)
			if t != "" {
				versionTags = append(versionTags, t)
			}
		}
	}

	allowedTypes := map[string]bool{
		"roadmap":        true,
		"recommendation": true,
	}
	if !allowedTypes[fileType] {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "INVALID_FILE_TYPE", "Unsupported file type", map[string]interface{}{"field": "fileType", "allowed": []string{"roadmap", "recommendation"}})
		if l := logger.GetLogger(); l != nil {
			l.WarnCtx(logger.EventError, "upload_invalid_file_type", map[string]interface{}{"fileType": fileType}, "INVALID_FILE_TYPE", r.Context().Value(middleware.RequestIDKey), getActor(r))
		}
		return
	}

	if !isValidFileExtension(header.Filename) {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "INVALID_FILE_FORMAT", "Unsupported file format", map[string]interface{}{"field": "file", "filename": header.Filename})
		if l := logger.GetLogger(); l != nil {
			l.WarnCtx(logger.EventError, "upload_invalid_ext", map[string]interface{}{"filename": header.Filename}, "INVALID_FILE_FORMAT", r.Context().Value(middleware.RequestIDKey), getActor(r))
		}
		return
	}

	ext := strings.ToLower(filepath.Ext(header.Filename))
	var fixedOriginalName string
	switch fileType {
	case "roadmap":
		if ext != ".tsv" {
			writeErrorWithCodeDetails(w, http.StatusBadRequest, "INVALID_FILE_FORMAT", "File extension does not match fileType", map[string]interface{}{"field": "file", "expected_ext": ".tsv", "got": ext})
			if l := logger.GetLogger(); l != nil {
				l.WarnCtx(logger.EventError, "upload_ext_mismatch", map[string]interface{}{"expected": ".tsv", "got": ext}, "INVALID_FILE_FORMAT", r.Context().Value(middleware.RequestIDKey), getActor(r))
			}
			return
		}
		fixedOriginalName = "roadmap.tsv"
	case "recommendation":
		if ext != ".xlsx" {
			writeErrorWithCodeDetails(w, http.StatusBadRequest, "INVALID_FILE_FORMAT", "File extension does not match fileType", map[string]interface{}{"field": "file", "expected_ext": ".xlsx", "got": ext})
			if l := logger.GetLogger(); l != nil {
				l.WarnCtx(logger.EventError, "upload_ext_mismatch", map[string]interface{}{"expected": ".xlsx", "got": ext}, "INVALID_FILE_FORMAT", r.Context().Value(middleware.RequestIDKey), getActor(r))
			}
			return
		}
		fixedOriginalName = "recommendation.xlsx"
	default:
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "INVALID_FILE_TYPE", "Unsupported file type", map[string]interface{}{"field": "fileType", "allowed": []string{"roadmap", "recommendation"}})
		return
	}

	var uploader string
	if userCtx := r.Context().Value("user"); userCtx != nil {
		if user, ok := userCtx.(*auth.User); ok {
			uploader = user.Username
		} else {
			uploader = "unknown"
		}
	} else {
		uploader = "unknown"
	}

	fileInfo := &FileInfo{
		ID:           generateFileID(),
		FileName:     header.Filename,
		OriginalName: fixedOriginalName,
		FileType:     fileType,
		Size:         header.Size,
		Description:  description,
		UploadTime:   time.Now(),
		Uploader:     uploader,
	}

	versionedFileName, version, err := generateVersionedFileName(fileType, fixedOriginalName)
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to generate filename: "+err.Error())
		return
	}

	fileInfo.FileName = versionedFileName
	fileInfo.Version = version
	fileInfo.IsLatest = true

	ts := time.Now().UTC().Format("20060102150405") + "Z"
	versionID := "v" + ts

	targetDir := filepath.Join("downloads", fileType+"s")
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create directory: "+err.Error())
		if l := logger.GetLogger(); l != nil {
			l.ErrorCtx(logger.EventError, "upload_mkdir_failed", map[string]interface{}{"error": err.Error(), "dir": targetDir}, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r))
		}
		return
	}

	ext = strings.ToLower(filepath.Ext(fixedOriginalName))
	finalFileName := fmt.Sprintf("%s%s", versionID, ext)

	if strings.HasPrefix(finalFileName, fileType+"_") {
		finalFileName = strings.TrimPrefix(finalFileName, fileType+"_")
	}

	versionDir := filepath.Join(targetDir, versionID)
	if err := os.MkdirAll(versionDir, 0755); err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create version directory: "+err.Error())
		if l := logger.GetLogger(); l != nil {
			l.ErrorCtx(logger.EventError, "upload_mkdir_version_failed", map[string]interface{}{"error": err.Error(), "dir": versionDir}, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r))
		}
		return
	}

	targetPath := filepath.Join(versionDir, finalFileName)
	fileInfo.Path = targetPath
	fileInfo.FileName = finalFileName

	dst, err := os.Create(targetPath)
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create file: "+err.Error())
		if l := logger.GetLogger(); l != nil {
			l.ErrorCtx(logger.EventError, "upload_create_file_failed", map[string]interface{}{"error": err.Error(), "path": targetPath}, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r))
		}
		return
	}
	defer dst.Close()

	_, err = io.Copy(dst, file)
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to save file: "+err.Error())
		if l := logger.GetLogger(); l != nil {
			l.ErrorCtx(logger.EventError, "upload_write_failed", map[string]interface{}{"error": err.Error(), "path": targetPath}, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r))
		}
		return
	}

	latestPath := filepath.Join(targetDir, fixedOriginalName)
	os.Remove(latestPath)

	if err := os.Link(targetPath, latestPath); err != nil {
		if copyErr := copyFile(targetPath, latestPath); copyErr != nil {
			log.Printf("Warning: Failed to create latest version link: %v", copyErr)
		}
	}

	checksum, err := calculateFileChecksum(targetPath)
	if err != nil {
		log.Printf("Warning: Failed to calculate SHA256 checksum: %v", err)
	}

	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Database not initialized")
		if l := logger.GetLogger(); l != nil {
			l.ErrorCtx(logger.EventError, "upload_db_unavailable", nil, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r))
		}
		return
	}

	record := &database.FileRecord{
		ID:            fileInfo.ID,
		OriginalName:  fixedOriginalName,
		VersionedName: finalFileName,
		FileType:      fileType,
		FilePath:      targetPath,
		Size:          fileInfo.Size,
		Description:   description,
		Uploader:      uploader,
		UploadTime:    time.Now(),
		Version:       version,
		IsLatest:      true,
		Checksum:      checksum,
	}

	if err := db.InsertFileRecord(record); err != nil {
		os.Remove(targetPath)
		os.Remove(latestPath)
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to save file metadata: "+err.Error())
		if l := logger.GetLogger(); l != nil {
			l.ErrorCtx(logger.EventError, "upload_db_insert_failed", map[string]interface{}{"error": err.Error()}, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r))
		}
		return
	}

	if err := writeWebVersionArtifacts(fileType, versionID, fileInfo.FileName, targetPath, checksum, versionTags); err != nil {
		log.Printf("Warning: failed to write version artifacts: %v", err)
	}

	if l := logger.GetLogger(); l != nil {
		details := map[string]interface{}{
			"fileType":    fileType,
			"version":     version,
			"description": description,
		}
		if rid := r.Context().Value(middleware.RequestIDKey); rid != nil {
			details["request_id"] = rid
		}
		l.LogFileUpload(fileInfo.Path, uploader, fileInfo.Size, details)
	}

	w.Header().Set("X-Version-ID", versionID)
	fileInfo.VersionID = versionID

	response := Response{
		Success: true,
		Message: "File uploaded successfully",
		Data:    fileInfo,
	}

	writeJSONResponse(w, http.StatusOK, response)
}

func handleListFiles(w http.ResponseWriter, r *http.Request) {
	fileType := r.URL.Query().Get("type")

	page := 1
	limit := 50
	if v := r.URL.Query().Get("page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			page = n
		}
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}

	var controller *fc.FileController
	if appContainer != nil && appContainer.FileController != nil {
		controller = appContainer.FileController
	} else {
		controller = fc.NewFileController(usecases.NewFileUseCase(repo.NewFileRepo()))
	}
	items, total, err := controller.ListWithPagination(fileType, page, limit)
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get file list: "+err.Error())
		if l := logger.GetLogger(); l != nil {
			l.ErrorCtx(logger.EventError, "list_files_failed", map[string]interface{}{"type": fileType, "page": page, "limit": limit}, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r))
		}
		return
	}

	files := make([]FileInfo, 0, len(items))
	for _, f := range items {
		files = append(files, convertEntityToFileInfo(f))
	}
	response := Response{
		Success: true,
		Message: "File list retrieved successfully",
		Data: map[string]interface{}{
			"files": files,
			"count": total,
			"page":  page,
			"limit": limit,
		},
	}
	writeJSONResponse(w, http.StatusOK, response)
	if l := logger.GetLogger(); l != nil {
		l.InfoCtx(logger.EventAPIRequest, "list_files_success", map[string]interface{}{"type": fileType, "count": len(files), "total": total, "page": page, "limit": limit}, "", r.Context().Value(middleware.RequestIDKey), getActor(r))
	}
}

func handleGetFileVersions(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	fileType := vars["type"]
	filename := vars["filename"]

	var controller *fc.FileController
	if appContainer != nil && appContainer.FileController != nil {
		controller = appContainer.FileController
	} else {
		controller = fc.NewFileController(usecases.NewFileUseCase(repo.NewFileRepo()))
	}
	items, err := controller.Versions(fileType, filename)
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get file versions: "+err.Error())
		if l := logger.GetLogger(); l != nil {
			l.ErrorCtx(logger.EventError, "get_versions_failed", map[string]interface{}{"type": fileType, "filename": filename}, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r))
		}
		return
	}
	versions := make([]FileInfo, 0, len(items))
	for _, f := range items {
		versions = append(versions, convertEntityToFileInfo(f))
	}

	response := Response{
		Success: true,
		Message: "File versions retrieved successfully",
		Data: map[string]interface{}{
			"versions": versions,
			"count":    len(versions),
		},
	}

	writeJSONResponse(w, http.StatusOK, response)
	if l := logger.GetLogger(); l != nil {
		l.InfoCtx(logger.EventAPIRequest, "get_versions_success", map[string]interface{}{"type": fileType, "filename": filename, "count": len(versions)}, "", r.Context().Value(middleware.RequestIDKey), getActor(r))
	}
}

func handleDeleteFile(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	fileID := vars["id"]

	var deletedBy string
	if userCtx := r.Context().Value("user"); userCtx != nil {
		if user, ok := userCtx.(*auth.User); ok {
			deletedBy = user.Username
		} else {
			deletedBy = "unknown"
		}
	} else {
		deletedBy = "unknown"
	}

	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Database not initialized")
		if l := logger.GetLogger(); l != nil {
			l.ErrorCtx(logger.EventError, "recyclebin_db_unavailable", nil, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r))
		}
		return
	}

	if err := db.SoftDeleteFile(fileID, deletedBy); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			writeErrorWithCode(w, http.StatusNotFound, "FILE_NOT_FOUND", "File not found or already deleted")
			if l := logger.GetLogger(); l != nil {
				l.WarnCtx(logger.EventError, "soft_delete_not_found", map[string]interface{}{"file_id": fileID}, "FILE_NOT_FOUND", r.Context().Value(middleware.RequestIDKey), getActor(r))
			}
		} else {
			writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete file: "+err.Error())
			if l := logger.GetLogger(); l != nil {
				l.ErrorCtx(logger.EventError, "soft_delete_failed", map[string]interface{}{"file_id": fileID}, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r))
			}
		}
		return
	}

	response := Response{
		Success: true,
		Message: "File moved to recycle bin successfully",
	}

	writeJSONResponse(w, http.StatusOK, response)
	if l := logger.GetLogger(); l != nil {
		l.InfoCtx(logger.EventAPIRequest, "soft_delete_success", map[string]interface{}{"file_id": fileID, "by": deletedBy}, "", r.Context().Value(middleware.RequestIDKey), getActor(r))
	}
}

func handleRestoreFile(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	fileID := vars["id"]

	var restoredBy string
	if userCtx := r.Context().Value("user"); userCtx != nil {
		if user, ok := userCtx.(*auth.User); ok {
			restoredBy = user.Username
		} else {
			restoredBy = "unknown"
		}
	} else {
		restoredBy = "unknown"
	}

	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Database not initialized")
		if l := logger.GetLogger(); l != nil {
			l.ErrorCtx(logger.EventError, "clear_recyclebin_db_unavailable", nil, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r))
		}
		return
	}

	if err := db.RestoreFile(fileID, restoredBy); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			writeErrorWithCode(w, http.StatusNotFound, "FILE_NOT_FOUND", "File not found in recycle bin")
			if l := logger.GetLogger(); l != nil {
				l.WarnCtx(logger.EventError, "restore_not_found", map[string]interface{}{"file_id": fileID}, "FILE_NOT_FOUND", r.Context().Value(middleware.RequestIDKey), getActor(r))
			}
		} else {
			writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to restore file: "+err.Error())
			if l := logger.GetLogger(); l != nil {
				l.ErrorCtx(logger.EventError, "restore_failed", map[string]interface{}{"file_id": fileID}, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r))
			}
		}
		return
	}

	response := Response{
		Success: true,
		Message: "File restored successfully",
	}

	writeJSONResponse(w, http.StatusOK, response)
	if l := logger.GetLogger(); l != nil {
		l.InfoCtx(logger.EventAPIRequest, "restore_success", map[string]interface{}{"file_id": fileID, "by": restoredBy}, "", r.Context().Value(middleware.RequestIDKey), getActor(r))
	}
}

func handlePurgeFile(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	fileID := vars["id"]

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
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Database not initialized")
		return
	}

	if err := db.PermanentlyDeleteFile(fileID, purgedBy); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			writeErrorWithCode(w, http.StatusNotFound, "FILE_NOT_FOUND", "File not found or already purged")
			if l := logger.GetLogger(); l != nil {
				l.WarnCtx(logger.EventError, "purge_not_found", map[string]interface{}{"file_id": fileID}, "FILE_NOT_FOUND", r.Context().Value(middleware.RequestIDKey), getActor(r))
			}
		} else {
			writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to purge file: "+err.Error())
			if l := logger.GetLogger(); l != nil {
				l.ErrorCtx(logger.EventError, "purge_failed", map[string]interface{}{"file_id": fileID}, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r))
			}
		}
		return
	}

	response := Response{
		Success: true,
		Message: "File permanently deleted",
	}

	writeJSONResponse(w, http.StatusOK, response)
	if l := logger.GetLogger(); l != nil {
		l.InfoCtx(logger.EventAPIRequest, "purge_success", map[string]interface{}{"file_id": fileID, "by": purgedBy}, "", r.Context().Value(middleware.RequestIDKey), getActor(r))
	}
}
