package handler

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"

	"secure-file-hub/internal/auth"
	"secure-file-hub/internal/middleware"

	di "secure-file-hub/internal/infrastructure/di"

	"github.com/gorilla/mux"
)

var appContainer *di.Container

const maxUploadBytes = 128 << 20

type Response struct {
	Success bool                   `json:"success"`
	Message string                 `json:"message,omitempty"`
	Data    interface{}            `json:"data,omitempty"`
	Error   string                 `json:"error,omitempty"`
	Code    string                 `json:"code,omitempty"`
	Details map[string]interface{} `json:"details"`
}

// File-related utility functions moved to file_handlers.go

func RegisterRoutes(router *mux.Router) {

	router.HandleFunc("/api/v1/health", healthCheckHandler).Methods("GET")
	router.HandleFunc("/api/v1/healthz", healthCheckHandler).Methods("GET")

	webAPI := router.PathPrefix("/api/v1/web").Subrouter()

	webAPI.HandleFunc("/auth/me", meHandler).Methods("GET")
	webAPI.HandleFunc("/auth/users", handleGetDefaultUsers).Methods("GET")

	webAPI.HandleFunc("/auth/check-permission", middleware.RequireAuthorization(handleCheckPermission)).Methods("POST")
	webAPI.HandleFunc("/auth/check-permissions", middleware.RequireAuthorization(handleCheckMultiplePermissions)).Methods("POST")

	webAPI.HandleFunc("", apiInfoHandler).Methods("GET")
	webAPI.HandleFunc("/", apiInfoHandler).Methods("GET")
	webAPI.HandleFunc("/health", healthCheckHandler).Methods("GET")
	webAPI.HandleFunc("/healthz", healthCheckHandler).Methods("GET")

	webFileMgmtRouter := webAPI.PathPrefix("").Subrouter()
	webFileMgmtRouter.Use(middleware.APILoggingMiddleware)
	webFileMgmtRouter.HandleFunc("/upload", middleware.RequireAuthorization(uploadFileHandler)).Methods("POST")
	webFileMgmtRouter.HandleFunc("/files/list", middleware.RequireAuthorization(listFilesHandler)).Methods("GET")
	webFileMgmtRouter.HandleFunc("/files/versions/{type}/{filename}", middleware.RequireAuthorization(getFileVersionsHandler)).Methods("GET")
	webFileMgmtRouter.HandleFunc("/files/{id}/delete", middleware.RequireAuthorization(deleteFileHandler)).Methods("DELETE")
	webFileMgmtRouter.HandleFunc("/files/{id}/restore", middleware.RequireAuthorization(restoreFileHandler)).Methods("POST")
	webFileMgmtRouter.HandleFunc("/files/{id}/purge", middleware.RequireAuthorization(purgeFileHandler)).Methods("DELETE")

	webAPI.HandleFunc("/versions/{type}/versions.json", middleware.RequireAuthorization(handleGetVersionsList)).Methods("GET")
	webAPI.HandleFunc("/versions/{type}/{versionId}/manifest", middleware.RequireAuthorization(handleGetVersionManifest)).Methods("GET")
	webAPI.HandleFunc("/versions/{type}/{versionId}/tags", middleware.RequireAuthorization(handleUpdateVersionTags)).Methods("PUT")

	webAPI.HandleFunc("/recycle-bin", middleware.RequireAuthorization(getRecycleBinHandler)).Methods("GET")
	webAPI.HandleFunc("/recycle-bin/clear", middleware.RequireAuthorization(clearRecycleBinHandler)).Methods("DELETE")

	webFilesRouter := webAPI.PathPrefix("/files").Subrouter()
	webFilesRouter.Use(middleware.APILoggingMiddleware) // Add API logging for file downloads
	webFilesRouter.Use(middleware.Authorize())
	webFilesRouter.PathPrefix("/").HandlerFunc(downloadFileHandler).Methods("GET")

	webPackagesRouter := webAPI.PathPrefix("/packages").Subrouter()
	webPackagesRouter.Use(middleware.APILoggingMiddleware)
	webPackagesRouter.HandleFunc("", middleware.RequireAuthorization(handleListPackages)).Methods("GET")
	webPackagesRouter.HandleFunc("/{id}/remark", middleware.RequireAuthorization(handleUpdatePackageRemark)).Methods("PATCH")

	webAPI.HandleFunc("/packages/upload/assets-zip", middleware.RequireAuthorization(handleAPIUploadAssetsZip)).Methods("POST")
	webAPI.HandleFunc("/packages/upload/others-zip", middleware.RequireAuthorization(handleAPIUploadOthersZip)).Methods("POST")

	RegisterWebAdminRoutes(webAPI)
	RegisterAPIRoutes(router)

	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))
}

// File handler functions moved to file_handlers.go
func downloadFileHandler(w http.ResponseWriter, r *http.Request) {
	handleFileDownload(w, r)
}

// API handler functions moved to api_handlers.go
func apiInfoHandler(w http.ResponseWriter, r *http.Request) {
	handleAPIInfo(w, r)
}

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	handleHealthCheck(w, r)
}

func healthAPIKeyCheckHandler(w http.ResponseWriter, r *http.Request) {
	handleHealthAPIKeyCheck(w, r)
}

func apiDownloadFileByIDHandler(w http.ResponseWriter, r *http.Request) {
	handleAPIDownloadFileByID(w, r)
}

func apiGetLatestVersionInfoHandler(w http.ResponseWriter, r *http.Request) {
	handleAPIGetLatestVersionInfo(w, r)
}

func apiGetVersionInfoHandler(w http.ResponseWriter, r *http.Request) {
	handleAPIGetVersionInfo(w, r)
}

func apiGetVersionTypeStatusHandler(w http.ResponseWriter, r *http.Request) {
	handleAPIGetVersionTypeStatus(w, r)
}

func apiDownloadLatestByTypeHandler(w http.ResponseWriter, r *http.Request) {
	handleAPIDownloadLatestByType(w, r)
}

func apiUploadAssetsZipHandler(w http.ResponseWriter, r *http.Request) {
	handleAPIUploadAssetsZip(w, r)
}

func apiUploadOthersZipHandler(w http.ResponseWriter, r *http.Request) {
	handleAPIUploadOthersZip(w, r)
}

func apiUploadZipHandler(w http.ResponseWriter, r *http.Request, kind string) {
	handleAPIUploadZip(w, r, kind)
}

// API handler functions moved to api_handlers.go

// Health check handlers moved to api_handlers.go

func writeJSONResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
	}
}

func writeErrorWithCode(w http.ResponseWriter, status int, code, message string) {

	details := make(map[string]interface{})
	if rid := w.Header().Get("X-Request-ID"); rid != "" {
		details["request_id"] = rid
	}
	response := Response{
		Success: false,
		Error:   message,
		Code:    code,
		Details: details,
	}
	writeJSONResponse(w, status, response)
}

func writeErrorWithCodeDetails(w http.ResponseWriter, status int, code, message string, details map[string]interface{}) {
	if details == nil {
		details = make(map[string]interface{})
	}
	// Only add request_id from header if it doesn't already exist in details
	if rid := w.Header().Get("X-Request-ID"); rid != "" {
		if _, ok := details["request_id"]; !ok {
			details["request_id"] = rid
		}
	}
	response := Response{
		Success: false,
		Error:   message,
		Code:    code,
		Details: details,
	}
	writeJSONResponse(w, status, response)
}

// Authentication handler functions moved to auth_handlers.go
func meHandler(w http.ResponseWriter, r *http.Request) {
	handleMe(w, r)
}

// Authentication handler functions moved to auth_handlers.go
func loadUserFromDatabase(username string) (*auth.User, error) {
	return loadUserFromDatabaseImpl(username)
}

func checkUserStatus(username string) error {
	return checkUserStatusImpl(username)
}

// Authentication handlers moved to auth_handlers.go

// Access logs handler moved to admin_handlers.go

type FileUploadRequest struct {
	FileType    string `form:"fileType" json:"fileType"`
	Description string `form:"description" json:"description"`
}

type FileInfo struct {
	ID           string    `json:"id"`
	FileName     string    `json:"fileName"`
	OriginalName string    `json:"originalName"`
	FileType     string    `json:"fileType"`
	Size         int64     `json:"size"`
	Description  string    `json:"description"`
	UploadTime   time.Time `json:"uploadTime"`
	Version      int       `json:"version"`
	IsLatest     bool      `json:"isLatest"`
	Uploader     string    `json:"uploader"`
	Path         string    `json:"path"`
	VersionID    string    `json:"versionId,omitempty"`
	Checksum     string    `json:"checksum,omitempty"`
}

// File handler functions moved to file_handlers.go
func uploadFileHandler(w http.ResponseWriter, r *http.Request) {
	handleFileUpload(w, r)
}

// File handler functions moved to file_handlers.go
func listFilesHandler(w http.ResponseWriter, r *http.Request) {
	handleListFiles(w, r)
}

// File handler functions moved to file_handlers.go
func getFileVersionsHandler(w http.ResponseWriter, r *http.Request) {
	handleGetFileVersions(w, r)
}

// File handler functions moved to file_handlers.go
func deleteFileHandler(w http.ResponseWriter, r *http.Request) {
	handleDeleteFile(w, r)
}

// File handler functions moved to file_handlers.go
func restoreFileHandler(w http.ResponseWriter, r *http.Request) {
	handleRestoreFile(w, r)
}

// File handler functions moved to file_handlers.go
func purgeFileHandler(w http.ResponseWriter, r *http.Request) {
	handlePurgeFile(w, r)
}

// Recycle bin handler functions moved to recycle_handlers.go
func getRecycleBinHandler(w http.ResponseWriter, r *http.Request) {
	handleGetRecycleBin(w, r)
}

// Recycle bin handler functions moved to recycle_handlers.go
func clearRecycleBinHandler(w http.ResponseWriter, r *http.Request) {
	handleClearRecycleBin(w, r)
}

func generateSecurePassword(length int) (string, error) {
	if length < 12 {
		length = 12 // Minimum secure length
	}

	lowercase := "abcdefghijklmnopqrstuvwxyz"
	uppercase := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits := "0123456789"
	special := "!@#$%^&*()_+-=[]{}|;:,.<>?"

	allChars := lowercase + uppercase + digits + special

	password := make([]byte, length)

	// Fill first 4 positions with one character from each set
	sets := []string{lowercase, uppercase, digits, special}
	err := fillPasswordWithRequiredSets(password, sets)
	if err != nil {
		return "", err
	}

	// Fill remaining positions with random characters
	err = fillRemainingPasswordPositions(password, allChars, len(sets))
	if err != nil {
		return "", err
	}

	// Shuffle the password
	err = shufflePassword(password)
	if err != nil {
		return "", err
	}

	return string(password), nil
}

// fillPasswordWithRequiredSets fills the first positions with required character sets
func fillPasswordWithRequiredSets(password []byte, sets []string) error {
	for i, set := range sets {
		charIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
		if err != nil {
			return fmt.Errorf("failed to generate random character: %v", err)
		}
		password[i] = set[charIndex.Int64()]
	}
	return nil
}

// fillRemainingPasswordPositions fills remaining positions with random characters
func fillRemainingPasswordPositions(password []byte, allChars string, startIndex int) error {
	for i := startIndex; i < len(password); i++ {
		charIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(allChars))))
		if err != nil {
			return fmt.Errorf("failed to generate random character: %v", err)
		}
		password[i] = allChars[charIndex.Int64()]
	}
	return nil
}

// shufflePassword shuffles the password array
func shufflePassword(password []byte) error {
	for i := len(password) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return fmt.Errorf("failed to shuffle password: %v", err)
		}
		password[i], password[j.Int64()] = password[j.Int64()], password[i]
	}
	return nil
}

// Version handlers moved to version_handlers.go

func SetContainer(container *di.Container) {
	appContainer = container
}

func RegisterWebAdminRoutes(router *mux.Router) {

	admin := router.PathPrefix("/admin").Subrouter()
	admin.Use(middleware.RequireAdminAuth)

	admin.HandleFunc("/api-keys", handleAdminListAPIKeys).Methods("GET")
	admin.HandleFunc("/api-keys", handleAdminCreateAPIKey).Methods("POST")
	admin.HandleFunc("/api-keys/{id}", handleAdminUpdateAPIKey).Methods("PUT")
	admin.HandleFunc("/api-keys/{id}", handleAdminDeleteAPIKey).Methods("DELETE")
	admin.HandleFunc("/api-keys/{id}/status", handleAdminUpdateAPIKeyStatus).Methods("PATCH")

	admin.HandleFunc("/usage/logs", handleAdminUsageLogs).Methods("GET")

	admin.HandleFunc("/analytics", handleAdminAnalytics).Methods("GET")
	admin.HandleFunc("/analytics/data", handleAdminAnalytics).Methods("GET")

	admin.HandleFunc("/users", handleAdminListUsers).Methods("GET")
	admin.HandleFunc("/users/{id}", handleAdminGetUser).Methods("GET")
	admin.HandleFunc("/users", handleAdminCreateUser).Methods("POST")
	admin.HandleFunc("/users/{id}", handleAdminPatchUser).Methods("PATCH")
	admin.HandleFunc("/users/{id}/approve", handleAdminApproveUser).Methods("POST")
	admin.HandleFunc("/users/{id}/suspend", handleAdminSuspendUser).Methods("POST")
	admin.HandleFunc("/users/{id}/2fa/enable", handleAdminEnable2FA).Methods("POST")
	admin.HandleFunc("/users/{id}/2fa/disable", handleAdminDisable2FA).Methods("POST")
	admin.HandleFunc("/users/{id}/reset-password", handleAdminResetPassword).Methods("POST")

	log.Printf("Admin routes registered")
}

// Admin handler functions moved to admin_handlers.go

// Authentication handler functions moved to auth_handlers.go

// Package handler functions moved to package_handlers.go

// API routes moved to api_handlers.go

// Utility functions moved to appropriate modules
