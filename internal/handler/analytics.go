package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"secure-file-hub/internal/database"

	"github.com/gorilla/mux"
)

// getAnalyticsDataHandler provides comprehensive analytics data
func getAnalyticsDataHandler(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	timeRange := r.URL.Query().Get("timeRange")
	customStart := r.URL.Query().Get("startDate")
	customEnd := r.URL.Query().Get("endDate")
	apiKeyFilter := r.URL.Query().Get("apiKey")
	userFilter := r.URL.Query().Get("user")

	// Calculate time range
	var startTime, endTime time.Time
	now := time.Now()

	switch timeRange {
	case "1d":
		startTime = now.AddDate(0, 0, -1)
		endTime = now
	case "7d":
		startTime = now.AddDate(0, 0, -7)
		endTime = now
	case "30d":
		startTime = now.AddDate(0, 0, -30)
		endTime = now
	case "custom":
		if customStart != "" {
			if t, err := time.Parse(time.RFC3339, customStart); err == nil {
				startTime = t
			} else if t, err := time.Parse("2006-01-02T15:04", customStart); err == nil {
				startTime = t
			} else {
				writeErrorResponse(w, http.StatusBadRequest, "Invalid start date format")
				return
			}
		} else {
			startTime = now.AddDate(0, 0, -7) // Default to 7 days
		}

		if customEnd != "" {
			if t, err := time.Parse(time.RFC3339, customEnd); err == nil {
				endTime = t
			} else if t, err := time.Parse("2006-01-02T15:04", customEnd); err == nil {
				endTime = t
			} else {
				writeErrorResponse(w, http.StatusBadRequest, "Invalid end date format")
				return
			}
		} else {
			endTime = now
		}
	default:
		// Default to last 7 days
		startTime = now.AddDate(0, 0, -7)
		endTime = now
	}

	// Validate time range
	if endTime.Before(startTime) {
		writeErrorResponse(w, http.StatusBadRequest, "End date must be after start date")
		return
	}

	// Limit time range to prevent excessive queries
	maxDuration := 90 * 24 * time.Hour // 90 days
	if endTime.Sub(startTime) > maxDuration {
		writeErrorResponse(w, http.StatusBadRequest, "Time range cannot exceed 90 days")
		return
	}

	db := database.GetDatabase()
	if db == nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Database not available")
		return
	}

	// Create analytics time range
	analyticsTimeRange := database.AnalyticsTimeRange{
		Start: startTime,
		End:   endTime,
	}

	// Filter validation
	if apiKeyFilter == "all" {
		apiKeyFilter = ""
	}
	if userFilter == "all" {
		userFilter = ""
	}

	// Get analytics data
	analyticsData, err := db.GetAnalyticsData(analyticsTimeRange, apiKeyFilter, userFilter)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve analytics data: "+err.Error())
		return
	}

	response := Response{
		Success: true,
		Message: "Analytics data retrieved successfully",
		Data:    analyticsData,
	}

	writeJSONResponse(w, http.StatusOK, response)
}

// getAnalyticsSummaryHandler provides quick summary statistics
func getAnalyticsSummaryHandler(w http.ResponseWriter, r *http.Request) {
	db := database.GetDatabase()
	if db == nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Database not available")
		return
	}

	now := time.Now()

	// Get today's stats
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	todayEnd := now

	todayRange := database.AnalyticsTimeRange{Start: todayStart, End: todayEnd}
	todayData, err := db.GetAnalyticsData(todayRange, "", "")
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve today's data")
		return
	}

	// Get this week's stats
	weekStart := now.AddDate(0, 0, -7)
	weekRange := database.AnalyticsTimeRange{Start: weekStart, End: now}
	weekData, err := db.GetAnalyticsData(weekRange, "", "")
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve week's data")
		return
	}

	// Get this month's stats
	monthStart := now.AddDate(0, 0, -30)
	monthRange := database.AnalyticsTimeRange{Start: monthStart, End: now}
	monthData, err := db.GetAnalyticsData(monthRange, "", "")
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve month's data")
		return
	}

	// Get all-time API keys count
	apiKeys, err := db.GetAllAPIKeys()
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve API keys")
		return
	}

	activeKeysCount := 0
	for _, key := range apiKeys {
		if key.Status == "active" {
			activeKeysCount++
		}
	}

	summary := map[string]interface{}{
		"today": map[string]interface{}{
			"requests":         todayData.Overview.TotalRequests,
			"successRate":      todayData.Overview.SuccessRate,
			"avgResponseTime":  todayData.Overview.AvgResponseTime,
			"activeUsers":      todayData.Overview.ActiveUsers,
		},
		"this_week": map[string]interface{}{
			"requests":         weekData.Overview.TotalRequests,
			"successRate":      weekData.Overview.SuccessRate,
			"avgResponseTime":  weekData.Overview.AvgResponseTime,
			"activeUsers":      weekData.Overview.ActiveUsers,
		},
		"this_month": map[string]interface{}{
			"requests":         monthData.Overview.TotalRequests,
			"successRate":      monthData.Overview.SuccessRate,
			"avgResponseTime":  monthData.Overview.AvgResponseTime,
			"activeUsers":      monthData.Overview.ActiveUsers,
		},
		"total": map[string]interface{}{
			"api_keys":         len(apiKeys),
			"active_keys":      activeKeysCount,
			"disabled_keys":    len(apiKeys) - activeKeysCount,
		},
	}

	response := Response{
		Success: true,
		Message: "Analytics summary retrieved successfully",
		Data:    summary,
	}

	writeJSONResponse(w, http.StatusOK, response)
}

// getTopAPIKeysHandler gets top performing API keys
func getTopAPIKeysHandler(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	limitStr := r.URL.Query().Get("limit")
	timeRange := r.URL.Query().Get("timeRange")

	limit := 10
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}

	// Calculate time range (default to last 7 days)
	now := time.Now()
	var startTime time.Time

	switch timeRange {
	case "1d":
		startTime = now.AddDate(0, 0, -1)
	case "30d":
		startTime = now.AddDate(0, 0, -30)
	default:
		startTime = now.AddDate(0, 0, -7)
	}

	db := database.GetDatabase()
	if db == nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Database not available")
		return
	}

	analyticsTimeRange := database.AnalyticsTimeRange{
		Start: startTime,
		End:   now,
	}

	analyticsData, err := db.GetAnalyticsData(analyticsTimeRange, "", "")
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve analytics data")
		return
	}

	// Limit results
	topAPIKeys := analyticsData.APIKeyUsage
	if len(topAPIKeys) > limit {
		topAPIKeys = topAPIKeys[:limit]
	}

	response := Response{
		Success: true,
		Message: "Top API keys retrieved successfully",
		Data: map[string]interface{}{
			"apiKeys":   topAPIKeys,
			"timeRange": timeRange,
			"limit":     limit,
		},
	}

	writeJSONResponse(w, http.StatusOK, response)
}

// getAnalyticsExportHandler exports analytics data
func getAnalyticsExportHandler(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters (similar to getAnalyticsDataHandler)
	timeRange := r.URL.Query().Get("timeRange")
	customStart := r.URL.Query().Get("startDate")
	customEnd := r.URL.Query().Get("endDate")
	apiKeyFilter := r.URL.Query().Get("apiKey")
	userFilter := r.URL.Query().Get("user")
	format := r.URL.Query().Get("format")

	if format == "" {
		format = "json"
	}

	// Calculate time range (reuse logic from getAnalyticsDataHandler)
	var startTime, endTime time.Time
	now := time.Now()

	switch timeRange {
	case "1d":
		startTime = now.AddDate(0, 0, -1)
		endTime = now
	case "7d":
		startTime = now.AddDate(0, 0, -7)
		endTime = now
	case "30d":
		startTime = now.AddDate(0, 0, -30)
		endTime = now
	case "custom":
		if customStart != "" {
			if t, err := time.Parse(time.RFC3339, customStart); err == nil {
				startTime = t
			} else if t, err := time.Parse("2006-01-02T15:04", customStart); err == nil {
				startTime = t
			} else {
				writeErrorResponse(w, http.StatusBadRequest, "Invalid start date format")
				return
			}
		} else {
			startTime = now.AddDate(0, 0, -7)
		}

		if customEnd != "" {
			if t, err := time.Parse(time.RFC3339, customEnd); err == nil {
				endTime = t
			} else if t, err := time.Parse("2006-01-02T15:04", customEnd); err == nil {
				endTime = t
			} else {
				writeErrorResponse(w, http.StatusBadRequest, "Invalid end date format")
				return
			}
		} else {
			endTime = now
		}
	default:
		startTime = now.AddDate(0, 0, -7)
		endTime = now
	}

	db := database.GetDatabase()
	if db == nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Database not available")
		return
	}

	analyticsTimeRange := database.AnalyticsTimeRange{
		Start: startTime,
		End:   endTime,
	}

	if apiKeyFilter == "all" {
		apiKeyFilter = ""
	}
	if userFilter == "all" {
		userFilter = ""
	}

	analyticsData, err := db.GetAnalyticsData(analyticsTimeRange, apiKeyFilter, userFilter)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve analytics data")
		return
	}

	switch format {
	case "json":
		// Set headers for file download
		filename := "analytics-" + now.Format("2006-01-02-15-04-05") + ".json"
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename="+filename)

		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(analyticsData); err != nil {
			writeErrorResponse(w, http.StatusInternalServerError, "Failed to encode analytics data")
			return
		}

	default:
		writeErrorResponse(w, http.StatusBadRequest, "Unsupported export format")
	}
}

// RegisterAnalyticsRoutes registers analytics-specific routes
func RegisterAnalyticsRoutes(router *mux.Router) {
	// Enhanced analytics routes
	router.HandleFunc("/analytics/data", requireAdminAuth(getAnalyticsDataHandler)).Methods("GET")
	router.HandleFunc("/analytics/summary", requireAdminAuth(getAnalyticsSummaryHandler)).Methods("GET")
	router.HandleFunc("/analytics/top-keys", requireAdminAuth(getTopAPIKeysHandler)).Methods("GET")
	router.HandleFunc("/analytics/export", requireAdminAuth(getAnalyticsExportHandler)).Methods("GET")
}