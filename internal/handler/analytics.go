package handler

import (
    "encoding/json"
    "net/http"
    "strconv"
    "time"

    "secure-file-hub/internal/database"
    "secure-file-hub/internal/middleware"
    "secure-file-hub/internal/logger"

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
                writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid start date format", map[string]interface{}{"field": "startDate"})
                if l := logger.GetLogger(); l != nil { l.WarnCtx(logger.EventError, "analytics_invalid_start_date", nil, "VALIDATION_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
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
                writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid end date format", map[string]interface{}{"field": "endDate"})
                if l := logger.GetLogger(); l != nil { l.WarnCtx(logger.EventError, "analytics_invalid_end_date", nil, "VALIDATION_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
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
        writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "End date must be after start date", map[string]interface{}{"fields": map[string]interface{}{"startDate": startTime.Format(time.RFC3339), "endDate": endTime.Format(time.RFC3339)}})
        if l := logger.GetLogger(); l != nil { l.WarnCtx(logger.EventError, "analytics_invalid_range_order", nil, "VALIDATION_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
        return
    }

	// Limit time range to prevent excessive queries
	maxDuration := 90 * 24 * time.Hour // 90 days
    if endTime.Sub(startTime) > maxDuration {
        writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "Time range cannot exceed 90 days", map[string]interface{}{"max_days": 90})
        if l := logger.GetLogger(); l != nil { l.WarnCtx(logger.EventError, "analytics_range_exceeds_limit", map[string]interface{}{"max_days": 90}, "VALIDATION_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
        return
    }

	db := database.GetDatabase()
    if db == nil {
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Database not available")
        if l := logger.GetLogger(); l != nil { l.ErrorCtx(logger.EventError, "analytics_db_unavailable", nil, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
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
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve analytics data: "+err.Error())
        if l := logger.GetLogger(); l != nil { l.ErrorCtx(logger.EventError, "analytics_query_failed", nil, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
        return
    }

	response := Response{
		Success: true,
		Message: "Analytics data retrieved successfully",
		Data:    analyticsData,
	}

    writeJSONResponse(w, http.StatusOK, response)
    if l := logger.GetLogger(); l != nil { l.InfoCtx(logger.EventAPIRequest, "analytics_data_success", map[string]interface{}{"from": startTime, "to": endTime}, "", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
}

// getAnalyticsSummaryHandler provides quick summary statistics
func getAnalyticsSummaryHandler(w http.ResponseWriter, r *http.Request) {
	db := database.GetDatabase()
    if db == nil {
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Database not available")
        if l := logger.GetLogger(); l != nil { l.ErrorCtx(logger.EventError, "analytics_summary_db_unavailable", nil, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
        return
    }

	now := time.Now()

	// Get today's stats
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	todayEnd := now

	todayRange := database.AnalyticsTimeRange{Start: todayStart, End: todayEnd}
	todayData, err := db.GetAnalyticsData(todayRange, "", "")
    if err != nil {
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve today's data")
        if l := logger.GetLogger(); l != nil { l.ErrorCtx(logger.EventError, "analytics_summary_today_failed", nil, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
        return
    }

	// Get this week's stats
	weekStart := now.AddDate(0, 0, -7)
	weekRange := database.AnalyticsTimeRange{Start: weekStart, End: now}
	weekData, err := db.GetAnalyticsData(weekRange, "", "")
    if err != nil {
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve week's data")
        if l := logger.GetLogger(); l != nil { l.ErrorCtx(logger.EventError, "analytics_summary_week_failed", nil, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
        return
    }

	// Get this month's stats
	monthStart := now.AddDate(0, 0, -30)
	monthRange := database.AnalyticsTimeRange{Start: monthStart, End: now}
	monthData, err := db.GetAnalyticsData(monthRange, "", "")
    if err != nil {
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve month's data")
        if l := logger.GetLogger(); l != nil { l.ErrorCtx(logger.EventError, "analytics_summary_month_failed", nil, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
        return
    }

	// Get all-time API keys count
	apiKeys, err := db.GetAllAPIKeys()
    if err != nil {
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve API keys")
        if l := logger.GetLogger(); l != nil { l.ErrorCtx(logger.EventError, "analytics_summary_apikeys_failed", nil, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
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
    if l := logger.GetLogger(); l != nil { l.InfoCtx(logger.EventAPIRequest, "analytics_summary_success", nil, "", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
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
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Database not available")
        if l := logger.GetLogger(); l != nil { l.ErrorCtx(logger.EventError, "analytics_top_keys_db_unavailable", nil, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
        return
    }

	analyticsTimeRange := database.AnalyticsTimeRange{
		Start: startTime,
		End:   now,
	}

	analyticsData, err := db.GetAnalyticsData(analyticsTimeRange, "", "")
    if err != nil {
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve analytics data")
        if l := logger.GetLogger(); l != nil { l.ErrorCtx(logger.EventError, "analytics_top_keys_query_failed", nil, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
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
    if l := logger.GetLogger(); l != nil { l.InfoCtx(logger.EventAPIRequest, "analytics_top_keys_success", map[string]interface{}{"limit": limit}, "", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
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
                writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid start date format", map[string]interface{}{"field": "startDate"})
                if l := logger.GetLogger(); l != nil { l.WarnCtx(logger.EventError, "analytics_export_invalid_start_date", nil, "VALIDATION_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
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
                writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid end date format", map[string]interface{}{"field": "endDate"})
                if l := logger.GetLogger(); l != nil { l.WarnCtx(logger.EventError, "analytics_export_invalid_end_date", nil, "VALIDATION_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
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
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Database not available")
        if l := logger.GetLogger(); l != nil { l.ErrorCtx(logger.EventError, "analytics_export_db_unavailable", nil, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
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
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve analytics data")
        if l := logger.GetLogger(); l != nil { l.ErrorCtx(logger.EventError, "analytics_export_query_failed", nil, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
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
            writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to encode analytics data")
            if l := logger.GetLogger(); l != nil { l.ErrorCtx(logger.EventError, "analytics_export_encode_failed", nil, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
            return
        }

	default:
        writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "Unsupported export format", map[string]interface{}{"field": "format", "allowed": []string{"json"}})
        if l := logger.GetLogger(); l != nil { l.WarnCtx(logger.EventError, "analytics_export_unsupported_format", map[string]interface{}{"format": format}, "VALIDATION_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
    }
}

// RegisterAnalyticsRoutes registers analytics-specific routes
func RegisterAnalyticsRoutes(router *mux.Router) {
    // Enhanced analytics routes
    router.HandleFunc("/analytics/data", middleware.RequireAuthorization(getAnalyticsDataHandler)).Methods("GET")
    router.HandleFunc("/analytics/summary", middleware.RequireAuthorization(getAnalyticsSummaryHandler)).Methods("GET")
    router.HandleFunc("/analytics/top-keys", middleware.RequireAuthorization(getTopAPIKeysHandler)).Methods("GET")
    router.HandleFunc("/analytics/export", middleware.RequireAuthorization(getAnalyticsExportHandler)).Methods("GET")
}
