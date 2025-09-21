package database

import (
	"database/sql"
	"fmt"
	"log"
	"time"
)

// AnalyticsTimeRange represents different time range options
type AnalyticsTimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// AnalyticsOverview contains high-level statistics
type AnalyticsOverview struct {
	TotalRequests   int64   `json:"totalRequests"`
	TotalAPIKeys    int64   `json:"totalApiKeys"`
	ActiveUsers     int64   `json:"activeUsers"`
	AvgResponseTime float64 `json:"avgResponseTime"`
	SuccessRate     float64 `json:"successRate"`
	ErrorRate       float64 `json:"errorRate"`
}

// AnalyticsTrend represents daily/hourly trends
type AnalyticsTrend struct {
	Date            string  `json:"date"`
	Requests        int64   `json:"requests"`
	SuccessCount    int64   `json:"successCount"`
	ErrorCount      int64   `json:"errorCount"`
	AvgResponseTime float64 `json:"avgResponseTime"`
}

// APIKeyUsageStats represents API key usage statistics
type APIKeyUsageStats struct {
	APIKeyID    string  `json:"apiKeyId"`
	APIKeyName  string  `json:"apiKeyName"`
	UserID      string  `json:"userId"`
	Requests    int64   `json:"requests"`
	SuccessRate float64 `json:"successRate"`
	LastUsed    string  `json:"lastUsed"`
}

// OperationTypeStats represents operation type distribution
type OperationTypeStats struct {
	Operation  string  `json:"operation"`
	Count      int64   `json:"count"`
	Percentage float64 `json:"percentage"`
}

// HourlyDistribution represents hourly request distribution
type HourlyDistribution struct {
	Hour     int   `json:"hour"`
	Requests int64 `json:"requests"`
}

// ErrorTypeStats represents error type statistics
type ErrorTypeStats struct {
	StatusCode int    `json:"statusCode"`
	Message    string `json:"message"`
	Count      int64  `json:"count"`
}

// AnalyticsData represents comprehensive analytics data
type AnalyticsData struct {
	TimeRange          AnalyticsTimeRange   `json:"timeRange"`
	Overview           AnalyticsOverview    `json:"overview"`
	Trends             []AnalyticsTrend     `json:"trends"`
	APIKeyUsage        []APIKeyUsageStats   `json:"apiKeyUsage"`
	OperationTypes     []OperationTypeStats `json:"operationTypes"`
	HourlyDistribution []HourlyDistribution `json:"hourlyDistribution"`
	ErrorTypes         []ErrorTypeStats     `json:"errorTypes"`
}

// GetAnalyticsData retrieves comprehensive analytics data for the specified time range
func (d *Database) GetAnalyticsData(timeRange AnalyticsTimeRange, apiKeyFilter, userFilter string) (*AnalyticsData, error) {
	analytics := &AnalyticsData{
		TimeRange: timeRange,
	}

	// Build WHERE clause for filters
	whereClause := "WHERE request_time >= ? AND request_time <= ?"
	args := []interface{}{timeRange.Start.Format(time.RFC3339), timeRange.End.Format(time.RFC3339)}

	if apiKeyFilter != "" {
		whereClause += " AND api_key_id = ?"
		args = append(args, apiKeyFilter)
	}

	if userFilter != "" {
		whereClause += " AND user_id = ?"
		args = append(args, userFilter)
	}

	// Get overview statistics
	overview, err := d.getAnalyticsOverview(whereClause, args)
	if err != nil {
		return nil, fmt.Errorf("failed to get overview: %w", err)
	}
	analytics.Overview = overview

	// Get trends
	trends, err := d.getAnalyticsTrends(whereClause, args)
	if err != nil {
		return nil, fmt.Errorf("failed to get trends: %w", err)
	}
	analytics.Trends = trends

	// Get API key usage stats
	apiKeyUsage, err := d.getAPIKeyUsageStats(whereClause, args)
	if err != nil {
		return nil, fmt.Errorf("failed to get API key usage: %w", err)
	}
	analytics.APIKeyUsage = apiKeyUsage

	// Get operation type stats
	operationTypes, err := d.getOperationTypeStats(whereClause, args)
	if err != nil {
		return nil, fmt.Errorf("failed to get operation types: %w", err)
	}
	analytics.OperationTypes = operationTypes

	// Get hourly distribution
	hourlyDist, err := d.getHourlyDistribution(whereClause, args)
	if err != nil {
		return nil, fmt.Errorf("failed to get hourly distribution: %w", err)
	}
	analytics.HourlyDistribution = hourlyDist

	// Get error types
	errorTypes, err := d.getErrorTypeStats(whereClause, args)
	if err != nil {
		return nil, fmt.Errorf("failed to get error types: %w", err)
	}
	analytics.ErrorTypes = errorTypes

	return analytics, nil
}

// getAnalyticsOverview gets overview statistics
func (d *Database) getAnalyticsOverview(whereClause string, args []interface{}) (AnalyticsOverview, error) {
	overview := AnalyticsOverview{}

	// Total requests
	query := fmt.Sprintf("SELECT COUNT(*) FROM api_usage_logs %s", whereClause)
	err := d.db.QueryRow(query, args...).Scan(&overview.TotalRequests)
	if err != nil {
		return overview, err
	}

	// Success/Error counts and average response time
	query = fmt.Sprintf(`
		SELECT
			COUNT(CASE WHEN status_code >= 200 AND status_code < 300 THEN 1 END) as success_count,
			COUNT(CASE WHEN status_code >= 400 THEN 1 END) as error_count,
			AVG(response_time_ms) as avg_response_time
		FROM api_usage_logs %s
	`, whereClause)

	var successCount, errorCount int64
	var avgResponseTime sql.NullFloat64

	err = d.db.QueryRow(query, args...).Scan(&successCount, &errorCount, &avgResponseTime)
	if err != nil {
		return overview, err
	}

	if avgResponseTime.Valid {
		overview.AvgResponseTime = avgResponseTime.Float64
	}

	if overview.TotalRequests > 0 {
		overview.SuccessRate = float64(successCount) / float64(overview.TotalRequests) * 100
		overview.ErrorRate = float64(errorCount) / float64(overview.TotalRequests) * 100
	}

	// Active users count
	query = fmt.Sprintf("SELECT COUNT(DISTINCT user_id) FROM api_usage_logs %s", whereClause)
	err = d.db.QueryRow(query, args...).Scan(&overview.ActiveUsers)
	if err != nil {
		return overview, err
	}

	// Total API keys count
	query = fmt.Sprintf("SELECT COUNT(DISTINCT api_key_id) FROM api_usage_logs %s", whereClause)
	err = d.db.QueryRow(query, args...).Scan(&overview.TotalAPIKeys)
	if err != nil {
		return overview, err
	}

	return overview, nil
}

// getAnalyticsTrends gets daily trends
func (d *Database) getAnalyticsTrends(whereClause string, args []interface{}) ([]AnalyticsTrend, error) {
	query := fmt.Sprintf(`
		SELECT
			DATE(request_time) as date,
			COUNT(*) as requests,
			COUNT(CASE WHEN status_code >= 200 AND status_code < 300 THEN 1 END) as success_count,
			COUNT(CASE WHEN status_code >= 400 THEN 1 END) as error_count,
			AVG(response_time_ms) as avg_response_time
		FROM api_usage_logs %s
		GROUP BY DATE(request_time)
		ORDER BY date
	`, whereClause)

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var trends []AnalyticsTrend
	for rows.Next() {
		var trend AnalyticsTrend
		var avgResponseTime sql.NullFloat64

		err := rows.Scan(&trend.Date, &trend.Requests, &trend.SuccessCount,
			&trend.ErrorCount, &avgResponseTime)
		if err != nil {
			log.Printf("Error scanning trend record: %v", err)
			continue
		}

		if avgResponseTime.Valid {
			trend.AvgResponseTime = avgResponseTime.Float64
		}

		trends = append(trends, trend)
	}

	return trends, nil
}

// getAPIKeyUsageStats gets API key usage statistics
func (d *Database) getAPIKeyUsageStats(whereClause string, args []interface{}) ([]APIKeyUsageStats, error) {
	query := fmt.Sprintf(`
        SELECT
            l.api_key_id,
            CASE
              WHEN l.api_key_id = 'web_session' THEN 'Web Session'
              ELSE COALESCE(l.api_key_name, k.name, 'Unknown')
            END as api_key_name,
            l.user_id,
            COUNT(*) as requests,
            COUNT(CASE WHEN l.status_code >= 200 AND l.status_code < 300 THEN 1 END) as success_count,
            MAX(l.request_time) as last_used
        FROM api_usage_logs l
        LEFT JOIN api_keys k ON l.api_key_id = k.id AND l.api_key_id != 'web_session'
        %s
        GROUP BY l.api_key_id, l.user_id
        ORDER BY requests DESC
        LIMIT 20
    `, whereClause)

	// Debug log for analytics query
	log.Printf("[DEBUG] getAPIKeyUsageStats: Executing query with args: %v", args)

	rows, err := d.db.Query(query, args...)
	if err != nil {
		log.Printf("[DEBUG] getAPIKeyUsageStats: Query failed: %v", err)
		return nil, err
	}
	defer rows.Close()

	var stats []APIKeyUsageStats
	for rows.Next() {
		var stat APIKeyUsageStats
		var successCount int64

		err := rows.Scan(&stat.APIKeyID, &stat.APIKeyName, &stat.UserID,
			&stat.Requests, &successCount, &stat.LastUsed)
		if err != nil {
			log.Printf("[DEBUG] getAPIKeyUsageStats: Error scanning row: %v", err)
			continue
		}

		// Debug log for API key name from analytics
		log.Printf("[DEBUG] getAPIKeyUsageStats: API key ID='%s', Name='%s'", stat.APIKeyID, stat.APIKeyName)

		if stat.Requests > 0 {
			stat.SuccessRate = float64(successCount) / float64(stat.Requests) * 100
		}

		stats = append(stats, stat)
	}

	// Debug log for final results
	log.Printf("[DEBUG] getAPIKeyUsageStats: Returning %d stats", len(stats))

	return stats, nil
}

// getOperationTypeStats gets operation type statistics
func (d *Database) getOperationTypeStats(whereClause string, args []interface{}) ([]OperationTypeStats, error) {
	query := fmt.Sprintf(`
		SELECT
			PRINTF('%%s %%s', method,
				CASE
					WHEN endpoint LIKE '%%/files/%%/download' THEN 'download'
					WHEN endpoint LIKE '%%/files' AND method = 'POST' THEN 'upload'
					WHEN endpoint LIKE '%%/files' AND method = 'GET' THEN 'list'
					WHEN endpoint LIKE '%%/health' THEN 'health'
					ELSE SUBSTR(endpoint, INSTR(endpoint, '/api/') + 5)
				END
			) as operation,
			COUNT(*) as count
		FROM api_usage_logs %s
		GROUP BY operation
		ORDER BY count DESC
		LIMIT 10
	`, whereClause)

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var totalRequests int64 = 0
	var operations []OperationTypeStats

	// First pass: get counts
	for rows.Next() {
		var op OperationTypeStats
		err := rows.Scan(&op.Operation, &op.Count)
		if err != nil {
			log.Printf("Error scanning operation type stat: %v", err)
			continue
		}
		totalRequests += op.Count
		operations = append(operations, op)
	}

	// Second pass: calculate percentages
	for i := range operations {
		if totalRequests > 0 {
			operations[i].Percentage = float64(operations[i].Count) / float64(totalRequests) * 100
		}
	}

	return operations, nil
}

// getHourlyDistribution gets hourly request distribution
func (d *Database) getHourlyDistribution(whereClause string, args []interface{}) ([]HourlyDistribution, error) {
	query := fmt.Sprintf(`
		SELECT
			CAST(strftime('%%H', request_time) AS INTEGER) as hour,
			COUNT(*) as requests
		FROM api_usage_logs %s
		GROUP BY hour
		ORDER BY hour
	`, whereClause)

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Initialize 24-hour array
	distribution := make([]HourlyDistribution, 24)
	for i := 0; i < 24; i++ {
		distribution[i] = HourlyDistribution{Hour: i, Requests: 0}
	}

	// Fill in actual data
	for rows.Next() {
		var hour int
		var requests int64
		err := rows.Scan(&hour, &requests)
		if err != nil {
			log.Printf("Error scanning hourly distribution: %v", err)
			continue
		}
		if hour >= 0 && hour < 24 {
			distribution[hour].Requests = requests
		}
	}

	return distribution, nil
}

// getErrorTypeStats gets error type statistics
func (d *Database) getErrorTypeStats(whereClause string, args []interface{}) ([]ErrorTypeStats, error) {
	query := fmt.Sprintf(`
		SELECT
			status_code,
			COUNT(*) as count
		FROM api_usage_logs %s AND status_code >= 400
		GROUP BY status_code
		ORDER BY count DESC
		LIMIT 10
	`, whereClause)

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var errors []ErrorTypeStats
	for rows.Next() {
		var errorStat ErrorTypeStats
		err := rows.Scan(&errorStat.StatusCode, &errorStat.Count)
		if err != nil {
			log.Printf("Error scanning error type stat: %v", err)
			continue
		}

		// Set human-readable message based on status code
		errorStat.Message = getStatusMessage(errorStat.StatusCode)
		errors = append(errors, errorStat)
	}

	return errors, nil
}

// getStatusMessage returns human-readable message for HTTP status codes
func getStatusMessage(statusCode int) string {
	messages := map[int]string{
		400: "Bad Request",
		401: "Unauthorized",
		403: "Forbidden",
		404: "Not Found",
		405: "Method Not Allowed",
		429: "Too Many Requests",
		500: "Internal Server Error",
		502: "Bad Gateway",
		503: "Service Unavailable",
		504: "Gateway Timeout",
	}

	if message, exists := messages[statusCode]; exists {
		return message
	}
	return fmt.Sprintf("HTTP %d", statusCode)
}
