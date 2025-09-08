package logger

import (
    "database/sql"
    "encoding/json"
    "fmt"
    "log"
    "os"
    "runtime"
    "strings"
    "time"
)

// LogLevel represents logging severity level
type LogLevel string

const (
    LogLevelDEBUG LogLevel = "DEBUG"
    LogLevelINFO  LogLevel = "INFO"
    LogLevelWARN  LogLevel = "WARN"
    LogLevelERROR LogLevel = "ERROR"
    LogLevelFATAL LogLevel = "FATAL"
)

// EventCode represents structured event types
type EventCode string

const (
    EventAPIRequest      EventCode = "API_REQUEST"
    EventAPIResponse     EventCode = "API_RESPONSE"
    EventLogin           EventCode = "USER_LOGIN"
    EventLogout          EventCode = "USER_LOGOUT"
    EventFileDownload    EventCode = "FILE_DOWNLOAD"
    EventFileUpload      EventCode = "FILE_UPLOAD"
    EventAuthError       EventCode = "AUTH_ERROR"
    EventSystemStart     EventCode = "SYSTEM_START"
    EventSystemStop      EventCode = "SYSTEM_STOP"
    EventError           EventCode = "ERROR"
    EventCollectionStart EventCode = "COLLECTION_START"
)

// StructuredLog is the persisted log record format
type StructuredLog struct {
    Timestamp      string                 `json:"timestamp"`
    Level          LogLevel               `json:"level"`
    CIID           string                 `json:"ciid"`
    GBID           string                 `json:"gbid"`
    EventCode      EventCode              `json:"event_code"`
    Message        string                 `json:"message"`
    Details        map[string]interface{} `json:"details"`
    Hostname       string                 `json:"hostname"`
    SourceLocation string                 `json:"source_location"`
}

// Logger writes structured logs to stdout and database
type Logger struct {
    db       *sql.DB
    hostname string
    ciid     string
    gbid     string
}

var defaultLogger *Logger

// InitLogger initializes default logger
func InitLogger(db *sql.DB) error {
    hostname, err := os.Hostname()
    if err != nil {
        hostname = "unknown"
    }

    defaultLogger = &Logger{
        db:       db,
        hostname: hostname,
        ciid:     "secure-file-hub-v1-prod",
        gbid:     generateGBID(),
    }

    return nil
}

// GetLogger returns default logger
func GetLogger() *Logger {
    return defaultLogger
}

// LogAPIRequest records an API request event
func (l *Logger) LogAPIRequest(method, path, userAgent, remoteAddr string, userInfo map[string]interface{}) {
    details := map[string]interface{}{
        "method":      method,
        "path":        path,
        "user_agent":  userAgent,
        "remote_addr": remoteAddr,
    }
    if userInfo != nil {
        details["user"] = userInfo
    }
    l.log(LogLevelINFO, EventAPIRequest, fmt.Sprintf("API request: %s %s", method, path), details)
}

// LogAPIResponse records an API response event
func (l *Logger) LogAPIResponse(method, path string, statusCode int, responseTime time.Duration, userInfo map[string]interface{}) {
    details := map[string]interface{}{
        "method":        method,
        "path":          path,
        "status_code":   statusCode,
        "response_time": responseTime.Milliseconds(),
    }
    if userInfo != nil {
        details["user"] = userInfo
    }

    level := LogLevelINFO
    if statusCode >= 400 { level = LogLevelWARN }
    if statusCode >= 500 { level = LogLevelERROR }

    l.log(level, EventAPIResponse, fmt.Sprintf("API response: %s %s [%d] (%dms)", method, path, statusCode, responseTime.Milliseconds()), details)
}

// LogUserLogin records a user login attempt
func (l *Logger) LogUserLogin(tenantID, username, remoteAddr string, success bool) {
    details := map[string]interface{}{
        "tenant_id":   tenantID,
        "username":    username,
        "remote_addr": remoteAddr,
        "success":     success,
    }
    level := LogLevelINFO
    message := fmt.Sprintf("User login success: %s@%s", username, tenantID)
    if !success {
        level = LogLevelWARN
        message = fmt.Sprintf("User login failed: %s@%s", username, tenantID)
    }
    l.log(level, EventLogin, message, details)
}

// LogFileDownload records a file download event
func (l *Logger) LogFileDownload(filePath, remoteAddr string, fileSize int64, userInfo map[string]interface{}) {
    details := map[string]interface{}{
        "file_path":   filePath,
        "remote_addr": remoteAddr,
        "file_size":   fileSize,
    }
    if userInfo != nil {
        details["user"] = userInfo
    }
    l.log(LogLevelINFO, EventFileDownload, fmt.Sprintf("File download: %s (%d bytes)", filePath, fileSize), details)
}

// LogFileUpload records a file upload event
func (l *Logger) LogFileUpload(filePath, uploader string, fileSize int64, details map[string]interface{}) {
    uploadDetails := map[string]interface{}{
        "file_path": filePath,
        "uploader":  uploader,
        "file_size": fileSize,
    }
    if details != nil {
        for k, v := range details { uploadDetails[k] = v }
    }
    l.log(LogLevelINFO, EventFileUpload, fmt.Sprintf("File upload: %s (%d bytes) by %s", filePath, fileSize, uploader), uploadDetails)
}

// LogError records an error event with optional error payload
func (l *Logger) LogError(message string, err error, details map[string]interface{}) {
    if details == nil { details = make(map[string]interface{}) }
    if err != nil { details["error"] = err.Error() }
    l.log(LogLevelERROR, EventError, message, details)
}

// log writes structured log to stdout and persists to DB
func (l *Logger) log(level LogLevel, eventCode EventCode, message string, details map[string]interface{}) {
    // Capture caller location
    _, file, line, ok := runtime.Caller(2)
    sourceLocation := "unknown"
    if ok {
        parts := strings.Split(file, "/")
        filename := parts[len(parts)-1]
        sourceLocation = fmt.Sprintf("%s:%d", filename, line)
    }

    structuredLog := StructuredLog{
        Timestamp:      time.Now().UTC().Format(time.RFC3339Nano),
        Level:          level,
        CIID:           l.ciid,
        GBID:           l.gbid,
        EventCode:      eventCode,
        Message:        message,
        Details:        details,
        Hostname:       l.hostname,
        SourceLocation: sourceLocation,
    }

    // Console
    logJSON, _ := json.Marshal(structuredLog)
    log.Printf("%s", string(logJSON))

    // Persist
    l.saveToDatabase(structuredLog)
}

// saveToDatabase persists a structured log into access_logs
func (l *Logger) saveToDatabase(logEntry StructuredLog) {
    if l.db == nil { return }

    detailsJSON, _ := json.Marshal(logEntry.Details)

    insertSQL := `
    INSERT INTO access_logs (
        timestamp, level, ciid, gbid, event_code,
        message, details, hostname, source_location
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `

    _, err := l.db.Exec(insertSQL,
        logEntry.Timestamp,
        logEntry.Level,
        logEntry.CIID,
        logEntry.GBID,
        logEntry.EventCode,
        logEntry.Message,
        string(detailsJSON),
        logEntry.Hostname,
        logEntry.SourceLocation,
    )
    if err != nil {
        log.Printf("Failed to save log to database: %v", err)
    }
}

// generateGBID returns a pseudo-UUID-like id (simple placeholder)
func generateGBID() string {
    return fmt.Sprintf("f47ac10b-58cc-4372-a567-%d", time.Now().UnixNano()%1000000000000)
}

// GetAccessLogs loads recent logs with pagination
func (l *Logger) GetAccessLogs(limit int, offset int) ([]StructuredLog, error) {
    querySQL := `
    SELECT timestamp, level, ciid, gbid, event_code,
           message, details, hostname, source_location
    FROM access_logs
    ORDER BY timestamp DESC
    LIMIT ? OFFSET ?
    `

    rows, err := l.db.Query(querySQL, limit, offset)
    if err != nil { return nil, err }
    defer rows.Close()

    var logs []StructuredLog
    for rows.Next() {
        var logRec StructuredLog
        var detailsJSON string

        err := rows.Scan(
            &logRec.Timestamp,
            &logRec.Level,
            &logRec.CIID,
            &logRec.GBID,
            &logRec.EventCode,
            &logRec.Message,
            &detailsJSON,
            &logRec.Hostname,
            &logRec.SourceLocation,
        )
        if err != nil { continue }

        if detailsJSON != "" {
            _ = json.Unmarshal([]byte(detailsJSON), &logRec.Details)
        }
        logs = append(logs, logRec)
    }
    return logs, nil
}

// Close closes the logger database handle
func (l *Logger) Close() error {
    if l.db != nil { return l.db.Close() }
    return nil
}

