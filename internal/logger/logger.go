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

	_ "github.com/mattn/go-sqlite3"
)

// LogLevel 日志级别
type LogLevel string

const (
	LogLevelDEBUG LogLevel = "DEBUG"
	LogLevelINFO  LogLevel = "INFO"
	LogLevelWARN  LogLevel = "WARN"
	LogLevelERROR LogLevel = "ERROR"
	LogLevelFATAL LogLevel = "FATAL"
)

// EventCode 事件代码
type EventCode string

const (
	EventAPIRequest     EventCode = "API_REQUEST"
	EventAPIResponse    EventCode = "API_RESPONSE"
	EventLogin          EventCode = "USER_LOGIN"
	EventLogout         EventCode = "USER_LOGOUT"
	EventFileDownload   EventCode = "FILE_DOWNLOAD"
	EventFileUpload     EventCode = "FILE_UPLOAD"
	EventAuthError      EventCode = "AUTH_ERROR"
	EventSystemStart    EventCode = "SYSTEM_START"
	EventSystemStop     EventCode = "SYSTEM_STOP"
	EventError          EventCode = "ERROR"
	EventCollectionStart EventCode = "COLLECTION_START"
)

// StructuredLog 结构化日志格式
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

// Logger 结构化日志记录器
type Logger struct {
	db       *sql.DB
	hostname string
	ciid     string
	gbid     string
}

var defaultLogger *Logger

// InitLogger 初始化日志系统
func InitLogger() error {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// 创建SQLite数据库连接
	db, err := sql.Open("sqlite3", "logs.db")
	if err != nil {
		return fmt.Errorf("failed to open database: %v", err)
	}

	// 创建日志表
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS access_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp TEXT NOT NULL,
		level TEXT NOT NULL,
		ciid TEXT NOT NULL,
		gbid TEXT NOT NULL,
		event_code TEXT NOT NULL,
		message TEXT NOT NULL,
		details TEXT,
		hostname TEXT NOT NULL,
		source_location TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_timestamp ON access_logs(timestamp);
	CREATE INDEX IF NOT EXISTS idx_event_code ON access_logs(event_code);
	CREATE INDEX IF NOT EXISTS idx_level ON access_logs(level);
	`

	if _, err := db.Exec(createTableSQL); err != nil {
		return fmt.Errorf("failed to create tables: %v", err)
	}

	defaultLogger = &Logger{
		db:       db,
		hostname: hostname,
		ciid:     "secure-file-hub-v1-prod",
		gbid:     generateGBID(),
	}

	return nil
}

// GetLogger 获取默认日志记录器
func GetLogger() *Logger {
	return defaultLogger
}

// LogAPIRequest 记录API请求日志
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

	l.log(LogLevelINFO, EventAPIRequest, fmt.Sprintf("API请求: %s %s", method, path), details)
}

// LogAPIResponse 记录API响应日志
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
	if statusCode >= 400 {
		level = LogLevelWARN
	}
	if statusCode >= 500 {
		level = LogLevelERROR
	}

	l.log(level, EventAPIResponse, fmt.Sprintf("API响应: %s %s [%d] (%dms)", method, path, statusCode, responseTime.Milliseconds()), details)
}

// LogUserLogin 记录用户登录日志
func (l *Logger) LogUserLogin(tenantID, username, remoteAddr string, success bool) {
	details := map[string]interface{}{
		"tenant_id":   tenantID,
		"username":    username,
		"remote_addr": remoteAddr,
		"success":     success,
	}

	level := LogLevelINFO
	message := fmt.Sprintf("用户登录成功: %s@%s", username, tenantID)
	if !success {
		level = LogLevelWARN
		message = fmt.Sprintf("用户登录失败: %s@%s", username, tenantID)
	}

	l.log(level, EventLogin, message, details)
}

// LogFileDownload 记录文件下载日志
func (l *Logger) LogFileDownload(filePath, remoteAddr string, fileSize int64, userInfo map[string]interface{}) {
	details := map[string]interface{}{
		"file_path":   filePath,
		"remote_addr": remoteAddr,
		"file_size":   fileSize,
	}

	if userInfo != nil {
		details["user"] = userInfo
	}

	l.log(LogLevelINFO, EventFileDownload, fmt.Sprintf("文件下载: %s (%d bytes)", filePath, fileSize), details)
}

// LogFileUpload 记录文件上传日志
func (l *Logger) LogFileUpload(filePath, uploader string, fileSize int64, details map[string]interface{}) {
	uploadDetails := map[string]interface{}{
		"file_path": filePath,
		"uploader":  uploader,
		"file_size": fileSize,
	}

	// 合并额外的详细信息
	if details != nil {
		for k, v := range details {
			uploadDetails[k] = v
		}
	}

	l.log(LogLevelINFO, EventFileUpload, fmt.Sprintf("文件上传: %s (%d bytes) by %s", filePath, fileSize, uploader), uploadDetails)
}

// LogError 记录错误日志
func (l *Logger) LogError(message string, err error, details map[string]interface{}) {
	if details == nil {
		details = make(map[string]interface{})
	}

	if err != nil {
		details["error"] = err.Error()
	}

	l.log(LogLevelERROR, EventError, message, details)
}

// log 内部日志记录方法
func (l *Logger) log(level LogLevel, eventCode EventCode, message string, details map[string]interface{}) {
	// 获取调用位置
	_, file, line, ok := runtime.Caller(2)
	sourceLocation := "unknown"
	if ok {
		// 只保留文件名和行号
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

	// 输出到控制台
	logJSON, _ := json.Marshal(structuredLog)
	log.Printf("%s", string(logJSON))

	// 存储到数据库
	l.saveToDatabase(structuredLog)
}

// saveToDatabase 保存日志到数据库
func (l *Logger) saveToDatabase(logEntry StructuredLog) {
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

// generateGBID 生成全局唯一标识符
func generateGBID() string {
	// 简化版UUID生成
	return fmt.Sprintf("f47ac10b-58cc-4372-a567-%d", time.Now().UnixNano()%1000000000000)
}

// GetAccessLogs 获取访问日志
func (l *Logger) GetAccessLogs(limit int, offset int) ([]StructuredLog, error) {
	querySQL := `
	SELECT timestamp, level, ciid, gbid, event_code,
		   message, details, hostname, source_location
	FROM access_logs
	ORDER BY timestamp DESC
	LIMIT ? OFFSET ?
	`

	rows, err := l.db.Query(querySQL, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []StructuredLog
	for rows.Next() {
		var log StructuredLog
		var detailsJSON string

		err := rows.Scan(
			&log.Timestamp,
			&log.Level,
			&log.CIID,
			&log.GBID,
			&log.EventCode,
			&log.Message,
			&detailsJSON,
			&log.Hostname,
			&log.SourceLocation,
		)

		if err != nil {
			continue
		}

		// 解析details JSON
		if detailsJSON != "" {
			if err := json.Unmarshal([]byte(detailsJSON), &log.Details); err != nil {
				// If we can't unmarshal details, just leave it nil
				log.Details = nil
			}
		}

		logs = append(logs, log)
	}

	return logs, nil
}

// Close 关闭日志系统
func (l *Logger) Close() error {
	if l.db != nil {
		return l.db.Close()
	}
	return nil
}