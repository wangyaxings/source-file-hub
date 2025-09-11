package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"secure-file-hub/internal/auth"
	"secure-file-hub/internal/database"
	"secure-file-hub/internal/handler"
	"secure-file-hub/internal/logger"
	"secure-file-hub/internal/migration"
	"secure-file-hub/internal/server"
)

func main() {
	log.Println("Starting Secure File Hub...")

	// 初始化数据库系统
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "data/fileserver.db"
	}
	if err := database.InitDatabase(dbPath); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer func() {
		if db := database.GetDatabase(); db != nil {
			db.Close()
		}
	}()

	// 初始化结构化日志系统
	if err := logger.InitLogger(database.GetDatabase().GetDB()); err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer func() {
		if l := logger.GetLogger(); l != nil {
			l.Close()
		}
	}()

	// 运行数据迁移
	log.Println("Running data migration...")
	if err := migration.MigrateFromJSON("downloads/metadata.json"); err != nil {
		log.Printf("Warning: JSON migration failed: %v", err)
	}

	// Seed initial admin account and DB role
	adminPassword := os.Getenv("ADMIN_PASSWORD")
	if adminPassword == "" {
		adminPassword = "admin123" // Default password for development
		log.Printf("Using default admin password: admin123")
	}
	auth.SeedAdmin(adminPassword)
	if db := database.GetDatabase(); db != nil {
		// Ensure admin role exists in DB for consistency
		_ = db.CreateOrUpdateUserRole(&database.UserRole{
			UserID:       "admin",
			Role:         "administrator",
			Permissions:  []string{"read", "download", "upload", "admin"},
			QuotaDaily:   -1,
			QuotaMonthly: -1,
			Status:       "active",
		})

		// Debug: Check if admin user exists
		if user, err := db.GetUser("admin"); err == nil {
			log.Printf("Admin user exists: username=%s, role=%s, email=%s", user.Username, user.Role, user.Email)
			log.Printf("Admin password hash exists: %t", user.PasswordHash != "")
		} else {
			log.Printf("Admin user not found: %v", err)
		}
	}

	// 启动自动清理任务
	go func() {
		ticker := time.NewTicker(24 * time.Hour) // 每24小时运行一次
		defer ticker.Stop()

		for range ticker.C {
			if db := database.GetDatabase(); db != nil {
				if err := db.AutoCleanupRecycleBin(); err != nil {
					log.Printf("Auto cleanup failed: %v", err)
				}
			}
		}
	}()

	// 启动临时API Key清理任务
	go func() {
		ticker := time.NewTicker(5 * time.Minute) // 每5分钟清理一次
		defer ticker.Stop()

		for range ticker.C {
			handler.CleanupExpiredTempKeys()
		}
	}()

	// 记录系统启动日志
	if l := logger.GetLogger(); l != nil {
		details := map[string]interface{}{
			"version": "v1.0.0",
			"port":    8443,
			"mode":    "production",
		}
		l.LogError("System Started", nil, details)
	}

	// 创建服务器实例
	srv := server.New()

	// 注册路由
	handler.RegisterRoutes(srv.Router)

	// HTTPS-only unified mode
	certFile := "certs/server.crt"
	keyFile := "certs/server.key"

	httpsServer := &http.Server{
		Addr:         ":8443",
		Handler:      srv.Router,
		ReadTimeout:  120 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  180 * time.Second,
	}

	go func() {
		log.Printf("HTTPS Server starting on port 8443 (Unified HTTPS Mode)...")
		if err := httpsServer.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTPS Server failed to start: %v", err)
		}
	}()

	// 等待中断信号以优雅关闭服务器
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// 设置关闭超时
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 优雅关闭服务器
	log.Println("Shutting down HTTPS server...")
	if err := httpsServer.Shutdown(ctx); err != nil {
		log.Printf("HTTPS Server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
}
