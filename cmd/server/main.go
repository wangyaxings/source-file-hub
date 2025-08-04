package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

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
		log.Printf("Warning: Migration failed: %v", err)
	}

	// 启动自动清理任务
	go func() {
		ticker := time.NewTicker(24 * time.Hour) // 每24小时运行一次
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if db := database.GetDatabase(); db != nil {
					if err := db.AutoCleanupRecycleBin(); err != nil {
						log.Printf("Auto cleanup failed: %v", err)
					}
				}
			}
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

	// 检查是否为开发模式（通过环境变量或证书文件存在与否判断）
	certFile := "certs/server.crt"
	keyFile := "certs/server.key"

	var httpServer *http.Server
	var httpsServer *http.Server

	// 检查证书文件是否存在
	_, certErr := os.Stat(certFile)
	_, keyErr := os.Stat(keyFile)

	if os.Getenv("DEV_MODE") == "true" || (certErr != nil || keyErr != nil) {
		// 开发模式：启动HTTP服务器
		httpServer = &http.Server{
			Addr:         ":8080",
			Handler:      srv.Router,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		}

		go func() {
			log.Printf("HTTP Server starting on port 8080 (Development Mode)...")
			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("HTTP Server failed to start: %v", err)
			}
		}()
	} else {
		// 生产模式：启动HTTPS服务器
		httpsServer = &http.Server{
			Addr:         ":8443",
			Handler:      srv.Router,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		}

		go func() {
			log.Printf("HTTPS Server starting on port 8443 (Production Mode)...")
			if err := httpsServer.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
				log.Fatalf("HTTPS Server failed to start: %v", err)
			}
		}()
	}

	// 等待中断信号以优雅关闭服务器
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// 设置关闭超时
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 优雅关闭服务器
	if httpServer != nil {
		log.Println("Shutting down HTTP server...")
		if err := httpServer.Shutdown(ctx); err != nil {
			log.Printf("HTTP Server forced to shutdown: %v", err)
		}
	}

	if httpsServer != nil {
		log.Println("Shutting down HTTPS server...")
		if err := httpsServer.Shutdown(ctx); err != nil {
			log.Printf("HTTPS Server forced to shutdown: %v", err)
		}
	}

	log.Println("Server exited")
}