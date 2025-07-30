package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"secure-file-hub/internal/handler"
	"secure-file-hub/internal/logger"
	"secure-file-hub/internal/server"
)

func main() {
	log.Println("Starting Secure File Hub...")

	// 初始化结构化日志系统
	if err := logger.InitLogger(); err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer func() {
		if l := logger.GetLogger(); l != nil {
			l.Close()
		}
	}()

	// 记录系统启动日志
	if l := logger.GetLogger(); l != nil {
		details := map[string]interface{}{
			"version": "v1.0.0",
			"port":    8443,
			"mode":    "production",
		}
		l.LogError("系统启动", nil, details)
	}

	// 创建服务器实例
	srv := server.New()

	// 注册路由
	handler.RegisterRoutes(srv.Router)

		// 创建HTTPS服务器
	httpsServer := &http.Server{
		Addr:         ":8443",
		Handler:      srv.Router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// 启动HTTPS服务器
	go func() {
		log.Printf("HTTPS Server starting on port 8443...")
		certFile := "certs/server.crt"
		keyFile := "certs/server.key"

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