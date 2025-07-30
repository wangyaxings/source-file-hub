package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"fileserver/internal/handler"
	"fileserver/internal/server"
)

func main() {
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

	// 创建HTTP重定向服务器（可选）
	httpRedirectServer := &http.Server{
		Addr: ":8080",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			httpsURL := "https://" + r.Host + ":8443" + r.RequestURI
			http.Redirect(w, r, httpsURL, http.StatusMovedPermanently)
		}),
	}

	// 启动HTTP重定向服务器
	go func() {
		log.Printf("HTTP Redirect Server starting on port 8080 (redirects to HTTPS)...")
		if err := httpRedirectServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP Redirect Server error: %v", err)
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

	log.Println("Shutting down HTTP redirect server...")
	if err := httpRedirectServer.Shutdown(ctx); err != nil {
		log.Printf("HTTP Redirect Server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
}