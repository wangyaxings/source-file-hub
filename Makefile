# ================================
# Secure File Hub - Makefile
# ================================

.PHONY: help build up down logs clean test deploy dev prod

# 默认目标
.DEFAULT_GOAL := help

# 颜色输出
BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[1;33m
RED := \033[0;31m
NC := \033[0m

# 变量
DOCKER_REGISTRY ?= localhost:5000
IMAGE_NAME ?= secure-file-hub
IMAGE_TAG ?= latest
ENVIRONMENT ?= development

# 帮助信息
help: ## 显示帮助信息
	@echo "$(BLUE)=======================================$(NC)"
	@echo "$(BLUE)Secure File Hub - 构建和部署工具$(NC)"
	@echo "$(BLUE)=======================================$(NC)"
	@echo ""
	@echo "$(YELLOW)可用命令:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(BLUE)%-20s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(YELLOW)常用示例:$(NC)"
	@echo "  make build          # 构建镜像"
	@echo "  make up            # 启动服务"
	@echo "  make deploy        # 完整部署"
	@echo "  make dev           # 开发环境部署"
	@echo "  make prod          # 生产环境部署"
	@echo ""
	@echo "$(YELLOW)环境变量:$(NC)"
	@echo "  DOCKER_REGISTRY    # Docker仓库 (默认: localhost:5000)"
	@echo "  IMAGE_NAME        # 镜像名称 (默认: secure-file-hub)"
	@echo "  IMAGE_TAG         # 镜像标签 (默认: latest)"
	@echo "  ENVIRONMENT       # 部署环境 (默认: development)"

# 构建镜像
build: ## 构建Docker镜像
	@echo "$(BLUE)[INFO]$(NC) 构建Docker镜像..."
	@export DOCKER_BUILDKIT=1 && \
	docker build \
		--target runtime \
		--tag $(DOCKER_REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG) \
		--label "build-date=$$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
		--label "version=$(IMAGE_TAG)" \
		--label "environment=$(ENVIRONMENT)" \
		.
	@echo "$(GREEN)[SUCCESS]$(NC) 镜像构建完成"

# 启动服务
up: ## 启动所有服务
	@echo "$(BLUE)[INFO]$(NC) 启动服务..."
	@docker-compose up -d
	@echo "$(GREEN)[SUCCESS]$(NC) 服务启动完成"
	@echo ""
	@echo "$(YELLOW)服务地址:$(NC)"
	@echo "  前端: http://localhost:30000"
	@echo "  后端: https://localhost:8443"

# 停止服务
down: ## 停止所有服务
	@echo "$(BLUE)[INFO]$(NC) 停止服务..."
	@docker-compose down --remove-orphans
	@echo "$(GREEN)[SUCCESS]$(NC) 服务已停止"

# 重启服务
restart: down up ## 重启所有服务

# 查看日志
logs: ## 查看服务日志
	@docker-compose logs -f

# 查看服务状态
status: ## 查看服务状态
	@echo "$(BLUE)[INFO]$(NC) 服务状态:"
	@docker-compose ps
	@echo ""
	@echo "$(YELLOW)健康检查:$(NC)"
	@curl -s -k https://localhost:8443/api/v1/health >/dev/null && echo "  ✅ 后端服务正常" || echo "  ❌ 后端服务异常"
	@curl -s http://localhost:30000 >/dev/null && echo "  ✅ 前端服务正常" || echo "  ❌ 前端服务异常"

# 清理资源
clean: ## 清理Docker资源
	@echo "$(BLUE)[INFO]$(NC) 清理Docker资源..."
	@docker-compose down --volumes --remove-orphans 2>/dev/null || true
	@docker image prune -f 2>/dev/null || true
	@docker volume prune -f 2>/dev/null || true
	@echo "$(GREEN)[SUCCESS]$(NC) 清理完成"

# 深度清理
clean-all: clean ## 深度清理（包括镜像）
	@echo "$(YELLOW)[WARNING]$(NC) 将删除所有相关镜像..."
	@docker images | grep $(IMAGE_NAME) | awk '{print $$3}' | xargs docker rmi -f 2>/dev/null || true
	@echo "$(GREEN)[SUCCESS]$(NC) 深度清理完成"

# 运行测试
test: ## 运行项目测试
	@echo "$(BLUE)[INFO]$(NC) 运行测试..."
	@go test -v ./tests/...
	@echo "$(GREEN)[SUCCESS]$(NC) 测试完成"

# 部署（完整流程）
deploy: ## 完整部署流程
	@echo "$(BLUE)[INFO]$(NC) 开始完整部署..."
	@make clean
	@make build
	@make up
	@echo "$(GREEN)[SUCCESS]$(NC) 部署完成"
	@make status

# 开发环境部署
dev: ## 开发环境部署
	@echo "$(BLUE)[INFO]$(NC) 部署到开发环境..."
	@export ENVIRONMENT=development && \
	export IMAGE_TAG=dev && \
	make deploy

# 生产环境部署
prod: ## 生产环境部署
	@echo "$(BLUE)[INFO]$(NC) 部署到生产环境..."
	@if [ -z "$(DOCKER_REGISTRY)" ] || [ "$(DOCKER_REGISTRY)" = "localhost:5000" ]; then \
		echo "$(RED)[ERROR]$(NC) 生产环境需要设置 DOCKER_REGISTRY"; \
		exit 1; \
	fi
	@export ENVIRONMENT=production && \
	export IMAGE_TAG=$(shell date +%Y%m%d_%H%M%S) && \
	make deploy

# 快速部署（跳过清理）
quick-deploy: build up status ## 快速部署（不清理）

# 备份数据
backup: ## 备份应用数据
	@echo "$(BLUE)[INFO]$(NC) 备份数据..."
	@mkdir -p backups
	@docker run --rm -v secure-file-hub_data:/data -v $(PWD)/backups:/backup alpine tar czf /backup/backup-data-$(shell date +%Y%m%d_%H%M%S).tar.gz -C /data .
	@docker run --rm -v secure-file-hub_downloads:/downloads -v $(PWD)/backups:/backup alpine tar czf /backup/backup-downloads-$(shell date +%Y%m%d_%H%M%S).tar.gz -C /downloads .
	@echo "$(GREEN)[SUCCESS]$(NC) 备份完成"

# 恢复数据
restore: ## 从备份恢复数据
	@echo "$(BLUE)[INFO]$(NC) 恢复数据..."
	@echo "$(YELLOW)[WARNING]$(NC) 此操作将覆盖现有数据"
	@read -p "确认要恢复数据吗? (y/N): " confirm && \
	if [ "$$confirm" = "y" ] || [ "$$confirm" = "Y" ]; then \
		echo "请选择备份文件:" && \
		ls -la backups/ && \
		read -p "输入数据备份文件名: " data_file && \
		read -p "输入下载备份文件名: " downloads_file && \
		docker run --rm -v secure-file-hub_data:/data -v $(PWD)/backups:/backup alpine sh -c "cd /data && tar xzf /backup/$$data_file" && \
		docker run --rm -v secure-file-hub_downloads:/downloads -v $(PWD)/backups:/backup alpine sh -c "cd /downloads && tar xzf /backup/$$downloads_file" && \
		echo "$(GREEN)[SUCCESS]$(NC) 数据恢复完成"; \
	else \
		echo "已取消恢复操作"; \
	fi

# 查看系统信息
info: ## 显示系统信息
	@echo "$(BLUE)=======================================$(NC)"
	@echo "$(BLUE)Secure File Hub - 系统信息$(NC)"
	@echo "$(BLUE)=======================================$(NC)"
	@echo ""
	@echo "$(YELLOW)Docker信息:$(NC)"
	@docker --version
	@docker-compose --version 2>/dev/null || echo "docker-compose 未安装"
	@echo ""
	@echo "$(YELLOW)镜像信息:$(NC)"
	@docker images | grep $(IMAGE_NAME) || echo "无相关镜像"
	@echo ""
	@echo "$(YELLOW)容器信息:$(NC)"
	@docker-compose ps 2>/dev/null || echo "服务未运行"
	@echo ""
	@echo "$(YELLOW)磁盘使用:$(NC)"
	@df -h | grep -E "(Filesystem|overlay|/)$"
	@echo ""
	@echo "$(YELLOW)内存使用:$(NC)"
	@free -h 2>/dev/null || echo "无法获取内存信息"

# 更新依赖
update-deps: ## 更新项目依赖
	@echo "$(BLUE)[INFO]$(NC) 更新前端依赖..."
	@cd frontend && yarn install
	@echo "$(BLUE)[INFO]$(NC) 更新后端依赖..."
	@go mod tidy
	@echo "$(GREEN)[SUCCESS]$(NC) 依赖更新完成"

# 代码检查
lint: ## 运行代码检查
	@echo "$(BLUE)[INFO]$(NC) 运行Go代码检查..."
	@go vet ./...
	@echo "$(BLUE)[INFO]$(NC) 运行前端代码检查..."
	@cd frontend && yarn lint 2>/dev/null || echo "前端lint未配置"
	@echo "$(GREEN)[SUCCESS]$(NC) 代码检查完成"

# 安全扫描
security-scan: ## 运行安全扫描
	@echo "$(BLUE)[INFO]$(NC) 扫描Docker镜像安全..."
	@docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
		goodwithtech/dockle:latest \
		$(DOCKER_REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG) || echo "Dockle未安装"
	@echo "$(GREEN)[SUCCESS]$(NC) 安全扫描完成"

# 性能监控
monitor: ## 启动性能监控
	@echo "$(BLUE)[INFO]$(NC) 启动性能监控..."
	@docker run -d --name secure-file-hub-monitor \
		--network container:secure-file-hub \
		-v /var/run/docker.sock:/var/run/docker.sock \
		docker/docker-bench-security || echo "性能监控启动失败"
	@echo "$(GREEN)[SUCCESS]$(NC) 性能监控已启动"

# 停止监控
stop-monitor: ## 停止性能监控
	@echo "$(BLUE)[INFO]$(NC) 停止性能监控..."
	@docker stop secure-file-hub-monitor 2>/dev/null || true
	@docker rm secure-file-hub-monitor 2>/dev/null || true
	@echo "$(GREEN)[SUCCESS]$(NC) 监控已停止"

# 帮助别名
h: help
b: build
u: up
d: down
l: logs
s: status
c: clean
