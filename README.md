# FileServer

一个使用Go实现的REST API文件服务器，支持配置文件下载功能。

## 功能特性

- ✅ REST API接口
- ✅ 配置文件下载功能
- ✅ 健康检查接口
- ✅ CORS支持
- ✅ 请求日志记录
- ✅ 优雅关闭

## 项目结构

```
FileServer/
├── cmd/server/         # 主程序入口
├── internal/           # 内部包
│   ├── handler/        # HTTP处理器
│   └── server/         # 服务器配置
├── configs/            # 配置文件
├── .gitignore          # Git忽略文件
├── go.mod              # Go模块文件
└── README.md           # 项目说明
```

## 安装和运行

### 前置要求

- Go 1.19 或更高版本

### 安装依赖

```bash
go mod download
```

### 运行服务器

```bash
go run cmd/server/main.go
```

服务器将在 `http://localhost:8080` 启动。

## API接口

### 下载配置文件

```http
GET /api/v1/config/download
```

下载 `config.json` 配置文件。

**响应：**
- 成功：返回配置文件内容，Content-Type: `application/json`
- 失败：返回错误信息的JSON响应

### 健康检查

```http
GET /api/v1/health
```

检查服务状态。

**响应示例：**
```json
{
  "success": true,
  "message": "服务运行正常",
  "data": {
    "status": "healthy",
    "timestamp": "1640995200"
  }
}
```

## 使用示例

### 使用curl下载配置文件

```bash
# 下载配置文件
curl -O -J http://localhost:8080/api/v1/config/download

# 健康检查
curl http://localhost:8080/api/v1/health
```

### 使用浏览器

直接访问 `http://localhost:8080/api/v1/config/download` 即可下载配置文件。

## 配置说明

配置文件位于 `configs/config.json`，包含以下配置项：

- `server`: 服务器配置（主机、端口、超时等）
- `application`: 应用程序信息
- `logging`: 日志配置
- `features`: 功能开关

## 最佳实践

本项目遵循Go项目的最佳实践：

1. **项目结构**: 使用标准的Go项目布局
2. **错误处理**: 完善的错误处理和日志记录
3. **HTTP中间件**: 使用中间件处理CORS和日志
4. **优雅关闭**: 支持优雅关闭服务器
5. **安全性**: 设置适当的HTTP头部
6. **可维护性**: 清晰的代码结构和注释

## 开发

### 构建

```bash
go build -o fileserver cmd/server/main.go
```

### 测试

```bash
go test ./...
```

## 许可证

MIT License