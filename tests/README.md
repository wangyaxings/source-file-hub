# Secure File Hub 测试套件

本目录包含了 Secure File Hub 项目的完整测试套件，遵循 Go 项目的最佳实践。

## 📁 目录结构

```
tests/
├── auth/              # 认证模块测试
├── database/          # 数据库模块测试
├── handler/           # 处理器模块测试
├── middleware/        # 中间件模块测试
├── server/            # 服务器模块测试
├── apikey/            # API密钥模块测试
├── authz/             # 授权模块测试
├── logger/            # 日志模块测试
├── helpers/           # 测试辅助工具
├── integration/       # 集成测试
├── run_tests.go       # 测试运行脚本
└── README.md          # 本文档
```

## 🚀 快速开始

### 运行所有测试

```bash
# 运行所有测试
go test ./tests/...

# 运行测试并生成覆盖率报告
go test -cover ./tests/...

# 运行测试并启用竞态检测
go test -race ./tests/...

# 运行测试并显示详细信息
go test -v ./tests/...
```

### 运行特定模块测试

```bash
# 运行认证模块测试
go test ./tests/auth/...

# 运行数据库模块测试
go test ./tests/database/...

# 运行集成测试
go test ./tests/integration/...
```

### 使用测试运行脚本

```bash
# 运行测试并生成完整报告
go run tests/run_tests.go -cover -race -v

# 指定输出目录
go run tests/run_tests.go -cover -output=test-results

# 运行特定包的测试
go run tests/run_tests.go -pkg=./tests/auth/...
```

## 📊 测试覆盖率

### 生成覆盖率报告

```bash
# 生成覆盖率文件
go test -coverprofile=coverage.out ./tests/...

# 生成HTML覆盖率报告
go tool cover -html=coverage.out -o coverage.html

# 查看覆盖率统计
go tool cover -func=coverage.out
```

### 覆盖率目标

- **整体覆盖率**: ≥ 80%
- **核心模块覆盖率**: ≥ 90%
- **关键业务逻辑覆盖率**: ≥ 95%

## 🧪 测试类型

### 1. 单元测试 (Unit Tests)

测试单个函数或方法的功能，使用模拟数据。

**特点:**
- 快速执行
- 独立运行
- 使用测试辅助工具
- 覆盖边界条件

**示例:**
```go
func TestUser_ValidatePassword(t *testing.T) {
    user := &auth.User{Password: "ValidPassword123!"}
    if !user.ValidatePassword() {
        t.Error("Expected valid password to pass validation")
    }
}
```

### 2. 集成测试 (Integration Tests)

测试多个模块之间的交互，使用真实的数据库和文件系统。

**特点:**
- 测试完整工作流
- 使用真实环境
- 验证数据一致性
- 测试错误处理

**示例:**
```go
func TestIntegration_UserRegistrationAndLogin(t *testing.T) {
    // 测试用户注册和登录的完整流程
    // 包括数据库操作、认证、会话管理等
}
```

## 🛠️ 测试辅助工具

### 测试环境设置

```go
// 设置测试环境
config := helpers.SetupTestEnvironment(t)

// 创建测试用户
user := helpers.CreateTestUser(t, "testuser", "password123", "viewer")

// 创建测试API密钥
apiKey := helpers.CreateTestAPIKey(t, user.Username, "test_key", []string{"read"})

// 创建测试文件
filePath := helpers.CreateTestFile(t, config, "test.txt", "content")
```

### 请求创建

```go
// 创建HTTP请求
req := helpers.CreateTestRequest(t, http.MethodGet, "/api/v1/health", nil, nil)

// 创建多部分请求（文件上传）
req := helpers.CreateMultipartRequest(t, "/api/v1/web/upload", "test.txt", "content", nil)

// 添加认证上下文
req = helpers.AddAuthContext(req, authUser)
```

### 响应验证

```go
// 验证成功响应
response := helpers.AssertSuccessResponse(t, rr, http.StatusOK)

// 验证错误响应
helpers.AssertErrorResponse(t, rr, http.StatusBadRequest)

// 验证JSON响应
response := helpers.AssertJSONResponse(t, rr, http.StatusOK)
```

## 📋 测试最佳实践

### 1. 测试命名

- 使用描述性的测试名称
- 遵循 `TestFunction_Scenario_ExpectedResult` 格式
- 包含测试的上下文和预期结果

```go
func TestUser_ValidatePassword_WithValidPassword_ReturnsTrue(t *testing.T) {
    // 测试实现
}
```

### 2. 测试结构

- 使用 `t.Helper()` 标记辅助函数
- 使用 `t.Cleanup()` 进行资源清理
- 使用 `t.Fatalf()` 进行致命错误处理

```go
func TestExample(t *testing.T) {
    t.Helper()
    
    // 设置
    config := setupTest(t)
    t.Cleanup(func() {
        cleanupTest(config)
    })
    
    // 执行
    result := performTest(config)
    
    // 验证
    if result != expected {
        t.Fatalf("Expected %v, got %v", expected, result)
    }
}
```

### 3. 表驱动测试

对于多个测试场景，使用表驱动测试：

```go
func TestUser_ValidatePassword(t *testing.T) {
    tests := []struct {
        name     string
        password string
        expected bool
    }{
        {"ValidPassword", "ValidPassword123!", true},
        {"TooShort", "short", false},
        {"NoUppercase", "nouppercase123!", false},
        {"NoNumbers", "NoNumbers!", false},
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            user := &auth.User{Password: tt.password}
            result := user.ValidatePassword()
            if result != tt.expected {
                t.Errorf("Expected %v, got %v", tt.expected, result)
            }
        })
    }
}
```

### 4. 模拟和存根

- 使用接口进行依赖注入
- 创建模拟对象替代外部依赖
- 使用测试数据库和文件系统

```go
func TestHandler_WithMockDatabase(t *testing.T) {
    // 创建模拟数据库
    mockDB := &MockDatabase{}
    
    // 注入依赖
    handler := NewHandler(mockDB)
    
    // 执行测试
    result := handler.ProcessRequest()
    
    // 验证结果
    assert.Equal(t, expected, result)
}
```

## 🔧 测试配置

### 环境变量

```bash
# 测试数据库路径
export TEST_DB_PATH="/tmp/test.db"

# 测试文件目录
export TEST_UPLOAD_DIR="/tmp/test-uploads"

# 日志级别
export TEST_LOG_LEVEL="debug"
```

### 配置文件

测试使用独立的配置文件，避免影响生产环境：

```json
{
  "server": {
    "port": 8443,
    "host": "localhost"
  },
  "database": {
    "path": "data/test.db"
  },
  "upload": {
    "max_file_size": 10485760,
    "allowed_types": [".txt", ".pdf", ".doc"]
  }
}
```

## 📈 性能测试

### 基准测试

```go
func BenchmarkUser_ValidatePassword(b *testing.B) {
    user := &auth.User{Password: "ValidPassword123!"}
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        user.ValidatePassword()
    }
}
```

### 并发测试

```go
func TestConcurrentUserOperations(t *testing.T) {
    concurrency := 100
    done := make(chan bool, concurrency)
    
    for i := 0; i < concurrency; i++ {
        go func(index int) {
            // 执行并发操作
            performUserOperation(index)
            done <- true
        }(i)
    }
    
    // 等待所有操作完成
    for i := 0; i < concurrency; i++ {
        <-done
    }
}
```

## 🐛 调试测试

### 调试单个测试

```bash
# 运行特定测试
go test -run TestUser_ValidatePassword ./tests/auth/...

# 使用调试器
dlv test ./tests/auth/... -- -test.run TestUser_ValidatePassword
```

### 测试日志

```go
func TestWithLogging(t *testing.T) {
    // 启用测试日志
    t.Logf("Starting test: %s", t.Name())
    
    // 执行测试
    result := performTest()
    
    // 记录结果
    t.Logf("Test result: %v", result)
}
```

## 📚 测试文档

### 测试用例文档

每个测试文件都应该包含：

1. **包说明**: 描述测试的目的和范围
2. **测试用例说明**: 每个测试函数的注释
3. **示例代码**: 展示如何使用被测试的功能
4. **注意事项**: 测试的特殊要求和限制

### 测试报告

测试运行后会生成以下报告：

- **测试结果**: 通过/失败的测试数量
- **覆盖率报告**: HTML格式的覆盖率报告
- **性能报告**: 测试执行时间和内存使用
- **测试摘要**: 测试结果的详细摘要

## 🤝 贡献指南

### 添加新测试

1. 在相应的模块目录中创建测试文件
2. 使用描述性的测试名称
3. 包含必要的测试用例
4. 更新测试文档

### 测试审查

- 确保测试覆盖所有代码路径
- 验证测试的独立性和可重复性
- 检查测试的性能影响
- 确保测试遵循最佳实践

## 📞 支持

如果您在测试过程中遇到问题，请：

1. 查看测试日志和错误信息
2. 检查测试环境配置
3. 参考本文档的最佳实践
4. 联系开发团队获取支持

---

**注意**: 本测试套件遵循 Go 项目的标准测试实践，确保代码质量和系统稳定性。
