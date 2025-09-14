# API Key 管理页面 "Failed to fetch" 错误排查与解决

## 问题概述

在 API Key 管理页面创建新的 API Key 时，前端出现 `TypeError: Failed to fetch` 错误，导致 API Key 创建功能无法正常工作。始终处于无法跳转到复制apikey页面。主要是通过开启了浏览器的AI助手，对该错误消息进行了分析，使用该分析后的内容，重新处理即最终得到了结果。

## 错误现象

### 前端错误信息
```
Unhandled Runtime Error
TypeError: Failed to fetch

Source
components\admin\api-key-management.tsx (452:45) @ map

Call Stack
map
components\admin\api-key-management.tsx (426:27)
```

### 控制台错误
```
Request failed for /api/v1/web/admin/api-keys: TypeError: Failed to fetch
```

## 问题分析

### 1. 初步排查

通过分析错误信息，`Failed to fetch` 通常表示：
- 网络连接问题
- CORS 策略问题
- 混合内容问题（HTTPS/HTTP）
- 无效的 URL
- 浏览器扩展或防火墙干扰

### 2. 深入调查

#### 2.1 网络连接验证
- ✅ 前端服务器正常运行在 `https://127.0.0.1:30000`
- ✅ 后端服务器正常运行在 `https://localhost:8443`
- ✅ 代理配置正确，将 `/api` 请求转发到后端

#### 2.2 API 端点验证
- ✅ API 端点路径正确：`/api/v1/web/admin/api-keys`
- ✅ 路由注册正确：`RegisterWebAdminRoutes(webAPI)`
- ✅ 权限配置正确：管理员有 `/api/v1/admin/*` 权限

#### 2.3 数据库问题发现
发现数据库中存在格式错误的 API Key 记录：
```sql
-- 错误的 permissions 格式
ak_1757861895160042700|Star|[" read\,\download\,\upload\,\admin\]
```

这些记录包含无效的 JSON 格式，导致后端解析错误：
```
Warning: failed to parse permissions JSON: invalid character ',' in string escape code
```

### 3. 根本原因定位

通过逐步调试发现，问题出现在 `storeTempAPIKey` 函数中的**死锁**：

```go
// 问题代码
func storeTempAPIKey(keyID, key, name, role string) {
    tempKeysMux.Lock()           // 获取锁
    defer tempKeysMux.Unlock()

    tempAPIKeys[keyID] = &TempAPIKey{...}

    // 死锁！在持有锁的情况下调用另一个需要同一把锁的函数
    cleanupExpiredTempKeys()     // 试图再次获取同一个锁
}

func cleanupExpiredTempKeys() {
    tempKeysMux.Lock()           // 死锁发生在这里
    defer tempKeysMux.Unlock()
    // ...
}
```

### 4. 死锁问题发现思路和方法

#### 4.1 排查思路

**从现象到本质的逐步排查：**

1. **前端错误分析** → 网络请求失败
2. **网络层验证** → 服务器可达，代理正常
3. **API 端点验证** → 路由和权限配置正确
4. **数据库问题** → 发现格式错误数据，清理后问题仍存在
5. **后端日志分析** → 发现请求挂起，无响应
6. **代码审查** → 发现潜在的并发问题

#### 4.2 死锁发现方法

**关键发现步骤：**

1. **请求超时现象**
   ```
   - 前端请求长时间无响应
   - 后端日志显示请求到达但无处理完成日志
   - 服务器进程正常，但特定功能挂起
   ```

2. **逐步排除法**
   ```bash
   # 测试 1: 基础 API 调用
   curl -k https://localhost:30000/api/v1/web/admin/api-keys
   # 结果: ✅ 成功 - 排除路由和权限问题

   # 测试 2: 创建 API Key
   curl -k -X POST https://localhost:30000/api/v1/web/admin/api-keys -d '...'
   # 结果: ❌ 超时 - 问题在创建逻辑中
   ```

3. **代码审查重点**
   ```go
   // 重点关注并发相关的代码
   func createAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
       // ... 其他逻辑正常

       // 可疑点 1: 临时存储
       storeTempAPIKey(created.ID, keyValue, req.Name, req.Role)

       // 可疑点 2: 权限创建
       authz.CreateAPIKeyPolicies(created.ID, req.Permissions)
   }
   ```

4. **临时禁用测试**
   ```go
   // 方法 1: 注释掉可疑代码
   // storeTempAPIKey(created.ID, keyValue, req.Name, req.Role)

   // 方法 2: 注释掉权限创建
   // authz.CreateAPIKeyPolicies(created.ID, req.Permissions)

   // 测试结果: 禁用 storeTempAPIKey 后问题消失
   ```

5. **锁使用分析**
   ```go
   // 发现死锁模式
   func storeTempAPIKey(keyID, key, name, role string) {
       tempKeysMux.Lock()           // 获取锁 A
       defer tempKeysMux.Unlock()

       // ... 业务逻辑

       cleanupExpiredTempKeys()     // 调用需要锁 A 的函数
   }

   func cleanupExpiredTempKeys() {
       tempKeysMux.Lock()           // 尝试获取锁 A (已持有)
       defer tempKeysMux.Unlock()   // 死锁！
   }
   ```

#### 4.3 死锁识别技巧

**常见的死锁模式：**

1. **重入锁死锁**
   ```go
   // 错误模式
   func functionA() {
       mutex.Lock()
       defer mutex.Unlock()
       functionB()  // functionB 也需要同一个锁
   }

   func functionB() {
       mutex.Lock()  // 死锁！
       defer mutex.Unlock()
   }
   ```

2. **循环等待死锁**
   ```go
   // 错误模式
   func process1() {
       lockA.Lock()
       lockB.Lock()  // 等待 lockB
   }

   func process2() {
       lockB.Lock()
       lockA.Lock()  // 等待 lockA
   }
   ```

3. **嵌套调用死锁**
   ```go
   // 错误模式
   func outer() {
       mutex.Lock()
       defer mutex.Unlock()
       inner()  // inner 函数内部也需要同一个锁
   }
   ```

#### 4.4 调试工具和方法

**推荐的调试方法：**

1. **日志追踪**
   ```go
   func storeTempAPIKey(keyID, key, name, role string) {
       log.Printf("storeTempAPIKey: 尝试获取锁")
       tempKeysMux.Lock()
       log.Printf("storeTempAPIKey: 锁获取成功")
       defer tempKeysMux.Unlock()

       // ... 业务逻辑

       log.Printf("storeTempAPIKey: 调用 cleanupExpiredTempKeys")
       cleanupExpiredTempKeys()  // 如果这里挂起，说明死锁
       log.Printf("storeTempAPIKey: cleanupExpiredTempKeys 完成")
   }
   ```

2. **超时测试**
   ```go
   // 添加超时机制来检测死锁
   func testWithTimeout() {
       done := make(chan bool)
       go func() {
           // 执行可能死锁的操作
           createAPIKey()
           done <- true
       }()

       select {
       case <-done:
           fmt.Println("操作完成")
       case <-time.After(5 * time.Second):
           fmt.Println("操作超时，可能存在死锁")
       }
   }
   ```

3. **Go 运行时检测**
   ```bash
   # 使用 Go 的竞争检测器
   go run -race cmd/server/main.go

   # 使用 pprof 分析
   go tool pprof http://localhost:6060/debug/pprof/profile
   ```

4. **代码审查检查清单**
   ```
   □ 检查所有 mutex.Lock() 调用
   □ 确认 defer mutex.Unlock() 的存在
   □ 检查锁的获取顺序是否一致
   □ 避免在持有锁时调用其他可能获取锁的函数
   □ 使用读写锁时注意升级/降级问题
   □ 检查 channel 操作是否可能导致死锁
   ```

#### 4.5 预防死锁的最佳实践

1. **锁的获取顺序**
   ```go
   // 好的做法：固定锁的获取顺序
   func process() {
       lockA.Lock()
       defer lockA.Unlock()

       lockB.Lock()
       defer lockB.Unlock()

       // 业务逻辑
   }
   ```

2. **避免嵌套锁调用**
   ```go
   // 好的做法：内联逻辑避免嵌套调用
   func storeTempAPIKey(keyID, key, name, role string) {
       tempKeysMux.Lock()
       defer tempKeysMux.Unlock()

       // 直接内联清理逻辑，避免调用其他需要锁的函数
       now := time.Now()
       for keyID, tempKey := range tempAPIKeys {
           if now.Sub(tempKey.CreatedAt) > 10*time.Minute {
               delete(tempAPIKeys, keyID)
           }
       }
   }
   ```

3. **使用超时机制**
   ```go
   // 好的做法：使用带超时的锁
   func acquireLockWithTimeout(mutex *sync.Mutex, timeout time.Duration) bool {
       done := make(chan struct{})
       go func() {
           mutex.Lock()
           close(done)
       }()

       select {
       case <-done:
           return true
       case <-time.After(timeout):
           return false
       }
   }
   ```

## 解决方案

### 1. 修复死锁问题

将 `cleanupExpiredTempKeys` 的逻辑内联到 `storeTempAPIKey` 中，避免重复获取锁：

```go
// 修复后的代码
func storeTempAPIKey(keyID, key, name, role string) {
    tempKeysMux.Lock()
    defer tempKeysMux.Unlock()

    tempAPIKeys[keyID] = &TempAPIKey{
        Key:       key,
        Name:      name,
        Role:      role,
        CreatedAt: time.Now(),
    }

    // 内联清理逻辑，避免死锁
    now := time.Now()
    for keyID, tempKey := range tempAPIKeys {
        // Remove keys older than 10 minutes
        if now.Sub(tempKey.CreatedAt) > 10*time.Minute {
            delete(tempAPIKeys, keyID)
        }
    }
}
```

### 2. 清理数据库问题数据

删除数据库中 permissions 字段格式错误的记录：

```sql
-- 删除有问题的 API Key 记录
DELETE FROM api_keys WHERE permissions LIKE '%read%';
```

### 3. 增强前端错误处理

在 API 客户端中添加更详细的错误日志：

```typescript
// frontend/lib/api.ts
} catch (error) {
    console.error(`Request failed for ${url}:`, error)
    console.error('Error type:', typeof error)
    console.error('Error message:', error.message)
    console.error('Error stack:', error.stack)

    if (error instanceof TypeError && error.message.includes('fetch')) {
        throw new Error('Network connection failed, please check server status')
    }

    throw error
}
```

### 4. 修复前端空值检查

在 API Key 管理组件中添加 permissions 字段的空值检查：

```typescript
// frontend/components/admin/api-key-management.tsx
// 修复前
{key.permissions.map((perm) => (...))}

// 修复后
{(key.permissions || []).map((perm) => (...))}
```

## 验证结果

### 测试用例

创建了一个完整的测试脚本来验证修复效果：

```python
def test_complete_api_key_creation():
    # 1. 登录验证
    # 2. 创建 API Key 测试
    # 3. 验证响应格式
    # 4. 检查权限配置
```

### 测试结果

```
=== Complete API Key Creation Test ===
1. Logging in...
   Login Status: 307
   ✅ Login successful!

2. Testing complete API key creation...
   Response Status: 201
   ✅ Complete API key creation successful!

   Created API Key ID: ak_1757873058372848700
   API Key Name: Complete Test Key
   API Key Role: admin
   API Key Permissions: ['read', 'download', 'upload', 'admin']
```

## 技术细节

### API 端点信息

- **URL**: `POST /api/v1/web/admin/api-keys`
- **认证**: Session cookie (Authboss)
- **权限**: 需要管理员角色

### 请求格式

```json
{
  "name": "API Key Name",
  "description": "Optional description",
  "role": "admin|read_only|download_only|upload_only|read_upload",
  "permissions": ["read", "download", "upload", "admin"]
}
```

### 响应格式

```json
{
  "success": true,
  "message": "API key created successfully. Please save this key securely - it will not be shown again.",
  "data": {
    "api_key": {
      "id": "ak_1757873058372848700",
      "name": "Complete Test Key",
      "key": "sk_806f812566d1e23e7473f3b8c11eabe07d89d37166bd86babd4655778f0348d6",
      "role": "admin",
      "permissions": ["read", "download", "upload", "admin"],
      "status": "active",
      "usageCount": 0,
      "createdAt": "2025-09-15T02:04:18.3728487+08:00",
      "updatedAt": "2025-09-15T02:04:18.3728487+08:00"
    },
    "download_url": "/api/v1/web/admin/api-keys/ak_1757873058372848700/download"
  }
}
```

## 预防措施

### 1. 代码审查要点

- 检查锁的使用，避免在持有锁的情况下调用其他需要同一把锁的函数
- 确保数据库字段格式的一致性
- 添加适当的错误处理和日志记录

### 2. 测试建议

- 定期测试 API Key 创建功能
- 监控服务器日志中的错误信息
- 验证数据库数据的完整性

### 3. 监控指标

- API Key 创建成功率
- 服务器响应时间
- 错误日志频率

## 相关文件

### 后端文件
- `internal/handler/admin.go` - API Key 处理逻辑
- `internal/authz/casbin.go` - 权限管理
- `internal/database/database.go` - 数据库操作

### 前端文件
- `frontend/components/admin/api-key-management.tsx` - API Key 管理组件
- `frontend/lib/api.ts` - API 客户端
- `frontend/server.js` - 前端服务器配置

### 配置文件
- `configs/casbin_model.conf` - Casbin 权限模型
- `docker-compose.yml` - 服务配置

## 总结

这个问题的根本原因是后端代码中的死锁问题，导致 API Key 创建请求挂起。通过修复死锁、清理数据库问题数据、增强错误处理等措施，成功解决了 "Failed to fetch" 错误。

### 关键教训

1. **死锁是严重的并发问题**，需要仔细检查锁的使用
2. **数据完整性很重要**，格式错误的数据会导致解析失败
3. **详细的错误日志**有助于快速定位问题
4. **渐进式调试**是解决复杂问题的有效方法
5. **死锁发现需要系统性方法**，从现象到本质逐步排查

### 死锁排查方法论

**本次问题解决的核心价值在于建立了一套完整的死锁排查方法论：**

1. **现象观察** → 请求超时、无响应
2. **逐步排除** → 网络、路由、权限、数据库
3. **代码审查** → 重点关注并发相关代码
4. **临时禁用** → 通过注释代码定位问题函数
5. **锁分析** → 识别重入锁死锁模式
6. **工具辅助** → 日志追踪、超时测试、竞争检测器

**这套方法不仅解决了当前问题，更为今后类似问题的排查提供了可复制的流程。**

### 死锁发现的核心思路

**从本次问题中总结的死锁发现核心思路：**

#### 1. 从"症状"到"病因"的思维链
```
前端报错 "Failed to fetch"
    ↓
网络请求超时/无响应
    ↓
后端请求处理挂起
    ↓
特定功能代码执行阻塞
    ↓
并发控制机制问题
    ↓
锁的使用不当导致死锁
```

#### 2. 关键判断点
- **请求是否到达后端？** → 检查服务器日志
- **请求是否开始处理？** → 检查处理函数入口日志
- **请求是否完成处理？** → 检查处理函数出口日志
- **哪个步骤卡住了？** → 通过日志定位具体位置

#### 3. 死锁的"指纹"特征
- **请求超时**：前端等待响应超时
- **进程正常**：服务器进程仍在运行
- **日志中断**：处理日志在某个点停止
- **功能特定**：只有特定功能受影响
- **可重现**：问题可以稳定重现

#### 4. 排查的"排除法"策略
```
排除网络问题 → 排除路由问题 → 排除权限问题 →
排除数据库问题 → 排除业务逻辑问题 → 定位并发问题
```

#### 5. 代码审查的"并发敏感点"
- **锁的获取和释放**
- **函数调用链中的锁依赖**
- **临时存储和清理逻辑**
- **权限创建和验证逻辑**
- **数据库事务处理**

**这套思路可以应用到任何类似的并发问题排查中。**

### 预防措施总结

- **代码审查**：重点关注锁的使用模式
- **测试覆盖**：包含并发场景的测试用例
- **监控告警**：设置请求超时和死锁检测
- **最佳实践**：遵循锁使用的最佳实践
- **工具使用**：定期使用竞争检测器检查代码

---

*文档创建时间：2025-09-15*
*问题解决时间：2025-09-15*
*状态：已解决*
