# Secure File Hub 项目设计文档

## 1. 项目概述

### 1.1 项目简介
Secure File Hub 是一个基于 Go + Next.js 的企业级安全文件管理系统，提供完整的文件上传下载、用户管理、权限控制和API管理功能。

### 1.2 核心特性
- **安全认证**：JWT Token + TOTP 2FA 双因子认证
- **权限控制**：基于 Casbin 的 RBAC 权限管理
- **文件管理**：支持版本控制、回收站、批量操作
- **用户管理**：GitLab 风格的用户管理界面
- **API管理**：完整的 RESTful API 和密钥管理
- **监控分析**：详细的访问日志和使用分析

### 1.3 技术栈
- **后端**：Go 1.23 + Gorilla Mux + SQLite + Casbin
- **前端**：Next.js 14 + React 18 + TypeScript + Tailwind CSS  
- **认证**：JWT + TOTP (Google Authenticator 兼容)
- **部署**：Docker + Docker Compose

## 2. 系统架构

### 2.1 整体架构图

```mermaid
graph TB
    subgraph "客户端层"
        A[Web 前端<br/>Next.js] 
        B[移动端/API客户端]
        C[第三方应用]
    end
    
    subgraph "网络层"
        D[HTTPS/TLS 加密]
        E[反向代理<br/>Nginx (可选)]
    end
    
    subgraph "应用层"
        F[Go HTTP Server<br/>Gorilla Mux]
        G[中间件层<br/>认证/授权/日志]
        H[业务逻辑层<br/>Handler Services]
    end
    
    subgraph "数据层"
        I[SQLite 数据库<br/>用户/文件/日志]
        J[文件存储<br/>downloads 目录]
        K[配置存储<br/>configs 目录]
    end
    
    A --> D
    B --> D
    C --> D
    D --> E
    E --> F
    F --> G
    G --> H
    H --> I
    H --> J
    H --> K
```

### 2.2 模块架构图

```mermaid
graph LR
    subgraph "前端模块"
        A1[登录注册页面]
        A2[文件管理界面]
        A3[用户管理界面]
        A4[API密钥管理]
        A5[日志分析界面]
        A6[2FA设置页面]
    end
    
    subgraph "后端核心模块"
        B1[认证模块<br/>auth/]
        B2[文件处理模块<br/>handler/]
        B3[用户管理模块<br/>admin/]
        B4[中间件模块<br/>middleware/]
        B5[数据库模块<br/>database/]
        B6[日志模块<br/>logger/]
    end
    
    A1 --> B1
    A2 --> B2
    A3 --> B3
    A4 --> B3
    A5 --> B6
    A6 --> B1
    
    B1 --> B5
    B2 --> B5
    B3 --> B5
    B4 --> B5
    B6 --> B5
```

## 3. 数据库设计

### 3.1 数据库表结构

```mermaid
erDiagram
    users ||--o{ user_roles : has
    users ||--o{ api_keys : owns
    users ||--o{ files : uploads
    users ||--o{ api_usage_logs : generates
    users ||--o{ admin_logs : performs
    
    users {
        string username PK
        string email
        string password_hash
        string role
        boolean twofa_enabled
        string totp_secret
        datetime created_at
        datetime updated_at
        datetime last_login_at
    }
    
    user_roles {
        int id PK
        string user_id FK
        string role
        string permissions_json
        int quota_daily
        int quota_monthly
        string status
        datetime created_at
        datetime updated_at
    }
    
    api_keys {
        string id PK
        string name
        string key_hash
        string user_id FK
        string permissions_json
        datetime expires_at
        datetime created_at
        datetime last_used
        boolean active
    }
    
    files {
        string id PK
        string original_name
        string versioned_name
        string file_path
        string file_type
        int size
        string description
        string uploader FK
        datetime upload_time
        int version
        boolean is_latest
        string checksum
        boolean file_exists
    }
    
    api_usage_logs {
        int id PK
        string api_key_id FK
        string user_id FK
        string endpoint
        string method
        string file_id
        string file_path
        string ip_address
        string user_agent
        int status_code
        int response_size
        int response_time_ms
        string error_message
        datetime request_time
        datetime created_at
    }
    
    admin_logs {
        int id PK
        string actor FK
        string target_user
        string action
        string details_json
        datetime created_at
    }
```

## 4. 用户认证流程

### 4.1 登录认证时序图

```mermaid
sequenceDiagram
    participant U as 用户
    participant F as 前端
    participant A as 认证服务
    participant D as 数据库
    participant T as TOTP服务
    
    U->>F: 输入用户名密码
    F->>A: POST /api/v1/web/auth/login
    A->>D: 验证用户凭据
    D-->>A: 返回用户信息
    
    alt 用户启用2FA
        A-->>F: 返回需要2FA验证
        F-->>U: 显示OTP输入框
        U->>F: 输入OTP码
        F->>A: POST /api/v1/web/auth/login (带OTP)
        A->>T: 验证OTP码
        T-->>A: 验证结果
    end
    
    alt 认证成功
        A->>A: 生成JWT Token
        A->>D: 更新最后登录时间
        A-->>F: 返回Token和用户信息
        F->>F: 存储Token到LocalStorage
        F-->>U: 跳转到主页面
    else 认证失败
        A-->>F: 返回错误信息
        F-->>U: 显示错误提示
    end
```

### 4.2 2FA设置流程图

```mermaid
flowchart TD
    A[用户进入2FA设置页面] --> B{检查当前2FA状态}
    B -->|未启用| C[生成TOTP密钥]
    B -->|已启用| M[显示禁用选项]
    
    C --> D[显示QR码和密钥]
    D --> E[用户扫描QR码]
    E --> F[用户输入验证码]
    F --> G{验证码正确?}
    
    G -->|是| H[启用2FA]
    G -->|否| I[显示错误提示]
    I --> F
    
    H --> J[保存TOTP密钥到数据库]
    J --> K[显示备用恢复码]
    K --> L[2FA启用完成]
    
    M --> N[用户确认禁用]
    N --> O[验证当前密码]
    O --> P{密码正确?}
    P -->|是| Q[禁用2FA]
    P -->|否| R[显示错误提示]
    Q --> S[清除TOTP密钥]
    S --> T[2FA禁用完成]
```

## 5. 文件管理流程

### 5.1 文件上传流程图

```mermaid
flowchart TD
    A[用户选择文件] --> B[前端验证文件]
    B --> C{文件格式正确?}
    C -->|否| D[显示格式错误]
    C -->|是| E[检查用户权限]
    
    E --> F{有上传权限?}
    F -->|否| G[显示权限错误]
    F -->|是| H[创建FormData]
    
    H --> I[POST /api/v1/web/upload]
    I --> J[服务器接收文件]
    J --> K[验证API权限]
    K --> L[检查文件大小]
    L --> M{大小合规?}
    
    M -->|否| N[返回大小错误]
    M -->|是| O[生成文件ID和路径]
    O --> P[保存文件到磁盘]
    P --> Q[计算文件校验和]
    Q --> R[保存文件记录到数据库]
    R --> S[返回上传成功]
    S --> T[前端更新文件列表]
```

### 5.2 文件下载时序图

```mermaid
sequenceDiagram
    participant U as 用户
    participant F as 前端
    participant A as API服务
    participant Auth as 认证中间件
    participant H as 文件处理器
    participant FS as 文件系统
    participant D as 数据库
    
    U->>F: 点击下载文件
    F->>A: GET /api/v1/web/files/{id}/download
    Note over F,A: 请求头包含 Authorization: Bearer <token>
    
    A->>Auth: 验证Token
    Auth->>D: 查询用户权限
    D-->>Auth: 返回权限信息
    Auth-->>A: 权限验证通过
    
    A->>H: 处理下载请求
    H->>D: 查询文件信息
    D-->>H: 返回文件元数据
    
    H->>H: 检查下载权限
    H->>FS: 读取文件内容
    FS-->>H: 返回文件数据
    
    H->>D: 记录下载日志
    H-->>A: 返回文件流
    A-->>F: 返回文件内容
    F-->>U: 触发文件下载
```

## 6. 用户管理流程

### 6.1 用户注册审批流程图

```mermaid
flowchart TD
    A[用户提交注册申请] --> B[POST /api/v1/web/auth/register]
    B --> C[验证注册信息]
    C --> D{信息有效?}
    
    D -->|否| E[返回验证错误]
    D -->|是| F[创建用户记录]
    F --> G[设置用户状态为 pending]
    G --> H[发送注册成功响应]
    
    H --> I[管理员登录管理界面]
    I --> J[查看待审批用户列表]
    J --> K[管理员点击 Approve]
    K --> L[POST /api/v1/web/admin/users/{username}/approve]
    
    L --> M[更新用户状态为 active]
    M --> N[记录管理员操作日志]
    N --> O[用户可正常登录]
    
    J --> P[管理员点击 Suspend]
    P --> Q[POST /api/v1/web/admin/users/{username}/suspend]
    Q --> R[更新用户状态为 suspended]
    R --> S[用户被禁止登录]
```

### 6.2 用户角色权限管理

```mermaid
graph TB
    subgraph "权限层级"
        A[Administrator 管理员]
        B[Viewer 查看者]
    end
    
    subgraph "Administrator 权限"
        A1[用户管理]
        A2[文件上传/下载/删除]
        A3[API密钥管理]
        A4[系统配置]
        A5[日志查看]
        A6[所有API访问]
    end
    
    subgraph "Viewer 权限"
        B1[文件查看/下载]
        B2[个人资料管理]
        B3[只读API访问]
    end
    
    A --> A1
    A --> A2
    A --> A3
    A --> A4
    A --> A5
    A --> A6
    
    B --> B1
    B --> B2
    B --> B3
```

## 7. API管理流程

### 7.1 API密钥创建流程图

```mermaid
flowchart TD
    A[管理员进入API管理页面] --> B[点击创建新密钥]
    B --> C[填写密钥信息]
    C --> D[选择权限范围]
    D --> E[设置过期时间]
    E --> F[POST /api/v1/admin/api-keys]
    
    F --> G[验证管理员权限]
    G --> H{权限验证通过?}
    H -->|否| I[返回权限错误]
    H -->|是| J[生成随机密钥]
    
    J --> K[哈希存储密钥]
    K --> L[保存到数据库]
    L --> M[返回完整密钥给前端]
    M --> N[前端显示密钥]
    N --> O[提示用户保存密钥]
    
    O --> P[用户复制密钥]
    P --> Q[关闭对话框后密钥不再显示]
```

### 7.2 API调用监控流程

```mermaid
sequenceDiagram
    participant C as 客户端
    participant M as 中间件
    participant A as API处理器
    participant L as 日志服务
    participant D as 数据库
    
    C->>M: API请求 + API Key
    M->>M: 记录请求开始时间
    M->>D: 验证API Key
    D-->>M: 返回Key信息和权限
    
    alt API Key有效
        M->>A: 转发请求到处理器
        A->>A: 处理业务逻辑
        A-->>M: 返回处理结果
        M->>M: 计算响应时间
        M->>L: 记录成功日志
    else API Key无效
        M->>M: 计算响应时间
        M->>L: 记录失败日志
        M-->>C: 返回认证错误
    end
    
    L->>D: 异步写入使用日志
    M-->>C: 返回最终响应
```

## 8. 系统监控与日志

### 8.1 日志记录架构

```mermaid
graph TB
    subgraph "日志来源"
        A[HTTP请求日志]
        B[认证操作日志]
        C[文件操作日志]
        D[管理员操作日志]
        E[API使用日志]
        F[系统错误日志]
    end
    
    subgraph "日志处理"
        G[结构化日志模块]
        H[日志聚合器]
        I[日志过滤器]
    end
    
    subgraph "存储层"
        J[SQLite 数据库]
        K[文件日志]
    end
    
    subgraph "分析展示"
        L[使用统计分析]
        M[错误率分析]
        N[性能监控]
        O[用户行为分析]
    end
    
    A --> G
    B --> G
    C --> G
    D --> G
    E --> G
    F --> G
    
    G --> H
    H --> I
    I --> J
    I --> K
    
    J --> L
    J --> M
    J --> N
    J --> O
```

### 8.2 系统健康检查流程

```mermaid
flowchart TD
    A[健康检查请求] --> B[GET /api/v1/health]
    B --> C[检查数据库连接]
    C --> D{数据库可用?}
    
    D -->|否| E[返回数据库错误]
    D -->|是| F[检查文件系统]
    F --> G{存储可写?}
    
    G -->|否| H[返回存储错误]
    G -->|是| I[检查内存使用]
    I --> J[检查CPU使用率]
    J --> K[汇总系统状态]
    K --> L[返回健康状态]
```

## 9. 部署架构

### 9.1 Docker部署架构

```mermaid
graph TB
    subgraph "Docker 容器"
        A[fileserver-app 容器]
        subgraph "应用服务"
            B[Go 后端服务<br/>端口 8443]
            C[Next.js 前端服务<br/>端口 30000]
        end
    end
    
    subgraph "数据卷挂载"
        D[data/ - 数据库文件]
        E[downloads/ - 用户文件]
        F[configs/ - 配置文件]
        G[certs/ - SSL证书]
        H[logs/ - 日志文件]
    end
    
    subgraph "网络端口"
        I[8443:8443 - HTTPS API]
        J[30000:30000 - HTTP Web界面]
    end
    
    A --> B
    A --> C
    A --> D
    A --> E
    A --> F
    A --> G
    A --> H
    A --> I
    A --> J
```

### 9.2 生产环境部署流程

```mermaid
flowchart TD
    A[拉取Docker镜像] --> B[创建目录结构]
    B --> C[生成SSL证书]
    C --> D[配置config.json]
    D --> E[启动Docker Compose]
    E --> F[等待服务启动]
    F --> G[健康检查]
    G --> H{服务正常?}
    
    H -->|否| I[查看日志排错]
    H -->|是| J[配置反向代理]
    I --> F
    
    J --> K[设置防火墙规则]
    K --> L[配置定时备份]
    L --> M[监控设置]
    M --> N[部署完成]
```

## 10. 安全设计

### 10.1 安全防护体系

```mermaid
graph TB
    subgraph "网络安全"
        A[HTTPS/TLS 加密]
        B[自签名证书]
        C[端口访问控制]
    end
    
    subgraph "认证安全"
        D[JWT Token 认证]
        E[TOTP 2FA 双因子]
        F[密码BCrypt哈希]
        G[Token过期管理]
    end
    
    subgraph "授权安全"
        H[Casbin RBAC权限]
        I[API密钥权限控制]
        J[路径访问控制]
        K[文件类型白名单]
    end
    
    subgraph "数据安全"
        L[SQLite 数据库]
        M[文件路径验证]
        N[防路径遍历攻击]
        O[输入验证清理]
    end
    
    subgraph "审计安全"
        P[详细访问日志]
        Q[操作审计记录]
        R[异常行为监控]
    end
```

### 10.2 权限控制矩阵

| 功能模块 | Administrator | Viewer | 匿名用户 |
|---------|---------------|--------|----------|
| 用户注册 | ✅ | ✅ | ✅ |
| 用户登录 | ✅ | ✅ | ❌ |
| 文件上传 | ✅ | ❌ | ❌ |
| 文件下载 | ✅ | ✅ | ❌ |
| 文件删除 | ✅ | ❌ | ❌ |
| 用户管理 | ✅ | ❌ | ❌ |
| API密钥管理 | ✅ | ❌ | ❌ |
| 系统配置 | ✅ | ❌ | ❌ |
| 日志查看 | ✅ | ❌ | ❌ |
| 健康检查 | ✅ | ✅ | ✅ |

## 11. 接口设计

### 11.1 RESTful API 概览

| 模块 | 端点 | 方法 | 权限要求 | 描述 |
|------|------|------|----------|------|
| **认证模块** | | | | |
| | `/api/v1/web/auth/register` | POST | 公开 | 用户注册 |
| | `/api/v1/web/auth/login` | POST | 公开 | 用户登录 |
| | `/api/v1/web/auth/logout` | POST | 已认证 | 用户登出 |
| | `/api/v1/web/auth/2fa/setup` | POST | 已认证 | 设置2FA |
| | `/api/v1/web/auth/2fa/enable` | POST | 已认证 | 启用2FA |
| | `/api/v1/web/auth/2fa/disable` | POST | 已认证 | 禁用2FA |
| **文件模块** | | | | |
| | `/api/v1/web/files/list` | GET | 已认证 | 文件列表 |
| | `/api/v1/web/files/{id}/download` | GET | 已认证 | 文件下载 |
| | `/api/v1/web/upload` | POST | upload权限 | 文件上传 |
| | `/api/v1/web/files/{id}/delete` | POST | admin权限 | 删除文件 |
| **管理模块** | | | | |
| | `/api/v1/web/admin/users` | GET | admin权限 | 用户列表 |
| | `/api/v1/web/admin/users/{username}` | PATCH | admin权限 | 更新用户 |
| | `/api/v1/web/admin/users/{username}/approve` | POST | admin权限 | 批准用户 |
| | `/api/v1/web/admin/users/{username}/suspend` | POST | admin权限 | 冻结用户 |
| **API密钥** | | | | |
| | `/api/v1/admin/api-keys` | GET | admin权限 | 密钥列表 |
| | `/api/v1/admin/api-keys` | POST | admin权限 | 创建密钥 |
| | `/api/v1/admin/api-keys/{id}` | DELETE | admin权限 | 删除密钥 |

## 12. 性能优化

### 12.1 缓存策略

```mermaid
graph TB
    subgraph "前端缓存"
        A[浏览器缓存]
        B[LocalStorage Token]
        C[组件状态缓存]
    end
    
    subgraph "后端缓存"
        D[内存Token存储]
        E[文件元数据缓存]
        F[权限验证缓存]
    end
    
    subgraph "数据库优化"
        G[SQLite索引]
        H[查询优化]
        I[连接池管理]
    end
    
    subgraph "文件存储优化"
        J[文件压缩]
        K[增量备份]
        L[清理策略]
    end
```

### 12.2 监控指标

- **性能指标**：响应时间、吞吐量、错误率
- **资源指标**：CPU使用率、内存使用、磁盘空间
- **业务指标**：用户活跃度、文件上传下载量、API调用频率
- **安全指标**：认证失败次数、异常访问模式、权限违规尝试

---

## 结论

本设计文档详细描述了 Secure File Hub 项目的整体架构、核心流程和技术实现。项目采用现代化的微服务架构，注重安全性和可扩展性，为企业级文件管理提供了完整的解决方案。

通过清晰的模块划分、完善的权限控制和详细的日志审计，系统能够满足企业对文件管理安全性、可靠性和可管理性的要求。