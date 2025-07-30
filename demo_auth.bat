@echo off
:: FileServer 认证功能演示脚本 (Windows版本)
:: 
:: 这个脚本演示了完整的认证流程：
:: 1. 获取默认用户列表
:: 2. 用户登录获取token
:: 3. 使用token访问受保护的接口
:: 4. 用户登出

echo 🚀 FileServer 认证功能演示
echo ========================================

set BASE_URL=http://localhost:8080/api/v1

:: 检查服务器是否运行
echo 🔍 检查服务器状态...
curl -s "%BASE_URL%/health" >nul 2>&1
if errorlevel 1 (
    echo ❌ 服务器未运行，请先启动服务器：
    echo    go run cmd/server/main.go
    pause
    exit /b 1
)
echo ✅ 服务器运行正常
echo.

:: 1. 获取默认用户列表
echo 👥 获取默认测试用户...
curl -s "%BASE_URL%/auth/users"
echo.
echo.

:: 2. 用户登录
echo 🔐 用户登录 ^(demo/admin^)...
curl -s -X POST "%BASE_URL%/auth/login" ^
    -H "Content-Type: application/json" ^
    -d "{\"tenant_id\": \"demo\", \"username\": \"admin\", \"password\": \"admin123\"}" > login_response.tmp

type login_response.tmp
echo.

:: 注意：Windows批处理脚本难以解析JSON，这里提供一个简化的演示
echo.
echo ✅ 请复制上面返回的token，手动测试以下命令：
echo.
echo 📁 下载配置文件：
echo curl -H "Authorization: Bearer YOUR_TOKEN_HERE" %BASE_URL%/config/download
echo.
echo 👋 用户登出：
echo curl -X POST -H "Authorization: Bearer YOUR_TOKEN_HERE" %BASE_URL%/auth/logout
echo.

:: 清理临时文件
del login_response.tmp >nul 2>&1

echo 🎉 演示完成！
echo.
echo 💡 提示：
echo - 默认用户: demo/admin ^(密码: admin123^)
echo - Token有效期: 24小时
echo - 所有配置文件下载都需要认证
echo - 健康检查接口无需认证
echo.
pause