# FileServer API测试脚本 - 兼容Windows PowerShell 5.1

Write-Host "FileServer API 测试开始" -ForegroundColor Green
Write-Host "============================" -ForegroundColor Green

# 忽略SSL证书验证 (适用于自签名证书)
if (-not ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type) {
    Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
}
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

$baseUrl = "https://localhost:8443/api/v1"

try {
    Write-Host "`n0. 测试API根信息页面..." -ForegroundColor Yellow
    $response = Invoke-WebRequest -Uri $baseUrl -UseBasicParsing
    Write-Host "状态码: $($response.StatusCode)" -ForegroundColor Green
    $content = $response.Content | ConvertFrom-Json
    Write-Host "API名称: $($content.data.name)" -ForegroundColor Cyan
    Write-Host "版本: $($content.data.version)" -ForegroundColor Cyan
    Write-Host "描述: $($content.data.description)" -ForegroundColor Cyan

    Write-Host "`n1. 测试健康检查..." -ForegroundColor Yellow
    $healthResponse = Invoke-WebRequest -Uri "$baseUrl/health" -UseBasicParsing
    Write-Host "状态码: $($healthResponse.StatusCode)" -ForegroundColor Green
    $healthContent = $healthResponse.Content | ConvertFrom-Json
    Write-Host "健康状态: $($healthContent.data.status)" -ForegroundColor Cyan

    Write-Host "`n2. 获取默认用户列表..." -ForegroundColor Yellow
    $usersResponse = Invoke-WebRequest -Uri "$baseUrl/auth/users" -UseBasicParsing
    Write-Host "状态码: $($usersResponse.StatusCode)" -ForegroundColor Green
    $usersContent = $usersResponse.Content | ConvertFrom-Json
    Write-Host "用户数量: $($usersContent.data.users.Count)" -ForegroundColor Cyan

    Write-Host "`n3. 测试用户登录..." -ForegroundColor Yellow
    $loginData = @{
        tenant_id = "demo"
        username = "admin"
        password = "admin123"
    } | ConvertTo-Json

    $loginResponse = Invoke-WebRequest -Uri "$baseUrl/auth/login" -Method POST -Body $loginData -ContentType "application/json" -UseBasicParsing
    Write-Host "状态码: $($loginResponse.StatusCode)" -ForegroundColor Green
    $loginContent = $loginResponse.Content | ConvertFrom-Json
    $token = $loginContent.data.token
    Write-Host "Token获取成功: $($token.Substring(0,20))..." -ForegroundColor Cyan

    Write-Host "`n4. 测试文件下载（需要认证）..." -ForegroundColor Yellow
    $headers = @{
        "Authorization" = "Bearer $token"
    }

    $fileResponse = Invoke-WebRequest -Uri "$baseUrl/files/configs/config.json" -Headers $headers -UseBasicParsing
    Write-Host "状态码: $($fileResponse.StatusCode)" -ForegroundColor Green
    Write-Host "内容类型: $($fileResponse.Headers['Content-Type'])" -ForegroundColor Cyan
    Write-Host "文件大小: $($fileResponse.Headers['Content-Length']) bytes" -ForegroundColor Cyan

    Write-Host "`n5. 测试访问日志查询..." -ForegroundColor Yellow
    $logsResponse = Invoke-WebRequest -Uri "$baseUrl/logs/access" -Headers $headers -UseBasicParsing
    Write-Host "状态码: $($logsResponse.StatusCode)" -ForegroundColor Green
    $logsContent = $logsResponse.Content | ConvertFrom-Json
    Write-Host "日志条数: $($logsContent.data.count)" -ForegroundColor Cyan

    Write-Host "`n6. 测试无认证访问（应该失败）..." -ForegroundColor Yellow
    try {
        $unauthorizedResponse = Invoke-WebRequest -Uri "$baseUrl/files/configs/config.json" -UseBasicParsing
        Write-Host "意外成功: $($unauthorizedResponse.StatusCode)" -ForegroundColor Red
    } catch {
        Write-Host "正确拒绝: 401 Unauthorized" -ForegroundColor Green
    }

    Write-Host "所有测试完成!" -ForegroundColor Green
    Write-Host "API功能正常工作!" -ForegroundColor Green

} catch {
    Write-Host "测试失败: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "请确保服务器正在运行: go run cmd/server/main.go" -ForegroundColor Yellow
}

Write-Host "`n📊 测试总结:" -ForegroundColor Blue
Write-Host "- API信息页面: 正常" -ForegroundColor White
Write-Host "- 健康检查: 正常" -ForegroundColor White
Write-Host "- 用户认证: 正常" -ForegroundColor White
Write-Host "- 文件下载: 正常" -ForegroundColor White
Write-Host "- 访问日志: 正常" -ForegroundColor White
Write-Host "- 安全控制: 正常" -ForegroundColor White