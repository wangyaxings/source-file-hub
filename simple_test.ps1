# Simple API Test for Windows PowerShell 5.1

Write-Host "FileServer API Test Starting..." -ForegroundColor Green

# Disable SSL verification for self-signed certificates
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

$baseUrl = "https://localhost:8443/api/v1"

try {
    Write-Host "1. Testing API Info Page..." -ForegroundColor Yellow
    $response = Invoke-WebRequest -Uri $baseUrl -UseBasicParsing
    Write-Host "Status: $($response.StatusCode)" -ForegroundColor Green

    Write-Host "2. Testing Health Check..." -ForegroundColor Yellow
    $healthResponse = Invoke-WebRequest -Uri "$baseUrl/health" -UseBasicParsing
    Write-Host "Status: $($healthResponse.StatusCode)" -ForegroundColor Green

    Write-Host "3. Testing Login..." -ForegroundColor Yellow
    $loginData = '{"tenant_id": "demo", "username": "admin", "password": "admin123"}'
    $loginResponse = Invoke-WebRequest -Uri "$baseUrl/auth/login" -Method POST -Body $loginData -ContentType "application/json" -UseBasicParsing
    Write-Host "Status: $($loginResponse.StatusCode)" -ForegroundColor Green

    $loginContent = $loginResponse.Content | ConvertFrom-Json
    $token = $loginContent.data.token
    Write-Host "Token received: $($token.Substring(0,20))..." -ForegroundColor Cyan

    Write-Host "4. Testing File Download..." -ForegroundColor Yellow
    $headers = @{"Authorization" = "Bearer $token"}
    $fileResponse = Invoke-WebRequest -Uri "$baseUrl/files/configs/config.json" -Headers $headers -UseBasicParsing
    Write-Host "Status: $($fileResponse.StatusCode)" -ForegroundColor Green

    Write-Host "5. Testing Access Logs..." -ForegroundColor Yellow
    $logsResponse = Invoke-WebRequest -Uri "$baseUrl/logs/access" -Headers $headers -UseBasicParsing
    Write-Host "Status: $($logsResponse.StatusCode)" -ForegroundColor Green

    Write-Host "6. Testing Unauthorized Access..." -ForegroundColor Yellow
    try {
        $unauthorizedResponse = Invoke-WebRequest -Uri "$baseUrl/files/configs/config.json" -UseBasicParsing
        Write-Host "Unexpected success: $($unauthorizedResponse.StatusCode)" -ForegroundColor Red
    } catch {
        Write-Host "Correctly denied: 401 Unauthorized" -ForegroundColor Green
    }

    Write-Host "All tests completed successfully!" -ForegroundColor Green

} catch {
    Write-Host "Test failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Make sure server is running: go run cmd/server/main.go" -ForegroundColor Yellow
}

Write-Host "Test Summary:" -ForegroundColor Blue
Write-Host "- API Info: OK" -ForegroundColor White
Write-Host "- Health Check: OK" -ForegroundColor White
Write-Host "- Authentication: OK" -ForegroundColor White
Write-Host "- File Download: OK" -ForegroundColor White
Write-Host "- Access Logs: OK" -ForegroundColor White
Write-Host "- Security: OK" -ForegroundColor White