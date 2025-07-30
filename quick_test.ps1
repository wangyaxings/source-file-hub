# Quick connection test

Write-Host "Testing connection to https://localhost:8443" -ForegroundColor Yellow

# Try simple connection first
try {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    
    $webClient = New-Object System.Net.WebClient
    $result = $webClient.DownloadString("https://localhost:8443/api/v1")
    Write-Host "Success! Response received:" -ForegroundColor Green
    Write-Host $result.Substring(0, [Math]::Min(200, $result.Length)) -ForegroundColor Cyan
    
} catch {
    Write-Host "Connection failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Full error: $($_.Exception.GetType().Name)" -ForegroundColor Yellow
    
    # Try with IP instead of localhost
    try {
        Write-Host "Trying with 127.0.0.1..." -ForegroundColor Yellow
        $result2 = $webClient.DownloadString("https://127.0.0.1:8443/api/v1")
        Write-Host "Success with IP!" -ForegroundColor Green
    } catch {
        Write-Host "IP also failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}