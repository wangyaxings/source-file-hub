Param(
  [switch]$Html
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Move to repo root
Set-Location (Join-Path $PSScriptRoot '..')

$env:DISABLE_HTTPS_REDIRECT = 'true'

Write-Host "Running unit tests with race detector and coverage..."
go test ./... -race -count=1 -coverprofile=coverage.out

Write-Host "`nCoverage summary:"
try {
  go tool cover -func=coverage.out | Select-Object -Last 1 | Write-Host
} catch {}

if ($Html) {
  go tool cover -html=coverage.out -o coverage.html
  Write-Host "Coverage HTML generated at coverage.html"
}

Write-Host "Done."

