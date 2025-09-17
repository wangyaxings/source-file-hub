param(
  [string[]]$Ips = @($env:TARGET_IP ? $env:TARGET_IP : '127.0.0.1'),
  [int[]]$Ports = @(8444, 30000),
  [string]$Hostname = ($env:TARGET_HOSTNAME ? $env:TARGET_HOSTNAME : 'localhost'),
  [string]$ApiKey = $env:API_KEY,
  [string]$Tenant = ($env:TENANT ? $env:TENANT : 'tenant123'),
  [switch]$DoUploads
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path tmp)) { New-Item -ItemType Directory -Path tmp | Out-Null }
$outDir = Join-Path 'tmp' 'api-test'
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }

function Invoke-CurlJson {
  param([string]$Name, [string[]]$Args, [string]$OutFile)
  $code = & curl.exe @Args -s -o $OutFile -w '%{http_code}'
  $preview = ''
  if (Test-Path $OutFile) {
    $preview = (Get-Content -Raw -ErrorAction SilentlyContinue $OutFile)
    if ($preview.Length -gt 160) { $preview = $preview.Substring(0,160) + '...' }
  }
  Write-Output ("{0} -> {1} | {2}" -f $Name, $code, $preview)
}

function BuildHeaders {
  param([string]$ApiKey)
  $hs = @()
  if ($ApiKey) { $hs += @('-H', "X-API-Key: $ApiKey") }
  return ,$hs
}

foreach ($ip in $Ips) {
  foreach ($port in $Ports) {
    Write-Host "== Testing $ip:$port ==" -ForegroundColor Cyan
    $base = "https://$Hostname:$port/api/v1"
    $resolve = @('--resolve',"$Hostname:$port:$ip")

    # Health
    Invoke-CurlJson "health" @($resolve,'-k',"$base/health") (Join-Path $outDir "health-$ip-$port.json")
    Invoke-CurlJson "healthz" @($resolve,'-k',"$base/healthz") (Join-Path $outDir "healthz-$ip-$port.json")

    # Files list (public)
    $headers = BuildHeaders $ApiKey
    Invoke-CurlJson "files" @($resolve,'-k',$headers,"$base/public/files") (Join-Path $outDir "files-$ip-$port.json")

    # Versions
    Invoke-CurlJson "versions/roadmap/latest" @($resolve,'-k',$headers,"$base/public/versions/roadmap/latest") (Join-Path $outDir "latest-roadmap-$ip-$port.json")
    Invoke-CurlJson "versions/recommendation/latest" @($resolve,'-k',$headers,"$base/public/versions/recommendation/latest") (Join-Path $outDir "latest-reco-$ip-$port.json")

    # Download latest (headers only to avoid large downloads)
    $dlOut = Join-Path $outDir "dl-latest-roadmap-$ip-$port.headers"
    $code = & curl.exe @($resolve,'-k','-I',$headers,"$base/public/versions/roadmap/latest/download") -s -o $dlOut -w '%{http_code}'
    Write-Output ("download latest roadmap (HEAD) -> {0}" -f $code)

    if ($DoUploads -and $ApiKey) {
      # Prepare temp zip files
      $utc = (Get-Date -AsUTC).ToString('yyyyMMddTHHmmssZ')
      $tmpFolder = Join-Path $outDir "tmp-$ip-$port"
      if (-not (Test-Path $tmpFolder)) { New-Item -ItemType Directory -Path $tmpFolder | Out-Null }
      $dummy = Join-Path $tmpFolder 'dummy.txt'
      'hello api test' | Out-File -Encoding utf8 $dummy

      $zipA = Join-Path $tmpFolder ("{0}_assets_{1}.zip" -f $Tenant, $utc)
      $zipO = Join-Path $tmpFolder ("{0}_others_{1}.zip" -f $Tenant, $utc)
      if (Test-Path $zipA) { Remove-Item $zipA -Force }
      if (Test-Path $zipO) { Remove-Item $zipO -Force }
      Compress-Archive -Path $dummy -DestinationPath $zipA -Force
      Compress-Archive -Path $dummy -DestinationPath $zipO -Force

      # Upload assets
      Invoke-CurlJson "upload assets-zip" @($resolve,'-k',$headers,'-F',"file=@$zipA","$base/public/upload/assets-zip") (Join-Path $outDir "upload-assets-$ip-$port.json")
      # Upload others
      Invoke-CurlJson "upload others-zip" @($resolve,'-k',$headers,'-F',"file=@$zipO","$base/public/upload/others-zip") (Join-Path $outDir "upload-others-$ip-$port.json")
    }
  }
}

Write-Host "Done. Outputs in $outDir" -ForegroundColor Green

