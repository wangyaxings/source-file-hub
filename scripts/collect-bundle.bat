@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0\.."

rem Args: --no-build --skip-proxy-pull
set "NO_BUILD=0"
set "SKIP_PROXY_PULL=0"
:parse_args
if "%~1"=="" goto args_done
if /I "%~1"=="--no-build" set "NO_BUILD=1" & shift & goto parse_args
if /I "%~1"=="--skip-proxy-pull" set "SKIP_PROXY_PULL=1" & shift & goto parse_args
echo Unknown option: %1
exit /b 2
:args_done

echo [^+] Checking docker and compose...
docker --version >nul 2>&1
if errorlevel 1 ( echo [-] docker not found & exit /b 1 )
docker compose version >nul 2>&1
if errorlevel 1 ( echo [-] docker compose plugin not found & exit /b 1 )

if "%BACKEND_REPO%"=="" set "BACKEND_REPO=secure-file-hub-backend"
if "%FRONTEND_REPO%"=="" set "FRONTEND_REPO=secure-file-hub-frontend"
if "%BACKEND_TAG%"=="" set "BACKEND_TAG=bundle"
if "%FRONTEND_TAG%"=="" set "FRONTEND_TAG=bundle"
if "%PROXY_IMAGE%"=="" set "PROXY_IMAGE=caddy:2-alpine"

echo [^+] Preparing bundle tree...
for %%D in (bundle bundle\images bundle\certs bundle\configs bundle\data bundle\logs bundle\downloads) do (
  if not exist "%%D" mkdir "%%D"
)

if exist "certs\server.crt" (
  if exist "certs\server.key" (
    copy /y "certs\server.crt" "bundle\certs\server.crt" >nul
    copy /y "certs\server.key" "bundle\certs\server.key" >nul
    echo [^+] Copied certs/server.*
  ) else (
    echo [i] certs/server.key not found; you can place it into bundle\certs later
  )
) else (
  echo [i] certs/server.crt not found; you can place it into bundle\certs later
)

set "APP_YAML_SRC="
if exist "configs\app.yaml" set "APP_YAML_SRC=configs\app.yaml"
if not defined APP_YAML_SRC if exist "configs\app.yaml.example" set "APP_YAML_SRC=configs\app.yaml.example"

if defined APP_YAML_SRC (
  copy /y "%APP_YAML_SRC%" "bundle\configs\app.yaml" >nul
  if /I "%APP_YAML_SRC%"=="configs\app.yaml" (
    echo [^+] Copied configs/app.yaml
  ) else (
    echo [^+] Generated bundle/configs/app.yaml from app.yaml.example
  )
) else (
  echo [i] configs/app.yaml not found; using existing bundle/configs/app.yaml if present
)

rem Ensure Casbin model file is included for permissions initialization
if exist "configs\casbin_model.conf" (
  copy /y "configs\casbin_model.conf" "bundle\configs\casbin_model.conf" >nul
  echo [^+] Copied configs/casbin_model.conf
) else (
  echo [i] configs/casbin_model.conf not found; make sure to provide it for policy initialization
)

if "%NO_BUILD%"=="0" (
  echo [^+] Building backend/frontend images via docker compose...
  docker compose build backend frontend
  if errorlevel 1 (
    echo [-] build failed
    exit /b 1
  )
) else (
  echo [i] Skipping build --no-build. Ensure images exist locally.
)

echo [^+] Tagging images as :%BACKEND_TAG% and :%FRONTEND_TAG%...
docker tag "%BACKEND_REPO%:latest" "%BACKEND_REPO%:%BACKEND_TAG%"
docker tag "%FRONTEND_REPO%:latest" "%FRONTEND_REPO%:%FRONTEND_TAG%"

echo [^+] Saving images to bundle\images ...
docker save -o "bundle\images\backend.tar" "%BACKEND_REPO%:%BACKEND_TAG%"
if errorlevel 1 (
  echo [-] save backend failed
  exit /b 1
)
docker save -o "bundle\images\frontend.tar" "%FRONTEND_REPO%:%FRONTEND_TAG%"
if errorlevel 1 (
  echo [-] save frontend failed
  exit /b 1
)

echo [^+] Ensuring proxy image (%PROXY_IMAGE%) is available...
if "%SKIP_PROXY_PULL%"=="0" (
  docker image inspect "%PROXY_IMAGE%" >nul 2>&1
  if errorlevel 1 (
    docker pull "%PROXY_IMAGE%"
  )
)
docker image inspect "%PROXY_IMAGE%" >nul 2>&1
if errorlevel 1 (
  echo [i] Proxy image %PROXY_IMAGE% not present; bundle will attempt to pull it during deploy
) else (
  docker save -o "bundle\images\proxy.tar" "%PROXY_IMAGE%"
  if errorlevel 1 (
    echo [-] save proxy failed
    exit /b 1
  )
  echo [^+] Saved proxy image to bundle\images\proxy.tar
)

rem Include helper image used by deploy.sh for permission fix
set "HELPER_IMAGE=alpine:3.18"
echo [^+] Ensuring helper image (%HELPER_IMAGE%) is available...
docker image inspect "%HELPER_IMAGE%" >nul 2>&1
if errorlevel 1 (
  if "%SKIP_PROXY_PULL%"=="0" (
    docker pull "%HELPER_IMAGE%" || echo [i] Failed to pull %HELPER_IMAGE%
  ) else (
    echo [i] Skipping pull for %HELPER_IMAGE%
  )
)
docker image inspect "%HELPER_IMAGE%" >nul 2>&1
if errorlevel 1 (
  echo [i] Helper image %HELPER_IMAGE% not present; deploy will try to pull if needed
) else (
  docker save -o "bundle\images\alpine.tar" "%HELPER_IMAGE%"
  if errorlevel 1 (
    echo [-] save helper image failed
    exit /b 1
  )
  echo [^+] Saved helper image to bundle\images\alpine.tar
)

echo [^+] Bundle ready at: %CD%\bundle
echo [^+] Next steps:
echo     - Copy the bundle\ folder to the Linux host
echo     - On Linux host: chmod +x ./deploy.sh& echo     - On Linux host: ./deploy.sh

exit /b 0
