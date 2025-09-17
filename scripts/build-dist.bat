@echo off
REM Build offline Windows package into dist/
setlocal enabledelayedexpansion
cd /d "%~dp0\.."

set DIST=dist
echo [INFO] Preparing %DIST% folder...
if not exist "%DIST%" mkdir "%DIST%"
if exist "%DIST%\fileserver.exe" del /q "%DIST%\fileserver.exe"

echo [INFO] Building backend...
go build -o "%DIST%\fileserver.exe" cmd/server/main.go || goto :err

echo [INFO] Copying configs/certs...
if not exist "%DIST%\configs" mkdir "%DIST%\configs"
if not exist "%DIST%\certs" mkdir "%DIST%\certs"
copy /Y configs\config.json "%DIST%\configs\" >nul 2>&1
copy /Y certs\server.crt "%DIST%\certs\" >nul 2>&1
copy /Y certs\server.key "%DIST%\certs\" >nul 2>&1

echo [INFO] Copying frontend (standalone)...
if not exist "%DIST%\frontend" mkdir "%DIST%\frontend"
copy /Y frontend\server.js "%DIST%\frontend\" >nul 2>&1
copy /Y frontend\package.json "%DIST%\frontend\" >nul 2>&1
if not exist "%DIST%\frontend\.next" mkdir "%DIST%\frontend\.next"
robocopy frontend\.next\static "%DIST%\frontend\.next\static" /E /NFL /NDL /NJH /NJS >nul 2>&1
robocopy frontend\node_modules "%DIST%\frontend\node_modules" /E /NFL /NDL /NJH /NJS >nul 2>&1

echo [INFO] Creating runtime folders (data/logs/downloads)...
for %%D in (data logs downloads) do (
  if not exist "%DIST%\%%D" mkdir "%DIST%\%%D"
)

echo [INFO] Ensuring startup scripts present...
copy /Y dist\start.bat "%DIST%\start.bat" >nul 2>&1
copy /Y dist\stop.bat "%DIST%\stop.bat" >nul 2>&1
copy /Y dist\README-offline.md "%DIST%\README-offline.md" >nul 2>&1

echo.
echo [OK] Offline package is ready in %DIST%\
exit /b 0

:err
echo [ERROR] Failed. Ensure Go toolchain is installed and frontend build exists (server.js, node_modules).
exit /b 1

