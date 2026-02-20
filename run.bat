@echo off
echo ============================================
echo  EventHub - Event Management System Setup
echo ============================================
echo.

echo [1/4] Checking Go installation...
go version
if errorlevel 1 (
    echo ERROR: Go is not installed. Download from https://golang.org
    pause
    exit /b 1
)

echo.
echo [2/4] Installing dependencies...
go mod tidy
if errorlevel 1 (
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)

echo.
echo [3/4] Creating uploads directory...
if not exist "static\uploads" mkdir static\uploads

echo.
echo [4/4] Starting EventHub Server...
echo.
echo ============================================
echo  Server starting at: http://localhost:8080
echo ============================================
echo.
echo  Demo Accounts (password: admin123):
echo  - admin@events.com    [ADMIN]
echo  - organizer@events.com [ORGANIZER]  
echo  - user@events.com     [USER]
echo.
echo  Press Ctrl+C to stop the server
echo ============================================
echo.
go run main.go
pause
