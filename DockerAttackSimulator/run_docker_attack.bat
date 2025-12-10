@echo off
echo ========================================
echo Docker DDoS Attack Launcher
echo ========================================
echo.

REM Check if Docker is running
docker version >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Docker is not running!
    echo Please start Docker Desktop and try again.
    echo.
    pause
    exit /b 1
)

echo Docker is running - OK
echo.

REM Get Windows 11 IP address
echo Detecting your Windows 11 IP address...
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /c:"IPv4 Address"') do (
    set DETECTED_IP=%%a
    goto :found_ip
)

:found_ip
set DETECTED_IP=%DETECTED_IP: =%
echo Detected IP: %DETECTED_IP%
echo.

REM Ask for confirmation or override
set /p USE_IP="Is this your correct IP? (y/n): "
if /i "%USE_IP%" neq "y" (
    set /p DETECTED_IP="Enter your Windows 11 IP address: "
)

echo.
echo Target IP will be: %DETECTED_IP%
echo.

REM Set target port
set /p TARGET_PORT="Enter target port (default 8050): "
if "%TARGET_PORT%"=="" set TARGET_PORT=8050

REM Select attack type
echo.
echo Select Attack Type:
echo 1. HTTP Flood (recommended for testing)
echo 2. SYN Flood
echo 3. UDP Flood
echo 4. Slowloris
echo.
set /p ATTACK_CHOICE="Enter choice (1-4, default 1): "

if "%ATTACK_CHOICE%"=="" set ATTACK_CHOICE=1

if "%ATTACK_CHOICE%"=="1" (
    set ATTACK_TYPE=http
) else if "%ATTACK_CHOICE%"=="2" (
    set ATTACK_TYPE=syn
) else if "%ATTACK_CHOICE%"=="3" (
    set ATTACK_TYPE=udp
) else if "%ATTACK_CHOICE%"=="4" (
    set ATTACK_TYPE=slowloris
) else (
    set ATTACK_TYPE=http
)

REM Set duration
set /p DURATION="Enter duration in seconds (default 120): "
if "%DURATION%"=="" set DURATION=120

REM Set intensity
echo.
echo Select Intensity:
echo 1. Low
echo 2. Medium (recommended)
echo 3. High
echo.
set /p INTENSITY_CHOICE="Enter choice (1-3, default 2): "

if "%INTENSITY_CHOICE%"=="" set INTENSITY_CHOICE=2

if "%INTENSITY_CHOICE%"=="1" (
    set INTENSITY=low
) else if "%INTENSITY_CHOICE%"=="2" (
    set INTENSITY=medium
) else if "%INTENSITY_CHOICE%"=="3" (
    set INTENSITY=high
) else (
    set INTENSITY=medium
)

echo.
echo ========================================
echo Attack Configuration:
echo ========================================
echo Target IP: %DETECTED_IP%
echo Target Port: %TARGET_PORT%
echo Attack Type: %ATTACK_TYPE%
echo Duration: %DURATION% seconds
echo Intensity: %INTENSITY%
echo ========================================
echo.

set /p CONFIRM="Start attack? (yes/no): "
if /i "%CONFIRM%" neq "yes" (
    echo Attack cancelled.
    pause
    exit /b 0
)

echo.
echo Building Docker image...
docker build -t ddos-attacker .

if %errorLevel% neq 0 (
    echo ERROR: Failed to build Docker image!
    pause
    exit /b 1
)

echo.
echo Starting DDoS attack from Docker container...
echo Press Ctrl+C to stop the attack
echo.

docker run --rm -it ^
    -e TARGET_IP=%DETECTED_IP% ^
    -e TARGET_PORT=%TARGET_PORT% ^
    -e ATTACK_TYPE=%ATTACK_TYPE% ^
    -e DURATION=%DURATION% ^
    -e INTENSITY=%INTENSITY% ^
    ddos-attacker python3 docker_ddos_attacker.py ^
    --target %DETECTED_IP% ^
    --port %TARGET_PORT% ^
    --type %ATTACK_TYPE% ^
    --duration %DURATION% ^
    --intensity %INTENSITY%

echo.
echo Attack completed or stopped.
pause