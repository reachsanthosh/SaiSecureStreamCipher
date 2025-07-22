@echo off
echo Building PassAuth Stream Cipher 
echo.

REM Check if Maven is available
where mvn >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Error: Maven not found. Please install Maven first.
    echo Download from: https://maven.apache.org/download.cgi
    pause
    exit /b 1
)

REM Check if Java is available
where java >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Error: Java not found. Please install Java 11 or higher.
    pause
    exit /b 1
)

echo Building project with Maven...
mvn clean package

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ✅ Build successful!
    echo.
    echo Starting PassAuth Stream Cipher GUI...
    java -jar target\passauth-stream-cipher-1.0.0.jar
) else (
    echo.
    echo ❌ Build failed. Please check the error messages above.
    pause
)
