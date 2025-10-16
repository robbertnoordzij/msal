@echo off
echo Setting up MSAL Authentication Demo...

echo.
echo Installing frontend dependencies...
cd frontend
call npm install
if errorlevel 1 (
    echo Failed to install frontend dependencies
    exit /b 1
)

echo.
echo Building backend...
cd ..\backend
call mvn clean install
if errorlevel 1 (
    echo Failed to build backend
    exit /b 1
)

echo.
echo Setup complete!
echo.
echo To start the application:
echo 1. Backend: cd backend && mvn spring-boot:run
echo 2. Frontend: cd frontend && npm start
echo.
echo Don't forget to configure Azure AD settings in:
echo - frontend\src\config\msalConfig.js
echo - backend\src\main\resources\application.properties