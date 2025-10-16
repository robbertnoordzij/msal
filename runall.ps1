# MSAL Authentication Demo - Setup and Run All Services
# This script builds dependencies and starts both backend and frontend services concurrently

Write-Host "MSAL Authentication Demo - Setup & Run" -ForegroundColor Green
Write-Host "=======================================" -ForegroundColor Green
Write-Host ""

# Step 1: Generate configuration from .env file
Write-Host "Step 1: Generating configuration from .env file..." -ForegroundColor Cyan
& "$PSScriptRoot\configure.ps1"
if ($LASTEXITCODE -ne 0) {
    Write-Host "✗ Configuration generation failed. Please check your .env file." -ForegroundColor Red
    exit 1
}

Write-Host ""

# Check if required directories exist
if (-not (Test-Path "backend")) {
    Write-Host "Error: backend directory not found!" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path "frontend")) {
    Write-Host "Error: frontend directory not found!" -ForegroundColor Red
    exit 1
}

# Setup Phase: Install dependencies and build
Write-Host "Step 2: Setting up dependencies and building..." -ForegroundColor Cyan
Write-Host ""

Write-Host "Installing frontend dependencies..." -ForegroundColor Yellow
Set-Location "frontend"
try {
    npm install
    if ($LASTEXITCODE -ne 0) {
        throw "npm install failed with exit code $LASTEXITCODE"
    }
    Write-Host "✓ Frontend dependencies installed successfully" -ForegroundColor Green
}
catch {
    Write-Host "✗ Failed to install frontend dependencies: $($_.Exception.Message)" -ForegroundColor Red
    Set-Location ".."
    exit 1
}
finally {
    Set-Location ".."
}

Write-Host ""
Write-Host "Building backend..." -ForegroundColor Yellow
Set-Location "backend"
try {
    mvn clean install
    if ($LASTEXITCODE -ne 0) {
        throw "Maven build failed with exit code $LASTEXITCODE"
    }
    Write-Host "✓ Backend built successfully" -ForegroundColor Green
}
catch {
    Write-Host "✗ Failed to build backend: $($_.Exception.Message)" -ForegroundColor Red
    Set-Location ".."
    exit 1
}
finally {
    Set-Location ".."
}

Write-Host ""
Write-Host "✓ Setup complete! Starting services..." -ForegroundColor Green
Write-Host ""

# Start services in separate terminal windows
Write-Host "Starting backend service in new terminal window..." -ForegroundColor Cyan
$backendProcess = Start-Process -FilePath "pwsh.exe" -ArgumentList @(
    "-NoExit", 
    "-Command", 
    "Set-Location 'backend'; Write-Host 'Starting Spring Boot backend on port 8080...' -ForegroundColor Yellow; mvn spring-boot:run"
) -PassThru -WindowStyle Normal

# Wait a moment for backend to start
Start-Sleep -Seconds 2

Write-Host "Starting frontend service in new terminal window..." -ForegroundColor Cyan
$frontendProcess = Start-Process -FilePath "pwsh.exe" -ArgumentList @(
    "-NoExit", 
    "-Command", 
    "Set-Location 'frontend'; Write-Host 'Starting React frontend on port 3000...' -ForegroundColor Yellow; npm start"
) -PassThru -WindowStyle Normal

Write-Host ""
Write-Host "✓ Both services are starting in separate terminal windows..." -ForegroundColor Green
Write-Host ""
Write-Host "Services:" -ForegroundColor White
Write-Host "  Backend:  http://localhost:8080/api" -ForegroundColor Cyan
Write-Host "  Frontend: http://localhost:3000" -ForegroundColor Cyan
Write-Host ""
Write-Host "To stop services:" -ForegroundColor Yellow
Write-Host "  - Close the terminal windows, or" -ForegroundColor Yellow
Write-Host "  - Press Ctrl+C in each terminal window" -ForegroundColor Yellow
Write-Host ""
Write-Host "Configuration files to check:" -ForegroundColor Magenta
Write-Host "  - frontend\src\config\msalConfig.js" -ForegroundColor White
Write-Host "  - backend\src\main\resources\application.properties" -ForegroundColor White
Write-Host ""
Write-Host "Press any key to exit this setup script..." -ForegroundColor Gray
Read-Host

# Optional: Monitor processes and clean up if they exit unexpectedly
Write-Host "Monitoring services... (Press Ctrl+C to stop monitoring)" -ForegroundColor Yellow
try {
    while ($true) {
        if ($backendProcess.HasExited) {
            Write-Host "⚠️  Backend process has exited" -ForegroundColor Red
            break
        }
        if ($frontendProcess.HasExited) {
            Write-Host "⚠️  Frontend process has exited" -ForegroundColor Red
            break
        }
        Start-Sleep -Seconds 5
    }
}
catch {
    Write-Host "Stopped monitoring services." -ForegroundColor Yellow
}

Write-Host "Setup script completed." -ForegroundColor Green