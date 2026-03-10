# Load Environment Variables and Generate Config Files
# This script reads .env file and generates configuration for both frontend and backend

Write-Host "Loading configuration from .env file..." -ForegroundColor Cyan

# Check if .env file exists
if (-not (Test-Path ".env")) {
    Write-Host "Error: .env file not found!" -ForegroundColor Red
    Write-Host "Please copy .env.example to .env and fill in your Azure AD details." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Run: Copy-Item .env.example .env" -ForegroundColor White
    exit 1
}

# Function to load .env file
function Load-EnvFile {
    param([string]$Path)
    
    $envVars = @{}
    Get-Content $Path | ForEach-Object {
        $line = $_.Trim()
        # Skip comments and empty lines
        if ($line -and -not $line.StartsWith('#')) {
            $parts = $line -split '=', 2
            if ($parts.Count -eq 2) {
                $key = $parts[0].Trim()
                $value = $parts[1].Trim()
                $envVars[$key] = $value
            }
        }
    }
    return $envVars
}

# Load environment variables
$env_vars = Load-EnvFile -Path ".env"

# Validate required variables
$required = @('AZURE_CLIENT_ID', 'AZURE_TENANT_ID')
$missing = @()
foreach ($var in $required) {
    if (-not $env_vars.ContainsKey($var) -or $env_vars[$var] -eq 'your-client-id-here' -or $env_vars[$var] -eq 'your-tenant-id-here') {
        $missing += $var
    }
}

if ($missing.Count -gt 0) {
    Write-Host "Error: Missing or invalid required variables in .env file:" -ForegroundColor Red
    $missing | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
    Write-Host ""
    Write-Host "Please update .env file with your Azure AD App Registration details." -ForegroundColor White
    exit 1
}

Write-Host "✓ Environment variables loaded successfully" -ForegroundColor Green
Write-Host ""

# Display loaded configuration
Write-Host "Configuration:" -ForegroundColor Cyan
Write-Host "  Client ID: $($env_vars['AZURE_CLIENT_ID'])" -ForegroundColor White
Write-Host "  Tenant ID: $($env_vars['AZURE_TENANT_ID'])" -ForegroundColor White
Write-Host "  Frontend URL: $($env_vars['FRONTEND_URL'])" -ForegroundColor White
Write-Host "  Backend URL: $($env_vars['BACKEND_URL'])" -ForegroundColor White
Write-Host ""

# Generate Frontend Config
Write-Host "Generating frontend configuration..." -ForegroundColor Yellow

$frontendConfigDir = "frontend/src/config"
if (-not (Test-Path $frontendConfigDir)) {
    Write-Host "Creating frontend config directory..." -ForegroundColor Gray
    New-Item -ItemType Directory -Path $frontendConfigDir -Force | Out-Null
}

$frontendConfig = @"
// Auto-generated from .env file - DO NOT EDIT MANUALLY
// Run '../configure.ps1' to regenerate

// Backend API configuration
// The BFF (Backend For Frontend) handles all token exchange server-side.
// The browser only needs to know the API base URL — no client-id or tenant-id required.
export const apiConfig = {
  baseUrl: "/api", // Proxy forwards to backend (see setupProxy.js)
  endpoints: {
    hello: "/hello",
    login: "/auth/login",
    logout: "/auth/logout",
  },
};
"@

$frontendConfig | Out-File -FilePath "frontend/src/config/msalConfig.js" -Encoding UTF8
Write-Host "✓ Frontend config generated: frontend/src/config/msalConfig.js" -ForegroundColor Green

# Generate Backend Config
Write-Host "Generating backend configuration..." -ForegroundColor Yellow

$backendConfigDir = "backend/src/main/resources"
if (-not (Test-Path $backendConfigDir)) {
    Write-Host "Creating backend config directory..." -ForegroundColor Gray
    New-Item -ItemType Directory -Path $backendConfigDir -Force | Out-Null
}

$backendConfig = @"
# Application Configuration
# Auto-generated from .env file - DO NOT EDIT MANUALLY
# Run './configure.ps1' to regenerate
spring.application.name=msal-bff

# Server Configuration
server.port=$($env_vars['BACKEND_PORT'])
server.servlet.context-path=$($env_vars['BACKEND_CONTEXT_PATH'])

# Azure AD — single source of truth
app.azure-ad.tenant-id=$($env_vars['AZURE_TENANT_ID'])
app.azure-ad.client-id=$($env_vars['AZURE_CLIENT_ID'])
app.azure-ad.client-secret=$($env_vars['AZURE_CLIENT_SECRET'])
app.azure-ad.authority=https://login.microsoftonline.com/`${app.azure-ad.tenant-id}
app.azure-ad.jwk-set-uri=`${app.azure-ad.authority}/discovery/v2.0/keys
app.azure-ad.redirect-uri=$($env_vars['FRONTEND_URL'])$($env_vars['BACKEND_CONTEXT_PATH'])/auth/callback
app.azure-ad.scopes=openid profile offline_access User.Read

# Cookie Configuration
app.cookie.name=$($env_vars['COOKIE_NAME'])
app.cookie.max-age=$($env_vars['COOKIE_MAX_AGE'])
app.cookie.secure=$($env_vars['COOKIE_SECURE'])
app.cookie.same-site=$($env_vars['COOKIE_SAME_SITE'])

# CORS Configuration
app.cors.allowed-origins=$($env_vars['FRONTEND_URL'])

# Redis — distributed MSAL token cache
app.redis.host=$($env_vars.ContainsKey('REDIS_HOST') ? $env_vars['REDIS_HOST'] : 'localhost')
app.redis.port=$($env_vars.ContainsKey('REDIS_PORT') ? $env_vars['REDIS_PORT'] : '6379')
app.redis.password=$($env_vars.ContainsKey('REDIS_PASSWORD') ? $env_vars['REDIS_PASSWORD'] : 'changeme-in-dev')
app.redis.ttl=$($env_vars.ContainsKey('REDIS_TTL') ? $env_vars['REDIS_TTL'] : '90d')
app.redis.tls=$($env_vars.ContainsKey('REDIS_TLS') ? $env_vars['REDIS_TLS'] : 'false')
app.redis.encryption-key=$($env_vars.ContainsKey('REDIS_ENCRYPTION_KEY') ? $env_vars['REDIS_ENCRYPTION_KEY'] : '')

# Logging
logging.level.com.example=$($env_vars['LOG_LEVEL'])
logging.level.org.springframework.security=$($env_vars['LOG_LEVEL'])
"@

$backendConfig | Out-File -FilePath "backend/src/main/resources/application.properties" -Encoding UTF8
Write-Host "✓ Backend config generated: backend/src/main/resources/application.properties" -ForegroundColor Green

Write-Host ""
Write-Host "Configuration files generated successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Review the generated config files" -ForegroundColor White
Write-Host "  2. Run './runall.ps1' to build and start the application" -ForegroundColor White
Write-Host ""
