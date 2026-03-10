#!/bin/bash

# Load Environment Variables and Generate Config Files
# This script reads .env file and generates configuration for both frontend and backend

# Colors for output
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color
GRAY='\033[0;90m'

echo -e "${CYAN}Loading configuration from .env file...${NC}"

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo -e "${RED}Error: .env file not found!${NC}"
    echo -e "${YELLOW}Please copy .env.example to .env and fill in your Azure AD details.${NC}"
    echo ""
    echo -e "Run: cp .env.example .env"
    exit 1
fi

# Function to load .env file
load_env() {
    local env_file="$1"
    if [ -f "$env_file" ]; then
        # Read file line by line, skip comments and empty lines
        while IFS='=' read -r key value || [ -n "$key" ]; do
            # Trim whitespace
            key=$(echo "$key" | xargs)
            value=$(echo "$value" | xargs)
            
            if [[ ! $key =~ ^# ]] && [ -n "$key" ]; then
                export "$key=$value"
            fi
        done < "$env_file"
    fi
}

# Load environment variables
load_env ".env"

# Validate required variables
missing=()
if [ -z "$AZURE_CLIENT_ID" ] || [ "$AZURE_CLIENT_ID" == "your-client-id-here" ]; then
    missing+=("AZURE_CLIENT_ID")
fi
if [ -z "$AZURE_TENANT_ID" ] || [ "$AZURE_TENANT_ID" == "your-tenant-id-here" ]; then
    missing+=("AZURE_TENANT_ID")
fi

if [ ${#missing[@]} -gt 0 ]; then
    echo -e "${RED}Error: Missing or invalid required variables in .env file:${NC}"
    for var in "${missing[@]}"; do
        echo -e "${YELLOW}  - $var${NC}"
    done
    echo ""
    echo -e "Please update .env file with your Azure AD App Registration details."
    exit 1
fi

echo -e "${GREEN}✓ Environment variables loaded successfully${NC}"
echo ""

# Display loaded configuration
echo -e "${CYAN}Configuration:${NC}"
echo -e "  Client ID: $AZURE_CLIENT_ID"
echo -e "  Tenant ID: $AZURE_TENANT_ID"
echo -e "  Frontend URL: $FRONTEND_URL"
echo -e "  Backend URL: $BACKEND_URL"
echo ""

# Generate Frontend Config
echo -e "${YELLOW}Generating frontend configuration...${NC}"

FRONTEND_CONFIG_DIR="frontend/src/config"
if [ ! -d "$FRONTEND_CONFIG_DIR" ]; then
    echo -e "${GRAY}Creating frontend config directory...${NC}"
    mkdir -p "$FRONTEND_CONFIG_DIR"
fi

cat <<EOF > "$FRONTEND_CONFIG_DIR/msalConfig.js"
// Auto-generated from .env file - DO NOT EDIT MANUALLY
// Run './configure.sh' to regenerate

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
EOF

echo -e "${GREEN}✓ Frontend config generated: $FRONTEND_CONFIG_DIR/msalConfig.js${NC}"

# Generate Backend Config
echo -e "${YELLOW}Generating backend configuration...${NC}"

BACKEND_CONFIG_DIR="backend/src/main/resources"
if [ ! -d "$BACKEND_CONFIG_DIR" ]; then
    echo -e "${GRAY}Creating backend config directory...${NC}"
    mkdir -p "$BACKEND_CONFIG_DIR"
fi

cat <<EOF > "$BACKEND_CONFIG_DIR/application.properties"
# Application Configuration
# Auto-generated from .env file - DO NOT EDIT MANUALLY
# Run './configure.sh' to regenerate
spring.application.name=msal-bff

# Server Configuration
server.port=${BACKEND_PORT:-8080}
server.servlet.context-path=${BACKEND_CONTEXT_PATH:-/api}

# Azure AD — single source of truth
app.azure-ad.tenant-id=$AZURE_TENANT_ID
app.azure-ad.client-id=$AZURE_CLIENT_ID
app.azure-ad.client-secret=${AZURE_CLIENT_SECRET:-}
app.azure-ad.authority=https://login.microsoftonline.com/\${app.azure-ad.tenant-id}
app.azure-ad.jwk-set-uri=\${app.azure-ad.authority}/discovery/v2.0/keys
app.azure-ad.redirect-uri=${FRONTEND_URL:-http://localhost:3000}${BACKEND_CONTEXT_PATH:-/api}/auth/callback
app.azure-ad.scopes=openid profile offline_access User.Read

# Cookie Configuration
app.cookie.name=${COOKIE_NAME:-AUTH_TOKEN}
app.cookie.max-age=${COOKIE_MAX_AGE:-3600}
app.cookie.secure=${COOKIE_SECURE:-false}
app.cookie.same-site=${COOKIE_SAME_SITE:-Lax}

# CORS Configuration
app.cors.allowed-origins=${FRONTEND_URL:-http://localhost:3000}

# Redis — distributed MSAL token cache
app.redis.host=${REDIS_HOST:-localhost}
app.redis.port=${REDIS_PORT:-6379}
app.redis.password=${REDIS_PASSWORD:-changeme-in-dev}
app.redis.ttl=${REDIS_TTL:-90d}
app.redis.tls=${REDIS_TLS:-false}
app.redis.encryption-key=${REDIS_ENCRYPTION_KEY:-}

# Logging
logging.level.com.example=${LOG_LEVEL:-DEBUG}
logging.level.org.springframework.security=${LOG_LEVEL:-DEBUG}
EOF

echo -e "${GREEN}✓ Backend config generated: $BACKEND_CONFIG_DIR/application.properties${NC}"

echo ""
echo -e "${GREEN}Configuration files generated successfully!${NC}"
echo ""
echo -e "${CYAN}Next steps:${NC}"
echo -e "  1. Review the generated config files"
echo -e "  2. Run './runall.sh' to build and start the application"
echo ""
