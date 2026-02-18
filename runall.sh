#!/bin/bash

# MSAL Authentication Demo - Setup and Run All Services
# This script builds dependencies and starts both backend and frontend services concurrently

# Colors for output
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color
WHITE='\033[1;37m'
MAGENTA='\033[0;35m'
GRAY='\033[0;90m'

echo -e "${GREEN}MSAL Authentication Demo - Setup & Run${NC}"
echo -e "${GREEN}=======================================${NC}"
echo ""

# Step 1: Generate configuration from .env file
echo -e "${CYAN}Step 1: Generating configuration from .env file...${NC}"
./configure.sh
if [ $? -ne 0 ]; then
    echo -e "${RED}✗ Configuration generation failed. Please check your .env file.${NC}"
    exit 1
fi

echo ""

# Check if required directories exist
if [ ! -d "backend" ]; then
    echo -e "${RED}Error: backend directory not found!${NC}"
    exit 1
fi

if [ ! -d "frontend" ]; then
    echo -e "${RED}Error: frontend directory not found!${NC}"
    exit 1
fi

# Setup Phase: Install dependencies and build
echo -e "${CYAN}Step 2: Setting up dependencies and building...${NC}"
echo ""

echo -e "${YELLOW}Installing frontend dependencies...${NC}"
(
    cd frontend
    npm install
    if [ $? -ne 0 ]; then
        echo -e "${RED}✗ Failed to install frontend dependencies${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Frontend dependencies installed successfully${NC}"
) || exit 1

echo ""
echo -e "${YELLOW}Building backend...${NC}"
(
    cd backend
    mvn clean install
    if [ $? -ne 0 ]; then
        echo -e "${RED}✗ Failed to build backend${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Backend built successfully${NC}"
) || exit 1

echo ""
echo -e "${GREEN}✓ Setup complete! Starting services...${NC}"
echo ""

# Start services in separate terminal windows (macOS specific)
echo -e "${CYAN}Starting backend service in new terminal window...${NC}"
osascript -e "tell application \"Terminal\" to do script \"cd '$(pwd)/backend' && echo 'Starting Spring Boot backend on port 8080...' && mvn spring-boot:run\"" > /dev/null

# Wait a moment for backend to start
sleep 2

echo -e "${CYAN}Starting frontend service in new terminal window...${NC}"
osascript -e "tell application \"Terminal\" to do script \"cd '$(pwd)/frontend' && echo 'Starting React frontend on port 3000...' && npm start\"" > /dev/null

echo ""
echo -e "${GREEN}✓ Both services are starting in separate terminal windows...${NC}"
echo ""
echo -e "${WHITE}Services:${NC}"
echo -e "  Backend:  ${CYAN}http://localhost:8080/api${NC}"
echo -e "  Frontend: ${CYAN}http://localhost:3000${NC}"
echo ""
echo -e "${YELLOW}To stop services:${NC}"
echo -e "  - Close the terminal windows, or"
echo -e "  - Press Ctrl+C in each terminal window"
echo ""
echo -e "${MAGENTA}Configuration files to check:${NC}"
echo -e "  - frontend/src/config/msalConfig.js"
echo -e "  - backend/src/main/resources/application.properties"
echo ""

echo -e "${GRAY}Press any key to exit this setup script...${NC}"
read -n 1 -s

echo -e "${GREEN}Setup script completed.${NC}"
