#!/bin/bash

# Development Server Launcher for Linux/Mac
# Automatically starts all services for Zein Security WAF

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

log() {
    local service=$1
    local message=$2
    local color=$3
    local timestamp=$(date +"%H:%M:%S")
    echo -e "${color}[${timestamp}] [${service}]${NC} ${message}"
}

echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗
║         Zein Security WAF - Development Server              ║
║         Starting all services...                             ║
╚══════════════════════════════════════════════════════════════╝${NC}"

# Check prerequisites
log "SYSTEM" "Checking prerequisites..." "$CYAN"

command -v docker >/dev/null 2>&1 && HAS_DOCKER=true || HAS_DOCKER=false
command -v go >/dev/null 2>&1 && HAS_GO=true || HAS_GO=false
command -v python3 >/dev/null 2>&1 && HAS_PYTHON=true || HAS_PYTHON=false
command -v node >/dev/null 2>&1 && HAS_NODE=true || HAS_NODE=false

if [ "$HAS_NODE" = false ]; then
    log "SYSTEM" "Node.js is required but not found!" "$RED"
    exit 1
fi

if [ "$HAS_GO" = false ]; then
    log "SYSTEM" "Go is required for the backend but not found!" "$RED"
    log "SYSTEM" "Please install Go from https://golang.org/dl/" "$YELLOW"
fi

if [ "$HAS_PYTHON" = false ]; then
    log "SYSTEM" "Python is required for the AI service but not found!" "$RED"
    log "SYSTEM" "Please install Python from https://www.python.org/downloads/" "$YELLOW"
fi

# Start Docker services if available
if [ "$HAS_DOCKER" = true ]; then
    log "DOCKER" "Starting PostgreSQL and Redis..." "$BLUE"
    docker-compose up -d postgres redis || log "DOCKER" "Docker services may already be running" "$YELLOW"
    sleep 5
else
    log "SYSTEM" "Docker not found. Make sure PostgreSQL and Redis are running locally." "$YELLOW"
fi

# Start all services
log "SYSTEM" "Starting application services..." "$CYAN"

# Start AI Service
if [ "$HAS_PYTHON" = true ]; then
    log "AI-SERVICE" "Starting AI Service..." "$GREEN"
    cd backend/ai-service
    python3 -m uvicorn ai:app --host 0.0.0.0 --port 5000 --reload &
    AI_PID=$!
    cd ../..
    sleep 2
    log "AI-SERVICE" "AI Service is running (PID: $AI_PID)" "$GREEN"
else
    log "AI-SERVICE" "Skipped (Python not found)" "$YELLOW"
fi

# Start Backend
if [ "$HAS_GO" = true ]; then
    log "BACKEND" "Starting Backend..." "$YELLOW"
    cd backend
    go run main.go &
    BACKEND_PID=$!
    cd ..
    sleep 2
    log "BACKEND" "Backend is running (PID: $BACKEND_PID)" "$GREEN"
else
    log "BACKEND" "Skipped (Go not found)" "$YELLOW"
fi

# Start Frontend
log "FRONTEND" "Starting Frontend..." "$MAGENTA"
cd frontend
npm run dev &
FRONTEND_PID=$!
cd ..
sleep 2
log "FRONTEND" "Frontend is running (PID: $FRONTEND_PID)" "$GREEN"

# Handle graceful shutdown
cleanup() {
    echo -e "\n${YELLOW}Shutting down all services...${NC}"
    [ ! -z "$AI_PID" ] && kill $AI_PID 2>/dev/null || true
    [ ! -z "$BACKEND_PID" ] && kill $BACKEND_PID 2>/dev/null || true
    [ ! -z "$FRONTEND_PID" ] && kill $FRONTEND_PID 2>/dev/null || true
    if [ "$HAS_DOCKER" = true ]; then
        docker-compose stop postgres redis
    fi
    exit 0
}

trap cleanup SIGINT SIGTERM

log "SYSTEM" "All services started! Press Ctrl+C to stop." "$GREEN"
log "SYSTEM" "Frontend: http://localhost:3000" "$CYAN"
log "SYSTEM" "Backend API: http://localhost:8080" "$CYAN"
log "SYSTEM" "AI Service: http://localhost:5000" "$CYAN"

# Wait for all background processes
wait







