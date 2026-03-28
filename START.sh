#!/bin/bash

echo "========================================"
echo "  Zein Security WAF - Starting All Services"
echo "========================================"
echo ""

echo "[1/4] Checking prerequisites..."
command -v node >/dev/null 2>&1 && echo "  [OK] Node.js installed" || { echo "  [ERROR] Node.js not found!"; exit 1; }
command -v go >/dev/null 2>&1 && echo "  [OK] Go installed" || echo "  [WARN] Go not found!"
command -v python3 >/dev/null 2>&1 && echo "  [OK] Python installed" || echo "  [WARN] Python not found!"
command -v docker >/dev/null 2>&1 && echo "  [OK] Docker installed" || echo "  [WARN] Docker not found!"
echo ""

echo "[2/4] Starting Docker services (PostgreSQL & Redis)..."
docker-compose up -d postgres redis
sleep 5
echo "  [OK] Docker services started"
echo ""

echo "[3/4] Starting all application services..."
echo "  - AI Service (Python) on port 5000"
echo "  - Backend (Go) on port 8080"
echo "  - Frontend (React) on port 3000"
echo ""
echo "  Press Ctrl+C to stop all services"
echo ""

echo "[4/4] Launching services..."

# Start AI Service
cd backend/ai-service
python3 -m uvicorn ai:app --host 0.0.0.0 --port 5000 --reload &
AI_PID=$!
cd ../..
sleep 2

# Start Backend
cd backend
go run main.go &
BACKEND_PID=$!
cd ..
sleep 2

# Start Frontend
cd frontend
npm run dev &
FRONTEND_PID=$!
cd ..

echo ""
echo "========================================"
echo "  All services are starting!"
echo "========================================"
echo ""
echo "  Frontend:  http://localhost:3000"
echo "  Backend:   http://localhost:8080"
echo "  AI Service: http://localhost:5000"
echo ""

# Handle cleanup
cleanup() {
    echo ""
    echo "Stopping services..."
    kill $AI_PID 2>/dev/null
    kill $BACKEND_PID 2>/dev/null
    kill $FRONTEND_PID 2>/dev/null
    docker-compose stop
    echo "Done!"
    exit 0
}

trap cleanup SIGINT SIGTERM

# Wait for all processes
wait







