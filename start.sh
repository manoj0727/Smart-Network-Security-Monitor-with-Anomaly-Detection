#!/bin/bash

# Cybernet Security Matrix - Startup Script
# One command to rule them all!

echo "
╔═══════════════════════════════════════════════════════════╗
║     🛡️  CYBERNET SECURITY MATRIX v2.0                     ║
║     Neural Network Initializing...                       ║
╚═══════════════════════════════════════════════════════════╝
"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to check if port is in use
check_port() {
    lsof -i :$1 > /dev/null 2>&1
    return $?
}

# Function to kill process on port
kill_port() {
    if check_port $1; then
        echo -e "${YELLOW}[!] Port $1 in use. Killing existing process...${NC}"
        lsof -ti :$1 | xargs kill -9 2>/dev/null
        sleep 1
    fi
}

# Function to cleanup on exit
cleanup() {
    echo -e "\n${YELLOW}[!] Shutting down Cybernet Security Matrix...${NC}"
    
    # Kill API server
    if [ ! -z "$API_PID" ]; then
        kill $API_PID 2>/dev/null
    fi
    
    # Kill Frontend server
    if [ ! -z "$FRONTEND_PID" ]; then
        kill $FRONTEND_PID 2>/dev/null
    fi
    
    # Kill any remaining processes on our ports
    kill_port 8001
    kill_port 8082
    
    echo -e "${GREEN}[✓] System shutdown complete${NC}"
    exit 0
}

# Trap CTRL+C and cleanup
trap cleanup INT TERM

# Check Python installation
echo -e "${GREEN}[1/5] Checking system requirements...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[✗] Python 3 not found! Please install Python 3.9+${NC}"
    exit 1
fi

# Install dependencies if needed
echo -e "${GREEN}[2/5] Checking dependencies...${NC}"
if ! python3 -c "import fastapi" 2>/dev/null; then
    echo -e "${YELLOW}[!] Installing dependencies...${NC}"
    pip3 install -r requirements.txt
fi

# Clean up existing processes
echo -e "${GREEN}[3/5] Cleaning up existing processes...${NC}"
kill_port 8001
kill_port 8082

# Start API Server
echo -e "${GREEN}[4/5] Starting API Server on port 8001...${NC}"
python3 src/main.py --api-only --port 8001 > /tmp/api_server.log 2>&1 &
API_PID=$!

# Wait for API to start
echo -e "${YELLOW}    Waiting for API to initialize...${NC}"
for i in {1..10}; do
    if curl -s http://localhost:8001/health > /dev/null 2>&1; then
        echo -e "${GREEN}    [✓] API Server online!${NC}"
        break
    fi
    sleep 1
done

# Start Frontend Server
echo -e "${GREEN}[5/5] Starting Frontend Dashboard on port 8082...${NC}"
cd frontend
python3 -m http.server 8082 > /tmp/frontend_server.log 2>&1 &
FRONTEND_PID=$!
cd ..

# Wait a moment for frontend to start
sleep 2

# Display success message
echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     ✅ CYBERNET SECURITY MATRIX ACTIVATED                ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}🌐 Dashboard:${NC} http://localhost:8082"
echo -e "${GREEN}📡 API Server:${NC} http://localhost:8001"
echo -e "${GREEN}📚 API Docs:${NC} http://localhost:8001/docs"
echo ""
echo -e "${YELLOW}[!] Press CTRL+C to shutdown${NC}"
echo ""
echo -e "${GREEN}Opening dashboard in browser...${NC}"

# Try to open browser (works on Mac and most Linux)
if command -v open &> /dev/null; then
    open http://localhost:8082
elif command -v xdg-open &> /dev/null; then
    xdg-open http://localhost:8082
fi

echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}SYSTEM STATUS: MONITORING ACTIVE${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"

# Keep script running and show logs
tail -f /tmp/api_server.log /tmp/frontend_server.log 2>/dev/null