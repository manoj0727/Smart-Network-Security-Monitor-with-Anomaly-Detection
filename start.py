#!/usr/bin/env python3
"""
Cybernet Security Matrix - Easy Start Script
One command to launch everything!
"""

import subprocess
import time
import sys
import os
import signal
import webbrowser
import socket
from pathlib import Path

# ANSI color codes
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'
BOLD = '\033[1m'

# Global process handlers
api_process = None
frontend_process = None

def print_banner():
    """Print cool banner"""
    banner = f"""
{GREEN}╔═══════════════════════════════════════════════════════════╗
║     🛡️  CYBERNET SECURITY MATRIX v2.0                     ║
║     Neural Network Initializing...                       ║
╚═══════════════════════════════════════════════════════════╝{RESET}
    """
    print(banner)

def check_port(port):
    """Check if port is available"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('localhost', port))
    sock.close()
    return result == 0

def kill_port(port):
    """Kill process using port"""
    if check_port(port):
        print(f"{YELLOW}[!] Port {port} in use. Killing existing process...{RESET}")
        try:
            if sys.platform == "darwin":  # macOS
                subprocess.run(f"lsof -ti :{port} | xargs kill -9", shell=True, capture_output=True)
            else:  # Linux
                subprocess.run(f"fuser -k {port}/tcp", shell=True, capture_output=True)
        except:
            pass
        time.sleep(1)

def check_dependencies():
    """Check if all dependencies are installed"""
    print(f"{GREEN}[1/5] Checking dependencies...{RESET}")
    try:
        import fastapi
        import uvicorn
        print(f"{GREEN}    ✓ Dependencies OK{RESET}")
        return True
    except ImportError:
        print(f"{YELLOW}    Installing dependencies...{RESET}")
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        return True

def start_api_server():
    """Start the API server"""
    global api_process
    print(f"{GREEN}[2/5] Starting API Server on port 8001...{RESET}")
    
    # Kill any existing process on port
    kill_port(8001)
    
    # Start API server
    api_process = subprocess.Popen(
        [sys.executable, "src/main.py", "--api-only", "--port", "8001"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # Wait for API to be ready
    print(f"{YELLOW}    Waiting for API to initialize...{RESET}")
    for i in range(10):
        if check_port(8001):
            print(f"{GREEN}    ✓ API Server online!{RESET}")
            return True
        time.sleep(1)
    
    print(f"{RED}    ✗ API Server failed to start{RESET}")
    return False

def start_frontend_server():
    """Start the frontend server"""
    global frontend_process
    print(f"{GREEN}[3/5] Starting Frontend Dashboard on port 8082...{RESET}")
    
    # Kill any existing process on port
    kill_port(8082)
    
    # Change to frontend directory and start server
    frontend_dir = Path(__file__).parent / "frontend"
    frontend_process = subprocess.Popen(
        [sys.executable, "-m", "http.server", "8082"],
        cwd=frontend_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    time.sleep(2)
    
    if check_port(8082):
        print(f"{GREEN}    ✓ Frontend Dashboard online!{RESET}")
        return True
    else:
        print(f"{RED}    ✗ Frontend failed to start{RESET}")
        return False

def open_browser():
    """Open the dashboard in browser"""
    print(f"{GREEN}[4/5] Opening dashboard in browser...{RESET}")
    try:
        webbrowser.open("http://localhost:8082")
        print(f"{GREEN}    ✓ Browser opened{RESET}")
    except:
        print(f"{YELLOW}    ! Please open http://localhost:8082 manually{RESET}")

def cleanup(signum=None, frame=None):
    """Cleanup function to stop all services"""
    print(f"\n{YELLOW}[!] Shutting down Cybernet Security Matrix...{RESET}")
    
    if api_process:
        api_process.terminate()
        api_process.wait()
    
    if frontend_process:
        frontend_process.terminate()
        frontend_process.wait()
    
    # Final cleanup of ports
    kill_port(8001)
    kill_port(8082)
    
    print(f"{GREEN}[✓] System shutdown complete{RESET}")
    sys.exit(0)

def show_status():
    """Show running status"""
    print(f"""
{GREEN}╔═══════════════════════════════════════════════════════════╗
║     ✅ CYBERNET SECURITY MATRIX ACTIVATED                ║
╚═══════════════════════════════════════════════════════════╝{RESET}

{CYAN}🌐 Dashboard:{RESET} http://localhost:8082
{CYAN}📡 API Server:{RESET} http://localhost:8001
{CYAN}📚 API Docs:{RESET} http://localhost:8001/docs

{YELLOW}[!] Press CTRL+C to shutdown{RESET}

{GREEN}═══════════════════════════════════════════════════════════
SYSTEM STATUS: MONITORING ACTIVE
═══════════════════════════════════════════════════════════{RESET}
""")

def monitor_services():
    """Monitor running services"""
    print(f"{GREEN}[5/5] Monitoring services...{RESET}\n")
    
    try:
        while True:
            # Check if services are still running
            if api_process and api_process.poll() is not None:
                print(f"{RED}[!] API Server crashed! Restarting...{RESET}")
                start_api_server()
            
            if frontend_process and frontend_process.poll() is not None:
                print(f"{RED}[!] Frontend crashed! Restarting...{RESET}")
                start_frontend_server()
            
            time.sleep(5)
            
    except KeyboardInterrupt:
        cleanup()

def main():
    """Main function"""
    # Set up signal handlers
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)
    
    # Print banner
    print_banner()
    
    # Check dependencies
    if not check_dependencies():
        print(f"{RED}Failed to install dependencies!{RESET}")
        sys.exit(1)
    
    # Start services
    if not start_api_server():
        print(f"{RED}Failed to start API server!{RESET}")
        cleanup()
        sys.exit(1)
    
    if not start_frontend_server():
        print(f"{RED}Failed to start frontend!{RESET}")
        cleanup()
        sys.exit(1)
    
    # Open browser
    open_browser()
    
    # Show status
    show_status()
    
    # Monitor services
    monitor_services()

if __name__ == "__main__":
    main()