# 🛡️ CYBERNET SECURITY MATRIX

A Matrix-themed network security monitoring system with real-time threat detection.

## 🚀 Quick Start - ONE COMMAND!

### Option 1: Shell Script (Recommended)
```bash
./start.sh
```

### Option 2: Python Script
```bash
python3 start.py
```

### Option 3: Manual Start (if scripts don't work)
```bash
# Terminal 1 - API Server
python3 src/main.py --api-only --port 8001

# Terminal 2 - Dashboard
cd frontend && python3 -m http.server 8082
```

**That's it!** The dashboard will open automatically at **http://localhost:8082**

## ✨ Features

- **Matrix Rain Animation** - Falling green code effect
- **Real-time Threat Detection** - Live security monitoring
- **Cyber Terminal** - Hacker-style log display
- **Threat Simulation** - Generate test attacks
- **Glowing Neon UI** - Green/red/yellow cyber effects
- **Activity Timeline** - Visual threat chart

## 📁 Project Structure

```
├── frontend/
│   ├── index.html    # Hacker dashboard UI
│   └── app.js        # Dashboard logic
├── src/
│   ├── main.py       # Main application
│   ├── api/
│   │   └── server.py # API endpoints
│   ├── core/         # Network monitoring
│   ├── security/     # Threat detection
│   └── ml/           # Anomaly detection
└── requirements.txt
```

## 🎮 Dashboard Controls

- **LIVE ATTACK** - Start continuous threat simulation
- **SIMULATE** - Generate single threat
- **AUTO-SCAN** - Enable auto-refresh
- **PURGE LOGS** - Clear terminal

## 🔧 Running Modes

### API-Only Mode (No sudo)
```bash
python3 src/main.py --api-only --port 8001
```

### Full Monitoring (Requires sudo)
```bash
sudo python3 src/main.py --port 8001
```

## 🎨 Dashboard Theme

- Black background with Matrix effects
- Green glowing text (#0f0)
- Red threat alerts (#f00)
- Yellow anomalies (#ff0)
- Binary code animations

## 📊 API Endpoints

- `GET /` - API info
- `GET /health` - System health
- `GET /api/status` - Current statistics
- `POST /api/simulate/start` - Generate threat
- `POST /api/simulate/stop` - Stop simulation

## 🖥️ Requirements

- Python 3.9+
- Modern web browser
- Network interface (for full mode)

## 🚨 Security Features

- Port scan detection
- DDoS attack recognition
- SQL injection detection
- Malware traffic identification
- Anomaly detection with ML

---

**CYBERNET SECURITY MATRIX v2.0** | Neural Network Active
