// Configuration
const API_BASE_URL = 'http://localhost:8001';
let autoRefreshInterval = null;
let isAutoRefreshing = false;
let activityData = [];
let chartContext = null;

// Matrix Rain Effect
function initMatrixRain() {
    const canvas = document.getElementById('matrix-rain');
    const ctx = canvas.getContext('2d');
    
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    
    const matrix = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789@#$%^&*()*&^%+-/~{[|`]}10101010";
    const matrixArray = matrix.split("");
    
    const fontSize = 10;
    const columns = canvas.width / fontSize;
    
    const drops = [];
    for(let x = 0; x < columns; x++) {
        drops[x] = Math.random() * -100;
    }
    
    function drawMatrix() {
        ctx.fillStyle = 'rgba(0, 0, 0, 0.04)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        
        ctx.fillStyle = '#0f0';
        ctx.font = fontSize + 'px monospace';
        
        for(let i = 0; i < drops.length; i++) {
            const text = matrixArray[Math.floor(Math.random() * matrixArray.length)];
            ctx.fillText(text, i * fontSize, drops[i] * fontSize);
            
            if(drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                drops[i] = 0;
            }
            drops[i]++;
        }
    }
    
    setInterval(drawMatrix, 35);
}

// Binary Background Generator
function generateBinaryBackground() {
    const container = document.getElementById('binaryBg');
    let binaryString = '';
    for(let i = 0; i < 10000; i++) {
        binaryString += Math.random() > 0.5 ? '1' : '0';
        if(i % 100 === 0) binaryString += '\n';
    }
    container.textContent = binaryString;
}

// Initialize when page loads
document.addEventListener('DOMContentLoaded', () => {
    console.log('🚀 CYBERDEFENSE SYSTEM ACTIVATED');
    initMatrixRain();
    generateBinaryBackground();
    initializeChart();
    checkConnection();
    refreshData();
    startGlitchEffects();
    
    // Add typing effect to log entries
    addLogEntry('SYSTEM BOOT SEQUENCE COMPLETE', 'info');
    addLogEntry('NEURAL NETWORK INITIALIZED', 'info');
    addLogEntry('THREAT DETECTION ALGORITHMS LOADED', 'info');
});

// Glitch Effects
function startGlitchEffects() {
    setInterval(() => {
        const elements = document.querySelectorAll('.glow-green');
        elements.forEach(el => {
            if(Math.random() > 0.95) {
                el.style.textShadow = '-2px 0 #f00, 2px 0 #0ff, 0 0 20px #0f0';
                setTimeout(() => {
                    el.style.textShadow = '0 0 10px #0f0, 0 0 20px #0f0, 0 0 30px #0f0';
                }, 100);
            }
        });
    }, 2000);
}

// Check API connection
async function checkConnection() {
    const statusElement = document.getElementById('connectionStatus');
    
    try {
        const response = await fetch(`${API_BASE_URL}/health`);
        
        if (response.ok) {
            statusElement.textContent = '[ONLINE]';
            statusElement.style.color = '#0f0';
            addLogEntry('CONNECTION ESTABLISHED - SECURE CHANNEL ACTIVE', 'info');
        } else {
            throw new Error('API BREACH');
        }
    } catch (error) {
        statusElement.textContent = '[OFFLINE]';
        statusElement.style.color = '#f00';
        addLogEntry('WARNING: CONNECTION LOST - ATTEMPTING RECONNECT...', 'threat');
        console.error('SYSTEM ERROR:', error);
    }
}

// Refresh all data
async function refreshData() {
    console.log('⟳ SCANNING NETWORK...');
    
    try {
        // Fetch health status
        const healthResponse = await fetch(`${API_BASE_URL}/health`);
        if (healthResponse.ok) {
            const healthData = await healthResponse.json();
            updateHealthStatus(healthData);
        }
        
        // Fetch monitoring status
        const statusResponse = await fetch(`${API_BASE_URL}/api/status`);
        if (statusResponse.ok) {
            const statusData = await statusResponse.json();
            updateDashboard(statusData);
        }
        
        // Add scan complete entry
        addLogEntry('NETWORK SCAN COMPLETE - DATA SYNCHRONIZED', 'info');
        
    } catch (error) {
        console.error('CRITICAL ERROR:', error);
        addLogEntry('ERROR: DATA SYNCHRONIZATION FAILED - ' + error.message, 'threat');
    }
}

// Update dashboard with new data
function updateDashboard(data) {
    // Update status
    const statusEl = document.getElementById('systemStatus');
    statusEl.textContent = data.capture_status === 'active' ? 'ACTIVE' : 'STANDBY';
    statusEl.className = data.capture_status === 'active' ? 'stat-value glow-green' : 'stat-value';
    
    // Update counters with cyber effects
    animateNumber('packetsAnalyzed', data.packets_analyzed);
    
    // Check for threats
    const currentThreats = parseInt(document.getElementById('threatsDetected').textContent);
    if (data.threats_detected > currentThreats && currentThreats > 0) {
        showThreatAlert(data.threats_detected);
        document.body.style.animation = 'threat-flash 0.5s';
        setTimeout(() => {
            document.body.style.animation = '';
        }, 500);
    }
    animateNumber('threatsDetected', data.threats_detected);
    
    // Update anomalies
    animateNumber('anomaliesDetected', data.anomalies_detected);
    
    // Update chart
    updateChart(data);
}

// Update health status
function updateHealthStatus(data) {
    const healthEl = document.getElementById('healthStatus');
    healthEl.textContent = data.status.toUpperCase();
    
    const timestamp = new Date(data.timestamp);
    document.getElementById('lastUpdate').textContent = 
        `LAST SYNC: ${timestamp.toLocaleTimeString()}`;
}

// Animate number with cyber effect
function animateNumber(elementId, newValue) {
    const element = document.getElementById(elementId);
    const currentValue = parseInt(element.textContent) || 0;
    
    if (currentValue === newValue) return;
    
    // Add glitch effect during animation
    element.style.animation = 'glitch 0.3s';
    
    const increment = (newValue - currentValue) / 20;
    let current = currentValue;
    let steps = 0;
    
    const animation = setInterval(() => {
        current += increment;
        steps++;
        
        if (steps >= 20) {
            element.textContent = newValue.toLocaleString();
            clearInterval(animation);
            element.style.animation = '';
        } else {
            element.textContent = Math.round(current).toLocaleString();
        }
    }, 30);
}

// Add log entry with typing effect
function addLogEntry(message, type = 'info') {
    const logEntries = document.getElementById('logEntries');
    const entry = document.createElement('div');
    entry.className = 'log-entry';
    
    if (type === 'threat') entry.className += ' threat';
    if (type === 'anomaly') entry.className += ' anomaly';
    
    const time = new Date().toLocaleTimeString('en-US', { hour12: false });
    entry.innerHTML = `<span class="log-time">[${time}]</span> ${message}`;
    
    // Add to beginning
    logEntries.insertBefore(entry, logEntries.firstChild);
    
    // Keep only last 100 entries
    while (logEntries.children.length > 100) {
        logEntries.removeChild(logEntries.lastChild);
    }
    
    // Update count
    document.getElementById('logCount').textContent = 
        `${logEntries.children.length} ENTRIES`;
}

// Clear logs
function clearLogs() {
    const logEntries = document.getElementById('logEntries');
    logEntries.innerHTML = '';
    addLogEntry('LOGS PURGED - MEMORY CLEARED', 'info');
}

// Toggle auto-refresh
function toggleAutoRefresh() {
    const btn = document.getElementById('autoRefreshBtn');
    
    if (isAutoRefreshing) {
        clearInterval(autoRefreshInterval);
        autoRefreshInterval = null;
        isAutoRefreshing = false;
        btn.textContent = '▶ AUTO-SCAN';
        addLogEntry('AUTO-SCAN DEACTIVATED', 'info');
    } else {
        autoRefreshInterval = setInterval(refreshData, 5000);
        isAutoRefreshing = true;
        btn.textContent = '⏸ STOP SCAN';
        addLogEntry('AUTO-SCAN ACTIVATED - 5 SECOND INTERVALS', 'info');
    }
}

// Simulate threat
async function simulateThreat() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/simulate/start`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (response.ok) {
            const data = await response.json();
            await refreshData();
            
            if (data.status === 'threat_detected') {
                addLogEntry(`☠ THREAT DETECTED: ${data.threat}`, 'threat');
                addLogEntry(`SOURCE: ${data.source_ip} | SEVERITY: ${data.severity.toUpperCase()}`, 'threat');
                addLogEntry('COUNTERMEASURES DEPLOYED - THREAT NEUTRALIZED', 'info');
                showThreatAlert(data.threats_total);
            } else if (data.status === 'anomaly_detected') {
                addLogEntry(`⚠ ANOMALY: ${data.anomaly}`, 'anomaly');
                addLogEntry('NEURAL NETWORK ANALYZING PATTERN...', 'anomaly');
            } else {
                addLogEntry('SCAN COMPLETE - NO THREATS DETECTED', 'info');
            }
        }
    } catch (error) {
        console.error('SIMULATION ERROR:', error);
        addLogEntry('SIMULATION MODULE ERROR', 'threat');
    }
}

// Continuous simulation
let simulationInterval = null;
let isSimulating = false;

function toggleContinuousSimulation() {
    const btn = document.getElementById('continuousSimBtn');
    
    if (isSimulating) {
        clearInterval(simulationInterval);
        simulationInterval = null;
        isSimulating = false;
        btn.textContent = '◉ LIVE ATTACK';
        addLogEntry('ATTACK SIMULATION TERMINATED', 'info');
        fetch(`${API_BASE_URL}/api/simulate/stop`, { method: 'POST' });
    } else {
        isSimulating = true;
        btn.textContent = '■ CEASE FIRE';
        addLogEntry('INITIATING LIVE ATTACK SIMULATION...', 'threat');
        addLogEntry('WARNING: GENERATING HOSTILE TRAFFIC PATTERNS', 'threat');
        
        simulationInterval = setInterval(async () => {
            await simulateThreat();
        }, 2000);
    }
}

// Show threat alert
function showThreatAlert(threatCount) {
    const modal = document.getElementById('threatModal');
    const details = document.getElementById('threatDetails');
    
    details.innerHTML = `
        <p style="color: #f00;">⚠ SECURITY BREACH DETECTED ⚠</p>
        <p>THREAT LEVEL: <span style="color: #ff0;">CRITICAL</span></p>
        <p>TOTAL THREATS: <span style="color: #f00;">${threatCount}</span></p>
        <p>STATUS: <span style="color: #0f0;">NEUTRALIZED</span></p>
        <p style="margin-top: 10px;">FIREWALL UPDATED | IDS ACTIVE</p>
    `;
    
    modal.style.display = 'flex';
    
    // Auto-close after 3 seconds
    setTimeout(() => {
        closeThreatModal();
    }, 3000);
}

// Close threat modal
function closeThreatModal() {
    document.getElementById('threatModal').style.display = 'none';
}

// Initialize chart with cyber theme
function initializeChart() {
    const canvas = document.getElementById('chartCanvas');
    if (canvas && canvas.getContext) {
        chartContext = canvas.getContext('2d');
        canvas.width = canvas.offsetWidth;
        canvas.height = 200;
        
        // Initialize with empty data
        for (let i = 0; i < 20; i++) {
            activityData.push({
                packets: 0,
                threats: 0,
                anomalies: 0,
                time: new Date()
            });
        }
        drawCyberChart();
    }
}

// Update chart data
function updateChart(data) {
    activityData.push({
        packets: data.packets_analyzed,
        threats: data.threats_detected,
        anomalies: data.anomalies_detected,
        time: new Date()
    });
    
    if (activityData.length > 20) {
        activityData.shift();
    }
    
    drawCyberChart();
}

// Draw cyber-themed chart
function drawCyberChart() {
    if (!chartContext) return;
    
    const canvas = chartContext.canvas;
    const width = canvas.width;
    const height = canvas.height;
    
    // Clear with fade effect
    chartContext.fillStyle = 'rgba(0, 0, 0, 0.1)';
    chartContext.fillRect(0, 0, width, height);
    
    // Draw grid
    chartContext.strokeStyle = 'rgba(0, 255, 0, 0.1)';
    chartContext.lineWidth = 1;
    for (let i = 0; i <= 5; i++) {
        const y = (height / 5) * i;
        chartContext.beginPath();
        chartContext.moveTo(0, y);
        chartContext.lineTo(width, y);
        chartContext.stroke();
    }
    
    // Find max value
    let maxValue = 100;
    activityData.forEach(point => {
        maxValue = Math.max(maxValue, point.packets);
    });
    
    // Draw packet line
    chartContext.strokeStyle = '#0ff';
    chartContext.lineWidth = 2;
    chartContext.shadowColor = '#0ff';
    chartContext.shadowBlur = 10;
    chartContext.beginPath();
    
    activityData.forEach((point, index) => {
        const x = (width / activityData.length) * index;
        const y = height - (point.packets / maxValue) * height * 0.8;
        
        if (index === 0) {
            chartContext.moveTo(x, y);
        } else {
            chartContext.lineTo(x, y);
        }
    });
    chartContext.stroke();
    
    // Draw threat markers
    chartContext.fillStyle = '#f00';
    chartContext.shadowColor = '#f00';
    activityData.forEach((point, index) => {
        if (point.threats > 0) {
            const x = (width / activityData.length) * index;
            const y = height - (point.packets / maxValue) * height * 0.8;
            
            chartContext.beginPath();
            chartContext.arc(x, y, 5, 0, Math.PI * 2);
            chartContext.fill();
        }
    });
    
    // Draw anomaly markers
    chartContext.fillStyle = '#ff0';
    chartContext.shadowColor = '#ff0';
    activityData.forEach((point, index) => {
        if (point.anomalies > 0) {
            const x = (width / activityData.length) * index;
            const y = height - (point.packets / maxValue) * height * 0.8;
            
            chartContext.beginPath();
            chartContext.moveTo(x, y - 8);
            chartContext.lineTo(x - 5, y + 5);
            chartContext.lineTo(x + 5, y + 5);
            chartContext.closePath();
            chartContext.fill();
        }
    });
    
    // Reset shadow
    chartContext.shadowBlur = 0;
}

// Window resize handler
window.addEventListener('resize', () => {
    const canvas = document.getElementById('matrix-rain');
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
});