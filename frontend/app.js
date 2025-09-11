// Configuration
const API_BASE_URL = 'http://localhost:8001';
let autoRefreshInterval = null;
let isAutoRefreshing = false;
let activityData = [];
let chartContext = null;

// Initialize when page loads
document.addEventListener('DOMContentLoaded', () => {
    console.log('🚀 Dashboard initialized');
    initializeChart();
    checkConnection();
    refreshData();
});

// Check API connection
async function checkConnection() {
    const statusBadge = document.getElementById('connectionStatus');
    const spinner = document.getElementById('loadingSpinner');
    
    try {
        spinner.style.display = 'inline-block';
        const response = await fetch(`${API_BASE_URL}/health`);
        
        if (response.ok) {
            statusBadge.textContent = 'Online';
            statusBadge.className = 'status-badge status-online';
            showAlert('Connected to API successfully!', 'success');
        } else {
            throw new Error('API not responding');
        }
    } catch (error) {
        statusBadge.textContent = 'Offline';
        statusBadge.className = 'status-badge status-offline';
        showAlert('Cannot connect to API. Make sure the server is running on port 8001.', 'danger');
        console.error('Connection error:', error);
    } finally {
        spinner.style.display = 'none';
    }
}

// Refresh all data
async function refreshData() {
    console.log('🔄 Refreshing data...');
    const spinner = document.getElementById('loadingSpinner');
    spinner.style.display = 'inline-block';
    
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
        
        // Add log entry
        addLogEntry('Data refreshed successfully', 'info');
        
    } catch (error) {
        console.error('Error refreshing data:', error);
        addLogEntry('Failed to refresh data: ' + error.message, 'error');
    } finally {
        spinner.style.display = 'none';
    }
}

// Update dashboard with new data
function updateDashboard(data) {
    // Update status cards
    document.getElementById('systemStatus').textContent = 
        data.capture_status.charAt(0).toUpperCase() + data.capture_status.slice(1);
    
    // Update packet count with animation
    animateNumber('packetsAnalyzed', data.packets_analyzed);
    
    // Update threats with alert if increased
    const currentThreats = parseInt(document.getElementById('threatsDetected').textContent);
    if (data.threats_detected > currentThreats && currentThreats > 0) {
        showThreatAlert(data.threats_detected);
    }
    animateNumber('threatsDetected', data.threats_detected);
    
    // Update anomalies
    animateNumber('anomaliesDetected', data.anomalies_detected);
    
    // Update chart
    updateChart(data);
    
    // Update log count
    const logEntries = document.querySelectorAll('.log-entry').length;
    document.getElementById('logCount').textContent = `${logEntries} entries`;
}

// Update health status
function updateHealthStatus(data) {
    document.getElementById('healthStatus').textContent = 
        data.status.charAt(0).toUpperCase() + data.status.slice(1);
    
    const timestamp = new Date(data.timestamp);
    document.getElementById('lastUpdate').textContent = 
        `Last update: ${timestamp.toLocaleTimeString()}`;
}

// Animate number changes
function animateNumber(elementId, newValue) {
    const element = document.getElementById(elementId);
    const currentValue = parseInt(element.textContent) || 0;
    
    if (currentValue === newValue) return;
    
    const increment = (newValue - currentValue) / 20;
    let current = currentValue;
    let steps = 0;
    
    const animation = setInterval(() => {
        current += increment;
        steps++;
        
        if (steps >= 20) {
            element.textContent = newValue;
            clearInterval(animation);
        } else {
            element.textContent = Math.round(current);
        }
    }, 30);
}

// Add log entry
function addLogEntry(message, type = 'info') {
    const logEntries = document.getElementById('logEntries');
    const entry = document.createElement('div');
    entry.className = 'log-entry';
    
    if (type === 'threat') entry.className += ' threat';
    if (type === 'anomaly') entry.className += ' anomaly';
    
    const time = new Date().toLocaleTimeString();
    entry.innerHTML = `
        <div class="log-time">${time}</div>
        <div class="log-message">${message}</div>
    `;
    
    // Add to beginning of log
    logEntries.insertBefore(entry, logEntries.firstChild);
    
    // Keep only last 50 entries
    while (logEntries.children.length > 50) {
        logEntries.removeChild(logEntries.lastChild);
    }
    
    // Update count
    document.getElementById('logCount').textContent = 
        `${logEntries.children.length} entries`;
}

// Clear logs
function clearLogs() {
    const logEntries = document.getElementById('logEntries');
    logEntries.innerHTML = '';
    addLogEntry('Logs cleared', 'info');
}

// Toggle auto-refresh
function toggleAutoRefresh() {
    const btn = document.getElementById('autoRefreshBtn');
    
    if (isAutoRefreshing) {
        // Stop auto-refresh
        clearInterval(autoRefreshInterval);
        autoRefreshInterval = null;
        isAutoRefreshing = false;
        btn.textContent = '▶️ Start Auto-Refresh';
        addLogEntry('Auto-refresh stopped', 'info');
    } else {
        // Start auto-refresh (every 5 seconds)
        autoRefreshInterval = setInterval(refreshData, 5000);
        isAutoRefreshing = true;
        btn.textContent = '⏸️ Stop Auto-Refresh';
        addLogEntry('Auto-refresh started (5s interval)', 'info');
    }
}

// Simulate threat (for testing)
function simulateThreat() {
    const threats = parseInt(document.getElementById('threatsDetected').textContent) || 0;
    const packets = parseInt(document.getElementById('packetsAnalyzed').textContent) || 0;
    
    // Update values
    animateNumber('threatsDetected', threats + 1);
    animateNumber('packetsAnalyzed', packets + 100);
    
    // Show threat alert
    showThreatAlert(threats + 1);
    
    // Add log entries
    addLogEntry('⚠️ THREAT DETECTED: Port scan attempt from 192.168.1.100', 'threat');
    addLogEntry('Automatic response: IP blocked in firewall', 'info');
    
    // Update chart
    updateChart({
        threats_detected: threats + 1,
        packets_analyzed: packets + 100,
        anomalies_detected: parseInt(document.getElementById('anomaliesDetected').textContent) || 0
    });
}

// Show threat alert modal
function showThreatAlert(threatCount) {
    const modal = document.getElementById('threatModal');
    const details = document.getElementById('threatDetails');
    
    details.innerHTML = `
        <p><strong>Alert Level:</strong> High</p>
        <p><strong>Total Threats:</strong> ${threatCount}</p>
        <p><strong>Action Taken:</strong> Automatic blocking enabled</p>
        <p><strong>Recommendation:</strong> Review security logs for details</p>
    `;
    
    modal.style.display = 'flex';
    
    // Auto-close after 5 seconds
    setTimeout(() => {
        closeThreatModal();
    }, 5000);
}

// Close threat modal
function closeThreatModal() {
    document.getElementById('threatModal').style.display = 'none';
}

// Show alert message
function showAlert(message, type = 'info') {
    const alertBox = document.getElementById('alertBox');
    alertBox.className = `alert alert-${type}`;
    alertBox.textContent = message;
    alertBox.style.display = 'block';
    
    // Hide after 3 seconds
    setTimeout(() => {
        alertBox.style.display = 'none';
    }, 3000);
}

// Initialize chart
function initializeChart() {
    const canvas = document.getElementById('chartCanvas');
    if (canvas && canvas.getContext) {
        chartContext = canvas.getContext('2d');
        // Initialize with empty data
        for (let i = 0; i < 10; i++) {
            activityData.push({
                packets: 0,
                threats: 0,
                anomalies: 0,
                time: new Date()
            });
        }
        drawChart();
    }
}

// Update chart with new data
function updateChart(data) {
    // Add new data point
    activityData.push({
        packets: data.packets_analyzed,
        threats: data.threats_detected,
        anomalies: data.anomalies_detected,
        time: new Date()
    });
    
    // Keep only last 10 points
    if (activityData.length > 10) {
        activityData.shift();
    }
    
    drawChart();
}

// Draw chart
function drawChart() {
    if (!chartContext) return;
    
    const canvas = chartContext.canvas;
    const width = canvas.width;
    const height = canvas.height;
    
    // Clear canvas
    chartContext.clearRect(0, 0, width, height);
    
    // Find max value for scaling
    let maxValue = 1;
    activityData.forEach(point => {
        maxValue = Math.max(maxValue, point.packets, point.threats * 100, point.anomalies * 50);
    });
    
    // Draw grid lines
    chartContext.strokeStyle = '#e5e7eb';
    chartContext.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
        const y = (height / 4) * i;
        chartContext.beginPath();
        chartContext.moveTo(0, y);
        chartContext.lineTo(width, y);
        chartContext.stroke();
    }
    
    // Draw data lines
    const barWidth = width / activityData.length;
    
    activityData.forEach((point, index) => {
        const x = index * barWidth;
        
        // Draw packets bar (blue)
        const packetsHeight = (point.packets / maxValue) * height * 0.8;
        chartContext.fillStyle = 'rgba(59, 130, 246, 0.6)';
        chartContext.fillRect(x + 5, height - packetsHeight, barWidth - 10, packetsHeight);
        
        // Draw threats indicator (red)
        if (point.threats > 0) {
            const threatsHeight = (point.threats * 100 / maxValue) * height * 0.8;
            chartContext.fillStyle = 'rgba(239, 68, 68, 0.8)';
            chartContext.fillRect(x + barWidth/3, height - threatsHeight, barWidth/3, threatsHeight);
        }
        
        // Draw anomalies indicator (yellow)
        if (point.anomalies > 0) {
            const anomaliesHeight = (point.anomalies * 50 / maxValue) * height * 0.8;
            chartContext.fillStyle = 'rgba(245, 158, 11, 0.8)';
            chartContext.fillRect(x + barWidth/2, height - anomaliesHeight, barWidth/3, anomaliesHeight);
        }
    });
    
    // Draw labels
    chartContext.fillStyle = '#6b7280';
    chartContext.font = '12px sans-serif';
    chartContext.fillText('Packets', 10, 20);
    chartContext.fillStyle = 'rgba(239, 68, 68, 0.8)';
    chartContext.fillText('Threats', 70, 20);
    chartContext.fillStyle = 'rgba(245, 158, 11, 0.8)';
    chartContext.fillText('Anomalies', 130, 20);
}

// WebSocket connection for real-time updates (optional)
function connectWebSocket() {
    try {
        const ws = new WebSocket('ws://localhost:8001/ws');
        
        ws.onopen = () => {
            console.log('WebSocket connected');
            addLogEntry('Real-time connection established', 'info');
        };
        
        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            console.log('WebSocket message:', data);
            
            // Update dashboard with real-time data
            if (data.type === 'threat') {
                addLogEntry(`🚨 Real-time threat: ${data.message}`, 'threat');
            } else if (data.type === 'anomaly') {
                addLogEntry(`⚡ Real-time anomaly: ${data.message}`, 'anomaly');
            }
            
            // Refresh dashboard
            refreshData();
        };
        
        ws.onerror = (error) => {
            console.error('WebSocket error:', error);
        };
        
        ws.onclose = () => {
            console.log('WebSocket disconnected');
            addLogEntry('Real-time connection lost', 'error');
            
            // Try to reconnect after 5 seconds
            setTimeout(connectWebSocket, 5000);
        };
        
    } catch (error) {
        console.error('WebSocket connection failed:', error);
    }
}

// Try to establish WebSocket connection
// connectWebSocket(); // Uncomment when WebSocket endpoint is available