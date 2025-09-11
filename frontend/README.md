# Network Security Monitor - Web Dashboard

A modern, real-time web dashboard for monitoring network security threats and anomalies.

## Features

- **Real-time Monitoring**: Live updates of network statistics
- **Threat Detection**: Visual alerts when threats are detected
- **Activity Timeline**: Chart showing packet analysis over time
- **Activity Log**: Detailed log of all security events
- **Auto-Refresh**: Automatic data updates every 5 seconds
- **Responsive Design**: Works on desktop and mobile devices

## How to Access

### Currently Running:
- **Dashboard**: http://localhost:8082/
- **API Server**: http://localhost:8001/

### Start Fresh:

1. **Start the API server** (if not running):
```bash
python3 src/main.py --api-only --port 8001
```

2. **Start the frontend server**:
```bash
cd frontend
python3 -m http.server 8082
```

3. **Open in browser**:
```
http://localhost:8082/
```

## Dashboard Features

### Status Cards
- **System Status**: Shows if monitoring is active
- **Packets Analyzed**: Total network packets processed
- **Threats Detected**: Number of security threats found
- **Anomalies**: Unusual patterns detected by AI
- **Health Status**: API server health
- **API Endpoint**: Connected server address

### Controls
- **Refresh**: Manually refresh all data
- **Auto-Refresh**: Toggle automatic updates (5-second interval)
- **Clear Logs**: Clear the activity log
- **Simulate Threat**: Test threat detection (for demo)

### Activity Timeline
- Blue bars: Normal packet traffic
- Red bars: Threat detections
- Yellow bars: Anomaly detections

### Activity Log
- Real-time log of all security events
- Color-coded by severity:
  - Normal entries: Gray
  - Threats: Red
  - Anomalies: Yellow

## API Integration

The dashboard connects to the Security Monitor API at `http://localhost:8001` and fetches:
- `/health` - System health status
- `/api/status` - Current monitoring statistics

## Testing Features

1. **Click "Simulate Threat"** to see how the dashboard responds to threats
2. **Enable Auto-Refresh** to see real-time updates
3. **Check Activity Log** for detailed event history

## Customization

Edit `app.js` to:
- Change API endpoint URL
- Adjust refresh interval
- Modify chart settings
- Add new features

## Browser Support

Works on all modern browsers:
- Chrome/Edge 90+
- Firefox 88+
- Safari 14+
- Mobile browsers

## Troubleshooting

If the dashboard shows "Offline":
1. Check the API server is running on port 8001
2. Check browser console for errors (F12)
3. Ensure no CORS blocking issues
4. Try refreshing the page

## Security Note

This dashboard is for monitoring purposes only. For production use:
- Add authentication
- Use HTTPS
- Implement proper access controls
- Add rate limiting