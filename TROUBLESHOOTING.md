# DDoS Detection System - Troubleshooting Guide

## Common Issues and Solutions

### 1. UI Not Updating / No Traffic Display

**Symptoms:**
- Dashboard shows 0 active connections
- Traffic chart is empty
- No real-time updates

**Causes & Solutions:**

#### A. Packet Sniffing Not Working
- **Windows Permission Issues**: Packet sniffing requires administrator privileges
- **Solution**: Run the application as Administrator
- **Alternative**: Use the "Generate Test Traffic" button to create simulated traffic

#### B. WebSocket Connection Issues
- **Check Browser Console**: Look for WebSocket connection errors
- **Solution**: Ensure the server is running and accessible at http://localhost:5000
- **Refresh**: Use the "Refresh Data" button to reconnect

#### C. Background Threads Not Running
- **Check Logs**: Look for errors in `ddos_detection.log`
- **Solution**: Restart the application

### 2. Application Won't Start

**Symptoms:**
- Python errors on startup
- Missing dependencies
- Port already in use

**Solutions:**

#### A. Install Dependencies
```bash
pip install -r requirements.txt
```

#### B. Check Port Availability
```bash
# Windows
netstat -an | findstr :5000

# If port is in use, kill the process or change the port in config.py
```

#### C. Python Version
- Ensure Python 3.8+ is installed
- Check with: `python --version`

### 3. No Network Traffic Detection

**Symptoms:**
- Packet capture not working
- No real network data

**Solutions:**

#### A. Run as Administrator (Windows)
- Right-click on Command Prompt/PowerShell
- Select "Run as Administrator"
- Navigate to project directory and run the application

#### B. Check Network Interface
- The application auto-detects network interfaces
- Check logs for interface detection messages
- Manually specify interface in config.py if needed

#### C. Use Test Traffic
- Click "Generate Test Traffic" button
- This creates simulated network activity for testing

### 4. Web Interface Issues

**Symptoms:**
- Page not loading
- JavaScript errors
- Charts not displaying

**Solutions:**

#### A. Check Browser Console
- Press F12 to open Developer Tools
- Look for JavaScript errors in Console tab
- Check Network tab for failed requests

#### B. Clear Browser Cache
- Hard refresh: Ctrl+F5
- Clear browser cache and cookies

#### C. Check WebSocket Connection
- Look for connection status in top-right corner
- Should show "Connected" with green dot
- If disconnected, refresh the page

## Testing the Application

### 1. Basic Functionality Test
```bash
python test_app.py
```

### 2. Manual Testing
1. Start the application
2. Open http://localhost:5000 in browser
3. Click "Generate Test Traffic"
4. Watch for real-time updates
5. Check browser console for WebSocket messages

### 3. API Endpoints Test
```bash
# Test server status
curl http://localhost:5000/test

# Generate test traffic
curl -X POST http://localhost:5000/api/generate-test-traffic

# Get statistics
curl http://localhost:5000/api/stats
```

## Debug Mode

### Enable Debug Logging
Set environment variable or modify config.py:
```python
DEBUG = True
LOG_LEVEL = 'DEBUG'
```

### Check Logs
- Application logs: `ddos_detection.log`
- Browser console: F12 → Console tab
- Network tab: Monitor WebSocket connections

## Performance Issues

### High CPU Usage
- Reduce traffic analysis frequency
- Increase sleep intervals in background threads
- Limit maximum data points in charts

### Memory Issues
- Reduce HISTORY_WINDOW in config.py
- Clean up old data more frequently
- Monitor memory usage in Task Manager

## Network Configuration

### Firewall Settings
- Allow Python/application through Windows Firewall
- Check antivirus software blocking network access
- Ensure port 5000 is accessible

### Network Interface Selection
- Automatic detection works for most cases
- Manual override in config.py if needed:
```python
INTERFACE = 'your_interface_name'
```

## Getting Help

### Check Logs First
- `ddos_detection.log` contains detailed error information
- Look for ERROR or WARNING messages
- Check timestamps for correlation with issues

### Common Error Messages
- **"Permission denied"**: Run as Administrator
- **"Port already in use"**: Kill existing process or change port
- **"Module not found"**: Install missing dependencies
- **"WebSocket connection failed"**: Check server status and firewall

### Support
- Check the main README.md for setup instructions
- Review error logs for specific error messages
- Ensure all dependencies are properly installed
- Test with the provided test script first
