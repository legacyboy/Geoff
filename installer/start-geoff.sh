#!/bin/bash
# Geoff Starter Script
# Starts the Flask-based Geoff DFIR server

export PATH="$HOME/.npm-global/bin:$HOME/.local/bin:$PATH"

echo "=== Geoff DFIR Starter ==="

# Check if Geoff source files exist
if [[ ! -f "$HOME/.geoff/src/geoff_integrated.py" ]]; then
    echo "❌ Geoff Flask backend not found at ~/.geoff/src/geoff_integrated.py"
    echo "   Please run the installer first: bash install.sh"
    exit 1
fi

# Kill any existing Geoff server
echo "Stopping any existing Geoff server..."
pkill -f "geoff_integrated.py" 2>/dev/null
sleep 2

# Check if port 8080 is in use
if ss -tlnp | grep -q ':8080 '; then
    echo "⚠️  Port 8080 is already in use"
    ss -tlnp | grep 8080
fi

# Start the Flask server
echo "Starting Geoff DFIR server (Flask)..."
cd "$HOME/.geoff"

# Check if python3 is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 not found"
    exit 1
fi

# Start server
nohup python3 "$HOME/.geoff/src/geoff_integrated.py" > /tmp/geoff-server.log 2>&1 &
SERVER_PID=$!
echo $SERVER_PID > /tmp/geoff-server.pid

# Wait for it to start
sleep 3

# Check if running
if ps -p $SERVER_PID > /dev/null 2>&1; then
    echo "✅ Geoff server started (PID: $SERVER_PID)"
    
    # Check if port is listening
    if ss -tlnp | grep -q ':8080 '; then
        echo "✅ Server is listening on port 8080"
        echo ""
        echo "╔═══════════════════════════════════════╗"
        echo "║  Geoff DFIR Server is running!        ║"
        echo "║                                       ║"
        echo "║  Open your browser to:                ║"
        echo "║  http://localhost:8080                ║"
        echo "╚═══════════════════════════════════════╝"
        echo ""
        echo "To stop: pkill -f 'geoff_integrated.py'"
        echo "Logs: tail -f /tmp/geoff-server.log"
    else
        echo "⚠️  Server started but port 8080 not responding yet"
        echo "Check logs: cat /tmp/geoff-server.log"
    fi
else
    echo "❌ Failed to start server"
    echo "Check logs: cat /tmp/geoff-server.log"
    exit 1
fi
