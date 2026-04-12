#!/bin/bash
# Geoff Starter Script
# Run this on the test machine (192.168.1.94)

export PATH="$HOME/.npm-global/bin:$HOME/.local/bin:$PATH"

echo "=== Geoff UI Starter ==="

# Check if UI files exist
if [[ ! -d "$HOME/.geoff/ui" ]]; then
    echo "❌ UI directory not found at ~/.geoff/ui"
    echo "   Please ensure the UI files are copied there first"
    exit 1
fi

# Kill any existing UI server
echo "Stopping any existing UI server..."
pkill -f "node server.js" 2>/dev/null
sleep 2

# Check if port 8080 is in use
if ss -tlnp | grep -q ':8080 '; then
    echo "⚠️  Port 8080 is already in use"
    ss -tlnp | grep 8080
fi

# Start the UI server
echo "Starting Geoff UI server..."
cd "$HOME/.geoff/ui"

# Check if node is available
if ! command -v node &> /dev/null; then
    echo "❌ Node.js not found"
    exit 1
fi

# Start server
nohup node server.js > /tmp/geoff-ui.log 2>&1 &
SERVER_PID=$!
echo $SERVER_PID > /tmp/geoff-ui.pid

# Wait for it to start
sleep 3

# Check if running
if ps -p $SERVER_PID > /dev/null 2>&1; then
    echo "✅ Geoff UI server started (PID: $SERVER_PID)"
    
    # Check if port is listening
    if ss -tlnp | grep -q ':8080 '; then
        echo "✅ Server is listening on port 8080"
        echo ""
        echo "╔═══════════════════════════════════════╗"
        echo "║  Geoff UI is running!                 ║"
        echo "║                                       ║"
        echo "║  Open your browser to:                ║"
        echo "║  http://localhost:8080                ║"
        echo "╚═══════════════════════════════════════╝"
        echo ""
        echo "To stop: pkill -f 'node server.js'"
        echo "Logs: tail -f /tmp/geoff-ui.log"
    else
        echo "⚠️  Server started but port 8080 not responding"
        echo "Check logs: cat /tmp/geoff-ui.log"
    fi
else
    echo "❌ Failed to start server"
    echo "Check logs: cat /tmp/geoff-ui.log"
    exit 1
fi
