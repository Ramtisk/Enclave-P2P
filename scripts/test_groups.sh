#!/bin/bash
cd "$(dirname "$0")/.."

echo "╔════════════════════════════════════════╗"
echo "║     GROUP SYSTEM TEST                  ║"
echo "╚════════════════════════════════════════╝"

# Build
echo "[1/4] Building..."
make clean && make all

if [ $? -ne 0 ]; then
    echo "Build failed!"
    exit 1
fi

echo ""
echo "╔════════════════════════════════════════╗"
echo "║     MANUAL TEST INSTRUCTIONS           ║"
echo "╚════════════════════════════════════════╝"
echo ""
echo "Open 3 terminals and run:"
echo ""
echo "Terminal 1 (Relay):"
echo "  ./build/relay -v"
echo ""
echo "Terminal 2 (Client A - Founder):"
echo "  ./build/client -v"
echo "  > c MyGroup        # Create group"
echo "  > (note the invite token)"
echo ""
echo "Terminal 3 (Client B - Joiner):"
echo "  ./build/client -v"
echo "  > j <token>        # Join with token"
echo ""
echo "Back to Terminal 2:"
echo "  > y                # Vote YES to approve"
echo ""
echo "Terminal 4 (Client C - Outsider):"
echo "  ./build/client -v"
echo "  > j invalid_token  # Should be rejected"
echo ""
echo "Press Enter to start relay in background..."
read

./build/relay -v &
RELAY_PID=$!
sleep 1

echo "Relay started (PID: $RELAY_PID)"
echo "Now open another terminal and run: ./build/client -v"
echo ""
echo "Press Enter to stop relay..."
read

kill $RELAY_PID 2>/dev/null
echo "Test complete!"