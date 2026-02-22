#!/bin/bash
cd "$(dirname "$0")/.."

echo "╔════════════════════════════════════════════════════════╗"
echo "║           NAT TRAVERSAL TEST                          ║"
echo "╚════════════════════════════════════════════════════════╝"

# Build
echo "[1/5] Building..."
make clean && make all

if [ $? -ne 0 ]; then
    echo "❌ Build failed!"
    exit 1
fi
echo "✅ Build successful"
echo ""

# Create test file
echo "[2/5] Creating test file..."
mkdir -p data/shared data/downloads
dd if=/dev/urandom of=data/shared/nat_test_1mb.bin bs=1024 count=1024 2>/dev/null
echo "✅ Test file created: data/shared/nat_test_1mb.bin (1MB)"
echo ""

# Clean old downloads
rm -f data/downloads/nat_test_1mb.bin

echo "╔════════════════════════════════════════════════════════╗"
echo "║           MANUAL TEST INSTRUCTIONS                    ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""
echo "Open 3 terminals and follow these steps:"
echo ""
echo "┌──────────────────────────────────────────────────────┐"
echo "│ Terminal 1 (Relay Server):                           │"
echo "│   ./build/relay -v                                   │"
echo "│                                                      │"
echo "│ Terminal 2 (Client A — File Owner):                  │"
echo "│   ./build/client -v                                  │"
echo "│   > nat              # Check NAT status              │"
echo "│   > c NATTestGroup   # Create group                  │"
echo "│   > (note the invite token)                          │"
echo "│   > f data/shared/nat_test_1mb.bin  # Share file     │"
echo "│                                                      │"
echo "│ Terminal 3 (Client B — Downloader):                  │"
echo "│   ./build/client -v                                  │"
echo "│   > nat              # Check NAT status              │"
echo "│   > j <token>        # Join with token               │"
echo "│                                                      │"
echo "│ Back to Terminal 2:                                  │"
echo "│   > y                # Vote YES to approve           │"
echo "│                                                      │"
echo "│ Back to Terminal 3:                                  │"
echo "│   > ls               # List available files          │"
echo "│   > d <hash>         # Download — triggers NAT punch │"
echo "│                                                      │"
echo "│ Verify:                                              │"
echo "│   diff data/shared/nat_test_1mb.bin \\                │"
echo "│        data/downloads/nat_test_1mb.bin               │"
echo "│   (no output = identical = success)                  │"
echo "└──────────────────────────────────────────────────────┘"
echo ""
echo "╔════════════════════════════════════════════════════════╗"
echo "║           EXPECTED NAT OUTPUT                         ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""
echo "When typing 'nat' you should see:"
echo "  ╔════════════════════════════════════════╗"
echo "  ║           NAT STATUS                   ║"
echo "  ╠════════════════════════════════════════╣"
echo "  ║  Local IP:    192.168.x.x              ║"
echo "  ║  Local Port:  7xxx                     ║"
echo "  ║  Public IP:   <your public IP>         ║"
echo "  ║  Public Port: <mapped port>            ║"
echo "  ║  NAT Type:    No NAT / Restricted...   ║"
echo "  ║  Discovered:  Yes                      ║"
echo "  ╚════════════════════════════════════════╝"
echo ""
echo "On LAN (same network), NAT Type should be 'No NAT (Public IP)'"
echo "because relay sees the same IP the client reports."
echo ""
echo "Press Enter to start relay in background..."
read

./build/relay -v &
RELAY_PID=$!
sleep 1

echo ""
echo "✅ Relay started (PID: $RELAY_PID)"
echo ""
echo "Now open 2 more terminals and follow the steps above."
echo "Press Enter to stop relay when done..."
read

kill $RELAY_PID 2>/dev/null
wait $RELAY_PID 2>/dev/null
echo ""
echo "✅ Relay stopped. Test complete!"