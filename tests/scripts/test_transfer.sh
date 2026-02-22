#!/bin/bash
# filepath: /home/romanov/Documents/GitHub/Enclave-P2P/scripts/test_transfer.sh

cd "$(dirname "$0")/.."

echo "╔════════════════════════════════════════════════════════════╗"
echo "║              FILE TRANSFER TEST (10MB)                     ║"
echo "╚════════════════════════════════════════════════════════════╝"

# Build
echo "[1/5] Building..."
make clean && make all
if [ $? -ne 0 ]; then
    echo "Build failed!"
    exit 1
fi

# Create test file
echo "[2/5] Creating 10MB test file..."
dd if=/dev/urandom of=data/shared/test_10mb.bin bs=1M count=10 2>/dev/null
ORIGINAL_HASH=$(sha256sum data/shared/test_10mb.bin | cut -d' ' -f1)
echo "Original file hash: $ORIGINAL_HASH"

# Start relay
echo "[3/5] Starting relay server..."
./build/relay -v &
RELAY_PID=$!
sleep 1

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                    MANUAL TEST STEPS                       ║"
echo "╠════════════════════════════════════════════════════════════╣"
echo "║                                                            ║"
echo "║  TERMINAL 2 (Sender - Client A):                           ║"
echo "║  $ ./build/client -v                                       ║"
echo "║  > c TestGroup                (Create group)               ║"
echo "║  > f data/shared/test_10mb.bin (Share file)                ║"
echo "║  > (Note the file hash and invite token)                   ║"
echo "║                                                            ║"
echo "║  TERMINAL 3 (Receiver - Client B):                         ║"
echo "║  $ ./build/client -v                                       ║"
echo "║  > j <token>                   (Join group)                ║"
echo "║  > (In Terminal 2, press 'y' to approve)                   ║"
echo "║  > ls                          (List files)                ║"
echo "║  > d <hash>                    (Download file)             ║"
echo "║                                                            ║"
echo "║  VERIFY:                                                   ║"
echo "║  $ diff data/shared/test_10mb.bin data/downloads/test_10mb.bin ║"
echo "║  (Should output nothing if files are identical)            ║"
echo "║                                                            ║"
echo "╚════════════════════════════════════════════════════════════╝"

echo ""
echo "Relay is running (PID: $RELAY_PID)"
echo "Press Enter when done to cleanup..."
read

# Cleanup
kill $RELAY_PID 2>/dev/null

# Verify if download exists
if [ -f "data/downloads/test_10mb.bin" ]; then
    DOWNLOAD_HASH=$(sha256sum data/downloads/test_10mb.bin | cut -d' ' -f1)
    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║                    VERIFICATION                            ║"
    echo "╠════════════════════════════════════════════════════════════╣"
    echo "║  Original:   $ORIGINAL_HASH  ║"
    echo "║  Downloaded: $DOWNLOAD_HASH  ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    
    if [ "$ORIGINAL_HASH" == "$DOWNLOAD_HASH" ]; then
        echo "✅ SUCCESS: Files are identical!"
    else
        echo "❌ FAILURE: Files differ!"
    fi
else
    echo "Download file not found. Did you complete the transfer?"
fi

echo ""
echo "Cleaning up test files..."
rm -f data/shared/test_10mb.bin data/downloads/test_10mb.bin

echo "Test complete!"