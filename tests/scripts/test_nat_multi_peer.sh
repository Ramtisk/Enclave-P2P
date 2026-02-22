#!/bin/bash
cd "$(dirname "$0")/.."

NUM_CLIENTS=${1:-4}

echo "╔════════════════════════════════════════════════════════╗"
echo "║     NAT MULTI-PEER STRESS TEST ($NUM_CLIENTS clients)            ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

# Build
echo "[1/4] Building..."
make clean > /dev/null 2>&1 && make all > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "❌ Build failed!"
    exit 1
fi
echo "✅ Build OK"

# Prepare
echo "[2/4] Preparing..."
mkdir -p data/shared data/downloads
dd if=/dev/urandom of=data/shared/stress_test.bin bs=1024 count=256 2>/dev/null
echo "  Test file: 256KB"

# Cleanup function
PIDS=()
cleanup() {
    echo ""
    echo "[cleanup] Stopping all processes..."
    for pid in "${PIDS[@]}"; do
        kill $pid 2>/dev/null
    done
    wait 2>/dev/null
    rm -f /tmp/enclave_stress_*.log
    echo "Done."
}
trap cleanup EXIT

# Start relay
echo "[3/4] Starting relay..."
./build/relay -v > /tmp/enclave_stress_relay.log 2>&1 &
RELAY_PID=$!
PIDS+=($RELAY_PID)
sleep 1

if ! kill -0 $RELAY_PID 2>/dev/null; then
    echo "❌ Relay failed to start"
    exit 1
fi
echo "  Relay PID: $RELAY_PID"

# Start clients
echo "[4/4] Starting $NUM_CLIENTS clients..."
for i in $(seq 1 $NUM_CLIENTS); do
    ./build/client -v > /tmp/enclave_stress_client_${i}.log 2>&1 &
    CLIENT_PID=$!
    PIDS+=($CLIENT_PID)
    echo "  Client $i PID: $CLIENT_PID"
    sleep 0.5
done

echo ""
echo "All processes running. Waiting 10 seconds for connections + NAT discovery..."
sleep 10

echo ""
echo "╔════════════════════════════════════════════════════════╗"
echo "║                    RESULTS                            ║"
echo "╚════════════════════════════════════════════════════════╝"

# Check relay
echo ""
echo "--- Relay Status ---"
if kill -0 $RELAY_PID 2>/dev/null; then
    echo "  ✅ Relay running"
else
    echo "  ❌ Relay crashed!"
fi

CONNECT_COUNT=$(grep -c "CONNECT\|connect" /tmp/enclave_stress_relay.log 2>/dev/null || echo "0")
NAT_COUNT=$(grep -ci "NAT\|nat_discover" /tmp/enclave_stress_relay.log 2>/dev/null || echo "0")
echo "  Connection events: $CONNECT_COUNT"
echo "  NAT events: $NAT_COUNT"

# Check each client
echo ""
echo "--- Client Status ---"
CLIENTS_OK=0
CLIENTS_NAT=0

for i in $(seq 1 $NUM_CLIENTS); do
    LOG="/tmp/enclave_stress_client_${i}.log"
    STATUS=""
    
    if grep -qi "connected\|Connected" "$LOG" 2>/dev/null; then
        STATUS="✅ Connected"
        CLIENTS_OK=$((CLIENTS_OK + 1))
    else
        STATUS="❌ Not connected"
    fi
    
    if grep -qi "NAT.*discover\|public.*endpoint\|NAT.*init" "$LOG" 2>/dev/null; then
        STATUS="$STATUS | NAT ✅"
        CLIENTS_NAT=$((CLIENTS_NAT + 1))
    else
        STATUS="$STATUS | NAT ⏳"
    fi
    
    echo "  Client $i: $STATUS"
done

echo ""
echo "╔════════════════════════════════════════════════════════╗"
printf "║  Connected: %d/%d                                      ║\n" $CLIENTS_OK $NUM_CLIENTS
printf "║  NAT Init:  %d/%d                                      ║\n" $CLIENTS_NAT $NUM_CLIENTS
echo "╚════════════════════════════════════════════════════════╝"

if [ $CLIENTS_OK -eq $NUM_CLIENTS ]; then
    echo "🎉 All clients connected successfully!"
else
    echo "⚠️  Some clients failed to connect"
fi

echo ""
echo "Waiting 5 more seconds to check stability..."
sleep 5

CRASHED=0
for pid in "${PIDS[@]}"; do
    if ! kill -0 $pid 2>/dev/null; then
        CRASHED=$((CRASHED + 1))
    fi
done

if [ $CRASHED -eq 0 ]; then
    echo "✅ All processes stable (no crashes after 15s)"
else
    echo "❌ $CRASHED process(es) crashed!"
fi

echo ""
echo "Full logs available at:"
echo "  /tmp/enclave_stress_relay.log"
for i in $(seq 1 $NUM_CLIENTS); do
    echo "  /tmp/enclave_stress_client_${i}.log"
done