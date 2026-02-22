cd "$(dirname "$0")/.."

echo "=== Starting Relay ==="
./build/relay -v &
RELAY_PID=$!
sleep 1

echo "=== Starting 5 Clients ==="
for i in 1 2 3 4 5; do
    ./build/client &
    sleep 0.5
done

echo "=== Waiting 15 seconds to observe connections ==="
sleep 15

echo "=== Checking status ==="
ps aux | grep -E "build/(relay|client)" | grep -v grep

echo "=== Stopping all ==="
killall client 2>/dev/null
kill $RELAY_PID 2>/dev/null

echo "=== Test complete ==="
