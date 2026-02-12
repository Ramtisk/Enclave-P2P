CC = gcc
CFLAGS = -Wall -Wextra -Werror -g -I./src -pthread
LDFLAGS = -pthread

SRC_DIR = src
BUILD_DIR = build
APPS_DIR = apps

# Source files
STRATEGY_SRC = $(SRC_DIR)/transfer/strategy/strategy.c \
               $(SRC_DIR)/transfer/strategy/sequential.c \
               $(SRC_DIR)/transfer/strategy/random.c \
               $(SRC_DIR)/transfer/strategy/rarest_first.c
SCHEDULER_SRC = $(SRC_DIR)/transfer/scheduler.c
COMMON_SRC = $(SRC_DIR)/transfer/chunking.c $(SRC_DIR)/transfer/p2p_transfer.c \
             $(STRATEGY_SRC) $(SCHEDULER_SRC)
NAT_SRC = $(SRC_DIR)/network/nat_traversal/nat_traversal.c
RELAY_SRC = $(SRC_DIR)/network/relay.c $(SRC_DIR)/core/group_mgmt.c
CLIENT_SRC = $(SRC_DIR)/network/client.c $(COMMON_SRC) $(NAT_SRC)

RELAY_BIN = $(BUILD_DIR)/relay
CLIENT_BIN = $(BUILD_DIR)/client

.PHONY: all clean relay client run-relay run-client test-transfer test-groups

all: $(BUILD_DIR) relay client

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)
	mkdir -p data/shared data/downloads

relay: $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $(RELAY_BIN) $(APPS_DIR)/relay/main.c $(RELAY_SRC) $(COMMON_SRC) $(NAT_SRC) $(LDFLAGS)

client: $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $(CLIENT_BIN) $(APPS_DIR)/client/main.c $(CLIENT_SRC) $(LDFLAGS)

clean:
	rm -rf $(BUILD_DIR)

run-relay: relay
	$(RELAY_BIN) -v

run-client: client
	$(CLIENT_BIN) -v

test-transfer: all
	@echo "=== File Transfer Test ==="
	@echo "1. Start relay: make run-relay"
	@echo "2. Start client A: ./build/client -v"
	@echo "3. In client A: create group, share file (f <path>)"
	@echo "4. Start client B: ./build/client -v"  
	@echo "5. In client B: join group, list files (ls), download (d <hash>)"
	@echo ""
	@echo "After transfer, verify: diff original.file downloaded.file"

test-groups: relay client
	@echo "=== Testing Group System ==="
	@echo "Start relay: make run-relay"
	@echo "Start clients: make run-client"

test-nat: all
	@bash scripts/test_nat.sh

test-nat-auto: all
	@bash scripts/test_nat_auto.sh

test-nat-stress: all
	@bash scripts/test_nat_multi_peer.sh $(CLIENTS)