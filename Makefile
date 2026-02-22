CC = gcc
CFLAGS = -Wall -Wextra -Werror -g -I./src -pthread
LDFLAGS = -pthread

SRC_DIR = src
BUILD_DIR = build
APPS_DIR = apps

# Common
COMMON_SRC = $(SRC_DIR)/common/logging.c \
			 $(SRC_DIR)/common/protocol.c

# Group management
GROUP_SRC = $(SRC_DIR)/core/group_mgmt/group_manager.c \
			$(SRC_DIR)/core/group_mgmt/group_member.c \
			$(SRC_DIR)/core/group_mgmt/group_join.c \
			$(SRC_DIR)/core/group_mgmt/group_utils.c

# Transfer
TRANSFER_SRC = $(SRC_DIR)/transfer/sha256.c \
			   $(SRC_DIR)/transfer/chunking.c \
			   $(SRC_DIR)/transfer/transfer_context.c \
			   $(SRC_DIR)/transfer/file_manager.c \
			   $(SRC_DIR)/transfer/p2p_server.c \
			   $(SRC_DIR)/transfer/p2p_download.c

# Strategy
STRATEGY_SRC = $(SRC_DIR)/transfer/strategy/strategy_core.c \
			   $(SRC_DIR)/transfer/strategy/sequential.c \
			   $(SRC_DIR)/transfer/strategy/random.c \
			   $(SRC_DIR)/transfer/strategy/rarest_first.c

# Scheduler
SCHEDULER_SRC = $(SRC_DIR)/transfer/scheduler/priority_queue.c \
				$(SRC_DIR)/transfer/scheduler/bandwidth.c \
				$(SRC_DIR)/transfer/scheduler/scheduler_peers.c \
				$(SRC_DIR)/transfer/scheduler/scheduler_worker.c \
				$(SRC_DIR)/transfer/scheduler/scheduler.c

# NAT traversal
NAT_SRC = $(SRC_DIR)/network/nat_traversal/nat_traversal.c \
		  $(SRC_DIR)/network/nat_traversal/nat_discovery.c \
		  $(SRC_DIR)/network/nat_traversal/nat_punch.c \
		  $(SRC_DIR)/network/nat_traversal/nat_relay.c \
		  $(SRC_DIR)/network/nat_traversal/stun.c

# Relay server
RELAY_SRC = $(SRC_DIR)/network/relay/relay.c \
			$(SRC_DIR)/network/relay/relay_dispatch.c \
			$(SRC_DIR)/network/relay/relay_handlers_basic.c \
			$(SRC_DIR)/network/relay/relay_handlers_file.c \
			$(SRC_DIR)/network/relay/relay_handlers_group.c \
			$(SRC_DIR)/network/relay/relay_handlers_nat.c

# Client
CLIENT_SRC = $(SRC_DIR)/network/client/client.c \
			 $(SRC_DIR)/network/client/client_files.c \
			 $(SRC_DIR)/network/client/client_groups.c \
			 $(SRC_DIR)/network/client/client_messaging.c \
			 $(SRC_DIR)/network/client/client_nat.c \
			 $(SRC_DIR)/network/client/client_recv.c

# Shared by both binaries
SHARED_SRC = $(COMMON_SRC) $(GROUP_SRC) $(TRANSFER_SRC) $(STRATEGY_SRC) \
			 $(SCHEDULER_SRC) $(NAT_SRC)

RELAY_BIN = $(BUILD_DIR)/relay
CLIENT_BIN = $(BUILD_DIR)/client

.PHONY: all clean relay client run-relay run-client test-transfer test-groups test-nat test-nat-auto test-nat-stress

all: $(BUILD_DIR) relay client

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)
	mkdir -p data/shared data/downloads

relay: $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $(RELAY_BIN) $(APPS_DIR)/relay/main.c $(RELAY_SRC) $(SHARED_SRC) $(LDFLAGS)

client: $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $(CLIENT_BIN) $(APPS_DIR)/client/main.c $(CLIENT_SRC) $(SHARED_SRC) $(LDFLAGS)

clean:
	rm -rf $(BUILD_DIR)

run-relay: relay
	$(RELAY_BIN) -v

run-client: client
	$(CLIENT_BIN) -v

test-transfer: all
	bash scripts/test_transfer.sh

test-groups: relay client
	bash scripts/test_groups.sh

test-nat: all
	bash scripts/test_nat.sh

test-nat-auto: all
	bash scripts/test_nat_auto.sh

test-nat-stress: all
	bash scripts/test_nat_multi_peer.sh