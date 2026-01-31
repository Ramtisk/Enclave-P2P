CC = gcc
CFLAGS = -Wall -Wextra -Werror -g -I./src -pthread
LDFLAGS = -pthread

SRC_DIR = src
BUILD_DIR = build
APPS_DIR = apps

RELAY_SRC = $(SRC_DIR)/network/relay.c
CLIENT_SRC = $(SRC_DIR)/network/client.c

RELAY_BIN = $(BUILD_DIR)/relay
CLIENT_BIN = $(BUILD_DIR)/client

.PHONY: all clean relay client run-relay run-client

all: $(BUILD_DIR) relay client

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

relay: $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $(RELAY_BIN) $(APPS_DIR)/relay/main.c $(RELAY_SRC) $(LDFLAGS)

client: $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $(CLIENT_BIN) $(APPS_DIR)/client/main.c $(CLIENT_SRC) $(LDFLAGS)

clean:
	rm -rf $(BUILD_DIR)

run-relay: relay
	$(RELAY_BIN) -v

run-client: client
	$(CLIENT_BIN) -v
