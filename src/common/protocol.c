#define _POSIX_C_SOURCE 200809L
#include "protocol.h"

#include <string.h>
#include <time.h>

/*  Function: message_header_init
    Description:
    Initializes a message header structure with default values and sets the message type and timestamp.

    Parameters:
    - header: Pointer to the message_header_t structure to initialize.
    - type: The message_type_t value to set as the message type.

    Steps:
    1. Clears the header memory to zero.
    2. Sets the protocol magic number and version.
    3. Sets the message type and flags to zero.
    4. Sets the payload length to zero.
    5. Sets the timestamp to the current time in milliseconds since epoch.
    6. Leaves sender_id and target_id empty (to be filled by caller).
*/
void message_header_init(message_header_t *header, message_type_t type)
{
    memset(header, 0, sizeof(message_header_t));
    header->magic = PROTOCOL_MAGIC;
    header->version = PROTOCOL_VERSION;
    header->type = (uint8_t)type;
    header->flags = 0;
    header->payload_length = 0;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    header->timestamp = (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/*  Function: message_validate
    Description:
    Validates a message structure for protocol correctness.

    Parameters:
    - msg: Pointer to the message_t structure to validate.

    Returns:
    - 0 if the message is valid.
    - -1 if the pointer is NULL.
    - -2 if the magic number is incorrect.
    - -3 if the protocol version is incorrect.
    - -4 if the payload length exceeds the maximum allowed.
*/
int message_validate(const message_t *msg)
{
    if (!msg)
        return -1;
    if (msg->header.magic != PROTOCOL_MAGIC)
        return -2;
    if (msg->header.version != PROTOCOL_VERSION)
        return -3;
    if (msg->header.payload_length > MAX_PAYLOAD_SIZE)
        return -4;
    return 0;
}

/*  Function: message_total_size
    Description:
    Calculates the total size of a message, including header and payload.

    Parameters:
    - msg: Pointer to the message_t structure.

    Returns:
    - The total size in bytes (header + payload).
*/
size_t message_total_size(const message_t *msg)
{
    return sizeof(message_header_t) + msg->header.payload_length;
}

/*  Function: message_type_string
    Description:
    Returns a human-readable string for a given message type.

    Parameters:
    - type: The message_type_t value.

    Returns:
    - A constant string representing the message type (e.g., "CONNECT", "PING").
    - Returns "UNKNOWN" if the type is not recognized.
*/
const char *message_type_string(message_type_t type)
{
    switch (type)
    {
    case MSG_CONNECT: return "CONNECT";
    case MSG_DISCONNECT: return "DISCONNECT";
    case MSG_ACK: return "ACK";
    case MSG_NACK: return "NACK";
    case MSG_PING: return "PING";
    case MSG_PONG: return "PONG";
    case MSG_GROUP_CREATE: return "GROUP_CREATE";
    case MSG_GROUP_JOIN: return "GROUP_JOIN";
    case MSG_GROUP_LEAVE: return "GROUP_LEAVE";
    case MSG_GROUP_VOTE: return "GROUP_VOTE";
    case MSG_GROUP_INVITE: return "GROUP_INVITE";
    case MSG_GROUP_VOTE_REQ: return "GROUP_VOTE_REQ";
    case MSG_GROUP_APPROVED: return "GROUP_APPROVED";
    case MSG_GROUP_REJECTED: return "GROUP_REJECTED";
    case MSG_GROUP_INFO: return "GROUP_INFO";
    case MSG_FILE_ANNOUNCE: return "FILE_ANNOUNCE";
    case MSG_FILE_LIST: return "FILE_LIST";
    case MSG_FILE_REQUEST: return "FILE_REQUEST";
    case MSG_FILE_METADATA: return "FILE_METADATA";
    case MSG_CHUNK_REQUEST: return "CHUNK_REQUEST";
    case MSG_CHUNK_DATA: return "CHUNK_DATA";
    case MSG_CHUNK_ACK: return "CHUNK_ACK";
    case MSG_TRANSFER_COMPLETE: return "TRANSFER_COMPLETE";
    case MSG_P2P_CONNECT: return "P2P_CONNECT";
    case MSG_P2P_ACCEPT: return "P2P_ACCEPT";
    case MSG_P2P_REJECT: return "P2P_REJECT";
    case MSG_PEER_LIST: return "PEER_LIST";
    case MSG_NAT_DISCOVER: return "NAT_DISCOVER";
    case MSG_NAT_INFO: return "NAT_INFO";
    case MSG_NAT_PUNCH_REQ: return "NAT_PUNCH_REQ";
    case MSG_NAT_PUNCH_INSTR: return "NAT_PUNCH_INSTR";
    case MSG_NAT_PUNCH_RESULT: return "NAT_PUNCH_RESULT";
    case MSG_NAT_RELAY_DATA: return "NAT_RELAY_DATA";
    default: return "UNKNOWN";
    }
}