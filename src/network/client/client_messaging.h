#ifndef P2P_CLIENT_MESSAGING_H
#define P2P_CLIENT_MESSAGING_H

#include "client_types.h"

/*  ============================================
    CLIENT MESSAGING API

    Note: Low-level message send + ping.
    ============================================ */

int client_send_message(p2p_client_t* client, message_t* msg);
int client_send_ping(p2p_client_t* client);

// Callbacks
void client_set_message_callback(p2p_client_t* client,
                                  message_callback_t callback, void* user_data);

#endif // P2P_CLIENT_MESSAGING_H