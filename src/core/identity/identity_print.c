#include "identity_print.h"
#include "identity_helpers.h"
#include "../../common/logging.h"

#include <stdio.h>

/*  Function: identity_print
    Description:
    Prints a peer identity in a formatted box to the log output.

    Parameters:
    - id: Pointer to the peer_identity_t structure.

    Steps:
    1. Checks if the identity is initialized; logs a message if not.
    2. Converts the fingerprint and public key prefix to hex strings.
    3. Prints peer ID, fingerprint, public key prefix, and version in a formatted box.
*/
void identity_print(const peer_identity_t *id)
{
    if (!id || !id->initialized)
    {
        LOG_INFO("identity: <not initialized>");
        return;
    }

    char fp_hex[IDENTITY_FINGERPRINT_SIZE * 2 + 1];
    identity_bytes_to_hex(id->fingerprint, IDENTITY_FINGERPRINT_SIZE,
                          fp_hex, sizeof(fp_hex));

    char pk_hex[9];
    identity_bytes_to_hex(id->sign_pk, 4, pk_hex, sizeof(pk_hex));

    LOG_INFO("╔══════════════════════════════════════╗");
    LOG_INFO("║          PEER IDENTITY               ║");
    LOG_INFO("╠══════════════════════════════════════╣");
    LOG_INFO("║  Peer ID:     %-22s ║", id->peer_id);
    LOG_INFO("║  Fingerprint: %-22s ║", fp_hex);
    LOG_INFO("║  PK (prefix): %-22s ║", pk_hex);
    LOG_INFO("║  Version:     %-22d ║", id->version);
    LOG_INFO("╚══════════════════════════════════════╝");
}

/*  Function: identity_print_group
    Description:
    Prints a group ephemeral identity to the log output.

    Parameters:
    - gid: Pointer to the group_identity_t structure.

    Steps:
    1. Checks if the group identity is active; logs a message if not.
    2. Converts the fingerprint to a hex string.
    3. Prints group ID, ephemeral ID, fingerprint, and active status.
*/
void identity_print_group(const group_identity_t *gid)
{
    if (!gid || !gid->active)
    {
        LOG_INFO("identity: <no group identity>");
        return;
    }

    char fp_hex[IDENTITY_FINGERPRINT_SIZE * 2 + 1];
    identity_bytes_to_hex(gid->fingerprint, IDENTITY_FINGERPRINT_SIZE,
                          fp_hex, sizeof(fp_hex));

    LOG_INFO("  Group: %s", gid->group_id);
    LOG_INFO("    Ephemeral ID: %s", gid->ephemeral_id);
    LOG_INFO("    Fingerprint:  %s", fp_hex);
    LOG_INFO("    Active:       %s", gid->active ? "yes" : "no");
}