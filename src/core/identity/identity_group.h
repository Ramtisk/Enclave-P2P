#ifndef P2P_IDENTITY_GROUP_H
#define P2P_IDENTITY_GROUP_H

#include "identity_types.h"

/*  ============================================
    GROUP EPHEMERAL IDENTITY API

    Note: Functions for creating, verifying, signing, and
    verifying group ephemeral identities used for unlinkability.
    ============================================ */
int identity_create_group_ephemeral(peer_identity_t *long_term,
                                    group_identity_t *gid,
                                    const char *group_id_str);
int identity_verify_binding(const uint8_t long_term_pk[CRYPTO_SIGN_PK_SIZE],
                            const group_identity_t *ephemeral);
int identity_group_sign(const group_identity_t *gid,
                        uint8_t *sig, size_t *sig_len,
                        const uint8_t *data, size_t data_len);
int identity_group_verify(const uint8_t ephemeral_pk[CRYPTO_SIGN_PK_SIZE],
                          const uint8_t *sig,
                          const uint8_t *data, size_t data_len);

#endif