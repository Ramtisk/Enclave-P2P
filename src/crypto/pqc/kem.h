#ifndef P2P_CRYPTO_PQC_KEM_H
#define P2P_CRYPTO_PQC_KEM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*  ============================================
    POST-QUANTUM KEM SIZES

    Note: Using X-Wing (ML-KEM-768 + X25519 hybrid) via libsodium >= 1.0.21.
    Falls back to simulated KEM for API compatibility if unavailable.
    ============================================ */
#ifdef USE_LIBSODIUM
#include <sodium.h>
#if defined(crypto_kem_PUBLICKEYBYTES)
#define PQC_KEM_AVAILABLE       1
#define PQC_KEM_PK_SIZE         crypto_kem_PUBLICKEYBYTES
#define PQC_KEM_SK_SIZE         crypto_kem_SECRETKEYBYTES
#define PQC_KEM_CT_SIZE         crypto_kem_CIPHERTEXTBYTES
#define PQC_KEM_SS_SIZE         crypto_kem_SHAREDSECRETBYTES
#define PQC_KEM_SEED_SIZE       crypto_kem_SEEDBYTES
#define PQC_KEM_NAME            "X-Wing (ML-KEM-768 + X25519)"
#else
#define PQC_KEM_AVAILABLE       0
#define PQC_KEM_PK_SIZE         1216
#define PQC_KEM_SK_SIZE         2432
#define PQC_KEM_CT_SIZE         1120
#define PQC_KEM_SS_SIZE         32
#define PQC_KEM_SEED_SIZE       96
#define PQC_KEM_NAME            "Simulated KEM (libsodium too old)"
#endif
#else
#define PQC_KEM_AVAILABLE       0
#define PQC_KEM_PK_SIZE         1216
#define PQC_KEM_SK_SIZE         2432
#define PQC_KEM_CT_SIZE         1120
#define PQC_KEM_SS_SIZE         32
#define PQC_KEM_SEED_SIZE       96
#define PQC_KEM_NAME            "Simulated KEM (no libsodium)"
#endif

/*  ============================================
    KEM RAW API

    Note: Low-level KEM operations for keypair generation,
    encapsulation, and decapsulation.
    ============================================ */
int pqc_kem_keypair(uint8_t pk[PQC_KEM_PK_SIZE],
                    uint8_t sk[PQC_KEM_SK_SIZE]);

int pqc_kem_encapsulate(uint8_t ct[PQC_KEM_CT_SIZE],
                        uint8_t ss[PQC_KEM_SS_SIZE],
                        const uint8_t pk[PQC_KEM_PK_SIZE]);

int pqc_kem_decapsulate(uint8_t ss[PQC_KEM_SS_SIZE],
                        const uint8_t ct[PQC_KEM_CT_SIZE],
                        const uint8_t sk[PQC_KEM_SK_SIZE]);

bool pqc_is_available(void);
const char* pqc_kem_name(void);

#endif