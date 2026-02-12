#include "hashing.h"
#include "classic.h"
#include "../common/logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================
// SHA-256 (uses chunking.c implementation already in the project)
// For consistency, we delegate to it or provide crypto-layer API
// ============================================

// Forward declaration from chunking.c
extern void sha256_hash(const uint8_t* data, size_t len, uint8_t* hash_out);