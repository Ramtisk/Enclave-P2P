#ifndef P2P_SHA256_H
#define P2P_SHA256_H

#include <stdint.h>
#include <stddef.h>

void sha256_hash(const uint8_t* data, size_t len, uint8_t* hash_out);

#endif