#ifndef P2P_GALOIS_H
#define P2P_GALOIS_H

#include <stdint.h>
#include <stddef.h>

// ============================================
// GALOIS FIELD GF(2^8)
// ============================================
// Polynomial: x^8 + x^4 + x^3 + x^2 + 1 (0x11D)
// This is the same irreducible polynomial used by
// Reed-Solomon in RAID-6, QR codes, etc.
//
// All operations are over 256 elements {0..255}

#define GF_FIELD_SIZE   256
#define GF_POLYNOMIAL   0x11D   // x^8 + x^4 + x^3 + x^2 + 1
#define GF_GENERATOR    2       // Primitive element α = 2

// ============================================
// INITIALIZATION
// ============================================

// Build log/exp/mul tables (call once at startup)
void gf_init(void);

// ============================================
// FIELD ARITHMETIC
// ============================================

// Addition in GF(2^8) = XOR
static inline uint8_t gf_add(uint8_t a, uint8_t b) {
    return a ^ b;
}

// Subtraction in GF(2^8) = XOR (same as addition)
static inline uint8_t gf_sub(uint8_t a, uint8_t b) {
    return a ^ b;
}

// Multiplication using lookup tables
uint8_t gf_mul(uint8_t a, uint8_t b);

// Division: a / b (b must be non-zero)
uint8_t gf_div(uint8_t a, uint8_t b);

// Multiplicative inverse: 1/a (a must be non-zero)
uint8_t gf_inv(uint8_t a);

// Exponentiation: a^n
uint8_t gf_pow(uint8_t a, uint8_t n);

// ============================================
// VECTOR OPERATIONS (over byte arrays)
// ============================================

// dst[i] ^= src[i] for len bytes
void gf_vec_add(uint8_t* dst, const uint8_t* src, size_t len);

// dst[i] = src[i] * scalar for len bytes
void gf_vec_scale(uint8_t* dst, const uint8_t* src, uint8_t scalar, size_t len);

// dst[i] += src[i] * scalar (i.e., dst[i] ^= src[i] * scalar)
void gf_vec_muladd(uint8_t* dst, const uint8_t* src, uint8_t scalar, size_t len);

// ============================================
// MATRIX OPERATIONS (for Reed-Solomon)
// ============================================

// Matrix stored as row-major: matrix[row * cols + col]

// Create Vandermonde matrix (n rows × k cols)
// Used to generate encoding matrix for Reed-Solomon
// matrix[i][j] = generator^(i*j)
void gf_matrix_vandermonde(uint8_t* matrix, int rows, int cols);

// Create Cauchy matrix (n rows × k cols)
// matrix[i][j] = 1 / (x[i] ^ y[j])
// Better numerical properties than Vandermonde
void gf_matrix_cauchy(uint8_t* matrix, int rows, int cols);

// Invert a square matrix in-place (Gauss-Jordan)
// Returns 0 on success, -1 if singular
int gf_matrix_invert(uint8_t* matrix, int n);

// Multiply: result = A × B
// A is (rows_a × cols_a), B is (cols_a × cols_b)
void gf_matrix_multiply(uint8_t* result,
                        const uint8_t* a, int rows_a, int cols_a,
                        const uint8_t* b, int cols_b);

// Multiply matrix by data vectors
// Encodes k data shards into n total shards
// matrix: n × k encoding matrix
// data_in: k pointers to shard_size buffers
// data_out: n pointers to shard_size buffers
void gf_matrix_encode(const uint8_t* matrix, int n, int k,
                      const uint8_t** data_in, uint8_t** data_out,
                      size_t shard_size);

// ============================================
// TABLE ACCESS (for debugging/testing)
// ============================================

// Get the log table value: log_α(x)
uint8_t gf_log(uint8_t x);

// Get the exp table value: α^x
uint8_t gf_exp(uint8_t x);

#endif // P2P_GALOIS_H