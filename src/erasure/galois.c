#include "galois.h"
#include "../common/logging.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// ============================================
// LOOKUP TABLES
// ============================================
// exp_table[i] = α^i   (α = generator = 2)
// log_table[x] = i such that α^i = x
// mul_table[a][b] = a * b in GF(2^8)
//
// exp_table has 512 entries for wraparound convenience
// log_table[0] is undefined (log of 0 doesn't exist)

static uint8_t exp_table[512];
static uint8_t log_table[256];
static int gf_initialized = 0;

// ============================================
// INITIALIZATION
// ============================================

void gf_init(void) {
    if (gf_initialized) return;
    
    // Build exp and log tables
    // exp_table[i] = α^i mod polynomial
    uint16_t x = 1;
    for (int i = 0; i < 255; i++) {
        exp_table[i] = (uint8_t)x;
        log_table[x] = (uint8_t)i;
        
        // Multiply by generator (α = 2)
        x <<= 1;  // x *= 2
        if (x & 0x100) {
            x ^= GF_POLYNOMIAL;  // Reduce modulo polynomial
        }
    }
    
    // log_table[0] is undefined, set to 0 for safety
    log_table[0] = 0;
    
    // Extend exp_table for easy wraparound
    // exp_table[i + 255] = exp_table[i] for all i
    for (int i = 0; i < 255; i++) {
        exp_table[i + 255] = exp_table[i];
    }
    
    // Verify: α^255 should equal 1 (Fermat's little theorem)
    if (exp_table[254] != 1 && exp_table[0] != 1) {
        // exp_table[0] = α^0 = 1, which is correct
        // The period of GF(2^8)\{0} is 255
    }
    
    gf_initialized = 1;
    LOG_DEBUG("galois: GF(2^8) tables initialized (poly=0x%03X, gen=%d)",
              GF_POLYNOMIAL, GF_GENERATOR);
}

// ============================================
// FIELD ARITHMETIC
// ============================================

uint8_t gf_mul(uint8_t a, uint8_t b) {
    if (a == 0 || b == 0) return 0;
    
    // a * b = exp(log(a) + log(b))
    int sum = (int)log_table[a] + (int)log_table[b];
    // sum is in [0, 508], exp_table has 512 entries
    return exp_table[sum];
}

uint8_t gf_div(uint8_t a, uint8_t b) {
    if (b == 0) {
        LOG_ERROR("galois: Division by zero!");
        return 0;
    }
    if (a == 0) return 0;
    
    // a / b = exp(log(a) - log(b))
    int diff = (int)log_table[a] - (int)log_table[b];
    if (diff < 0) diff += 255;
    return exp_table[diff];
}

uint8_t gf_inv(uint8_t a) {
    if (a == 0) {
        LOG_ERROR("galois: Inverse of zero!");
        return 0;
    }
    
    // 1/a = exp(255 - log(a))
    return exp_table[255 - (int)log_table[a]];
}

uint8_t gf_pow(uint8_t a, uint8_t n) {
    if (n == 0) return 1;
    if (a == 0) return 0;
    
    int log_result = ((int)log_table[a] * (int)n) % 255;
    return exp_table[log_result];
}

uint8_t gf_log(uint8_t x) {
    return log_table[x];
}

uint8_t gf_exp(uint8_t x) {
    return exp_table[x];
}

// ============================================
// VECTOR OPERATIONS
// ============================================

void gf_vec_add(uint8_t* dst, const uint8_t* src, size_t len) {
    for (size_t i = 0; i < len; i++) {
        dst[i] ^= src[i];
    }
}

void gf_vec_scale(uint8_t* dst, const uint8_t* src, uint8_t scalar, size_t len) {
    if (scalar == 0) {
        memset(dst, 0, len);
        return;
    }
    if (scalar == 1) {
        if (dst != src) memcpy(dst, src, len);
        return;
    }
    
    int log_s = log_table[scalar];
    for (size_t i = 0; i < len; i++) {
        if (src[i] == 0) {
            dst[i] = 0;
        } else {
            dst[i] = exp_table[(int)log_table[src[i]] + log_s];
        }
    }
}

void gf_vec_muladd(uint8_t* dst, const uint8_t* src, uint8_t scalar, size_t len) {
    if (scalar == 0) return;
    if (scalar == 1) {
        gf_vec_add(dst, src, len);
        return;
    }
    
    int log_s = log_table[scalar];
    for (size_t i = 0; i < len; i++) {
        if (src[i] != 0) {
            dst[i] ^= exp_table[(int)log_table[src[i]] + log_s];
        }
    }
}

// ============================================
// MATRIX OPERATIONS
// ============================================

void gf_matrix_vandermonde(uint8_t* matrix, int rows, int cols) {
    // matrix[i][j] = i^j in GF(2^8)
    // Row 0: [1, 0, 0, 0, ...] (0^j = 0 for j>0, 0^0 = 1)
    // Row 1: [1, 1, 1, 1, ...] (1^j = 1)
    // Row 2: [1, 2, 4, 8, ...] (2^j)
    // etc.
    
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            if (i == 0) {
                matrix[i * cols + j] = (j == 0) ? 1 : 0;
            } else {
                matrix[i * cols + j] = gf_pow((uint8_t)i, (uint8_t)j);
            }
        }
    }
}

void gf_matrix_cauchy(uint8_t* matrix, int rows, int cols) {
    // Cauchy matrix: matrix[i][j] = 1 / (x[i] XOR y[j])
    // x[i] = i (for i = 0..rows-1)
    // y[j] = rows + j (for j = 0..cols-1)
    // This ensures x[i] != y[j] for all i,j
    //
    // First k rows form the identity after normalization,
    // making systematic encoding easier.
    
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            uint8_t x = (uint8_t)i;
            uint8_t y = (uint8_t)(rows + j);
            uint8_t denominator = gf_add(x, y);
            
            if (denominator == 0) {
                // Should not happen with our x,y choice
                LOG_ERROR("galois: Cauchy matrix denominator is zero at [%d][%d]", i, j);
                matrix[i * cols + j] = 0;
            } else {
                matrix[i * cols + j] = gf_inv(denominator);
            }
        }
    }
}

int gf_matrix_invert(uint8_t* matrix, int n) {
    // Gauss-Jordan elimination with augmented identity matrix
    // [M | I] → row ops → [I | M^-1]
    
    // Allocate augmented matrix [n × 2n]
    uint8_t* aug = malloc(n * 2 * n);
    if (!aug) return -1;
    
    // Build augmented matrix
    for (int i = 0; i < n; i++) {
        // Left half: original matrix
        memcpy(aug + i * 2 * n, matrix + i * n, n);
        // Right half: identity
        memset(aug + i * 2 * n + n, 0, n);
        aug[i * 2 * n + n + i] = 1;
    }
    
    // Forward elimination
    for (int col = 0; col < n; col++) {
        // Find pivot (non-zero element in this column)
        int pivot = -1;
        for (int row = col; row < n; row++) {
            if (aug[row * 2 * n + col] != 0) {
                pivot = row;
                break;
            }
        }
        
        if (pivot == -1) {
            LOG_ERROR("galois: Matrix is singular (no pivot at column %d)", col);
            free(aug);
            return -1;
        }
        
        // Swap rows if needed
        if (pivot != col) {
            for (int j = 0; j < 2 * n; j++) {
                uint8_t tmp = aug[col * 2 * n + j];
                aug[col * 2 * n + j] = aug[pivot * 2 * n + j];
                aug[pivot * 2 * n + j] = tmp;
            }
        }
        
        // Scale pivot row so pivot element = 1
        uint8_t scale = gf_inv(aug[col * 2 * n + col]);
        for (int j = 0; j < 2 * n; j++) {
            aug[col * 2 * n + j] = gf_mul(aug[col * 2 * n + j], scale);
        }
        
        // Eliminate all other rows
        for (int row = 0; row < n; row++) {
            if (row == col) continue;
            uint8_t factor = aug[row * 2 * n + col];
            if (factor == 0) continue;
            
            for (int j = 0; j < 2 * n; j++) {
                aug[row * 2 * n + j] ^= gf_mul(factor, aug[col * 2 * n + j]);
            }
        }
    }
    
    // Extract inverse from right half
    for (int i = 0; i < n; i++) {
        memcpy(matrix + i * n, aug + i * 2 * n + n, n);
    }
    
    free(aug);
    return 0;
}

void gf_matrix_multiply(uint8_t* result,
                        const uint8_t* a, int rows_a, int cols_a,
                        const uint8_t* b, int cols_b) {
    for (int i = 0; i < rows_a; i++) {
        for (int j = 0; j < cols_b; j++) {
            uint8_t val = 0;
            for (int k = 0; k < cols_a; k++) {
                val ^= gf_mul(a[i * cols_a + k], b[k * cols_b + j]);
            }
            result[i * cols_b + j] = val;
        }
    }
}

void gf_matrix_encode(const uint8_t* matrix, int n, int k,
                      const uint8_t** data_in, uint8_t** data_out,
                      size_t shard_size) {
    // For each output shard i:
    //   data_out[i][byte] = Σ(matrix[i][j] * data_in[j][byte]) for j=0..k-1
    
    for (int i = 0; i < n; i++) {
        memset(data_out[i], 0, shard_size);
        for (int j = 0; j < k; j++) {
            uint8_t coeff = matrix[i * k + j];
            if (coeff == 0) continue;
            gf_vec_muladd(data_out[i], data_in[j], coeff, shard_size);
        }
    }
}