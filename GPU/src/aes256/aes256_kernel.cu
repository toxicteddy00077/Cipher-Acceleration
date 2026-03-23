#include "aes256/AES256_GPU.h"
#include "common_gpu/cuda_utils.h"
#include <cuda_runtime.h>

namespace AES256_GPU {

// Constants on device
__constant__ uint8_t d_SBOX[256];
__constant__ uint8_t d_INV_SBOX[256];
__constant__ uint8_t d_RCON[15];

// Rotation macro
#define ROTATE_LEFT(x, n) ((x << n) | (x >> (32 - n)))

// ============================================================
// Device Helper Functions
// ============================================================

__device__ static inline uint8_t gpu_xtime(uint8_t x) {
    return (x << 1) ^ ((x & 0x80) ? 0x1B : 0x00);
}

__device__ static inline uint8_t gpu_galois_mult(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    while (b) {
        if (b & 1) result ^= a;
        a = gpu_xtime(a);
        b >>= 1;
    }
    return result;
}

// ============================================================
// AES256 State Structure (on device)
// ============================================================

struct AES256_State {
    uint8_t mat[4][4];

    __device__ void load(const uint8_t input[16]) {
        for (int i = 0; i < 16; ++i) {
            mat[i % 4][i / 4] = input[i];
        }
    }

    __device__ void store(uint8_t output[16]) const {
        for (int i = 0; i < 16; ++i) {
            output[i] = mat[i % 4][i / 4];
        }
    }

    __device__ void xor_round_key(const uint8_t roundKey[16]) {
        for (int i = 0; i < 16; ++i) {
            mat[i % 4][i / 4] ^= roundKey[i];
        }
    }

    __device__ void sub_bytes() {
        for (int r = 0; r < 4; ++r) {
            for (int c = 0; c < 4; ++c) {
                mat[r][c] = d_SBOX[mat[r][c]];
            }
        }
    }

    __device__ void inv_sub_bytes() {
        for (int r = 0; r < 4; ++r) {
            for (int c = 0; c < 4; ++c) {
                mat[r][c] = d_INV_SBOX[mat[r][c]];
            }
        }
    }

    __device__ void shift_rows() {
        uint8_t temp;
        
        // Rotate row 1 left by 1
        temp = mat[1][0];
        mat[1][0] = mat[1][1];
        mat[1][1] = mat[1][2];
        mat[1][2] = mat[1][3];
        mat[1][3] = temp;

        // Rotate row 2 left by 2
        temp = mat[2][0];
        mat[2][0] = mat[2][2];
        mat[2][2] = temp;
        temp = mat[2][1];
        mat[2][1] = mat[2][3];
        mat[2][3] = temp;

        // Rotate row 3 left by 3
        temp = mat[3][3];
        mat[3][3] = mat[3][2];
        mat[3][2] = mat[3][1];
        mat[3][1] = mat[3][0];
        mat[3][0] = temp;
    }

    __device__ void inv_shift_rows() {
        uint8_t temp;
        
        // Rotate row 1 right by 1
        temp = mat[1][3];
        mat[1][3] = mat[1][2];
        mat[1][2] = mat[1][1];
        mat[1][1] = mat[1][0];
        mat[1][0] = temp;

        // Rotate row 2 right by 2
        temp = mat[2][0];
        mat[2][0] = mat[2][2];
        mat[2][2] = temp;
        temp = mat[2][1];
        mat[2][1] = mat[2][3];
        mat[2][3] = temp;

        // Rotate row 3 right by 3
        temp = mat[3][0];
        mat[3][0] = mat[3][1];
        mat[3][1] = mat[3][2];
        mat[3][2] = mat[3][3];
        mat[3][3] = temp;
    }

    __device__ void mix_columns() {
        for (int c = 0; c < 4; ++c) {
            uint8_t col[4];
            for (int r = 0; r < 4; ++r)
                col[r] = mat[r][c];

            mat[0][c] = gpu_galois_mult(0x02, col[0]) ^ gpu_galois_mult(0x03, col[1]) ^ col[2] ^ col[3];
            mat[1][c] = col[0] ^ gpu_galois_mult(0x02, col[1]) ^ gpu_galois_mult(0x03, col[2]) ^ col[3];
            mat[2][c] = col[0] ^ col[1] ^ gpu_galois_mult(0x02, col[2]) ^ gpu_galois_mult(0x03, col[3]);
            mat[3][c] = gpu_galois_mult(0x03, col[0]) ^ col[1] ^ col[2] ^ gpu_galois_mult(0x02, col[3]);
        }
    }

    __device__ void inv_mix_columns() {
        for (int c = 0; c < 4; ++c) {
            uint8_t col[4];
            for (int r = 0; r < 4; ++r)
                col[r] = mat[r][c];

            mat[0][c] = gpu_galois_mult(0x0e, col[0]) ^ gpu_galois_mult(0x0b, col[1]) ^ gpu_galois_mult(0x0d, col[2]) ^ gpu_galois_mult(0x09, col[3]);
            mat[1][c] = gpu_galois_mult(0x09, col[0]) ^ gpu_galois_mult(0x0e, col[1]) ^ gpu_galois_mult(0x0b, col[2]) ^ gpu_galois_mult(0x0d, col[3]);
            mat[2][c] = gpu_galois_mult(0x0d, col[0]) ^ gpu_galois_mult(0x09, col[1]) ^ gpu_galois_mult(0x0e, col[2]) ^ gpu_galois_mult(0x0b, col[3]);
            mat[3][c] = gpu_galois_mult(0x0b, col[0]) ^ gpu_galois_mult(0x0d, col[1]) ^ gpu_galois_mult(0x09, col[2]) ^ gpu_galois_mult(0x0e, col[3]);
        }
    }
};

// ============================================================
// Key Schedule (Precomputed on Host, Copied to Device)
// ============================================================

__device__ void gpu_key_schedule_expand(const uint8_t* key, uint8_t* expandedKey) {
    for (int i = 0; i < 32; ++i) {
        expandedKey[i] = key[i];
    }

    uint8_t temp[4];
    for (int i = 8; i < 60; ++i) {
        int idx = i * 4;
        int prevIdx = (i - 1) * 4;
        int prevPrevIdx = (i - 8) * 4;

        temp[0] = expandedKey[prevIdx];
        temp[1] = expandedKey[prevIdx + 1];
        temp[2] = expandedKey[prevIdx + 2];
        temp[3] = expandedKey[prevIdx + 3];

        if (i % 8 == 0) {
            // RotWord
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            // SubWord
            for (int j = 0; j < 4; ++j) {
                temp[j] = d_SBOX[temp[j]];
            }

            temp[0] ^= d_RCON[(i / 8) - 1];
        } else if (i % 8 == 4) {
            // SubWord for 256-bit key
            for (int j = 0; j < 4; ++j) {
                temp[j] = d_SBOX[temp[j]];
            }
        }

        for (int j = 0; j < 4; ++j) {
            expandedKey[idx + j] = expandedKey[prevPrevIdx + j] ^ temp[j];
        }
    }
}

// ============================================================
// CUDA Kernels
// ============================================================

__global__ void aes256_encrypt_kernel(const uint8_t* d_plaintext,
                                     uint8_t* d_ciphertext,
                                     const uint8_t* d_expandedKey,
                                     size_t numBlocks) {
    size_t idx = blockIdx.x * blockDim.x + threadIdx.x;

    if (idx < numBlocks) {
        AES256_State state;
        uint8_t expandedKey[240];

        // Copy expanded key (each thread loads its key)
        for (int i = threadIdx.x; i < 240; i += blockDim.x) {
            expandedKey[i] = d_expandedKey[i];
        }
        __syncthreads();

        // Load plaintext block
        state.load(&d_plaintext[idx * 16]);

        // Initial AddRoundKey (round 0)
        state.xor_round_key(&expandedKey[0]);

        // Rounds 1-13
        for (int round = 1; round < 14; ++round) {
            state.sub_bytes();
            state.shift_rows();
            state.mix_columns();
            state.xor_round_key(&expandedKey[round * 16]);
        }

        // Final round (14)
        state.sub_bytes();
        state.shift_rows();
        state.xor_round_key(&expandedKey[14 * 16]);

        // Store ciphertext block
        state.store(&d_ciphertext[idx * 16]);
    }
}

__global__ void aes256_decrypt_kernel(const uint8_t* d_ciphertext,
                                     uint8_t* d_plaintext,
                                     const uint8_t* d_expandedKey,
                                     size_t numBlocks) {
    size_t idx = blockIdx.x * blockDim.x + threadIdx.x;

    if (idx < numBlocks) {
        AES256_State state;
        uint8_t expandedKey[240];

        // Copy expanded key (each thread loads its key)
        for (int i = threadIdx.x; i < 240; i += blockDim.x) {
            expandedKey[i] = d_expandedKey[i];
        }
        __syncthreads();

        // Load ciphertext block
        state.load(&d_ciphertext[idx * 16]);

        // Initial AddRoundKey (round 14)
        state.xor_round_key(&expandedKey[14 * 16]);

        // Rounds 13-1 (reverse order)
        for (int round = 13; round >= 1; --round) {
            state.inv_shift_rows();
            state.inv_sub_bytes();
            state.xor_round_key(&expandedKey[round * 16]);
            state.inv_mix_columns();
        }

        // Final round
        state.inv_shift_rows();
        state.inv_sub_bytes();
        state.xor_round_key(&expandedKey[0]);

        // Store plaintext block
        state.store(&d_plaintext[idx * 16]);
    }
}

}
