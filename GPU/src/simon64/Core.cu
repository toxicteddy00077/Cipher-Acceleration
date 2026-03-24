#include "simon64/SIMON64_GPU.h"
#include <cuda_runtime.h>

void load_simon64_constants();

static const uint32_t h_Z[32] = {
    1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0,
    1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0
};

__host__ __device__ uint32_t rotateLeft32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static void expand_key_simon64(const uint8_t* key, uint32_t* rk) {
    uint32_t k[4];
    for (int i = 0; i < 4; i++)
        k[i] = ((uint32_t)key[4*i] << 24) | ((uint32_t)key[4*i+1] << 16) |
                ((uint32_t)key[4*i+2] << 8) | (uint32_t)key[4*i+3];

    for (int i = 0; i < 32; i++) {
        uint32_t temp = k[3];
        k[3] = k[2]; k[2] = k[1]; k[1] = k[0];
        k[0] = temp ^ (rotateLeft32(k[0], 3) ^ rotateLeft32(k[0], 4)) ^ rotateLeft32(k[3], 1) ^ h_Z[i];
        rk[i] = k[0];
    }
}

__global__ void simon64_encrypt_kernel(const uint8_t* keys, const uint8_t* plaintext,
                                       uint8_t* ciphertext, std::size_t num_blocks,
                                       const uint32_t* rk) {
    std::size_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= num_blocks) return;

    uint32_t x = ((uint32_t)plaintext[idx*8] << 24) | ((uint32_t)plaintext[idx*8+1] << 16) |
                 ((uint32_t)plaintext[idx*8+2] << 8) | (uint32_t)plaintext[idx*8+3];
    uint32_t y = ((uint32_t)plaintext[idx*8+4] << 24) | ((uint32_t)plaintext[idx*8+5] << 16) |
                 ((uint32_t)plaintext[idx*8+6] << 8) | (uint32_t)plaintext[idx*8+7];

    for (int i = 0; i < 32; i++) {
        uint32_t tmp = y ^ (rotateLeft32(x, 1) & rotateLeft32(x, 8)) ^ rotateLeft32(x, 2) ^ rk[i];
        y = x;
        x = tmp;
    }

    ciphertext[idx*8] = (x >> 24) & 0xFF;
    ciphertext[idx*8+1] = (x >> 16) & 0xFF;
    ciphertext[idx*8+2] = (x >> 8) & 0xFF;
    ciphertext[idx*8+3] = x & 0xFF;
    ciphertext[idx*8+4] = (y >> 24) & 0xFF;
    ciphertext[idx*8+5] = (y >> 16) & 0xFF;
    ciphertext[idx*8+6] = (y >> 8) & 0xFF;
    ciphertext[idx*8+7] = y & 0xFF;
}

__global__ void simon64_decrypt_kernel(const uint8_t* keys, const uint8_t* ciphertext,
                                       uint8_t* plaintext, std::size_t num_blocks,
                                       const uint32_t* rk) {
    std::size_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= num_blocks) return;

    uint32_t x = ((uint32_t)ciphertext[idx*8] << 24) | ((uint32_t)ciphertext[idx*8+1] << 16) |
                 ((uint32_t)ciphertext[idx*8+2] << 8) | (uint32_t)ciphertext[idx*8+3];
    uint32_t y = ((uint32_t)ciphertext[idx*8+4] << 24) | ((uint32_t)ciphertext[idx*8+5] << 16) |
                 ((uint32_t)ciphertext[idx*8+6] << 8) | (uint32_t)ciphertext[idx*8+7];

    for (int i = 31; i >= 0; i--) {
        uint32_t tmp = y ^ (rotateLeft32(x, 1) & rotateLeft32(x, 8)) ^ rotateLeft32(x, 2) ^ rk[i];
        y = x;
        x = tmp;
    }

    plaintext[idx*8] = (x >> 24) & 0xFF;
    plaintext[idx*8+1] = (x >> 16) & 0xFF;
    plaintext[idx*8+2] = (x >> 8) & 0xFF;
    plaintext[idx*8+3] = x & 0xFF;
    plaintext[idx*8+4] = (y >> 24) & 0xFF;
    plaintext[idx*8+5] = (y >> 16) & 0xFF;
    plaintext[idx*8+6] = (y >> 8) & 0xFF;
    plaintext[idx*8+7] = y & 0xFF;
}

static uint32_t* d_rk = nullptr;

void SIMON64_GPU::initialize_gpu() {
    cudaMalloc(&d_rk, 10000 * 32 * sizeof(uint32_t));
}

void SIMON64_GPU::cleanup_gpu() {
    if (d_rk) cudaFree(d_rk);
}

void SIMON64_GPU::encrypt_batch(const uint8_t* keys, const uint8_t* plaintext,
                                uint8_t* ciphertext, std::size_t num_blocks) {
    uint32_t* h_rk = new uint32_t[num_blocks * 32];
    for (std::size_t i = 0; i < num_blocks; i++)
        expand_key_simon64(keys + i * 16, h_rk + i * 32);

    uint8_t* d_plaintext = nullptr, *d_ciphertext = nullptr, *d_keys = nullptr;
    cudaMalloc(&d_plaintext, num_blocks * 8);
    cudaMalloc(&d_ciphertext, num_blocks * 8);
    cudaMalloc(&d_keys, num_blocks * 16);

    cudaMemcpy(d_plaintext, plaintext, num_blocks * 8, cudaMemcpyHostToDevice);
    cudaMemcpy(d_keys, keys, num_blocks * 16, cudaMemcpyHostToDevice);
    cudaMemcpy(d_rk, h_rk, num_blocks * 32 * sizeof(uint32_t), cudaMemcpyHostToDevice);

    std::size_t blockSize = 256;
    std::size_t gridSize = (num_blocks + blockSize - 1) / blockSize;
    simon64_encrypt_kernel<<<gridSize, blockSize>>>(d_keys, d_plaintext, d_ciphertext, num_blocks, d_rk);

    cudaMemcpy(ciphertext, d_ciphertext, num_blocks * 8, cudaMemcpyDeviceToHost);

    cudaFree(d_plaintext);
    cudaFree(d_ciphertext);
    cudaFree(d_keys);
    delete[] h_rk;
}

void SIMON64_GPU::decrypt_batch(const uint8_t* keys, const uint8_t* ciphertext,
                                uint8_t* plaintext, std::size_t num_blocks) {
    uint32_t* h_rk = new uint32_t[num_blocks * 32];
    for (std::size_t i = 0; i < num_blocks; i++)
        expand_key_simon64(keys + i * 16, h_rk + i * 32);

    uint8_t* d_ciphertext = nullptr, *d_plaintext = nullptr, *d_keys = nullptr;
    cudaMalloc(&d_ciphertext, num_blocks * 8);
    cudaMalloc(&d_plaintext, num_blocks * 8);
    cudaMalloc(&d_keys, num_blocks * 16);

    cudaMemcpy(d_ciphertext, ciphertext, num_blocks * 8, cudaMemcpyHostToDevice);
    cudaMemcpy(d_keys, keys, num_blocks * 16, cudaMemcpyHostToDevice);
    cudaMemcpy(d_rk, h_rk, num_blocks * 32 * sizeof(uint32_t), cudaMemcpyHostToDevice);

    std::size_t blockSize = 256;
    std::size_t gridSize = (num_blocks + blockSize - 1) / blockSize;
    simon64_decrypt_kernel<<<gridSize, blockSize>>>(d_keys, d_ciphertext, d_plaintext, num_blocks, d_rk);

    cudaMemcpy(plaintext, d_plaintext, num_blocks * 8, cudaMemcpyDeviceToHost);

    cudaFree(d_ciphertext);
    cudaFree(d_plaintext);
    cudaFree(d_keys);
    delete[] h_rk;
}
