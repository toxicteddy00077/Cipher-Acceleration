#include "aes128/AES128_GPU.h"
#include <cuda_runtime.h>

extern __constant__ uint8_t d_SBOX[256];
extern __constant__ uint8_t d_INV_SBOX[256];
extern __constant__ uint8_t d_RCON[10];

void load_aes128_constants();

struct AES128_State {
    uint8_t mat[4][4];

    __device__ void Load(const uint8_t* block) {
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                mat[i][j] = block[i + j * 4];
    }

    __device__ void Store(uint8_t* block) const {
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                block[i + j * 4] = mat[i][j];
    }

    __device__ void XorRoundKey(const uint8_t* key) {
        for (int i = 0; i < 16; i++)
            reinterpret_cast<uint8_t*>(mat)[i] ^= key[i];
    }
};

__device__ void gpu_sub_bytes(AES128_State& state) {
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            state.mat[i][j] = d_SBOX[state.mat[i][j]];
}

__device__ void gpu_shift_rows(AES128_State& state) {
    uint8_t temp;
    temp = state.mat[1][0]; state.mat[1][0] = state.mat[1][1]; state.mat[1][1] = state.mat[1][2];
    state.mat[1][2] = state.mat[1][3]; state.mat[1][3] = temp;

    temp = state.mat[2][0]; state.mat[2][0] = state.mat[2][2]; state.mat[2][2] = temp;
    temp = state.mat[2][1]; state.mat[2][1] = state.mat[2][3]; state.mat[2][3] = temp;

    temp = state.mat[3][3]; state.mat[3][3] = state.mat[3][2]; state.mat[3][2] = state.mat[3][1];
    state.mat[3][1] = state.mat[3][0]; state.mat[3][0] = temp;
}

__device__ uint8_t gpu_xtime(uint8_t x) {
    return (x << 1) ^ ((x & 0x80) ? 0x1b : 0x00);
}

__device__ void gpu_mix_columns(AES128_State& state) {
    for (int i = 0; i < 4; i++) {
        uint8_t a0 = state.mat[0][i], a1 = state.mat[1][i];
        uint8_t a2 = state.mat[2][i], a3 = state.mat[3][i];
        uint8_t tmp = a0 ^ a1 ^ a2 ^ a3;

        state.mat[0][i] ^= tmp ^ gpu_xtime(a0 ^ a1);
        state.mat[1][i] ^= tmp ^ gpu_xtime(a1 ^ a2);
        state.mat[2][i] ^= tmp ^ gpu_xtime(a2 ^ a3);
        state.mat[3][i] ^= tmp ^ gpu_xtime(a3 ^ a0);
    }
}

__device__ void gpu_inv_sub_bytes(AES128_State& state) {
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            state.mat[i][j] = d_INV_SBOX[state.mat[i][j]];
}

__device__ void gpu_inv_shift_rows(AES128_State& state) {
    uint8_t temp;
    temp = state.mat[1][3]; state.mat[1][3] = state.mat[1][2]; state.mat[1][2] = state.mat[1][1];
    state.mat[1][1] = state.mat[1][0]; state.mat[1][0] = temp;

    temp = state.mat[2][0]; state.mat[2][0] = state.mat[2][2]; state.mat[2][2] = temp;
    temp = state.mat[2][1]; state.mat[2][1] = state.mat[2][3]; state.mat[2][3] = temp;

    temp = state.mat[3][0]; state.mat[3][0] = state.mat[3][3]; state.mat[3][3] = state.mat[3][2];
    state.mat[3][2] = state.mat[3][1]; state.mat[3][1] = temp;
}

__device__ void gpu_inv_mix_columns(AES128_State& state) {
    for (int i = 0; i < 4; i++) {
        uint8_t a0 = state.mat[0][i], a1 = state.mat[1][i];
        uint8_t a2 = state.mat[2][i], a3 = state.mat[3][i];
        
        uint8_t u = gpu_xtime(gpu_xtime(a0 ^ a2));
        uint8_t v = gpu_xtime(gpu_xtime(a1 ^ a3));
        
        state.mat[0][i] ^= u; state.mat[1][i] ^= v;
        state.mat[2][i] ^= u; state.mat[3][i] ^= v;
    }
}

static void expand_key_cpu(const uint8_t* key, uint8_t* expanded) {
    static const uint8_t RCON[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
    static const uint8_t SBOX[256] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5e, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xd7, 0x4b, 0x55, 0xcf, 0x34, 0xc5, 0x84,
        0xcb, 0xfe, 0x36, 0x21, 0xd3, 0x96, 0x0a, 0xf7, 0xca, 0xf3, 0x0b, 0xd4, 0x0d, 0xad, 0x58, 0x3c,
        0x39, 0x29, 0xc3, 0x9b, 0x1f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xc2, 0x60, 0xb6,
        0x23, 0x66, 0x2a, 0x65, 0xc3, 0x21, 0x78, 0x82, 0xa6, 0xc9, 0x61, 0x1a, 0xe0, 0xae, 0xb7, 0x1c
    };

    for (int i = 0; i < 16; i++)
        expanded[i] = key[i];

    for (int i = 1; i < 11; i++) {
        uint8_t temp[4];
        for (int j = 0; j < 4; j++)
            temp[j] = expanded[(i-1)*16 + 12 + j];

        uint8_t t0 = SBOX[temp[1]];
        uint8_t t1 = SBOX[temp[2]];
        uint8_t t2 = SBOX[temp[3]];
        uint8_t t3 = SBOX[temp[0]];

        for (int j = 0; j < 4; j++) {
            uint8_t idx = i * 16 + j;
            expanded[idx] = expanded[(i-1)*16 + j] ^ (j == 0 ? (t0 ^ RCON[i-1]) : 0);
            if (j > 0) expanded[idx] ^= (j == 1 ? t0 : (j == 2 ? t1 : t2));
        }
        for (int j = 4; j < 16; j++) {
            expanded[i*16 + j] = expanded[(i-1)*16 + j] ^ expanded[i*16 + j - 4];
        }
    }
}

__global__ void aes128_encrypt_kernel(const uint8_t* keys, const uint8_t* plaintext,
                                      uint8_t* ciphertext, std::size_t num_blocks,
                                      const uint8_t* expanded_keys) {
    std::size_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= num_blocks) return;

    AES128_State state;
    state.Load(plaintext + idx * 16);

    const uint8_t* rkey = expanded_keys + idx * 176;
    state.XorRoundKey(rkey);

    for (int r = 1; r < 10; r++) {
        gpu_sub_bytes(state);
        gpu_shift_rows(state);
        gpu_mix_columns(state);
        state.XorRoundKey(rkey + r * 16);
    }

    gpu_sub_bytes(state);
    gpu_shift_rows(state);
    state.XorRoundKey(rkey + 160);

    state.Store(ciphertext + idx * 16);
}

__global__ void aes128_decrypt_kernel(const uint8_t* keys, const uint8_t* ciphertext,
                                      uint8_t* plaintext, std::size_t num_blocks,
                                      const uint8_t* expanded_keys) {
    std::size_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= num_blocks) return;

    AES128_State state;
    state.Load(ciphertext + idx * 16);

    const uint8_t* rkey = expanded_keys + idx * 176;
    state.XorRoundKey(rkey + 160);

    for (int r = 9; r > 0; r--) {
        gpu_inv_shift_rows(state);
        gpu_inv_sub_bytes(state);
        state.XorRoundKey(rkey + r * 16);
        gpu_inv_mix_columns(state);
    }

    gpu_inv_shift_rows(state);
    gpu_inv_sub_bytes(state);
    state.XorRoundKey(rkey);

    state.Store(plaintext + idx * 16);
}

static uint8_t* d_expanded_keys = nullptr;

void AES128_GPU::initialize_gpu() {
    load_aes128_constants();
    cudaMalloc(&d_expanded_keys, 10000 * 176);
}

void AES128_GPU::cleanup_gpu() {
    if (d_expanded_keys) cudaFree(d_expanded_keys);
}

void AES128_GPU::encrypt_batch(const uint8_t* keys, const uint8_t* plaintext,
                               uint8_t* ciphertext, std::size_t num_blocks) {
    uint8_t* h_expanded_keys = new uint8_t[num_blocks * 176];
    for (std::size_t i = 0; i < num_blocks; i++)
        expand_key_cpu(keys + i * 16, h_expanded_keys + i * 176);

    uint8_t* d_plaintext = nullptr, *d_ciphertext = nullptr, *d_keys = nullptr;
    cudaMalloc(&d_plaintext, num_blocks * 16);
    cudaMalloc(&d_ciphertext, num_blocks * 16);
    cudaMalloc(&d_keys, num_blocks * 16);

    cudaMemcpy(d_plaintext, plaintext, num_blocks * 16, cudaMemcpyHostToDevice);
    cudaMemcpy(d_keys, keys, num_blocks * 16, cudaMemcpyHostToDevice);
    cudaMemcpy(d_expanded_keys, h_expanded_keys, num_blocks * 176, cudaMemcpyHostToDevice);

    std::size_t blockSize = 256;
    std::size_t gridSize = (num_blocks + blockSize - 1) / blockSize;
    aes128_encrypt_kernel<<<gridSize, blockSize>>>(d_keys, d_plaintext, d_ciphertext, num_blocks, d_expanded_keys);

    cudaMemcpy(ciphertext, d_ciphertext, num_blocks * 16, cudaMemcpyDeviceToHost);

    cudaFree(d_plaintext);
    cudaFree(d_ciphertext);
    cudaFree(d_keys);
    delete[] h_expanded_keys;
}

void AES128_GPU::decrypt_batch(const uint8_t* keys, const uint8_t* ciphertext,
                               uint8_t* plaintext, std::size_t num_blocks) {
    uint8_t* h_expanded_keys = new uint8_t[num_blocks * 176];
    for (std::size_t i = 0; i < num_blocks; i++)
        expand_key_cpu(keys + i * 16, h_expanded_keys + i * 176);

    uint8_t* d_ciphertext = nullptr, *d_plaintext = nullptr, *d_keys = nullptr;
    cudaMalloc(&d_ciphertext, num_blocks * 16);
    cudaMalloc(&d_plaintext, num_blocks * 16);
    cudaMalloc(&d_keys, num_blocks * 16);

    cudaMemcpy(d_ciphertext, ciphertext, num_blocks * 16, cudaMemcpyHostToDevice);
    cudaMemcpy(d_keys, keys, num_blocks * 16, cudaMemcpyHostToDevice);
    cudaMemcpy(d_expanded_keys, h_expanded_keys, num_blocks * 176, cudaMemcpyHostToDevice);

    std::size_t blockSize = 256;
    std::size_t gridSize = (num_blocks + blockSize - 1) / blockSize;
    aes128_decrypt_kernel<<<gridSize, blockSize>>>(d_keys, d_ciphertext, d_plaintext, num_blocks, d_expanded_keys);

    cudaMemcpy(plaintext, d_plaintext, num_blocks * 16, cudaMemcpyDeviceToHost);

    cudaFree(d_ciphertext);
    cudaFree(d_plaintext);
    cudaFree(d_keys);
    delete[] h_expanded_keys;
}
