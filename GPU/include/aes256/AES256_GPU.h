#ifndef AES256_GPU_H
#define AES256_GPU_H

#include <cstddef>
#include <cstdint>

namespace AES256_GPU {

// Constants
constexpr size_t BLOCK_SIZE = 16;
constexpr size_t KEY_SIZE = 32;
constexpr size_t EXPANDED_KEY_SIZE = 240;

/**
 * Batch encrypt plaintext blocks using AES-256 on GPU
 * @param h_plaintext: Host plaintext buffer (numBlocks * 16 bytes)
 * @param h_ciphertext: Host ciphertext buffer (numBlocks * 16 bytes) - will be filled
 * @param key: AES-256 key (32 bytes)
 * @param numBlocks: Number of 16-byte blocks to encrypt
 */
void encrypt_batch(const uint8_t* h_plaintext,
                  uint8_t* h_ciphertext,
                  const uint8_t* key,
                  size_t numBlocks);

/**
 * Batch decrypt ciphertext blocks using AES-256 on GPU
 * @param h_ciphertext: Host ciphertext buffer (numBlocks * 16 bytes)
 * @param h_plaintext: Host plaintext buffer (numBlocks * 16 bytes) - will be filled
 * @param key: AES-256 key (32 bytes)
 * @param numBlocks: Number of 16-byte blocks to decrypt
 */
void decrypt_batch(const uint8_t* h_ciphertext,
                  uint8_t* h_plaintext,
                  const uint8_t* key,
                  size_t numBlocks);

/**
 * Initialize GPU (load S-boxes to constant memory)
 * Must be called once before any encrypt/decrypt operations
 */
void initialize_gpu();

/**
 * Cleanup GPU resources
 */
void cleanup_gpu();

}

#endif
