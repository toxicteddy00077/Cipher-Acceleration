#ifndef AES128_GPU_H
#define AES128_GPU_H

#include <cstddef>
#include <cstdint>

namespace AES128_GPU {
    constexpr std::size_t BLOCK_SIZE = 16;
    constexpr std::size_t KEY_SIZE = 16;
    constexpr std::size_t EXPANDED_KEY_SIZE = 176;

    void initialize_gpu();
    void cleanup_gpu();
    
    void encrypt_batch(const uint8_t* keys, const uint8_t* plaintext, 
                       uint8_t* ciphertext, std::size_t num_blocks);
    void decrypt_batch(const uint8_t* keys, const uint8_t* ciphertext, 
                       uint8_t* plaintext, std::size_t num_blocks);
}

#endif
