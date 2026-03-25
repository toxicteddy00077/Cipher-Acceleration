#include "simon64/SIMON64.h"
#include <cstring>

void SIMON64_State::Load(const uint8_t input[SIMON64_Constants::BLOCK_SIZE / 8]) {
    left = 0;
    right = 0;
    for (std::size_t i = 0; i < 4; ++i) {
        left |= static_cast<SIMON_word>(input[i]) << (8 * i);
        right |= static_cast<SIMON_word>(input[4 + i]) << (8 * i);
    }
}

void SIMON64_State::Store(uint8_t output[SIMON64_Constants::BLOCK_SIZE / 8]) const {
    for (std::size_t i = 0; i < 4; ++i) {
        output[i] = (left >> (8 * i)) & 0xFF;
        output[4 + i] = (right >> (8 * i)) & 0xFF;
    }
}

namespace SIMON64_Utils {

SIMON_word Primitives::f(SIMON_word x) {
    return (x << 1 & x >> 8) ^ (x >> 2);
}

void Primitives::EncryptRound(SIMON_word &left, SIMON_word &right, SIMON_word roundKey) {
    SIMON_word temp = left;
    left = right ^ f(left) ^ roundKey;
    right = temp;
}

// ============================================================
// Key Schedule (128-bit key for SIMON-64/128)
// ============================================================

std::array<SIMON_word, SIMON64_Constants::ROUNDS> KeySchedule::ExpandKey(const std::array<uint8_t, SIMON64_Constants::KEY_SIZE / 8>& masterKey) {
    std::array<SIMON_word, SIMON64_Constants::ROUNDS> roundKeys;
    
    for (std::size_t i = 0; i < SIMON64_Constants::KEY_WORDS; ++i) {
        roundKeys[i] = 0;
        for (std::size_t j = 0; j < 4; ++j) {
            roundKeys[i] |= static_cast<SIMON_word>(masterKey[i * 4 + j]) << (8 * j);
        }
    }

    constexpr uint64_t c = 0xfffffffffffffffcULL;
    constexpr std::size_t z[5][32] = {
        {1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0},
        {0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0},
        {1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1},
        {1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1},
        {1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0}
    };

    for (std::size_t i = SIMON64_Constants::KEY_WORDS; i < SIMON64_Constants::ROUNDS; ++i) {
        SIMON_word temp = roundKeys[i - 1];
        temp = (temp >> 3) ^ (temp >> 4) ^ (temp >> 1) ^ (temp ^ (c & ((uint64_t)z[i / SIMON64_Constants::KEY_WORDS][i % 32])));
        roundKeys[i] = roundKeys[i - SIMON64_Constants::KEY_WORDS] ^ temp ^ 3;
    }

    return roundKeys;
}

}

void SIMON64_Utils::Modes::ECB_Encrypt(const uint8_t* key, const uint8_t* plaintext,
                                       uint8_t* ciphertext, std::size_t length) {
    std::array<uint8_t, 16> master_key;
    for (int i = 0; i < 16; i++) master_key[i] = key[i];
    auto rk = KeySchedule::ExpandKey(master_key);
    
    for (std::size_t i = 0; i < length; i += 8) {
        SIMON64_State state;
        state.Load(plaintext + i);
        
        for (int r = 0; r < 32; r++)
            Primitives::EncryptRound(state.left, state.right, rk[r]);
        
        state.Store(ciphertext + i);
    }
}

void SIMON64_Utils::Modes::ECB_Decrypt(const uint8_t* key, const uint8_t* ciphertext,
                                       uint8_t* plaintext, std::size_t length) {
    std::array<uint8_t, 16> master_key;
    for (int i = 0; i < 16; i++) master_key[i] = key[i];
    auto rk = KeySchedule::ExpandKey(master_key);
    
    for (std::size_t i = 0; i < length; i += 8) {
        SIMON64_State state;
        state.Load(ciphertext + i);
        
        for (int r = 31; r >= 0; r--)
            Primitives::EncryptRound(state.right, state.left, rk[r]);
        
        state.Store(plaintext + i);
    }
}

void SIMON64_Utils::Modes::CTR_Encrypt(const uint8_t* key, const uint8_t* iv,
                                       const uint8_t* plaintext, uint8_t* ciphertext, std::size_t length) {
    std::array<uint8_t, 16> master_key;
    for (int i = 0; i < 16; i++) master_key[i] = key[i];
    auto rk = KeySchedule::ExpandKey(master_key);
    
    uint8_t counter[8];
    for (int i = 0; i < 8; i++) counter[i] = iv[i];
    
    for (std::size_t i = 0; i < length; i += 8) {
        SIMON64_State state;
        state.Load(counter);
        
        for (int r = 0; r < 32; r++)
            Primitives::EncryptRound(state.left, state.right, rk[r]);
        
        uint8_t keystream[8];
        state.Store(keystream);
        
        std::size_t block_len = (length - i < 8) ? (length - i) : 8;
        for (std::size_t j = 0; j < block_len; j++)
            ciphertext[i + j] = plaintext[i + j] ^ keystream[j];
        
        for (int j = 7; j >= 0; j--) {
            counter[j]++;
            if (counter[j] != 0) break;
        }
    }
}

void SIMON64_Utils::Modes::CTR_Decrypt(const uint8_t* key, const uint8_t* iv,
                                       const uint8_t* ciphertext, uint8_t* plaintext, std::size_t length) {
    CTR_Encrypt(key, iv, ciphertext, plaintext, length);
}
