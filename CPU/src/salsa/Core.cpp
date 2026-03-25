#include "salsa/Salsa20.h"
#include "common/Utilities.h"

void Salsa20_State::Load(const uint8_t key[32], const uint8_t nonce[8]) {
    words[0] = 0x61707865;
    words[5] = 0x3320646e;
    words[10] = 0x79622d32;
    words[15] = 0x6b206574;

    for (std::size_t i = 0; i < 8; ++i) {
        words[1 + i / 4] |= static_cast<Salsa_word>(key[i]) << (8 * (i % 4));
    }

    for (std::size_t i = 0; i < 8; ++i) {
        words[12 + i / 4] |= static_cast<Salsa_word>(nonce[i]) << (8 * (i % 4));
    }
}

void Salsa20_State::Store(uint8_t output[64]) const {
    for (std::size_t i = 0; i < Salsa20_Constants::STATE_SIZE; ++i) {
        for (std::size_t j = 0; j < 4; ++j) {
            output[i * 4 + j] = (words[i] >> (8 * j)) & 0xFF;
        }
    }
}

namespace Salsa20_Utils {

using CommonUtils::rotateLeft;

void Primitives::QuarterRound(Salsa_word &a, Salsa_word &b, Salsa_word &c, Salsa_word &d) {
    b ^= rotateLeft(a + d, 7);
    c ^= rotateLeft(b + a, 9);
    d ^= rotateLeft(c + b, 13);
    a ^= rotateLeft(d + c, 18);
}

void Primitives::ChaChaBlock(Salsa20_State &state) {
    std::array<Salsa_word, Salsa20_Constants::STATE_SIZE> working = state.words;

    for (std::size_t i = 0; i < Salsa20_Constants::ROUNDS; i += 2) {
        QuarterRound(working[0], working[4], working[8], working[12]);
        QuarterRound(working[1], working[5], working[9], working[13]);
        QuarterRound(working[2], working[6], working[10], working[14]);
        QuarterRound(working[3], working[7], working[11], working[15]);

        QuarterRound(working[0], working[5], working[10], working[15]);
        QuarterRound(working[1], working[6], working[11], working[12]);
        QuarterRound(working[2], working[7], working[8], working[13]);
        QuarterRound(working[3], working[4], working[9], working[14]);
    }

    for (std::size_t i = 0; i < Salsa20_Constants::STATE_SIZE; ++i) {
        state.words[i] += working[i];
    }
}

Salsa20_State KeySchedule::Initialize(const std::array<uint8_t, Salsa20_Constants::KEY_SIZE / 8>& key,
                                      const std::array<uint8_t, Salsa20_Constants::NONCE_SIZE / 8>& nonce) {
    Salsa20_State state;
    state.Load(key.data(), nonce.data());
    return state;
}

}

void Salsa20_Utils::Modes::CTR_Encrypt(const uint8_t* key, const uint8_t* nonce,
                                       const uint8_t* plaintext, uint8_t* ciphertext, std::size_t length) {
    std::array<uint8_t, 32> master_key;
    std::array<uint8_t, 8> master_nonce;
    for (int i = 0; i < 32; i++) master_key[i] = key[i];
    for (int i = 0; i < 8; i++) master_nonce[i] = nonce[i];
    
    Salsa20_State state = KeySchedule::Initialize(master_key, master_nonce);
    
    for (std::size_t i = 0; i < length; i += 64) {
        Salsa20_State block_state = state;
        Primitives::ChaChaBlock(block_state);
        
        uint8_t keystream[64];
        block_state.Store(keystream);
        
        std::size_t block_len = (length - i < 64) ? (length - i) : 64;
        for (std::size_t j = 0; j < block_len; j++)
            ciphertext[i + j] = plaintext[i + j] ^ keystream[j];
        
        state.words[12]++;
        if (state.words[12] == 0) state.words[13]++;
    }
}

void Salsa20_Utils::Modes::CTR_Decrypt(const uint8_t* key, const uint8_t* nonce,
                                       const uint8_t* ciphertext, uint8_t* plaintext, std::size_t length) {
    CTR_Encrypt(key, nonce, ciphertext, plaintext, length);
}
