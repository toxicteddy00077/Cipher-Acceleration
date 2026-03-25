#include "ascon/Ascon.h"
#include "common/Utilities.h"

void ASCON_State::Load(const uint8_t input[40]) {
    for (std::size_t i = 0; i < ASCON_Constants::STATE_SIZE; ++i) {
        words[i] = 0;
        for (std::size_t j = 0; j < 8; ++j) {
            words[i] |= static_cast<ASCON_word>(input[i * 8 + j]) << (56 - 8 * j);
        }
    }
}

void ASCON_State::Store(uint8_t output[40]) const {
    for (std::size_t i = 0; i < ASCON_Constants::STATE_SIZE; ++i) {
        for (std::size_t j = 0; j < 8; ++j) {
            output[i * 8 + j] = (words[i] >> (56 - 8 * j)) & 0xFF;
        }
    }
}

namespace ASCON_Utils {

using CommonUtils::rotateRight;

void Primitives::SubstitutionLayer(ASCON_State &state) {
    for (std::size_t i = 0; i < ASCON_Constants::STATE_SIZE; ++i) {
        ASCON_word x = state.words[i];
        x ^= (x >> 16);
        x ^= (x >> 8);
        x ^= (x >> 4);
        x ^= (x >> 2);
        x ^= (x >> 1);
        state.words[i] = x;
    }
}

void Primitives::LinearLayer(ASCON_State &state) {
    for (std::size_t i = 0; i < ASCON_Constants::STATE_SIZE; ++i) {
        state.words[i] ^= rotateRight(state.words[i], 19) ^ rotateRight(state.words[i], 28);
    }
}

void Primitives::Round(ASCON_State &state, ASCON_word roundConstant) {
    state.words[2] ^= roundConstant;
    SubstitutionLayer(state);
    LinearLayer(state);
}

void Primitives::Permutation(ASCON_State &state, std::size_t rounds) {
    for (std::size_t i = ASCON_Constants::ROUNDS_PA - rounds; i < ASCON_Constants::ROUNDS_PA; ++i) {
        ASCON_word rc = (0xf0ULL ^ (i << 4)) & 0xf0ULL;
        Round(state, rc << 56);
    }
}

ASCON_State KeySchedule::Initialize(const std::array<uint8_t, ASCON_Constants::KEY_SIZE / 8>& key,
                                    const std::array<uint8_t, ASCON_Constants::NONCE_SIZE / 8>& nonce) {
    ASCON_State state;
    
    state.words[0] = 0x80400c0600000000ULL;
    state.words[1] = 0;
    state.words[2] = 0;
    state.words[3] = 0;
    state.words[4] = 0;

    for (std::size_t i = 0; i < 16; ++i) {
        state.words[i / 8] |= static_cast<ASCON_word>(key[i]) << (56 - 8 * (i % 8));
    }

    for (std::size_t i = 0; i < 16; ++i) {
        state.words[2 + i / 8] |= static_cast<ASCON_word>(nonce[i]) << (56 - 8 * (i % 8));
    }

    Primitives::Permutation(state, 0);

    return state;
}

}

void ASCON_Utils::Modes::CTR_Encrypt(const uint8_t* key, const uint8_t* nonce,
                                     const uint8_t* plaintext, uint8_t* ciphertext, std::size_t length) {
    std::array<uint8_t, 16> master_key, master_nonce;
    for (int i = 0; i < 16; i++) {
        master_key[i] = key[i];
        master_nonce[i] = nonce[i];
    }
    
    ASCON_State state = KeySchedule::Initialize(master_key, master_nonce);
    Primitives::Permutation(state, 12);
    
    uint8_t counter = 0;
    for (std::size_t i = 0; i < length; i += 8) {
        Primitives::Permutation(state, 6);
        
        uint8_t keystream[8];
        for (int j = 0; j < 8; j++)
            keystream[j] = (state.words[0] >> (56 - j * 8)) & 0xFF;
        
        std::size_t block_len = (length - i < 8) ? (length - i) : 8;
        for (std::size_t j = 0; j < block_len; j++)
            ciphertext[i + j] = plaintext[i + j] ^ keystream[j];
        
        counter++;
        state.words[4] ^= (uint64_t)counter;
    }
}

void ASCON_Utils::Modes::CTR_Decrypt(const uint8_t* key, const uint8_t* nonce,
                                     const uint8_t* ciphertext, uint8_t* plaintext, std::size_t length) {
    CTR_Encrypt(key, nonce, ciphertext, plaintext, length);
}
