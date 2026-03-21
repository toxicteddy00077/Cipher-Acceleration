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
