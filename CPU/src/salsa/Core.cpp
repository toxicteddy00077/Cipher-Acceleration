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
