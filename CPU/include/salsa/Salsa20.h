#ifndef SALSA20_H
#define SALSA20_H

#include <cstddef>
#include <cstdint>
#include <array>

using Salsa_word = uint32_t;

namespace Salsa20_Constants {
    constexpr std::size_t STATE_SIZE = 16;
    constexpr std::size_t WORD_SIZE = 32;
    constexpr std::size_t KEY_SIZE = 256;
    constexpr std::size_t NONCE_SIZE = 64;
    constexpr std::size_t BLOCK_SIZE = 512;
    constexpr std::size_t ROUNDS = 20;
}

struct Salsa20_State {
    std::array<Salsa_word, Salsa20_Constants::STATE_SIZE> words;

    void Load(const uint8_t key[32], const uint8_t nonce[8]);
    void Store(uint8_t output[64]) const;
};

namespace Salsa20_Utils {

    class Primitives {
    public:
        static void ChaChaBlock(Salsa20_State &state);

    private:
        static constexpr std::size_t ROTL(Salsa_word x, std::size_t n) {
            return (x << n) | (x >> (32 - n));
        }
        static void QuarterRound(Salsa_word &a, Salsa_word &b, Salsa_word &c, Salsa_word &d);
    };

    class KeySchedule {
    public:
        static Salsa20_State Initialize(const std::array<uint8_t, Salsa20_Constants::KEY_SIZE / 8>& key,
                                        const std::array<uint8_t, Salsa20_Constants::NONCE_SIZE / 8>& nonce);
    };
}

#endif
