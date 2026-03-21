#ifndef ASCON_H
#define ASCON_H

#include <cstddef>
#include <cstdint>
#include <array>

using ASCON_word = uint64_t;

namespace ASCON_Constants {
    constexpr std::size_t STATE_SIZE = 5;
    constexpr std::size_t WORD_SIZE = 64;
    constexpr std::size_t NONCE_SIZE = 128;
    constexpr std::size_t KEY_SIZE = 128;
    constexpr std::size_t TAG_SIZE = 128;
    constexpr std::size_t RATE = 64;
    constexpr std::size_t ROUNDS_PA = 12;
    constexpr std::size_t ROUNDS_PB = 6;
}

struct ASCON_State {
    std::array<ASCON_word, ASCON_Constants::STATE_SIZE> words;

    void Load(const uint8_t input[40]);
    void Store(uint8_t output[40]) const;
};

namespace ASCON_Utils {

    class Primitives {
    public:
        static void Permutation(ASCON_State &state, std::size_t rounds);

    private:
        static void Round(ASCON_State &state, ASCON_word roundConstant);
        static void LinearLayer(ASCON_State &state);
        static void SubstitutionLayer(ASCON_State &state);
    };

    class KeySchedule {
    public:
        static ASCON_State Initialize(const std::array<uint8_t, ASCON_Constants::KEY_SIZE / 8>& key,
                                      const std::array<uint8_t, ASCON_Constants::NONCE_SIZE / 8>& nonce);
    };
}

#endif
