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
        static void perm(ASCON_State &state, std::size_t rounds);

    private:
        static void rnd(ASCON_State &state, ASCON_word roundConstant);
        static void linLyr(ASCON_State &state);
        static void subLyr(ASCON_State &state);
    };

    class KeySchedule {
    public:
        static ASCON_State init(const std::array<uint8_t, ASCON_Constants::KEY_SIZE / 8>& key,
                                      const std::array<uint8_t, ASCON_Constants::NONCE_SIZE / 8>& nonce);
    };

    class Modes {
    public:
        static void CTR_Encrypt(const uint8_t* key, const uint8_t* nonce,
                                const uint8_t* plaintext, uint8_t* ciphertext, std::size_t length);
        static void CTR_Decrypt(const uint8_t* key, const uint8_t* nonce,
                                const uint8_t* ciphertext, uint8_t* plaintext, std::size_t length);
    };
}

#endif
