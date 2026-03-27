#ifndef SIMON64_H
#define SIMON64_H

#include <cstddef>
#include <cstdint>
#include <array>

using SIMON_word = uint32_t;

namespace SIMON64_Constants {
    constexpr std::size_t WORD_SIZE = 32;
    constexpr std::size_t BLOCK_SIZE = 64;
    constexpr std::size_t KEY_SIZE = 128;
    constexpr std::size_t ROUNDS = 32;
    constexpr std::size_t KEY_WORDS = 4;
    constexpr std::size_t BLOCK_WORDS = 2;
}

struct SIMON64_State {
    SIMON_word left;
    SIMON_word right;

    void Load(const uint8_t input[SIMON64_Constants::BLOCK_SIZE / 8]);
    void Store(uint8_t output[SIMON64_Constants::BLOCK_SIZE / 8]) const;
};

namespace SIMON64_Utils {

    class Primitives {
    public:
        static void EncryptRound(SIMON_word &left, SIMON_word &right, SIMON_word roundKey);

    private:
        static constexpr std::size_t S1 = 1;
        static constexpr std::size_t S8 = 8;
        static constexpr std::size_t S2 = 2;
        static SIMON_word f(SIMON_word x);
    };

    class KeySchedule {
    public:
        static std::array<SIMON_word, SIMON64_Constants::ROUNDS> ExpandKey(const std::array<uint8_t, SIMON64_Constants::KEY_SIZE / 8>& masterKey);
    };

    class Modes {
    public:
        static void ECB_Encrypt(const uint8_t* key, const uint8_t* plaintext,
                                uint8_t* ciphertext, std::size_t length);
        static void ECB_Decrypt(const uint8_t* key, const uint8_t* ciphertext,
                                uint8_t* plaintext, std::size_t length);
        static void CTR_Encrypt(const uint8_t* key, const uint8_t* iv,
                                const uint8_t* plaintext, uint8_t* ciphertext, std::size_t length);
        static void CTR_Decrypt(const uint8_t* key, const uint8_t* iv,
                                const uint8_t* ciphertext, uint8_t* plaintext, std::size_t length);
    };
}

#endif
