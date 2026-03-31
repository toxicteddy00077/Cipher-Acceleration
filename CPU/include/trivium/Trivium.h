#ifndef TRIVIUM_H
#define TRIVIUM_H

#include <cstddef>
#include <cstdint>
#include <array>

namespace Trivium_Constants {
    constexpr std::size_t STATE_SIZE = 288;
    constexpr std::size_t KEY_SIZE = 80;
    constexpr std::size_t NONCE_SIZE = 80;
    constexpr std::size_t BLOCK_SIZE = 64;
    constexpr std::size_t INITIALIZATION_ROUNDS = 1152;
}

struct Trivium_State {
    std::array<uint32_t, 9> state;

    void Load(const uint8_t key[10], const uint8_t nonce[10]);
    uint32_t genKeystream();
};

namespace Trivium_Utils {

    class Primitives {
    public:
        static void init(Trivium_State &state, const uint8_t key[10], const uint8_t nonce[10]);
        static uint32_t genOutput(Trivium_State &state);
        static void updState(Trivium_State &state);

    private:
        static uint32_t genKs(const Trivium_State &state);
    };

    class KeySchedule {
    public:
        static Trivium_State setup(const std::array<uint8_t, Trivium_Constants::KEY_SIZE / 8>& key,
                                   const std::array<uint8_t, Trivium_Constants::NONCE_SIZE / 8>& nonce);
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
