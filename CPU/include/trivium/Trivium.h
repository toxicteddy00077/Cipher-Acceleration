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
    uint32_t GenerateKeystream();
};

namespace Trivium_Utils {

    class Primitives {
    public:
        static void Initialize(Trivium_State &state, const uint8_t key[10], const uint8_t nonce[10]);
        static uint32_t GenerateOutput(Trivium_State &state);
        static void UpdateState(Trivium_State &state);

    private:
        static uint32_t Output(const Trivium_State &state);
    };

    class KeySchedule {
    public:
        static Trivium_State Setup(const std::array<uint8_t, Trivium_Constants::KEY_SIZE / 8>& key,
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
