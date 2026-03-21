#ifndef AES128_H
#define AES128_H

#include <cstddef>
#include <cstdint>
#include <array>

using AES_byte = uint8_t;

namespace AES128_Constants {
    constexpr std::size_t BLOCK_COLUMNS = 4;
    constexpr std::size_t KEY_WORDS = 4;
    constexpr std::size_t STATE_DIM = 4;
    constexpr std::size_t BLOCK_SIZE = 16;
    constexpr std::size_t KEY_SIZE_128 = 16;
    constexpr std::size_t ROUNDS = 10;
    constexpr std::size_t EXPANDED_KEY_SIZE = BLOCK_SIZE * (ROUNDS + 1);
    constexpr std::size_t WORD_SIZE = 4;
    constexpr std::size_t TOTAL_WORDS = BLOCK_COLUMNS * (ROUNDS + 1);

    extern const AES_byte SBOX[256];
    extern const AES_byte INV_SBOX[256];
    extern const AES_byte RCON[10];
}

struct AES128_State {
    AES_byte mat[AES128_Constants::STATE_DIM][AES128_Constants::STATE_DIM];

    void Load(const AES_byte input[AES128_Constants::BLOCK_SIZE]);
    void Store(AES_byte output[AES128_Constants::BLOCK_SIZE]) const;
    void XorRoundKey(const AES_byte roundKey[AES128_Constants::BLOCK_SIZE]);
};

namespace AES128_Utils {

    class Primitives {
    public:
        static void SubBytes(AES128_State &state);
        static void ShiftRows(AES128_State &state);
        static void MixColumns(AES128_State &state);
        static void AddRoundKey(AES128_State &state, const std::array<AES_byte, AES128_Constants::BLOCK_SIZE>& roundKey);

        static void InvSubBytes(AES128_State &state);
        static void InvShiftRows(AES128_State &state);
        static void InvMixColumns(AES128_State &state);

    private:
        static constexpr AES_byte AES_POLY = 0x1B;
        static AES_byte galoisMult(AES_byte a, AES_byte b);
        static AES_byte xtime(AES_byte x);
    };

    class KeySchedule {
    public:
        static std::array<AES_byte, AES128_Constants::EXPANDED_KEY_SIZE> ExpandKey(const std::array<AES_byte, AES128_Constants::KEY_SIZE_128>& masterKey);

    private:
        static void RotWord(AES_byte* word);
        static void SubWord(AES_byte* word);
    };
}

#endif
