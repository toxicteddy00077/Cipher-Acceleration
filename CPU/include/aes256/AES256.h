#ifndef AES256_UTILS_H
#define AES256_UTILS_H

#include <cstddef>
#include <cstdint>
#include <array>

using AES_byte = uint8_t;

namespace AES256_Constants {
    constexpr std::size_t BLOCK_COLUMNS = 4;
    constexpr std::size_t KEY_WORDS = 8;
    constexpr std::size_t STATE_DIM = 4;
    constexpr std::size_t BLOCK_SIZE = 16;
    constexpr std::size_t KEY_SIZE_256 = 32;
    constexpr std::size_t ROUNDS = 14;
    constexpr std::size_t EXPANDED_KEY_SIZE = BLOCK_SIZE * (ROUNDS + 1); 
    constexpr std::size_t WORD_SIZE = 4;
    constexpr std::size_t TOTAL_WORDS = BLOCK_COLUMNS * (ROUNDS + 1);
  
    //S-box and Round constant (these will be hardcoded)
    extern const AES_byte SBOX[256];
    extern const AES_byte INV_SBOX[256];
    extern const AES_byte RCON[15];
}

struct AES256_State { 
  AES_byte mat[AES256_Constants::STATE_DIM][AES256_Constants::STATE_DIM]; 
  
  void Load(const AES_byte input[AES256_Constants::BLOCK_SIZE]);
  void Store(AES_byte output[AES256_Constants::BLOCK_SIZE]) const;
  void XorRoundKey(const AES_byte roundKey[AES256_Constants::BLOCK_SIZE]);
};

namespace AES256_Utils {

    class Primitives {
    public:
        // Encryption Primitives
        static void subBytes(AES256_State &state);
        static void shiftRows(AES256_State &state);
        static void mixCols(AES256_State &state);
        static void addRndKey(AES256_State &state, const std::array<AES_byte, AES256_Constants::BLOCK_SIZE>& roundKey);

        // Decryption Primitives
        static void invSubBytes(AES256_State &state);
        static void invShiftRows(AES256_State &state);
        static void invMixCols(AES256_State &state);

    private:
        // Internal Galois Field Multiplications 
        static constexpr AES_byte AES_POLY = 0x1B;
        static AES_byte galoisMult(AES_byte a, AES_byte b);
        static AES_byte xtime(AES_byte x); 
    };

    class KeySchedule {
    public:
        // Generates the 240-byte expanded key from the 32-byte input key
        static std::array<AES_byte, AES256_Constants::EXPANDED_KEY_SIZE> expKey(const std::array<AES_byte, AES256_Constants::KEY_SIZE_256>& masterKey);

    private:
        static void RotWord(AES_byte* word);
        static void SubWord(AES_byte* word);
    };

    class Modes {
    public:
        static void ECB_Encrypt(const AES_byte* key, const AES_byte* plaintext, 
                                AES_byte* ciphertext, std::size_t length);
        static void ECB_Decrypt(const AES_byte* key, const AES_byte* ciphertext, 
                                AES_byte* plaintext, std::size_t length);
        static void CTR_Encrypt(const AES_byte* key, const AES_byte* iv, 
                                const AES_byte* plaintext, AES_byte* ciphertext, std::size_t length);
        static void CTR_Decrypt(const AES_byte* key, const AES_byte* iv, 
                                const AES_byte* ciphertext, AES_byte* plaintext, std::size_t length);
    };
}

#endif
