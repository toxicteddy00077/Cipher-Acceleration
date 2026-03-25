#include "aes256/AES256.h"
#include "common/Utilities.h"
#include <algorithm>

// ============================================================
// State Operations
// ============================================================

void AES256_State::Load(const AES_byte input[AES256_Constants::BLOCK_SIZE]) {
    for (std::size_t i = 0; i < AES256_Constants::BLOCK_SIZE; ++i) {
        mat[i % 4][i / 4] = input[i];
    }
}

void AES256_State::Store(AES_byte output[AES256_Constants::BLOCK_SIZE]) const {
    for (std::size_t i = 0; i < AES256_Constants::BLOCK_SIZE; ++i) {
        output[i] = mat[i % 4][i / 4];
    }
}

void AES256_State::XorRoundKey(const AES_byte roundKey[AES256_Constants::BLOCK_SIZE]) {
    for (std::size_t i = 0; i < AES256_Constants::BLOCK_SIZE; ++i) {
        mat[i % 4][i / 4] ^= roundKey[i];
    }
}

namespace AES256_Utils {

using CommonUtils::xtime;
using CommonUtils::galoisMult;

// ============================================================
// Primitives - Encryption
// ============================================================

void Primitives::SubBytes(AES256_State &state) {
    for (std::size_t r = 0; r < AES256_Constants::STATE_DIM; ++r) {
        for (std::size_t c = 0; c < AES256_Constants::STATE_DIM; ++c) {
            state.mat[r][c] = AES256_Constants::SBOX[state.mat[r][c]];
        }
    }
}

void Primitives::ShiftRows(AES256_State &state) {
    std::rotate(&state.mat[1][0], &state.mat[1][1], &state.mat[1][4]);
    std::rotate(&state.mat[2][0], &state.mat[2][2], &state.mat[2][4]);
    std::rotate(&state.mat[3][0], &state.mat[3][3], &state.mat[3][4]);
}

void Primitives::MixColumns(AES256_State &state) {
    for (std::size_t c = 0; c < AES256_Constants::STATE_DIM; ++c) {
        AES_byte temp[4];
        for (std::size_t r = 0; r < 4; ++r)
            temp[r] = state.mat[r][c];

        state.mat[0][c] = galoisMult(0x02, temp[0]) ^ galoisMult(0x03, temp[1]) ^ temp[2] ^ temp[3];
        state.mat[1][c] = temp[0] ^ galoisMult(0x02, temp[1]) ^ galoisMult(0x03, temp[2]) ^ temp[3];
        state.mat[2][c] = temp[0] ^ temp[1] ^ galoisMult(0x02, temp[2]) ^ galoisMult(0x03, temp[3]);
        state.mat[3][c] = galoisMult(0x03, temp[0]) ^ temp[1] ^ temp[2] ^ galoisMult(0x02, temp[3]);
    }
}

void Primitives::AddRoundKey(AES256_State &state,
                             const std::array<AES_byte, AES256_Constants::BLOCK_SIZE>& roundKey) {
    for (std::size_t i = 0; i < AES256_Constants::BLOCK_SIZE; ++i) {
        state.mat[i % 4][i / 4] ^= roundKey[i];
    }
}

// ============================================================
// Primitives - Decryption
// ============================================================

void Primitives::InvSubBytes(AES256_State &state) {
    for (std::size_t r = 0; r < AES256_Constants::STATE_DIM; ++r) {
        for (std::size_t c = 0; c < AES256_Constants::STATE_DIM; ++c) {
            state.mat[r][c] = AES256_Constants::INV_SBOX[state.mat[r][c]];
        }
    }
}

void Primitives::InvShiftRows(AES256_State &state) {
    std::rotate(&state.mat[1][0], &state.mat[1][3], &state.mat[1][4]);
    std::rotate(&state.mat[2][0], &state.mat[2][2], &state.mat[2][4]);
    std::rotate(&state.mat[3][0], &state.mat[3][1], &state.mat[3][4]);
}

void Primitives::InvMixColumns(AES256_State &state) {
    for (std::size_t c = 0; c < AES256_Constants::STATE_DIM; ++c) {
        AES_byte temp[4];
        for (std::size_t r = 0; r < 4; ++r)
            temp[r] = state.mat[r][c];

        state.mat[0][c] = galoisMult(0x0E, temp[0]) ^ galoisMult(0x0B, temp[1]) ^ galoisMult(0x0D, temp[2]) ^ galoisMult(0x09, temp[3]);
        state.mat[1][c] = galoisMult(0x09, temp[0]) ^ galoisMult(0x0E, temp[1]) ^ galoisMult(0x0B, temp[2]) ^ galoisMult(0x0D, temp[3]);
        state.mat[2][c] = galoisMult(0x0D, temp[0]) ^ galoisMult(0x09, temp[1]) ^ galoisMult(0x0E, temp[2]) ^ galoisMult(0x0B, temp[3]);
        state.mat[3][c] = galoisMult(0x0B, temp[0]) ^ galoisMult(0x0D, temp[1]) ^ galoisMult(0x09, temp[2]) ^ galoisMult(0x0E, temp[3]);
    }
}

// ============================================================
// KeySchedule - Key Expansion
// ============================================================

static void rotWord(AES_byte* word) {
    AES_byte temp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = temp;
}

static void subWord(AES_byte* word) {
    for (std::size_t i = 0; i < 4; ++i) {
        word[i] = AES256_Constants::SBOX[word[i]];
    }
}

std::array<AES_byte, AES256_Constants::EXPANDED_KEY_SIZE> KeySchedule::ExpandKey(
    const std::array<AES_byte, AES256_Constants::KEY_SIZE_256>& masterKey) {

    std::array<AES_byte, AES256_Constants::EXPANDED_KEY_SIZE> expandedKey;

    for (std::size_t i = 0; i < AES256_Constants::KEY_SIZE_256; ++i) {
        expandedKey[i] = masterKey[i];
    }

    for (std::size_t i = AES256_Constants::KEY_WORDS; i < AES256_Constants::TOTAL_WORDS; ++i) {
        std::size_t wordIndex = i * AES256_Constants::WORD_SIZE;
        std::size_t prevWordIndex = (i - 1) * AES256_Constants::WORD_SIZE;
        std::size_t prev8WordIndex = (i - AES256_Constants::KEY_WORDS) * AES256_Constants::WORD_SIZE;

        if (i % AES256_Constants::KEY_WORDS == 0) {
            AES_byte temp[4];
            temp[0] = expandedKey[prevWordIndex + 1];
            temp[1] = expandedKey[prevWordIndex + 2];
            temp[2] = expandedKey[prevWordIndex + 3];
            temp[3] = expandedKey[prevWordIndex];

            rotWord(temp);
            subWord(temp);
            temp[0] ^= AES256_Constants::RCON[(i / AES256_Constants::KEY_WORDS) - 1];

            for (std::size_t j = 0; j < 4; ++j) {
                expandedKey[wordIndex + j] = expandedKey[prev8WordIndex + j] ^ temp[j];
            }
        } else if (AES256_Constants::KEY_WORDS > 6 && i % AES256_Constants::KEY_WORDS == 4) {
            AES_byte temp[4];
            for (std::size_t j = 0; j < 4; ++j) {
                temp[j] = expandedKey[prevWordIndex + j];
            }
            subWord(temp);
            for (std::size_t j = 0; j < 4; ++j) {
                expandedKey[wordIndex + j] = expandedKey[prev8WordIndex + j] ^ temp[j];
            }
        } else {
            for (std::size_t j = 0; j < 4; ++j) {
                expandedKey[wordIndex + j] = expandedKey[prev8WordIndex + j] ^ expandedKey[prevWordIndex + j];
            }
        }
    }

    return expandedKey;
}

} // namespace AES256_Utils

void AES256_Utils::Modes::ECB_Encrypt(const AES_byte* key, const AES_byte* plaintext,
                                       AES_byte* ciphertext, std::size_t length) {
    auto expanded_key = KeySchedule::ExpandKey(
        *reinterpret_cast<const std::array<AES_byte, 32>*>(key));
    
    for (std::size_t i = 0; i < length; i += 16) {
        AES256_State state;
        state.Load(plaintext + i);
        
        std::array<AES_byte, 16> rkey;
        for (int j = 0; j < 16; j++) rkey[j] = expanded_key[j];
        state.XorRoundKey(rkey.data());
        
        for (int r = 1; r < 14; r++) {
            Primitives::SubBytes(state);
            Primitives::ShiftRows(state);
            Primitives::MixColumns(state);
            for (int j = 0; j < 16; j++) rkey[j] = expanded_key[r * 16 + j];
            Primitives::AddRoundKey(state, rkey);
        }
        
        Primitives::SubBytes(state);
        Primitives::ShiftRows(state);
        for (int j = 0; j < 16; j++) rkey[j] = expanded_key[224 + j];
        Primitives::AddRoundKey(state, rkey);
        
        state.Store(ciphertext + i);
    }
}

void AES256_Utils::Modes::ECB_Decrypt(const AES_byte* key, const AES_byte* ciphertext,
                                       AES_byte* plaintext, std::size_t length) {
    auto expanded_key = KeySchedule::ExpandKey(
        *reinterpret_cast<const std::array<AES_byte, 32>*>(key));
    
    for (std::size_t i = 0; i < length; i += 16) {
        AES256_State state;
        state.Load(ciphertext + i);
        
        std::array<AES_byte, 16> rkey;
        for (int j = 0; j < 16; j++) rkey[j] = expanded_key[224 + j];
        state.XorRoundKey(rkey.data());
        
        for (int r = 13; r > 0; r--) {
            Primitives::InvShiftRows(state);
            Primitives::InvSubBytes(state);
            for (int j = 0; j < 16; j++) rkey[j] = expanded_key[r * 16 + j];
            Primitives::AddRoundKey(state, rkey);
            Primitives::InvMixColumns(state);
        }
        
        Primitives::InvShiftRows(state);
        Primitives::InvSubBytes(state);
        for (int j = 0; j < 16; j++) rkey[j] = expanded_key[j];
        Primitives::AddRoundKey(state, rkey);
        
        state.Store(plaintext + i);
    }
}

void AES256_Utils::Modes::CTR_Encrypt(const AES_byte* key, const AES_byte* iv,
                                      const AES_byte* plaintext, AES_byte* ciphertext, std::size_t length) {
    auto expanded_key = KeySchedule::ExpandKey(
        *reinterpret_cast<const std::array<AES_byte, 32>*>(key));
    
    uint8_t counter[16];
    for (int i = 0; i < 16; i++) counter[i] = iv[i];
    
    for (std::size_t i = 0; i < length; i += 16) {
        AES256_State state;
        state.Load(counter);
        
        std::array<AES_byte, 16> rkey;
        for (int j = 0; j < 16; j++) rkey[j] = expanded_key[j];
        state.XorRoundKey(rkey.data());
        
        for (int r = 1; r < 14; r++) {
            Primitives::SubBytes(state);
            Primitives::ShiftRows(state);
            Primitives::MixColumns(state);
            for (int j = 0; j < 16; j++) rkey[j] = expanded_key[r * 16 + j];
            Primitives::AddRoundKey(state, rkey);
        }
        
        Primitives::SubBytes(state);
        Primitives::ShiftRows(state);
        for (int j = 0; j < 16; j++) rkey[j] = expanded_key[224 + j];
        Primitives::AddRoundKey(state, rkey);
        
        uint8_t keystream[16];
        state.Store(keystream);
        
        std::size_t block_len = (length - i < 16) ? (length - i) : 16;
        for (std::size_t j = 0; j < block_len; j++)
            ciphertext[i + j] = plaintext[i + j] ^ keystream[j];
        
        for (int j = 15; j >= 0; j--) {
            counter[j]++;
            if (counter[j] != 0) break;
        }
    }
}

void AES256_Utils::Modes::CTR_Decrypt(const AES_byte* key, const AES_byte* iv,
                                      const AES_byte* ciphertext, AES_byte* plaintext, std::size_t length) {
    CTR_Encrypt(key, iv, ciphertext, plaintext, length);
}
