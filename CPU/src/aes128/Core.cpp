#include "aes128/AES128.h"
#include "common/Utilities.h"
#include <algorithm>

void AES128_State::Load(const AES_byte input[AES128_Constants::BLOCK_SIZE]) {
    for (std::size_t i = 0; i < AES128_Constants::BLOCK_SIZE; ++i) {
        mat[i % 4][i / 4] = input[i];
    }
}

void AES128_State::Store(AES_byte output[AES128_Constants::BLOCK_SIZE]) const {
    for (std::size_t i = 0; i < AES128_Constants::BLOCK_SIZE; ++i) {
        output[i] = mat[i % 4][i / 4];
    }
}

void AES128_State::XorRoundKey(const AES_byte roundKey[AES128_Constants::BLOCK_SIZE]) {
    for (std::size_t i = 0; i < AES128_Constants::BLOCK_SIZE; ++i) {
        mat[i % 4][i / 4] ^= roundKey[i];
    }
}

namespace AES128_Utils {

using CommonUtils::xtime;
using CommonUtils::galoisMult;

// ============================================================
// Primitives - Encryption
// ============================================================

void Primitives::SubBytes(AES128_State &state) {
    for (std::size_t r = 0; r < AES128_Constants::STATE_DIM; ++r) {
        for (std::size_t c = 0; c < AES128_Constants::STATE_DIM; ++c) {
            state.mat[r][c] = AES128_Constants::SBOX[state.mat[r][c]];
        }
    }
}

void Primitives::ShiftRows(AES128_State &state) {
    std::rotate(&state.mat[1][0], &state.mat[1][1], &state.mat[1][4]);
    std::rotate(&state.mat[2][0], &state.mat[2][2], &state.mat[2][4]);
    std::rotate(&state.mat[3][0], &state.mat[3][3], &state.mat[3][4]);
}

void Primitives::MixColumns(AES128_State &state) {
    for (std::size_t c = 0; c < AES128_Constants::STATE_DIM; ++c) {
        AES_byte temp[4];
        for (std::size_t r = 0; r < 4; ++r)
            temp[r] = state.mat[r][c];

        state.mat[0][c] = galoisMult(0x02, temp[0]) ^ galoisMult(0x03, temp[1]) ^ temp[2] ^ temp[3];
        state.mat[1][c] = temp[0] ^ galoisMult(0x02, temp[1]) ^ galoisMult(0x03, temp[2]) ^ temp[3];
        state.mat[2][c] = temp[0] ^ temp[1] ^ galoisMult(0x02, temp[2]) ^ galoisMult(0x03, temp[3]);
        state.mat[3][c] = galoisMult(0x03, temp[0]) ^ temp[1] ^ temp[2] ^ galoisMult(0x02, temp[3]);
    }
}

void Primitives::AddRoundKey(AES128_State &state, const std::array<AES_byte, AES128_Constants::BLOCK_SIZE>& roundKey) {
    for (std::size_t i = 0; i < AES128_Constants::BLOCK_SIZE; ++i) {
        state.mat[i % 4][i / 4] ^= roundKey[i];
    }
}

// ============================================================
// Primitives - Decryption
// ============================================================

void Primitives::InvSubBytes(AES128_State &state) {
    for (std::size_t r = 0; r < AES128_Constants::STATE_DIM; ++r) {
        for (std::size_t c = 0; c < AES128_Constants::STATE_DIM; ++c) {
            state.mat[r][c] = AES128_Constants::INV_SBOX[state.mat[r][c]];
        }
    }
}

void Primitives::InvShiftRows(AES128_State &state) {
    std::rotate(&state.mat[1][0], &state.mat[1][3], &state.mat[1][4]);
    std::rotate(&state.mat[2][0], &state.mat[2][2], &state.mat[2][4]);
    std::rotate(&state.mat[3][0], &state.mat[3][1], &state.mat[3][4]);
}

void Primitives::InvMixColumns(AES128_State &state) {
    for (std::size_t c = 0; c < AES128_Constants::STATE_DIM; ++c) {
        AES_byte temp[4];
        for (std::size_t r = 0; r < 4; ++r)
            temp[r] = state.mat[r][c];

        state.mat[0][c] = galoisMult(0x0e, temp[0]) ^ galoisMult(0x0b, temp[1]) ^ galoisMult(0x0d, temp[2]) ^ galoisMult(0x09, temp[3]);
        state.mat[1][c] = galoisMult(0x09, temp[0]) ^ galoisMult(0x0e, temp[1]) ^ galoisMult(0x0b, temp[2]) ^ galoisMult(0x0d, temp[3]);
        state.mat[2][c] = galoisMult(0x0d, temp[0]) ^ galoisMult(0x09, temp[1]) ^ galoisMult(0x0e, temp[2]) ^ galoisMult(0x0b, temp[3]);
        state.mat[3][c] = galoisMult(0x0b, temp[0]) ^ galoisMult(0x0d, temp[1]) ^ galoisMult(0x09, temp[2]) ^ galoisMult(0x0e, temp[3]);
    }
}

// ============================================================
// Key Schedule
// ============================================================

void KeySchedule::RotWord(AES_byte* word) {
    AES_byte temp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = temp;
}

void KeySchedule::SubWord(AES_byte* word) {
    for (int i = 0; i < 4; ++i) {
        word[i] = AES128_Constants::SBOX[word[i]];
    }
}

std::array<AES_byte, AES128_Constants::EXPANDED_KEY_SIZE> KeySchedule::ExpandKey(const std::array<AES_byte, AES128_Constants::KEY_SIZE_128>& masterKey) {
    std::array<AES_byte, AES128_Constants::EXPANDED_KEY_SIZE> expandedKey;
    std::copy(masterKey.begin(), masterKey.end(), expandedKey.begin());

    for (std::size_t i = AES128_Constants::KEY_WORDS; i < AES128_Constants::TOTAL_WORDS; ++i) {
        std::size_t byteIndex = i * 4;
        std::size_t prevByteIndex = (i - 1) * 4;
        std::size_t prevPrevByteIndex = (i - AES128_Constants::KEY_WORDS) * 4;

        if (i % AES128_Constants::KEY_WORDS == 0) {
            AES_byte temp[4] = {expandedKey[prevByteIndex], expandedKey[prevByteIndex + 1], expandedKey[prevByteIndex + 2], expandedKey[prevByteIndex + 3]};
            RotWord(temp);
            SubWord(temp);
            temp[0] ^= AES128_Constants::RCON[(i / AES128_Constants::KEY_WORDS) - 1];

            for (int j = 0; j < 4; ++j) {
                expandedKey[byteIndex + j] = expandedKey[prevPrevByteIndex + j] ^ temp[j];
            }
        } else {
            for (int j = 0; j < 4; ++j) {
                expandedKey[byteIndex + j] = expandedKey[prevPrevByteIndex + j] ^ expandedKey[prevByteIndex + j];
            }
        }
    }

    return expandedKey;
}

}

void AES128_Utils::Modes::ECB_Encrypt(const AES_byte* key, const AES_byte* plaintext,
                                       AES_byte* ciphertext, std::size_t length) {
    auto expanded_key = KeySchedule::ExpandKey(
        *reinterpret_cast<const std::array<AES_byte, 16>*>(key));
    
    for (std::size_t i = 0; i < length; i += 16) {
        AES128_State state;
        state.Load(plaintext + i);
        
        std::array<AES_byte, 16> rkey;
        for (int j = 0; j < 16; j++) rkey[j] = expanded_key[j];
        state.XorRoundKey(rkey.data());
        
        for (int r = 1; r < 10; r++) {
            Primitives::SubBytes(state);
            Primitives::ShiftRows(state);
            Primitives::MixColumns(state);
            for (int j = 0; j < 16; j++) rkey[j] = expanded_key[r * 16 + j];
            Primitives::AddRoundKey(state, rkey);
        }
        
        Primitives::SubBytes(state);
        Primitives::ShiftRows(state);
        for (int j = 0; j < 16; j++) rkey[j] = expanded_key[160 + j];
        Primitives::AddRoundKey(state, rkey);
        
        state.Store(ciphertext + i);
    }
}

void AES128_Utils::Modes::ECB_Decrypt(const AES_byte* key, const AES_byte* ciphertext,
                                       AES_byte* plaintext, std::size_t length) {
    auto expanded_key = KeySchedule::ExpandKey(
        *reinterpret_cast<const std::array<AES_byte, 16>*>(key));
    
    for (std::size_t i = 0; i < length; i += 16) {
        AES128_State state;
        state.Load(ciphertext + i);
        
        std::array<AES_byte, 16> rkey;
        for (int j = 0; j < 16; j++) rkey[j] = expanded_key[160 + j];
        state.XorRoundKey(rkey.data());
        
        for (int r = 9; r > 0; r--) {
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

void AES128_Utils::Modes::CTR_Encrypt(const AES_byte* key, const AES_byte* iv,
                                      const AES_byte* plaintext, AES_byte* ciphertext, std::size_t length) {
    auto expanded_key = KeySchedule::ExpandKey(
        *reinterpret_cast<const std::array<AES_byte, 16>*>(key));
    
    uint8_t counter[16];
    for (int i = 0; i < 16; i++) counter[i] = iv[i];
    
    for (std::size_t i = 0; i < length; i += 16) {
        AES128_State state;
        state.Load(counter);
        
        std::array<AES_byte, 16> rkey;
        for (int j = 0; j < 16; j++) rkey[j] = expanded_key[j];
        state.XorRoundKey(rkey.data());
        
        for (int r = 1; r < 10; r++) {
            Primitives::SubBytes(state);
            Primitives::ShiftRows(state);
            Primitives::MixColumns(state);
            for (int j = 0; j < 16; j++) rkey[j] = expanded_key[r * 16 + j];
            Primitives::AddRoundKey(state, rkey);
        }
        
        Primitives::SubBytes(state);
        Primitives::ShiftRows(state);
        for (int j = 0; j < 16; j++) rkey[j] = expanded_key[160 + j];
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

void AES128_Utils::Modes::CTR_Decrypt(const AES_byte* key, const AES_byte* iv,
                                      const AES_byte* ciphertext, AES_byte* plaintext, std::size_t length) {
    CTR_Encrypt(key, iv, ciphertext, plaintext, length);
}
