#ifndef COMMON_UTILITIES_H
#define COMMON_UTILITIES_H

#include <cstddef>
#include <cstdint>
#include <array>

namespace CommonUtils {

// ============================================================
// Bit Rotation Operations
// ============================================================

template<typename T>
constexpr T rotL(T x, std::size_t n) {
    return (x << n) | (x >> (sizeof(T) * 8 - n));
}

template<typename T>
constexpr T rotR(T x, std::size_t n) {
    return (x >> n) | (x << (sizeof(T) * 8 - n));
}

// ============================================================
// Bit Access Operations
// ============================================================

template<typename T>
inline T getBt(const T& word, std::size_t bit) {
    return (word >> bit) & 1;
}

template<typename T>
inline void setBt(T& word, std::size_t bit, T val) {
    if (val) {
        word |= (1 << bit);
    } else {
        word &= ~(1 << bit);
    }
}

template<typename T>
inline T getBtArr(const std::array<T, 9>& state, std::size_t bit) {
    return (state[bit / (sizeof(T) * 8)] >> (bit % (sizeof(T) * 8))) & 1;
}

template<typename T>
inline void setBtArr(std::array<T, 9>& state, std::size_t bit, T val) {
    if (val) {
        state[bit / (sizeof(T) * 8)] |= (1 << (bit % (sizeof(T) * 8)));
    } else {
        state[bit / (sizeof(T) * 8)] &= ~(1 << (bit % (sizeof(T) * 8)));
    }
}

// ============================================================
// Galois Field Arithmetic (GF(2^8))
// ============================================================

constexpr uint8_t GALOIS_POLY = 0x1B;

inline uint8_t xTime(uint8_t x) {
    return (x << 1) ^ ((x & 0x80) ? GALOIS_POLY : 0x00);
}

inline uint8_t gfMult(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    while (b) {
        if (b & 1) result ^= a;
        a = xTime(a);
        b >>= 1;
    }
    return result;
}

// ============================================================
// Byte Packing/Unpacking
// ============================================================

template<typename T>
inline T loadWord(const uint8_t* bytes, std::size_t offset = 0) {
    T word = 0;
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        word |= static_cast<T>(bytes[offset + i]) << (8 * i);
    }
    return word;
}

template<typename T>
inline void storeWord(uint8_t* bytes, T word, std::size_t offset = 0) {
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        bytes[offset + i] = (word >> (8 * i)) & 0xFF;
    }
}

template<typename T>
inline T loadWordBE(const uint8_t* bytes, std::size_t offset = 0) {
    T word = 0;
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        word |= static_cast<T>(bytes[offset + i]) << (8 * (sizeof(T) - 1 - i));
    }
    return word;
}

template<typename T>
inline void storeWordBE(uint8_t* bytes, T word, std::size_t offset = 0) {
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        bytes[offset + i] = (word >> (8 * (sizeof(T) - 1 - i))) & 0xFF;
    }
}

// ============================================================
// Utility Constants
// ============================================================

constexpr uint8_t BYTE_MASK = 0xFF;
constexpr uint16_t WORD16_MASK = 0xFFFF;
constexpr uint32_t WORD32_MASK = 0xFFFFFFFF;
constexpr uint64_t WORD64_MASK = 0xFFFFFFFFFFFFFFFF;

}

#endif
