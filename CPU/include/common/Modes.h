#ifndef CIPHER_MODES_H
#define CIPHER_MODES_H

#include <cstddef>
#include <cstdint>
#include <array>

namespace CipherModes {
    void increment_counter(uint8_t* counter, std::size_t size);
}

#endif
