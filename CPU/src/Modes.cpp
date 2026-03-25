#include "common/Modes.h"

void CipherModes::increment_counter(uint8_t* counter, std::size_t size) {
    for (int i = size - 1; i >= 0; i--) {
        counter[i]++;
        if (counter[i] != 0) break;
    }
}
