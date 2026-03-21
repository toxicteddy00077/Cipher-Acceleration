#include "trivium/Trivium.h"
#include "common/Utilities.h"

void Trivium_State::Load(const uint8_t key[10], const uint8_t nonce[10]) {
    state.fill(0);
    
    for (std::size_t i = 0; i < 10; ++i) {
        state[i / 4] |= static_cast<uint32_t>(key[i]) << (8 * (i % 4));
    }

    for (std::size_t i = 0; i < 10; ++i) {
        state[3 + i / 4] |= static_cast<uint32_t>(nonce[i]) << (8 * (i % 4));
    }
}

uint32_t Trivium_State::GenerateKeystream() {
    uint32_t output = 0;
    
    for (std::size_t i = 0; i < 32; ++i) {
        output |= (((CommonUtils::getBitFromArray(state, 1 * 32 + 4) ^ CommonUtils::getBitFromArray(state, 4 * 32 + 13) ^ CommonUtils::getBitFromArray(state, 7 * 32 + 1)) & 1U) << i);
        Trivium_Utils::Primitives::UpdateState(*this);
    }
    
    return output;
}

namespace Trivium_Utils {

using CommonUtils::getBitFromArray;
using CommonUtils::setBitInArray;

uint32_t Primitives::Output(const Trivium_State &state) {
    return (getBitFromArray(state.state, 65) ^ getBitFromArray(state.state, 170) ^ getBitFromArray(state.state, 263));
}

void Primitives::UpdateState(Trivium_State &state) {
    uint32_t t1 = getBitFromArray(state.state, 65) ^ getBitFromArray(state.state, 92);
    uint32_t t2 = getBitFromArray(state.state, 170) ^ getBitFromArray(state.state, 263);
    uint32_t t3 = getBitFromArray(state.state, 263) ^ getBitFromArray(state.state, 287);

    uint32_t t4 = t1 ^ getBitFromArray(state.state, 161) ^ getBitFromArray(state.state, 176);
    uint32_t t5 = t2 ^ getBitFromArray(state.state, 242) ^ getBitFromArray(state.state, 287);
    uint32_t t6 = t3 ^ getBitFromArray(state.state, 68) ^ getBitFromArray(state.state, 93);

    setBitInArray(state.state, 0, t6);
    setBitInArray(state.state, 93, t4);
    setBitInArray(state.state, 177, t5);
}

void Primitives::Initialize(Trivium_State &state, const uint8_t key[10], const uint8_t nonce[10]) {
    state.Load(key, nonce);

    for (std::size_t i = 0; i < Trivium_Constants::INITIALIZATION_ROUNDS; ++i) {
        UpdateState(state);
    }
}

uint32_t Primitives::GenerateOutput(Trivium_State &state) {
    return state.GenerateKeystream();
}

Trivium_State KeySchedule::Setup(const std::array<uint8_t, Trivium_Constants::KEY_SIZE / 8>& key,
                                 const std::array<uint8_t, Trivium_Constants::NONCE_SIZE / 8>& nonce) {
    Trivium_State state;
    Primitives::Initialize(state, key.data(), nonce.data());
    return state;
}

}
