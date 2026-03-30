#ifndef SALSA20_GPU_IMPL_H
#define SALSA20_GPU_IMPL_H

#include <cstddef>
#include <cstdint>
using namespace std;
#include <vector>

namespace Salsa20GPUImpl {
    vector<uint8_t> ctrEncrypt(const vector<uint8_t>& key,
                                    const vector<uint8_t>& nonce,
                                    const vector<uint8_t>& ptext);
    vector<uint8_t> ctrDecrypt(const vector<uint8_t>& key,
                                    const vector<uint8_t>& nonce,
                                    const vector<uint8_t>& ctext);
}

#endif
