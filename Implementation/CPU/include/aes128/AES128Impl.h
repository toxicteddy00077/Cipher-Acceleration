#ifndef AES128_IMPL_H
#define AES128_IMPL_H

#include <cstddef>
#include <cstdint>
using namespace std;
#include <vector>

namespace AES128Impl {
    vector<uint8_t> ecbEncrypt(const vector<uint8_t>& key,
                                    const vector<uint8_t>& ptext);
    vector<uint8_t> ecbDecrypt(const vector<uint8_t>& key,
                                    const vector<uint8_t>& ctext);

    vector<uint8_t> ctrEncrypt(const vector<uint8_t>& key,
                                    const vector<uint8_t>& iv,
                                    const vector<uint8_t>& ptext);
    vector<uint8_t> ctrDecrypt(const vector<uint8_t>& key,
                                    const vector<uint8_t>& iv,
                                    const vector<uint8_t>& ctext);
}

#endif
