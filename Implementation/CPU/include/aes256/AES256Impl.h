#ifndef AES256_IMPL_H
#define AES256_IMPL_H

#include <cstddef>
#include <cstdint>
using namespace std;
#include <vector>

namespace AES256Impl {
    // ECB mode encryption/decryption
    vector<uint8_t> ecbEncrypt(const vector<uint8_t>& key,
                                    const vector<uint8_t>& ptext);
    vector<uint8_t> ecbDecrypt(const vector<uint8_t>& key,
                                    const vector<uint8_t>& ctext);

    // CTR mode encryption/decryption
    vector<uint8_t> ctrEncrypt(const vector<uint8_t>& key,
                                    const vector<uint8_t>& iv,
                                    const vector<uint8_t>& ptext);
    vector<uint8_t> ctrDecrypt(const vector<uint8_t>& key,
                                    const vector<uint8_t>& iv,
                                    const vector<uint8_t>& ctext);
}

#endif
