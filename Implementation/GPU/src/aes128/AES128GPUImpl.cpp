#include "aes128/AES128GPUImpl.h"
#include <aes128/AES128_GPU.h>
using namespace std;

namespace AES128GPUImpl {

vector<uint8_t> ecbEncrypt(const vector<uint8_t>& key,
                                const vector<uint8_t>& ptext) {
    vector<uint8_t> ctext(ptext.size());
    AES128_GPU::ecbEncBatch(const_cast<uint8_t*>(key.data()), const_cast<uint8_t*>(ptext.data()), ctext.data(), ptext.size() / 16);
    return ctext;
}

vector<uint8_t> ecbDecrypt(const vector<uint8_t>& key,
                                const vector<uint8_t>& ctext) {
    vector<uint8_t> ptext(ctext.size());
    AES128_GPU::ecbDecBatch(const_cast<uint8_t*>(key.data()), const_cast<uint8_t*>(ctext.data()), ptext.data(), ctext.size() / 16);
    return ptext;
}

vector<uint8_t> ctrEncrypt(const vector<uint8_t>& key,
                                const vector<uint8_t>& iv,
                                const vector<uint8_t>& ptext) {
    vector<uint8_t> ctext(ptext.size());
    AES128_GPU::ctrEncBatch(const_cast<uint8_t*>(key.data()), const_cast<uint8_t*>(iv.data()), const_cast<uint8_t*>(ptext.data()), ctext.data(), ptext.size() / 16);
    return ctext;
}

vector<uint8_t> ctrDecrypt(const vector<uint8_t>& key,
                                const vector<uint8_t>& iv,
                                const vector<uint8_t>& ctext) {
    vector<uint8_t> ptext(ctext.size());
    AES128_GPU::ctrDecBatch(const_cast<uint8_t*>(key.data()), const_cast<uint8_t*>(iv.data()), const_cast<uint8_t*>(ctext.data()), ptext.data(), ctext.size() / 16);
    return ptext;
}

}
