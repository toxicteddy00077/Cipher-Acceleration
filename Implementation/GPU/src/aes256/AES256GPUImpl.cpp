#include "aes256/AES256GPUImpl.h"
#include <aes256/AES256_GPU.h>
using namespace std;

namespace AES256GPUImpl {

vector<uint8_t> ecbEncrypt(const vector<uint8_t>& key,
                                const vector<uint8_t>& ptext) {
    vector<uint8_t> ctext(ptext.size());
    AES256_GPU::ecbEncBatch(const_cast<uint8_t*>(key.data()), const_cast<uint8_t*>(ptext.data()), ctext.data(), ptext.size() / 16);
    return ctext;
}

vector<uint8_t> ecbDecrypt(const vector<uint8_t>& key,
                                const vector<uint8_t>& ctext) {
    vector<uint8_t> ptext(ctext.size());
    AES256_GPU::ecbDecBatch(const_cast<uint8_t*>(key.data()), const_cast<uint8_t*>(ctext.data()), ptext.data(), ctext.size() / 16);
    return ptext;
}

vector<uint8_t> ctrEncrypt(const vector<uint8_t>& key,
                                const vector<uint8_t>& iv,
                                const vector<uint8_t>& ptext) {
    vector<uint8_t> ctext(ptext.size());
    AES256_GPU::ctrEncBatch(const_cast<uint8_t*>(key.data()), const_cast<uint8_t*>(iv.data()), const_cast<uint8_t*>(ptext.data()), ctext.data(), ptext.size() / 16);
    return ctext;
}

vector<uint8_t> ctrDecrypt(const vector<uint8_t>& key,
                                const vector<uint8_t>& iv,
                                const vector<uint8_t>& ctext) {
    vector<uint8_t> ptext(ctext.size());
    AES256_GPU::ctrDecBatch(const_cast<uint8_t*>(key.data()), const_cast<uint8_t*>(iv.data()), const_cast<uint8_t*>(ctext.data()), ptext.data(), ctext.size() / 16);
    return ptext;
}

}
