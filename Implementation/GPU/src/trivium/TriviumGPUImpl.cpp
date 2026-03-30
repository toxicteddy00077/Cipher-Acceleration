#include "trivium/TriviumGPUImpl.h"
#include <trivium/Trivium_GPU.h>
using namespace std;

namespace TriviumGPUImpl {

vector<uint8_t> ctrEncrypt(const vector<uint8_t>& key,
                                const vector<uint8_t>& nonce,
                                const vector<uint8_t>& ptext) {
    vector<uint8_t> ctext(ptext.size());
    Trivium_GPU::ctrEncBatch(const_cast<uint8_t*>(key.data()), const_cast<uint8_t*>(nonce.data()), const_cast<uint8_t*>(ptext.data()), ctext.data(), ptext.size() / 4);
    return ctext;
}

vector<uint8_t> ctrDecrypt(const vector<uint8_t>& key,
                                const vector<uint8_t>& nonce,
                                const vector<uint8_t>& ctext) {
    vector<uint8_t> ptext(ctext.size());
    Trivium_GPU::ctrDecBatch(const_cast<uint8_t*>(key.data()), const_cast<uint8_t*>(nonce.data()), const_cast<uint8_t*>(ctext.data()), ptext.data(), ctext.size() / 4);
    return ptext;
}

}
