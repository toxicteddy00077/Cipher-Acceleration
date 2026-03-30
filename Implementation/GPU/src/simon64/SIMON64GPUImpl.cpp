#include "simon64/SIMON64GPUImpl.h"
#include <simon64/SIMON64_GPU.h>
using namespace std;

namespace SIMON64GPUImpl {

vector<uint8_t> ecbEncrypt(const vector<uint8_t>& key,
                                const vector<uint8_t>& ptext) {
    vector<uint8_t> ctext(ptext.size());
    SIMON64_GPU::ecbEncBatch(const_cast<uint8_t*>(key.data()), const_cast<uint8_t*>(ptext.data()), ctext.data(), ptext.size() / 8);
    return ctext;
}

vector<uint8_t> ecbDecrypt(const vector<uint8_t>& key,
                                const vector<uint8_t>& ctext) {
    vector<uint8_t> ptext(ctext.size());
    SIMON64_GPU::ecbDecBatch(const_cast<uint8_t*>(key.data()), const_cast<uint8_t*>(ctext.data()), ptext.data(), ctext.size() / 8);
    return ptext;
}

vector<uint8_t> ctrEncrypt(const vector<uint8_t>& key,
                                const vector<uint8_t>& iv,
                                const vector<uint8_t>& ptext) {
    vector<uint8_t> ctext(ptext.size());
    SIMON64_GPU::ctrEncBatch(const_cast<uint8_t*>(key.data()), const_cast<uint8_t*>(iv.data()), const_cast<uint8_t*>(ptext.data()), ctext.data(), ptext.size() / 8);
    return ctext;
}

vector<uint8_t> ctrDecrypt(const vector<uint8_t>& key,
                                const vector<uint8_t>& iv,
                                const vector<uint8_t>& ctext) {
    vector<uint8_t> ptext(ctext.size());
    SIMON64_GPU::ctrDecBatch(const_cast<uint8_t*>(key.data()), const_cast<uint8_t*>(iv.data()), const_cast<uint8_t*>(ctext.data()), ptext.data(), ctext.size() / 8);
    return ptext;
}

}
