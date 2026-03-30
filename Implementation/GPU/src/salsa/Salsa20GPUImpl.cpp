#include "salsa/Salsa20GPUImpl.h"
#include <salsa/Salsa20_GPU.h>
using namespace std;

namespace Salsa20GPUImpl {

vector<uint8_t> ctrEncrypt(const vector<uint8_t>& key,
                                const vector<uint8_t>& nonce,
                                const vector<uint8_t>& ptext) {
    vector<uint8_t> ctext(ptext.size());
    Salsa20_GPU::ctrEncBatch(const_cast<uint8_t*>(key.data()), const_cast<uint8_t*>(nonce.data()), const_cast<uint8_t*>(ptext.data()), ctext.data(), ptext.size() / 64);
    return ctext;
}

vector<uint8_t> ctrDecrypt(const vector<uint8_t>& key,
                                const vector<uint8_t>& nonce,
                                const vector<uint8_t>& ctext) {
    vector<uint8_t> ptext(ctext.size());
    Salsa20_GPU::ctrDecBatch(const_cast<uint8_t*>(key.data()), const_cast<uint8_t*>(nonce.data()), const_cast<uint8_t*>(ctext.data()), ptext.data(), ctext.size() / 64);
    return ptext;
}

}
