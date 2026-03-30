#include "salsa/Salsa20Impl.h"
#include <salsa/Salsa20.h>
using namespace std;

namespace Salsa20Impl {

vector<uint8_t> ctrEncrypt(const vector<uint8_t>& key,
                                const vector<uint8_t>& nonce,
                                const vector<uint8_t>& ptext) {
    vector<uint8_t> ctext(ptext.size());
    Salsa20_Utils::Modes::CTR_Encrypt(key.data(), nonce.data(), ptext.data(), ctext.data(), ptext.size());
    return ctext;
}

vector<uint8_t> ctrDecrypt(const vector<uint8_t>& key,
                                const vector<uint8_t>& nonce,
                                const vector<uint8_t>& ctext) {
    vector<uint8_t> ptext(ctext.size());
    Salsa20_Utils::Modes::CTR_Decrypt(key.data(), nonce.data(), ctext.data(), ptext.data(), ctext.size());
    return ptext;
}

}
