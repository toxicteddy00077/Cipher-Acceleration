#include "ascon/AsconImpl.h"
#include <ascon/Ascon.h>
using namespace std;

namespace AsconImpl {

vector<uint8_t> ctrEncrypt(const vector<uint8_t>& key,
                                const vector<uint8_t>& nonce,
                                const vector<uint8_t>& ptext) {
    vector<uint8_t> ctext(ptext.size());
    ASCON_Utils::Modes::CTR_Encrypt(key.data(), nonce.data(), ptext.data(), ctext.data(), ptext.size());
    return ctext;
}

vector<uint8_t> ctrDecrypt(const vector<uint8_t>& key,
                                const vector<uint8_t>& nonce,
                                const vector<uint8_t>& ctext) {
    vector<uint8_t> ptext(ctext.size());
    ASCON_Utils::Modes::CTR_Decrypt(key.data(), nonce.data(), ctext.data(), ptext.data(), ctext.size());
    return ptext;
}

}
