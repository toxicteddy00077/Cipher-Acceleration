#include "trivium/TriviumImpl.h"
#include <trivium/Trivium.h>
using namespace std;

using namespace std;

namespace TriviumImpl {

vector<uint8_t> ctrEncrypt(const vector<uint8_t>& key,
                                const vector<uint8_t>& nonce,
                                const vector<uint8_t>& ptext) {
    vector<uint8_t> ctext(ptext.size());
    Trivium_Utils::Modes::CTR_Encrypt(key.data(), nonce.data(), ptext.data(), ctext.data(), ptext.size());
    return ctext;
}

vector<uint8_t> ctrDecrypt(const vector<uint8_t>& key,
                                const vector<uint8_t>& nonce,
                                const vector<uint8_t>& ctext) {
    vector<uint8_t> ptext(ctext.size());
    Trivium_Utils::Modes::CTR_Decrypt(key.data(), nonce.data(), ctext.data(), ptext.data(), ctext.size());
    return ptext;
}

}
