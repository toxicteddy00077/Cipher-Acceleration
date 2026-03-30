#include "aes256/AES256Impl.h"
#include <aes256/AES256.h>
using namespace std;

namespace AES256Impl {

vector<uint8_t> ecbEncrypt(const vector<uint8_t>& key,
                                const vector<uint8_t>& ptext) {
    vector<uint8_t> ctext(ptext.size());
    AES256_Utils::Modes::ECB_Encrypt(key.data(), ptext.data(), ctext.data(), ptext.size());
    return ctext;
}

vector<uint8_t> ecbDecrypt(const vector<uint8_t>& key,
                                const vector<uint8_t>& ctext) {
    vector<uint8_t> ptext(ctext.size());
    AES256_Utils::Modes::ECB_Decrypt(key.data(), ctext.data(), ptext.data(), ctext.size());
    return ptext;
}

vector<uint8_t> ctrEncrypt(const vector<uint8_t>& key,
                                const vector<uint8_t>& iv,
                                const vector<uint8_t>& ptext) {
    vector<uint8_t> ctext(ptext.size());
    AES256_Utils::Modes::CTR_Encrypt(key.data(), iv.data(), ptext.data(), ctext.data(), ptext.size());
    return ctext;
}

vector<uint8_t> ctrDecrypt(const vector<uint8_t>& key,
                                const vector<uint8_t>& iv,
                                const vector<uint8_t>& ctext) {
    vector<uint8_t> ptext(ctext.size());
    AES256_Utils::Modes::CTR_Decrypt(key.data(), iv.data(), ctext.data(), ptext.data(), ctext.size());
    return ptext;
}

}
