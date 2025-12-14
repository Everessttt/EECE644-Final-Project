#pragma once

#include <iostream>
#include <vector>

using std::vector;
using std::uint8_t;

//prototypes
vector<uint8_t> ChaCha20(const vector<uint8_t>& key, const uint32_t counter, const vector<uint8_t>& nonce);
vector<uint8_t> Poly1305(vector<uint8_t>& r, vector<uint8_t>& s, vector<uint8_t>& msg);
struct AEAD_encrypt{vector<uint8_t> ciphertext; vector<uint8_t> tag;};
struct AEAD_decrypt{vector<uint8_t> plaintext; bool is_valid;};
AEAD_encrypt ChaCha20_Poly1305_encrypt(const vector<uint8_t>& key, const vector<uint8_t>& nonce, const vector<uint8_t>& plaintext, const vector<uint8_t>& ad);
AEAD_decrypt ChaCha20_Poly1305_decrypt(const vector<uint8_t>& key, const vector<uint8_t>& nonce, const vector<uint8_t>& ciphertext, const vector<uint8_t>& ad, const vector<uint8_t>& recieved_tag);