#include <iostream>
#include <vector>
#include <string>
#include <algorithm>

using namespace std;

#include "ChaCha20-Poly1305.h"

//helpers
namespace {
    //ChaCha20 helpers
    uint32_t rotl(uint32_t x, int n) 
    {
        return (x << n) | (x >> (32 - n));
    }

    void quarter_round(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d) 
    {
        a += b; d ^= a; d = rotl(d, 16);
        c += d; b ^= c; b = rotl(b, 12);
        a += b; d ^= a; d = rotl(d, 8);
        c += d; b ^= c; b = rotl(b, 7);
    }

    vector<uint32_t> bytes_to_words(const vector<uint8_t>& vec8) 
    {
        size_t n = vec8.size() / 4;
        vector<uint32_t> vec32(n);
        
        for(size_t i = 0; i < n; i++) {
            uint32_t word =
                static_cast<uint32_t>(vec8[i*4 + 0]) | 
                (static_cast<uint32_t>(vec8[i*4 + 1]) << 8) | 
                (static_cast<uint32_t>(vec8[i*4 + 2]) << 16) | 
                (static_cast<uint32_t>(vec8[i*4 + 3]) << 24
            );
            vec32[i] = word;
        }

        return vec32;
    }

    //Poly1305 helpers
    vector<uint32_t> bytes_to_limbs(const vector<uint8_t>& vec8) 
    {
        vector<uint32_t> vec26(5, 0);
        int bit_offset = 0;
        int limb_idx = 0;

        //assign each byte to the correct limb
        for(size_t i = 0; i < 17 && i < vec8.size(); i++) {
            //assign byte to limb and increment offset
            vec26[limb_idx] |= static_cast<uint32_t>(vec8[i]) << bit_offset;
            bit_offset += 8;

            //when offset overflows reset offset, cap current limb to 26'b, and assign remainder of byte to next limb
            if(bit_offset >= 26) {
                bit_offset = bit_offset - 26;
                vec26[limb_idx] &= 0x03FFFFFF;
                if(limb_idx < 4) {
                    limb_idx++;
                    vec26[limb_idx] |= static_cast<uint32_t>(vec8[i]) >> (8 - bit_offset);
                }
            }
        }
        
        return vec26;
    }

    vector<uint32_t> limbs_add(const vector<uint32_t>& a, const vector<uint32_t>& b) 
    {
        vector<uint32_t> result(5, 0);
        uint32_t c = 0; //carry

        for(int i = 0; i < 5; i++) {
            uint32_t temp = a[i] + b[i] + c;
            result[i] = temp & 0x03FFFFFF;
            c = temp >> 26;
        }

        return result;
    }

    vector<uint32_t> limbs_mul(const vector<uint32_t>& a, const vector<uint32_t>& b)
    {
        uint64_t r0 = a[0], r1 = a[1], r2 = a[2], r3 = a[3], r4 = a[4];
        uint64_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;

        uint64_t t0 = r0*b[0] + s1*b[4] + s2*b[3] + s3*b[2] + s4*b[1];
        uint64_t t1 = r0*b[1] + r1*b[0] + s2*b[4] + s3*b[3] + s4*b[2];
        uint64_t t2 = r0*b[2] + r1*b[1] + r2*b[0] + s3*b[4] + s4*b[3];
        uint64_t t3 = r0*b[3] + r1*b[2] + r2*b[1] + r3*b[0] + s4*b[4];
        uint64_t t4 = r0*b[4] + r1*b[3] + r2*b[2] + r3*b[1] + r4*b[0];

        uint64_t c; //carry
        c = (t0 >> 26); t0 &= 0x3ffffff; t1 += c;
        c = (t1 >> 26); t1 &= 0x3ffffff; t2 += c;
        c = (t2 >> 26); t2 &= 0x3ffffff; t3 += c;
        c = (t3 >> 26); t3 &= 0x3ffffff; t4 += c;
        c = (t4 >> 26); t4 &= 0x3ffffff; t0 += c * 5;
        c = (t0 >> 26); t0 &= 0x3ffffff; t1 += c;

        return {
            static_cast<uint32_t>(t0), static_cast<uint32_t>(t1), static_cast<uint32_t>(t2), static_cast<uint32_t>(t3), static_cast<uint32_t>(t4)
        };
    }

    //ChaCha20-Poly1305 helpers
    vector<uint8_t> compute_tag(const vector<uint8_t>& key, const vector<uint8_t>& nonce, const vector<uint8_t>& ciphertext, const vector<uint8_t>& ad)
    {
        //generate one-time Poly1305 key
        vector<uint8_t> otk = ChaCha20(key, 0, nonce);
        vector<uint8_t> r(otk.begin(), otk.begin() + 16);
        vector<uint8_t> s(otk.begin() + 16, otk.begin() + 32);

        //create input for Poly1305
        vector<uint8_t> poly_input;

        //append and pad additional data
        poly_input.insert(poly_input.end(), ad.begin(), ad.end());
        while(poly_input.size() % 16 != 0) {
            poly_input.push_back(0);
        }

        //append and pad ciphertext
        poly_input.insert(poly_input.end(), ciphertext.begin(), ciphertext.end());
        while(poly_input.size() % 16 != 0) {
            poly_input.push_back(0);
        }

        //append length of additional data and ciphertext
        uint64_t ad_len = ad.size();
        uint64_t ciphertext_len = ciphertext.size();
        
        for(int i = 0; i < 8; i++) {
            poly_input.push_back((ad_len >> (8*i)) & 0xFF);
        }
        for(int i = 0; i < 8; i++) {
            poly_input.push_back((ciphertext_len >> (8*i)) & 0xFF);
        }

        //return tag
        return Poly1305(r, s, poly_input);
    }

    vector<uint8_t> encrypt_decrypt(const vector<uint8_t>& key, const vector<uint8_t>& nonce, const vector<uint8_t>& text)
    {
        //generate keystream and xor with to encrypt/ decrypt
        uint32_t counter = 1;
        vector<uint8_t> text_inv(text.size());
        for(size_t i = 0; i < (text.size() + 63) / 64; i++) {
            vector<uint8_t> keystream = ChaCha20(key, counter, nonce);
            counter++;
            
            for(size_t j = 0; j < min(static_cast<size_t>(64), text.size() - i*64); j++) {
                int idx = i*64 + j;
                text_inv[idx] = text[idx] ^ keystream[j];
            }
        }

        return text_inv;
    }
}

vector<uint8_t> ChaCha20(const vector<uint8_t>& key, const uint32_t counter, const vector<uint8_t>& nonce) 
{
    //define constant
    vector<uint32_t> constant = {
        0x61707865, //expa
        0x3320646e, //nd 3
        0x79622d32, //2-by
        0x6b206574  //te k
    };

    //reconstruct key and nonce as 32'b vectors
    vector<uint32_t> key32 = bytes_to_words(key);
    vector<uint32_t> nonce32 = bytes_to_words(nonce);

    //create 4 word x 4 word matrix
    vector<uint32_t> mx(16);
    for(int i = 0; i < 16; i++) {
        if(i < 4)           mx[i] = constant[i];
        else if(i < 12)     mx[i] = key32[i - 4];
        else if(i == 12)    mx[i] = counter;
        else                mx[i] = nonce32[i - 13];
    }

    //duplicate the matrix before starting rounds
    vector<uint32_t> round_mx = mx;

    //perform 10 double rounds on the matrix, each round operates over four quarter-rounds
    //double rounds contain a column rounds followed by a diagonal round
    for(int i = 0; i < 10; i++) {
        //column round
        quarter_round(round_mx[0], round_mx[4], round_mx[8] , round_mx[12]);
        quarter_round(round_mx[1], round_mx[5], round_mx[9] , round_mx[13]);
        quarter_round(round_mx[2], round_mx[6], round_mx[10], round_mx[14]);
        quarter_round(round_mx[3], round_mx[7], round_mx[11], round_mx[15]);
        
        //diagonal round
        quarter_round(round_mx[0], round_mx[5], round_mx[10], round_mx[15]);
        quarter_round(round_mx[1], round_mx[6], round_mx[11], round_mx[12]);
        quarter_round(round_mx[2], round_mx[7], round_mx[8] , round_mx[13]);
        quarter_round(round_mx[3], round_mx[4], round_mx[9] , round_mx[14]);
    }

    //add original matrix to round matrix
    for(int i = 0; i < 16; i++) {
        mx[i] = mx[i] + round_mx[i];
    }

    //break up matrix into bytes and return output
    vector<uint8_t> final_mx(64);
    for(int i = 0; i < 16; i++) {
        for(int j = 0; j < 4; j++) {
            final_mx[i*4 + j] = static_cast<uint8_t>((mx[i] >> (8*j)) & 0xFF);
        }
    }

    return final_mx;
}

vector<uint8_t> Poly1305(vector<uint8_t>& r, vector<uint8_t>& s, vector<uint8_t>& msg)
{
    //restrict bits in r
    r[3]  &= 0x0F; r[7]  &= 0x0F; r[11] &= 0x0F; r[15] &= 0x0F;
    r[4]  &= 0xFC; r[8]  &= 0xFC; r[12] &= 0xFC;

    //represent 130'b integer as 5 limbs, each limb contains 26'b
    vector<uint32_t> r26 = bytes_to_limbs(r);
    vector<uint32_t> acc(5, 0);

    //process message in 16'B chunks
    size_t n = (msg.size() + 15) / 16;

    for(size_t i = 0; i < n; i++) {
        vector<uint8_t> chunk(17, 0);

        //fill in each chunk from msg
        size_t chunk_len = min(static_cast<size_t>(16), msg.size() - i*16);
        for(size_t j = 0; j < chunk_len; j++) {
            chunk[j] = msg[i * 16 + j];
        }
        chunk[chunk_len] = 1; //append 1 byte to end of each chunk

        //add each chunk to accumulator and multiply by r
        vector<uint32_t> chunk26 = bytes_to_limbs(chunk);
        acc = limbs_add(acc, chunk26);
        acc = limbs_mul(acc, r26);
    }

    //reduce accumulator modulo 2^130-5
    uint32_t c = 0;
    for(int i = 0; i < 5; i++) {
        uint32_t temp = acc[i] + c;
        acc[i] = temp & 0x03FFFFFF;
        c = temp >> 26;
    }
    acc[0] += c * 5;
    c = acc[0] >> 26;
    acc[0] &= 0x03FFFFFF;
    acc[1] += c;

    vector<uint32_t> g(5);
    c = 5;
    for(int i = 0; i < 5; i++) {
        uint32_t temp = acc[i] + c;
        g[i] = temp & 0x03FFFFFF;
        c = temp >> 26;
    }
    g[0] -= 5;
    
    uint32_t mask = (c != 0) ? 0xFFFFFFFF : 0;
    for(int i = 0; i < 5; i++) {
        acc[i] = (acc[i] & ~mask) | (g[i] & mask);
    }

    uint64_t t0 =
          (uint64_t)acc[0]
        | ((uint64_t)acc[1] << 26)
        | ((uint64_t)acc[2] << 52);

    uint64_t t1 =
          ((uint64_t)acc[2] >> 12)
        | ((uint64_t)acc[3] << 14)
        | ((uint64_t)acc[4] << 40);

    uint64_t s0 = 0, s1 = 0;
    for(int i = 0; i < 8; i++)  s0 |= (uint64_t)s[i]     << (8 * i);
    for(int i = 0; i < 8; i++)  s1 |= (uint64_t)s[8 + i] << (8 * i);

    t0 += s0;
    uint64_t carry = (t0 < s0);
    t1 += s1 + carry;

    vector<uint8_t> tag(16);
    for (int i = 0; i < 8; i++) tag[i]     = (t0 >> (8 * i)) & 0xFF;
    for (int i = 0; i < 8; i++) tag[8 + i] = (t1 >> (8 * i)) & 0xFF;

    return tag;
}

AEAD_encrypt ChaCha20_Poly1305_encrypt(const vector<uint8_t>& key, const vector<uint8_t>& nonce, const vector<uint8_t>& plaintext, const vector<uint8_t>& ad)
{
    //compute ciphertext and tag
    vector<uint8_t> ciphertext = encrypt_decrypt(key, nonce, plaintext);
    vector<uint8_t> tag = compute_tag(key, nonce, ciphertext, ad);

    return {ciphertext, tag};
}

AEAD_decrypt ChaCha20_Poly1305_decrypt(const vector<uint8_t>& key, const vector<uint8_t>& nonce, const vector<uint8_t>& ciphertext, const vector<uint8_t>& ad, const vector<uint8_t>& recieved_tag)
{
    //compute plaintext and tag
    vector<uint8_t> plaintext = encrypt_decrypt(key, nonce, ciphertext);
    vector<uint8_t> tag = compute_tag(key, nonce, ciphertext, ad);

    //verify tag, return plaintext if true or nothing if false
    if(tag == recieved_tag) {
        return {plaintext, true};  
    }
    else {
        return {vector<uint8_t>(), false};
    }
}