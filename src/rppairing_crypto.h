//
//  rppairing_crypto.h
//  librppairing
//
//  Created by Magesh K on 23/08/26.
//  Copyright © 2026 Magesh K. All rights reserved.
//

#ifndef RPPAIRING_CRYPTO_H
#define RPPAIRING_CRYPTO_H

#include <vector>
#include <string>
#include <cstdint>
#include <cstddef>

namespace rppairing {

class Crypto {
public:
    static bool random_bytes(uint8_t* buf, size_t len);

    static bool hkdf_sha512(
        const uint8_t* salt, size_t salt_len,
        const uint8_t* ikm, size_t ikm_len,
        const char* info, size_t info_len,
        uint8_t* okm, size_t okm_len
    );

    static bool x25519_keypair(uint8_t* priv_32, uint8_t* pub_32);
    static bool x25519_dh(const uint8_t* priv_32, const uint8_t* peer_pub_32, uint8_t* out_shared_32);

    static bool ed25519_keypair(uint8_t* priv_32, uint8_t* pub_32);
    static bool ed25519_sign(const uint8_t* priv_32, const uint8_t* msg, size_t msg_len, uint8_t* out_sig_64);
    static bool ed25519_verify(const uint8_t* pub_32, const uint8_t* msg, size_t msg_len, const uint8_t* sig_64);

    static bool chacha20_poly1305_encrypt(
        const uint8_t* key_32,
        const uint8_t* nonce_12,
        const uint8_t* aad, size_t aad_len,
        const uint8_t* pt, size_t pt_len,
        std::vector<uint8_t>& out_ct_tag
    );

    static bool chacha20_poly1305_decrypt(
        const uint8_t* key_32,
        const uint8_t* nonce_12,
        const uint8_t* aad, size_t aad_len,
        const uint8_t* ct_tag, size_t ct_tag_len,
        std::vector<uint8_t>& out_pt
    );

    static void sha512(const uint8_t* in, size_t in_len, uint8_t* out_64);
    static std::string uuidv3_dns(const std::string& name);
    static std::string base64_encode(const uint8_t* data, size_t len);
    static bool base64_decode(const std::string& in, std::vector<uint8_t>& out);
};

} // namespace rppairing

#endif // RPPAIRING_CRYPTO_H
