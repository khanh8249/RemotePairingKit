//
//  rppairing_crypto.cpp
//  librppairing
//
//  Created by Magesh K on 23/08/26.
//  Copyright © 2026 Magesh K. All rights reserved.
//

#include "rppairing_crypto.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace rppairing {

bool Crypto::random_bytes(uint8_t* buf, size_t len) {
    return (RAND_bytes(buf, static_cast<int>(len)) == 1);
}

bool Crypto::hkdf_sha512(
    const uint8_t* salt, size_t salt_len,
    const uint8_t* ikm, size_t ikm_len,
    const char* info, size_t info_len,
    uint8_t* okm, size_t okm_len
) {
    EVP_KDF* kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) return false;

    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx) return false;

    char digest_name[] = "SHA512";
    OSSL_PARAM params[5];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest_name, 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void*)ikm, ikm_len);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void*)info, info_len);
    if (salt && salt_len > 0) {
        params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void*)salt, salt_len);
        params[4] = OSSL_PARAM_construct_end();
    } else {
        params[3] = OSSL_PARAM_construct_end();
    }

    int ret = EVP_KDF_derive(kctx, okm, okm_len, params);
    EVP_KDF_CTX_free(kctx);
    return (ret > 0);
}

bool Crypto::x25519_keypair(uint8_t* priv_32, uint8_t* pub_32) {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx) return false;

    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_keygen_init(pctx) <= 0 || EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }
    EVP_PKEY_CTX_free(pctx);

    size_t priv_len = 32;
    size_t pub_len = 32;
    EVP_PKEY_get_raw_private_key(pkey, priv_32, &priv_len);
    EVP_PKEY_get_raw_public_key(pkey, pub_32, &pub_len);
    EVP_PKEY_free(pkey);
    return true;
}

bool Crypto::x25519_dh(const uint8_t* priv_32, const uint8_t* peer_pub_32, uint8_t* out_shared_32) {
    EVP_PKEY* priv_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv_32, 32);
    EVP_PKEY* peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub_32, 32);
    if (!priv_key || !peer_key) {
        if (priv_key) EVP_PKEY_free(priv_key);
        if (peer_key) EVP_PKEY_free(peer_key);
        return false;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv_key, NULL);
    if (!ctx || EVP_PKEY_derive_init(ctx) <= 0 || EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0) {
        if (ctx) EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(priv_key);
        EVP_PKEY_free(peer_key);
        return false;
    }

    size_t out_len = 32;
    int ret = EVP_PKEY_derive(ctx, out_shared_32, &out_len);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(priv_key);
    EVP_PKEY_free(peer_key);
    return (ret > 0 && out_len == 32);
}

bool Crypto::ed25519_keypair(uint8_t* priv_32, uint8_t* pub_32) {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!pctx) return false;

    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_keygen_init(pctx) <= 0 || EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }
    EVP_PKEY_CTX_free(pctx);

    size_t priv_len = 32;
    size_t pub_len = 32;
    EVP_PKEY_get_raw_private_key(pkey, priv_32, &priv_len);
    EVP_PKEY_get_raw_public_key(pkey, pub_32, &pub_len);
    EVP_PKEY_free(pkey);
    return true;
}

bool Crypto::ed25519_sign(const uint8_t* priv_32, const uint8_t* msg, size_t msg_len, uint8_t* out_sig_64) {
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, priv_32, 32);
    if (!pkey) return false;

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pkey);
        return false;
    }

    if (EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, pkey) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return false;
    }

    size_t sig_len = 64;
    int ret = EVP_DigestSign(md_ctx, out_sig_64, &sig_len, msg, msg_len);
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    return (ret > 0 && sig_len == 64);
}

bool Crypto::ed25519_verify(const uint8_t* pub_32, const uint8_t* msg, size_t msg_len, const uint8_t* sig_64) {
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pub_32, 32);
    if (!pkey) return false;

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pkey);
        return false;
    }

    if (EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, pkey) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return false;
    }

    int ret = EVP_DigestVerify(md_ctx, sig_64, 64, msg, msg_len);
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    return (ret == 1);
}

bool Crypto::chacha20_poly1305_encrypt(
    const uint8_t* key_32,
    const uint8_t* nonce_12,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* pt, size_t pt_len,
    std::vector<uint8_t>& out_ct_tag
) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key_32, nonce_12) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int len = 0;
    if (aad && aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, static_cast<int>(aad_len)) <= 0) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    }

    out_ct_tag.resize(pt_len + 16);
    if (pt_len > 0) {
        if (EVP_EncryptUpdate(ctx, out_ct_tag.data(), &len, pt, static_cast<int>(pt_len)) <= 0) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    }

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, out_ct_tag.data() + len, &final_len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    uint8_t tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    std::memcpy(out_ct_tag.data() + pt_len, tag, 16);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool Crypto::chacha20_poly1305_decrypt(
    const uint8_t* key_32,
    const uint8_t* nonce_12,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ct_tag, size_t ct_tag_len,
    std::vector<uint8_t>& out_pt
) {
    if (ct_tag_len < 16) return false;
    size_t pt_len = ct_tag_len - 16;
    const uint8_t* tag = ct_tag + pt_len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key_32, nonce_12) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int len = 0;
    if (aad && aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, static_cast<int>(aad_len)) <= 0) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    }

    out_pt.resize(pt_len);
    if (pt_len > 0) {
        if (EVP_DecryptUpdate(ctx, out_pt.data(), &len, ct_tag, static_cast<int>(pt_len)) <= 0) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void*)tag) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int final_len = 0;
    int ret = EVP_DecryptFinal_ex(ctx, out_pt.data() + len, &final_len);
    EVP_CIPHER_CTX_free(ctx);
    return (ret > 0);
}

void Crypto::sha512(const uint8_t* in, size_t in_len, uint8_t* out_64) {
    SHA512(in, in_len, out_64);
}

std::string Crypto::uuidv3_dns(const std::string& name) {
    // DNS Namespace UUID: 6ba7b810-9dad-11d1-80b4-00c04fd430c8
    static const uint8_t dns_ns[16] = {
        0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1,
        0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8
    };

    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, dns_ns, 16);
    MD5_Update(&ctx, name.data(), name.size());
    uint8_t hash[16];
    MD5_Final(hash, &ctx);

    hash[6] = (hash[6] & 0x0F) | 0x30; // Version 3
    hash[8] = (hash[8] & 0x3F) | 0x80; // Variant 1

    std::ostringstream oss;
    for (int i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) oss << '-';
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return oss.str();
}

std::string Crypto::base64_encode(const uint8_t* data, size_t len) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);

    BIO_write(b64, data, static_cast<int>(len));
    BIO_flush(b64);

    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);
    std::string res(bptr->data, bptr->length);
    BIO_free_all(b64);
    return res;
}

bool Crypto::base64_decode(const std::string& in, std::vector<uint8_t>& out) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new_mem_buf(in.data(), static_cast<int>(in.size()));
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);

    out.resize(in.size());
    int read_len = BIO_read(b64, out.data(), static_cast<int>(out.size()));
    BIO_free_all(b64);

    if (read_len < 0) return false;
    out.resize(read_len);
    return true;
}

} // namespace rppairing
