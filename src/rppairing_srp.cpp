//
//  rppairing_srp.cpp
//  librppairing
//
//  Created by Magesh K on 23/08/26.
//  Copyright © 2026 Magesh K. All rights reserved.
//

#include "rppairing_srp.h"
#include "rppairing_crypto.h"
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <cstring>

namespace rppairing {

static const char* RFC5054_3072_PRIME_HEX =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF";

static void bn_to_padded_vec(const BIGNUM* bn, size_t target_len, std::vector<uint8_t>& out) {
    out.assign(target_len, 0);
    int num_bytes = BN_num_bytes(bn);
    if (num_bytes <= static_cast<int>(target_len)) {
        size_t offset = target_len - num_bytes;
        BN_bn2bin(bn, out.data() + offset);
    }
}

SrpClient3072::SrpClient3072()
    : N_(NULL), g_(NULL), a_(NULL), A_(NULL), B_(NULL), ctx_(NULL) {
    ctx_ = BN_CTX_new();
    N_ = BN_new();
    g_ = BN_new();
    a_ = BN_new();
    A_ = BN_new();
    B_ = BN_new();
    BN_hex2bn(&N_, RFC5054_3072_PRIME_HEX);
    BN_set_word(g_, 5);
}

SrpClient3072::~SrpClient3072() {
    if (N_) BN_free(N_);
    if (g_) BN_free(g_);
    if (a_) BN_free(a_);
    if (A_) BN_free(A_);
    if (B_) BN_free(B_);
    if (ctx_) BN_CTX_free(ctx_);
}

bool SrpClient3072::init(const std::string& username, const std::string& password) {
    username_ = username;
    password_ = password;
    return true;
}

bool SrpClient3072::generate_client_public(std::vector<uint8_t>& out_A) {
    BN_rand(a_, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
    BN_mod_exp(A_, g_, a_, N_, ctx_);
    bn_to_padded_vec(A_, 384, out_A);
    return true;
}

bool SrpClient3072::process_server_public(
    const uint8_t* salt, size_t salt_len,
    const uint8_t* server_B, size_t server_B_len,
    std::vector<uint8_t>& out_M1
) {
    salt_.assign(salt, salt + salt_len);
    BN_bin2bn(server_B, static_cast<int>(server_B_len), B_);

    BIGNUM* b_mod = BN_new();
    BN_nnmod(b_mod, B_, N_, ctx_);
    if (BN_is_zero(b_mod)) {
        BN_free(b_mod);
        return false;
    }
    BN_free(b_mod);

    // Compute k = H(N || PAD(g))
    std::vector<uint8_t> n_vec, g_vec;
    bn_to_padded_vec(N_, 384, n_vec);
    bn_to_padded_vec(g_, 384, g_vec);

    SHA512_CTX sha_ctx;
    uint8_t k_hash[64];
    SHA512_Init(&sha_ctx);
    SHA512_Update(&sha_ctx, n_vec.data(), n_vec.size());
    SHA512_Update(&sha_ctx, g_vec.data(), g_vec.size());
    SHA512_Final(k_hash, &sha_ctx);
    BIGNUM* k = BN_new();
    BN_bin2bn(k_hash, 64, k);

    // Compute u = H(PAD(A) || PAD(B))
    std::vector<uint8_t> a_vec, b_vec;
    bn_to_padded_vec(A_, 384, a_vec);
    bn_to_padded_vec(B_, 384, b_vec);

    uint8_t u_hash[64];
    SHA512_Init(&sha_ctx);
    SHA512_Update(&sha_ctx, a_vec.data(), a_vec.size());
    SHA512_Update(&sha_ctx, b_vec.data(), b_vec.size());
    SHA512_Final(u_hash, &sha_ctx);
    BIGNUM* u = BN_new();
    BN_bin2bn(u_hash, 64, u);

    // Compute x = H(s || H(I || ":" || P))
    uint8_t inner_user_pass_hash[64];
    SHA512_Init(&sha_ctx);
    SHA512_Update(&sha_ctx, username_.data(), username_.size());
    SHA512_Update(&sha_ctx, ":", 1);
    SHA512_Update(&sha_ctx, password_.data(), password_.size());
    SHA512_Final(inner_user_pass_hash, &sha_ctx);

    uint8_t x_hash[64];
    SHA512_Init(&sha_ctx);
    SHA512_Update(&sha_ctx, salt_.data(), salt_.size());
    SHA512_Update(&sha_ctx, inner_user_pass_hash, 64);
    SHA512_Final(x_hash, &sha_ctx);
    BIGNUM* x = BN_new();
    BN_bin2bn(x_hash, 64, x);

    // Compute S = (B - k*(g^x mod N)) ^ (a + u*x) mod N
    BIGNUM* gx = BN_new();
    BN_mod_exp(gx, g_, x, N_, ctx_);

    BIGNUM* kgx = BN_new();
    BN_mod_mul(kgx, k, gx, N_, ctx_);

    BIGNUM* base = BN_new();
    BN_mod_sub(base, B_, kgx, N_, ctx_);

    BIGNUM* ux = BN_new();
    BN_mul(ux, u, x, ctx_);

    BIGNUM* exp = BN_new();
    BN_add(exp, a_, ux);

    BIGNUM* S = BN_new();
    BN_mod_exp(S, base, exp, N_, ctx_);

    std::vector<uint8_t> s_vec;
    bn_to_padded_vec(S, 384, s_vec);

    session_key_.resize(64);
    Crypto::sha512(s_vec.data(), s_vec.size(), session_key_.data());

    // Compute M1 = H(H(N) XOR H(g) || H(I) || s || A || B || K)
    uint8_t hn[64], hg[64], hxor[64], hi[64];
    Crypto::sha512(n_vec.data(), n_vec.size(), hn);
    Crypto::sha512(g_vec.data(), g_vec.size(), hg);
    for (int i = 0; i < 64; ++i) hxor[i] = hn[i] ^ hg[i];
    Crypto::sha512(reinterpret_cast<const uint8_t*>(username_.data()), username_.size(), hi);

    M1_.resize(64);
    SHA512_Init(&sha_ctx);
    SHA512_Update(&sha_ctx, hxor, 64);
    SHA512_Update(&sha_ctx, hi, 64);
    SHA512_Update(&sha_ctx, salt_.data(), salt_.size());
    SHA512_Update(&sha_ctx, a_vec.data(), a_vec.size());
    SHA512_Update(&sha_ctx, b_vec.data(), b_vec.size());
    SHA512_Update(&sha_ctx, session_key_.data(), session_key_.size());
    SHA512_Final(M1_.data(), &sha_ctx);

    out_M1 = M1_;

    BN_free(k);
    BN_free(u);
    BN_free(x);
    BN_free(gx);
    BN_free(kgx);
    BN_free(base);
    BN_free(ux);
    BN_free(exp);
    BN_free(S);
    return true;
}

bool SrpClient3072::verify_server_proof(const uint8_t* server_M2, size_t m2_len) {
    if (m2_len != 64) return false;

    std::vector<uint8_t> a_vec;
    bn_to_padded_vec(A_, 384, a_vec);

    uint8_t expected_M2[64];
    SHA512_CTX sha_ctx;
    SHA512_Init(&sha_ctx);
    SHA512_Update(&sha_ctx, a_vec.data(), a_vec.size());
    SHA512_Update(&sha_ctx, M1_.data(), M1_.size());
    SHA512_Update(&sha_ctx, session_key_.data(), session_key_.size());
    SHA512_Final(expected_M2, &sha_ctx);

    return (std::memcmp(server_M2, expected_M2, 64) == 0);
}

} // namespace rppairing
