//
//  rppairing_srp.h
//  librppairing
//
//  Created by Magesh K on 23/08/26.
//  Copyright © 2026 Magesh K. All rights reserved.
//

#ifndef RPPAIRING_SRP_H
#define RPPAIRING_SRP_H

#include <vector>
#include <string>
#include <cstdint>
#include <cstddef>
#include <openssl/bn.h>

namespace rppairing {

class SrpClient3072 {
public:
    SrpClient3072();
    ~SrpClient3072();

    // Initializes client with username ("Pair-Setup") and PIN password ("000000" or user PIN)
    bool init(const std::string& username, const std::string& password);

    // Generates client ephemeral private 'a' and computes public 'A' (384 bytes)
    bool generate_client_public(std::vector<uint8_t>& out_A);

    // Processes server public 'B' and salt 's', computing proof M1 and session key
    bool process_server_public(
        const uint8_t* salt, size_t salt_len,
        const uint8_t* server_B, size_t server_B_len,
        std::vector<uint8_t>& out_M1
    );

    // Verifies server proof M2
    bool verify_server_proof(const uint8_t* server_M2, size_t m2_len);

    // Returns derived session key K (64 bytes)
    const std::vector<uint8_t>& session_key() const { return session_key_; }

private:
    std::string username_;
    std::string password_;
    BIGNUM* N_;
    BIGNUM* g_;
    BIGNUM* a_;
    BIGNUM* A_;
    BIGNUM* B_;
    BN_CTX* ctx_;
    std::vector<uint8_t> salt_;
    std::vector<uint8_t> M1_;
    std::vector<uint8_t> session_key_;
};

} // namespace rppairing

#endif // RPPAIRING_SRP_H
