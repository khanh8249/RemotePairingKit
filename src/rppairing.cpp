//
//  rppairing.cpp
//  librppairing
//
//  Created by Magesh K on 23/08/26.
//  Copyright © 2026 Magesh K. All rights reserved.
//

#include "rppairing/rppairing.h"
#include "rppairing_crypto.h"
#include "rppairing_tlv8.h"
#include "rppairing_opack.h"
#include "rppairing_transport.h"
#include "rppairing_srp.h"
#include "rppairing_cdtunnel.h"
#include <iostream>
#include <sstream>
#include <cstring>

using namespace rppairing;

static int g_debug_level = 0;

#define LOG_DEBUG(msg) do { if (g_debug_level > 0) std::cout << "[librppairing] " << msg << std::endl; } while(0)

struct rppairing_client_s {
    Transport transport;
    std::string device_host;
    uint16_t port;
    std::string hostname;
    uint64_t sequence_number;
    uint64_t encrypted_sequence_number;
    std::vector<uint8_t> encryption_key;
    std::vector<uint8_t> client_key;
    std::vector<uint8_t> server_key;
    bool is_paired;

    rppairing_client_s()
        : port(0), sequence_number(0), encrypted_sequence_number(0), is_paired(false) {}
};

struct rppairing_tunnel_s {
    CdTunnel tunnel;
};

static void derive_main_ciphers(rppairing_client_s* client) {
    client->client_key.resize(32);
    client->server_key.resize(32);

    Crypto::hkdf_sha512(
        NULL, 0,
        client->encryption_key.data(), client->encryption_key.size(),
        "ClientEncrypt-main", 18,
        client->client_key.data(), 32
    );

    Crypto::hkdf_sha512(
        NULL, 0,
        client->encryption_key.data(), client->encryption_key.size(),
        "ServerEncrypt-main", 18,
        client->server_key.data(), 32
    );
}

static std::string wrap_plain_message(rppairing_client_s* client, const std::string& inner_json) {
    uint64_t seq = client->sequence_number++;
    std::ostringstream oss;
    oss << "{\"message\":{\"plain\":{\"_0\":" << inner_json << "}},\"originatedBy\":\"host\",\"sequenceNumber\":" << seq << "}";
    return oss.str();
}

static bool unwrap_message(const std::string& full_json, std::string& out_inner) {
    size_t plain_pos = full_json.find("\"plain\"");
    if (plain_pos == std::string::npos) return false;
    size_t zero_pos = full_json.find("\"_0\":", plain_pos);
    if (zero_pos == std::string::npos) return false;
    size_t start = zero_pos + 5;
    while (start < full_json.size() && (full_json[start] == ' ' || full_json[start] == '\t')) start++;

    // Find the matching closing brace
    int brace_count = 0;
    size_t end = start;
    for (; end < full_json.size(); ++end) {
        if (full_json[end] == '{') brace_count++;
        else if (full_json[end] == '}') {
            brace_count--;
            if (brace_count == 0) {
                end++;
                break;
            }
        }
    }
    out_inner = full_json.substr(start, end - start);
    return true;
}

static std::string extract_field(const std::string& json, const std::string& field) {
    size_t pos = json.find("\"" + field + "\"");
    if (pos == std::string::npos) return "";
    pos = json.find(":", pos);
    if (pos == std::string::npos) return "";
    pos = json.find("\"", pos);
    if (pos == std::string::npos) return "";

    size_t end = pos + 1;
    while (end < json.size()) {
        if (json[end] == '\"' && json[end - 1] != '\\') break;
        end++;
    }
    if (end >= json.size()) return "";

    std::string val = json.substr(pos + 1, end - pos - 1);
    std::string clean;
    for (size_t i = 0; i < val.size(); ++i) {
        if (val[i] == '\\' && i + 1 < val.size()) {
            if (val[i + 1] == '/' || val[i + 1] == '\\' || val[i + 1] == '\"') {
                clean += val[++i];
                continue;
            }
        }
        clean += val[i];
    }
    return clean;
}

extern "C" {

void rppairing_set_debug_level(int level) {
    g_debug_level = level;
}

rppairing_error_t rppairing_client_new(const char *device_host, uint16_t port, const char *hostname, rppairing_client_t *client) {
    if (!device_host || !client) return RPPAIRING_E_INVALID_ARG;

    rppairing_client_s *c = new rppairing_client_s();
    c->device_host = device_host;
    c->port = port;
    c->hostname = (hostname && hostname[0] != '\0') ? hostname : "RPPairing-Host";

    if (!c->transport.connect(device_host, port)) {
        delete c;
        return RPPAIRING_E_CONN_FAILED;
    }

    *client = c;
    return RPPAIRING_E_SUCCESS;
}

void rppairing_client_free(rppairing_client_t client) {
    if (client) {
        client->transport.disconnect();
        delete client;
    }
}

rppairing_error_t rppairing_get_encryption_key(rppairing_client_t client, uint8_t *key_buf, size_t *key_len) {
    if (!client || !key_buf || !key_len) return RPPAIRING_E_INVALID_ARG;
    if (client->encryption_key.empty()) return RPPAIRING_E_NOT_FOUND;
    if (*key_len < client->encryption_key.size()) return RPPAIRING_E_INVALID_ARG;

    std::memcpy(key_buf, client->encryption_key.data(), client->encryption_key.size());
    *key_len = client->encryption_key.size();
    return RPPAIRING_E_SUCCESS;
}

rppairing_error_t rppairing_pair_verify(rppairing_client_t client, const rppairing_identity_t *identity) {
    if (!client || !identity) return RPPAIRING_E_INVALID_ARG;

    LOG_DEBUG("Starting pair-verify for identifier: " << identity->identifier);

    // Step 1: Send hostOptions request
    std::string opt_json = wrap_plain_message(client, "{\"request\":{\"_0\":{\"handshake\":{\"_0\":{\"hostOptions\":{\"attemptPairVerify\":true},\"wireProtocolVersion\":19}}}}}");
    LOG_DEBUG("[RPPairing] Step 1 sending hostOptions...");
    if (!client->transport.send_message(opt_json)) return RPPAIRING_E_CONN_FAILED;

    std::string resp_json;
    if (!client->transport.recv_message(resp_json)) return RPPAIRING_E_CONN_FAILED;
    LOG_DEBUG("[RPPairing] Step 1 response: " << resp_json);

    // Step 2: Generate ephemeral X25519 keypair
    uint8_t x_priv[32], x_pub[32];
    if (!Crypto::x25519_keypair(x_priv, x_pub)) return RPPAIRING_E_CRYPTO_ERROR;

    std::vector<TlvEntry> step2_tlvs = {
        {RPPAIRING_TLV_STATE, {0x01}},
        {RPPAIRING_TLV_PUBLIC_KEY, std::vector<uint8_t>(x_pub, x_pub + 32)}
    };
    std::vector<uint8_t> step2_bytes = Tlv8::serialize(step2_tlvs);
    std::string step2_b64 = Crypto::base64_encode(step2_bytes.data(), step2_bytes.size());

    std::ostringstream oss2;
    oss2 << "{\"event\":{\"_0\":{\"pairingData\":{\"_0\":{\"data\":\"" << step2_b64 << "\",\"kind\":\"verifyManualPairing\",\"startNewSession\":true}}}}}";
    LOG_DEBUG("[RPPairing] Step 2 sending verifyManualPairing (State 1)...");
    if (!client->transport.send_message(wrap_plain_message(client, oss2.str()))) return RPPAIRING_E_CONN_FAILED;

    // Step 3: Receive State 0x02 + device X25519 key + encrypted proof
    if (!client->transport.recv_message(resp_json)) return RPPAIRING_E_CONN_FAILED;
    LOG_DEBUG("[RPPairing] Step 3 response: " << resp_json);

    std::string b64_data = extract_field(resp_json, "data");
    if (b64_data.empty()) {
        LOG_DEBUG("[RPPairing] Step 3 no data in response");
        return RPPAIRING_E_VERIFY_FAILED;
    }

    std::vector<uint8_t> tlv_bytes;
    if (!Crypto::base64_decode(b64_data, tlv_bytes)) return RPPAIRING_E_MALFORMED_TLV;

    std::vector<TlvEntry> resp_tlvs;
    if (!Tlv8::deserialize(tlv_bytes.data(), tlv_bytes.size(), resp_tlvs)) return RPPAIRING_E_MALFORMED_TLV;

    if (Tlv8::contains(resp_tlvs, RPPAIRING_TLV_ERROR_RESPONSE)) {
        LOG_DEBUG("[RPPairing] Step 3 device returned ErrorResponse TLV");
        return RPPAIRING_E_VERIFY_FAILED;
    }

    std::vector<uint8_t> device_pub = Tlv8::collect(resp_tlvs, RPPAIRING_TLV_PUBLIC_KEY);
    if (device_pub.size() != 32) return RPPAIRING_E_VERIFY_FAILED;

    // Step 4: Compute X25519 shared secret
    uint8_t shared_secret[32];
    if (!Crypto::x25519_dh(x_priv, device_pub.data(), shared_secret)) return RPPAIRING_E_CRYPTO_ERROR;

    client->encryption_key.assign(shared_secret, shared_secret + 32);

    // Step 5: Derive pair-verify key
    uint8_t pair_verify_key[32];
    const char salt_str[] = "Pair-Verify-Encrypt-Salt";
    const char info_str[] = "Pair-Verify-Encrypt-Info";
    Crypto::hkdf_sha512(
        reinterpret_cast<const uint8_t*>(salt_str), sizeof(salt_str) - 1,
        shared_secret, 32,
        info_str, sizeof(info_str) - 1,
        pair_verify_key, 32
    );

    // Step 6: Build signature: x_pub (32) || identifier || device_x25519_pub (32)
    std::string id_str(identity->identifier);
    std::vector<uint8_t> sign_buf;
    sign_buf.insert(sign_buf.end(), x_pub, x_pub + 32);
    sign_buf.insert(sign_buf.end(), id_str.begin(), id_str.end());
    sign_buf.insert(sign_buf.end(), device_pub.begin(), device_pub.end());

    uint8_t signature[64];
    if (!Crypto::ed25519_sign(identity->private_key, sign_buf.data(), sign_buf.size(), signature)) {
        return RPPAIRING_E_CRYPTO_ERROR;
    }

    // Step 7: Encrypt inner TLV8
    std::vector<TlvEntry> inner_tlvs = {
        {RPPAIRING_TLV_IDENTIFIER, std::vector<uint8_t>(id_str.begin(), id_str.end())},
        {RPPAIRING_TLV_SIGNATURE, std::vector<uint8_t>(signature, signature + 64)}
    };
    std::vector<uint8_t> inner_bytes = Tlv8::serialize(inner_tlvs);

    uint8_t nonce[12] = {0, 0, 0, 0, 'P', 'V', '-', 'M', 's', 'g', '0', '3'};
    std::vector<uint8_t> encrypted_proof;
    if (!Crypto::chacha20_poly1305_encrypt(pair_verify_key, nonce, NULL, 0, inner_bytes.data(), inner_bytes.size(), encrypted_proof)) {
        return RPPAIRING_E_CRYPTO_ERROR;
    }

    std::vector<TlvEntry> step7_tlvs = {
        {RPPAIRING_TLV_STATE, {0x03}},
        {RPPAIRING_TLV_ENCRYPTED_DATA, encrypted_proof}
    };
    std::vector<uint8_t> step7_bytes = Tlv8::serialize(step7_tlvs);
    std::string step7_b64 = Crypto::base64_encode(step7_bytes.data(), step7_bytes.size());

    std::ostringstream oss7;
    oss7 << "{\"event\":{\"_0\":{\"pairingData\":{\"_0\":{\"data\":\"" << step7_b64 << "\",\"kind\":\"verifyManualPairing\",\"startNewSession\":false}}}}}";
    LOG_DEBUG("[RPPairing] Step 7 sending verifyManualPairing (State 3)...");
    if (!client->transport.send_message(wrap_plain_message(client, oss7.str()))) return RPPAIRING_E_CONN_FAILED;

    // Step 8: Receive State 0x04 verification
    if (!client->transport.recv_message(resp_json)) return RPPAIRING_E_CONN_FAILED;
    LOG_DEBUG("[RPPairing] Step 8 response: " << resp_json);

    std::string final_b64 = extract_field(resp_json, "data");
    if (!final_b64.empty()) {
        std::vector<uint8_t> final_tlv_bytes;
        Crypto::base64_decode(final_b64, final_tlv_bytes);
        std::vector<TlvEntry> final_tlvs;
        Tlv8::deserialize(final_tlv_bytes.data(), final_tlv_bytes.size(), final_tlvs);
        if (Tlv8::contains(final_tlvs, RPPAIRING_TLV_ERROR_RESPONSE)) {
            LOG_DEBUG("[RPPairing] Step 8 device returned ErrorResponse");
            return RPPAIRING_E_VERIFY_FAILED;
        }
    }

    derive_main_ciphers(client);
    client->is_paired = true;
    LOG_DEBUG("Pair-verify SUCCEEDED!");
    return RPPAIRING_E_SUCCESS;
}

rppairing_error_t rppairing_pair_setup(
    rppairing_client_t client,
    rppairing_identity_t *identity,
    rppairing_pin_callback_t pin_callback,
    void *user_data
) {
    if (!client || !identity) return RPPAIRING_E_INVALID_ARG;

    LOG_DEBUG("Starting pair-setup (SRP) for host: " << client->hostname);

    // Phase 1: Request Consent
    std::vector<TlvEntry> step1_tlvs = {
        {RPPAIRING_TLV_METHOD, {0x00}},
        {RPPAIRING_TLV_STATE, {0x01}}
    };
    std::vector<uint8_t> step1_bytes = Tlv8::serialize(step1_tlvs);
    std::string step1_b64 = Crypto::base64_encode(step1_bytes.data(), step1_bytes.size());

    std::ostringstream oss1;
    oss1 << "{\"event\":{\"_0\":{\"pairingData\":{\"_0\":{\"data\":\"" << step1_b64
         << "\",\"kind\":\"setupManualPairing\",\"sendingHost\":\"" << client->hostname
         << "\",\"startNewSession\":true}}}}}";

    if (!client->transport.send_message(wrap_plain_message(client, oss1.str()))) return RPPAIRING_E_CONN_FAILED;

    std::string resp_json;
    if (!client->transport.recv_message(resp_json, 15000)) return RPPAIRING_E_CONN_FAILED;

    if (resp_json.find("awaitingUserConsent") != std::string::npos) {
        LOG_DEBUG("Device is awaiting user trust confirmation on screen...");
        if (!client->transport.recv_message(resp_json, 60000)) return RPPAIRING_E_TIMEOUT;
    }

    if (resp_json.find("pairingRejected") != std::string::npos) {
        return RPPAIRING_E_USER_REJECTED;
    }

    std::string b64_data = extract_field(resp_json, "data");
    if (b64_data.empty()) return RPPAIRING_E_SETUP_FAILED;

    std::vector<uint8_t> tlv_bytes;
    Crypto::base64_decode(b64_data, tlv_bytes);
    std::vector<TlvEntry> srp_tlvs;
    Tlv8::deserialize(tlv_bytes.data(), tlv_bytes.size(), srp_tlvs);

    std::vector<uint8_t> salt = Tlv8::collect(srp_tlvs, RPPAIRING_TLV_SALT);
    std::vector<uint8_t> server_B = Tlv8::collect(srp_tlvs, RPPAIRING_TLV_PUBLIC_KEY);
    if (salt.empty() || server_B.empty()) return RPPAIRING_E_SETUP_FAILED;

    // Default PIN for iOS trust dialog is "000000"
    std::string pin = "000000";
    if (pin_callback) {
        const char* custom_pin = pin_callback(user_data);
        if (custom_pin && custom_pin[0] != '\0') {
            pin = custom_pin;
        }
    }

    SrpClient3072 srp;
    srp.init("Pair-Setup", pin);

    std::vector<uint8_t> client_A;
    srp.generate_client_public(client_A);

    std::vector<uint8_t> client_M1;
    if (!srp.process_server_public(salt.data(), salt.size(), server_B.data(), server_B.size(), client_M1)) {
        return RPPAIRING_E_SETUP_FAILED;
    }

    // Build TLV8: State=0x03, PublicKey=A (split into 254B + remainder), Proof=M1
    std::vector<TlvEntry> step3_tlvs;
    step3_tlvs.push_back({RPPAIRING_TLV_STATE, {0x03}});
    step3_tlvs.push_back({RPPAIRING_TLV_PUBLIC_KEY, std::vector<uint8_t>(client_A.begin(), client_A.begin() + 254)});
    step3_tlvs.push_back({RPPAIRING_TLV_PUBLIC_KEY, std::vector<uint8_t>(client_A.begin() + 254, client_A.end())});
    step3_tlvs.push_back({RPPAIRING_TLV_PROOF, client_M1});

    std::vector<uint8_t> step3_bytes = Tlv8::serialize(step3_tlvs);
    std::string step3_b64 = Crypto::base64_encode(step3_bytes.data(), step3_bytes.size());

    std::ostringstream oss3;
    oss3 << "{\"event\":{\"_0\":{\"pairingData\":{\"_0\":{\"data\":\"" << step3_b64
         << "\",\"kind\":\"setupManualPairing\",\"startNewSession\":false}}}}}";
    if (!client->transport.send_message(wrap_plain_message(client, oss3.str()))) return RPPAIRING_E_CONN_FAILED;

    // Receive Server Proof M2 (State 0x04)
    if (!client->transport.recv_message(resp_json, 15000)) return RPPAIRING_E_CONN_FAILED;

    std::string proof_b64 = extract_field(resp_json, "data");
    Crypto::base64_decode(proof_b64, tlv_bytes);
    Tlv8::deserialize(tlv_bytes.data(), tlv_bytes.size(), srp_tlvs);

    std::vector<uint8_t> server_M2 = Tlv8::collect(srp_tlvs, RPPAIRING_TLV_PROOF);
    if (!srp.verify_server_proof(server_M2.data(), server_M2.size())) {
        return RPPAIRING_E_SETUP_FAILED;
    }

    client->encryption_key = srp.session_key();

    // Regenerate fresh Ed25519 keys for this pairing file
    rppairing_identity_generate(client->hostname.c_str(), identity);

    // Derive setup keys
    uint8_t setup_enc_key[32], sign_mat[32];
    const char s_salt[] = "Pair-Setup-Encrypt-Salt";
    const char s_info[] = "Pair-Setup-Encrypt-Info";
    Crypto::hkdf_sha512(reinterpret_cast<const uint8_t*>(s_salt), sizeof(s_salt) - 1, client->encryption_key.data(), client->encryption_key.size(), s_info, sizeof(s_info) - 1, setup_enc_key, 32);

    const char sm_salt[] = "Pair-Setup-Controller-Sign-Salt";
    const char sm_info[] = "Pair-Setup-Controller-Sign-Info";
    Crypto::hkdf_sha512(reinterpret_cast<const uint8_t*>(sm_salt), sizeof(sm_salt) - 1, client->encryption_key.data(), client->encryption_key.size(), sm_info, sizeof(sm_info) - 1, sign_mat, 32);

    // Build sign buffer: sign_mat (32) || identifier || ed25519_pub (32)
    std::string id_str(identity->identifier);
    std::vector<uint8_t> sign_buf;
    sign_buf.insert(sign_buf.end(), sign_mat, sign_mat + 32);
    sign_buf.insert(sign_buf.end(), id_str.begin(), id_str.end());
    sign_buf.insert(sign_buf.end(), identity->public_key, identity->public_key + 32);

    uint8_t signature[64];
    Crypto::ed25519_sign(identity->private_key, sign_buf.data(), sign_buf.size(), signature);

    // Build OPACK device info
    uint8_t dummy_irk[16] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00};
    uint8_t dummy_mac[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};

    std::map<std::string, OpackValue> dev_info_dict = {
        {"altIRK", OpackValue::make_data(dummy_irk, 16)},
        {"btAddr", OpackValue::make_string("11:22:33:44:55:66")},
        {"mac", OpackValue::make_data(dummy_mac, 6)},
        {"remotepairing_serial_number", OpackValue::make_string("AAAAAAAAAAAA")},
        {"accountID", OpackValue::make_string(id_str)},
        {"model", OpackValue::make_string("RPPairing-Client")},
        {"name", OpackValue::make_string(client->hostname)}
    };
    std::vector<uint8_t> opack_bytes = Opack::encode(OpackValue::make_dict(dev_info_dict));

    // Inner TLV8: Identifier, PublicKey, Signature, Info
    std::vector<TlvEntry> inner_setup_tlvs = {
        {RPPAIRING_TLV_IDENTIFIER, std::vector<uint8_t>(id_str.begin(), id_str.end())},
        {RPPAIRING_TLV_PUBLIC_KEY, std::vector<uint8_t>(identity->public_key, identity->public_key + 32)},
        {RPPAIRING_TLV_SIGNATURE, std::vector<uint8_t>(signature, signature + 64)},
        {RPPAIRING_TLV_INFO, opack_bytes}
    };
    std::vector<uint8_t> inner_setup_bytes = Tlv8::serialize(inner_setup_tlvs);

    uint8_t nonce5[12] = {0, 0, 0, 0, 'P', 'S', '-', 'M', 's', 'g', '0', '5'};
    std::vector<uint8_t> enc_setup_data;
    Crypto::chacha20_poly1305_encrypt(setup_enc_key, nonce5, NULL, 0, inner_setup_bytes.data(), inner_setup_bytes.size(), enc_setup_data);

    std::vector<TlvEntry> step5_tlvs = {
        {RPPAIRING_TLV_STATE, {0x05}},
        {RPPAIRING_TLV_ENCRYPTED_DATA, enc_setup_data}
    };
    std::vector<uint8_t> step5_bytes = Tlv8::serialize(step5_tlvs);
    std::string step5_b64 = Crypto::base64_encode(step5_bytes.data(), step5_bytes.size());

    std::ostringstream oss5;
    oss5 << "{\"event\":{\"_0\":{\"pairingData\":{\"_0\":{\"data\":\"" << step5_b64
         << "\",\"kind\":\"setupManualPairing\",\"startNewSession\":false}}}}}";
    if (!client->transport.send_message(wrap_plain_message(client, oss5.str()))) return RPPAIRING_E_CONN_FAILED;

    // Receive final confirmation (State 0x06)
    if (!client->transport.recv_message(resp_json, 15000)) return RPPAIRING_E_CONN_FAILED;

    derive_main_ciphers(client);
    client->is_paired = true;
    LOG_DEBUG("Pair-setup SUCCEEDED!");
    return RPPAIRING_E_SUCCESS;
}

rppairing_error_t rppairing_connect(
    rppairing_client_t client,
    rppairing_identity_t *identity,
    rppairing_pin_callback_t pin_callback,
    void *user_data
) {
    if (!client || !identity) return RPPAIRING_E_INVALID_ARG;

    rppairing_error_t err = rppairing_pair_verify(client, identity);
    if (err == RPPAIRING_E_SUCCESS) {
        return RPPAIRING_E_SUCCESS;
    }

    LOG_DEBUG("Pair-verify failed or uninitialized, falling back to pair-setup...");
    return rppairing_pair_setup(client, identity, pin_callback, user_data);
}

rppairing_error_t rppairing_create_tunnel_listener(rppairing_client_t client, uint16_t *tunnel_port) {
    if (!client || !tunnel_port) return RPPAIRING_E_INVALID_ARG;
    if (!client->is_paired || client->encryption_key.empty()) return RPPAIRING_E_VERIFY_FAILED;

    std::string key_b64 = Crypto::base64_encode(client->encryption_key.data(), client->encryption_key.size());
    std::ostringstream oss;
    oss << "{\"request\":{\"_0\":{\"createListener\":{\"key\":\"" << key_b64 << "\",\"transportProtocolType\":\"tcp\"}}}}";
    std::string req_json = oss.str();

    // Encrypt with client_key using 0-based encrypted sequence number
    uint8_t nonce[12] = {0};
    for (int i = 0; i < 8; ++i) {
        nonce[i] = static_cast<uint8_t>((client->encrypted_sequence_number >> (i * 8)) & 0xFF);
    }

    std::vector<uint8_t> ct;
    if (!Crypto::chacha20_poly1305_encrypt(client->client_key.data(), nonce, NULL, 0, reinterpret_cast<const uint8_t*>(req_json.data()), req_json.size(), ct)) {
        LOG_DEBUG("[RPPairing] create_tunnel_listener: encryption failed");
        return RPPAIRING_E_CRYPTO_ERROR;
    }

    std::string ct_b64 = Crypto::base64_encode(ct.data(), ct.size());
    uint64_t seq = client->sequence_number++;
    std::ostringstream env_oss;
    env_oss << "{\"message\":{\"streamEncrypted\":{\"_0\":\"" << ct_b64 << "\"}},\"originatedBy\":\"host\",\"sequenceNumber\":" << seq << "}";

    LOG_DEBUG("[RPPairing] create_tunnel_listener: sending encrypted createListener frame (seq " << seq << ")...");
    if (!client->transport.send_message(env_oss.str())) {
        LOG_DEBUG("[RPPairing] create_tunnel_listener: send_message failed");
        return RPPAIRING_E_CONN_FAILED;
    }

    std::string resp_json;
    if (!client->transport.recv_message(resp_json, 15000)) {
        LOG_DEBUG("[RPPairing] create_tunnel_listener: recv_message failed or timed out");
        return RPPAIRING_E_CONN_FAILED;
    }
    LOG_DEBUG("[RPPairing] create_tunnel_listener response: " << resp_json);

    std::string enc_resp_b64 = extract_field(resp_json, "_0");
    if (enc_resp_b64.empty()) {
        LOG_DEBUG("[RPPairing] create_tunnel_listener: missing _0 field in response");
        return RPPAIRING_E_TUNNEL_FAILED;
    }

    std::vector<uint8_t> enc_resp_ct;
    Crypto::base64_decode(enc_resp_b64, enc_resp_ct);

    std::vector<uint8_t> pt_resp;
    if (!Crypto::chacha20_poly1305_decrypt(client->server_key.data(), nonce, NULL, 0, enc_resp_ct.data(), enc_resp_ct.size(), pt_resp)) {
        LOG_DEBUG("[RPPairing] create_tunnel_listener: decryption failed");
        return RPPAIRING_E_CRYPTO_ERROR;
    }

    client->encrypted_sequence_number++;

    std::string dec_json(reinterpret_cast<const char*>(pt_resp.data()), pt_resp.size());
    LOG_DEBUG("[RPPairing] create_tunnel_listener decrypted response: " << dec_json);

    size_t p_pos = dec_json.find("\"port\":");
    if (p_pos == std::string::npos) p_pos = dec_json.find("\"port\" :");
    if (p_pos == std::string::npos) return RPPAIRING_E_TUNNEL_FAILED;
    p_pos = dec_json.find(":", p_pos);
    while (p_pos < dec_json.size() && (dec_json[p_pos] == ':' || dec_json[p_pos] == ' ' || dec_json[p_pos] == '\t')) p_pos++;
    size_t p_end = p_pos;
    while (p_end < dec_json.size() && (dec_json[p_end] >= '0' && dec_json[p_end] <= '9')) p_end++;

    uint16_t port_num = static_cast<uint16_t>(std::stoul(dec_json.substr(p_pos, p_end - p_pos)));
    *tunnel_port = port_num;
    LOG_DEBUG("Tunnel listener created on device port: " << port_num);
    return RPPAIRING_E_SUCCESS;
}

rppairing_error_t rppairing_tunnel_connect(
    const char *device_host,
    uint16_t tunnel_port,
    const uint8_t *encryption_key,
    size_t key_len,
    rppairing_tunnel_info_t *tunnel_info,
    rppairing_tunnel_t *tunnel
) {
    if (!device_host || !encryption_key || key_len == 0 || !tunnel) return RPPAIRING_E_INVALID_ARG;

    rppairing_tunnel_s *t = new rppairing_tunnel_s();
    rppairing_error_t err = t->tunnel.connect(device_host, tunnel_port, encryption_key, key_len, tunnel_info);
    if (err != RPPAIRING_E_SUCCESS) {
        delete t;
        return err;
    }

    *tunnel = t;
    return RPPAIRING_E_SUCCESS;
}

rppairing_error_t rppairing_tunnel_send_packet(rppairing_tunnel_t tunnel, const uint8_t *packet, size_t len) {
    if (!tunnel) return RPPAIRING_E_INVALID_ARG;
    return tunnel->tunnel.send_packet(packet, len);
}

rppairing_error_t rppairing_tunnel_recv_packet(rppairing_tunnel_t tunnel, uint8_t *buf, size_t buf_len, size_t *received_len, int timeout_ms) {
    if (!tunnel) return RPPAIRING_E_INVALID_ARG;
    return tunnel->tunnel.recv_packet(buf, buf_len, received_len, timeout_ms);
}

void rppairing_tunnel_close(rppairing_tunnel_t tunnel) {
    if (tunnel) {
        tunnel->tunnel.close();
        delete tunnel;
    }
}

} // extern "C"
