//
//  rppairing_file.cpp
//  librppairing
//
//  Created by Magesh K on 23/08/26.
//  Copyright © 2026 Magesh K. All rights reserved.
//

#include "rppairing/rppairing_file.h"
#include "rppairing_crypto.h"
#include <cstring>
#include <string>
#include <vector>
#include <sstream>
#include <cstdlib>

using namespace rppairing;

static std::string extract_tag_content(const std::string& xml, const std::string& key) {
    size_t key_pos = xml.find("<key>" + key + "</key>");
    if (key_pos == std::string::npos) return "";

    size_t data_start = xml.find("<data>", key_pos);
    size_t string_start = xml.find("<string>", key_pos);

    if (data_start != std::string::npos && (string_start == std::string::npos || data_start < string_start)) {
        size_t start = data_start + 6;
        size_t end = xml.find("</data>", start);
        if (end == std::string::npos) return "";
        std::string raw = xml.substr(start, end - start);
        // Strip whitespace/newlines
        std::string clean;
        for (char c : raw) {
            if (!std::isspace(static_cast<unsigned char>(c))) clean += c;
        }
        return clean;
    } else if (string_start != std::string::npos) {
        size_t start = string_start + 8;
        size_t end = xml.find("</string>", start);
        if (end == std::string::npos) return "";
        return xml.substr(start, end - start);
    }
    return "";
}

extern "C" {

rppairing_error_t rppairing_identity_generate(const char *hostname, rppairing_identity_t *identity) {
    if (!identity) return RPPAIRING_E_INVALID_ARG;
    std::memset(identity, 0, sizeof(*identity));

    if (!Crypto::ed25519_keypair(identity->private_key, identity->public_key)) {
        return RPPAIRING_E_CRYPTO_ERROR;
    }

    std::string host = (hostname && hostname[0] != '\0') ? hostname : "RPPairing-Host";
    std::string uuid = Crypto::uuidv3_dns(host);
    std::strncpy(identity->identifier, uuid.c_str(), sizeof(identity->identifier) - 1);

    return RPPAIRING_E_SUCCESS;
}

rppairing_error_t rppairing_identity_from_plist(const char *plist_xml, size_t len, rppairing_identity_t *identity) {
    if (!plist_xml || len == 0 || !identity) return RPPAIRING_E_INVALID_ARG;
    std::memset(identity, 0, sizeof(*identity));

    std::string xml(plist_xml, len);

    std::string pub_b64 = extract_tag_content(xml, "public_key");
    std::string priv_b64 = extract_tag_content(xml, "private_key");
    std::string id_str = extract_tag_content(xml, "identifier");

    std::vector<uint8_t> pub_vec, priv_vec;
    if (!Crypto::base64_decode(pub_b64, pub_vec) || pub_vec.size() != 32) {
        return RPPAIRING_E_INVALID_ARG;
    }
    if (!Crypto::base64_decode(priv_b64, priv_vec) || priv_vec.size() != 32) {
        return RPPAIRING_E_INVALID_ARG;
    }

    std::memcpy(identity->public_key, pub_vec.data(), 32);
    std::memcpy(identity->private_key, priv_vec.data(), 32);
    std::strncpy(identity->identifier, id_str.c_str(), sizeof(identity->identifier) - 1);

    return RPPAIRING_E_SUCCESS;
}

rppairing_error_t rppairing_identity_to_plist(const rppairing_identity_t *identity, char **plist_xml, size_t *out_len) {
    if (!identity || !plist_xml) return RPPAIRING_E_INVALID_ARG;

    std::string pub_b64 = Crypto::base64_encode(identity->public_key, 32);
    std::string priv_b64 = Crypto::base64_encode(identity->private_key, 32);

    std::ostringstream oss;
    oss << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    oss << "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n";
    oss << "<plist version=\"1.0\">\n";
    oss << "<dict>\n";
    oss << "\t<key>public_key</key>\n";
    oss << "\t<data>" << pub_b64 << "</data>\n";
    oss << "\t<key>private_key</key>\n";
    oss << "\t<data>" << priv_b64 << "</data>\n";
    oss << "\t<key>identifier</key>\n";
    oss << "\t<string>" << identity->identifier << "</string>\n";
    oss << "</dict>\n";
    oss << "</plist>\n";

    std::string str = oss.str();
    char *buf = static_cast<char*>(std::malloc(str.size() + 1));
    if (!buf) return RPPAIRING_E_CRYPTO_ERROR;

    std::memcpy(buf, str.c_str(), str.size() + 1);
    *plist_xml = buf;
    if (out_len) {
        *out_len = str.size();
    }

    return RPPAIRING_E_SUCCESS;
}

void rppairing_plist_free(char *plist_xml) {
    if (plist_xml) {
        std::free(plist_xml);
    }
}

} // extern "C"
