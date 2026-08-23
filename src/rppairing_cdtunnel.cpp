//
//  rppairing_cdtunnel.cpp
//  librppairing
//
//  Created by Magesh K on 23/08/26.
//  Copyright © 2026 Magesh K. All rights reserved.
//

#include "rppairing_cdtunnel.h"
#include <cstring>
#include <string>
#include <sstream>

namespace rppairing {

static const char CDTUNNEL_MAGIC[8] = {'C', 'D', 'T', 'u', 'n', 'n', 'e', 'l'};

static std::string extract_json_string(const std::string& json, const std::string& key) {
    size_t pos = json.find("\"" + key + "\"");
    if (pos == std::string::npos) return "";
    pos = json.find(":", pos);
    if (pos == std::string::npos) return "";
    pos = json.find("\"", pos);
    if (pos == std::string::npos) return "";
    size_t end = json.find("\"", pos + 1);
    if (end == std::string::npos) return "";
    return json.substr(pos + 1, end - pos - 1);
}

static uint32_t extract_json_uint(const std::string& json, const std::string& key) {
    size_t pos = json.find("\"" + key + "\"");
    if (pos == std::string::npos) return 0;
    pos = json.find(":", pos);
    if (pos == std::string::npos) return 0;
    while (pos < json.size() && (json[pos] == ':' || json[pos] == ' ' || json[pos] == '\t')) pos++;
    size_t end = pos;
    while (end < json.size() && (json[end] >= '0' && json[end] <= '9')) end++;
    if (end == pos) return 0;
    return static_cast<uint32_t>(std::stoul(json.substr(pos, end - pos)));
}

CdTunnel::CdTunnel() {
    std::memset(&info_, 0, sizeof(info_));
}

CdTunnel::~CdTunnel() {
    close();
}

void CdTunnel::close() {
    tls_client_.disconnect();
    std::memset(&info_, 0, sizeof(info_));
}

rppairing_error_t CdTunnel::connect(
    const char* host,
    uint16_t port,
    const uint8_t* psk,
    size_t psk_len,
    rppairing_tunnel_info_t* out_info,
    int timeout_ms
) {
    close();

    if (!tls_client_.connect(host, port, psk, psk_len, timeout_ms)) {
        return RPPAIRING_E_SSL_ERROR;
    }

    // Send CDTunnel handshake request: "CDTunnel" (8B) + 2B BE length + JSON
    std::string req_json = "{\"type\":\"clientHandshakeRequest\",\"mtu\":16000}";
    uint16_t len = static_cast<uint16_t>(req_json.size());

    std::vector<uint8_t> frame;
    frame.insert(frame.end(), CDTUNNEL_MAGIC, CDTUNNEL_MAGIC + 8);
    frame.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
    frame.push_back(static_cast<uint8_t>(len & 0xFF));
    frame.insert(frame.end(), req_json.begin(), req_json.end());

    if (tls_client_.send(frame.data(), frame.size()) != static_cast<int>(frame.size())) {
        close();
        return RPPAIRING_E_TUNNEL_FAILED;
    }

    // Read CDTunnel handshake response
    uint8_t header[10];
    int r = tls_client_.recv(header, 10, timeout_ms);
    if (r != 10 || std::memcmp(header, CDTUNNEL_MAGIC, 8) != 0) {
        close();
        return RPPAIRING_E_TUNNEL_FAILED;
    }

    uint16_t resp_len = (static_cast<uint16_t>(header[8]) << 8) | static_cast<uint16_t>(header[9]);
    std::vector<uint8_t> body(resp_len);
    r = tls_client_.recv(body.data(), resp_len, timeout_ms);
    if (r != static_cast<int>(resp_len)) {
        close();
        return RPPAIRING_E_TUNNEL_FAILED;
    }

    std::string resp_json(reinterpret_cast<const char*>(body.data()), resp_len);

    std::string client_addr = extract_json_string(resp_json, "address");
    std::string client_mask = extract_json_string(resp_json, "netmask");
    std::string server_addr = extract_json_string(resp_json, "serverAddress");
    uint32_t rsd_port = extract_json_uint(resp_json, "serverRSDPort");
    uint32_t mtu = extract_json_uint(resp_json, "mtu");
    if (mtu == 0) mtu = kDefaultCdTunnelMtu;

    std::strncpy(info_.client_address, client_addr.c_str(), sizeof(info_.client_address) - 1);
    std::strncpy(info_.client_netmask, client_mask.c_str(), sizeof(info_.client_netmask) - 1);
    std::strncpy(info_.server_address, server_addr.c_str(), sizeof(info_.server_address) - 1);
    info_.server_rsd_port = static_cast<uint16_t>(rsd_port);
    info_.mtu = mtu;

    if (out_info) {
        *out_info = info_;
    }

    return RPPAIRING_E_SUCCESS;
}

rppairing_error_t CdTunnel::send_packet(const uint8_t* packet, size_t len) {
    if (!is_open()) return RPPAIRING_E_CONN_FAILED;
    if (tls_client_.send(packet, len) != static_cast<int>(len)) {
        return RPPAIRING_E_TUNNEL_FAILED;
    }
    return RPPAIRING_E_SUCCESS;
}

rppairing_error_t CdTunnel::recv_packet(uint8_t* buf, size_t buf_len, size_t* out_received, int timeout_ms) {
    if (!is_open()) return RPPAIRING_E_CONN_FAILED;

    // IPv6 header is 40 bytes fixed
    if (buf_len < kIpv6HeaderLength) return RPPAIRING_E_INVALID_ARG;

    if (!tls_client_.recv_exact(buf, kIpv6HeaderLength, timeout_ms)) {
        return RPPAIRING_E_TIMEOUT;
    }

    // Bytes [4:6] are Payload Length (big-endian)
    uint16_t payload_len = (static_cast<uint16_t>(buf[4]) << 8) | static_cast<uint16_t>(buf[5]);
    size_t total_packet_len = kIpv6HeaderLength + payload_len;

    if (total_packet_len > buf_len) {
        return RPPAIRING_E_INVALID_ARG;
    }

    if (payload_len > 0) {
        if (!tls_client_.recv_exact(buf + kIpv6HeaderLength, payload_len, timeout_ms)) {
            return RPPAIRING_E_TUNNEL_FAILED;
        }
    }

    if (out_received) {
        *out_received = total_packet_len;
    }

    return RPPAIRING_E_SUCCESS;
}

} // namespace rppairing
