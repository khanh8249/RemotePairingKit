//
//  rppairing_cdtunnel.cpp
//  librppairing
//
//  Created by Magesh K on 23/08/26.
//  Copyright © 2026 Magesh K. All rights reserved.
//

#include "rppairing_cdtunnel.h"
#include "rppairing_tcp.h"
#include <cstring>
#include <string>
#include <sstream>
#include <iostream>

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
    std::lock_guard<std::mutex> close_lock(close_mutex_);
    reader_running_ = false;
    tls_client_.disconnect();
    if (reader_thread_.joinable()) {
        reader_thread_.join();
    }

    std::lock_guard<std::mutex> send_lock(send_mutex_);
    {
        std::lock_guard<std::mutex> s_lock(streams_mutex_);
        streams_.clear();
    }
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
    std::cout << "[librppairing] [CdTunnel] connect() starting to " << host << ":" << port << std::endl;
    close();

    std::lock_guard<std::mutex> close_lock(close_mutex_);
    std::lock_guard<std::mutex> send_lock(send_mutex_);

    if (!tls_client_.connect(host, port, psk, psk_len, timeout_ms)) {
        std::cout << "[librppairing] [CdTunnel] tls_client_.connect failed!" << std::endl;
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
        std::cout << "[librppairing] [CdTunnel] Handshake send failed" << std::endl;
        tls_client_.disconnect();
        return RPPAIRING_E_TUNNEL_FAILED;
    }

    // Read CDTunnel handshake response: 10-byte header
    uint8_t header[10];
    if (!tls_client_.recv_exact(header, 10, timeout_ms) || std::memcmp(header, CDTUNNEL_MAGIC, 8) != 0) {
        std::cout << "[librppairing] [CdTunnel] Handshake header recv failed or magic mismatch" << std::endl;
        tls_client_.disconnect();
        return RPPAIRING_E_TUNNEL_FAILED;
    }

    uint16_t resp_len = (static_cast<uint16_t>(header[8]) << 8) | static_cast<uint16_t>(header[9]);
    std::vector<uint8_t> body(resp_len);
    if (!tls_client_.recv_exact(body.data(), resp_len, timeout_ms)) {
        std::cout << "[librppairing] [CdTunnel] Handshake body recv failed" << std::endl;
        tls_client_.disconnect();
        return RPPAIRING_E_TUNNEL_FAILED;
    }

    std::string resp_json(reinterpret_cast<const char*>(body.data()), resp_len);
    std::cout << "[librppairing] [CdTunnel] Handshake json response: " << resp_json << std::endl;

    std::string client_addr = extract_json_string(resp_json, "address");
    std::string client_mask = extract_json_string(resp_json, "netmask");
    std::string server_addr = extract_json_string(resp_json, "serverAddress");
    uint32_t rsd_port = extract_json_uint(resp_json, "serverRSDPort");
    uint32_t mtu = extract_json_uint(resp_json, "mtu");

    if (client_addr.empty() || server_addr.empty() || rsd_port == 0) {
        std::cout << "[librppairing] [CdTunnel] Handshake response missing fields" << std::endl;
        tls_client_.disconnect();
        return RPPAIRING_E_TUNNEL_FAILED;
    }

    std::strncpy(info_.client_address, client_addr.c_str(), sizeof(info_.client_address) - 1);
    std::strncpy(info_.client_netmask, client_mask.c_str(), sizeof(info_.client_netmask) - 1);
    std::strncpy(info_.server_address, server_addr.c_str(), sizeof(info_.server_address) - 1);
    info_.server_rsd_port = static_cast<uint16_t>(rsd_port);
    info_.mtu = mtu;

    if (out_info) {
        *out_info = info_;
    }

    std::cout << "[librppairing] [CdTunnel] Tunnel handshake SUCCESS! Server: " << info_.server_address 
              << ":" << info_.server_rsd_port << std::endl;

    // Start background reader loop
    reader_running_ = true;
    reader_thread_ = std::thread(&CdTunnel::reader_loop, this);

    return RPPAIRING_E_SUCCESS;
}

rppairing_error_t CdTunnel::send_packet(const uint8_t* packet, size_t len) {
    std::lock_guard<std::mutex> lock(send_mutex_);
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

void CdTunnel::register_stream(uint16_t local_port, VirtualTcpStream* stream) {
    std::lock_guard<std::mutex> lock(streams_mutex_);
    streams_[local_port] = stream;
}

void CdTunnel::unregister_stream(uint16_t local_port) {
    std::lock_guard<std::mutex> lock(streams_mutex_);
    streams_.erase(local_port);
}

void CdTunnel::reader_loop() {
    std::vector<uint8_t> rx_buf;
    rx_buf.reserve(65536);
    size_t rx_offset = 0;
    uint8_t read_chunk[16384];

    while (reader_running_) {
        // 1. Process all fully-formed IPv6 packets in the accumulation buffer
        while ((rx_buf.size() - rx_offset) >= kIpv6HeaderLength) {
            const uint8_t* cur_packet = rx_buf.data() + rx_offset;
            // Verify IPv6 (version 6)
            if ((cur_packet[0] >> 4) != 6) {
                rx_offset++;
                continue;
            }

            uint16_t payload_len = (static_cast<uint16_t>(cur_packet[4]) << 8) | static_cast<uint16_t>(cur_packet[5]);
            size_t total_packet_len = kIpv6HeaderLength + payload_len;

            if ((rx_buf.size() - rx_offset) < total_packet_len) {
                // Incomplete packet in buffer — wait for more bytes from socket
                break;
            }

            if (total_packet_len >= 60 && cur_packet[6] == 6) {
                uint16_t in_dst_port = (static_cast<uint16_t>(cur_packet[42]) << 8) | cur_packet[43];

                VirtualTcpStream* target = nullptr;
                {
                    std::lock_guard<std::mutex> lock(streams_mutex_);
                    auto it = streams_.find(in_dst_port);
                    if (it != streams_.end()) {
                        target = it->second;
                    }
                }

                if (target) {
                    target->handle_incoming_packet(cur_packet, total_packet_len);
                }
            }

            rx_offset += total_packet_len;
        }

        // Compact buffer when offset passes threshold to keep memory footprint low with zero per-packet copies
        if (rx_offset > 32768) {
            rx_buf.erase(rx_buf.begin(), rx_buf.begin() + rx_offset);
            rx_offset = 0;
        }

        if (!reader_running_) break;

        // 2. Event-driven blocking read from TLS socket (timeout_ms = -1, zero polling)
        int bytes_read = tls_client_.recv(read_chunk, sizeof(read_chunk), -1);
        if (bytes_read < 0) {
            if (!reader_running_) break;
            std::cout << "[librppairing] [CdTunnel] Socket closed or fatal read error in reader loop. Terminating." << std::endl;

            // Notify all active streams of disconnect
            std::lock_guard<std::mutex> lock(streams_mutex_);
            for (auto& pair : streams_) {
                pair.second->handle_incoming_packet(nullptr, 0);
            }
            break;
        }

        if (bytes_read == 0) {
            continue; // Non-fatal TLS control frame or spurious poll wake
        }

        // 3. Append newly arrived bytes into accumulation buffer
        rx_buf.insert(rx_buf.end(), read_chunk, read_chunk + bytes_read);
    }
}

} // namespace rppairing
