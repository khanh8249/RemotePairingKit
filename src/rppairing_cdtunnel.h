//
//  rppairing_cdtunnel.h
//  librppairing
//
//  Created by Magesh K on 23/08/26.
//  Copyright © 2026 Magesh K. All rights reserved.
//

#ifndef RPPAIRING_CDTUNNEL_H
#define RPPAIRING_CDTUNNEL_H

#include "rppairing/rppairing_types.h"
#include "rppairing_tls_psk.h"
#include <memory>
#include <cstdint>
#include <cstddef>
#include <mutex>
#include <unordered_map>
#include <thread>
#include <atomic>

namespace rppairing {

class VirtualTcpStream;

static constexpr uint32_t kDefaultCdTunnelMtu = 16000;
static constexpr size_t kIpv6HeaderLength = 40;
static constexpr size_t kTcpHeaderLength = 20;

class CdTunnel {
public:
    CdTunnel();
    ~CdTunnel();

    // Connects TLS PSK and performs CDTunnel handshake
    rppairing_error_t connect(
        const char* host,
        uint16_t port,
        const uint8_t* psk,
        size_t psk_len,
        rppairing_tunnel_info_t* out_info,
        int timeout_ms = 5000
    );

    void close();
    bool is_open() const { return tls_client_.is_connected(); }
    const rppairing_tunnel_info_t* info() const { return &info_; }

    virtual rppairing_error_t send_packet(const uint8_t* packet, size_t len);
    virtual rppairing_error_t recv_packet(uint8_t* buf, size_t buf_len, size_t* out_received, int timeout_ms = 5000);

    // Multi-stream demuxing
    virtual void register_stream(uint16_t local_port, VirtualTcpStream* stream);
    virtual void unregister_stream(uint16_t local_port);
    size_t active_stream_count() const {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(streams_mutex_));
        return streams_.size();
    }

private:
    void reader_loop();

    TlsPskClient tls_client_;
    rppairing_tunnel_info_t info_;
    std::mutex send_mutex_;
    std::mutex close_mutex_;
    std::unordered_map<uint16_t, VirtualTcpStream*> streams_;
    std::mutex streams_mutex_;
    std::thread reader_thread_;
    std::atomic<bool> reader_running_{false};
};

} // namespace rppairing

#endif // RPPAIRING_CDTUNNEL_H
