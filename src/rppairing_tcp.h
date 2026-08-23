//
//  rppairing_tcp.h
//  librppairing
//
//  Created by Magesh K on 23/08/26.
//  Copyright © 2026 Magesh K. All rights reserved.
//

#ifndef RPPAIRING_TCP_H
#define RPPAIRING_TCP_H

#include "rppairing/rppairing_types.h"
#include "rppairing_cdtunnel.h"
#include <stdint.h>
#include <stddef.h>
#include <vector>
#include <deque>
#include <string>
#include <mutex>
#include <chrono>
#include <condition_variable>

namespace rppairing {

static constexpr size_t kTcpDefaultMss = 1440;
static constexpr size_t kTcpStackBufferSize = 16384;

// RFC 793: Default 16-bit TCP Window Size
static constexpr uint16_t kTcpDefaultWindowSize = 65535;

// RFC 7323 : 1 MiB Send Window cap for high throughput over virtual tunnel
static constexpr size_t kTcpDefaultSendWindow = 1 << 20; // 1 MiB

// Maximum retransmission attempts before connection timeout
static constexpr uint32_t kTcpMaxRetries = 5;

// RFC 6298: Initial Retransmission Timeout (RTO) in milliseconds
static constexpr uint64_t kTcpInitialRtoMs = 200;

struct UnackedSegment {
    uint32_t seq;
    std::vector<uint8_t> data;
    std::chrono::steady_clock::time_point sent_at;
    uint32_t retries;
};

class VirtualTcpStream {
public:
    VirtualTcpStream(CdTunnel& tunnel);
    ~VirtualTcpStream();

    bool connect(const std::string& server_ip6, uint16_t dest_port, int timeout_ms = 10000);
    void close();

    bool send(const uint8_t* data, size_t len);
    int recv(uint8_t* buf, size_t max_len, int timeout_ms = 10000);
    bool recv_exact(uint8_t* buf, size_t len, int timeout_ms = 10000);

    bool is_connected() const { return connected_; }
    uint16_t src_port() const { return src_port_; }
    size_t mss() const { return mss_; }

    int handle_incoming_packet(const uint8_t* buf, size_t received);

private:
    CdTunnel& tunnel_;
    uint8_t client_ip6_[16];
    uint8_t server_ip6_[16];
    uint16_t src_port_;
    uint16_t dst_port_;
    uint32_t seq_num_;
    uint32_t ack_num_;
    uint32_t peer_ack_num_;
    uint32_t peer_window_;
    size_t mss_;
    bool connected_;

    std::deque<UnackedSegment> unacked_;
    size_t bytes_in_flight_;

    std::vector<uint8_t> rx_buffer_;
    std::mutex stream_mutex_;
    std::condition_variable cv_;

    bool send_packet(uint8_t flags, const uint8_t* payload = NULL, size_t payload_len = 0, int64_t custom_seq = -1);
    static uint16_t checksum(const uint8_t* ip6_src, const uint8_t* ip6_dst, uint32_t tcp_len, const uint8_t* tcp_hdr, size_t hdr_len, const uint8_t* payload, size_t payload_len);
};

} // namespace rppairing

#endif // RPPAIRING_TCP_H
