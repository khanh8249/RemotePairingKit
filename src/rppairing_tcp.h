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
#include <string>

namespace rppairing {

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

private:
    CdTunnel& tunnel_;
    uint8_t client_ip6_[16];
    uint8_t server_ip6_[16];
    uint16_t src_port_;
    uint16_t dst_port_;
    uint32_t seq_num_;
    uint32_t ack_num_;
    bool connected_;

    std::vector<uint8_t> rx_buffer_;

    bool send_packet(uint8_t flags, const uint8_t* payload = NULL, size_t payload_len = 0);
    int process_incoming(int timeout_ms);
    static uint16_t checksum(const uint8_t* ip6_src, const uint8_t* ip6_dst, uint32_t tcp_len, const uint8_t* tcp_hdr, size_t hdr_len, const uint8_t* payload, size_t payload_len);
};

} // namespace rppairing

#endif // RPPAIRING_TCP_H
