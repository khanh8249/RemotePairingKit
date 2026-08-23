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

namespace rppairing {

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

    rppairing_error_t send_packet(const uint8_t* packet, size_t len);
    rppairing_error_t recv_packet(uint8_t* buf, size_t buf_len, size_t* out_received, int timeout_ms = 5000);

private:
    TlsPskClient tls_client_;
    rppairing_tunnel_info_t info_;
};

} // namespace rppairing

#endif // RPPAIRING_CDTUNNEL_H
