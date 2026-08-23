//
//  rppairing_transport.h
//  librppairing
//
//  Created by Magesh K on 23/08/26.
//  Copyright © 2026 Magesh K. All rights reserved.
//

#ifndef RPPAIRING_TRANSPORT_H
#define RPPAIRING_TRANSPORT_H

#include "rppairing/rppairing_types.h"
#include <string>
#include <vector>
#include <cstdint>
#include <cstddef>

namespace rppairing {

class Transport {
public:
    Transport();
    ~Transport();

    bool connect(const char* host, uint16_t port, int timeout_ms = 5000);
    void disconnect();
    bool is_connected() const { return (fd_ >= 0); }

    // Wire Framing: 9-byte magic "RPPairing" + 2-byte BE len + JSON payload
    bool send_message(const std::string& json_str);
    bool recv_message(std::string& out_json_str, int timeout_ms = 5000);

    // Raw read/write
    bool send_exact(const uint8_t* data, size_t len);
    bool recv_exact(uint8_t* buf, size_t len, int timeout_ms = 5000);

private:
    int fd_;
};

} // namespace rppairing

#endif // RPPAIRING_TRANSPORT_H
