//
//  rppairing_tls_psk.h
//  librppairing
//
//  Created by Magesh K on 23/08/26.
//  Copyright © 2026 Magesh K. All rights reserved.
//

#ifndef RPPAIRING_TLS_PSK_H
#define RPPAIRING_TLS_PSK_H

#include <vector>
#include <cstdint>
#include <cstddef>
#include <openssl/ssl.h>

namespace rppairing {

class TlsPskClient {
public:
    TlsPskClient();
    ~TlsPskClient();

    // Connects to device_host:port and negotiates TLS 1.2 PSK with the given key
    bool connect(const char* host, uint16_t port, const uint8_t* psk, size_t psk_len, int timeout_ms = 5000);
    void disconnect();
    bool is_connected() const { return (ssl_ != NULL); }

    int send(const uint8_t* data, size_t len);
    int recv(uint8_t* buf, size_t len, int timeout_ms = 5000);
    bool recv_exact(uint8_t* buf, size_t len, int timeout_ms = 5000);

    const std::vector<uint8_t>& psk() const { return psk_; }

private:
    int fd_;
    SSL_CTX* ctx_;
    SSL* ssl_;
    std::vector<uint8_t> psk_;
};

} // namespace rppairing

#endif // RPPAIRING_TLS_PSK_H
