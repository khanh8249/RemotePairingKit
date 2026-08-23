//
//  rppairing_tls_psk.cpp
//  librppairing
//
//  Created by Magesh K on 23/08/26.
//  Copyright © 2026 Magesh K. All rights reserved.
//

#include "rppairing_tls_psk.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <cstring>
#include <algorithm>

namespace rppairing {

static unsigned int psk_client_cb(
    SSL* ssl,
    const char* hint,
    char* identity,
    unsigned int max_identity_len,
    unsigned char* psk,
    unsigned int max_psk_len
) {
    TlsPskClient* self = reinterpret_cast<TlsPskClient*>(SSL_get_app_data(ssl));
    if (!self) return 0;

    if (max_identity_len > 0) {
        identity[0] = '\0';
    }

    const auto& key = self->psk();
    if (key.size() > max_psk_len) return 0;

    std::memcpy(psk, key.data(), key.size());
    return static_cast<unsigned int>(key.size());
}

TlsPskClient::TlsPskClient() : fd_(kInvalidSocket), ctx_(NULL), ssl_(NULL) {}

TlsPskClient::~TlsPskClient() {
    disconnect();
}

bool TlsPskClient::connect(const char* host, uint16_t port, const uint8_t* psk, size_t psk_len, int timeout_ms) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    disconnect();
    psk_.assign(psk, psk + psk_len);

    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[16];
    std::snprintf(port_str, sizeof(port_str), "%u", port);

    struct addrinfo* res = NULL;
    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res) {
        return false;
    }

    int sock = kInvalidSocket;
    for (struct addrinfo* p = res; p != NULL; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock == kInvalidSocket) continue;

        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);

        int c_res = ::connect(sock, p->ai_addr, p->ai_addrlen);
        if (c_res == 0) {
            fcntl(sock, F_SETFL, flags);
            break;
        }

        struct pollfd pfd;
        pfd.fd = sock;
        pfd.events = POLLOUT;
        int poll_res = poll(&pfd, 1, timeout_ms);
        if (poll_res > 0 && (pfd.revents & POLLOUT) && !(pfd.revents & (POLLERR | POLLHUP | POLLNVAL))) {
            int so_error = 0;
            socklen_t len = sizeof(so_error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
            if (so_error == 0) {
                fcntl(sock, F_SETFL, flags);
                int flag = 1;
                setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(int));
                #ifdef SO_NOSIGPIPE
                setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, (char*)&flag, sizeof(int));
                #endif
                int buf_size = kSocketBufferSize;
                setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char*)&buf_size, sizeof(buf_size));
                setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char*)&buf_size, sizeof(buf_size));
                break;
            }
        }

        close(sock);
        sock = kInvalidSocket;
    }

    freeaddrinfo(res);
    if (sock == kInvalidSocket) return false;
    fd_ = sock;

    ctx_ = SSL_CTX_new(TLS_client_method());
    if (!ctx_) {
        disconnect();
        return false;
    }

    SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx_, TLS1_2_VERSION);
    SSL_CTX_set_cipher_list(ctx_, "PSK-AES256-CBC-SHA384:PSK-AES128-CBC-SHA");
    SSL_CTX_set_psk_client_callback(ctx_, psk_client_cb);

    ssl_ = SSL_new(ctx_);
    if (!ssl_) {
        disconnect();
        return false;
    }

    SSL_set_app_data(ssl_, this);
    SSL_set_fd(ssl_, fd_);

    if (SSL_connect(ssl_) <= 0) {
        disconnect();
        return false;
    }

    return true;
}

void TlsPskClient::disconnect() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (ssl_) {
        SSL_shutdown(ssl_);
        SSL_free(ssl_);
        ssl_ = NULL;
    }
    if (ctx_) {
        SSL_CTX_free(ctx_);
        ctx_ = NULL;
    }
    if (fd_ != kInvalidSocket) {
        close(fd_);
        fd_ = kInvalidSocket;
    }
    psk_.clear();
}

int TlsPskClient::send(const uint8_t* data, size_t len) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!ssl_ || fd_ == kInvalidSocket) return -1;
    return SSL_write(ssl_, data, static_cast<int>(len));
}

bool TlsPskClient::recv_exact(uint8_t* buf, size_t len, int timeout_ms) {
    size_t total = 0;
    while (total < len) {
        int r = recv(buf + total, len - total, timeout_ms);
        if (r <= 0) return false;
        total += r;
    }
    return true;
}

int TlsPskClient::recv(uint8_t* buf, size_t len, int timeout_ms) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!ssl_ || fd_ == kInvalidSocket) return -1;

    if (SSL_pending(ssl_) == 0) {
        struct pollfd pfd;
        pfd.fd = fd_;
        pfd.events = POLLIN;
        int p_res = poll(&pfd, 1, timeout_ms);
        if (p_res <= 0 || !(pfd.revents & POLLIN)) return 0;
        if (!ssl_ || fd_ == kInvalidSocket) return -1;
    }

    return SSL_read(ssl_, buf, static_cast<int>(len));
}

} // namespace rppairing
