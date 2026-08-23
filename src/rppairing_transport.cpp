//
//  rppairing_transport.cpp
//  librppairing
//
//  Created by Magesh K on 23/08/26.
//  Copyright © 2026 Magesh K. All rights reserved.
//

#include "rppairing_transport.h"
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

namespace rppairing {

static const char MAGIC[9] = {'R', 'P', 'P', 'a', 'i', 'r', 'i', 'n', 'g'};

Transport::Transport() : fd_(-1) {}

Transport::~Transport() {
    disconnect();
}

bool Transport::connect(const char* host, uint16_t port, int timeout_ms) {
    disconnect();

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

    int sock = -1;
    for (struct addrinfo* p = res; p != NULL; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock < 0) continue;

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
                break;
            }
        }

        close(sock);
        sock = -1;
    }

    freeaddrinfo(res);
    fd_ = sock;
    return (fd_ >= 0);
}

void Transport::disconnect() {
    if (fd_ >= 0) {
        close(fd_);
        fd_ = -1;
    }
}

bool Transport::send_exact(const uint8_t* data, size_t len) {
    if (fd_ < 0) return false;
    size_t total_sent = 0;
    while (total_sent < len) {
        ssize_t sent = ::write(fd_, data + total_sent, len - total_sent);
        if (sent <= 0) return false;
        total_sent += sent;
    }
    return true;
}

bool Transport::recv_exact(uint8_t* buf, size_t len, int timeout_ms) {
    if (fd_ < 0) return false;
    size_t total_read = 0;
    while (total_read < len) {
        struct pollfd pfd;
        pfd.fd = fd_;
        pfd.events = POLLIN;
        int p_res = poll(&pfd, 1, timeout_ms);
        if (p_res <= 0 || !(pfd.revents & POLLIN)) return false;

        ssize_t r = ::read(fd_, buf + total_read, len - total_read);
        if (r <= 0) return false;
        total_read += r;
    }
    return true;
}

bool Transport::send_message(const std::string& json_str) {
    if (json_str.size() > 0xFFFF) return false;
    uint16_t len = static_cast<uint16_t>(json_str.size());

    std::vector<uint8_t> frame;
    frame.insert(frame.end(), MAGIC, MAGIC + 9);
    frame.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
    frame.push_back(static_cast<uint8_t>(len & 0xFF));
    frame.insert(frame.end(), json_str.begin(), json_str.end());

    return send_exact(frame.data(), frame.size());
}

bool Transport::recv_message(std::string& out_json_str, int timeout_ms) {
    uint8_t header[11];
    if (!recv_exact(header, 11, timeout_ms)) return false;

    if (std::memcmp(header, MAGIC, 9) != 0) {
        return false;
    }

    uint16_t length = (static_cast<uint16_t>(header[9]) << 8) | static_cast<uint16_t>(header[10]);
    std::vector<uint8_t> body(length);
    if (!recv_exact(body.data(), length, timeout_ms)) return false;

    out_json_str.assign(reinterpret_cast<const char*>(body.data()), length);
    return true;
}

} // namespace rppairing
