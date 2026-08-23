//
//  rppairing_tcp.cpp
//  librppairing
//
//  Created by Magesh K on 23/08/26.
//  Copyright © 2026 Magesh K. All rights reserved.
//

#include "rppairing_tcp.h"
#include "rppairing_crypto.h"
#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <random>
#include <chrono>

namespace rppairing {

static const uint8_t TCP_FIN = 0x01;
static const uint8_t TCP_SYN = 0x02;
static const uint8_t TCP_RST = 0x04;
static const uint8_t TCP_PSH = 0x08;
static const uint8_t TCP_ACK = 0x10;

VirtualTcpStream::VirtualTcpStream(CdTunnel& tunnel)
    : tunnel_(tunnel), src_port_(0), dst_port_(0), seq_num_(0), ack_num_(0),
      peer_ack_num_(0), peer_window_(kTcpDefaultWindowSize), connected_(false),
      bytes_in_flight_(0) {
    std::memset(client_ip6_, 0, sizeof(client_ip6_));
    std::memset(server_ip6_, 0, sizeof(server_ip6_));
}

VirtualTcpStream::~VirtualTcpStream() {
    close();
}

uint16_t VirtualTcpStream::checksum(
    const uint8_t* ip6_src, const uint8_t* ip6_dst,
    uint32_t tcp_len,
    const uint8_t* tcp_hdr, size_t hdr_len,
    const uint8_t* payload, size_t payload_len
) {
    uint32_t sum = 0;

    // IPv6 pseudo header: Src (16B) + Dst (16B) + Length (4B) + NextHeader (4B)
    for (int i = 0; i < 16; i += 2) {
        sum += (static_cast<uint16_t>(ip6_src[i]) << 8) | ip6_src[i + 1];
        sum += (static_cast<uint16_t>(ip6_dst[i]) << 8) | ip6_dst[i + 1];
    }
    sum += (tcp_len >> 16) & 0xFFFF;
    sum += tcp_len & 0xFFFF;
    sum += 6; // Next header = TCP

    // TCP Header
    for (size_t i = 0; i < hdr_len; i += 2) {
        sum += (static_cast<uint16_t>(tcp_hdr[i]) << 8) | tcp_hdr[i + 1];
    }

    // Payload
    for (size_t i = 0; i < (payload_len & ~1); i += 2) {
        sum += (static_cast<uint16_t>(payload[i]) << 8) | payload[i + 1];
    }
    if (payload_len & 1) {
        sum += static_cast<uint16_t>(payload[payload_len - 1]) << 8;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

bool VirtualTcpStream::send_packet(uint8_t flags, const uint8_t* payload, size_t payload_len, int64_t custom_seq) {
    uint16_t tcp_len = 20 + payload_len;
    uint16_t total_len = 40 + tcp_len;

    uint8_t stack_buf[kTcpStackBufferSize];
    uint8_t* packet = stack_buf;
    std::vector<uint8_t> heap_buf;
    if (total_len > sizeof(stack_buf)) {
        heap_buf.resize(total_len);
        packet = heap_buf.data();
    }

    // IPv6 Header (40 bytes)
    packet[0] = 0x60; // Version 6
    packet[1] = 0x00;
    packet[2] = 0x00;
    packet[3] = 0x00;
    packet[4] = static_cast<uint8_t>((tcp_len >> 8) & 0xFF);
    packet[5] = static_cast<uint8_t>(tcp_len & 0xFF);
    packet[6] = 6;    // Next header: TCP
    packet[7] = 64;   // Hop limit
    std::memcpy(&packet[8], client_ip6_, 16);
    std::memcpy(&packet[24], server_ip6_, 16);

    uint32_t effective_seq = (custom_seq >= 0) ? static_cast<uint32_t>(custom_seq) : seq_num_;

    // TCP Header (20 bytes)
    uint8_t* tcp = &packet[40];
    tcp[0] = static_cast<uint8_t>((src_port_ >> 8) & 0xFF);
    tcp[1] = static_cast<uint8_t>(src_port_ & 0xFF);
    tcp[2] = static_cast<uint8_t>((dst_port_ >> 8) & 0xFF);
    tcp[3] = static_cast<uint8_t>(dst_port_ & 0xFF);
    tcp[4] = static_cast<uint8_t>((effective_seq >> 24) & 0xFF);
    tcp[5] = static_cast<uint8_t>((effective_seq >> 16) & 0xFF);
    tcp[6] = static_cast<uint8_t>((effective_seq >> 8) & 0xFF);
    tcp[7] = static_cast<uint8_t>(effective_seq & 0xFF);
    tcp[8] = static_cast<uint8_t>((ack_num_ >> 24) & 0xFF);
    tcp[9] = static_cast<uint8_t>((ack_num_ >> 16) & 0xFF);
    tcp[10] = static_cast<uint8_t>((ack_num_ >> 8) & 0xFF);
    tcp[11] = static_cast<uint8_t>(ack_num_ & 0xFF);
    tcp[12] = 0x50; // Data offset: 5 words (20 bytes)
    tcp[13] = flags;
    tcp[14] = static_cast<uint8_t>((kTcpDefaultWindowSize >> 8) & 0xFF);
    tcp[15] = static_cast<uint8_t>(kTcpDefaultWindowSize & 0xFF);
    tcp[16] = 0x00; // Checksum placeholder
    tcp[17] = 0x00;
    tcp[18] = 0x00; // Urgent pointer
    tcp[19] = 0x00;

    if (payload && payload_len > 0) {
        std::memcpy(&packet[60], payload, payload_len);
    }

    uint16_t csum = checksum(client_ip6_, server_ip6_, tcp_len, tcp, 20, payload, payload_len);
    tcp[16] = static_cast<uint8_t>((csum >> 8) & 0xFF);
    tcp[17] = static_cast<uint8_t>(csum & 0xFF);

    return (tunnel_.send_packet(packet, total_len) == RPPAIRING_E_SUCCESS);
}

int VirtualTcpStream::handle_incoming_packet(const uint8_t* buf, size_t received) {
    if (!buf || received == 0) {
        std::lock_guard<std::mutex> lock(stream_mutex_);
        connected_ = false;
        cv_.notify_all();
        return -1;
    }
    if (received < 60) return 0;

    uint16_t in_src_port = (static_cast<uint16_t>(buf[40]) << 8) | buf[41];
    uint16_t in_dst_port = (static_cast<uint16_t>(buf[42]) << 8) | buf[43];

    if (in_src_port != dst_port_ || in_dst_port != src_port_) return 0;

    uint32_t in_seq = (static_cast<uint32_t>(buf[44]) << 24) | (static_cast<uint32_t>(buf[45]) << 16) | (static_cast<uint32_t>(buf[46]) << 8) | buf[47];
    uint32_t in_ack = (static_cast<uint32_t>(buf[48]) << 24) | (static_cast<uint32_t>(buf[49]) << 16) | (static_cast<uint32_t>(buf[50]) << 8) | buf[51];
    uint8_t in_flags = buf[53];
    uint16_t in_win = (static_cast<uint16_t>(buf[54]) << 8) | buf[55];
    uint8_t tcp_hdr_len = (buf[52] >> 4) * 4;

    size_t payload_offset = 40 + tcp_hdr_len;
    size_t payload_len = 0;
    if (received > payload_offset) {
        payload_len = received - payload_offset;
    }

    bool send_ack = false;
    bool send_syn_ack = false;
    bool notify = false;
    int result = 0;

    {
        std::lock_guard<std::mutex> lock(stream_mutex_);

        if (in_flags & TCP_ACK) {
            peer_ack_num_ = in_ack;
            // Drain acknowledged segments from unacked queue (matching jktcp adapter.rs)
            while (!unacked_.empty()) {
                const auto& seg = unacked_.front();
                uint32_t seg_end = seg.seq + static_cast<uint32_t>(seg.data.size());
                if (static_cast<int32_t>(in_ack - seg_end) >= 0) {
                    bytes_in_flight_ = (bytes_in_flight_ >= seg.data.size()) ? (bytes_in_flight_ - seg.data.size()) : 0;
                    unacked_.pop_front();
                } else {
                    break;
                }
            }

            peer_window_ = in_win;
            notify = true;
        }

        if (in_flags & TCP_RST) {
            connected_ = false;
            cv_.notify_all();
            return -1;
        }

        if ((in_flags & TCP_SYN) && (in_flags & TCP_ACK)) {
            ack_num_ = in_seq + 1;
            seq_num_++;
            peer_ack_num_ = in_ack;
            connected_ = true;
            send_syn_ack = true;
            notify = true;
            result = 1;
        } else if (payload_len > 0) {
            if (in_seq == ack_num_) {
                // Expected in-order segment: accept and buffer
                rx_buffer_.insert(rx_buffer_.end(), &buf[payload_offset], &buf[payload_offset + payload_len]);
                ack_num_ = in_seq + payload_len;
                send_ack = true;
                notify = true;
                result = static_cast<int>(payload_len);
            } else {
                // Duplicate or out-of-order segment: re-ACK with current ack_num_
                send_ack = true;
            }
        } else if (in_flags & TCP_FIN) {
            ack_num_ = in_seq + 1;
            connected_ = false;
            send_ack = true;
            notify = true;
            result = -1;
        } else if (in_flags & TCP_ACK) {
            result = 2; // Pure ACK processed
        }
    }

    // Call send_packet outside stream_mutex_ to avoid lock contention / inversion
    if (send_syn_ack) {
        std::cout << "[VirtualTcp] Received SYN-ACK from port " << in_src_port << "! Sending ACK..." << std::endl;
        send_packet(TCP_ACK);
    } else if (send_ack) {
        send_packet(TCP_ACK);
    }

    if (notify) {
        cv_.notify_all();
    }

    return result;
}

bool VirtualTcpStream::connect(const std::string& server_ip6, uint16_t dest_port, int timeout_ms) {
    if (connected_) return true;

    const rppairing_tunnel_info_t* info = tunnel_.info();
    if (!info) return false;

    if (inet_pton(AF_INET6, info->client_address, client_ip6_) != 1) return false;
    if (inet_pton(AF_INET6, server_ip6.c_str(), server_ip6_) != 1) return false;

    // Pick a random ephemeral source port 50000-65000 (thread-safe)
    thread_local static std::random_device rd;
    thread_local static std::mt19937 gen(rd());
    std::uniform_int_distribution<uint16_t> port_dis(50000, 65000);
    std::uniform_int_distribution<uint32_t> seq_dis(10000, 1000000);

    src_port_ = port_dis(gen);
    dst_port_ = dest_port;
    seq_num_ = seq_dis(gen);
    ack_num_ = 0;
    peer_ack_num_ = seq_num_;
    peer_window_ = kTcpDefaultWindowSize;
    mss_ = (info->mtu > 60) ? (info->mtu - 60) : kTcpDefaultMss;
    unacked_.clear();
    bytes_in_flight_ = 0;
    connected_ = false;

    tunnel_.register_stream(src_port_, this);

    // Send SYN
    std::cout << "[VirtualTcp] Sending SYN from port " << src_port_ << " to port " << dst_port_ << " (seq " << seq_num_ << ")..." << std::endl;
    if (!send_packet(TCP_SYN)) {
        tunnel_.unregister_stream(src_port_);
        return false;
    }

    // Wait for SYN-ACK event (zero polling)
    std::unique_lock<std::mutex> lock(stream_mutex_);
    cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms), [this] { return connected_; });

    if (!connected_) {
        std::cout << "[VirtualTcp] SYN timeout on port " << src_port_ << std::endl;
        tunnel_.unregister_stream(src_port_);
    } else {
        std::cout << "[VirtualTcp] Stream connected successfully on port " << src_port_ << " to " << dst_port_ << std::endl;
    }

    return connected_;
}

void VirtualTcpStream::close() {
    if (connected_) {
        send_packet(TCP_FIN | TCP_ACK);
        seq_num_++;
        connected_ = false;
    }
    if (src_port_ != 0) {
        tunnel_.unregister_stream(src_port_);
        src_port_ = 0;
    }
    std::lock_guard<std::mutex> lock(stream_mutex_);
    rx_buffer_.clear();
    unacked_.clear();
    bytes_in_flight_ = 0;
    cv_.notify_all();
}

bool VirtualTcpStream::send(const uint8_t* data, size_t len) {
    if (!connected_) return false;

    size_t sent = 0;
    while (sent < len) {
        size_t effective_window = std::min<size_t>(kTcpDefaultSendWindow, peer_window_);
        size_t chunk_len = std::min(len - sent, mss_);
        uint32_t current_seq = 0;

        {
            std::unique_lock<std::mutex> lock(stream_mutex_);
            while (connected_ && bytes_in_flight_ >= effective_window) {
                uint64_t current_rto_ms = kTcpInitialRtoMs;
                if (!unacked_.empty()) {
                    current_rto_ms = kTcpInitialRtoMs << std::min<uint32_t>(unacked_.front().retries, 6);
                }

                if (cv_.wait_for(lock, std::chrono::milliseconds(current_rto_ms)) == std::cv_status::timeout) {
                    if (!unacked_.empty()) {
                        auto& head = unacked_.front();
                        if (head.retries >= kTcpMaxRetries) {
                            connected_ = false;
                            return false;
                        }
                        head.retries++;
                        head.sent_at = std::chrono::steady_clock::now();
                        uint32_t retransmit_seq = head.seq;
                        std::vector<uint8_t> retransmit_data = head.data;

                        lock.unlock();
                        send_packet(TCP_PSH | TCP_ACK, retransmit_data.data(), retransmit_data.size(), retransmit_seq);
                        lock.lock();
                    }
                }
            }
            if (!connected_) return false;

            current_seq = seq_num_;
            UnackedSegment seg;
            seg.seq = current_seq;
            seg.data.assign(data + sent, data + sent + chunk_len);
            seg.sent_at = std::chrono::steady_clock::now();
            seg.retries = 0;

            unacked_.push_back(std::move(seg));
            bytes_in_flight_ += chunk_len;
            seq_num_ += chunk_len;
        }

        if (!send_packet(TCP_PSH | TCP_ACK, data + sent, chunk_len, current_seq)) {
            std::lock_guard<std::mutex> lock(stream_mutex_);
            connected_ = false;
            cv_.notify_all();
            return false;
        }

        sent += chunk_len;
    }
    return true;
}

int VirtualTcpStream::recv(uint8_t* buf, size_t max_len, int timeout_ms) {
    std::unique_lock<std::mutex> lock(stream_mutex_);

    // Wait for incoming packet event (zero polling)
    cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms), [this] {
        return !rx_buffer_.empty() || !connected_;
    });

    if (!rx_buffer_.empty()) {
        size_t to_copy = std::min(max_len, rx_buffer_.size());
        std::memcpy(buf, rx_buffer_.data(), to_copy);
        rx_buffer_.erase(rx_buffer_.begin(), rx_buffer_.begin() + to_copy);
        return static_cast<int>(to_copy);
    }

    if (!connected_) return -1;
    return 0; // Timeout
}

bool VirtualTcpStream::recv_exact(uint8_t* buf, size_t len, int timeout_ms) {
    size_t total = 0;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (total < len) {
        int rem_ms = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count());
        if (rem_ms <= 0) return false;

        int r = recv(buf + total, len - total, rem_ms);
        if (r < 0) return false;
        if (r > 0) total += r;
    }
    return true;
}

} // namespace rppairing
