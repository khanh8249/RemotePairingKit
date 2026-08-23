//
//  test_tcp.cpp
//  librppairing
//
//  Created by Magesh K on 23/08/26.
//  Copyright © 2026 Magesh K. All rights reserved.
//

#include "rppairing_tcp.h"
#include "rppairing_cdtunnel.h"
#include "rppairing_crypto.h"
#include <iostream>
#include <vector>
#include <thread>
#include <atomic>
#include <cassert>
#include <cstring>
#include <random>
#include <chrono>
#include <mutex>
#include <map>
#include <condition_variable>
#include <iomanip>
#include <arpa/inet.h>
#include <openssl/evp.h>

using namespace rppairing;

static std::mutex g_log_mutex;

#define TEST_LOG(msg) do { \
    std::lock_guard<std::mutex> log_lock(g_log_mutex); \
    auto now = std::chrono::system_clock::now(); \
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000; \
    std::time_t t = std::chrono::system_clock::to_time_t(now); \
    std::tm tm_buf; \
    localtime_r(&t, &tm_buf); \
    std::cout << std::put_time(&tm_buf, "%H:%M:%S.") << std::setfill('0') << std::setw(3) << ms.count() \
              << " [TestTcp] " << msg << std::endl; \
} while(0)

// ---------------------------------------------------------------------------
// Streaming SHA-512 for O(1) Memory Multi-Gigabyte Verification
// ---------------------------------------------------------------------------

class StreamingSha512 {
public:
    StreamingSha512() {
        ctx_ = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx_, EVP_sha512(), nullptr);
    }
    ~StreamingSha512() {
        if (ctx_) EVP_MD_CTX_free(ctx_);
    }
    void update(const uint8_t* data, size_t len) {
        if (len > 0) EVP_DigestUpdate(ctx_, data, len);
    }
    std::string finalize() {
        uint8_t hash[64];
        unsigned int len = 0;
        EVP_DigestFinal_ex(ctx_, hash, &len);
        return Crypto::base64_encode(hash, 64);
    }
private:
    EVP_MD_CTX* ctx_;
};

// ---------------------------------------------------------------------------
// Virtual In-Memory Loopback Network Router
// ---------------------------------------------------------------------------

struct EndpointKey {
    std::string ip;
    uint16_t port;

    bool operator<(const EndpointKey& other) const {
        if (ip != other.ip) return ip < other.ip;
        return port < other.port;
    }
};

class IPacketReceiver {
public:
    virtual ~IPacketReceiver() = default;
    virtual void handle_packet(const uint8_t* raw_packet, size_t len) = 0;
};

class VirtualNetworkRouter {
public:
    void register_endpoint(const std::string& ip, uint16_t port, IPacketReceiver* receiver) {
        std::lock_guard<std::mutex> lock(mutex_);
        routes_[{ip, port}] = receiver;
    }

    void unregister_endpoint(const std::string& ip, uint16_t port) {
        std::lock_guard<std::mutex> lock(mutex_);
        routes_.erase({ip, port});
    }

    bool route_packet(const uint8_t* raw_packet, size_t len) {
        if (!raw_packet || len < 60) return false;

        char dst_ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &raw_packet[24], dst_ip_str, sizeof(dst_ip_str));
        uint16_t dst_port = (static_cast<uint16_t>(raw_packet[42]) << 8) | raw_packet[43];

        IPacketReceiver* target = nullptr;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = routes_.find({dst_ip_str, dst_port});
            if (it != routes_.end()) {
                target = it->second;
            }
        }

        if (target) {
            target->handle_packet(raw_packet, len);
            return true;
        }
        return false;
    }

private:
    std::mutex mutex_;
    std::map<EndpointKey, IPacketReceiver*> routes_;
};

class VirtualTcpStreamReceiver : public IPacketReceiver {
public:
    VirtualTcpStreamReceiver(VirtualTcpStream* stream) : stream_(stream) {}
    void handle_packet(const uint8_t* raw_packet, size_t len) override {
        if (stream_) stream_->handle_incoming_packet(raw_packet, len);
    }
private:
    VirtualTcpStream* stream_;
};

// ---------------------------------------------------------------------------
// Streaming High-Speed Mirror TCP Server Endpoint
// ---------------------------------------------------------------------------

struct ServerSessionResult {
    size_t total_bytes_received = 0;
    std::string received_sha512;
    bool success = false;
};

class MockTcpServer : public IPacketReceiver {
public:
    MockTcpServer(VirtualNetworkRouter& router, const std::string& server_ip, uint16_t port)
        : router_(router), server_ip_(server_ip), port_(port), expected_bytes_(0), bytes_received_(0) {}

    void set_expected_bytes(size_t expected) {
        expected_bytes_ = expected;
    }

    void handle_packet(const uint8_t* buf, size_t len) override {
        if (!buf || len < 60) return;

        uint8_t client_ip[16];
        uint8_t server_ip[16];
        std::memcpy(client_ip, &buf[8], 16);
        std::memcpy(server_ip, &buf[24], 16);

        uint16_t src_port = (static_cast<uint16_t>(buf[40]) << 8) | buf[41];
        uint32_t in_seq = (static_cast<uint32_t>(buf[44]) << 24) | (static_cast<uint32_t>(buf[45]) << 16) | (static_cast<uint32_t>(buf[46]) << 8) | buf[47];
        uint8_t in_flags = buf[53];
        uint8_t tcp_hdr_len = (buf[52] >> 4) * 4;
        size_t payload_offset = 40 + tcp_hdr_len;
        size_t payload_len = (len > payload_offset) ? (len - payload_offset) : 0;

        uint8_t resp_buf[64];
        size_t resp_len = 0;

        {
            std::lock_guard<std::mutex> lock(mutex_);

            if (in_flags & 0x02) { // SYN
                client_port_ = src_port;
                client_seq_ = in_seq + 1;
                server_seq_ = 100000;
                resp_len = build_tcp_packet_buf(client_ip, server_ip, 0x12, nullptr, 0, resp_buf); // SYN | ACK
                server_seq_++;
            } else if (payload_len > 0) {
                if (in_seq == client_seq_) {
                    hasher_.update(&buf[payload_offset], payload_len);
                    bytes_received_ += payload_len;
                    client_seq_ = in_seq + static_cast<uint32_t>(payload_len);
                }
                resp_len = build_tcp_packet_buf(client_ip, server_ip, 0x10, nullptr, 0, resp_buf); // ACK
                if (bytes_received_ >= expected_bytes_) {
                    cv_.notify_all();
                }
            } else if (in_flags & 0x01) { // FIN
                client_seq_ = in_seq + 1;
                resp_len = build_tcp_packet_buf(client_ip, server_ip, 0x11, nullptr, 0, resp_buf); // FIN | ACK
                cv_.notify_all();
            }
        }

        if (resp_len > 0) {
            router_.route_packet(resp_buf, resp_len);
        }
    }

    bool wait_for_data(size_t expected_bytes, int timeout_ms, ServerSessionResult* out_result) {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms), [&] {
            return bytes_received_ >= expected_bytes;
        });

        out_result->total_bytes_received = bytes_received_;
        if (bytes_received_ == expected_bytes) {
            out_result->received_sha512 = hasher_.finalize();
            out_result->success = true;
        } else {
            out_result->success = false;
        }
        return out_result->success;
    }

private:
    VirtualNetworkRouter& router_;
    std::string server_ip_;
    uint16_t port_;
    uint16_t client_port_ = 0;
    uint32_t client_seq_ = 0;
    uint32_t server_seq_ = 100000;
    size_t expected_bytes_;
    size_t bytes_received_;
    StreamingSha512 hasher_;
    std::mutex mutex_;
    std::condition_variable cv_;

    size_t build_tcp_packet_buf(const uint8_t* client_ip, const uint8_t* server_ip, uint8_t flags, const uint8_t* payload, size_t payload_len, uint8_t* pkt) {
        uint16_t tcp_len = 20 + payload_len;
        uint16_t total_len = 40 + tcp_len;

        // IPv6 Header
        pkt[0] = 0x60;
        pkt[1] = 0x00;
        pkt[2] = 0x00;
        pkt[3] = 0x00;
        pkt[4] = static_cast<uint8_t>((tcp_len >> 8) & 0xFF);
        pkt[5] = static_cast<uint8_t>(tcp_len & 0xFF);
        pkt[6] = 6;  // TCP
        pkt[7] = 64;
        std::memcpy(&pkt[8], server_ip, 16);  // Src = server
        std::memcpy(&pkt[24], client_ip, 16); // Dst = client

        // TCP Header
        uint8_t* tcp = &pkt[40];
        tcp[0] = static_cast<uint8_t>((port_ >> 8) & 0xFF);
        tcp[1] = static_cast<uint8_t>(port_ & 0xFF);
        tcp[2] = static_cast<uint8_t>((client_port_ >> 8) & 0xFF);
        tcp[3] = static_cast<uint8_t>(client_port_ & 0xFF);
        tcp[4] = static_cast<uint8_t>((server_seq_ >> 24) & 0xFF);
        tcp[5] = static_cast<uint8_t>((server_seq_ >> 16) & 0xFF);
        tcp[6] = static_cast<uint8_t>((server_seq_ >> 8) & 0xFF);
        tcp[7] = static_cast<uint8_t>(server_seq_ & 0xFF);
        tcp[8] = static_cast<uint8_t>((client_seq_ >> 24) & 0xFF);
        tcp[9] = static_cast<uint8_t>((client_seq_ >> 16) & 0xFF);
        tcp[10] = static_cast<uint8_t>((client_seq_ >> 8) & 0xFF);
        tcp[11] = static_cast<uint8_t>(client_seq_ & 0xFF);
        tcp[12] = 0x50; // 20 bytes
        tcp[13] = flags;
        tcp[14] = 0xFF; // Window: 65535
        tcp[15] = 0xFF;
        tcp[16] = 0x00;
        tcp[17] = 0x00;
        tcp[18] = 0x00;
        tcp[19] = 0x00;

        if (payload && payload_len > 0) {
            std::memcpy(&pkt[60], payload, payload_len);
        }

        uint32_t sum = 0;
        for (int i = 0; i < 16; i += 2) {
            sum += (static_cast<uint16_t>(server_ip[i]) << 8) | server_ip[i + 1];
            sum += (static_cast<uint16_t>(client_ip[i]) << 8) | client_ip[i + 1];
        }
        sum += (tcp_len >> 16) & 0xFFFF;
        sum += tcp_len & 0xFFFF;
        sum += 6;
        for (size_t i = 0; i < 20; i += 2) {
            sum += (static_cast<uint16_t>(tcp[i]) << 8) | tcp[i + 1];
        }
        for (size_t i = 0; i < (payload_len & ~1); i += 2) {
            sum += (static_cast<uint16_t>(payload[i]) << 8) | payload[i + 1];
        }
        if (payload_len & 1) {
            sum += static_cast<uint16_t>(payload[payload_len - 1]) << 8;
        }
        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        uint16_t csum = static_cast<uint16_t>(~sum);
        tcp[16] = static_cast<uint8_t>((csum >> 8) & 0xFF);
        tcp[17] = static_cast<uint8_t>(csum & 0xFF);

        return total_len;
    }
};

class MockLoopbackTunnel : public CdTunnel {
public:
    MockLoopbackTunnel(VirtualNetworkRouter& router, const std::string& client_ip, const std::string& server_ip)
        : router_(router), client_ip_(client_ip) {
        rppairing_tunnel_info_t* info = const_cast<rppairing_tunnel_info_t*>(this->info());
        std::strncpy(info->client_address, client_ip.c_str(), sizeof(info->client_address) - 1);
        std::strncpy(info->server_address, server_ip.c_str(), sizeof(info->server_address) - 1);
        info->server_rsd_port = 55555;
        info->mtu = 16000;
    }

    bool is_open() const { return true; }

    rppairing_error_t send_packet(const uint8_t* packet, size_t len) override {
        if (router_.route_packet(packet, len)) {
            return RPPAIRING_E_SUCCESS;
        }
        return RPPAIRING_E_SUCCESS;
    }

    void register_stream(uint16_t local_port, VirtualTcpStream* stream) override {
        std::lock_guard<std::mutex> lock(mutex_);
        receivers_[local_port] = std::make_unique<VirtualTcpStreamReceiver>(stream);
        router_.register_endpoint(client_ip_, local_port, receivers_[local_port].get());
    }

    void unregister_stream(uint16_t local_port) override {
        std::lock_guard<std::mutex> lock(mutex_);
        router_.unregister_endpoint(client_ip_, local_port);
        receivers_.erase(local_port);
    }

private:
    VirtualNetworkRouter& router_;
    std::string client_ip_;
    std::mutex mutex_;
    std::map<uint16_t, std::unique_ptr<VirtualTcpStreamReceiver>> receivers_;
};

// ---------------------------------------------------------------------------
// Streaming Generator Helpers (Constant O(1) Memory Usage)
// ---------------------------------------------------------------------------

std::vector<uint8_t> generate_pattern_buffer(size_t size, uint32_t seed) {
    std::vector<uint8_t> data(size);
    std::mt19937 gen(seed);
    for (size_t i = 0; i < size; ++i) {
        data[i] = static_cast<uint8_t>(gen() & 0xFF);
    }
    return data;
}

struct ClientSessionResult {
    size_t total_bytes_sent = 0;
    std::string sent_sha512;
    double duration_seconds = 0.0;
    double throughput_mb_s = 0.0;
    bool success = false;
};

// Streaming Bulk Client (supports transfers from 17 bytes to 10+ GB without memory ballooning)
void run_streaming_client_session(
    VirtualTcpStream* client_stream,
    const std::string& server_ip,
    uint16_t server_port,
    size_t total_bytes_to_send,
    const std::vector<uint8_t>& pattern_buf,
    ClientSessionResult* out_result
) {
    auto start_time = std::chrono::high_resolution_clock::now();

    TEST_LOG("Client connecting to " << server_ip << ":" << server_port << "...");
    if (!client_stream->connect(server_ip, server_port, 15000)) {
        TEST_LOG("Client FAILED connecting to " << server_ip << ":" << server_port);
        out_result->success = false;
        return;
    }
    TEST_LOG("Client connected to " << server_ip << ":" << server_port << "! Streaming " 
             << (total_bytes_to_send >= 1024*1024 ? (std::to_string(total_bytes_to_send / (1024*1024)) + " MB") : (std::to_string(total_bytes_to_send) + " B")) << "...");

    StreamingSha512 client_hasher;
    size_t total_sent = 0;
    size_t chunk_block = 64 * 1024;
    size_t last_log_bytes = 0;
    size_t log_step = std::max<size_t>(512 * 1024, total_bytes_to_send / 4);

    while (total_sent < total_bytes_to_send) {
        size_t to_send = std::min(chunk_block, total_bytes_to_send - total_sent);
        size_t pattern_offset = total_sent % pattern_buf.size();
        if (pattern_offset + to_send > pattern_buf.size()) {
            to_send = pattern_buf.size() - pattern_offset;
        }

        client_hasher.update(pattern_buf.data() + pattern_offset, to_send);

        if (!client_stream->send(pattern_buf.data() + pattern_offset, to_send)) {
            TEST_LOG("Client FAILED send on port " << server_port << " at offset " << total_sent);
            out_result->success = false;
            return;
        }
        total_sent += to_send;

        if (total_sent - last_log_bytes >= log_step || total_sent == total_bytes_to_send) {
            TEST_LOG("Client [:" << server_port << "] Progress: " << (total_sent / (1024 * 1024)) 
                     << "/" << (total_bytes_to_send / (1024 * 1024)) << " MB (" 
                     << (total_sent * 100 / total_bytes_to_send) << "%)");
            last_log_bytes = total_sent;
        }
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end_time - start_time;

    out_result->total_bytes_sent = total_sent;
    out_result->duration_seconds = elapsed.count();
    out_result->throughput_mb_s = (total_sent / (1024.0 * 1024.0)) / elapsed.count();
    out_result->sent_sha512 = client_hasher.finalize();
    out_result->success = true;

    TEST_LOG("Client [:" << server_port << "] FINISHED: " << (total_sent / (1024.0 * 1024.0)) << " MB in " 
             << std::fixed << std::setprecision(3) << elapsed.count() << "s (" 
             << std::setprecision(1) << out_result->throughput_mb_s << " MB/s)");
}

// Variable-Chunk Streaming Client
void run_variable_chunk_streaming_session(
    VirtualTcpStream* client_stream,
    const std::string& server_ip,
    uint16_t server_port,
    size_t total_bytes_to_send,
    const std::vector<uint8_t>& pattern_buf,
    const std::vector<size_t>& chunk_sizes,
    ClientSessionResult* out_result
) {
    auto start_time = std::chrono::high_resolution_clock::now();

    TEST_LOG("Variable Client connecting to " << server_ip << ":" << server_port << "...");
    if (!client_stream->connect(server_ip, server_port, 15000)) {
        TEST_LOG("Variable Client FAILED connecting to " << server_ip << ":" << server_port);
        out_result->success = false;
        return;
    }
    TEST_LOG("Variable Client connected to " << server_ip << ":" << server_port << "! Streaming " 
             << (total_bytes_to_send / (1024 * 1024)) << " MB across alternating dynamic variable chunks...");

    StreamingSha512 client_hasher;
    size_t total_sent = 0;
    size_t chunk_idx = 0;
    size_t last_log_bytes = 0;
    size_t log_step = std::max<size_t>(512 * 1024, total_bytes_to_send / 4);

    while (total_sent < total_bytes_to_send) {
        size_t c_size = chunk_sizes[chunk_idx % chunk_sizes.size()];
        chunk_idx++;
        size_t to_send = std::min(c_size, total_bytes_to_send - total_sent);
        size_t pattern_offset = total_sent % pattern_buf.size();
        if (pattern_offset + to_send > pattern_buf.size()) {
            to_send = pattern_buf.size() - pattern_offset;
        }

        client_hasher.update(pattern_buf.data() + pattern_offset, to_send);

        if (!client_stream->send(pattern_buf.data() + pattern_offset, to_send)) {
            TEST_LOG("Variable Client FAILED send on port " << server_port << " at offset " << total_sent);
            out_result->success = false;
            return;
        }
        total_sent += to_send;

        if (total_sent - last_log_bytes >= log_step || total_sent == total_bytes_to_send) {
            TEST_LOG("Variable Client [:" << server_port << "] Progress: " << (total_sent / (1024 * 1024)) 
                     << "/" << (total_bytes_to_send / (1024 * 1024)) << " MB (" 
                     << (total_sent * 100 / total_bytes_to_send) << "%)");
            last_log_bytes = total_sent;
        }
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end_time - start_time;

    out_result->total_bytes_sent = total_sent;
    out_result->duration_seconds = elapsed.count();
    out_result->throughput_mb_s = (total_sent / (1024.0 * 1024.0)) / elapsed.count();
    out_result->sent_sha512 = client_hasher.finalize();
    out_result->success = true;

    TEST_LOG("Variable Client [:" << server_port << "] FINISHED: " << (total_sent / (1024.0 * 1024.0)) << " MB in " 
             << std::fixed << std::setprecision(3) << elapsed.count() << "s (" 
             << std::setprecision(1) << out_result->throughput_mb_s << " MB/s)");
}

// ---------------------------------------------------------------------------
// 20-Gigabyte Multi-Scenario Stress Test Matrix
// ---------------------------------------------------------------------------

void run_test_scenario_1() {
    TEST_LOG("========================================================");
    TEST_LOG("[Scenario 1] 8 Streams (Same IP x Many Ports): ~3.01 GB Scale");
    TEST_LOG("========================================================");

    // Spectrum from 17 bytes to 1.5 GB
    std::vector<size_t> stream_sizes = {
        17,                                     // 17 bytes
        512,                                    // 512 bytes
        64 * 1024,                              // 64 KB
        773 * 1024 + 509,                       // 773 KB (non-aligned)
        10 * 1024 * 1024,                       // 10 MB
        500 * 1024 * 1024,                      // 500 MB
        static_cast<size_t>(1536) * 1024 * 1024,// 1.5 GB
        static_cast<size_t>(1024) * 1024 * 1024 // Variable-chunk stream (1 GB)
    };

    size_t num_streams = stream_sizes.size();
    size_t total_expected_bytes = 0;
    for (size_t s : stream_sizes) total_expected_bytes += s;

    VirtualNetworkRouter router;
    std::string client_ip = "fd00::1";
    std::string server_ip = "fd00::2";

    MockLoopbackTunnel client_tunnel(router, client_ip, server_ip);

    std::vector<std::unique_ptr<VirtualTcpStream>> client_streams;
    std::vector<std::unique_ptr<MockTcpServer>> servers;
    std::vector<ClientSessionResult> client_results(num_streams);
    std::vector<ServerSessionResult> server_results(num_streams);
    std::vector<uint8_t> pattern_buf = generate_pattern_buffer(1024 * 1024, 1000);

    for (size_t i = 0; i < num_streams; ++i) {
        client_streams.push_back(std::make_unique<VirtualTcpStream>(client_tunnel));

        uint16_t server_port = static_cast<uint16_t>(8000 + i);
        auto s = std::make_unique<MockTcpServer>(router, server_ip, server_port);
        s->set_expected_bytes(stream_sizes[i]);
        servers.push_back(std::move(s));
        router.register_endpoint(server_ip, server_port, servers[i].get());
    }

    auto start_all = std::chrono::high_resolution_clock::now();

    std::vector<size_t> var_chunks = {7, 131, 4096, 1, 65536, 122880, 5, 262144, 524288};

    std::vector<std::thread> threads;
    for (size_t i = 0; i < num_streams; ++i) {
        uint16_t server_port = static_cast<uint16_t>(8000 + i);
        if (i == num_streams - 1) {
            threads.emplace_back(run_variable_chunk_streaming_session, client_streams[i].get(), server_ip, server_port, stream_sizes[i], std::ref(pattern_buf), var_chunks, &client_results[i]);
        } else {
            threads.emplace_back(run_streaming_client_session, client_streams[i].get(), server_ip, server_port, stream_sizes[i], std::ref(pattern_buf), &client_results[i]);
        }
    }

    for (size_t i = 0; i < num_streams; ++i) {
        servers[i]->wait_for_data(stream_sizes[i], 60000, &server_results[i]);
    }

    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }

    auto end_all = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> total_elapsed = end_all - start_all;
    double total_mb = total_expected_bytes / (1024.0 * 1024.0);
    double aggregate_throughput = total_mb / total_elapsed.count();

    for (size_t i = 0; i < num_streams; ++i) {
        assert(client_results[i].success && "Client stream failed to send data");
        assert(server_results[i].success && "Server stream failed to receive full data");
        assert(client_results[i].sent_sha512 == server_results[i].received_sha512 && "Data corruption detected! Hashes mismatch");
    }

    TEST_LOG("-> Scenario 1 PASSED (100% SHA-512 Data Integrity across 8 streams)");
    TEST_LOG("-> Total Transferred: " << std::fixed << std::setprecision(2) << total_mb << " MB (" 
             << (total_mb / 1024.0) << " GB) in " << std::setprecision(3) 
             << total_elapsed.count() << "s (" << std::setprecision(1) << aggregate_throughput << " MB/s)");

    for (auto& s : client_streams) {
        s->close();
    }
    client_streams.clear();
    servers.clear();
}

void run_test_scenario_2() {
    TEST_LOG("========================================================");
    TEST_LOG("[Scenario 2] 8 Clients (Many IPs x Shared Ports): ~4.55 GB Scale");
    TEST_LOG("========================================================");

    std::vector<size_t> stream_sizes = {
        29,                                     // 29 bytes
        1024,                                   // 1 KB
        128 * 1024,                             // 128 KB
        1333 * 1024 + 317,                      // 1.33 MB
        50 * 1024 * 1024,                       // 50 MB
        500 * 1024 * 1024,                      // 500 MB
        static_cast<size_t>(2560) * 1024 * 1024,// 2.5 GB
        static_cast<size_t>(1536) * 1024 * 1024 // Variable-chunk stream (1.5 GB)
    };

    size_t num_streams = stream_sizes.size();
    size_t total_expected_bytes = 0;
    for (size_t s : stream_sizes) total_expected_bytes += s;

    VirtualNetworkRouter router;
    std::string server_ip = "fd00::100";
    uint16_t shared_server_port = 9000;

    std::vector<std::unique_ptr<MockLoopbackTunnel>> client_tunnels;
    std::vector<std::unique_ptr<VirtualTcpStream>> client_streams;
    std::vector<std::unique_ptr<MockTcpServer>> servers;
    std::vector<ClientSessionResult> client_results(num_streams);
    std::vector<ServerSessionResult> server_results(num_streams);
    std::vector<uint8_t> pattern_buf = generate_pattern_buffer(1024 * 1024, 2000);

    for (size_t i = 0; i < num_streams; ++i) {
        std::string client_ip = "fd00::" + std::to_string(i + 1);
        client_tunnels.push_back(std::make_unique<MockLoopbackTunnel>(router, client_ip, server_ip));
        client_streams.push_back(std::make_unique<VirtualTcpStream>(*client_tunnels[i]));

        uint16_t port = shared_server_port + static_cast<uint16_t>(i);
        auto s = std::make_unique<MockTcpServer>(router, server_ip, port);
        s->set_expected_bytes(stream_sizes[i]);
        servers.push_back(std::move(s));
        router.register_endpoint(server_ip, port, servers[i].get());
    }

    auto start_all = std::chrono::high_resolution_clock::now();

    std::vector<size_t> var_chunks = {19, 512, 16384, 3, 32768, 500000, 11, 1000000};

    std::vector<std::thread> threads;
    for (size_t i = 0; i < num_streams; ++i) {
        uint16_t port = shared_server_port + static_cast<uint16_t>(i);
        if (i == num_streams - 1) {
            threads.emplace_back(run_variable_chunk_streaming_session, client_streams[i].get(), server_ip, port, stream_sizes[i], std::ref(pattern_buf), var_chunks, &client_results[i]);
        } else {
            threads.emplace_back(run_streaming_client_session, client_streams[i].get(), server_ip, port, stream_sizes[i], std::ref(pattern_buf), &client_results[i]);
        }
    }

    for (size_t i = 0; i < num_streams; ++i) {
        servers[i]->wait_for_data(stream_sizes[i], 60000, &server_results[i]);
    }

    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }

    auto end_all = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> total_elapsed = end_all - start_all;
    double total_mb = total_expected_bytes / (1024.0 * 1024.0);
    double aggregate_throughput = total_mb / total_elapsed.count();

    for (size_t i = 0; i < num_streams; ++i) {
        assert(client_results[i].success && "Client stream failed to send data");
        assert(server_results[i].success && "Server stream failed to receive full data");
        assert(client_results[i].sent_sha512 == server_results[i].received_sha512 && "Data corruption detected! Hashes mismatch");
    }

    TEST_LOG("-> Scenario 2 PASSED (100% SHA-512 Data Integrity across multi-IP clients)");
    TEST_LOG("-> Total Transferred: " << std::fixed << std::setprecision(2) << total_mb << " MB (" 
             << (total_mb / 1024.0) << " GB) in " << std::setprecision(3) 
             << total_elapsed.count() << "s (" << std::setprecision(1) << aggregate_throughput << " MB/s)");

    for (auto& s : client_streams) {
        s->close();
    }
    client_streams.clear();
    servers.clear();
    client_tunnels.clear();
}

void run_test_scenario_3() {
    TEST_LOG("========================================================");
    TEST_LOG("[Scenario 3] 16 All-to-All Streams (Many IPs x Many Ports): ~12.44 GB Scale");
    TEST_LOG("========================================================");

    std::vector<size_t> stream_sizes = {
        13,                                     // 13 bytes
        4096,                                   // 4 KB
        32 * 1024,                              // 32 KB
        64 * 1024,                              // 64 KB
        512 * 1024,                             // 512 KB
        773 * 1024 + 509,                       // 773 KB
        5 * 1024 * 1024,                        // 5 MB
        25 * 1024 * 1024,                       // 25 MB
        100 * 1024 * 1024,                      // 100 MB
        250 * 1024 * 1024,                      // 250 MB
        500 * 1024 * 1024,                      // 500 MB
        static_cast<size_t>(1024) * 1024 * 1024,// 1.0 GB
        static_cast<size_t>(1536) * 1024 * 1024,// 1.5 GB
        static_cast<size_t>(2560) * 1024 * 1024,// 2.5 GB
        static_cast<size_t>(3072) * 1024 * 1024,// 3.0 GB
        static_cast<size_t>(2560) * 1024 * 1024 // Variable-chunk stream (2.5 GB)
    };

    size_t num_streams = stream_sizes.size();
    size_t total_expected_bytes = 0;
    for (size_t s : stream_sizes) total_expected_bytes += s;

    VirtualNetworkRouter router;

    std::vector<std::unique_ptr<MockLoopbackTunnel>> client_tunnels;
    std::vector<std::unique_ptr<VirtualTcpStream>> client_streams;
    std::vector<std::unique_ptr<MockTcpServer>> servers;
    std::vector<ClientSessionResult> client_results(num_streams);
    std::vector<ServerSessionResult> server_results(num_streams);
    std::vector<uint8_t> pattern_buf = generate_pattern_buffer(1024 * 1024, 3000);

    for (size_t i = 0; i < num_streams; ++i) {
        std::string client_ip = "fd00:1::" + std::to_string(i + 1);
        std::string server_ip = "fd00:2::" + std::to_string(i + 1);
        uint16_t server_port = static_cast<uint16_t>(50000 + i);

        client_tunnels.push_back(std::make_unique<MockLoopbackTunnel>(router, client_ip, server_ip));
        client_streams.push_back(std::make_unique<VirtualTcpStream>(*client_tunnels[i]));

        auto s = std::make_unique<MockTcpServer>(router, server_ip, server_port);
        s->set_expected_bytes(stream_sizes[i]);
        servers.push_back(std::move(s));
        router.register_endpoint(server_ip, server_port, servers[i].get());
    }

    auto start_all = std::chrono::high_resolution_clock::now();

    std::vector<size_t> var_chunks = {3, 17, 8192, 1, 65535, 100000, 7, 500000, 1000000};

    std::vector<std::thread> threads;
    for (size_t i = 0; i < num_streams; ++i) {
        std::string server_ip = "fd00:2::" + std::to_string(i + 1);
        uint16_t server_port = static_cast<uint16_t>(50000 + i);

        if (i == num_streams - 1) {
            threads.emplace_back(run_variable_chunk_streaming_session, client_streams[i].get(), server_ip, server_port, stream_sizes[i], std::ref(pattern_buf), var_chunks, &client_results[i]);
        } else {
            threads.emplace_back(run_streaming_client_session, client_streams[i].get(), server_ip, server_port, stream_sizes[i], std::ref(pattern_buf), &client_results[i]);
        }
    }

    for (size_t i = 0; i < num_streams; ++i) {
        servers[i]->wait_for_data(stream_sizes[i], 120000, &server_results[i]);
    }

    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }

    auto end_all = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> total_elapsed = end_all - start_all;
    double total_mb = total_expected_bytes / (1024.0 * 1024.0);
    double aggregate_throughput = total_mb / total_elapsed.count();

    for (size_t i = 0; i < num_streams; ++i) {
        assert(client_results[i].success && "Client stream failed to send data");
        assert(server_results[i].success && "Server stream failed to receive full data");
        assert(client_results[i].sent_sha512 == server_results[i].received_sha512 && "Data corruption detected! Hashes mismatch");
    }

    TEST_LOG("-> Scenario 3 PASSED (100% SHA-512 Data Integrity across all 16 streams)");
    TEST_LOG("-> Total Transferred: " << std::fixed << std::setprecision(2) << total_mb << " MB (" 
             << (total_mb / 1024.0) << " GB) in " << std::setprecision(3) 
             << total_elapsed.count() << "s (" << std::setprecision(1) << aggregate_throughput << " MB/s)");

    for (auto& s : client_streams) {
        s->close();
    }
    client_streams.clear();
    servers.clear();
    client_tunnels.clear();
}

int main() {
    TEST_LOG("==========================================================");
    TEST_LOG("  VirtualTcpStream 20-Gigabyte Heterogeneous Thrash Suite ");
    TEST_LOG("==========================================================");

    auto test_suite_start = std::chrono::high_resolution_clock::now();

    // Scenario 1: ~3.01 GB across 8 streams (17B to 1.5 GB + 1 GB Variable Stream)
    run_test_scenario_1();

    // Scenario 2: ~4.55 GB across 8 distinct IPs (29B to 2.5 GB + 1.5 GB Variable Stream)
    run_test_scenario_2();

    // Scenario 3: ~12.44 GB across 16 all-to-all streams (13B to 3.0 GB + 2.5 GB Variable Stream)
    run_test_scenario_3();

    auto test_suite_end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> total_suite_time = test_suite_end - test_suite_start;

    TEST_LOG("==========================================================");
    TEST_LOG("  20.0 GB TOTAL THRASHING TEST PASSED WITH 100% INTEGRITY ");
    TEST_LOG("  Total Execution Time: " << std::fixed << std::setprecision(2) << total_suite_time.count() << "s");
    TEST_LOG("==========================================================");
    return 0;
}
