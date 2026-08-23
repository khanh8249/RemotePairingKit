//
//  rppairing_rsd.cpp
//  librppairing
//
//  Created by Magesh K on 23/08/26.
//  Copyright © 2026 Magesh K. All rights reserved.
//

#include "rppairing_rsd.h"
#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <sstream>
#include <vector>
#include <unordered_map>

namespace rppairing {

// ─────────────────────────────────────────────────────────────
// HTTP/2 Protocol Constants (RFC 7540)
// ─────────────────────────────────────────────────────────────
static const char HTTP2_PREFACE[24] = {
    'P', 'R', 'I', ' ', '*', ' ', 'H', 'T',
    'T', 'P', '/', '2', '.', '0', '\r', '\n',
    '\r', '\n', 'S', 'M', '\r', '\n', '\r', '\n'
};

enum Http2FrameType : uint8_t {
    H2_FRAME_DATA          = 0x00,
    H2_FRAME_HEADERS       = 0x01,
    H2_FRAME_SETTINGS      = 0x04,
    H2_FRAME_PING          = 0x06,
    H2_FRAME_WINDOW_UPDATE = 0x08
};

enum Http2Flags : uint8_t {
    H2_FLAG_NONE        = 0x00,
    H2_FLAG_END_STREAM  = 0x01,
    H2_FLAG_END_HEADERS = 0x04,
    H2_FLAG_ACK         = 0x01
};

enum Http2Stream : uint32_t {
    H2_STREAM_CONTROL = 0,
    H2_STREAM_ROOT    = 1, // Channel 1 (root channel for RSD commands)
    H2_STREAM_REPLY   = 3  // Channel 3 (reply channel for RemoteXPC events)
};

// ─────────────────────────────────────────────────────────────
// Apple RemoteXPC Protocol Constants
// ─────────────────────────────────────────────────────────────
static const uint32_t XPC_WRAPPER_MAGIC = 0x29B00B92; // 4-byte LE wrapper magic
static const uint32_t XPC_OBJECT_MAGIC  = 0x42133742; // 4-byte LE binary XPC dictionary magic
static const uint32_t XPC_OBJECT_VERSION = 5;          // Modern binary XPC format version

enum XPCFlags : uint32_t {
    XPC_FLAG_ALWAYS_SET     = 0x00000001,
    XPC_FLAG_DATA           = 0x00000100,
    XPC_FLAG_WANTING_REPLY  = 0x00010000,
    XPC_FLAG_REPLY          = 0x00020000,
    XPC_FLAG_INIT_HANDSHAKE = 0x00400000,
    XPC_FLAG_CHANNEL_INIT   = 0x00000201  // Channel 1 negotiation flags
};

enum XPCType : uint32_t {
    XPC_TYPE_BOOL       = 0x00002000,
    XPC_TYPE_INT64      = 0x00003000,
    XPC_TYPE_UINT64     = 0x00004000,
    XPC_TYPE_DOUBLE     = 0x00005000,
    XPC_TYPE_DATE       = 0x00007000,
    XPC_TYPE_DATA       = 0x00008000,
    XPC_TYPE_STRING     = 0x00009000,
    XPC_TYPE_UUID       = 0x0000A000,
    XPC_TYPE_ARRAY      = 0x0000E000,
    XPC_TYPE_DICTIONARY = 0x0000F000
};

// ─────────────────────────────────────────────────────────────
// RsdClient Implementation
// ─────────────────────────────────────────────────────────────

RsdClient::RsdClient(CdTunnel& tunnel)
    : tunnel_(tunnel), tcp_(tunnel) {
}

RsdClient::~RsdClient() {
}

uint16_t RsdClient::get_service_port(const std::string& service_name) const {
    // 1. Exact match
    auto it = services_.find(service_name);
    if (it != services_.end()) {
        return it->second.port;
    }
    // 2. Trusted remote endpoint match
    it = services_.find(service_name + ".remote.trusted");
    if (it != services_.end()) {
        return it->second.port;
    }
    // 3. Shim remote match
    it = services_.find(service_name + ".shim.remote");
    if (it != services_.end()) {
        return it->second.port;
    }
    // 4. Remote match
    it = services_.find(service_name + ".remote");
    if (it != services_.end()) {
        return it->second.port;
    }
    // 5. Prefix match
    for (const auto& kv : services_) {
        if (kv.first.rfind(service_name, 0) == 0) {
            return kv.second.port;
        }
    }
    // 6. Substring match
    for (const auto& kv : services_) {
        if (kv.first.find(service_name) != std::string::npos) {
            return kv.second.port;
        }
    }
    return 0;
}

static void append_u32_le(std::vector<uint8_t>& buf, uint32_t val) {
    buf.push_back(static_cast<uint8_t>(val & 0xFF));
    buf.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((val >> 24) & 0xFF));
}

static void append_u64_le(std::vector<uint8_t>& buf, uint64_t val) {
    append_u32_le(buf, static_cast<uint32_t>(val & 0xFFFFFFFF));
    append_u32_le(buf, static_cast<uint32_t>((val >> 32) & 0xFFFFFFFF));
}

static std::vector<uint8_t> make_h2_frame(uint8_t type, uint8_t flags, uint32_t stream_id, const uint8_t* payload, size_t payload_len) {
    std::vector<uint8_t> frame(9 + payload_len);
    frame[0] = static_cast<uint8_t>((payload_len >> 16) & 0xFF);
    frame[1] = static_cast<uint8_t>((payload_len >> 8) & 0xFF);
    frame[2] = static_cast<uint8_t>(payload_len & 0xFF);
    frame[3] = type;
    frame[4] = flags;
    frame[5] = static_cast<uint8_t>((stream_id >> 24) & 0x7F);
    frame[6] = static_cast<uint8_t>((stream_id >> 16) & 0xFF);
    frame[7] = static_cast<uint8_t>((stream_id >> 8) & 0xFF);
    frame[8] = static_cast<uint8_t>(stream_id & 0xFF);
    if (payload && payload_len > 0) {
        std::memcpy(&frame[9], payload, payload_len);
    }
    return frame;
}

static std::vector<uint8_t> make_xpc_msg(uint32_t flags, uint64_t msg_id, const std::vector<uint8_t>& xpc_obj) {
    std::vector<uint8_t> wrapper;
    append_u32_le(wrapper, XPC_WRAPPER_MAGIC);
    append_u32_le(wrapper, flags);
    append_u64_le(wrapper, static_cast<uint64_t>(xpc_obj.size()));
    append_u64_le(wrapper, msg_id);
    if (!xpc_obj.empty()) {
        wrapper.insert(wrapper.end(), xpc_obj.begin(), xpc_obj.end());
    }
    return wrapper;
}

static std::vector<uint8_t> encode_empty_dict() {
    std::vector<uint8_t> xpc_obj;
    // Magic: 0x42133742 (LE) + Version 5 (LE)
    uint32_t magic = XPC_OBJECT_MAGIC;
    uint32_t version = XPC_OBJECT_VERSION;
    uint32_t dict_type = XPC_TYPE_DICTIONARY;
    uint32_t content_len = 4; // 4-byte count header
    uint32_t count = 0;

    for (int i = 0; i < 4; ++i) xpc_obj.push_back(static_cast<uint8_t>((magic >> (i * 8)) & 0xFF));
    for (int i = 0; i < 4; ++i) xpc_obj.push_back(static_cast<uint8_t>((version >> (i * 8)) & 0xFF));
    for (int i = 0; i < 4; ++i) xpc_obj.push_back(static_cast<uint8_t>((dict_type >> (i * 8)) & 0xFF));
    for (int i = 0; i < 4; ++i) xpc_obj.push_back(static_cast<uint8_t>((content_len >> (i * 8)) & 0xFF));
    for (int i = 0; i < 4; ++i) xpc_obj.push_back(static_cast<uint8_t>((count >> (i * 8)) & 0xFF));
    return xpc_obj;
}

// Encode device handshake dictionary matching Apple RemoteXPC
static std::vector<uint8_t> encode_device_handshake_dict() {
    // 1. Properties sub-dictionary
    std::vector<uint8_t> prop_content;
    uint32_t prop_entries = 2;
    for (int i = 0; i < 4; ++i) prop_content.push_back(static_cast<uint8_t>((prop_entries >> (i * 8)) & 0xFF));

    // "RemoteXPCVersionFlags" -> UInt64 0x0100000000000006
    std::string pk1 = "RemoteXPCVersionFlags";
    prop_content.insert(prop_content.end(), pk1.begin(), pk1.end());
    prop_content.push_back(0);
    while (prop_content.size() % 4 != 0) prop_content.push_back(0);

    uint32_t type_u64 = XPC_TYPE_UINT64;
    for (int i = 0; i < 4; ++i) prop_content.push_back(static_cast<uint8_t>((type_u64 >> (i * 8)) & 0xFF));
    uint64_t pv1 = 0x0100000000000006ULL;
    for (int i = 0; i < 8; ++i) prop_content.push_back(static_cast<uint8_t>((pv1 >> (i * 8)) & 0xFF));

    // "SensitivePropertiesVisible" -> Bool true
    std::string pk2 = "SensitivePropertiesVisible";
    prop_content.insert(prop_content.end(), pk2.begin(), pk2.end());
    prop_content.push_back(0);
    while (prop_content.size() % 4 != 0) prop_content.push_back(0);

    uint32_t type_bool = XPC_TYPE_BOOL;
    for (int i = 0; i < 4; ++i) prop_content.push_back(static_cast<uint8_t>((type_bool >> (i * 8)) & 0xFF));
    prop_content.push_back(1);
    prop_content.push_back(0);
    prop_content.push_back(0);
    prop_content.push_back(0);

    // 2. Services sub-dictionary (empty)
    std::vector<uint8_t> srv_content;
    uint32_t srv_entries = 0;
    for (int i = 0; i < 4; ++i) srv_content.push_back(static_cast<uint8_t>((srv_entries >> (i * 8)) & 0xFF));

    // 3. Root dictionary
    std::vector<uint8_t> root_content;
    uint32_t root_entries = 5;
    for (int i = 0; i < 4; ++i) root_content.push_back(static_cast<uint8_t>((root_entries >> (i * 8)) & 0xFF));

    // Key 1: "MessageType" -> String "Handshake"
    std::string rk1 = "MessageType";
    root_content.insert(root_content.end(), rk1.begin(), rk1.end());
    root_content.push_back(0);
    while (root_content.size() % 4 != 0) root_content.push_back(0);

    uint32_t type_str = XPC_TYPE_STRING;
    for (int i = 0; i < 4; ++i) root_content.push_back(static_cast<uint8_t>((type_str >> (i * 8)) & 0xFF));
    std::string rv1 = "Handshake";
    uint32_t rv1_len = static_cast<uint32_t>(rv1.size() + 1);
    for (int i = 0; i < 4; ++i) root_content.push_back(static_cast<uint8_t>((rv1_len >> (i * 8)) & 0xFF));
    root_content.insert(root_content.end(), rv1.begin(), rv1.end());
    root_content.push_back(0);
    while (root_content.size() % 4 != 0) root_content.push_back(0);

    // Key 2: "MessagingProtocolVersion" -> UInt64 7
    std::string rk2 = "MessagingProtocolVersion";
    root_content.insert(root_content.end(), rk2.begin(), rk2.end());
    root_content.push_back(0);
    while (root_content.size() % 4 != 0) root_content.push_back(0);

    for (int i = 0; i < 4; ++i) root_content.push_back(static_cast<uint8_t>((type_u64 >> (i * 8)) & 0xFF));
    uint64_t rv2 = 7;
    for (int i = 0; i < 8; ++i) root_content.push_back(static_cast<uint8_t>((rv2 >> (i * 8)) & 0xFF));

    // Key 3: "UUID" -> Uuid (16 random bytes)
    std::string rk3 = "UUID";
    root_content.insert(root_content.end(), rk3.begin(), rk3.end());
    root_content.push_back(0);
    while (root_content.size() % 4 != 0) root_content.push_back(0);

    uint32_t type_uuid = XPC_TYPE_UUID;
    for (int i = 0; i < 4; ++i) root_content.push_back(static_cast<uint8_t>((type_uuid >> (i * 8)) & 0xFF));
    for (int i = 0; i < 16; ++i) root_content.push_back(static_cast<uint8_t>(rand() & 0xFF));

    // Key 4: "Properties" -> Dictionary
    std::string rk4 = "Properties";
    root_content.insert(root_content.end(), rk4.begin(), rk4.end());
    root_content.push_back(0);
    while (root_content.size() % 4 != 0) root_content.push_back(0);

    uint32_t dict_type = XPC_TYPE_DICTIONARY;
    for (int i = 0; i < 4; ++i) root_content.push_back(static_cast<uint8_t>((dict_type >> (i * 8)) & 0xFF));
    uint32_t prop_len = static_cast<uint32_t>(prop_content.size());
    for (int i = 0; i < 4; ++i) root_content.push_back(static_cast<uint8_t>((prop_len >> (i * 8)) & 0xFF));
    root_content.insert(root_content.end(), prop_content.begin(), prop_content.end());

    // Key 5: "Services" -> Dictionary
    std::string rk5 = "Services";
    root_content.insert(root_content.end(), rk5.begin(), rk5.end());
    root_content.push_back(0);
    while (root_content.size() % 4 != 0) root_content.push_back(0);

    for (int i = 0; i < 4; ++i) root_content.push_back(static_cast<uint8_t>((dict_type >> (i * 8)) & 0xFF));
    uint32_t srv_len = static_cast<uint32_t>(srv_content.size());
    for (int i = 0; i < 4; ++i) root_content.push_back(static_cast<uint8_t>((srv_len >> (i * 8)) & 0xFF));
    root_content.insert(root_content.end(), srv_content.begin(), srv_content.end());

    // 4. Wrap with XPC Header
    std::vector<uint8_t> xpc_obj;
    uint32_t magic = XPC_OBJECT_MAGIC;
    uint32_t version = XPC_OBJECT_VERSION;
    for (int i = 0; i < 4; ++i) xpc_obj.push_back(static_cast<uint8_t>((magic >> (i * 8)) & 0xFF));
    for (int i = 0; i < 4; ++i) xpc_obj.push_back(static_cast<uint8_t>((version >> (i * 8)) & 0xFF));

    for (int i = 0; i < 4; ++i) xpc_obj.push_back(static_cast<uint8_t>((dict_type >> (i * 8)) & 0xFF));
    uint32_t root_len = static_cast<uint32_t>(root_content.size());
    for (int i = 0; i < 4; ++i) xpc_obj.push_back(static_cast<uint8_t>((root_len >> (i * 8)) & 0xFF));
    xpc_obj.insert(xpc_obj.end(), root_content.begin(), root_content.end());

    return xpc_obj;
}

rppairing_error_t RsdClient::perform_handshake(int timeout_ms) {
    std::cout << "[RsdClient] Starting HTTP/2 connection preface on RSD port..." << std::endl;

    // 1. Send HTTP/2 Connection Preface
    if (!tcp_.send(reinterpret_cast<const uint8_t*>(HTTP2_PREFACE), sizeof(HTTP2_PREFACE))) {
        return RPPAIRING_E_CONN_FAILED;
    }

    // 2. Send initial SETTINGS frame (Stream 0)
    // MAX_CONCURRENT_STREAMS = 100, INITIAL_WINDOW_SIZE = 1048576
    uint8_t settings_payload[12] = {
        0x00, 0x03, 0x00, 0x00, 0x00, 0x64,
        0x00, 0x04, 0x00, 0x10, 0x00, 0x00
    };
    std::vector<uint8_t> set_frame = make_h2_frame(H2_FRAME_SETTINGS, H2_FLAG_NONE, H2_STREAM_CONTROL, settings_payload, sizeof(settings_payload));
    if (!tcp_.send(set_frame.data(), set_frame.size())) {
        return RPPAIRING_E_CONN_FAILED;
    }

    // 3. Send WINDOW_UPDATE frame (Stream 0) increment by 983041
    uint8_t win_payload[4] = { 0x00, 0x0F, 0x00, 0x01 };
    std::vector<uint8_t> win_frame = make_h2_frame(H2_FRAME_WINDOW_UPDATE, H2_FLAG_NONE, H2_STREAM_CONTROL, win_payload, sizeof(win_payload));
    if (!tcp_.send(win_frame.data(), win_frame.size())) {
        return RPPAIRING_E_CONN_FAILED;
    }

    // 4. Open Root Stream (Stream 1) with empty HEADERS frame
    std::vector<uint8_t> open_s1 = make_h2_frame(H2_FRAME_HEADERS, H2_FLAG_END_HEADERS, H2_STREAM_ROOT, NULL, 0);
    tcp_.send(open_s1.data(), open_s1.size());

    // 5. Send empty dictionary (Flags: XPC_FLAG_ALWAYS_SET) on Stream 1
    std::vector<uint8_t> msg1 = make_xpc_msg(XPC_FLAG_ALWAYS_SET, 1, encode_empty_dict());
    std::vector<uint8_t> d1 = make_h2_frame(H2_FRAME_DATA, H2_FLAG_NONE, H2_STREAM_ROOT, msg1.data(), msg1.size());
    tcp_.send(d1.data(), d1.size());

    // 6. Open Reply Stream (Stream 3) with empty HEADERS frame
    std::vector<uint8_t> open_s3 = make_h2_frame(H2_FRAME_HEADERS, H2_FLAG_END_HEADERS, H2_STREAM_REPLY, NULL, 0);
    tcp_.send(open_s3.data(), open_s3.size());

    // 7. Send InitHandshake (Flags: XPC_FLAG_INIT_HANDSHAKE | XPC_FLAG_ALWAYS_SET) on Stream 3
    std::vector<uint8_t> msg2 = make_xpc_msg(XPC_FLAG_INIT_HANDSHAKE | XPC_FLAG_ALWAYS_SET, 1, {});
    std::vector<uint8_t> d2 = make_h2_frame(H2_FRAME_DATA, H2_FLAG_NONE, H2_STREAM_REPLY, msg2.data(), msg2.size());
    tcp_.send(d2.data(), d2.size());

    // 8. Send Channel Init Flags (0x201) on Stream 1
    std::vector<uint8_t> msg3 = make_xpc_msg(XPC_FLAG_CHANNEL_INIT, 1, {});
    std::vector<uint8_t> d3 = make_h2_frame(H2_FRAME_DATA, H2_FLAG_NONE, H2_STREAM_ROOT, msg3.data(), msg3.size());
    tcp_.send(d3.data(), d3.size());

    // 9. Send Device Handshake message on Stream 1
    std::vector<uint8_t> msg4 = make_xpc_msg(XPC_FLAG_DATA | XPC_FLAG_ALWAYS_SET, 1, encode_device_handshake_dict());
    std::vector<uint8_t> d4 = make_h2_frame(H2_FRAME_DATA, H2_FLAG_NONE, H2_STREAM_ROOT, msg4.data(), msg4.size());
    tcp_.send(d4.data(), d4.size());

    std::cout << "[RsdClient] Sent RemoteXPC handshake, awaiting response..." << std::endl;

    // 10. Read HTTP/2 response frames
    std::vector<uint8_t> stream1_data;
    uint8_t h2_hdr[9];
    int elapsed = 0;

    while (elapsed < timeout_ms) {
        if (!tcp_.recv_exact(h2_hdr, 9, 1000)) {
            elapsed += 1000;
            continue;
        }

        uint32_t payload_len = (static_cast<uint32_t>(h2_hdr[0]) << 16) | (static_cast<uint32_t>(h2_hdr[1]) << 8) | h2_hdr[2];
        uint8_t type = h2_hdr[3];
        uint8_t flags = h2_hdr[4];
        uint32_t stream_id = ((static_cast<uint32_t>(h2_hdr[5]) & 0x7F) << 24) | (static_cast<uint32_t>(h2_hdr[6]) << 16) | (static_cast<uint32_t>(h2_hdr[7]) << 8) | h2_hdr[8];

        std::cout << "[RsdClient] Recv H2 frame: type=" << (int)type << " len=" << payload_len << " stream=" << stream_id << " flags=" << (int)flags << std::endl;

        std::vector<uint8_t> payload(payload_len);
        if (payload_len > 0) {
            if (!tcp_.recv_exact(payload.data(), payload_len, 2000)) {
                break;
            }
        }

        if (type == H2_FRAME_SETTINGS && !(flags & H2_FLAG_ACK)) {
            // SETTINGS received, reply with SETTINGS ACK
            std::vector<uint8_t> ack = make_h2_frame(H2_FRAME_SETTINGS, H2_FLAG_ACK, H2_STREAM_CONTROL, NULL, 0);
            tcp_.send(ack.data(), ack.size());
        }

        if (type == H2_FRAME_DATA) {
            stream1_data.insert(stream1_data.end(), payload.begin(), payload.end());
            if (stream1_data.size() > 50) {
                std::string data_str(reinterpret_cast<const char*>(stream1_data.data()), stream1_data.size());
                parse_services_plist(data_str);
                if (!services_.empty()) {
                    std::cout << "[RsdClient] Discovered " << services_.size() << " services via RSD!" << std::endl;
                    return RPPAIRING_E_SUCCESS;
                }
            }
        }
    }

    if (!services_.empty()) return RPPAIRING_E_SUCCESS;
    return RPPAIRING_E_TIMEOUT;
}

static uint16_t extract_service_port(const uint8_t* raw, size_t p_pos, size_t len, const std::string& data_str) {
    size_t max_search = std::min(len, p_pos + 64);
    for (size_t i = p_pos + 4; i < max_search; ++i) {
        // Binary XPC UInt64/Int64 tag check (0x00004000 or 0x00003000 LE)
        if (i + 12 <= len) {
            uint32_t type = static_cast<uint32_t>(raw[i]) |
                            (static_cast<uint32_t>(raw[i+1]) << 8) |
                            (static_cast<uint32_t>(raw[i+2]) << 16) |
                            (static_cast<uint32_t>(raw[i+3]) << 24);
            if (type == XPC_TYPE_UINT64 || type == XPC_TYPE_INT64) {
                uint64_t port = static_cast<uint64_t>(raw[i+4]) |
                                (static_cast<uint64_t>(raw[i+5]) << 8) |
                                (static_cast<uint64_t>(raw[i+6]) << 16) |
                                (static_cast<uint64_t>(raw[i+7]) << 24);
                if (port > 1024 && port < 65536) {
                    return static_cast<uint16_t>(port);
                }
            }
        }

        // ASCII string decimal digit fallback
        if (std::isdigit(raw[i])) {
            size_t num_end = i;
            while (num_end < len && std::isdigit(raw[num_end])) num_end++;
            try {
                uint16_t port = static_cast<uint16_t>(std::stoul(data_str.substr(i, num_end - i)));
                if (port > 1024) return port;
            } catch (...) {}
        }
    }
    return 0;
}

void RsdClient::parse_services_plist(const std::string& data_str) {
    const uint8_t* raw = reinterpret_cast<const uint8_t*>(data_str.data());
    size_t len = data_str.size();

    // 1. First scan for binary XPC / plist service entries
    size_t pos = 0;
    while ((pos = data_str.find("com.apple.", pos)) != std::string::npos) {
        size_t name_end = pos;
        while (name_end < len && (std::isalnum(raw[name_end]) || raw[name_end] == '.' || raw[name_end] == '_' || raw[name_end] == '-')) {
            name_end++;
        }
        std::string s_name = data_str.substr(pos, name_end - pos);

        // If preceded by "Entitlement", this is an entitlement attribute, not a service name
        if (pos >= 20) {
            std::string prefix = data_str.substr(pos - 20, 20);
            if (prefix.find("Entitlement") != std::string::npos) {
                pos = name_end + 1;
                continue;
            }
        }

        // Find "Port" nearby
        size_t p_pos = data_str.find("Port", name_end);
        if (p_pos == std::string::npos || (p_pos - name_end) >= 300) {
            pos = name_end + 1;
            continue;
        }

        uint16_t port = extract_service_port(raw, p_pos, len, data_str);
        if (port > 0) {
            RsdService s;
            s.name = s_name;
            s.port = port;
            services_[s_name] = s;
            std::cout << "[RsdClient] Service: " << s_name << " -> Port: " << port << std::endl;
        }

        pos = name_end + 1;
    }
}

rppairing_error_t RsdClient::connect(const std::string& server_ip6, uint16_t rsd_port, int timeout_ms) {
    services_.clear();
    std::cout << "[RsdClient] Connecting virtual TCP to [" << server_ip6 << "]:" << rsd_port << "..." << std::endl;
    if (!tcp_.connect(server_ip6, rsd_port, timeout_ms)) {
        std::cout << "[RsdClient] Virtual TCP connect failed" << std::endl;
        return RPPAIRING_E_CONN_FAILED;
    }
    std::cout << "[RsdClient] Virtual TCP connected, performing RemoteXPC handshake..." << std::endl;
    return perform_handshake(timeout_ms);
}

} // namespace rppairing
