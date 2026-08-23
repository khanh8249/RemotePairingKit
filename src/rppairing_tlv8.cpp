//
//  rppairing_tlv8.cpp
//  librppairing
//
//  Created by Magesh K on 23/08/26.
//  Copyright © 2026 Magesh K. All rights reserved.
//

#include "rppairing_tlv8.h"
#include <algorithm>

namespace rppairing {

std::vector<uint8_t> Tlv8::serialize(const std::vector<TlvEntry>& entries) {
    std::vector<uint8_t> out;
    for (const auto& entry : entries) {
        if (entry.data.empty()) {
            out.push_back(entry.type);
            out.push_back(0);
            continue;
        }

        size_t offset = 0;
        while (offset < entry.data.size()) {
            size_t chunk_len = std::min<size_t>(255, entry.data.size() - offset);
            out.push_back(entry.type);
            out.push_back(static_cast<uint8_t>(chunk_len));
            out.insert(out.end(), entry.data.begin() + offset, entry.data.begin() + offset + chunk_len);
            offset += chunk_len;
        }
    }
    return out;
}

bool Tlv8::deserialize(const uint8_t* data, size_t length, std::vector<TlvEntry>& out_entries) {
    out_entries.clear();
    size_t index = 0;

    while (index + 2 <= length) {
        uint8_t type = data[index];
        size_t len = data[index + 1];
        index += 2;

        if (index + len > length) {
            return false;
        }

        std::vector<uint8_t> chunk(data + index, data + index + len);
        index += len;

        out_entries.push_back({type, std::move(chunk)});
    }

    return (index == length);
}

std::vector<uint8_t> Tlv8::collect(const std::vector<TlvEntry>& entries, uint8_t type) {
    std::vector<uint8_t> result;
    for (const auto& entry : entries) {
        if (entry.type == type) {
            result.insert(result.end(), entry.data.begin(), entry.data.end());
        }
    }
    return result;
}

bool Tlv8::contains(const std::vector<TlvEntry>& entries, uint8_t type) {
    for (const auto& entry : entries) {
        if (entry.type == type) {
            return true;
        }
    }
    return false;
}

} // namespace rppairing
