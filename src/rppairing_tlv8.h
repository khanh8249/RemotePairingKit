//
//  rppairing_tlv8.h
//  librppairing
//
//  Created by Magesh K on 23/08/26.
//  Copyright © 2026 Magesh K. All rights reserved.
//

#ifndef RPPAIRING_TLV8_H
#define RPPAIRING_TLV8_H

#include "rppairing/rppairing_types.h"
#include <vector>
#include <cstdint>
#include <cstddef>

namespace rppairing {

struct TlvEntry {
    uint8_t type;
    std::vector<uint8_t> data;
};

class Tlv8 {
public:
    // Serializes vector of entries into TLV8 bytes (splits >255 byte buffers across consecutive entries)
    static std::vector<uint8_t> serialize(const std::vector<TlvEntry>& entries);

    // Parses raw TLV8 bytes into entries
    static bool deserialize(const uint8_t* data, size_t length, std::vector<TlvEntry>& out_entries);

    // Helper to collect and concatenate all contiguous/matching chunks of a given component type
    static std::vector<uint8_t> collect(const std::vector<TlvEntry>& entries, uint8_t type);

    // Checks if a component type exists in the list
    static bool contains(const std::vector<TlvEntry>& entries, uint8_t type);
};

} // namespace rppairing

#endif // RPPAIRING_TLV8_H
