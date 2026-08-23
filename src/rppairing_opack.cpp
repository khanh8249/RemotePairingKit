//
//  rppairing_opack.cpp
//  librppairing
//
//  Created by Magesh K on 23/08/26.
//  Copyright © 2026 Magesh K. All rights reserved.
//

#include "rppairing_opack.h"
#include <cstring>
#include <limits>

namespace rppairing {

static void append_le16(std::vector<uint8_t>& buf, uint16_t v) {
    buf.push_back(static_cast<uint8_t>(v & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
}

static void append_le32(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back(static_cast<uint8_t>(v & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
}

static void append_le64(std::vector<uint8_t>& buf, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        buf.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
    }
}

std::vector<uint8_t> Opack::encode(const OpackValue& value) {
    std::vector<uint8_t> buf;
    encode_inner(value, buf);
    return buf;
}

void Opack::encode_inner(const OpackValue& node, std::vector<uint8_t>& buf) {
    switch (node.type) {
    case OpackType::Null:
        break;
    case OpackType::Bool:
        buf.push_back(node.bool_val ? 0x01 : 0x02);
        break;
    case OpackType::Int: {
        uint64_t v = node.int_val;
        if (v <= 0xFF) {
            uint8_t u8val = static_cast<uint8_t>(v);
            if (u8val > 0x27) {
                buf.push_back(0x30);
                buf.push_back(u8val);
            } else {
                buf.push_back(u8val + 8);
            }
        } else if (v <= 0xFFFFFFFF) {
            buf.push_back(0x32);
            append_le32(buf, static_cast<uint32_t>(v));
        } else {
            buf.push_back(0x33);
            append_le64(buf, v);
        }
        break;
    }
    case OpackType::Real: {
        double dval = node.real_val;
        float fval = static_cast<float>(dval);
        if (static_cast<double>(fval) == dval) {
            buf.push_back(0x35);
            uint32_t bits;
            std::memcpy(&bits, &fval, sizeof(bits));
            // big-endian
            buf.push_back((bits >> 24) & 0xFF);
            buf.push_back((bits >> 16) & 0xFF);
            buf.push_back((bits >> 8) & 0xFF);
            buf.push_back(bits & 0xFF);
        } else {
            buf.push_back(0x36);
            uint64_t bits;
            std::memcpy(&bits, &dval, sizeof(bits));
            for (int i = 7; i >= 0; --i) {
                buf.push_back((bits >> (i * 8)) & 0xFF);
            }
        }
        break;
    }
    case OpackType::String: {
        const std::string& s = node.string_val;
        size_t len = s.size();
        if (len > 0x20) {
            if (len <= 0xFF) {
                buf.push_back(0x61);
                buf.push_back(static_cast<uint8_t>(len));
            } else if (len <= 0xFFFF) {
                buf.push_back(0x62);
                append_le16(buf, static_cast<uint16_t>(len));
            } else if (len <= 0xFFFFFFFF) {
                buf.push_back(0x63);
                append_le32(buf, static_cast<uint32_t>(len));
            } else {
                buf.push_back(0x64);
                append_le64(buf, static_cast<uint64_t>(len));
            }
        } else {
            buf.push_back(static_cast<uint8_t>(0x40 + len));
        }
        buf.insert(buf.end(), s.begin(), s.end());
        break;
    }
    case OpackType::Data: {
        const auto& d = node.data_val;
        size_t len = d.size();
        if (len > 0x20) {
            if (len <= 0xFF) {
                buf.push_back(0x91);
                buf.push_back(static_cast<uint8_t>(len));
            } else if (len <= 0xFFFF) {
                buf.push_back(0x92);
                append_le16(buf, static_cast<uint16_t>(len));
            } else if (len <= 0xFFFFFFFF) {
                buf.push_back(0x93);
                append_le32(buf, static_cast<uint32_t>(len));
            } else {
                buf.push_back(0x94);
                append_le64(buf, static_cast<uint64_t>(len));
            }
        } else {
            buf.push_back(static_cast<uint8_t>(0x70 + len));
        }
        buf.insert(buf.end(), d.begin(), d.end());
        break;
    }
    case OpackType::Array: {
        size_t count = node.array_val.size();
        if (count < 15) {
            buf.push_back(static_cast<uint8_t>(0xD0 + count));
        } else {
            buf.push_back(0xDF);
        }
        for (const auto& elem : node.array_val) {
            encode_inner(elem, buf);
        }
        if (count >= 15) {
            buf.push_back(0x03);
        }
        break;
    }
    case OpackType::Dict: {
        size_t count = node.dict_val.size();
        if (count < 15) {
            buf.push_back(static_cast<uint8_t>(0xE0 + count));
        } else {
            buf.push_back(0xEF);
        }
        for (const auto& pair : node.dict_val) {
            encode_inner(OpackValue::make_string(pair.first), buf);
            encode_inner(pair.second, buf);
        }
        if (count >= 15) {
            buf.push_back(0x03);
        }
        break;
    }
    }
}

bool Opack::decode(const uint8_t* data, size_t length, OpackValue& out_value) {
    size_t offset = 0;
    if (!decode_inner(data, length, offset, out_value)) {
        return false;
    }
    return (offset == length);
}

bool Opack::decode_inner(const uint8_t* data, size_t length, size_t& offset, OpackValue& out) {
    if (offset >= length) return false;
    uint8_t tag = data[offset++];

    if (tag == 0x01) {
        out = OpackValue::make_bool(true);
        return true;
    } else if (tag == 0x02) {
        out = OpackValue::make_bool(false);
        return true;
    } else if (tag >= 0x08 && tag <= 0x2F) {
        out = OpackValue::make_int(tag - 8);
        return true;
    } else if (tag == 0x30) {
        if (offset >= length) return false;
        out = OpackValue::make_int(data[offset++]);
        return true;
    } else if (tag == 0x32) {
        if (offset + 4 > length) return false;
        uint32_t val = static_cast<uint32_t>(data[offset]) |
                       (static_cast<uint32_t>(data[offset + 1]) << 8) |
                       (static_cast<uint32_t>(data[offset + 2]) << 16) |
                       (static_cast<uint32_t>(data[offset + 3]) << 24);
        offset += 4;
        out = OpackValue::make_int(val);
        return true;
    } else if (tag == 0x33) {
        if (offset + 8 > length) return false;
        uint64_t val = 0;
        for (int i = 0; i < 8; ++i) {
            val |= (static_cast<uint64_t>(data[offset + i]) << (i * 8));
        }
        offset += 8;
        out = OpackValue::make_int(val);
        return true;
    } else if (tag >= 0x40 && tag <= 0x64) {
        size_t len = 0;
        if (tag >= 0x40 && tag <= 0x60) {
            len = tag - 0x40;
        } else if (tag == 0x61) {
            if (offset >= length) return false;
            len = data[offset++];
        } else if (tag == 0x62) {
            if (offset + 2 > length) return false;
            len = data[offset] | (data[offset + 1] << 8);
            offset += 2;
        } else if (tag == 0x63) {
            if (offset + 4 > length) return false;
            len = data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24);
            offset += 4;
        }
        if (offset + len > length) return false;
        out = OpackValue::make_string(std::string(reinterpret_cast<const char*>(data + offset), len));
        offset += len;
        return true;
    } else if (tag >= 0x70 && tag <= 0x94) {
        size_t len = 0;
        if (tag >= 0x70 && tag <= 0x90) {
            len = tag - 0x70;
        } else if (tag == 0x91) {
            if (offset >= length) return false;
            len = data[offset++];
        } else if (tag == 0x92) {
            if (offset + 2 > length) return false;
            len = data[offset] | (data[offset + 1] << 8);
            offset += 2;
        } else if (tag == 0x93) {
            if (offset + 4 > length) return false;
            len = data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24);
            offset += 4;
        }
        if (offset + len > length) return false;
        out = OpackValue::make_data(data + offset, len);
        offset += len;
        return true;
    } else if (tag >= 0xE0 && tag <= 0xEF) {
        std::map<std::string, OpackValue> dict;
        if (tag < 0xEF) {
            size_t count = tag - 0xE0;
            for (size_t i = 0; i < count; ++i) {
                OpackValue key_val, val;
                if (!decode_inner(data, length, offset, key_val) || key_val.type != OpackType::String) return false;
                if (!decode_inner(data, length, offset, val)) return false;
                dict[key_val.string_val] = val;
            }
        } else {
            while (offset < length && data[offset] != 0x03) {
                OpackValue key_val, val;
                if (!decode_inner(data, length, offset, key_val) || key_val.type != OpackType::String) return false;
                if (!decode_inner(data, length, offset, val)) return false;
                dict[key_val.string_val] = val;
            }
            if (offset < length && data[offset] == 0x03) offset++;
        }
        out = OpackValue::make_dict(dict);
        return true;
    }

    return false;
}

} // namespace rppairing
