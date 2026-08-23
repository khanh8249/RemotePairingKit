//
//  rppairing_opack.h
//  librppairing
//
//  Created by Magesh K on 23/08/26.
//  Copyright © 2026 Magesh K. All rights reserved.
//

#ifndef RPPAIRING_OPACK_H
#define RPPAIRING_OPACK_H

#include <vector>
#include <string>
#include <map>
#include <memory>
#include <cstdint>
#include <cstddef>

namespace rppairing {

enum class OpackType {
    Null,
    Bool,
    Int,
    Real,
    String,
    Data,
    Array,
    Dict
};

struct OpackValue {
    OpackType type = OpackType::Null;
    bool bool_val = false;
    uint64_t int_val = 0;
    double real_val = 0.0;
    std::string string_val;
    std::vector<uint8_t> data_val;
    std::vector<OpackValue> array_val;
    std::map<std::string, OpackValue> dict_val;

    static OpackValue make_bool(bool v) {
        OpackValue val; val.type = OpackType::Bool; val.bool_val = v; return val;
    }
    static OpackValue make_int(uint64_t v) {
        OpackValue val; val.type = OpackType::Int; val.int_val = v; return val;
    }
    static OpackValue make_real(double v) {
        OpackValue val; val.type = OpackType::Real; val.real_val = v; return val;
    }
    static OpackValue make_string(const std::string& v) {
        OpackValue val; val.type = OpackType::String; val.string_val = v; return val;
    }
    static OpackValue make_data(const std::vector<uint8_t>& v) {
        OpackValue val; val.type = OpackType::Data; val.data_val = v; return val;
    }
    static OpackValue make_data(const uint8_t* ptr, size_t len) {
        OpackValue val; val.type = OpackType::Data; val.data_val.assign(ptr, ptr + len); return val;
    }
    static OpackValue make_array(const std::vector<OpackValue>& v) {
        OpackValue val; val.type = OpackType::Array; val.array_val = v; return val;
    }
    static OpackValue make_dict(const std::map<std::string, OpackValue>& v) {
        OpackValue val; val.type = OpackType::Dict; val.dict_val = v; return val;
    }
};

class Opack {
public:
    static std::vector<uint8_t> encode(const OpackValue& value);
    static bool decode(const uint8_t* data, size_t length, OpackValue& out_value);

private:
    static void encode_inner(const OpackValue& value, std::vector<uint8_t>& buf);
    static bool decode_inner(const uint8_t* data, size_t length, size_t& offset, OpackValue& out_value);
};

} // namespace rppairing

#endif // RPPAIRING_OPACK_H
