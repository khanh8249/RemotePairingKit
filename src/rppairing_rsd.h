//
//  rppairing_rsd.h
//  librppairing
//
//  Created by Magesh K on 23/08/26.
//  Copyright © 2026 Magesh K. All rights reserved.
//

#ifndef RPPAIRING_RSD_H
#define RPPAIRING_RSD_H

#include "rppairing/rppairing_types.h"
#include "rppairing_cdtunnel.h"
#include "rppairing_tcp.h"
#include <stdint.h>
#include <map>
#include <string>

namespace rppairing {

struct RsdService {
    std::string name;
    uint16_t port;
    std::string entitlement;
    bool uses_remote_xpc;
};

class RsdClient {
public:
    RsdClient(CdTunnel& tunnel);
    ~RsdClient();

    rppairing_error_t connect(const std::string& server_ip6, uint16_t rsd_port, int timeout_ms = 10000);
    uint16_t get_service_port(const std::string& service_name) const;
    const std::map<std::string, RsdService>& services() const { return services_; }

private:
    CdTunnel& tunnel_;
    VirtualTcpStream tcp_;
    std::map<std::string, RsdService> services_;

    rppairing_error_t perform_handshake(int timeout_ms);
    void parse_services_plist(const std::string& plist_xml);
};

} // namespace rppairing

#endif // RPPAIRING_RSD_H
