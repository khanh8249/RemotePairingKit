//
//  rppairing_cli.cpp
//  librppairing
//
//  Created by Magesh K on 23/08/26.
//  Copyright © 2026 Magesh K. All rights reserved.
//

#include "rppairing/rppairing.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cout << "Usage: rppairing-cli <device_ip> <port> [pairing_file.plist]\n";
        return 1;
    }

    const char* ip = argv[1];
    uint16_t port = static_cast<uint16_t>(std::atoi(argv[2]));
    const char* plist_path = (argc >= 4) ? argv[3] : "pairing.plist";

    rppairing_set_debug_level(1);

    rppairing_identity_t identity;
    std::ifstream file(plist_path);
    if (file.is_open()) {
        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string xml = buffer.str();
        if (rppairing_identity_from_plist(xml.c_str(), xml.size(), &identity) == RPPAIRING_E_SUCCESS) {
            std::cout << "Loaded pairing file: " << identity.identifier << std::endl;
        } else {
            std::cout << "Failed parsing pairing file, generating new identity...\n";
            rppairing_identity_generate("RPPairing-CLI", &identity);
        }
    } else {
        std::cout << "No pairing file found, generating new identity...\n";
        rppairing_identity_generate("RPPairing-CLI", &identity);
    }

    rppairing_client_t client = NULL;
    rppairing_error_t err = rppairing_client_new(ip, port, "RPPairing-CLI", &client);
    if (err != RPPAIRING_E_SUCCESS) {
        std::cerr << "Failed connecting to " << ip << ":" << port << " (code " << err << ")\n";
        return 1;
    }

    err = rppairing_connect(client, &identity, NULL, NULL);
    if (err != RPPAIRING_E_SUCCESS) {
        std::cerr << "Pairing failed with code " << err << "\n";
        rppairing_client_free(client);
        return 1;
    }

    // Save updated pairing file
    char* xml_out = NULL;
    size_t xml_len = 0;
    if (rppairing_identity_to_plist(&identity, &xml_out, &xml_len) == RPPAIRING_E_SUCCESS) {
        std::ofstream out_file(plist_path);
        out_file.write(xml_out, xml_len);
        rppairing_plist_free(xml_out);
        std::cout << "Saved updated pairing file to " << plist_path << "\n";
    }

    uint16_t tunnel_port = 0;
    err = rppairing_create_tunnel_listener(client, &tunnel_port);
    if (err != RPPAIRING_E_SUCCESS) {
        std::cerr << "Failed creating tunnel listener: " << err << "\n";
        rppairing_client_free(client);
        return 1;
    }

    std::cout << "Tunnel listener ready on device port: " << tunnel_port << "\n";

    uint8_t psk[64];
    size_t psk_len = sizeof(psk);
    rppairing_get_encryption_key(client, psk, &psk_len);

    rppairing_tunnel_info_t tunnel_info;
    rppairing_tunnel_t tunnel = NULL;
    err = rppairing_tunnel_connect(ip, tunnel_port, psk, psk_len, &tunnel_info, &tunnel);
    if (err != RPPAIRING_E_SUCCESS) {
        std::cerr << "CDTunnel connection failed: " << err << "\n";
        rppairing_client_free(client);
        return 1;
    }

    std::cout << "CDTunnel established successfully!\n"
              << "Client IPv6: " << tunnel_info.client_address << "\n"
              << "Server IPv6: " << tunnel_info.server_address << "\n"
              << "Server RSD Port: " << tunnel_info.server_rsd_port << "\n"
              << "MTU: " << tunnel_info.mtu << "\n";

    rppairing_tunnel_close(tunnel);
    rppairing_client_free(client);
    return 0;
}
