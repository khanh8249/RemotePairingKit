//
//  rppairing.h
//  librppairing
//
//  Created by Magesh K on 23/08/26.
//  Copyright © 2026 Magesh K. All rights reserved.
//

#ifndef RPPAIRING_H
#define RPPAIRING_H

#include "rppairing_types.h"
#include "rppairing_file.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rppairing_client_s* rppairing_client_t;
typedef struct rppairing_tunnel_s* rppairing_tunnel_t;

// Callback type to request PIN from user when pairing with Apple TV / Vision Pro / prompt
typedef const char* (*rppairing_pin_callback_t)(void *user_data);

// Client Lifecycle
rppairing_error_t rppairing_client_new(const char *device_host, uint16_t port, const char *hostname, rppairing_client_t *client);
void rppairing_client_free(rppairing_client_t client);

// Enable/disable debug logging
void rppairing_set_debug_level(int level);

// Pair-Verify (Fast-path for previously paired devices)
rppairing_error_t rppairing_pair_verify(rppairing_client_t client, const rppairing_identity_t *identity);

// Pair-Setup (Initial pairing with PIN or Trust dialog)
rppairing_error_t rppairing_pair_setup(
    rppairing_client_t client,
    rppairing_identity_t *identity,
    rppairing_pin_callback_t pin_callback,
    void *user_data
);

// High-level connect helper: Tries pair-verify; falls back to pair-setup if not verified
rppairing_error_t rppairing_connect(
    rppairing_client_t client,
    rppairing_identity_t *identity,
    rppairing_pin_callback_t pin_callback,
    void *user_data
);

// Exports the established shared encryption key (used as TLS-PSK)
rppairing_error_t rppairing_get_encryption_key(rppairing_client_t client, uint8_t *key_buf, size_t *key_len);

// Tunnel Listener Creation & CDTunnel
rppairing_error_t rppairing_create_tunnel_listener(rppairing_client_t client, uint16_t *tunnel_port);

// Connect to the TLS 1.2 PSK tunnel and perform CDTunnel handshake
rppairing_error_t rppairing_tunnel_connect(
    const char *device_host,
    uint16_t tunnel_port,
    const uint8_t *encryption_key,
    size_t key_len,
    rppairing_tunnel_info_t *tunnel_info,
    rppairing_tunnel_t *tunnel
);

// Send/Receive raw IPv6 packets over CDTunnel
rppairing_error_t rppairing_tunnel_send_packet(rppairing_tunnel_t tunnel, const uint8_t *packet, size_t len);
rppairing_error_t rppairing_tunnel_recv_packet(rppairing_tunnel_t tunnel, uint8_t *buf, size_t buf_len, size_t *received_len, int timeout_ms);
bool rppairing_tunnel_is_open(rppairing_tunnel_t tunnel);
void rppairing_tunnel_close(rppairing_tunnel_t tunnel);

// RSD Client
typedef struct rppairing_rsd_s* rppairing_rsd_t;
rppairing_error_t rppairing_rsd_connect(rppairing_tunnel_t tunnel, rppairing_rsd_t *rsd);
rppairing_error_t rppairing_rsd_get_service_port(rppairing_rsd_t rsd, const char *service_name, uint16_t *port);
void rppairing_rsd_free(rppairing_rsd_t rsd);

// Generic Service Stream over CDTunnel
typedef struct rppairing_service_stream_s* rppairing_service_stream_t;

rppairing_error_t rppairing_connect_service_stream(
    rppairing_tunnel_t tunnel,
    uint16_t service_port,
    rppairing_service_stream_t *stream
);

rppairing_error_t rppairing_service_stream_send_plist(
    rppairing_service_stream_t stream,
    const char *plist_xml,
    size_t xml_len
);

rppairing_error_t rppairing_service_stream_recv_plist(
    rppairing_service_stream_t stream,
    char **out_plist_xml,
    size_t *out_xml_len,
    int timeout_ms
);

rppairing_error_t rppairing_service_stream_send_raw(
    rppairing_service_stream_t stream,
    const uint8_t *data,
    size_t len
);

rppairing_error_t rppairing_service_stream_recv_exact(
    rppairing_service_stream_t stream,
    uint8_t *buf,
    size_t len,
    int timeout_ms
);

void rppairing_service_stream_close(rppairing_service_stream_t stream);

#ifdef __cplusplus
}
#endif

#endif // RPPAIRING_H
