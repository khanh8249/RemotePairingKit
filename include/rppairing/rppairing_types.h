//
//  rppairing_types.h
//  librppairing
//
//  Created by Magesh K on 23/08/26.
//  Copyright © 2026 Magesh K. All rights reserved.
//

#ifndef RPPAIRING_TYPES_H
#define RPPAIRING_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    RPPAIRING_E_SUCCESS             =  0,
    RPPAIRING_E_INVALID_ARG         = -1,
    RPPAIRING_E_CONN_FAILED         = -2,
    RPPAIRING_E_VERIFY_FAILED       = -3,
    RPPAIRING_E_SETUP_FAILED        = -4,
    RPPAIRING_E_SSL_ERROR           = -5,
    RPPAIRING_E_TUNNEL_FAILED       = -6,
    RPPAIRING_E_TIMEOUT             = -7,
    RPPAIRING_E_UNKNOWN_ERROR       = -8,
    RPPAIRING_E_MALFORMED_TLV       = -9,
    RPPAIRING_E_USER_REJECTED       = -10,
    RPPAIRING_E_PIN_REQUIRED        = -11,
    RPPAIRING_E_CRYPTO_ERROR        = -12,
    RPPAIRING_E_NOT_FOUND           = -13
} rppairing_error_t;

typedef enum {
    RPPAIRING_TLV_METHOD            = 0x00,
    RPPAIRING_TLV_IDENTIFIER        = 0x01,
    RPPAIRING_TLV_SALT              = 0x02,
    RPPAIRING_TLV_PUBLIC_KEY        = 0x03,
    RPPAIRING_TLV_PROOF             = 0x04,
    RPPAIRING_TLV_ENCRYPTED_DATA    = 0x05,
    RPPAIRING_TLV_STATE             = 0x06,
    RPPAIRING_TLV_ERROR_RESPONSE    = 0x07,
    RPPAIRING_TLV_RETRY_DELAY       = 0x08,
    RPPAIRING_TLV_CERTIFICATE       = 0x09,
    RPPAIRING_TLV_SIGNATURE         = 0x0a,
    RPPAIRING_TLV_PERMISSIONS       = 0x0b,
    RPPAIRING_TLV_FRAGMENT_DATA     = 0x0c,
    RPPAIRING_TLV_FRAGMENT_LAST     = 0x0d,
    RPPAIRING_TLV_SESSION_ID        = 0x0e,
    RPPAIRING_TLV_TTL               = 0x0f,
    RPPAIRING_TLV_EXTRA_DATA        = 0x10,
    RPPAIRING_TLV_INFO              = 0x11,
    RPPAIRING_TLV_ACL               = 0x12,
    RPPAIRING_TLV_FLAGS             = 0x13,
    RPPAIRING_TLV_VALIDATION_DATA   = 0x14,
    RPPAIRING_TLV_MFI_AUTH_TOKEN    = 0x15,
    RPPAIRING_TLV_MFI_PRODUCT_TYPE  = 0x16,
    RPPAIRING_TLV_SERIAL_NUMBER     = 0x17,
    RPPAIRING_TLV_MFI_TOKEN_UUID    = 0x18,
    RPPAIRING_TLV_APP_FLAGS         = 0x19,
    RPPAIRING_TLV_OWNERSHIP_PROOF   = 0x1a,
    RPPAIRING_TLV_SETUP_CODE_TYPE   = 0x1b,
    RPPAIRING_TLV_PRODUCTION_DATA   = 0x1c,
    RPPAIRING_TLV_APP_INFO          = 0x1d,
    RPPAIRING_TLV_SEPARATOR         = 0xff
} rppairing_tlv_type_t;

typedef struct {
    uint8_t type;
    size_t length;
    uint8_t *data;
} rppairing_tlv_entry_t;

typedef struct {
    char client_address[64];
    char client_netmask[64];
    char server_address[64];
    uint16_t server_rsd_port;
    uint32_t mtu;
} rppairing_tunnel_info_t;

typedef struct {
    uint8_t public_key[32];
    uint8_t private_key[32];
    char identifier[64];
} rppairing_identity_t;

#ifdef __cplusplus
}
#endif

#endif // RPPAIRING_TYPES_H
