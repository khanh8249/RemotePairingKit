//
//  rppairing_file.h
//  librppairing
//
//  Created by Magesh K on 23/08/26.
//  Copyright © 2026 Magesh K. All rights reserved.
//

#ifndef RPPAIRING_FILE_H
#define RPPAIRING_FILE_H

#include "rppairing_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// Generates a fresh random Ed25519 identity and derives UUIDv3 identifier
rppairing_error_t rppairing_identity_generate(const char *hostname, rppairing_identity_t *identity);

// Parses an Apple XML/Binary plist pairing file into an identity
rppairing_error_t rppairing_identity_from_plist(const char *plist_xml, size_t len, rppairing_identity_t *identity);

// Serializes identity into standard Apple XML plist pairing file string
rppairing_error_t rppairing_identity_to_plist(const rppairing_identity_t *identity, char **plist_xml, size_t *out_len);

// Free XML buffer allocated by rppairing_identity_to_plist
void rppairing_plist_free(char *plist_xml);

#ifdef __cplusplus
}
#endif

#endif // RPPAIRING_FILE_H
