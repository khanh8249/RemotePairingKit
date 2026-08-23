# RemotePairingKit

A high-performance, native C/C++ library implementing Apple's **Remote Pairing (RPPairing)** and **CDTunnel** protocols for **iOS 17+, macOS, tvOS, and visionOS** devices.

---

## Background

Starting with **iOS 17**, Apple introduced a new pairing and tunneling architecture called **RPPairing (Remote Pairing)**. RPPairing replaces older `lockdownd`-based pairing for trusted modern services (such as DeveloperDiskImage mounting, Remote Service Discovery, and CoreDevice app services):

- **[@jkcoxson / idevice](https://github.com/jkcoxson/idevice)**: @jkcoxson reverse-engineered and documented the foundational RPPairing protocol, SRP-3072 authentication, TLV8/OPACK structures, and CDTunnel handshake.
- **`RemotePairingKit`**: Implements a standalone, pure C++17 library utilizing standard OpenSSL 3 EVP cryptographic primitives. It provides both native C API bindings and automated multi-platform XCFramework packaging for seamless integration into Swift, Objective-C, and C projects without external language runtimes.

---

## Features

- **Zero External Runtime Dependencies**: Pure C++17 and standard C codebase.
- **OpenSSL 3 Cryptographic Suite**:
  - **X25519**: Ephemeral Diffie-Hellman key exchange via `EVP_PKEY_X25519`.
  - **Ed25519**: Identity key generation, signing, and verification via `EVP_DigestSign` / `EVP_DigestVerify`.
  - **ChaCha20-Poly1305**: AEAD authenticated encryption and decryption for control channel frames.
  - **HKDF-SHA512**: Key expansion and cipher derivation for `Pair-Verify`, `Pair-Setup`, and main streams.
  - **SRP-3072 (SHA-512)**: RFC 5054 3072-bit group SRP client with OpenSSL `BIGNUM` modular arithmetic.
- **Binary Codecs**:
  - **TLV8**: Type-Length-Value serializer, deserializer, and automatic multi-chunk buffer combiner (>255 bytes).
  - **OPACK**: Full Apple binary serialization and deserialization for device info dictionaries.
- **Encrypted CDTunnel & TLS 1.2 PSK**:
  - Establishes TLS 1.2 Pre-Shared Key tunnel sessions (`TLS_PSK_WITH_AES_256_CBC_SHA384`).
  - Executes `CDTunnel` handshakes, discovers MTU and host/device IPv6 endpoints.
  - Streams raw point-to-point IPv6 packets back to back.
- **Multi-Platform XCFramework & SPM**:
  - Native Swift Package Manager target.
  - Pre-built CMake & `justfile` recipes producing universal `rppairing.xcframework`.

---

## Platforms Supported

| Platform                          | Native C++ | Swift Package | XCFramework |
| :-------------------------------- | :--------- | :------------ | :---------- |
| **iOS (Real Device & Simulator)** | Supported  | Supported     | Supported   |
| **macOS (ARM64 & x86_64)**        | Supported  | Supported     | Supported   |
| **tvOS (Device & Simulator)**     | Supported  | Supported     | Supported   |
| **visionOS (Device & Simulator)** | Supported  | Supported     | Supported   |

---

## Directory Structure

```
RemotePairingKit/
├── .github/
│   └── workflows/
│       └── ci.yml             # GitHub Actions CI for multi-platform build & tag release
├── include/rppairing/
│   ├── rppairing.h            # Public C API
│   ├── rppairing_types.h      # Status codes, TLV types & tunnel info
│   └── rppairing_file.h       # Apple Plist pairing file management
├── src/                       # C++ Implementation
│   ├── rppairing.cpp          # State machine coordinator
│   ├── rppairing_crypto.cpp   # OpenSSL 3 EVP crypto
│   ├── rppairing_srp.cpp      # RFC 5054 Group 3072 SRP Client
│   ├── rppairing_tlv8.cpp     # TLV8 codec
│   ├── rppairing_opack.cpp    # Apple OPACK binary codec
│   ├── rppairing_transport.cpp# RPPairing JSON socket transport
│   ├── rppairing_tls_psk.cpp  # TLS 1.2 PSK client (PSK-AES256-CBC-SHA384)
│   ├── rppairing_cdtunnel.cpp # CDTunnel handshake & IPv6 packet streaming
│   └── rppairing_file.cpp     # Pairing file parser / serializer
├── tools/
│   └── rppairing_cli.cpp      # Standalone CLI test utility
├── Package.swift              # Swift Package manifest
├── CMakeLists.txt             # Cross-platform CMake build configuration
├── justfile                   # Recipes for building rppairing.xcframework
├── LICENSE                    # AGPLv3 License
└── README.md                  # Documentation & spec reference
```

---

## Public C API Reference

All public functions are declared in [`include/rppairing/rppairing.h`](include/rppairing/rppairing.h).

### Client Management

```c
// Creates a new RPPairing client connected to device_host:port
rppairing_error_t rppairing_client_new(const char *device_host, uint16_t port, const char *hostname, rppairing_client_t *client);

// Frees the client and closes socket connection
void rppairing_client_free(rppairing_client_t client);
```

### Pairing Flows

```c
// Fast-path: Validates existing pairing file with the device
rppairing_error_t rppairing_pair_verify(rppairing_client_t client, const rppairing_identity_t *identity);

// Initial pairing: Prompts user trust dialog or accepts PIN callback
rppairing_error_t rppairing_pair_setup(
    rppairing_client_t client,
    rppairing_identity_t *identity,
    rppairing_pin_callback_t pin_callback,
    void *user_data
);

// High-level helper: Attempts pair-verify, automatically falls back to pair-setup
rppairing_error_t rppairing_connect(
    rppairing_client_t client,
    rppairing_identity_t *identity,
    rppairing_pin_callback_t pin_callback,
    void *user_data
);
```

### CDTunnel & IPv6 Packet I/O

```c
// Requests device to open an encrypted TCP tunnel listener
rppairing_error_t rppairing_create_tunnel_listener(rppairing_client_t client, uint16_t *tunnel_port);

// Connects to tunnel listener and negotiates CDTunnel parameters
rppairing_error_t rppairing_tunnel_connect(
    const char *device_host,
    uint16_t tunnel_port,
    const uint8_t *encryption_key,
    size_t key_len,
    rppairing_tunnel_info_t *tunnel_info,
    rppairing_tunnel_t *tunnel
);

// Sends and receives raw IPv6 packets across the encrypted tunnel
rppairing_error_t rppairing_tunnel_send_packet(rppairing_tunnel_t tunnel, const uint8_t *packet, size_t len);
rppairing_error_t rppairing_tunnel_recv_packet(rppairing_tunnel_t tunnel, uint8_t *buf, size_t buf_len, size_t *received_len, int timeout_ms);
void rppairing_tunnel_close(rppairing_tunnel_t tunnel);
```

---

## Standalone CLI Utility

A command-line tool `rppairing-cli` is included in [`tools/rppairing_cli.cpp`](tools/rppairing_cli.cpp):

```bash
# Build with CMake
cmake -B build -S .
cmake --build build

# Pair and establish CDTunnel to device
./build/rppairing-cli 10.7.0.1 49152 my_device_pair.plist
```

---

## Attribution & Acknowledgements

- **[@jkcoxson](https://github.com/jkcoxson)**: For the reverse-engineering and authoring the [RPPairing Protocol Specification](https://jkcoxson.com/blog/rppairing-spec) and CDTunnel research.

---

## Disclaimer

This project is provided for **educational and research purposes only**.

- `RemotePairingKit` is an independent project and is not affiliated with, sponsored by, or endorsed by Apple Inc.
- Use of this software is entirely at your own risk. The author and contributors assume no responsibility or liability for any damages or legal repercussions arising from the use of this code.

---

## License & Terms

`RemotePairingKit` is licensed under the **GNU Affero General Public License v3.0 (AGPLv3)**. See [`LICENSE`](LICENSE) for complete details.
