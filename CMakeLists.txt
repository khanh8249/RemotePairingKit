cmake_minimum_required(VERSION 3.15)
project(librppairing VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

set(SOURCES
    src/rppairing.cpp
    src/rppairing_crypto.cpp
    src/rppairing_tlv8.cpp
    src/rppairing_opack.cpp
    src/rppairing_transport.cpp
    src/rppairing_srp.cpp
    src/rppairing_tls_psk.cpp
    src/rppairing_cdtunnel.cpp
    src/rppairing_file.cpp
)

set(PUBLIC_HEADERS
    include/rppairing/rppairing.h
    include/rppairing/rppairing_types.h
    include/rppairing/rppairing_file.h
)

add_library(rppairing STATIC ${SOURCES} ${PUBLIC_HEADERS})

target_include_directories(rppairing
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(rppairing PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# Standalone CLI tool
add_executable(rppairing-cli tools/rppairing_cli.cpp)
target_link_libraries(rppairing-cli PRIVATE rppairing OpenSSL::SSL OpenSSL::Crypto)
target_include_directories(rppairing-cli PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
