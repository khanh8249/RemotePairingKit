export MODULEMAP := '''
module rppairing [system] {
    header "rppairing.h"
    header "rppairing_types.h"
    header "rppairing_file.h"
    export *
}
'''

default: xcframework

clean:
    rm -rf build libs

xcframework: build-all
    rm -rf libs/include libs/rppairing.xcframework
    mkdir -p libs/include/rppairing
    cp include/rppairing/*.h libs/include/rppairing/
    printf '%s\n' "$MODULEMAP" > libs/include/rppairing/module.modulemap
    xcodebuild -create-xcframework \
        -library libs/iphoneos/librppairing.a -headers libs/include \
        -library libs/iphonesimulator/librppairing.a -headers libs/include \
        -library libs/macosx/librppairing.a -headers libs/include \
        -output libs/rppairing.xcframework

build-all: build-iphoneos-arm64 build-iphonesimulator-arm64 build-iphonesimulator-x86_64 build-macosx-arm64 build-macosx-x86_64
    mkdir -p libs/iphoneos libs/iphonesimulator libs/macosx
    cp build/iphoneos-arm64/librppairing.a libs/iphoneos/librppairing.a
    lipo -create build/iphonesimulator-arm64/librppairing.a build/iphonesimulator-x86_64/librppairing.a -output libs/iphonesimulator/librppairing.a
    lipo -create build/macosx-arm64/librppairing.a build/macosx-x86_64/librppairing.a -output libs/macosx/librppairing.a

build-iphoneos-arm64:
    just build-slice iphoneos arm64 "-miphoneos-version-min=14.0"

build-iphonesimulator-arm64:
    just build-slice iphonesimulator arm64 "-mios-simulator-version-min=14.0"

build-iphonesimulator-x86_64:
    just build-slice iphonesimulator x86_64 "-mios-simulator-version-min=14.0"

build-macosx-arm64:
    just build-slice macosx arm64 "-mmacosx-version-min=11.0"

build-macosx-x86_64:
    just build-slice macosx x86_64 "-mmacosx-version-min=11.0"

build-slice sdk arch min_flag:
    #!/usr/bin/env bash
    set -euo pipefail

    ROOT_DIR="$(pwd)"
    SLICE_DIR="${ROOT_DIR}/build/{{sdk}}-{{arch}}"
    mkdir -p "${SLICE_DIR}"

    SDK_PATH="$(xcrun --sdk {{sdk}} --show-sdk-path)"
    
    # Locate OpenSSL headers
    OPENSSL_INC=""
    if brew --prefix openssl@3 >/dev/null 2>&1; then
        OPENSSL_INC="-I$(brew --prefix openssl@3)/include"
    elif [[ -d "/opt/homebrew/opt/openssl@3/include" ]]; then
        OPENSSL_INC="-I/opt/homebrew/opt/openssl@3/include"
    elif [[ -d "/usr/local/opt/openssl@3/include" ]]; then
        OPENSSL_INC="-I/usr/local/opt/openssl@3/include"
    fi

    CXXFLAGS="-arch {{arch}} -isysroot ${SDK_PATH} {{min_flag}} -std=c++17 -O3 -fPIC -Iinclude -Isrc ${OPENSSL_INC}"

    echo "Compiling {{sdk}}-{{arch}}..."
    for src_file in src/*.cpp; do
        obj_file="${SLICE_DIR}/$(basename "${src_file}" .cpp).o"
        xcrun clang++ ${CXXFLAGS} -c "${src_file}" -o "${obj_file}"
    done

    echo "Archiving librppairing.a for {{sdk}}-{{arch}}..."
    libtool -static -o "${SLICE_DIR}/librppairing.a" "${SLICE_DIR}"/*.o
