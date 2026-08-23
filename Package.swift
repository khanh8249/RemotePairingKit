// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "RemotePairingKit",
    platforms: [
        .iOS(.v14),
        .macOS(.v11)
    ],
    products: [
        .library(
            name: "RPPairing",
            targets: ["RPPairing"]
        )
    ],
    dependencies: [],
    targets: [
        .target(
            name: "RPPairing",
            dependencies: [],
            path: ".",
            exclude: [
                "CMakeLists.txt",
                "justfile",
                "tools",
                "README.md",
                "LICENSE"
            ],
            sources: [
                "src"
            ],
            publicHeadersPath: "include",
            cxxSettings: [
                .headerSearchPath("src"),
                .headerSearchPath("include")
            ],
            linkerSettings: [
                .linkedFramework("OpenSSL")
            ]
        )
    ],
    cxxLanguageStandard: .cxx17
)
