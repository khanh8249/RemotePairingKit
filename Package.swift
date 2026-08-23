// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "RPPairing",
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
        .binaryTarget(
            name: "OpenSSL",
            url: "https://github.com/krzyzanowskim/OpenSSL/releases/download/3.6.2000/OpenSSL.xcframework.zip",
            checksum: "37846a8bd302cb2443eff47f1045ab844d0cd40bf82cc6159cfad9aa5c3eff9e"
        ),
        .target(
            name: "RPPairing",
            dependencies: [
                "OpenSSL"
            ],
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
            ]
        )
    ],
    cxxLanguageStandard: .cxx17
)
