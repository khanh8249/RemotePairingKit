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
    dependencies: [
        .package(url: "https://github.com/krzyzanowskim/OpenSSL.git", from: "3.6.2000")
    ],
    targets: [
        .target(
            name: "RPPairing",
            dependencies: [
                .product(name: "OpenSSL", package: "OpenSSL")
            ],
            path: ".",
            exclude: [
                "CMakeLists.txt",
                "justfile",
                "tools",
                "README.md"
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
