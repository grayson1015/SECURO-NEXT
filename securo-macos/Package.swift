// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "SecuroMac",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "SecuroMac", targets: ["SecuroMac"])
    ],
    targets: [
        .executableTarget(
            name: "SecuroMac",
            path: "Sources/SecuroMac"
        ),
        .testTarget(
            name: "SecuroMacTests",
            dependencies: ["SecuroMac"],
            path: "Tests/SecuroMacTests"
        )
    ]
)
