// swift-tools-version: 6.0

//
//  Package.swift
//  OneTimePass
//
//  Created by Przemysław Ambroży on 22.06.2022.
//  Copyright © 2022 Przemysław Ambroży
//

import PackageDescription

let package = Package(
    name: "OneTimePass",
    platforms: [
        .iOS(.v13),
        .tvOS(.v13),
        .watchOS(.v6),
        .macOS(.v10_15),
        .macCatalyst(.v13)
    ],
    products: [
        .library(
            name: "OneTimePass",
            targets: ["OneTimePass"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-docc-plugin", from: "1.0.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0")
    ],
    targets: [
        .target(
            name: "OneTimePass",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto")
            ]
        ),
        .testTarget(
            name: "OneTimePassTests",
            dependencies: ["OneTimePass"]
        )
    ]
)
