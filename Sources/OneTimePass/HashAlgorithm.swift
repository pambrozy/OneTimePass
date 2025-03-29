//
//  HashAlgorithm.swift
//  OneTimePass
//
//  Created by Przemysław Ambroży on 22.06.2022.
//  Copyright © 2022 Przemysław Ambroży
//

import Crypto
import Foundation

/// A cryptographic hash algorithm.
public enum HashAlgorithm: String, Codable, Sendable {
    /// The SHA-1 (Secure Hash Algorithm 1) hash.
    case SHA1
    /// The SHA-2 (Secure Hash Algorithm 2) hash with a 256-bit digest.
    case SHA256
    /// The SHA-2 (Secure Hash Algorithm 2) hash with a 512-bit digest.
    case SHA512

    func authenticationCode<D: DataProtocol>(for data: D, using key: SymmetricKey) -> [UInt8] {
        switch self {
        case .SHA1:
            Array(HMAC<Insecure.SHA1>.authenticationCode(for: data, using: key))
        case .SHA256:
            Array(HMAC<SHA256>.authenticationCode(for: data, using: key))
        case .SHA512:
            Array(HMAC<SHA512>.authenticationCode(for: data, using: key))
        }
    }
}
