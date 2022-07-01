//
//  HOTP.swift
//  OneTimePass
//
//  Created by Przemysław Ambroży on 22.06.2022.
//  Copyright © 2022 Przemysław Ambroży
//

import Crypto
import Foundation

/// The HMAC-based one-time password algorithm.
public struct HOTP: Hashable, Codable {
    /// The secret.
    public let secret: [UInt8]

    /// The counter counting the number of iterations.
    public var counter: Int

    /// The cryptographic hash method used.
    public let algorithm: HashAlgorithm

    /// The number of digits in a one-time password.
    public let digits: Int

    /// The provider of the service the account is associated with.
    public let issuer: String?

    /// The account name.
    public let account: String?

    /// Creates a new HOTP generator.
    /// - Parameters:
    ///   - secret: The secret.
    ///   - counter: A counter, which counts the number of iterations.
    ///   - algorithm: A cryptographic hash method to use.
    ///   - digits: The number of digits in a one-time password (between 1 and 10).
    ///   - issuer: The provider of the service the account is associated with.
    ///   - account: The account name (such as an e-mail address).
    public init<D: DataProtocol>(
        secret: D,
        counter: Int,
        algorithm: HashAlgorithm = .SHA1,
        digits: Int = 6,
        issuer: String? = nil,
        account: String? = nil
    ) throws {
        guard (1...10).contains(digits) else {
            throw OTPError.wrongNumberOfDigits
        }

        self.secret = Array(secret)
        self.counter = counter
        self.algorithm = algorithm
        self.digits = digits
        self.issuer = issuer
        self.account = account
    }

    /// Creates a new HOTP generator from an URL string.
    /// - Parameter urlString: The URL string in an appropriate format.
    ///
    /// The example the the URL string:
    /// ```
    /// otpauth://hotp/Example:user@example.com?issuer=Example&secret=IE&algorithm=SHA512&digits=10&counter=0
    /// ```
    ///
    /// The example minimal valid URL string:
    /// ```
    /// otpauth://hotp/?secret=JBSWY3DPEHPK3PXP&counter=0
    /// ```
    public init(urlString: String) throws {
        let coder = try URLCoder(urlString)

        guard coder.type == "hotp" else {
            throw OTPError.invalidType
        }
        guard let counter = coder.counter else {
            throw OTPError.counterMissing
        }

        if let digits = coder.digits {
            guard (1...10).contains(digits) else {
                throw OTPError.wrongNumberOfDigits
            }
            self.digits = digits
        } else {
            digits = 6
        }

        self.secret = Array(coder.secret)
        self.counter = counter
        self.algorithm = coder.algorithm ?? .SHA1
        self.issuer = coder.issuer
        self.account = coder.account
    }

    /// Returns an URL string containing the parameters of the generator.
    public var urlString: String {
        URLCoder(
            type: "hotp",
            issuer: issuer,
            account: account,
            secret: secret,
            algorithm: algorithm,
            digits: digits,
            counter: counter,
            period: nil
        ).urlString
    }

    /// Generates a code for a given counter value.
    /// - Parameter counter: The counter value to generate the code for.
    /// - Returns: The generated one-time password code.
    public func generateCode(counter: Int) throws -> String {
        let data = withUnsafeBytes(of: Int64(counter).bigEndian, Array.init)
        let bytes = algorithm.authenticationCode(for: data, using: SymmetricKey(data: Array(secret)))

        guard let lastByte = bytes.last else {
            throw OTPError.creatingOTP
        }

        let offset = Int(lastByte & 0xF)

        guard bytes.count > offset + 3 else {
            throw OTPError.creatingOTP
        }

        let intCode =
            (UInt64(bytes[offset])  & 0x7F) << 24
            | (UInt64(bytes[offset + 1]) & 0xFF) << 16
            | (UInt64(bytes[offset + 2]) & 0xFF) <<  8
            | (UInt64(bytes[offset + 3]) & 0xFF)

        let code = String(String(intCode).suffix(digits))

        let leadingZeros = String(repeating: "0", count: max(digits - code.count, 0))

        return leadingZeros + code
    }

    /// Generates a code for the current counter value and increments the counter.
    /// - Returns: The generated one-time password code.
    public mutating func generateCode() throws -> String {
        let result = try generateCode(counter: counter)
        counter += 1
        return result
    }
}
