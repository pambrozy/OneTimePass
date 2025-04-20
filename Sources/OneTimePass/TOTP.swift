//
//  TOTP.swift
//  OneTimePass
//
//  Created by Przemysław Ambroży on 22.06.2022.
//  Copyright © 2022 Przemysław Ambroży
//

import Crypto
import Foundation

/// The Time-based one-time password algorithm.
public struct TOTP: Sendable {
    /// The code and the dates it is valid in.
    public struct Code: Hashable, Sendable {
        /// The one-time password code.
        public let code: String

        /// The date the code is valid from.
        public let validFrom: Date

        /// The date at which a new code will be generated.
        public let validTo: Date
    }

    /// The secret.
    public let secret: [UInt8]

    /// The cryptographic hash method used.
    public let algorithm: HashAlgorithm

    /// The number of digits in a one-time password.
    public let digits: Int

    /// The number of seconds the code is valid.
    public let period: UInt

    /// The provider of the service the account is associated with.
    public let issuer: String?

    /// The account name.
    public let account: String?

    /// A block of code the generator executes to obtain the current date.
    public var currentDateProvider: @Sendable () -> Date = { Date() }

    /// Creates a new TOTP generator.
    /// - Parameters:
    ///   - secret: The secret.
    ///   - algorithm: A cryptographic hash method to use.
    ///   - digits: The number of digits in a one-time password (between 1 and 10).
    ///   - period: The number of seconds the code is valid.
    ///   - issuer: The provider of the service the account is associated with.
    ///   - account: The account name (such as an e-mail address).
    public init<D: DataProtocol>(
        secret: D,
        algorithm: HashAlgorithm = .SHA1,
        digits: Int = 6,
        period: UInt = 30,
        issuer: String? = nil,
        account: String? = nil
    ) throws {
        guard (1...10).contains(digits) else {
            throw OTPError.wrongNumberOfDigits
        }
        guard period > 0 else {
            throw OTPError.zeroPeriod
        }

        self.secret = Array(secret)
        self.algorithm = algorithm
        self.digits = digits
        self.period = period
        self.issuer = issuer
        self.account = account
    }

    /// Creates a new TOTP generator from an URL string.
    /// - Parameter urlString: The URL string in an appropriate format.
    ///
    /// The example the URL string:
    /// ```
    /// otpauth://totp/Example:user@example.com?issuer=Example&secret=IE&algorithm=SHA512&digits=10&period=60
    /// ```
    ///
    /// The example minimal valid URL string:
    /// ```
    /// otpauth://totp/?secret=JBSWY3DPEHPK3PXP
    /// ```
    public init(urlString: String) throws {
        let coder = try URLCoder(urlString)

        guard coder.type == "totp" else {
            throw OTPError.invalidType
        }

        if let digits = coder.digits {
            guard (1...10).contains(digits) else {
                throw OTPError.wrongNumberOfDigits
            }
            self.digits = digits
        } else {
            digits = 6
        }

        if let period = coder.period {
            guard period > 0 else {
                throw OTPError.zeroPeriod
            }
            self.period = period
        } else {
            period = 30
        }

        self.secret = Array(coder.secret)
        self.algorithm = coder.algorithm ?? .SHA1
        self.issuer = coder.issuer
        self.account = coder.account
    }

    /// Returns an URL string containing the parameters of the generator.
    public var urlString: String {
        URLCoder(
            type: "totp",
            issuer: issuer,
            account: account,
            secret: secret,
            algorithm: algorithm,
            digits: digits,
            counter: nil,
            period: period
        ).urlString
    }

    /// The date when the last code was generated.
    var lastGenerationDate: Date {
        let period = Double(period)
        let fireInterval = (currentDateProvider().timeIntervalSince1970 / period).rounded(.down) * period
        return Date(timeIntervalSince1970: fireInterval)
    }

    /// Generates a code for a given date.
    /// - Parameter date: The date at which the code should be valid.
    /// - Returns: The generated one-time password code.
    public func generateCode(date: Date) throws -> Code {
        let dividedTimestamp = Int64(floor(date.timeIntervalSince1970 / Double(period)))
        let data = withUnsafeBytes(of: dividedTimestamp.bigEndian, Array.init)
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

        let validFrom = Date(timeIntervalSince1970: Double(dividedTimestamp) * Double(period))
        let validTo = validFrom.addingTimeInterval(Double(period))

        return Code(
            code: leadingZeros + code,
            validFrom: validFrom,
            validTo: validTo
        )
    }

    /// Generates a code for the current date.
    /// - Returns: The generated one-time password code.
    public func generateCode() throws -> Code {
        return try generateCode(date: currentDateProvider())
    }

    /// Returns an async sequence of one-time password codes.
    ///
    /// - Note: The current code is **not** included.
    public var codes: Codes {
        Codes(totp: self)
    }

    /// Validates a given one-time password code.
    /// - Parameters:
    ///   - code: The one-time password code to validate.
    ///   - acceptPreviousCodes: The number of previous codes to consider valid.
    ///   - acceptNextCodes: The number of next codes to consider valid.
    /// - Returns: Whenther the code is valid.
    public func validate(_ code: String, acceptPreviousCodes: Int, acceptNextCodes: Int) throws -> Bool {
        guard code.count == digits,
              CharacterSet.decimalDigits.isSuperset(of: CharacterSet(charactersIn: code))
        else {
            return false
        }

        let now = currentDateProvider()

        if try generateCode(date: now).code == code {
            return true
        }

        if acceptPreviousCodes > 0 {
            for number in (1...acceptPreviousCodes) {
                let date = now.addingTimeInterval(-1.0 * Double(number * Int(period)))
                if try generateCode(date: date).code == code {
                    return true
                }
            }
        }

        if acceptNextCodes > 0 {
            for number in (1...acceptNextCodes) {
                let date = now.addingTimeInterval(Double(number * Int(period)))
                if try generateCode(date: date).code == code {
                    return true
                }
            }
        }

        return false
    }
}

extension TOTP: Hashable {
    public static func == (lhs: TOTP, rhs: TOTP) -> Bool {
        lhs.secret == rhs.secret &&
        lhs.algorithm == rhs.algorithm &&
        lhs.digits == rhs.digits &&
        lhs.period == rhs.period &&
        lhs.issuer == rhs.issuer &&
        lhs.account == rhs.account
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(secret)
        hasher.combine(algorithm)
        hasher.combine(digits)
        hasher.combine(period)
        hasher.combine(issuer)
        hasher.combine(account)
    }
}

extension TOTP: Codable {
    private enum CodingKeys: String, CodingKey {
        case secret
        case algorithm
        case digits
        case period
        case issuer
        case account
    }
}
