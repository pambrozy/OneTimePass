//
//  OTPError.swift
//  OneTimePass
//
//  Created by Przemysław Ambroży on 22.06.2022.
//  Copyright © 2022 Przemysław Ambroży
//

/// An error that may occur when using the HOTP or TOTP generators.
public enum OTPError: Error, Hashable, Sendable {
    /// Could not create a one-time password code.
    case creatingOTP
    /// The provided number of digits is incorrect.
    /// The number of digits has to be between 1 and 10.
    case wrongNumberOfDigits
    /// The provided period is incorrect.
    /// The period has to be greater than zero.
    case zeroPeriod
    /// The type of generator in the URL string is invalid.
    case invalidType
    /// The provided URL string does not have the `counter` query item.
    case counterMissing
    /// Could not create `URLComponents` from the provided URL string.
    case creatingURLComponents
    /// The scheme in the URL string is invalid. The sheme has to be `otpauth`.
    case invalidScheme
    /// The provided URL string does not have the `secret` query item.
    case secretMissing
    /// Could not decode the secret from Base-32 to bytes.
    case decodingSecret
}
