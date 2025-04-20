//
//  SecretCoderTests.swift
//  OneTimePass
//
//  Created by Przemek Ambroży on 29.06.2022.
//  Copyright © 2022 Przemysław Ambroży
//

import OneTimePass
import Testing

struct SecretCoderTests {
    @Test
    func decoder() throws {
        _ = try HOTP(urlString: "otpauth://hotp/?secret=&counter=0")

        #expect(throws: OTPError.decodingSecret) {
            try HOTP(urlString: "otpauth://hotp/?secret=IF%C2%B7A&counter=0")
        }
        #expect(throws: OTPError.decodingSecret) {
            try HOTP(urlString: "otpauth://hotp/?secret=IF9A&counter=0")
        }
    }

    @Test
    func encoder() throws {
        _ = try HOTP(urlString: "otpauth://hotp/?secret=&counter=0").urlString
        _ = try HOTP(urlString: "otpauth://hotp/?secret=IFBEGRCF&counter=0").urlString
    }
}
