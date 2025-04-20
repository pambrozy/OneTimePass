//
//  HOTPTests.swift
//  OneTimePass
//
//  Created by Przemek Ambroży on 29.06.2022.
//  Copyright © 2022 Przemysław Ambroży
//

import OneTimePass
import Testing

@Suite
struct HOTPTests {
    private static let secret: [UInt8] = [
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        0x37, 0x38, 0x39, 0x30
    ]

    private static let expectedCodes = [
        (0, "1284755224"),
        (1, "1094287082"),
        (2, "0137359152"),
        (3, "1726969429"),
        (4, "1640338314"),
        (5, "0868254676"),
        (6, "1918287922"),
        (7, "0082162583"),
        (8, "0673399871"),
        (9, "0645520489")
    ]

    @Test
    func initWithData() throws {
        #expect(throws: OTPError.wrongNumberOfDigits) {
            try HOTP(secret: Self.secret, counter: 0, digits: 0)
        }
        #expect(throws: OTPError.wrongNumberOfDigits) {
            try HOTP(secret: Self.secret, counter: 0, digits: 11)
        }
        _ = try HOTP(secret: Self.secret, counter: 0, digits: 1)
        _ = try HOTP(secret: Self.secret, counter: 0, digits: 10)
    }

    @Test
    func initWithURL() throws {
        #expect(throws: OTPError.invalidType) {
            try HOTP(urlString: "otpauth://totp/?secret=JBSWY3DPEHPK3PXP&counter=0")
        }
        #expect(throws: OTPError.counterMissing) {
            try HOTP(urlString: "otpauth://hotp/?secret=JBSWY3DPEHPK3PXP")
        }
        #expect(throws: OTPError.wrongNumberOfDigits) {
            try HOTP(urlString: "otpauth://hotp/?secret=JBSWY3DPEHPK3PXP&counter=0&digits=11")
        }

        _ = try HOTP(urlString: "otpauth://hotp/?secret=JBSWY3DPEHPK3PXP&counter=0")

        let urlString =
            "otpauth://hotp/Example:user@example.com?issuer=Example&secret=IE&algorithm=SHA512&digits=7&counter=123"
        let hotp = try HOTP(urlString: urlString)
        #expect(hotp.secret == [0x41])
        #expect(hotp.counter == 123)
        #expect(hotp.algorithm == HashAlgorithm.SHA512)
        #expect(hotp.digits == 7)
        #expect(hotp.issuer == "Example")
        #expect(hotp.account == "user@example.com")
    }

    @Test
    func urlString() throws {
        let hotp = try HOTP(
            secret: [0x41],
            counter: 123,
            algorithm: .SHA512,
            digits: 7,
            issuer: "iss",
            account: "user"
        )

        let expectedString = "otpauth://hotp/iss:user?secret=IE&algorithm=SHA512&digits=7&counter=123&issuer=iss"

        #expect(hotp.urlString == expectedString)
    }

    @Test(arguments: Self.expectedCodes)
    func codes(counter: Int, expectedCode: String) throws {
        let hotp = try HOTP(secret: Self.secret, counter: 0, digits: 10)
        let code = try hotp.generateCode(counter: counter)
        #expect(code == expectedCode)
    }

    @Test
    func autoIncrement() throws {
        var hotp = try HOTP(secret: Self.secret, counter: 0, digits: 10)

        for (_, expectedCode) in Self.expectedCodes {
            let code = try hotp.generateCode()
            #expect(code == expectedCode)
        }
    }
}
