//
//  TOTPTests.swift
//  OneTimePass
//
//  Created by Przemek Ambroży on 29.06.2022.
//  Copyright © 2022 Przemysław Ambroży
//

import Foundation
import OneTimePass
import Testing

@Suite
struct TOTPTests {
    struct TestCode {
        let timestamp: Double
        let code: String
        let validFrom: Double
        let validTo: Double
        let mode: HashAlgorithm
        let secret: [UInt8]
    }
    private static let secretSHA1: [UInt8] = [
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        0x37, 0x38, 0x39, 0x30
    ]
    private static let secretSHA256: [UInt8] = [
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
        0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32
    ]
    private static let secretSHA512: [UInt8] = [
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
        0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32,
        0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34
    ]

    private static let validURL =
    "otpauth://totp/Example:user@example.com?issuer=Example&secret=IE&algorithm=SHA512&digits=10&period=60"

    @Test
    func initWithData() throws {
        #expect(throws: OTPError.wrongNumberOfDigits) {
            try TOTP(secret: Self.secretSHA1, digits: 0)
        }
        #expect(throws: OTPError.wrongNumberOfDigits) {
            try TOTP(secret: Self.secretSHA1, digits: 11)
        }
        #expect(throws: OTPError.zeroPeriod) {
            try TOTP(secret: Self.secretSHA1, digits: 6, period: 0)
        }
        _ = try TOTP(secret: Self.secretSHA1, digits: 6)
        _ = try TOTP(secret: Self.secretSHA1, digits: 6, period: 10)
    }

    @Test
    func initWithURL() throws {
        #expect(throws: OTPError.invalidType) {
            try TOTP(urlString: "otpauth://hotp/?secret=JBSWY3DPEHPK3PXP")
        }
        #expect(throws: OTPError.wrongNumberOfDigits) {
            try TOTP(urlString: "otpauth://totp/?secret=JBSWY3DPEHPK3PXP&digits=0")
        }
        _ = try TOTP(urlString: "otpauth://totp/?secret=JBSWY3DPEHPK3PXP&digits=8")
        _ = try TOTP(urlString: "otpauth://totp/?secret=JBSWY3DPEHPK3PXP")

        #expect(throws: OTPError.zeroPeriod) {
            try TOTP(urlString: "otpauth://totp/?secret=JBSWY3DPEHPK3PXP&period=0")
        }
        _ = try TOTP(urlString: "otpauth://totp/?secret=JBSWY3DPEHPK3PXP&period=10")

        let urlString =
            "otpauth://totp/Example:user@example.com?issuer=Example&secret=IE&algorithm=SHA512&digits=10&period=60"
        let totp = try TOTP(urlString: urlString)
        #expect(totp.secret == [0x41])
        #expect(totp.algorithm == HashAlgorithm.SHA512)
        #expect(totp.digits == 10)
        #expect(totp.period == 60)
        #expect(totp.issuer == "Example")
        #expect(totp.account == "user@example.com")
    }

    @Test
    func urlString() throws {
        let totp = try TOTP(
            secret: [0x41],
            algorithm: .SHA512,
            digits: 7,
            period: 60,
            issuer: "iss",
            account: "user"
        )

        let expectedString = "otpauth://totp/iss:user?secret=IE&algorithm=SHA512&digits=7&period=60&issuer=iss"

        #expect(totp.urlString == expectedString)
    }

    @Test(arguments: Self.expectedCodes)
    func codes(testCode: TestCode) throws {
        let totp = try TOTP(secret: testCode.secret, algorithm: testCode.mode, digits: 8)
        let code = try totp.generateCode(date: Date(timeIntervalSince1970: testCode.timestamp))
        #expect(code.code == testCode.code)
        #expect(code.validFrom == Date(timeIntervalSince1970: testCode.validFrom))
        #expect(code.validTo == Date(timeIntervalSince1970: testCode.validTo))
    }

    @Test
    func codeNow() throws {
        var totp = try TOTP(secret: Self.secretSHA1, algorithm: .SHA1, digits: 8, period: 30)
        totp.currentDateProvider = { Date(timeIntervalSince1970: 59) }

        let code = try totp.generateCode()
        #expect(try totp.generateCode().code == "94287082")
        #expect(code.validFrom == Date(timeIntervalSince1970: 30))
        #expect(code.validTo == Date(timeIntervalSince1970: 60))
    }

    @Test
    func codeStream() async throws {
        var totp = try TOTP(secret: Self.secretSHA1, algorithm: .SHA1, digits: 8, period: 5)
        let dateProvider = Reference(Date(timeIntervalSince1970: 1.0))
        totp.currentDateProvider = { dateProvider.value }
        let initialCode = try totp.generateCode()
        #expect(initialCode.code == "84755224")
        #expect(initialCode.validFrom == Date(timeIntervalSince1970: 0.0))
        #expect(initialCode.validTo == Date(timeIntervalSince1970: 5.0))

        let asyncIterator = totp.codes.makeAsyncIterator()

        dateProvider.value = Date(timeIntervalSince1970: 5.0)
        var code = try await asyncIterator.next()
        #expect(code?.code == "94287082")
        #expect(code?.validFrom == Date(timeIntervalSince1970: 5.0))
        #expect(code?.validTo == Date(timeIntervalSince1970: 10.0))

        dateProvider.value = Date(timeIntervalSince1970: 10.1)
        code = try await asyncIterator.next()
        #expect(code?.code == "37359152")
        #expect(code?.validFrom == Date(timeIntervalSince1970: 10.0))
        #expect(code?.validTo == Date(timeIntervalSince1970: 15.0))
    }

    @Test
    func validate() throws {
        var totp = try TOTP(secret: Self.secretSHA1, algorithm: .SHA1, digits: 8, period: 30)
        totp.currentDateProvider = { Date(timeIntervalSince1970: 1 + (3 * 30)) }

        #expect(try totp.validate("123456", acceptPreviousCodes: 0, acceptNextCodes: 0) == false)
        #expect(try totp.validate("123456aa", acceptPreviousCodes: 0, acceptNextCodes: 0) == false)
        #expect(try totp.validate("26969429", acceptPreviousCodes: 0, acceptNextCodes: 0) == true)

        // 1 + (0 * 30): 84755224 INVALID
        // 1 + (1 * 30): 94287082 VALID    \
        // 1 + (2 * 30): 37359152 VALID    |   2 previous
        // 1 + (3 * 30): 26969429 VALID    |<- now
        // 1 + (4 * 30): 40338314 VALID    /   1 next
        // 1 + (5 * 30): 68254676 INVALID

        #expect(try totp.validate("84755224", acceptPreviousCodes: 2, acceptNextCodes: 1) == false)
        #expect(try totp.validate("94287082", acceptPreviousCodes: 2, acceptNextCodes: 1) == true)
        #expect(try totp.validate("37359152", acceptPreviousCodes: 2, acceptNextCodes: 1) == true)
        #expect(try totp.validate("26969429", acceptPreviousCodes: 2, acceptNextCodes: 1) == true)
        #expect(try totp.validate("40338314", acceptPreviousCodes: 2, acceptNextCodes: 1) == true)
        #expect(try totp.validate("68254676", acceptPreviousCodes: 2, acceptNextCodes: 1) == false)
    }

    @Test
    func hashable() throws {
        let totp1 = try TOTP(
            urlString: "otpauth://totp/iss:user?issuer=Example&secret=IE&algorithm=SHA512&digits=10&period=60"
        )
        let totp2 = try TOTP(
            secret: [0x41],
            algorithm: .SHA512,
            digits: 10,
            period: 60,
            issuer: "iss",
            account: "user"
        )
        #expect(totp1 == totp2)
        _ = totp1.hashValue
    }
}

// MARK: - Test codes

extension TOTPTests {
    private static let expectedCodes = [
        TestCode(
            timestamp: 59.0,
            code: "94287082",
            validFrom: 30.0,
            validTo: 60.0,
            mode: .SHA1,
            secret: secretSHA1
        ),
        TestCode(
            timestamp: 59.0,
            code: "46119246",
            validFrom: 30.0,
            validTo: 60.0,
            mode: .SHA256,
            secret: secretSHA256
        ),
        TestCode(
            timestamp: 59.0,
            code: "90693936",
            validFrom: 30.0,
            validTo: 60.0,
            mode: .SHA512,
            secret: secretSHA512
        ),
        TestCode(
            timestamp: 1111111109.0,
            code: "07081804",
            validFrom: 1111111080.0,
            validTo: 1111111110.0,
            mode: .SHA1,
            secret: secretSHA1
        ),
        TestCode(
            timestamp: 1111111109.0,
            code: "68084774",
            validFrom: 1111111080.0,
            validTo: 1111111110.0,
            mode: .SHA256,
            secret: secretSHA256
        ),
        TestCode(
            timestamp: 1111111109.0,
            code: "25091201",
            validFrom: 1111111080.0,
            validTo: 1111111110.0,
            mode: .SHA512,
            secret: secretSHA512
        ),
        TestCode(
            timestamp: 1111111111.0,
            code: "14050471",
            validFrom: 1111111110.0,
            validTo: 1111111140.0,
            mode: .SHA1,
            secret: secretSHA1
        ),
        TestCode(
            timestamp: 1111111111.0,
            code: "67062674",
            validFrom: 1111111110.0,
            validTo: 1111111140.0,
            mode: .SHA256,
            secret: secretSHA256
        ),
        TestCode(
            timestamp: 1111111111.0,
            code: "99943326",
            validFrom: 1111111110.0,
            validTo: 1111111140.0,
            mode: .SHA512,
            secret: secretSHA512
        ),
        TestCode(
            timestamp: 1234567890.0,
            code: "89005924",
            validFrom: 1234567890.0,
            validTo: 1234567920.0,
            mode: .SHA1,
            secret: secretSHA1
        ),
        TestCode(
            timestamp: 1234567890.0,
            code: "91819424",
            validFrom: 1234567890.0,
            validTo: 1234567920.0,
            mode: .SHA256,
            secret: secretSHA256
        ),
        TestCode(
            timestamp: 1234567890.0,
            code: "93441116",
            validFrom: 1234567890.0,
            validTo: 1234567920.0,
            mode: .SHA512,
            secret: secretSHA512
        ),
        TestCode(
            timestamp: 2000000000.0,
            code: "69279037",
            validFrom: 1999999980.0,
            validTo: 2000000010.0,
            mode: .SHA1,
            secret: secretSHA1
        ),
        TestCode(
            timestamp: 2000000000.0,
            code: "90698825",
            validFrom: 1999999980.0,
            validTo: 2000000010.0,
            mode: .SHA256,
            secret: secretSHA256
        ),
        TestCode(
            timestamp: 2000000000.0,
            code: "38618901",
            validFrom: 1999999980.0,
            validTo: 2000000010.0,
            mode: .SHA512,
            secret: secretSHA512
        ),
        TestCode(
            timestamp: 20000000000.0,
            code: "65353130",
            validFrom: 19999999980.0,
            validTo: 20000000010.0,
            mode: .SHA1,
            secret: secretSHA1
        ),
        TestCode(
            timestamp: 20000000000.0,
            code: "77737706",
            validFrom: 19999999980.0,
            validTo: 20000000010.0,
            mode: .SHA256,
            secret: secretSHA256
        ),
        TestCode(
            timestamp: 20000000000.0,
            code: "47863826",
            validFrom: 19999999980.0,
            validTo: 20000000010.0,
            mode: .SHA512,
            secret: secretSHA512
        )
    ]
}
