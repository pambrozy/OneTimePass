//
//  TOTPTests.swift
//  OneTimePass
//
//  Created by Przemek Ambroży on 29.06.2022.
//  Copyright © 2022 Przemysław Ambroży
//

import OneTimePass
import XCTest

final class TOTPTests: XCTestCase {
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

    func testInitWithData() throws {
        XCTAssertThrowsError(try TOTP(secret: Self.secretSHA1, digits: 0)) { error in
            XCTAssertEqual(error as? OTPError, OTPError.wrongNumberOfDigits)
        }
        XCTAssertThrowsError(try TOTP(secret: Self.secretSHA1, digits: 11)) { error in
            XCTAssertEqual(error as? OTPError, OTPError.wrongNumberOfDigits)
        }
        XCTAssertThrowsError(try TOTP(secret: Self.secretSHA1, digits: 6, period: 0)) { error in
            XCTAssertEqual(error as? OTPError, OTPError.zeroPeriod)
        }
        _ = try TOTP(secret: Self.secretSHA1, digits: 6)
        _ = try TOTP(secret: Self.secretSHA1, digits: 6, period: 10)
    }

    func testInitWithURL() throws {
        XCTAssertThrowsError(try TOTP(urlString: "otpauth://hotp/?secret=JBSWY3DPEHPK3PXP")) { error in
            XCTAssertEqual(error as? OTPError, OTPError.invalidType)
        }
        XCTAssertThrowsError(try TOTP(urlString: "otpauth://totp/?secret=JBSWY3DPEHPK3PXP&digits=0")) { error in
            XCTAssertEqual(error as? OTPError, OTPError.wrongNumberOfDigits)
        }
        _ = try TOTP(urlString: "otpauth://totp/?secret=JBSWY3DPEHPK3PXP&digits=8")
        _ = try TOTP(urlString: "otpauth://totp/?secret=JBSWY3DPEHPK3PXP")

        XCTAssertThrowsError(try TOTP(urlString: "otpauth://totp/?secret=JBSWY3DPEHPK3PXP&period=0")) { error in
            XCTAssertEqual(error as? OTPError, OTPError.zeroPeriod)
        }
        _ = try TOTP(urlString: "otpauth://totp/?secret=JBSWY3DPEHPK3PXP&period=10")

        let urlString =
            "otpauth://totp/Example:user@example.com?issuer=Example&secret=IE&algorithm=SHA512&digits=10&period=60"
        let totp = try TOTP(urlString: urlString)
        XCTAssertEqual(totp.secret, [0x41])
        XCTAssertEqual(totp.algorithm, HashAlgorithm.SHA512)
        XCTAssertEqual(totp.digits, 10)
        XCTAssertEqual(totp.period, 60)
        XCTAssertEqual(totp.issuer, "Example")
        XCTAssertEqual(totp.account, "user@example.com")
    }

    func testURLString() throws {
        let totp = try TOTP(
            secret: [0x41],
            algorithm: .SHA512,
            digits: 7,
            period: 60,
            issuer: "iss",
            account: "user"
        )

        let expectedString = "otpauth://totp/iss:user?secret=IE&algorithm=SHA512&digits=7&period=60&issuer=iss"

        XCTAssertEqual(totp.urlString, expectedString)
    }

    func testCodes() throws {
        for testCode in Self.expectedCodes {
            let totp = try TOTP(secret: testCode.secret, algorithm: testCode.mode, digits: 8)
            let code = try totp.generateCode(date: Date(timeIntervalSince1970: testCode.timestamp))
            XCTAssertEqual(code.code, testCode.code)
            XCTAssertEqual(code.validFrom, Date(timeIntervalSince1970: testCode.validFrom))
            XCTAssertEqual(code.validTo, Date(timeIntervalSince1970: testCode.validTo))
        }
    }

    func testCodeNow() throws {
        var totp = try TOTP(secret: Self.secretSHA1, algorithm: .SHA1, digits: 8, period: 30)
        totp.currentDateProvider = { Date(timeIntervalSince1970: 59) }

        let code = try totp.generateCode()
        XCTAssertEqual(try totp.generateCode().code, "94287082")
        XCTAssertEqual(code.validFrom, Date(timeIntervalSince1970: 30))
        XCTAssertEqual(code.validTo, Date(timeIntervalSince1970: 60))
    }

    @MainActor
    func testCodeStream() async throws {
        var totp = try TOTP(secret: Self.secretSHA1, algorithm: .SHA1, digits: 8, period: 5)
        totp.currentDateProvider = { Date(timeIntervalSince1970: 1) }
        let initialCode = try totp.generateCode()
        XCTAssertEqual(initialCode.code, "84755224")
        XCTAssertEqual(initialCode.validFrom, Date(timeIntervalSince1970: 0))
        XCTAssertEqual(initialCode.validTo, Date(timeIntervalSince1970: 5))

        var asyncIterator = totp.codes.makeAsyncIterator()

        var code = try await asyncIterator.next()
        XCTAssertEqual(code?.code, "94287082")
        XCTAssertEqual(code?.validFrom, Date(timeIntervalSince1970: 5.0))
        XCTAssertEqual(code?.validTo, Date(timeIntervalSince1970: 10.0))

        code = try await asyncIterator.next()
        XCTAssertEqual(code?.code, "37359152")
        XCTAssertEqual(code?.validFrom, Date(timeIntervalSince1970: 10.0))
        XCTAssertEqual(code?.validTo, Date(timeIntervalSince1970: 15.0))
    }

    func testValidate() throws {
        var totp = try TOTP(secret: Self.secretSHA1, algorithm: .SHA1, digits: 8, period: 30)
        totp.currentDateProvider = { Date(timeIntervalSince1970: 1 + (3 * 30)) }

        XCTAssertEqual(try totp.validate("123456", acceptPreviousCodes: 0, acceptNextCodes: 0), false)
        XCTAssertEqual(try totp.validate("123456aa", acceptPreviousCodes: 0, acceptNextCodes: 0), false)
        XCTAssertEqual(try totp.validate("26969429", acceptPreviousCodes: 0, acceptNextCodes: 0), true)

        // 1 + (0 * 30): 84755224 INVALID
        // 1 + (1 * 30): 94287082 VALID    \
        // 1 + (2 * 30): 37359152 VALID    |   2 previous
        // 1 + (3 * 30): 26969429 VALID    |<- now
        // 1 + (4 * 30): 40338314 VALID    /   1 next
        // 1 + (5 * 30): 68254676 INVALID

        XCTAssertEqual(try totp.validate("84755224", acceptPreviousCodes: 2, acceptNextCodes: 1), false)
        XCTAssertEqual(try totp.validate("94287082", acceptPreviousCodes: 2, acceptNextCodes: 1), true)
        XCTAssertEqual(try totp.validate("37359152", acceptPreviousCodes: 2, acceptNextCodes: 1), true)
        XCTAssertEqual(try totp.validate("26969429", acceptPreviousCodes: 2, acceptNextCodes: 1), true)
        XCTAssertEqual(try totp.validate("40338314", acceptPreviousCodes: 2, acceptNextCodes: 1), true)
        XCTAssertEqual(try totp.validate("68254676", acceptPreviousCodes: 2, acceptNextCodes: 1), false)
    }

    func testHashable() throws {
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
        XCTAssertEqual(totp1, totp2)
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
