//
//  File.swift
//
//
//  Created by Przemek Ambroży on 29/06/2022.
//

import XCTest
import OneTimePass

final class TOTPTests: XCTestCase {
    struct TestCode {
        let timestamp: Double
        let code: String
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

    private static let expectedCodes = [
        TestCode(timestamp: 59, code: "94287082", mode: .SHA1, secret: secretSHA1),
        TestCode(timestamp: 59, code: "46119246", mode: .SHA256, secret: secretSHA256),
        TestCode(timestamp: 59, code: "90693936", mode: .SHA512, secret: secretSHA512),
        TestCode(timestamp: 1111111109, code: "07081804", mode: .SHA1, secret: secretSHA1),
        TestCode(timestamp: 1111111109, code: "68084774", mode: .SHA256, secret: secretSHA256),
        TestCode(timestamp: 1111111109, code: "25091201", mode: .SHA512, secret: secretSHA512),
        TestCode(timestamp: 1111111111, code: "14050471", mode: .SHA1, secret: secretSHA1),
        TestCode(timestamp: 1111111111, code: "67062674", mode: .SHA256, secret: secretSHA256),
        TestCode(timestamp: 1111111111, code: "99943326", mode: .SHA512, secret: secretSHA512),
        TestCode(timestamp: 1234567890, code: "89005924", mode: .SHA1, secret: secretSHA1),
        TestCode(timestamp: 1234567890, code: "91819424", mode: .SHA256, secret: secretSHA256),
        TestCode(timestamp: 1234567890, code: "93441116", mode: .SHA512, secret: secretSHA512),
        TestCode(timestamp: 2000000000, code: "69279037", mode: .SHA1, secret: secretSHA1),
        TestCode(timestamp: 2000000000, code: "90698825", mode: .SHA256, secret: secretSHA256),
        TestCode(timestamp: 2000000000, code: "38618901", mode: .SHA512, secret: secretSHA512),
        TestCode(timestamp: 20000000000, code: "65353130", mode: .SHA1, secret: secretSHA1),
        TestCode(timestamp: 20000000000, code: "77737706", mode: .SHA256, secret: secretSHA256),
        TestCode(timestamp: 20000000000, code: "47863826", mode: .SHA512, secret: secretSHA512),
    ]

//    func testInitWithData() throws {
//        XCTAssertThrowsError(try HOTP(secret: Self.secret, counter: 0, digits: 0)) { error in
//            XCTAssertEqual(error as? OTPError, OTPError.wrongNumberOfDigits)
//        }
//        XCTAssertThrowsError(try HOTP(secret: Self.secret, counter: 0, digits: 11)) { error in
//            XCTAssertEqual(error as? OTPError, OTPError.wrongNumberOfDigits)
//        }
//        _ = try HOTP(secret: Self.secret, counter: 0, digits: 1)
//        _ = try HOTP(secret: Self.secret, counter: 0, digits: 10)
//    }
//
//    func testInitWithURL() throws {
//        XCTAssertThrowsError(try HOTP(urlString: "otpauth://totp/?secret=JBSWY3DPEHPK3PXP&counter=0")) { error in
//            XCTAssertEqual(error as? OTPError, OTPError.invalidType)
//        }
//        XCTAssertThrowsError(try HOTP(urlString: "otpauth://hotp/?secret=JBSWY3DPEHPK3PXP")) { error in
//            XCTAssertEqual(error as? OTPError, OTPError.counterMissing)
//        }
//        XCTAssertThrowsError(
//            try HOTP(urlString: "otpauth://hotp/?secret=JBSWY3DPEHPK3PXP&counter=0&digits=11")
//        ) { error in
//            XCTAssertEqual(error as? OTPError, OTPError.wrongNumberOfDigits)
//        }
//
//        _ = try HOTP(urlString: "otpauth://hotp/?secret=JBSWY3DPEHPK3PXP&counter=0")
//
//        let hotp = try HOTP(
//            urlString: "otpauth://hotp/Example:user@example.com?issuer=Example&secret=IE&algorithm=SHA512&digits=7&counter=123"
//        )
//        XCTAssertEqual(hotp.secret, [0x41])
//        XCTAssertEqual(hotp.counter, 123)
//        XCTAssertEqual(hotp.algorithm, HashAlgorithm.SHA512)
//        XCTAssertEqual(hotp.digits, 7)
//        XCTAssertEqual(hotp.issuer, "Example")
//        XCTAssertEqual(hotp.account, "user@example.com")
//    }
//
//    func testURLString() throws {
//        let hotp = try HOTP(
//            secret: [0x41],
//            counter: 123,
//            algorithm: .SHA512,
//            digits: 7,
//            issuer: "Example",
//            account: "user@example.com"
//        )
//
//        let expectedString = "otpauth://hotp/Example:user@example.com?secret=IE&algorithm=SHA512&digits=7&counter=123&issuer=Example"
//
//        XCTAssertEqual(hotp.urlString, expectedString)
//    }
//
    func testCodes() throws {
        for testCode in Self.expectedCodes {
            let totp = try TOTP(secret: testCode.secret, algorithm: testCode.mode, digits: 8)
            let code = try totp.generateCode(date: Date(timeIntervalSince1970: testCode.timestamp))
            XCTAssertEqual(code, testCode.code)
        }
    }
//
//    func testAutoIncrement() throws {
//        var hotp = try HOTP(secret: Self.secret, counter: 0, digits: 10)
//
//        for (_, expectedCode) in Self.expectedCodes {
//            let code = try hotp.generateCode()
//            XCTAssertEqual(code, expectedCode)
//        }
//    }
}
