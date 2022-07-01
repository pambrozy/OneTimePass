//
//  File.swift
//  
//
//  Created by Przemek Ambroży on 29/06/2022.
//

import XCTest
import OneTimePass

final class HOTPTests: XCTestCase {
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

    func testInitWithData() throws {
        XCTAssertThrowsError(try HOTP(secret: Self.secret, counter: 0, digits: 0)) { error in
            XCTAssertEqual(error as? OTPError, OTPError.wrongNumberOfDigits)
        }
        XCTAssertThrowsError(try HOTP(secret: Self.secret, counter: 0, digits: 11)) { error in
            XCTAssertEqual(error as? OTPError, OTPError.wrongNumberOfDigits)
        }
        _ = try HOTP(secret: Self.secret, counter: 0, digits: 1)
        _ = try HOTP(secret: Self.secret, counter: 0, digits: 10)
    }

    func testInitWithURL() throws {
        XCTAssertThrowsError(try HOTP(urlString: "otpauth://totp/?secret=JBSWY3DPEHPK3PXP&counter=0")) { error in
            XCTAssertEqual(error as? OTPError, OTPError.invalidType)
        }
        XCTAssertThrowsError(try HOTP(urlString: "otpauth://hotp/?secret=JBSWY3DPEHPK3PXP")) { error in
            XCTAssertEqual(error as? OTPError, OTPError.counterMissing)
        }
        XCTAssertThrowsError(
            try HOTP(urlString: "otpauth://hotp/?secret=JBSWY3DPEHPK3PXP&counter=0&digits=11")
        ) { error in
            XCTAssertEqual(error as? OTPError, OTPError.wrongNumberOfDigits)
        }

        _ = try HOTP(urlString: "otpauth://hotp/?secret=JBSWY3DPEHPK3PXP&counter=0")

        let hotp = try HOTP(
            urlString: "otpauth://hotp/Example:user@example.com?issuer=Example&secret=IE&algorithm=SHA512&digits=7&counter=123"
        )
        XCTAssertEqual(hotp.secret, [0x41])
        XCTAssertEqual(hotp.counter, 123)
        XCTAssertEqual(hotp.algorithm, HashAlgorithm.SHA512)
        XCTAssertEqual(hotp.digits, 7)
        XCTAssertEqual(hotp.issuer, "Example")
        XCTAssertEqual(hotp.account, "user@example.com")
    }

    func testURLString() throws {
        let hotp = try HOTP(
            secret: [0x41],
            counter: 123,
            algorithm: .SHA512,
            digits: 7,
            issuer: "Example",
            account: "user@example.com"
        )

        let expectedString = "otpauth://hotp/Example:user@example.com?secret=IE&algorithm=SHA512&digits=7&counter=123&issuer=Example"

        XCTAssertEqual(hotp.urlString, expectedString)
    }

    func testCodes() throws {
        let hotp = try HOTP(secret: Self.secret, counter: 0, digits: 10)

        for (counter, expectedCode) in Self.expectedCodes {
            let code = try hotp.generateCode(counter: counter)
            XCTAssertEqual(code, expectedCode)
        }
    }

    func testAutoIncrement() throws {
        var hotp = try HOTP(secret: Self.secret, counter: 0, digits: 10)

        for (_, expectedCode) in Self.expectedCodes {
            let code = try hotp.generateCode()
            XCTAssertEqual(code, expectedCode)
        }
    }
}
