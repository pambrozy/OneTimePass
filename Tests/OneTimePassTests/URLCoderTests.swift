//
//  URLCoderTests.swift
//  OneTimePass
//
//  Created by Przemek Ambroży on 02.07.2022.
//  Copyright © 2022 Przemysław Ambroży
//

import Foundation
@testable import OneTimePass
import XCTest

final class URLCoderTests: XCTestCase {
    func testDecode() throws {
        XCTAssertThrowsError(try URLCoder("[/]")) { error in
            XCTAssertEqual(error as? OTPError, OTPError.invalidScheme)
        }
        XCTAssertThrowsError(try URLCoder("http://")) { error in
            XCTAssertEqual(error as? OTPError, OTPError.invalidScheme)
        }
        XCTAssertThrowsError(try URLCoder("otpauth://a/")) { error in
            XCTAssertEqual(error as? OTPError, OTPError.invalidType)
        }
        XCTAssertThrowsError(try URLCoder("otpauth://hotp/")) { error in
            XCTAssertEqual(error as? OTPError, OTPError.secretMissing)
        }
        XCTAssertThrowsError(try URLCoder("otpauth://hotp/?secret")) { error in
            XCTAssertEqual(error as? OTPError, OTPError.secretMissing)
        }

        XCTAssertEqual(try URLCoder("otpauth://hotp/?secret=IE&counter=0&counter=1").counter, 1)
        XCTAssertEqual(try URLCoder("otpauth://hotp/a?secret=IE&counter=0").account, "a")

        let issuserAccount = try URLCoder("otpauth://hotp/a:b?secret=IE&counter=0")
        XCTAssertEqual(issuserAccount.issuer, "a")
        XCTAssertEqual(issuserAccount.account, "b")

        let urlString =
            "otpauth://hotp/iss:user?issuer=iss&secret=IE&algorithm=SHA512&digits=8&counter=0&period=30"
        let urlCoder = try URLCoder(urlString)
        XCTAssertEqual(urlCoder.type, "hotp")
        XCTAssertEqual(urlCoder.issuer, "iss")
        XCTAssertEqual(urlCoder.account, "user")
        XCTAssertEqual(urlCoder.secret, [0x41])
        XCTAssertEqual(urlCoder.algorithm, .SHA512)
        XCTAssertEqual(urlCoder.digits, 8)
        XCTAssertEqual(urlCoder.counter, 0)
        XCTAssertEqual(urlCoder.period, 30)
    }

    func testEncode() throws {
        let urlCoder = URLCoder(
            type: "hotp",
            issuer: "iss",
            account: "user",
            secret: [0x41],
            algorithm: .SHA256,
            digits: 8,
            counter: 10,
            period: 60
        )

        let expectedString =
            "otpauth://hotp/iss:user?secret=IE&algorithm=SHA256&digits=8&counter=10&period=60&issuer=iss"
        XCTAssertEqual(urlCoder.urlString, expectedString)
    }
}
