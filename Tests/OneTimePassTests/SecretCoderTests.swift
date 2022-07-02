//
//  SecretCoderTests.swift
//  OneTimePass
//
//  Created by Przemek Ambroży on 29.06.2022.
//  Copyright © 2022 Przemysław Ambroży
//

import OneTimePass
import XCTest

final class SecretCoderTests: XCTestCase {
    func testDecoder() throws {
        _ = try HOTP(urlString: "otpauth://hotp/?secret=&counter=0")

        XCTAssertThrowsError(try HOTP(urlString: "otpauth://hotp/?secret=IF%C2%B7A&counter=0")) { error in
            XCTAssertEqual(error as? OTPError, OTPError.decodingSecret)
        }

        XCTAssertThrowsError(try HOTP(urlString: "otpauth://hotp/?secret=IF9A&counter=0")) { error in
            XCTAssertEqual(error as? OTPError, OTPError.decodingSecret)
        }
    }

    func testEncoder() throws {
        _ = try HOTP(urlString: "otpauth://hotp/?secret=&counter=0").urlString
        _ = try HOTP(urlString: "otpauth://hotp/?secret=IFBEGRCF&counter=0").urlString
    }
}
