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
        XCTAssertThrowsError(try HOTP(urlString: "[/]")) { error in
            XCTAssertEqual(error as? OTPError, OTPError.creatingURLComponents)
        }
        XCTAssertThrowsError(try HOTP(urlString: "http://")) { error in
            XCTAssertEqual(error as? OTPError, OTPError.invalidScheme)
        }
        XCTAssertThrowsError(try HOTP(urlString: "otpauth://a/")) { error in
            XCTAssertEqual(error as? OTPError, OTPError.invalidType)
        }
        XCTAssertThrowsError(try HOTP(urlString: "otpauth://hotp/")) { error in
            XCTAssertEqual(error as? OTPError, OTPError.secretMissing)
        }
        XCTAssertThrowsError(try HOTP(urlString: "otpauth://hotp/?secret")) { error in
            XCTAssertEqual(error as? OTPError, OTPError.secretMissing)
        }
        XCTAssertEqual(try HOTP(urlString: "otpauth://hotp/?secret=IE&counter=0&counter=1").counter, 1)
        XCTAssertEqual(try HOTP(urlString: "otpauth://hotp/a?secret=IE&counter=0").account, "a")

        let issuserAccount = try HOTP(urlString: "otpauth://hotp/a:b?secret=IE&counter=0")
        XCTAssertEqual(issuserAccount.issuer, "a")
        XCTAssertEqual(issuserAccount.account, "b")
    }
}
