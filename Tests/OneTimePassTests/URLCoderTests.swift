//
//  URLCoderTests.swift
//  OneTimePass
//
//  Created by Przemek Ambroży on 02.07.2022.
//  Copyright © 2022 Przemysław Ambroży
//

import Foundation
@testable import OneTimePass
import Testing

@Suite
struct URLCoderTests {
    func testDecode() throws {
        #expect(throws: OTPError.invalidScheme) {
            try URLCoder("[/]")
        }
        #expect(throws: OTPError.invalidScheme) {
            try URLCoder("http://")
        }
        #expect(throws: OTPError.invalidType) {
            try URLCoder("otpauth://a/")
        }
        #expect(throws: OTPError.secretMissing) {
            try URLCoder("otpauth://hotp/")
        }
        #expect(throws: OTPError.secretMissing) {
            try URLCoder("otpauth://hotp/?secret")
        }

        #expect(try URLCoder("otpauth://hotp/?secret=IE&counter=0&counter=1").counter == 1)
        #expect(try URLCoder("otpauth://hotp/a?secret=IE&counter=0").account == "a")

        let issuserAccount = try URLCoder("otpauth://hotp/a:b?secret=IE&counter=0")
        #expect(issuserAccount.issuer == "a")
        #expect(issuserAccount.account == "b")

        let urlString =
            "otpauth://hotp/iss:user?issuer=iss&secret=IE&algorithm=SHA512&digits=8&counter=0&period=30"
        let urlCoder = try URLCoder(urlString)
        #expect(urlCoder.type == "hotp")
        #expect(urlCoder.issuer == "iss")
        #expect(urlCoder.account == "user")
        #expect(urlCoder.secret == [0x41])
        #expect(urlCoder.algorithm == .SHA512)
        #expect(urlCoder.digits == 8)
        #expect(urlCoder.counter == 0)
        #expect(urlCoder.period == 30)
    }

    @Test
    func encode() throws {
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
        #expect(urlCoder.urlString == expectedString)
    }
}
