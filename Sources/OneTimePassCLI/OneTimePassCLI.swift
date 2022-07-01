//
//  File.swift
//  
//
//  Created by Przemek Ambroży on 22/06/2022.
//

import Foundation
import OneTimePass

@main
struct App {
    static func main() async {
        print("HELLO")

        do {
//            var hotp1 = try HOTP(secret: [0x12, 0x34], counter: 0, algorithm: .SHA1, digits: 10, issuer: "ISSUER", account: "ACCOUNT")
//
//            var hotp2 = try HOTP(urlString: "otpauth://hotp/Example:alice@google.com?secret=CI2A&counter=0&digits=10")
//            print("ENCODED", try hotp2.generateCode(counter: 1), hotp2.urlString)
//            print("rep", String(decoding: try JSONEncoder().encode(hotp2), as: UTF8.self))
//
//            let code1 = try hotp1.generateCode()
//            let code2 = try hotp2.generateCode()
//            print("CODE1", code1)
//            print("CODE2", code2)
//
//            let totp = try TOTP(urlString: "otpauth://totp/?secret=JBSWY3DPEHPK3PXP&period=5")
//            print("TOTP", try totp.generateCode(date: Date().addingTimeInterval(30.0)))
//            print("TOTP string", totp.urlString)
//            print("rep", String(decoding: try JSONEncoder().encode(totp), as: UTF8.self))
//
//            let previousCode = "787654"
//            let valid = try totp.validate(previousCode, acceptPreviousCodes: 0, acceptNextCodes: 1)
//            print("valid", valid)


            // TESTING

            let secret: [UInt8] = [
                0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
                0x37, 0x38, 0x39, 0x30
            ]

            let s = "12345678901234567890123456789012".data(using: .utf8)!

            let testTotp = try TOTP(secret: s, algorithm: .SHA256, digits: 8)
            print("URL", testTotp.urlString)
//            print("NOW", try testTotp.generateCode())
            print("TEST", try testTotp.generateCode(date: Date(timeIntervalSince1970: 59)) )

//            var i = 0
//            for try await code in totp.codes {
//                print("ASYNC CODE", code)
//                i += 1
//                if i >= 2 {
//                    break
//                }
//            }
        } catch {
            print("Error", error)
        }
    }
}
