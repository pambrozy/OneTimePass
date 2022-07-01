//
//  URLCoder.swift
//  OneTimePass
//
//  Created by Przemysław Ambroży on 26.06.2022.
//  Copyright © 2022 Przemysław Ambroży
//

import Foundation

struct URLCoder {
    let type: String
    let issuer: String?
    let account: String?
    let secret: [UInt8]
    let algorithm: HashAlgorithm?
    let digits: Int?
    let counter: Int?
    let period: UInt?
}

// MARK: Decode

extension URLCoder {
    init(_ urlString: String) throws {
        guard let components = URLComponents(string: urlString) else {
            throw OTPError.creatingURLComponents
        }
        guard components.scheme == "otpauth" else {
            throw OTPError.invalidScheme
        }
        guard let type = components.host, (type == "hotp" || type == "totp") else {
            throw OTPError.invalidType
        }
        let queryItems = Self.makeQueryItems(from: components)

        guard let secretString = queryItems["secret"] else {
            throw OTPError.secretMissing
        }
        secret = try SecretCoder.decode(secret: secretString)

        self.type = type
        let (labelIssuer, labelAccount) = Self.decodeLabel(String(components.path.dropFirst()))
        let queryIssuer = queryItems["issuer"]
        issuer = labelIssuer ?? queryIssuer
        account = labelAccount
        algorithm = queryItems["algorithm"].flatMap { HashAlgorithm(rawValue: $0) }
        digits = queryItems["digits"].flatMap { Int($0) }
        counter = queryItems["counter"].flatMap { Int($0) }
        period = queryItems["period"].flatMap { UInt($0) }
    }

    private static func makeQueryItems(from components: URLComponents) -> [String: String] {
        let array = (components.queryItems ?? [])
            .compactMap { (queryItem: URLQueryItem) -> (String, String)? in
                guard let value = queryItem.value else {
                    return nil
                }
                return (queryItem.name, value)
            }

        return Dictionary(array) { $1 }
    }

    private static func decodeLabel(_ label: String) -> (String?, String?) {
        guard !label.isEmpty else {
            return (nil, nil)
        }

        let parts: [String]

        if label.contains(":") {
            parts = label.components(separatedBy: ":")
        } else if label.contains("%3A") {
            parts = label.components(separatedBy: "%3A")
        } else {
            parts = [label]
        }

        switch parts.count {
        case 2:
            return (parts[0], parts[1])
        case 1:
            return (nil, parts[0])
        default:
            return (nil, nil)
        }
    }
}

// MARK: Encode

extension URLCoder {
    var urlString: String {
        var components = URLComponents()
        components.scheme = "otpauth"
        components.host = type

        var queryItems = [
            URLQueryItem(name: "secret", value: SecretCoder.encode(secret: secret))
        ]

        if let algorithm = algorithm, algorithm != .SHA1 {
            queryItems.append(URLQueryItem(name: "algorithm", value: algorithm.rawValue))
        }

        if let digits = digits {
            queryItems.append(URLQueryItem(name: "digits", value: String(digits)))
        }
        if let counter = counter {
            queryItems.append(URLQueryItem(name: "counter", value: String(counter)))
        }
        if let period = period, period != 30 {
            queryItems.append(URLQueryItem(name: "period", value: String(period)))
        }

        if let account = account,
           let urlEncodedAccount = account.addingPercentEncoding(
            withAllowedCharacters: .urlPathAllowed
           ) {
            var label = urlEncodedAccount

            if let issuer = issuer,
               let urlEncodedIssuer = issuer.addingPercentEncoding(
                withAllowedCharacters: .urlPathAllowed
               ) {
                label = urlEncodedIssuer + ":" + label
                queryItems.append(URLQueryItem(name: "issuer", value: urlEncodedIssuer))
            }

            components.path = "/" + label
        } else {
            components.path = "/"
        }

        components.queryItems = queryItems

        return components.string ?? ""
    }
}
