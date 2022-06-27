//
//  SecretCoder.swift
//  OneTimePass
//
//  Created by Przemysław Ambroży on 26.06.2022.
//  Copyright © 2022 Przemysław Ambroży
//

import Foundation

enum SecretCoder {
    private static let base32AlphabetValues: [UInt8?] = [
        nil, nil, nil, nil, nil, nil, nil, nil,
        nil, nil, nil, nil, nil, nil, nil, nil,
        nil, nil, nil, nil, nil, nil, nil, nil,
        nil, nil, nil, nil, nil, nil, nil, nil,
        nil, nil, nil, nil, nil, nil, nil, nil,
        nil, nil, nil, nil, nil, nil, nil, nil,
        nil, nil, 26, 27, 28, 29, 30, 31,
        nil, nil, nil, nil, nil, nil, nil, nil,
        nil, 0, 1, 2, 3, 4, 5, 6,
        7, 8, 9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22,
        23, 24, 25, nil, nil, nil, nil, nil,
        nil, 0, 1, 2, 3, 4, 5, 6,
        7, 8, 9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22,
        23, 24, 25, nil, nil, nil, nil, nil
    ]

    private static let base32AlphabetCharacters: [Character] = [
        "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P",
        "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "2", "3", "4", "5", "6", "7"
    ]

    static func decode(secret: String) throws -> [UInt8] {
        guard !secret.isEmpty else {
            return []
        }

        // Remove suffix
        var text = String(secret.trimmingSuffix { $0 == "=" })

        // Calculate pad characters
        let padCharacterCount = text.count.isMultiple(of: 8) ? 0 : 8 - (text.count % 8)

        text += String(repeating: "A", count: padCharacterCount)

        var data = [UInt8]()
        data.reserveCapacity(text.count * 5 / 8)

        for chunk in text.chunks(ofCount: 8) {
            let characters = try chunk
                .map { character -> UInt8 in
                    guard let asciiValue = character.asciiValue else {
                        throw OTPError.decodingSecret
                    }
                    guard let value = Self.base32AlphabetValues[Int(asciiValue)] else {
                        throw OTPError.decodingSecret
                    }
                    return value
                }

            data += [
                // [0](___11111) + [1](___11100)
                (characters[0] << 3) | (characters[1] >> 2),
                // [1](___00011) + [2](___11111) + [3](___10000)
                ((characters[1] & 0b11) << 6) | (characters[2] << 1) | (characters[3] >> 4),
                // [3](___01111) + [4](___11110)
                ((characters[3] & 0b1111) << 4) | (characters[4] >> 1),
                // [4](___00001) + [5](___11111) + [6](___11000)
                (characters[4] << 7) | (characters[5] << 2) | (characters[6] >> 3),
                // [6](___00111) + [7](___11111)
                (characters[6] << 5) | characters[7]
            ]
        }

        if padCharacterCount > 0 {
            data.removeLast((padCharacterCount + 1) * 5 / 8)
        }

        return data
    }

    static func encode(secret: [UInt8]) -> String {
        guard !secret.isEmpty else {
            return ""
        }

        let padding = secret.count.isMultiple(of: 5) ? 0 : 5 - (secret.count % 5)
        let padCharacterCount = padding * 8 / 5

        let data = secret + [UInt8](repeating: 0, count: padding)

        var output = ""
        output.reserveCapacity(data.count * 8 / 5)

        for chunk in data.chunks(ofCount: 5) {
            output += [
                // [0](11111000)
                // 11111___ ________ ________ ________ ________
                base32AlphabetCharacters[Int(
                    chunk[chunk.startIndex] >> 3
                )],
                // [0](00000111) + [1](11000000)
                // _____111 11______ ________ ________ ________
                base32AlphabetCharacters[Int(
                    ((chunk[chunk.startIndex] & 0b111) << 2) | (chunk[chunk.startIndex + 1] >> 6)
                )],
                // [1](00111110)
                // ________ __11111_ ________ ________ ________
                base32AlphabetCharacters[Int(
                    (chunk[chunk.startIndex + 1] >> 1) & 0b11111
                )],
                // [1](00000001) + [2](11110000)
                // ________ _______1 1111____ ________ ________
                base32AlphabetCharacters[Int(
                    ((chunk[chunk.startIndex + 1] & 0b1) << 4) | (chunk[chunk.startIndex + 2] >> 4)
                )],
                // [2](00001111) + [3](10000000)
                // ________ ________ ____1111 1_______ ________
                base32AlphabetCharacters[Int(
                    (chunk[chunk.startIndex + 2] & 0b1111) << 1 | (chunk[chunk.startIndex + 3] >> 7)
                )],
                // [3](01111100)
                // ________ ________ ________ _11111__ ________
                base32AlphabetCharacters[Int(
                    (chunk[chunk.startIndex + 3] >> 2) & 0b11111
                )],
                // [3](00000011) + [4](11100000)
                // ________ ________ ________ ______11 111_____
                base32AlphabetCharacters[Int(
                    (chunk[chunk.startIndex + 3] & 0b11) << 3 | (chunk[chunk.startIndex + 4] >> 5)
                )],
                // [4](00011111)
                // ________ ________ ________ ________ ___11111
                base32AlphabetCharacters[Int(
                    (chunk[chunk.startIndex + 4] & 0b11111)
                )]
            ]
        }

        output.removeLast(padCharacterCount)

        return output
    }
}

extension Collection {
    fileprivate func chunks(ofCount count: Int) -> [SubSequence] {
        var startIndex = self.startIndex
        var result = [SubSequence]()
        result.reserveCapacity(self.count / count)

        while startIndex < self.endIndex {
            let endIndex = index(startIndex, offsetBy: count, limitedBy: self.endIndex) ?? self.endIndex
            result.append(self[startIndex..<endIndex])
            startIndex = endIndex
        }

        return result
    }
}

extension BidirectionalCollection {
    fileprivate func trimmingSuffix(
        while predicate: (Element) throws -> Bool
    ) rethrows -> SubSequence {
        var end = endIndex
        while end != startIndex {
            let after = end
            formIndex(before: &end)
            if try !predicate(self[end]) {
                return self[..<after]
            }
        }
        return self[..<end]
    }
}
