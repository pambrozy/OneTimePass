//
//  TOTP+Codes.swift
//  OneTimePass
//
//  Created by Przemek Ambroży on 29/03/2025.
//

import Foundation

extension TOTP {
    /// An async sequence of one-time password codes.
    ///
    /// - Note: The current code is **not** included.
    public struct Codes: AsyncSequence {
        public typealias Element = Code
        public struct AsyncIterator: AsyncIteratorProtocol {
            public typealias Element = Code

            let totp: TOTP
            let period: Double

            init(totp: TOTP) {
                self.totp = totp
                self.period = Double(totp.period)
            }

            public func next() async throws -> Code? {
                let now = totp.currentDateProvider()
                let nextTimestamp = ((now.timeIntervalSince1970 / period).rounded(.down) * period) + period
                let nextDate = Date(timeIntervalSince1970: nextTimestamp)
                let duration = UInt64(nextDate.timeIntervalSince(now) * 1_000_000_000)
                try await Task.sleep(nanoseconds: duration)
                return try totp.generateCode()
            }

            public func next(isolation actor: isolated (any Actor)?) async throws -> Code? {
                let now = totp.currentDateProvider()
                let nextTimestamp = ((now.timeIntervalSince1970 / period).rounded(.down) * period) + period
                let nextDate = Date(timeIntervalSince1970: nextTimestamp)
                let duration = UInt64(nextDate.timeIntervalSince(now) * 1_000_000_000)
                try await Task.sleep(nanoseconds: duration)
                return try totp.generateCode()
            }
        }

        let totp: TOTP

        public func makeAsyncIterator() -> AsyncIterator {
            AsyncIterator(totp: totp)
        }
    }
}
