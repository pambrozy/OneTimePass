//
//  Reference.swift
//  OneTimePass
//
//  Created by Przemek Ambroży on 29.03.2025.
//  Copyright © 2025 Przemysław Ambroży
//

import Foundation

final class Reference<T>: @unchecked Sendable {
    private var lockedValue: T
    private let lock = NSLock()

    var value: T {
        get {
            lock.withLock {
                lockedValue
            }
        }
        set {
            lock.withLock {
                lockedValue = newValue
            }
        }
    }

    init(_ value: T) {
        self.lockedValue = value
    }
}
