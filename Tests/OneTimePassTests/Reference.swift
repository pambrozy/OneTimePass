//
//  Reference.swift
//  OneTimePass
//
//  Created by Przemek Ambroży on 29.03.2025.
//  Copyright © 2025 Przemysław Ambroży
//

import os

final class Reference<T>: @unchecked Sendable {
    private var lockedValue: T
    private var lock: UnsafeMutablePointer<os_unfair_lock>

    var value: T {
        get {
            os_unfair_lock_lock(lock)
            defer {
                os_unfair_lock_unlock(lock)
            }
            return lockedValue
        }
        set {
            os_unfair_lock_lock(lock)
            defer {
                os_unfair_lock_unlock(lock)
            }
            lockedValue = newValue
        }
    }

    init(_ value: T) {
        lock = UnsafeMutablePointer<os_unfair_lock>.allocate(capacity: 1)
        lock.initialize(to: os_unfair_lock())
        self.lockedValue = value
    }

    deinit {
        lock.deallocate()
    }
}
