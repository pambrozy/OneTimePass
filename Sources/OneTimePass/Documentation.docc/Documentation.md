# ``OneTimePass``

A package for generating HMAC-based and Time-based one-time passwords.

## Overview

To generate a TOTP one-time password code:
```swift
// Create a TOTP instance
let totp = try TOTP(urlString: "otpauth://totp/?secret=JBSWY3DPEHPK3PXP")

// Generate a code 
let code = try totp.generateCode()

// Print the code
print(code.code)
```

See how to present the codes to the user using SwiftUI: <doc:Use-with-SwiftUI>

## Topics

### Algorithms
- ``HOTP``
- ``TOTP``

### Hash
- ``HashAlgorithm``

### Errors
- ``OTPError``
