# OneTimePass

[![macOS Build](https://github.com/pambrozy/OneTimePass/actions/workflows/macos.yaml/badge.svg)](https://github.com/pambrozy/OneTimePass/actions/workflows/macos.yaml)
[![Linux Build](https://github.com/pambrozy/OneTimePass/actions/workflows/linux.yaml/badge.svg)](https://github.com/pambrozy/OneTimePass/actions/workflows/linux.yaml)

A package for generating HMAC-based and Time-based one-time passwords.

See the [full documentation](https://pambrozy.github.io/OneTimePass/documentation/onetimepass/).

## Usage

### Creating a generator
You can create a generator using an URL string:
```swift
let totp = try TOTP(urlString: "otpauth://totp/?secret=JBSWY3DPEHPK3PXP")
```

Alternatively, you can pass all of the parameters:
```swift
let hotp = try HOTP(secret: [0x41, 0x41, 0x43], counter: 0, digits: 8)
```

### Creating a one-time password code
To create a one-time password code, use the `generateCode()` method:
```swift
let code = try totp.generateCode()
```

If you are using the TOTP generator, you can validate a code accepting a number of previous and next codes:
```swift
let isValid = try totp.validate("123456", acceptPreviousCodes: 2, acceptNextCodes: 1)
```

For TOTP, you can also use a `for` loop over the async `codes` method:
```swift
let task = Task {
    for try await code in totp.codes {
        print("New code:", code.code)
    }
}
```

For details on how to use the package with SwiftUI, check the tutorial:
[Use with SwiftUI](https://pambrozy.github.io/OneTimePass/tutorials/onetimepass/use-with-swiftui)


## License
OneTimePass is released under the 2-Clause BSD License. See [LICENSE](LICENSE) for details.
