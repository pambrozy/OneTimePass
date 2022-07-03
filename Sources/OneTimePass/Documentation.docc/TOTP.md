# ``OneTimePass/TOTP``

## Topics

### Initializers
- ``init(secret:algorithm:digits:period:issuer:account:)``
- ``init(urlString:)``
- ``init(from:)``

### Properties
- ``secret``
- ``algorithm``
- ``digits``
- ``period``
- ``issuer``
- ``account``
- ``currentDateProvider``

### Code Generation
- ``Code``
- ``generateCode()``
- ``generateCode(date:)``
- ``codes``

### Code Validation
- ``validate(_:acceptPreviousCodes:acceptNextCodes:)``

### URL Representation
- ``urlString``
