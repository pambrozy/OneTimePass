import SwiftUI
import OneTimePass

struct TOTPView: View {
    private let totp: TOTP

    @State
    private var code: TOTP.Code?

    init(urlString: String) throws {
        self.totp = try TOTP(urlString: urlString)
    }

    var body: some View {
        Text("Hello, World!")
    }
}

struct TOTPView_Previews: PreviewProvider {
    static var previews: some View {
        if let totpView = try? TOTPView(urlString: "otpauth://totp/?secret=JBSWY3DPEHPK3PXP") {
            totpView
        } else {
            EmptyView()
        }
    }
}
