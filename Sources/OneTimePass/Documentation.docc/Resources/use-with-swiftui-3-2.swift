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
        VStack {
            Text("Current code:")
                .font(.headline)
                .padding(8.0)
            if let code = code {
                Text(code.code)
                    .font(.system(.largeTitle, design: .rounded))
                    .fontWeight(.semibold)
                Text(
                    code.validTo.addingTimeInterval(1.0),
                    style: .relative
                )
            } else {
                Text("Could not generate code")
            }
        }
        .task {
            code = try? totp.generateCode()
        }
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
