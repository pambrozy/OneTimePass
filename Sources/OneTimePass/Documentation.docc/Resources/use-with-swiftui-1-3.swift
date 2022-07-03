import SwiftUI
import OneTimePass

struct TOTPView: View {
    private let totp: TOTP

    @State
    private var code: TOTP.Code?
    
    var body: some View {
        Text("Hello, World!")
    }
}

struct TOTPView_Previews: PreviewProvider {
    static var previews: some View {
        TOTPView()
    }
}
