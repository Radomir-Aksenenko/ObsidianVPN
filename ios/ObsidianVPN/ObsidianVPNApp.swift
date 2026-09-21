import SwiftUI

@main
struct ObsidianVPNApp: App {
    @StateObject private var profiles = ProfileStore()
    @StateObject private var tunnel = TunnelController()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(profiles)
                .environmentObject(tunnel)
                .preferredColorScheme(.dark)
                .tint(ObsidianTheme.accent)
        }
    }
}
