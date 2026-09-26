import SwiftUI

struct RootView: View {
    @EnvironmentObject private var tunnel: TunnelController
    @State private var selection: Destination = .home

    enum Destination: Hashable { case home, servers, settings }

    var body: some View {
        TabView(selection: $selection) {
            HomeView(openServers: {
                withAnimation(.fluidSpring) {
                    selection = .servers
                }
            })
            .tag(Destination.home)
            .tabItem {
                Label("Главная", systemImage: "circle.hexagongrid.fill")
            }

            ServerListView()
                .tag(Destination.servers)
                .tabItem {
                    Label("Серверы", systemImage: "point.3.connected.trianglepath.dotted")
                }

            SettingsView()
                .tag(Destination.settings)
                .tabItem {
                    Label("Настройки", systemImage: "gearshape.fill")
                }
        }
        .tint(ObsidianTheme.accent)
        .toolbarBackground(ObsidianTheme.background.opacity(0.92), for: .tabBar)
        .toolbarBackground(.visible, for: .tabBar)
        .task { await tunnel.prepare() }
    }
}
