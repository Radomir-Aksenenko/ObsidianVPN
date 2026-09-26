import SwiftUI

struct ServerListView: View {
    @EnvironmentObject private var profiles: ProfileStore
    @State private var showImport = false

    var body: some View {
        NavigationStack {
            ZStack {
                MineralBackground()
                if profiles.profiles.isEmpty {
                    ContentUnavailableView {
                        Label("Нет серверов", systemImage: "point.3.connected.trianglepath.dotted")
                    } description: {
                        Text("Добавьте ссылку доступа Obsidian. Она хранится только на вашем устройстве.")
                    } actions: {
                        Button("Добавить сервер") { showImport = true }
                            .buttonStyle(.borderedProminent)
                    }
                } else {
                    List {
                        Section("Доступные") {
                            ForEach(profiles.profiles) { profile in
                                serverRow(profile)
                                    .listRowBackground(ObsidianTheme.surface)
                                    .swipeActions(edge: .leading, allowsFullSwipe: true) {
                                        Button { profiles.toggleFavorite(profile) } label: {
                                            Label("Избранное", systemImage: profile.isFavorite ? "star.slash" : "star")
                                        }
                                        .tint(.orange)
                                    }
                                    .swipeActions {
                                        Button(role: .destructive) { profiles.remove(profile) } label: {
                                            Label("Удалить", systemImage: "trash")
                                        }
                                    }
                            }
                        }
                    }
                    .scrollContentBackground(.hidden)
                }
            }
            .navigationTitle("Серверы")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button { showImport = true } label: { Image(systemName: "plus") }
                        .accessibilityLabel("Добавить сервер")
                }
            }
            .sheet(isPresented: $showImport) { AddProfileView() }
        }
    }

    private func serverRow(_ profile: VPNProfile) -> some View {
        Button { profiles.select(profile) } label: {
            HStack(spacing: 14) {
                Text(profile.countryCode)
                    .font(.system(.subheadline, design: .rounded, weight: .bold))
                    .foregroundStyle(ObsidianTheme.accent)
                    .frame(width: 42, height: 42)
                    .background(ObsidianTheme.accentMuted.opacity(0.72), in: Circle())
                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 6) {
                        Text(profile.name).font(.headline)
                        if profile.isFavorite {
                            Image(systemName: "star.fill")
                                .font(.caption2)
                                .foregroundStyle(.orange)
                        }
                    }
                    Text(profile.city == profile.name ? profile.endpoint : "\(profile.city) · \(profile.endpoint)")
                        .font(.caption)
                        .foregroundStyle(ObsidianTheme.secondaryText)
                }
                Spacer()
                if profiles.selectedID == profile.id || profiles.selectedProfile?.id == profile.id {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(ObsidianTheme.accent)
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityHint("Выбрать этот сервер")
    }
}
