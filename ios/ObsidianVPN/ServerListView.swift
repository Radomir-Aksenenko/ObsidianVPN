import SwiftUI
import UIKit

struct ServerListView: View {
    @EnvironmentObject private var profiles: ProfileStore
    @State private var showImport = false
    @State private var searchText = ""
    @StateObject private var pingService = PingService.shared

    private var filteredProfiles: [VPNProfile] {
        if searchText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return profiles.profiles
        }
        return profiles.profiles.filter {
            $0.name.localizedCaseInsensitiveContains(searchText) ||
            $0.city.localizedCaseInsensitiveContains(searchText) ||
            $0.endpoint.localizedCaseInsensitiveContains(searchText)
        }
    }

    var body: some View {
        NavigationStack {
            ZStack {
                MineralBackground()

                if profiles.profiles.isEmpty {
                    ContentUnavailableView {
                        Label("Нет серверов", systemImage: "point.3.connected.trianglepath.dotted")
                            .font(.system(.title2, design: .rounded, weight: .bold))
                    } description: {
                        Text("Добавьте ссылку доступа Obsidian (QR или ключ). Она хранится на вашем устройстве.")
                            .foregroundStyle(ObsidianTheme.secondaryText)
                    } actions: {
                        Button {
                            triggerHaptic()
                            showImport = true
                        } label: {
                            Text("Добавить сервер")
                                .font(.system(.body, design: .rounded, weight: .semibold))
                                .padding(.horizontal, 16)
                                .padding(.vertical, 8)
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(ObsidianTheme.accent)
                        .foregroundStyle(.black)
                    }
                } else {
                    List {
                        Section {
                            ForEach(filteredProfiles) { profile in
                                serverRow(profile)
                                    .listRowBackground(Color.white.opacity(0.03))
                                    .listRowSeparatorTint(Color.white.opacity(0.08))
                                    .swipeActions(edge: .leading, allowsFullSwipe: true) {
                                        Button {
                                            triggerHaptic()
                                            profiles.toggleFavorite(profile)
                                        } label: {
                                            Label("Избранное", systemImage: profile.isFavorite ? "star.slash.fill" : "star.fill")
                                        }
                                        .tint(.orange)
                                    }
                                    .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                                        Button(role: .destructive) {
                                            triggerHaptic()
                                            profiles.remove(profile)
                                        } label: {
                                            Label("Удалить", systemImage: "trash.fill")
                                        }
                                    }
                            }
                        } header: {
                            Text("Сохранённые серверы (\(filteredProfiles.count))")
                                .font(.system(size: 12, weight: .semibold, design: .rounded))
                                .foregroundStyle(ObsidianTheme.secondaryText)
                        }
                    }
                    .scrollContentBackground(.hidden)
                    .searchable(text: $searchText, prompt: "Поиск серверов")
                }
            }
            .navigationTitle("Серверы")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        triggerHaptic()
                        showImport = true
                    } label: {
                        Image(systemName: "plus")
                            .font(.system(size: 16, weight: .semibold))
                    }
                    .accessibilityLabel("Добавить сервер")
                }
            }
            .sheet(isPresented: $showImport) { AddProfileView() }
        }
    }

    private func serverRow(_ profile: VPNProfile) -> some View {
        Button {
            triggerHaptic()
            profiles.select(profile)
        } label: {
            HStack(spacing: 14) {
                // Country Squircle
                ZStack {
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .fill(
                            LinearGradient(
                                colors: [
                                    (isSelected(profile) ? ObsidianTheme.accent : Color.white).opacity(0.18),
                                    Color.white.opacity(0.04)
                                ],
                                startPoint: .topLeading,
                                endPoint: .bottomTrailing
                            )
                        )
                        .frame(width: 44, height: 44)
                        .overlay {
                            RoundedRectangle(cornerRadius: 12, style: .continuous)
                                .stroke(Color.white.opacity(0.16), lineWidth: 1)
                        }

                    Text(profile.countryCode)
                        .font(.system(size: 14, weight: .bold, design: .rounded))
                        .foregroundStyle(isSelected(profile) ? ObsidianTheme.accent : ObsidianTheme.primaryText)
                }

                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 6) {
                        Text(profile.name)
                            .font(.system(size: 16, weight: .semibold, design: .rounded))
                            .foregroundStyle(ObsidianTheme.primaryText)

                        if profile.isFavorite {
                            Image(systemName: "star.fill")
                                .font(.system(size: 11))
                                .foregroundStyle(.orange)
                        }
                    }

                    Text(profile.city == profile.name ? profile.endpoint : "\(profile.city) · \(profile.endpoint)")
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundStyle(ObsidianTheme.secondaryText)
                        .lineLimit(1)
                }

                Spacer()

                if isSelected(profile) {
                    Image(systemName: "checkmark.circle.fill")
                        .font(.system(size: 20))
                        .foregroundStyle(ObsidianTheme.accent)
                }
            }
            .padding(.vertical, 4)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private func isSelected(_ profile: VPNProfile) -> Bool {
        profiles.selectedID == profile.id || profiles.selectedProfile?.id == profile.id
    }

    private func triggerHaptic() {
        let generator = UIImpactFeedbackGenerator(style: .light)
        generator.impactOccurred()
    }
}
