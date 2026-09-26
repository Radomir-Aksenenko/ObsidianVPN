import SwiftUI
import UIKit

struct ServerListView: View {
    @EnvironmentObject private var profiles: ProfileStore
    @AppStorage("settings.haptics", store: UserDefaults(suiteName: "group.com.obsidian.vpn")) private var haptics = true
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
                    emptyStateView
                } else {
                    List {
                        Section {
                            ForEach(filteredProfiles) { profile in
                                serverRow(profile)
                                    .listRowBackground(
                                        RoundedRectangle(cornerRadius: 16, style: .continuous)
                                            .fill(.ultraThinMaterial.opacity(0.6))
                                            .overlay {
                                                RoundedRectangle(cornerRadius: 16, style: .continuous)
                                                    .stroke(
                                                        isSelected(profile) ? ObsidianTheme.accent.opacity(0.35) : Color.white.opacity(0.08),
                                                        lineWidth: 1
                                                    )
                                            }
                                            .padding(.vertical, 3)
                                    )
                                    .listRowSeparator(.hidden)
                                    .swipeActions(edge: .leading, allowsFullSwipe: true) {
                                        Button {
                                            triggerHaptic(.light)
                                            withAnimation(.fluidBouncy) {
                                                profiles.toggleFavorite(profile)
                                            }
                                        } label: {
                                            Label("Избранное", systemImage: profile.isFavorite ? "star.slash.fill" : "star.fill")
                                        }
                                        .tint(.orange)
                                    }
                                    .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                                        Button(role: .destructive) {
                                            triggerHaptic(.medium)
                                            profiles.remove(profile)
                                        } label: {
                                            Label("Удалить", systemImage: "trash.fill")
                                        }
                                    }
                            }
                        } header: {
                            HStack {
                                Text("Сохранённые серверы")
                                    .font(.system(size: 12, weight: .semibold, design: .rounded))
                                    .foregroundStyle(ObsidianTheme.secondaryText)
                                Spacer()
                                Text("\(filteredProfiles.count)")
                                    .font(.system(size: 11, weight: .bold, design: .rounded))
                                    .foregroundStyle(ObsidianTheme.tertiaryText)
                                    .padding(.horizontal, 7)
                                    .padding(.vertical, 2)
                                    .background(Color.white.opacity(0.08), in: Capsule())
                            }
                            .padding(.bottom, 4)
                        }
                    }
                    .listStyle(.insetGrouped)
                    .scrollContentBackground(.hidden)
                    .searchable(text: $searchText, prompt: "Поиск серверов и локаций")
                }
            }
            .navigationTitle("Серверы")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        triggerHaptic(.light)
                        showImport = true
                    } label: {
                        ZStack {
                            Circle()
                                .fill(.ultraThinMaterial)
                                .frame(width: 34, height: 34)
                                .overlay {
                                    Circle().stroke(Color.white.opacity(0.18), lineWidth: 1)
                                }

                            Image(systemName: "plus")
                                .font(.system(size: 14, weight: .semibold))
                                .foregroundStyle(ObsidianTheme.primaryText)
                        }
                    }
                    .accessibilityLabel("Добавить сервер")
                }
            }
            .sheet(isPresented: $showImport) { AddProfileView() }
        }
    }

    // MARK: - Server Row

    private func serverRow(_ profile: VPNProfile) -> some View {
        Button {
            triggerHaptic(.light)
            withAnimation(.fluidSpring) {
                profiles.select(profile)
            }
        } label: {
            HStack(spacing: 14) {
                // Country Emblem Squircle
                ZStack {
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .fill(
                            LinearGradient(
                                colors: [
                                    (isSelected(profile) ? ObsidianTheme.accent : Color.white).opacity(0.20),
                                    Color.white.opacity(0.04)
                                ],
                                startPoint: .topLeading,
                                endPoint: .bottomTrailing
                            )
                        )
                        .frame(width: 44, height: 44)
                        .overlay {
                            RoundedRectangle(cornerRadius: 12, style: .continuous)
                                .stroke(
                                    LinearGradient(
                                        colors: [
                                            (isSelected(profile) ? ObsidianTheme.accent : Color.white).opacity(0.35),
                                            Color.white.opacity(0.08)
                                        ],
                                        startPoint: .topLeading,
                                        endPoint: .bottomTrailing
                                    ),
                                    lineWidth: 1
                                )
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
                            .lineLimit(1)

                        if profile.isFavorite {
                            Image(systemName: "star.fill")
                                .font(.system(size: 11))
                                .foregroundStyle(.orange)
                                .symbolEffect(.bounce, value: profile.isFavorite)
                        }
                    }

                    Text(profile.city == profile.name ? profile.endpoint : "\(profile.city) · \(profile.endpoint)")
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundStyle(ObsidianTheme.secondaryText)
                        .lineLimit(1)
                }

                Spacer()

                // Selected Checkmark
                if isSelected(profile) {
                    Image(systemName: "checkmark.circle.fill")
                        .font(.system(size: 19, weight: .semibold))
                        .foregroundStyle(ObsidianTheme.accent)
                        .shadow(color: ObsidianTheme.accent.opacity(0.5), radius: 6)
                        .transition(.scale.combined(with: .opacity))
                }
            }
            .padding(.vertical, 6)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private func isSelected(_ profile: VPNProfile) -> Bool {
        profiles.selectedID == profile.id
    }

    // MARK: - Empty State View

    private var emptyStateView: some View {
        ContentUnavailableView {
            Label {
                Text("Нет серверов")
                    .font(.system(.title2, design: .rounded, weight: .bold))
            } icon: {
                ZStack {
                    Circle()
                        .fill(
                            RadialGradient(
                                colors: [ObsidianTheme.accent.opacity(0.25), .clear],
                                center: .center,
                                startRadius: 10,
                                endRadius: 50
                            )
                        )
                        .frame(width: 80, height: 80)

                    Image(systemName: "point.3.connected.trianglepath.dotted")
                        .font(.system(size: 36, weight: .medium))
                        .foregroundStyle(ObsidianTheme.accent)
                }
            }
        } description: {
            Text("Добавьте ссылку доступа Obsidian через QR-код или ключ. Ключи безопасно хранятся в Keychain на вашем устройстве.")
                .font(.subheadline)
                .foregroundStyle(ObsidianTheme.secondaryText)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 28)
        } actions: {
            Button {
                triggerHaptic(.light)
                showImport = true
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: "plus")
                        .font(.system(size: 14, weight: .semibold))
                    Text("Добавить сервер")
                        .font(.system(.body, design: .rounded, weight: .semibold))
                }
                .padding(.horizontal, 20)
                .padding(.vertical, 11)
                .background(ObsidianTheme.accent, in: Capsule())
                .foregroundStyle(Color.black)
            }
        }
    }

    private func triggerHaptic(_ style: UIImpactFeedbackGenerator.FeedbackStyle) {
        guard haptics else { return }
        let generator = UIImpactFeedbackGenerator(style: style)
        generator.impactOccurred()
    }
}
