import SwiftUI
import UIKit

struct HomeView: View {
    @EnvironmentObject private var profiles: ProfileStore
    @EnvironmentObject private var tunnel: TunnelController
    @AppStorage("settings.haptics", store: UserDefaults(suiteName: "group.com.obsidian.vpn")) private var haptics = true
    @State private var showImport = false

    let openServers: () -> Void

    var body: some View {
        NavigationStack {
            ZStack {
                MineralBackground()
                ScrollView {
                    VStack(spacing: 0) {
                        statusBlock.padding(.top, 18)

                        ConnectionOrb(state: tunnel.state) {
                            if haptics { UIImpactFeedbackGenerator(style: .soft).impactOccurred() }
                            Task { await tunnel.toggle(profile: profiles.selectedProfile) }
                        }
                        .padding(.top, 26)

                        serverButton.padding(.top, 36)
                        metrics.padding(.top, 18)

                        if case let .failed(message) = tunnel.state {
                            errorBanner(message).padding(.top, 16)
                        }
                    }
                    .padding(.horizontal, 20)
                    .padding(.bottom, 34)
                }
                .scrollIndicators(.hidden)
            }
            .navigationTitle("Obsidian")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Image(systemName: "hexagon.fill")
                        .foregroundStyle(ObsidianTheme.primaryText)
                        .accessibilityHidden(true)
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button { showImport = true } label: { Image(systemName: "plus") }
                        .accessibilityLabel("Добавить сервер")
                }
            }
            .sheet(isPresented: $showImport) { AddProfileView() }
        }
    }

    private var statusBlock: some View {
        VStack(spacing: 7) {
            Text(statusTitle)
                .font(.system(.title2, design: .rounded, weight: .semibold))
                .foregroundStyle(ObsidianTheme.primaryText)
            Text(statusSubtitle)
                .font(.subheadline)
                .foregroundStyle(ObsidianTheme.secondaryText)
                .multilineTextAlignment(.center)
        }
        .accessibilityElement(children: .combine)
    }

    private var statusTitle: String {
        switch tunnel.state {
        case .disconnected: "Не подключено"
        case .preparing: "Защищаем соединение"
        case .connected: "Подключено"
        case .disconnecting: "Завершаем сессию"
        case .failed: "Не удалось подключиться"
        }
    }

    private var statusSubtitle: String {
        switch tunnel.state {
        case .connected: "Трафик защищён протоколом Obsidian"
        case .preparing: "Проверяем сервер и создаём туннель"
        case .disconnecting: "Возвращаем обычное подключение"
        case .failed: "Проверьте профиль и попробуйте ещё раз"
        case .disconnected: profiles.selectedProfile == nil ? "Добавьте сервер, чтобы начать" : "Подключитесь, когда понадобится приватность"
        }
    }

    private var serverButton: some View {
        Button {
            if profiles.profiles.isEmpty { showImport = true }
            else { openServers() }
        } label: {
            HStack(spacing: 14) {
                Text(profiles.selectedProfile?.countryCode ?? "+")
                    .font(.system(.headline, design: .rounded, weight: .bold))
                    .foregroundStyle(profiles.selectedProfile == nil ? ObsidianTheme.primaryText : ObsidianTheme.accent)
                    .frame(width: 48, height: 48)
                    .background(ObsidianTheme.raised, in: Circle())

                VStack(alignment: .leading, spacing: 4) {
                    Text(profiles.selectedProfile?.city ?? "Добавить сервер")
                        .font(.headline)
                        .foregroundStyle(ObsidianTheme.primaryText)
                    Text(profiles.selectedProfile?.endpoint ?? "Вставить ключ Obsidian")
                        .font(.caption)
                        .foregroundStyle(ObsidianTheme.secondaryText)
                        .lineLimit(1)
                }
                Spacer()
                Image(systemName: "chevron.right")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(ObsidianTheme.secondaryText)
            }
            .padding(16)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .obsidianCard()
    }

    private var metrics: some View {
        HStack(spacing: 0) {
            metric(title: "Скорость", value: speedText, icon: "arrow.down")
            Rectangle().fill(ObsidianTheme.hairline).frame(width: 1, height: 48)
            TimelineView(.periodic(from: .now, by: 1)) { context in
                metric(title: "Сессия", value: sessionText(at: context.date), icon: "clock")
            }
        }
        .padding(.vertical, 18)
    }

    private func metric(title: String, value: String, icon: String) -> some View {
        VStack(spacing: 7) {
            Label(title, systemImage: icon)
                .font(.caption)
                .foregroundStyle(ObsidianTheme.secondaryText)
            Text(value)
                .font(.system(.body, design: .rounded, weight: .semibold))
                .monospacedDigit()
                .foregroundStyle(ObsidianTheme.primaryText)
        }
        .frame(maxWidth: .infinity)
    }

    private var speedText: String {
        guard tunnel.state == .connected else { return "—" }
        return ByteCountFormatter.string(fromByteCount: tunnel.downloadBytesPerSecond, countStyle: .file) + "/с"
    }

    private func sessionText(at date: Date) -> String {
        guard let start = tunnel.connectedAt, tunnel.state == .connected else { return "—" }
        let duration = max(0, Int(date.timeIntervalSince(start)))
        return String(format: "%02d:%02d:%02d", duration / 3600, (duration % 3600) / 60, duration % 60)
    }

    private func errorBanner(_ message: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "exclamationmark.circle.fill")
                .foregroundStyle(ObsidianTheme.danger)
            Text(message)
                .font(.footnote)
                .foregroundStyle(ObsidianTheme.primaryText)
                .frame(maxWidth: .infinity, alignment: .leading)
            Button("Закрыть") { tunnel.clearError() }
                .font(.footnote.weight(.semibold))
        }
        .padding(14)
        .background(ObsidianTheme.danger.opacity(0.09), in: RoundedRectangle(cornerRadius: 16, style: .continuous))
    }
}
