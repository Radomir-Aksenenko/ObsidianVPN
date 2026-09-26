import SwiftUI
import UIKit

struct HomeView: View {
    @EnvironmentObject private var profiles: ProfileStore
    @EnvironmentObject private var tunnel: TunnelController
    @AppStorage("settings.haptics", store: UserDefaults(suiteName: "group.com.obsidian.vpn")) private var haptics = true
    @State private var showImport = false
    @State private var showScanner = false
    @State private var showLogs = false
    @State private var showSecurityDetails = false
    @StateObject private var logStore = LogStore.shared
    @StateObject private var pingService = PingService.shared

    let openServers: () -> Void

    var body: some View {
        NavigationStack {
            ZStack {
                MineralBackground()

                ScrollView {
                    VStack(spacing: 24) {
                        // 1. Apple Dynamic Status Capsule
                        statusCapsule
                            .padding(.top, 10)

                        // 2. Centerpiece: Liquid Glass Activation Orb
                        ConnectionOrb(state: tunnel.state) {
                            triggerHaptic()
                            Task { await tunnel.toggle(profile: profiles.selectedProfile) }
                        }
                        .padding(.top, 12)

                        // 3. Apple Glass Server Card
                        serverCard

                        // 4. Apple 3-Tile Telemetry Dashboard
                        telemetryDashboard

                        // 5. Apple Quick Action Bar
                        quickActionsBar

                        // Error Banner if needed
                        if case let .failed(message) = tunnel.state {
                            errorBanner(message)
                        }

                        // 6. Foldable Glass Network Console
                        logsDrawer
                            .padding(.bottom, 24)
                    }
                    .padding(.horizontal, 20)
                }
                .scrollIndicators(.hidden)
            }
            .navigationTitle("Obsidian")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Image(systemName: "hexagon.fill")
                        .font(.system(size: 18))
                        .foregroundStyle(tunnel.state == .connected ? ObsidianTheme.accent : ObsidianTheme.primaryText.opacity(0.8))
                        .accessibilityHidden(true)
                }
                ToolbarItem(placement: .topBarTrailing) {
                    HStack(spacing: 16) {
                        Button {
                            triggerHaptic()
                            showScanner = true
                        } label: {
                            Image(systemName: "qrcode.viewfinder")
                                .font(.system(size: 17, weight: .semibold))
                        }
                        .accessibilityLabel("Сканировать QR-код")

                        Button {
                            triggerHaptic()
                            showImport = true
                        } label: {
                            Image(systemName: "plus")
                                .font(.system(size: 17, weight: .semibold))
                        }
                        .accessibilityLabel("Добавить сервер")
                    }
                }
            }
            .sheet(isPresented: $showImport) { AddProfileView() }
            .sheet(isPresented: $showScanner) {
                QRScannerSheet { scannedCode in
                    do {
                        let profile = try VPNProfile.imported(from: scannedCode)
                        profiles.add(profile)
                        logStore.log("QR успешно распознан: \(profile.name)")
                        pingCurrentServer()
                    } catch {
                        logStore.log("Ошибка формата QR: \(error.localizedDescription)")
                    }
                }
            }
            .sheet(isPresented: $showSecurityDetails) {
                securityDetailsSheet
            }
            .onAppear {
                pingCurrentServer()
            }
            .onChange(of: tunnel.state) { _, newState in
                if newState == .connected {
                    pingCurrentServer()
                }
            }
            .onChange(of: profiles.selectedID) { _, _ in
                pingCurrentServer()
            }
        }
    }

    // MARK: - 1. Dynamic Status Capsule

    private var statusCapsule: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(statusDotColor)
                .frame(width: 8, height: 8)
                .shadow(color: statusDotColor.opacity(0.8), radius: 4)

            Text(statusTitle.uppercased())
                .font(.system(size: 11, weight: .bold, design: .rounded))
                .foregroundStyle(ObsidianTheme.primaryText)
                .tracking(0.8)

            Text("·")
                .font(.system(size: 11, weight: .bold))
                .foregroundStyle(ObsidianTheme.tertiaryText)

            Text("1280 MTU")
                .font(.system(size: 11, weight: .medium, design: .monospaced))
                .foregroundStyle(ObsidianTheme.secondaryText)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 7)
        .background(.ultraThinMaterial, in: Capsule())
        .overlay {
            Capsule().stroke(Color.white.opacity(0.14), lineWidth: 1)
        }
    }

    private var statusDotColor: Color {
        switch tunnel.state {
        case .connected: return ObsidianTheme.accent
        case .preparing, .disconnecting: return ObsidianTheme.amber
        case .failed: return ObsidianTheme.danger
        case .disconnected: return Color.white.opacity(0.4)
        }
    }

    private var statusTitle: String {
        switch tunnel.state {
        case .connected: return "Защищено Reality"
        case .preparing: return "Подключение..."
        case .disconnecting: return "Отключение..."
        case .failed: return "Сбой подключения"
        case .disconnected: return "Готов к работе"
        }
    }

    // MARK: - 3. Apple Glass Server Card

    private var serverCard: some View {
        Button {
            triggerHaptic()
            if profiles.profiles.isEmpty { showImport = true }
            else { openServers() }
        } label: {
            HStack(spacing: 16) {
                // Flag / Country Squircle
                ZStack {
                    RoundedRectangle(cornerRadius: 14, style: .continuous)
                        .fill(
                            LinearGradient(
                                colors: [
                                    (tunnel.state == .connected ? ObsidianTheme.accent : Color.white).opacity(0.18),
                                    Color.white.opacity(0.04)
                                ],
                                startPoint: .topLeading,
                                endPoint: .bottomTrailing
                            )
                        )
                        .frame(width: 48, height: 48)
                        .overlay {
                            RoundedRectangle(cornerRadius: 14, style: .continuous)
                                .stroke(Color.white.opacity(0.18), lineWidth: 1)
                        }

                    Text(profiles.selectedProfile?.countryCode ?? "+")
                        .font(.system(size: 15, weight: .bold, design: .rounded))
                        .foregroundStyle(tunnel.state == .connected ? ObsidianTheme.accent : ObsidianTheme.primaryText)
                }

                VStack(alignment: .leading, spacing: 3) {
                    Text(profiles.selectedProfile?.name ?? "Добавить сервер")
                        .font(.system(size: 17, weight: .semibold, design: .rounded))
                        .foregroundStyle(ObsidianTheme.primaryText)
                        .lineLimit(1)

                    HStack(spacing: 6) {
                        Text(profiles.selectedProfile?.endpoint ?? "Нажмите для добавления ключа")
                            .font(.system(size: 13, weight: .regular, design: .monospaced))
                            .foregroundStyle(ObsidianTheme.secondaryText)
                            .lineLimit(1)
                    }
                }

                Spacer()

                // Ping Latency Pill
                if let latency = pingService.latencyMs, profiles.selectedProfile != nil {
                    HStack(spacing: 4) {
                        Circle()
                            .fill(latencyColor(latency))
                            .frame(width: 6, height: 6)
                        Text("\(latency) ms")
                            .font(.system(size: 11, weight: .semibold, design: .rounded))
                            .foregroundStyle(ObsidianTheme.primaryText.opacity(0.9))
                    }
                    .padding(.horizontal, 9)
                    .padding(.vertical, 5)
                    .background(Color.white.opacity(0.08), in: Capsule())
                    .overlay {
                        Capsule().stroke(Color.white.opacity(0.1), lineWidth: 0.8)
                    }
                } else if pingService.isPinging {
                    ProgressView()
                        .scaleEffect(0.7)
                }

                Image(systemName: "chevron.right")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(ObsidianTheme.tertiaryText)
            }
            .padding(.horizontal, 18)
            .padding(.vertical, 14)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .appleGlassCard(cornerRadius: 22, highlight: 0.22)
    }

    private func latencyColor(_ ms: Int) -> Color {
        if ms < 80 { return ObsidianTheme.accent }
        if ms < 160 { return ObsidianTheme.amber }
        return ObsidianTheme.danger
    }

    // MARK: - 4. Apple 3-Tile Telemetry Dashboard

    private var telemetryDashboard: some View {
        HStack(spacing: 12) {
            // Speed Tile
            telemetryTile(
                title: "Скорость",
                value: speedText,
                icon: "arrow.down.circle.fill",
                accent: tunnel.state == .connected ? ObsidianTheme.accentCyan : ObsidianTheme.secondaryText
            )

            // Ping Tile
            Button {
                triggerHaptic()
                pingCurrentServer()
            } label: {
                telemetryTile(
                    title: "Пинг",
                    value: pingText,
                    icon: "waveform.path.ecg",
                    accent: tunnel.state == .connected ? ObsidianTheme.accent : ObsidianTheme.secondaryText
                )
            }
            .buttonStyle(.plain)

            // Session Duration Tile
            TimelineView(.periodic(from: .now, by: 1)) { context in
                telemetryTile(
                    title: "Сессия",
                    value: sessionText(at: context.date),
                    icon: "clock.fill",
                    accent: tunnel.state == .connected ? Color.white : ObsidianTheme.secondaryText
                )
            }
        }
    }

    private func telemetryTile(title: String, value: String, icon: String, accent: Color) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Image(systemName: icon)
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(accent)
                Text(title)
                    .font(.system(size: 11, weight: .medium, design: .rounded))
                    .foregroundStyle(ObsidianTheme.secondaryText)
            }

            Text(value)
                .font(.system(size: 15, weight: .bold, design: .rounded))
                .monospacedDigit()
                .foregroundStyle(ObsidianTheme.primaryText)
                .lineLimit(1)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
        .appleGlassCard(cornerRadius: 18, highlight: 0.16)
    }

    private var speedText: String {
        guard tunnel.state == .connected else { return "0 Б/с" }
        return ByteCountFormatter.string(fromByteCount: tunnel.downloadBytesPerSecond, countStyle: .file) + "/с"
    }

    private var pingText: String {
        if pingService.isPinging { return "..." }
        if let ms = pingService.latencyMs { return "\(ms) мс" }
        return "—"
    }

    private func sessionText(at date: Date) -> String {
        guard let start = tunnel.connectedAt, tunnel.state == .connected else { return "00:00:00" }
        let duration = max(0, Int(date.timeIntervalSince(start)))
        return String(format: "%02d:%02d:%02d", duration / 3600, (duration % 3600) / 60, duration % 60)
    }

    // MARK: - 5. Apple Quick Action Bar

    private var quickActionsBar: some View {
        HStack(spacing: 10) {
            quickActionButton(label: "Замер пинга", icon: "bolt.fill") {
                pingCurrentServer()
            }

            quickActionButton(label: "Протокол", icon: "shield.lefthalf.filled") {
                showSecurityDetails = true
            }

            quickActionButton(label: "Журнал", icon: showLogs ? "chevron.up" : "terminal.fill") {
                withAnimation(.spring(response: 0.35, dampingFraction: 0.75)) {
                    showLogs.toggle()
                }
            }
        }
    }

    private func quickActionButton(label: String, icon: String, action: @escaping () -> Void) -> some View {
        Button {
            triggerHaptic()
            action()
        } label: {
            HStack(spacing: 6) {
                Image(systemName: icon)
                    .font(.system(size: 12, weight: .semibold))
                Text(label)
                    .font(.system(size: 12, weight: .semibold, design: .rounded))
            }
            .foregroundStyle(ObsidianTheme.primaryText.opacity(0.9))
            .padding(.horizontal, 12)
            .padding(.vertical, 9)
            .frame(maxWidth: .infinity)
            .background(.ultraThinMaterial, in: Capsule())
            .overlay {
                Capsule().stroke(Color.white.opacity(0.12), lineWidth: 1)
            }
        }
        .buttonStyle(.plain)
    }

    // MARK: - 6. Foldable Glass Network Console

    private var logsDrawer: some View {
        VStack(alignment: .leading, spacing: 10) {
            Button {
                withAnimation(.spring(response: 0.35, dampingFraction: 0.75)) {
                    showLogs.toggle()
                }
            } label: {
                HStack {
                    Label("Сетевой журнал", systemImage: "terminal.fill")
                        .font(.system(size: 13, weight: .semibold, design: .rounded))
                        .foregroundStyle(ObsidianTheme.secondaryText)
                    Spacer()
                    Image(systemName: showLogs ? "chevron.up.circle.fill" : "chevron.down.circle.fill")
                        .font(.system(size: 15))
                        .foregroundStyle(ObsidianTheme.tertiaryText)
                }
            }
            .buttonStyle(.plain)

            if showLogs {
                VStack(spacing: 8) {
                    HStack {
                        Spacer()
                        Button("Скопировать") {
                            triggerHaptic()
                            UIPasteboard.general.string = logStore.entries.joined(separator: "\n")
                        }
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(ObsidianTheme.accent)

                        Text("·").foregroundStyle(ObsidianTheme.tertiaryText)

                        Button("Очистить") {
                            triggerHaptic()
                            logStore.clear()
                        }
                        .font(.caption2)
                        .foregroundStyle(ObsidianTheme.secondaryText)
                    }

                    ScrollViewReader { proxy in
                        ScrollView {
                            LazyVStack(alignment: .leading, spacing: 4) {
                                if logStore.entries.isEmpty {
                                    Text("Ожидание сетевых событий...")
                                        .font(.system(.caption2, design: .monospaced))
                                        .foregroundStyle(ObsidianTheme.secondaryText.opacity(0.6))
                                } else {
                                    ForEach(Array(logStore.entries.enumerated()), id: \.offset) { index, entry in
                                        Text(entry)
                                            .font(.system(size: 10.5, design: .monospaced))
                                            .foregroundStyle(logColor(for: entry))
                                            .id(index)
                                    }
                                }
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(10)
                        }
                        .frame(height: 120)
                        .background(Color.black.opacity(0.45), in: RoundedRectangle(cornerRadius: 12))
                        .overlay {
                            RoundedRectangle(cornerRadius: 12).stroke(Color.white.opacity(0.08), lineWidth: 1)
                        }
                        .onChange(of: logStore.entries.count) { _ in
                            if let last = logStore.entries.indices.last {
                                withAnimation { proxy.scrollTo(last, anchor: .bottom) }
                            }
                        }
                    }
                }
                .transition(.opacity.combined(with: .move(edge: .top)))
            }
        }
        .padding(14)
        .appleGlassCard(cornerRadius: 20, highlight: 0.14)
    }

    private func logColor(for entry: String) -> Color {
        if entry.contains("ОШИБКА") || entry.contains("Сбой") || entry.contains("failed") {
            return ObsidianTheme.danger
        } else if entry.contains("успешно") || entry.contains("Подключено") || entry.contains("active") {
            return ObsidianTheme.accent
        } else if entry.contains("Добавлен") || entry.contains("Выбран") {
            return ObsidianTheme.accentCyan
        } else {
            return ObsidianTheme.primaryText.opacity(0.8)
        }
    }

    // MARK: - Security Modal

    private var securityDetailsSheet: some View {
        NavigationStack {
            ZStack {
                MineralBackground()
                VStack(spacing: 20) {
                    VStack(spacing: 8) {
                        Image(systemName: "lock.shield.fill")
                            .font(.system(size: 52))
                            .foregroundStyle(ObsidianTheme.accent)
                        Text("Obsidian Reality Engine")
                            .font(.system(.title3, design: .rounded, weight: .bold))
                            .foregroundStyle(ObsidianTheme.primaryText)
                        Text("Шифрование следующего поколения для защиты мобильного трафика")
                            .font(.subheadline)
                            .foregroundStyle(ObsidianTheme.secondaryText)
                            .multilineTextAlignment(.center)
                    }
                    .padding(.top, 20)

                    VStack(spacing: 12) {
                        securityRow(title: "Протокол", value: "Obsidian v1 / Reality")
                        securityRow(title: "Шифрование данных", value: "ChaCha20-Poly1305 AEAD")
                        securityRow(title: "Защита заголовков", value: "AES-ECB Header Masking")
                        securityRow(title: "Размер кадра MTU", value: "1280 байт (Zero Drop)")
                        securityRow(title: "Анти-DPI паддинг", value: "Dynamic Bucket Padding")
                    }
                    .padding(18)
                    .appleGlassCard(cornerRadius: 20, highlight: 0.2)

                    Spacer()

                    Button("Закрыть") { showSecurityDetails = false }
                        .font(.headline)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 14)
                        .background(ObsidianTheme.accent, in: RoundedRectangle(cornerRadius: 16))
                        .foregroundStyle(Color.black)
                }
                .padding(20)
            }
            .navigationTitle("Параметры защиты")
            .navigationBarTitleDisplayMode(.inline)
        }
        .presentationDetents([.medium])
    }

    private func securityRow(title: String, value: String) -> some View {
        HStack {
            Text(title)
                .font(.system(size: 13, design: .rounded))
                .foregroundStyle(ObsidianTheme.secondaryText)
            Spacer()
            Text(value)
                .font(.system(size: 13, weight: .semibold, design: .monospaced))
                .foregroundStyle(ObsidianTheme.primaryText)
        }
    }

    // MARK: - Actions

    private func pingCurrentServer() {
        if let ep = profiles.selectedProfile?.endpoint {
            pingService.measure(endpoint: ep)
        }
    }

    private func triggerHaptic() {
        guard haptics else { return }
        let generator = UIImpactFeedbackGenerator(style: .light)
        generator.impactOccurred()
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
                .foregroundStyle(ObsidianTheme.danger)
        }
        .padding(14)
        .background(ObsidianTheme.danger.opacity(0.12), in: RoundedRectangle(cornerRadius: 16, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .stroke(ObsidianTheme.danger.opacity(0.24), lineWidth: 1)
        }
    }
}
