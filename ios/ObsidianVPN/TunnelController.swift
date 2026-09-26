import Foundation
import NetworkExtension

@MainActor
final class TunnelController: ObservableObject {
    enum State: Equatable {
        case disconnected
        case preparing
        case connected
        case disconnecting
        case failed(String)

        var isBusy: Bool { self == .preparing || self == .disconnecting }
    }

    @Published private(set) var state: State = .disconnected
    @Published private(set) var connectedAt: Date?
    @Published private(set) var downloadBytesPerSecond: Int64 = 0
    @Published private(set) var uploadBytesPerSecond: Int64 = 0

    private var manager: NETunnelProviderManager?
    private var observer: NSObjectProtocol?
    private let sharedDefaults = UserDefaults(suiteName: "group.com.obsidian.vpn") ?? .standard
    private var statsTimer: Timer?
    private var lastRx: Int = 0
    private var lastTx: Int = 0
    private var lastStatsDate = Date()

    deinit {
        statsTimer?.invalidate()
        if let observer { NotificationCenter.default.removeObserver(observer) }
    }

    func prepare() async {
        do {
            manager = try await loadManager()
            observeStatus()
            apply(manager?.connection.status ?? .invalid)
        } catch {
            state = .failed(error.localizedDescription)
        }
    }

    func toggle(profile: VPNProfile?) async {
        switch state {
        case .connected, .preparing:
            disconnect()
        case .disconnecting:
            return
        case .disconnected, .failed:
            guard let profile else {
                state = .failed("Сначала добавьте сервер.")
                return
            }
            await connect(profile)
        }
    }

    func clearError() {
        if case .failed = state { state = .disconnected }
    }

    private func connect(_ profile: VPNProfile) async {
        state = .preparing
        sharedDefaults.removeObject(forKey: "lastTunnelError")
        LogStore.shared.log("Инициализация подключения к \(profile.name)...")
        do {
            let manager = try await configuredManager(for: profile)
            self.manager = manager
            observeStatus()
            let options: [String: NSObject] = [
                "configURI": profile.configURI as NSString,
                "profileName": profile.name as NSString
            ]
            LogStore.shared.log("Запрос startVPNTunnel к системному расширению...")
            try manager.connection.startVPNTunnel(options: options)
            LogStore.shared.log("Команда запуска передана в iOS")
        } catch {
            LogStore.shared.log("Ошибка запуска: \(error.localizedDescription)")
            state = .failed(error.localizedDescription)
        }
    }

    private func disconnect() {
        state = .disconnecting
        LogStore.shared.log("Остановка туннеля...")
        manager?.connection.stopVPNTunnel()
    }

    private func loadManager() async throws -> NETunnelProviderManager {
        try await withCheckedThrowingContinuation { continuation in
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume(returning: managers?.first ?? NETunnelProviderManager()) }
            }
        }
    }

    private func configuredManager(for profile: VPNProfile) async throws -> NETunnelProviderManager {
        let manager = try await loadManager()
        let tunnelProtocol = NETunnelProviderProtocol()

        let appBundleId = Bundle.main.bundleIdentifier ?? "com.obsidian.vpn"
        let pluginBundleId: String
        if let pluginURL = Bundle.main.builtInPlugInsURL?.appendingPathComponent("PacketTunnel.appex"),
           let pluginBundle = Bundle(url: pluginURL),
           let id = pluginBundle.bundleIdentifier {
            pluginBundleId = id
        } else {
            pluginBundleId = "\(appBundleId).PacketTunnel"
        }
        tunnelProtocol.providerBundleIdentifier = pluginBundleId
        tunnelProtocol.serverAddress = profile.endpoint
        tunnelProtocol.providerConfiguration = [
            "configURI": profile.configURI,
            "profileName": profile.name
        ]
        tunnelProtocol.disconnectOnSleep = false
        tunnelProtocol.includeAllNetworks = false
        tunnelProtocol.excludeLocalNetworks = false

        manager.localizedDescription = "Obsidian — \(profile.name)"
        manager.protocolConfiguration = tunnelProtocol
        manager.isEnabled = true
        let autoConnect = sharedDefaults.bool(forKey: "settings.autoConnect")
        manager.onDemandRules = autoConnect ? [NEOnDemandRuleConnect()] : []
        manager.isOnDemandEnabled = autoConnect

        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.saveToPreferences { error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume() }
            }
        }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.loadFromPreferences { error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume() }
            }
        }
        return manager
    }

    private func observeStatus() {
        if let observer { NotificationCenter.default.removeObserver(observer) }
        observer = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: nil,
            queue: .main
        ) { [weak self] note in
            guard let connection = note.object as? NEVPNConnection else { return }
            Task { @MainActor in self?.apply(connection.status) }
        }
    }

    private func apply(_ status: NEVPNStatus) {
        switch status {
        case .connected:
            if connectedAt == nil { connectedAt = Date() }
            state = .connected
            startStatsMonitoring()
            LogStore.shared.log("Статус: Подключено (VPN активен)")
        case .connecting:
            state = .preparing
            LogStore.shared.log("Статус: Соединение с сервером...")
        case .reasserting:
            state = .preparing
            LogStore.shared.log("Статус: Переподключение...")
        case .disconnecting:
            state = .disconnecting
            stopStatsMonitoring()
            LogStore.shared.log("Статус: Отключение...")
        case .disconnected:
            connectedAt = nil
            stopStatsMonitoring()
            if state == .preparing {
                let err = sharedDefaults.string(forKey: "lastTunnelError")
                if let err, !err.isEmpty {
                    sharedDefaults.removeObject(forKey: "lastTunnelError")
                    LogStore.shared.log("Сбой: \(err)")
                    state = .failed(err)
                } else {
                    let defaultErr = "Не удалось установить туннель к серверу. Проверьте ключ и доступность хоста."
                    LogStore.shared.log("Сбой: \(defaultErr)")
                    state = .failed(defaultErr)
                }
            } else {
                state = .disconnected
                LogStore.shared.log("Статус: Отключено")
            }
        case .invalid:
            connectedAt = nil
            stopStatsMonitoring()
            state = .disconnected
            LogStore.shared.log("Статус: Профиль недействителен (invalid)")
        @unknown default:
            stopStatsMonitoring()
            state = .disconnected
        }
    }

    private func startStatsMonitoring() {
        stopStatsMonitoring()
        lastRx = sharedDefaults.integer(forKey: "vpn.stats.rx")
        lastTx = sharedDefaults.integer(forKey: "vpn.stats.tx")
        lastStatsDate = Date()

        statsTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            Task { @MainActor in
                self?.sampleStats()
            }
        }
    }

    private func stopStatsMonitoring() {
        statsTimer?.invalidate()
        statsTimer = nil
        downloadBytesPerSecond = 0
        uploadBytesPerSecond = 0
    }

    private func sampleStats() {
        guard state == .connected else { return }
        let now = Date()
        let dt = max(0.5, now.timeIntervalSince(lastStatsDate))
        let curRx = sharedDefaults.integer(forKey: "vpn.stats.rx")
        let curTx = sharedDefaults.integer(forKey: "vpn.stats.tx")

        if curRx >= lastRx {
            downloadBytesPerSecond = Int64(Double(curRx - lastRx) / dt)
        }
        if curTx >= lastTx {
            uploadBytesPerSecond = Int64(Double(curTx - lastTx) / dt)
        }

        lastRx = curRx
        lastTx = curTx
        lastStatsDate = now
    }
}
