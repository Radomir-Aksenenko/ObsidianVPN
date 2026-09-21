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

    deinit {
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
        do {
            let manager = try await configuredManager(for: profile)
            self.manager = manager
            observeStatus()
            try manager.connection.startVPNTunnel()
        } catch {
            state = .failed(error.localizedDescription)
        }
    }

    private func disconnect() {
        state = .disconnecting
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
        tunnelProtocol.providerBundleIdentifier = "com.obsidian.vpn.PacketTunnel"
        tunnelProtocol.serverAddress = profile.endpoint
        tunnelProtocol.providerConfiguration = [
            "configURI": profile.configURI,
            "profileName": profile.name
        ]
        tunnelProtocol.disconnectOnSleep = false
        let preventBypass = sharedDefaults.object(forKey: "settings.killSwitch") as? Bool ?? true
        tunnelProtocol.includeAllNetworks = preventBypass
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
        case .connecting, .reasserting:
            state = .preparing
        case .disconnecting:
            state = .disconnecting
        case .disconnected, .invalid:
            connectedAt = nil
            downloadBytesPerSecond = 0
            uploadBytesPerSecond = 0
            state = .disconnected
        @unknown default:
            state = .disconnected
        }
    }
}
