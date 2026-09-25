import Foundation
import NetworkExtension
import Darwin

#if canImport(Obsidian)
import Obsidian
#endif

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let engine = ObsidianPacketEngine()
    private var isRunning = false
    private let receiveQueue = DispatchQueue(label: "com.obsidian.vpn.packet-receive", qos: .userInteractive)

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        guard let tunnelProtocol = protocolConfiguration as? NETunnelProviderProtocol,
              let configURI = tunnelProtocol.providerConfiguration?["configURI"] as? String else {
            completionHandler(TunnelProviderError.missingConfiguration)
            return
        }

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: tunnelProtocol.serverAddress ?? "127.0.0.1")
        let ipv4 = NEIPv4Settings(addresses: ["10.8.0.2"], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [.default()]
        settings.ipv4Settings = ipv4
        settings.dnsSettings = NEDNSSettings(servers: ["1.1.1.1", "8.8.8.8"])
        settings.mtu = 1420

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self else { return }
            if let error {
                completionHandler(error)
                return
            }

            do {
                try self.engine.start(configURI: configURI, mtu: 1420)
                self.isRunning = true
                self.readFromSystem()
                self.readFromEngine()
                completionHandler(nil)
            } catch {
                completionHandler(error)
            }
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        isRunning = false
        engine.stop()
        completionHandler()
    }

    private func readFromSystem() {
        guard isRunning else { return }
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self, self.isRunning else { return }
            for packet in packets {
                try? self.engine.inject(packet)
            }
            self.readFromSystem()
        }
    }

    private func readFromEngine() {
        receiveQueue.async { [weak self] in
            guard let self else { return }
            while self.isRunning {
                guard let packet = try? self.engine.receive(timeoutMilliseconds: 500), !packet.isEmpty else { continue }
                let version = packet.first.map { $0 >> 4 } ?? 4
                let family = NSNumber(value: version == 6 ? AF_INET6 : AF_INET)
                self.packetFlow.writePackets([packet], withProtocols: [family])
            }
        }
    }
}

private enum TunnelProviderError: LocalizedError {
    case missingConfiguration
    case missingFramework
    case engine(String)

    var errorDescription: String? {
        switch self {
        case .missingConfiguration: "Профиль Obsidian не содержит configURI."
        case .missingFramework: "Добавьте Obsidian.xcframework в таргет PacketTunnel."
        case let .engine(message): message
        }
    }
}

private final class ObsidianPacketEngine {
    private var sessionID: String?

    func start(configURI: String, mtu: Int) throws {
        #if canImport(Obsidian)
        var error: NSError?
        sessionID = MobileStartPacketTunnel(configURI, mtu, nil, nil, nil, &error)
        if let error { throw TunnelProviderError.engine(error.localizedDescription) }
        guard sessionID != nil else { throw TunnelProviderError.engine("Ядро не вернуло идентификатор сессии.") }
        #else
        throw TunnelProviderError.missingFramework
        #endif
    }

    func inject(_ packet: Data) throws {
        #if canImport(Obsidian)
        guard let sessionID else { return }
        var error: NSError?
        MobileInjectPacket(sessionID, packet, &error)
        if let error { throw TunnelProviderError.engine(error.localizedDescription) }
        #endif
    }

    func receive(timeoutMilliseconds: Int) throws -> Data {
        #if canImport(Obsidian)
        guard let sessionID else { return Data() }
        var error: NSError?
        let packet = MobileReceivePacket(sessionID, timeoutMilliseconds, &error) ?? Data()
        if let error { throw TunnelProviderError.engine(error.localizedDescription) }
        return packet
        #else
        return Data()
        #endif
    }

    func stop() {
        #if canImport(Obsidian)
        guard let sessionID else { return }
        var error: NSError?
        MobileStopTunnel(sessionID, &error)
        self.sessionID = nil
        #endif
    }
}
