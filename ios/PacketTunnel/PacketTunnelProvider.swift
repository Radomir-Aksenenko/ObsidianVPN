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
        let sharedDefaults = UserDefaults(suiteName: "group.com.obsidian.vpn") ?? .standard
        sharedDefaults.removeObject(forKey: "lastTunnelError")

        tunnelLog("Запрос на запуск туннеля...")

        var configURI = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?["configURI"] as? String
        if configURI == nil || configURI?.isEmpty == true {
            configURI = options?["configURI"] as? String
        }

        // Fallback to active config URI saved in shared defaults
        if configURI == nil || configURI?.isEmpty == true {
            if let activeURI = sharedDefaults.string(forKey: "vpn.active-config-uri.v1"), !activeURI.isEmpty {
                configURI = activeURI
                tunnelLog("Конфигурация получена из активного профиля")
            }
        }

        guard let uri = configURI, !uri.isEmpty else {
            let err = TunnelProviderError.missingConfiguration
            sharedDefaults.set(err.localizedDescription, forKey: "lastTunnelError")
            tunnelLog("ОШИБКА: отсутствует конфигурация configURI")
            completionHandler(err)
            return
        }

        tunnelLog("Ключ получен (\(uri.prefix(15))...)")

        let rawServer = (protocolConfiguration as? NETunnelProviderProtocol)?.serverAddress ?? ""
        let serverIP = extractServerIP(from: uri, fallback: rawServer)
        tunnelLog("Адрес шлюза/сервера: \(serverIP ?? "10.8.0.1")")

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: serverIP ?? "10.8.0.1")
        let ipv4 = NEIPv4Settings(addresses: ["10.8.0.2"], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [.default()]

        if let serverIP {
            ipv4.excludedRoutes = [NEIPv4Route(destinationAddress: serverIP, subnetMask: "255.255.255.255")]
        }

        settings.ipv4Settings = ipv4

        let dns = NEDNSSettings(servers: ["1.1.1.1", "8.8.8.8"])
        dns.matchDomains = [""]
        settings.dnsSettings = dns
        settings.mtu = 1420

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self else { return }
            if let error {
                let msg = "Ошибка сетевых настроек: \(error.localizedDescription)"
                sharedDefaults.set(msg, forKey: "lastTunnelError")
                tunnelLog("ОШИБКА: \(msg)")
                completionHandler(error)
                return
            }

            tunnelLog("Сетевые настройки применены, запуск ядра Obsidian...")
            do {
                try self.engine.start(configURI: uri, mtu: 1420)
                self.isRunning = true
                self.readFromSystem()
                self.readFromEngine()
                tunnelLog("Ядро Obsidian успешно запущено, туннель активен")
                completionHandler(nil)
            } catch {
                let msg = "Ошибка ядра: \(error.localizedDescription)"
                sharedDefaults.set(msg, forKey: "lastTunnelError")
                tunnelLog("ОШИБКА: \(msg)")
                completionHandler(error)
            }
        }
    }

    private func extractServerIP(from uri: String, fallback: String) -> String? {
        let host: String
        if let components = URLComponents(string: uri), let h = components.host, !h.isEmpty {
            host = h
        } else if !fallback.isEmpty {
            host = fallback
        } else {
            return nil
        }

        var cleaned = host
        if let colonIndex = cleaned.firstIndex(of: ":") {
            cleaned = String(cleaned[..<colonIndex])
        }
        cleaned = cleaned.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))

        var sin = sockaddr_in()
        if cleaned.withCString({ inet_pton(AF_INET, $0, &sin.sin_addr) }) == 1 {
            return cleaned
        }

        var hints = addrinfo(
            ai_flags: 0,
            ai_family: AF_INET,
            ai_socktype: SOCK_STREAM,
            ai_protocol: 0,
            ai_addrlen: 0,
            ai_canonname: nil,
            ai_addr: nil,
            ai_next: nil
        )
        var res: UnsafeMutablePointer<addrinfo>?
        if getaddrinfo(cleaned, nil, &hints, &res) == 0, let first = res {
            defer { freeaddrinfo(res) }
            let addr = first.pointee.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
            var ipBuf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            var ipAddr = addr.sin_addr
            if inet_ntop(AF_INET, &ipAddr, &ipBuf, socklen_t(INET_ADDRSTRLEN)) != nil {
                return String(cString: ipBuf)
            }
        }

        return nil
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

private func tunnelLog(_ message: String) {
    let formatter = DateFormatter()
    formatter.dateFormat = "HH:mm:ss"
    let timestamp = formatter.string(from: Date())
    let line = "[\(timestamp)] [Tunnel] \(message)"

    let defaults = UserDefaults(suiteName: "group.com.obsidian.vpn") ?? .standard
    let logsKey = "vpn.runtime.logs.v1"
    var logs = defaults.stringArray(forKey: logsKey) ?? []
    logs.append(line)
    if logs.count > 120 {
        logs.removeFirst(logs.count - 120)
    }
    defaults.set(logs, forKey: logsKey)
}
