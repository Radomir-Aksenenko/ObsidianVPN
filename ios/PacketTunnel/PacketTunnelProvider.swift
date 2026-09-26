import Foundation
import NetworkExtension
import Darwin

#if canImport(Obsidian)
import Obsidian
#endif

private struct ObsidianURIComponents {
    var scheme: String = "obsidian"
    var user: String? = nil
    var host: String = ""
    var port: Int? = nil
    var queryItems: [String: String] = [:]
    var fragment: String? = nil

    var endpoint: String {
        guard !host.isEmpty else { return "" }
        if let port {
            if host.contains(":") && !host.hasPrefix("[") {
                return "[\(host)]:\(port)"
            }
            return "\(host):\(port)"
        }
        return host
    }

    static func parse(_ raw: String) -> ObsidianURIComponents? {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }

        if trimmed.hasPrefix("OBSDN-") {
            var comp = ObsidianURIComponents()
            comp.scheme = "obsdn"
            comp.host = "OBSDN Key"
            comp.fragment = String(trimmed.prefix(20))
            return comp
        }

        var work = trimmed
        var scheme = "obsidian"
        if let schemeColon = work.range(of: "://") {
            scheme = String(work[..<schemeColon.lowerBound]).lowercased()
            work = String(work[schemeColon.upperBound...])
        } else if work.hasPrefix("vpn://") {
            scheme = "vpn"
            work = String(work.dropFirst(6))
        }

        if scheme == "vpn" && work.lowercased().hasPrefix("obsidian/") {
            work = String(work.dropFirst(9))
            scheme = "obsidian"
        }

        var fragment: String? = nil
        if let hashIdx = work.firstIndex(of: "#") {
            let rawFrag = String(work[work.index(after: hashIdx)...])
            fragment = rawFrag.removingPercentEncoding ?? rawFrag
            work = String(work[..<hashIdx])
        }

        var queryItems: [String: String] = [:]
        if let qIdx = work.firstIndex(of: "?") {
            let rawQuery = String(work[work.index(after: qIdx)...])
            work = String(work[..<qIdx])
            for pair in rawQuery.split(separator: "&") {
                let parts = pair.split(separator: "=", maxSplits: 1).map(String.init)
                if parts.count == 2 {
                    let k = parts[0].removingPercentEncoding ?? parts[0]
                    let v = parts[1].removingPercentEncoding ?? parts[1]
                    queryItems[k] = v
                } else if parts.count == 1 {
                    let k = parts[0].removingPercentEncoding ?? parts[0]
                    queryItems[k] = ""
                }
            }
        }

        while work.hasSuffix("/") {
            work.removeLast()
        }

        var user: String? = nil
        if let atIdx = work.lastIndex(of: "@") {
            user = String(work[..<atIdx])
            work = String(work[work.index(after: atIdx)...])
        }

        var host = ""
        var port: Int? = nil

        if work.hasPrefix("[") {
            if let closeBracket = work.firstIndex(of: "]") {
                host = String(work[work.index(after: work.startIndex)..<closeBracket])
                let afterBracket = work[work.index(after: closeBracket)...]
                if afterBracket.hasPrefix(":") {
                    port = Int(afterBracket.dropFirst())
                }
            } else {
                host = work
            }
        } else if let colonIdx = work.lastIndex(of: ":") {
            let potentialPort = String(work[work.index(after: colonIdx)...])
            if let p = Int(potentialPort) {
                port = p
                host = String(work[..<colonIdx])
            } else {
                host = work
            }
        } else {
            host = work
        }

        host = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))

        var result = ObsidianURIComponents()
        result.scheme = scheme
        result.user = user
        result.host = host
        result.port = port
        result.queryItems = queryItems
        result.fragment = fragment
        return result
    }
}

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let engine = ObsidianPacketEngine()
    private var isRunning = false
    private let receiveQueue = DispatchQueue(label: "com.obsidian.vpn.packet-receive", qos: .userInteractive)
    private var totalTxBytes: Int64 = 0
    private var totalRxBytes: Int64 = 0
    private var lastStatsFlush: Date = Date()
    private let statsLock = NSLock()

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        statsLock.lock()
        totalTxBytes = 0
        totalRxBytes = 0
        lastStatsFlush = Date()
        statsLock.unlock()

        let sharedDefaults = UserDefaults(suiteName: "group.com.obsidian.vpn") ?? .standard
        sharedDefaults.removeObject(forKey: "lastTunnelError")
        sharedDefaults.set(0, forKey: "vpn.stats.rx")
        sharedDefaults.set(0, forKey: "vpn.stats.tx")

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
        // MTU 1280 ensures zero fragmentation and no PMTU black hole across any mobile APN (LTE/5G)
        settings.mtu = 1280

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self else { return }
            if let error {
                let msg = "Ошибка сетевых настроек: \(error.localizedDescription)"
                sharedDefaults.set(msg, forKey: "lastTunnelError")
                tunnelLog("ОШИБКА: \(msg)")
                completionHandler(error)
                return
            }

            tunnelLog("Сетевые настройки применены (MTU 1280), запуск ядра Obsidian...")
            do {
                try self.engine.start(configURI: uri, mtu: 1280)
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
        if let parsed = ObsidianURIComponents.parse(uri), !parsed.host.isEmpty {
            host = parsed.host
        } else if let components = URLComponents(string: uri), let h = components.host, !h.isEmpty {
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
        let reasonStr = stopReasonString(reason)
        tunnelLog("Туннель остановлен iOS. Причина: \(reasonStr)")
        if reason != .userInitiated && reason != .none {
            let sharedDefaults = UserDefaults(suiteName: "group.com.obsidian.vpn") ?? .standard
            sharedDefaults.set("Остановлено системой (\(reasonStr))", forKey: "lastTunnelError")
        }
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        statsLock.lock()
        let curTx = totalTxBytes
        let curRx = totalRxBytes
        statsLock.unlock()

        let statsDict: [String: Any] = [
            "tx": curTx,
            "rx": curRx,
            "running": isRunning
        ]
        let data = try? JSONSerialization.data(withJSONObject: statsDict)
        completionHandler?(data)
    }

    private func stopReasonString(_ reason: NEProviderStopReason) -> String {
        switch reason {
        case .none: return "Обычное завершение"
        case .userInitiated: return "Пользователь остановил VPN"
        case .providerFailed: return "Сбой провайдера (providerFailed)"
        case .noNetworkAvailable: return "Сеть недоступна (noNetworkAvailable)"
        case .unrecoverableNetworkChange: return "Смена сети (unrecoverableNetworkChange)"
        case .providerDisabled: return "Конфигурация отключена (providerDisabled)"
        case .authenticationCanceled: return "Аутентификация отменена"
        case .configurationFailed: return "Ошибка конфигурации (configurationFailed)"
        case .idleTimeout: return "Таймаут неактивности (idleTimeout)"
        case .configurationDisabled: return "Профиль отключен (configurationDisabled)"
        case .configurationRemoved: return "Профиль удален (configurationRemoved)"
        case .superceded: return "Вытеснено другим VPN (superceded)"
        case .userLogout: return "Выход пользователя"
        case .userSwitch: return "Смена пользователя"
        case .connectionFailed: return "Сбой сетевого соединения (connectionFailed)"
        case .sleep: return "Переход устройства в сон (sleep)"
        case .appUpdate: return "Обновление приложения (appUpdate)"
        @unknown default: return "Код причины: \(reason.rawValue)"
        }
    }

    private func readFromSystem() {
        guard isRunning else { return }
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self, self.isRunning else { return }
            var batchBytes: Int64 = 0
            for packet in packets {
                try? self.engine.inject(packet)
                batchBytes += Int64(packet.count)
            }
            if batchBytes > 0 {
                self.statsLock.lock()
                self.totalTxBytes += batchBytes
                let now = Date()
                let shouldFlush = now.timeIntervalSince(self.lastStatsFlush) >= 1.5
                let curTx = self.totalTxBytes
                let curRx = self.totalRxBytes
                if shouldFlush {
                    self.lastStatsFlush = now
                }
                self.statsLock.unlock()

                if shouldFlush {
                    let defaults = UserDefaults(suiteName: "group.com.obsidian.vpn") ?? .standard
                    defaults.set(curTx, forKey: "vpn.stats.tx")
                    defaults.set(curRx, forKey: "vpn.stats.rx")
                }
            }
            self.readFromSystem()
        }
    }

    private func readFromEngine() {
        receiveQueue.async { [weak self] in
            guard let self else { return }
            var batchPackets: [Data] = []
            var batchProtocols: [NSNumber] = []
            batchPackets.reserveCapacity(64)
            batchProtocols.reserveCapacity(64)

            while self.isRunning {
                guard let firstPacket = try? self.engine.receive(timeoutMilliseconds: 200), !firstPacket.isEmpty else {
                    continue
                }

                batchPackets.removeAll(keepingCapacity: true)
                batchProtocols.removeAll(keepingCapacity: true)

                let firstVer = firstPacket.first.map({ $0 >> 4 }) ?? 4
                batchPackets.append(firstPacket)
                batchProtocols.append(NSNumber(value: firstVer == 6 ? AF_INET6 : AF_INET))
                var rxBytes: Int64 = Int64(firstPacket.count)

                // High-performance batch draining: pull up to 63 additional packets without waiting
                while batchPackets.count < 64 {
                    guard let nextPacket = try? self.engine.receive(timeoutMilliseconds: 0), !nextPacket.isEmpty else {
                        break
                    }
                    let ver = nextPacket.first.map({ $0 >> 4 }) ?? 4
                    batchPackets.append(nextPacket)
                    batchProtocols.append(NSNumber(value: ver == 6 ? AF_INET6 : AF_INET))
                    rxBytes += Int64(nextPacket.count)
                }

                self.packetFlow.writePackets(batchPackets, withProtocols: batchProtocols)

                self.statsLock.lock()
                self.totalRxBytes += rxBytes
                let now = Date()
                let shouldFlush = now.timeIntervalSince(self.lastStatsFlush) >= 1.5
                let curTx = self.totalTxBytes
                let curRx = self.totalRxBytes
                if shouldFlush {
                    self.lastStatsFlush = now
                }
                self.statsLock.unlock()

                if shouldFlush {
                    let defaults = UserDefaults(suiteName: "group.com.obsidian.vpn") ?? .standard
                    defaults.set(curTx, forKey: "vpn.stats.tx")
                    defaults.set(curRx, forKey: "vpn.stats.rx")
                }
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
