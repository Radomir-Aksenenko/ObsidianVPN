import Foundation
import Network

@MainActor
final class PingService: ObservableObject {
    static let shared = PingService()

    @Published var latencyMs: Int? = nil
    @Published var isPinging: Bool = false

    func measure(endpoint: String) {
        let (host, port) = parseHostPort(endpoint)
        guard !host.isEmpty else { return }
        measure(host: host, port: port)
    }

    func measure(host: String, port: Int = 8443) {
        guard !host.isEmpty, !isPinging else { return }
        isPinging = true

        let startTime = DispatchTime.now()
        let nwHost = NWEndpoint.Host(host)
        let nwPort = NWEndpoint.Port(rawValue: UInt16(port > 0 && port <= 65535 ? port : 8443)) ?? 8443

        let params = NWParameters.tcp
        params.preferNoProxies = true
        let connection = NWConnection(host: nwHost, port: nwPort, using: params)

        let queue = DispatchQueue(label: "com.obsidian.vpn.ping")
        connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                let elapsed = DispatchTime.now().uptimeNanoseconds - startTime.uptimeNanoseconds
                let ms = Int(elapsed / 1_000_000)
                connection.cancel()
                Task { @MainActor in
                    self?.latencyMs = max(1, ms)
                    self?.isPinging = false
                }
            case .failed:
                connection.cancel()
                Task { @MainActor in
                    self?.isPinging = false
                }
            default:
                break
            }
        }

        connection.start(queue: queue)

        queue.asyncAfter(deadline: .now() + 2.5) { [weak connection, weak self] in
            if connection?.state != .ready && connection?.state != .cancelled {
                connection?.cancel()
                Task { @MainActor in
                    self?.isPinging = false
                }
            }
        }
    }

    private func parseHostPort(_ endpoint: String) -> (String, Int) {
        var clean = endpoint.trimmingCharacters(in: .whitespacesAndNewlines)
        if clean.hasPrefix("[") {
            if let closeIdx = clean.firstIndex(of: "]") {
                let host = String(clean[clean.index(after: clean.startIndex)..<closeIdx])
                let rest = clean[clean.index(after: closeIdx)...]
                if rest.hasPrefix(":") {
                    let port = Int(rest.dropFirst()) ?? 8443
                    return (host, port)
                }
                return (host, 8443)
            }
        }
        if let colonIdx = clean.lastIndex(of: ":") {
            let host = String(clean[..<colonIdx])
            let port = Int(clean[clean.index(after: colonIdx)...]) ?? 8443
            return (host, port)
        }
        return (clean, 8443)
    }
}
