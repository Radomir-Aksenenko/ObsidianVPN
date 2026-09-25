import Foundation

@MainActor
final class LogStore: ObservableObject {
    static let shared = LogStore()

    @Published private(set) var entries: [String] = []

    private let sharedDefaults = UserDefaults(suiteName: "group.com.obsidian.vpn") ?? .standard
    private let standardDefaults = UserDefaults.standard
    private let logsKey = "vpn.runtime.logs.v1"
    private var timer: Timer?

    init() {
        loadStoredLogs()
        log("Приложение Obsidian запущено")
        timer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            Task { @MainActor in
                self?.loadStoredLogs()
            }
        }
    }

    deinit {
        timer?.invalidate()
    }

    func log(_ message: String) {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        let timestamp = formatter.string(from: Date())
        let line = "[\(timestamp)] \(message)"

        entries.append(line)
        if entries.count > 120 {
            entries.removeFirst(entries.count - 120)
        }
        saveStoredLogs()
    }

    func clear() {
        entries.removeAll()
        sharedDefaults.removeObject(forKey: logsKey)
        standardDefaults.removeObject(forKey: logsKey)
    }

    private func loadStoredLogs() {
        let stored = (sharedDefaults.stringArray(forKey: logsKey) ?? standardDefaults.stringArray(forKey: logsKey)) ?? []
        if stored != entries && !stored.isEmpty {
            entries = stored
        }
    }

    private func saveStoredLogs() {
        sharedDefaults.set(entries, forKey: logsKey)
        standardDefaults.set(entries, forKey: logsKey)
    }
}
