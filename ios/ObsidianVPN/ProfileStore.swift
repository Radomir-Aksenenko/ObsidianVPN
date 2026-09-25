import Foundation

@MainActor
final class ProfileStore: ObservableObject {
    @Published private(set) var profiles: [VPNProfile] = []
    @Published var selectedID: VPNProfile.ID?

    private let sharedDefaults: UserDefaults
    private let standardDefaults = UserDefaults.standard
    private let profilesKey = "vpn.profiles.v1"
    private let selectedKey = "vpn.selected-profile.v1"
    private let activeProfileKey = "vpn.active-profile.v1"
    private let vaultAccount = "saved-profiles.v1"

    init(defaults: UserDefaults = UserDefaults(suiteName: "group.com.obsidian.vpn") ?? .standard) {
        self.sharedDefaults = defaults
        load()
    }

    var selectedProfile: VPNProfile? {
        profiles.first(where: { $0.id == selectedID }) ?? profiles.first
    }

    func add(_ profile: VPNProfile) {
        profiles.removeAll(where: { $0.configURI == profile.configURI || $0.id == profile.id })
        profiles.insert(profile, at: 0)
        selectedID = profile.id
        persist()
        LogStore.shared.log("Добавлен сервер: \(profile.name) (\(profile.endpoint))")
    }

    func remove(_ profile: VPNProfile) {
        let name = profile.name
        profiles.removeAll(where: { $0.id == profile.id })
        if selectedID == profile.id { selectedID = profiles.first?.id }
        persist()
        LogStore.shared.log("Удален сервер: \(name)")
    }

    func select(_ profile: VPNProfile) {
        selectedID = profile.id
        persist()
        LogStore.shared.log("Выбран сервер: \(profile.name)")
    }

    func toggleFavorite(_ profile: VPNProfile) {
        guard let index = profiles.firstIndex(where: { $0.id == profile.id }) else { return }
        profiles[index].isFavorite.toggle()
        profiles.sort {
            if $0.isFavorite != $1.isFavorite { return $0.isFavorite }
            return $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
        }
        persist()
    }

    private func load() {
        var loadedProfiles: [VPNProfile]?

        // 1. Try shared defaults
        if let data = sharedDefaults.data(forKey: profilesKey),
           let decoded = try? JSONDecoder().decode([VPNProfile].self, from: data), !decoded.isEmpty {
            loadedProfiles = decoded
        }
        // 2. Try standard defaults
        else if let data = standardDefaults.data(forKey: profilesKey),
                let decoded = try? JSONDecoder().decode([VPNProfile].self, from: data), !decoded.isEmpty {
            loadedProfiles = decoded
        }
        // 3. Try Keychain
        else if let data = KeychainVault.read(account: vaultAccount),
                let decoded = try? JSONDecoder().decode([VPNProfile].self, from: data), !decoded.isEmpty {
            loadedProfiles = decoded
        }

        if let loadedProfiles {
            profiles = loadedProfiles
            LogStore.shared.log("Загружено сохраненных серверов: \(profiles.count)")
        } else {
            LogStore.shared.log("Список сохраненных серверов пуст")
        }

        // Load selected profile ID
        if let rawID = sharedDefaults.string(forKey: selectedKey) ?? standardDefaults.string(forKey: selectedKey) {
            selectedID = UUID(uuidString: rawID)
        }
        if selectedProfile == nil {
            selectedID = profiles.first?.id
        }
    }

    private func persist() {
        guard let data = try? JSONEncoder().encode(profiles) else { return }

        // Write to both UserDefaults stores so sideloaded apps never lose data
        sharedDefaults.set(data, forKey: profilesKey)
        standardDefaults.set(data, forKey: profilesKey)

        if let active = selectedProfile, let activeData = try? JSONEncoder().encode(active) {
            sharedDefaults.set(activeData, forKey: activeProfileKey)
            standardDefaults.set(activeData, forKey: activeProfileKey)
        }

        sharedDefaults.set(selectedID?.uuidString, forKey: selectedKey)
        standardDefaults.set(selectedID?.uuidString, forKey: selectedKey)

        // Best effort to Keychain
        try? KeychainVault.save(data, account: vaultAccount)
    }
}
