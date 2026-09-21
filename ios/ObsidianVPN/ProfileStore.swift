import Foundation

@MainActor
final class ProfileStore: ObservableObject {
    @Published private(set) var profiles: [VPNProfile] = []
    @Published var selectedID: VPNProfile.ID?

    private let defaults: UserDefaults
    private let profilesKey = "vpn.profiles.v1"
    private let selectedKey = "vpn.selected-profile.v1"
    private let vaultAccount = "saved-profiles.v1"

    init(defaults: UserDefaults = UserDefaults(suiteName: "group.com.obsidian.vpn") ?? .standard) {
        self.defaults = defaults
        load()
    }

    var selectedProfile: VPNProfile? {
        profiles.first(where: { $0.id == selectedID }) ?? profiles.first
    }

    func add(_ profile: VPNProfile) {
        profiles.removeAll(where: { $0.configURI == profile.configURI })
        profiles.insert(profile, at: 0)
        selectedID = profile.id
        persist()
    }

    func remove(_ profile: VPNProfile) {
        profiles.removeAll(where: { $0.id == profile.id })
        if selectedID == profile.id { selectedID = profiles.first?.id }
        persist()
    }

    func select(_ profile: VPNProfile) {
        selectedID = profile.id
        persist()
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
        if let data = KeychainVault.read(account: vaultAccount),
           let decoded = try? JSONDecoder().decode([VPNProfile].self, from: data) {
            profiles = decoded
        } else if let legacyData = defaults.data(forKey: profilesKey),
                  let decoded = try? JSONDecoder().decode([VPNProfile].self, from: legacyData) {
            profiles = decoded
            persist()
            defaults.removeObject(forKey: profilesKey)
        }
        if let rawID = defaults.string(forKey: selectedKey) {
            selectedID = UUID(uuidString: rawID)
        }
        if selectedProfile == nil { selectedID = profiles.first?.id }
    }

    private func persist() {
        if let data = try? JSONEncoder().encode(profiles) {
            try? KeychainVault.save(data, account: vaultAccount)
        }
        defaults.set(selectedID?.uuidString, forKey: selectedKey)
    }
}
