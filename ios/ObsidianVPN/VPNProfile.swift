import Foundation

struct VPNProfile: Identifiable, Codable, Hashable, Sendable {
    let id: UUID
    var name: String
    var city: String
    var countryCode: String
    var configURI: String
    var isFavorite: Bool

    init(id: UUID = UUID(), name: String, city: String, countryCode: String, configURI: String, isFavorite: Bool = false) {
        self.id = id
        self.name = name
        self.city = city
        self.countryCode = countryCode.uppercased()
        self.configURI = configURI
        self.isFavorite = isFavorite
    }

    var endpoint: String {
        guard let components = URLComponents(string: configURI), let host = components.host else {
            return "Obsidian"
        }
        return components.port.map { "\(host):\($0)" } ?? host
    }

    static func imported(from rawValue: String) throws -> VPNProfile {
        let value = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard value.hasPrefix("obsidian://") || value.hasPrefix("vpn://") || value.hasPrefix("OBSDN-") else {
            throw ProfileImportError.unsupportedFormat
        }

        let components = URLComponents(string: value)
        let fragment = components?.fragment?.removingPercentEncoding
        let host = components?.host ?? "Сервер"
        let suggestedName = fragment?.isEmpty == false ? fragment! : host
        let location = locationGuess(from: suggestedName)
        return VPNProfile(name: suggestedName, city: location.city, countryCode: location.code, configURI: value)
    }

    private static func locationGuess(from name: String) -> (city: String, code: String) {
        let lower = name.lowercased()
        let known: [(needles: [String], city: String, code: String)] = [
            (["helsinki", "finland", "хельсинки", "финлянд"], "Хельсинки", "FI"),
            (["amsterdam", "netherlands", "амстердам", "нидерланд"], "Амстердам", "NL"),
            (["frankfurt", "germany", "франкфурт", "германи"], "Франкфурт", "DE"),
            (["stockholm", "sweden", "стокгольм", "швец"], "Стокгольм", "SE"),
            (["warsaw", "poland", "варшав", "польш"], "Варшава", "PL")
        ]
        if let match = known.first(where: { item in item.needles.contains(where: lower.contains) }) {
            return (match.city, match.code)
        }
        return (name, "VPN")
    }
}

enum ProfileImportError: LocalizedError {
    case unsupportedFormat

    var errorDescription: String? { "Нужна ссылка obsidian://, vpn:// или ключ OBSDN-." }
}
