import Foundation

struct ObsidianURIComponents: Equatable, Sendable {
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
        if let parsed = ObsidianURIComponents.parse(configURI), !parsed.endpoint.isEmpty {
            return parsed.endpoint
        }
        if !name.isEmpty && name != "Сервер" {
            return name
        }
        return "Неизвестный узел"
    }

    static func imported(from rawValue: String, customName: String? = nil) throws -> VPNProfile {
        let value = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard value.hasPrefix("obsidian://") || value.hasPrefix("vpn://") || value.hasPrefix("OBSDN-") else {
            throw ProfileImportError.unsupportedFormat
        }

        let parsed = ObsidianURIComponents.parse(value)
        let hostOrEndpoint = (parsed?.endpoint.isEmpty == false) ? parsed!.endpoint : (parsed?.host ?? "")

        let chosenName: String
        if let custom = customName?.trimmingCharacters(in: .whitespacesAndNewlines), !custom.isEmpty {
            chosenName = custom
        } else if let frag = parsed?.fragment, !frag.isEmpty {
            chosenName = frag
        } else if !hostOrEndpoint.isEmpty {
            chosenName = hostOrEndpoint
        } else {
            chosenName = "Obsidian Сервер"
        }

        let location = locationGuess(from: chosenName)
        let displayCity = (location.city == chosenName || location.city.isEmpty)
            ? (hostOrEndpoint.isEmpty ? chosenName : hostOrEndpoint)
            : location.city

        return VPNProfile(
            name: chosenName,
            city: displayCity,
            countryCode: location.code,
            configURI: value
        )
    }

    private static func locationGuess(from name: String) -> (city: String, code: String) {
        let lower = name.lowercased()
        let known: [(needles: [String], city: String, code: String)] = [
            (["helsinki", "finland", "хельсинки", "финлянд", "suomi"], "Хельсинки", "FI"),
            (["amsterdam", "netherlands", "амстердам", "нидерланд", "голланди"], "Амстердам", "NL"),
            (["frankfurt", "germany", "франкфурт", "германи", "deutschland"], "Франкфурт", "DE"),
            (["stockholm", "sweden", "стокгольм", "швец"], "Стокгольм", "SE"),
            (["warsaw", "poland", "варшав", "польш"], "Варшава", "PL"),
            (["london", "uk", "лондон", "великобритан", "united kingdom"], "Лондон", "GB"),
            (["paris", "france", "париж", "франци"], "Париж", "FR"),
            (["tokyo", "japan", "токио", "япони"], "Токио", "JP"),
            (["singapore", "сингапур"], "Сингапур", "SG"),
            (["usa", "united states", "сша", "нью-йорк", "new york", "los angeles", "лос-анджелес"], "США", "US"),
            (["russia", "москв", "росси", "moscow", "spb", "питер", "санкт-петербург"], "Россия", "RU"),
            (["turkey", "турци", "стамбул", "istanbul"], "Стамбул", "TR"),
            (["kazakhstan", "казахстан", "алматы", "астана"], "Казахстан", "KZ")
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
