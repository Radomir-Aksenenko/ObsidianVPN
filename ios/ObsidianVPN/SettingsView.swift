import SwiftUI

struct SettingsView: View {
    @AppStorage("settings.autoConnect", store: UserDefaults(suiteName: "group.com.obsidian.vpn")) private var autoConnect = false
    @AppStorage("settings.killSwitch", store: UserDefaults(suiteName: "group.com.obsidian.vpn")) private var killSwitch = true
    @AppStorage("settings.haptics", store: UserDefaults(suiteName: "group.com.obsidian.vpn")) private var haptics = true

    var body: some View {
        NavigationStack {
            ZStack {
                MineralBackground()
                Form {
                    Section("Подключение") {
                        Toggle("Автоподключение", isOn: $autoConnect)
                        Toggle("Не пропускать трафик мимо VPN", isOn: $killSwitch)
                    }

                    Section("Интерфейс") {
                        Toggle("Тактильные отклики", isOn: $haptics)
                    }

                    Section {
                        LabeledContent("Хранение ключей", value: "На устройстве")
                        LabeledContent("Журнал сайтов", value: "Не ведётся")
                    } header: {
                        Text("Приватность")
                    } footer: {
                        Text("Ключи серверов хранятся локально. Obsidian не собирает историю сайтов и DNS-запросов.")
                    }

                    Section("О приложении") {
                        LabeledContent("Протокол", value: "Obsidian v2")
                        LabeledContent("Версия", value: "1.0.0")
                    }
                }
                .scrollContentBackground(.hidden)
            }
            .navigationTitle("Настройки")
        }
    }
}
