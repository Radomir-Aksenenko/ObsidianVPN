import SwiftUI
import UIKit

struct SettingsView: View {
    @AppStorage("settings.autoConnect", store: UserDefaults(suiteName: "group.com.obsidian.vpn")) private var autoConnect = false
    @AppStorage("settings.killSwitch", store: UserDefaults(suiteName: "group.com.obsidian.vpn")) private var killSwitch = true
    @AppStorage("settings.haptics", store: UserDefaults(suiteName: "group.com.obsidian.vpn")) private var haptics = true

    var body: some View {
        NavigationStack {
            ZStack {
                MineralBackground()

                Form {
                    Section {
                        Toggle(isOn: $autoConnect) {
                            Label {
                                Text("Автоподключение")
                            } icon: {
                                Image(systemName: "bolt.badge.automatic.fill")
                                    .foregroundStyle(ObsidianTheme.accent)
                            }
                        }
                        .tint(ObsidianTheme.accent)
                        .onChange(of: autoConnect) { _, _ in triggerHaptic() }

                        Toggle(isOn: $killSwitch) {
                            Label {
                                Text("Блокировка трафика без VPN")
                            } icon: {
                                Image(systemName: "shield.slash.fill")
                                    .foregroundStyle(ObsidianTheme.accentCyan)
                            }
                        }
                        .tint(ObsidianTheme.accent)
                        .onChange(of: killSwitch) { _, _ in triggerHaptic() }
                    } header: {
                        Text("Подключение")
                    } footer: {
                        Text("При разрыве туннеля функция блокировки предотвращает утечку реального IP-адреса наружу.")
                    }
                    .listRowBackground(
                        RoundedRectangle(cornerRadius: 14, style: .continuous)
                            .fill(.ultraThinMaterial.opacity(0.65))
                    )

                    Section {
                        Toggle(isOn: $haptics) {
                            Label {
                                Text("Тактильный отклик (Haptics)")
                            } icon: {
                                Image(systemName: "hand.tap.fill")
                                    .foregroundStyle(ObsidianTheme.amber)
                            }
                        }
                        .tint(ObsidianTheme.accent)
                        .onChange(of: haptics) { _, _ in triggerHaptic() }
                    } header: {
                        Text("Интерфейс")
                    } footer: {
                        Text("Тактильные микро-вибрации при взаимодействии с пузырем Liquid Glass, кнопками и туннелем.")
                    }
                    .listRowBackground(
                        RoundedRectangle(cornerRadius: 14, style: .continuous)
                            .fill(.ultraThinMaterial.opacity(0.65))
                    )

                    Section {
                        LabeledContent {
                            Text("Keychain на устройстве")
                                .foregroundStyle(ObsidianTheme.accent)
                                .font(.system(.subheadline, design: .rounded, weight: .medium))
                        } label: {
                            Label("Хранение ключей", systemImage: "key.fill")
                        }

                        LabeledContent {
                            Text("Не ведётся")
                                .foregroundStyle(ObsidianTheme.secondaryText)
                                .font(.system(.subheadline, design: .rounded))
                        } label: {
                            Label("Журнал сетевой активности", systemImage: "eye.slash.fill")
                        }

                        LabeledContent {
                            Text("1280 байт")
                                .foregroundStyle(ObsidianTheme.primaryText)
                                .font(.system(.subheadline, design: .monospaced))
                        } label: {
                            Label("Размер MTU", systemImage: "ruler.fill")
                        }
                    } header: {
                        Text("Приватность и Безопасность")
                    } footer: {
                        Text("Ключи шифрования хранятся исключительно в аппаратном хранилище Keychain. Obsidian не сохраняет историю соединений и DNS-запросов.")
                    }
                    .listRowBackground(
                        RoundedRectangle(cornerRadius: 14, style: .continuous)
                            .fill(.ultraThinMaterial.opacity(0.65))
                    )

                    Section {
                        LabeledContent("Архитектура", value: "Obsidian Reality Core")
                        LabeledContent("Спецификация", value: "Liquid Glass iOS 26+")
                        LabeledContent("Версия клиента", value: "1.0.0 (Build 26)")
                    } header: {
                        Text("О программе")
                    }
                    .listRowBackground(
                        RoundedRectangle(cornerRadius: 14, style: .continuous)
                            .fill(.ultraThinMaterial.opacity(0.65))
                    )
                }
                .scrollContentBackground(.hidden)
            }
            .navigationTitle("Настройки")
        }
    }

    private func triggerHaptic() {
        guard haptics else { return }
        let generator = UIImpactFeedbackGenerator(style: .light)
        generator.prepare()
        generator.impactOccurred()
    }
}
