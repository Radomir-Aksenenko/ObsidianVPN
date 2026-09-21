# Obsidian для iPhone

Нативный SwiftUI-клиент для протокола Obsidian. Интерфейс рассчитан на iOS 17+ и включает:

- главный экран подключения со всеми состояниями туннеля;
- хранение профилей в iOS Keychain и импорт `obsidian://`, `vpn://` и `OBSDN-` ссылок;
- выбор, избранное и удаление серверов;
- системный `NETunnelProviderManager`;
- Packet Tunnel Provider для обмена IP-пакетами с Go Mobile SDK;
- Dynamic Type, VoiceOver, Reduce Motion и тёмную тему.

## Подготовка на macOS

1. Установить Go, Xcode, XcodeGen и Go Mobile.
2. Из корня репозитория собрать SDK:

   ```sh
   gomobile bind -target=ios,iossimulator -o ios/Frameworks/Obsidian.xcframework ./pkg/mobile
   ```

3. Сгенерировать проект — `project.yml` уже подключает фреймворк к Packet Tunnel Extension:

   ```sh
   cd ios
   xcodegen generate
   open ObsidianVPN.xcodeproj
   ```

4. Выбрать свою Apple Development Team для обоих таргетов. В Developer Portal должны быть включены Network Extensions и App Groups. Если bundle ID занят, заменить `com.obsidian.vpn`, `com.obsidian.vpn.PacketTunnel` и `group.com.obsidian.vpn` согласованно во всех файлах.

> Packet Tunnel Extension нельзя полноценно проверить только в SwiftUI Preview. Для системного VPN-профиля нужен подписанный билд на физическом iPhone.

## Сборка в GitHub Actions

Workflow `.github/workflows/ios-build.yml` собирает Go Mobile XCFramework и неподписанное приложение для iOS Simulator на macOS runner. После успешного запуска в разделе **Artifacts** доступны:

- `ObsidianVPN-iOS-Simulator` — ZIP с `.app` и журналом Xcode;
- `ObsidianVPN-XCFramework` — собранное Go-ядро для iOS.

Для установки на физический iPhone понадобится отдельная подписанная сборка с Apple Developer Team, provisioning profiles и разрешением Network Extension.
