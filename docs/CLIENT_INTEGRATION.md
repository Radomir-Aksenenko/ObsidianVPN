# Obsidian Protocol: Client Developer Integration Guide

Руководство по встраиванию протокола ObsidianVPN в сторонние клиентские приложения для всех платформ: **Android**, **iOS**, **Linux**, **macOS**, **Windows**, а также для кроссплатформенных фреймворков (**Flutter**, **React Native**).

---

## 1. Архитектура интеграции

ObsidianVPN работает на 3-м сетевом уровне (IP-пакеты: IPv4/IPv6). Включает:
- Постквантовое гибридное рукопожатие (X25519 + ML-KEM-768).
- Маскировку TLS 1.3 REALITY-Plus / ShadowTLS v3 под легитимные домены.
- Высокоскоростной транспорт данных через WebRTC/STUN UDP с динамическим Port Hopping и защитой от тайминг-атак (Bucket Padding).
- Бесшовное резервирование трафика через TCP REALITY при блокировке UDP.

Для разработчиков клиентов предоставляется 3 уровня API:
1. **Go Mobile SDK (`pkg/mobile`)**: Готовые интерфейсы под `gomobile bind` для генерации `.aar` (Android) и `.xcframework` (iOS/macOS).
2. **C-ABI (`bindings/c`)**: Заголовочный файл `obsidian.h` и C-shared библиотека для Swift, Kotlin/JNI, Flutter FFI, C++, Rust, C#.
3. **Go Core API (`obsidian/client` и `obsidian/tun`)**: Для приложений и сервисов на чистом Go (Linux, macOS, Windows).

---

## 2. Интеграция под Android (Kotlin / Java)

На Android VPN-клиенты работают через системный класс `android.net.VpnService`. Система создает виртуальный сетевой интерфейс и возвращает файловый дескриптор (`fd`).

### 2.1. Сборка AAR для Android

Установите `gomobile` (если еще не установлен) и соберите библиотеку:

```bash
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init
gomobile bind -target=android -androidapi=21 -o obsidian.aar ./pkg/mobile
```

Поместите сгенерированный `obsidian.aar` в папку `app/libs/` вашего Android проекта.

### 2.2. Защита сокетов (Socket Protection)

> [!IMPORTANT]
> **Критическое требование Android:** Сокеты самого VPN-клиента (TCP REALITY и UDP Data Channel) обязаны быть защищены через `VpnService.protect(int socketFd)` до отправки данных. Без этого пакеты туннеля будут циклически заворачиваться обратно в VPN-интерфейс, вызывая мгновенное зависание сети.

### 2.3. Пример реализации VpnService на Kotlin

```kotlin
package com.example.vpn

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import mobile.Mobile
import mobile.SocketProtector
import mobile.StatusListener
import mobile.StatsListener

class ObsidianVpnService : VpnService() {

    private var pfd: ParcelFileDescriptor? = null
    private var sessionID: String? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val configUri = intent?.getStringExtra("CONFIG_URI") ?: return START_NOT_STICKY

        Thread {
            startTunnel(configUri)
        }.start()

        return START_STICKY
    }

    private fun startTunnel(configUri: String) {
        // 1. Настройка виртуального интерфейса
        val builder = Builder()
            .setSession("ObsidianVPN")
            .setMtu(1420)
            .addAddress("10.8.0.2", 24)
            .addDnsServer("1.1.1.1")
            .addDnsServer("8.8.8.8")
            .addRoute("0.0.0.0", 0) // Перенаправление всего IPv4 трафика в туннель

        pfd = builder.establish()
        val tunFd = pfd?.fd ?: return

        // 2. Реализация SocketProtector
        val protector = object : SocketProtector {
            override fun protect(socketFd: Long): Boolean {
                return this@ObsidianVpnService.protect(socketFd.toInt())
            }
        }

        // 3. Слушатели статуса и статистики
        val statusListener = object : StatusListener {
            override fun onStatusChange(status: String?, detail: String?) {
                // status: "connecting", "connected", "reconnecting", "disconnected"
                println("[Obsidian] Status: $status ($detail)")
            }
        }

        val statsListener = object : StatsListener {
            override fun onStats(bytesSent: Long, bytesRecv: Long, txSpeed: Long, rxSpeed: Long) {
                // Скорость в байтах в секунду
            }
        }

        // 4. Запуск туннеля в Go-ядре
        sessionID = Mobile.startTunnelWithFd(
            configUri,
            tunFd.toLong(),
            1420,
            protector,
            statusListener,
            statsListener
        )
    }

    override fun onDestroy() {
        sessionID?.let { Mobile.stopTunnel(it) }
        pfd?.close()
        super.onDestroy()
    }
}
```

---

## 3. Интеграция под iOS (Swift / Objective-C)

На iOS используется фреймворк `NetworkExtension` и его компонент `NEPacketTunnelProvider`.

### 3.1. Сборка XCFramework для iOS

```bash
gomobile bind -target=ios,iossimulator -o Obsidian.xcframework ./pkg/mobile
```

Подключите сгенерированный `Obsidian.xcframework` в Xcode к таргету Packet Tunnel Provider Extension (в разделе *Frameworks, Libraries, and Embedded Content*).

### 3.2. Пример реализации NEPacketTunnelProvider на Swift

```swift
import NetworkExtension
import Obsidian

class PacketTunnelProvider: NEPacketTunnelProvider {

    private var sessionID: String?
    private var isTunnelRunning = false

    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        guard let configUri = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?["configUri"] as? String else {
            completionHandler(NSError(domain: "Obsidian", code: -1, userInfo: [NSLocalizedDescriptionKey: "Missing configUri"]))
            return
        }

        // 1. Конфигурация параметров сетевого адаптера
        let tunnelNetworkSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        tunnelNetworkSettings.ipv4Settings = NEIPv4Settings(addresses: ["10.8.0.2"], subnetMasks: ["255.255.255.0"])
        tunnelNetworkSettings.ipv4Settings?.includedRoutes = [NEIPv4Route.default()]
        tunnelNetworkSettings.dnsSettings = NEDNSSettings(servers: ["1.1.1.1", "8.8.8.8"])
        tunnelNetworkSettings.mtu = 1420

        setTunnelNetworkSettings(tunnelNetworkSettings) { [weak self] error in
            if let error = error {
                completionHandler(error)
                return
            }

            guard let self = self else { return }

            // 2. Старт туннеля с in-memory обменом пакетов
            do {
                var err: NSError?
                self.sessionID = MobileStartPacketTunnel(
                    configUri,
                    1420,
                    nil, // Socket protection на iOS управляется системой через NEPacketTunnelProvider
                    nil,
                    nil,
                    &err
                )
                if let err = err {
                    completionHandler(err)
                    return
                }

                self.isTunnelRunning = true
                self.startPacketLoops()
                completionHandler(nil)
            } catch {
                completionHandler(error)
            }
        }
    }

    private func startPacketLoops() {
        // Цикл чтения из ОС и передачи в туннель
        readPacketsFromOS()

        // Цикл получения пакетов из туннеля и передачи в ОС
        DispatchQueue.global(qos: .userInteractive).async { [weak self] in
            while self?.isTunnelRunning == true {
                guard let sid = self?.sessionID else { break }
                var err: NSError?
                if let packet = MobileReceivePacket(sid, 500, &err), packet.count > 0 {
                    let protoNumber = NSNumber(value: AF_INET)
                    self?.packetFlow.writePackets([packet], withProtocols: [protoNumber])
                }
            }
        }
    }

    private func readPacketsFromOS() {
        guard isTunnelRunning else { return }
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self, let sid = self.sessionID else { return }
            for packet in packets {
                _ = MobileInjectPacket(sid, packet, nil)
            }
            self.readPacketsFromOS()
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        isTunnelRunning = false
        if let sid = sessionID {
            _ = MobileStopTunnel(sid, nil)
        }
        completionHandler()
    }
}
```

---

## 4. Интеграция под Linux и macOS (Десктоп и CLI)

Для десктопных клиентов доступны нативные TUN-интерфейсы без сторонних драйверов:
- **Linux**: `/dev/net/tun` с автоматической настройкой `ip route` и `ip addr`. Требует `CAP_NET_ADMIN` или запуск от `root`.
- **macOS**: Нативный системный сокет `utun` (компонент `com.apple.net.utun_control`). Требует запуска с правами администратора (`sudo`).

### 4.1. Запуск через готовый CLI-клиент

```bash
# Linux
sudo ./obsidian-client --uri "obsidian://..."

# macOS
sudo ./obsidian-client --uri "obsidian://..."
```

### 4.2. Использование пакета `obsidian/tun` в Go

```go
package main

import (
	"log"

	"obsidian/obsidian/client"
	"obsidian/obsidian/tun"
)

func main() {
	// Создание нативного TUN (автоматически выбирает /dev/net/tun на Linux или utun на macOS)
	dev, err := tun.Open(tun.Config{
		Name:       "obsidian0",
		Address:    "10.8.0.2/24",
		MTU:        1420,
		DNS:        "1.1.1.1",
		ServerHost: "198.51.100.1",
	})
	if err != nil {
		log.Fatalf("failed to open TUN: %v", err)
	}
	defer dev.Close()

	// Инициализация и старт сессии
	session, err := client.NewSessionFromURI("obsidian://...",
		client.WithDebug(true),
		client.WithStatusCallback(func(status, detail string) {
			log.Printf("[Status] %s: %s", status, detail)
		}),
	)
	if err != nil {
		log.Fatalf("init session: %v", err)
	}

	log.Println("Starting tunnel...")
	if err := session.Start(dev); err != nil {
		log.Fatalf("session error: %v", err)
	}
}
```

---

## 5. Кроссплатформенный C-ABI (Flutter, React Native, C++, Rust)

Файлы C-интерфейса расположены в каталоге `bindings/c/`:
- `bindings/c/obsidian.h`: Готовый C-заголовочный файл.
- `bindings/c/obsidian_c.go`: Экспортируемые C-функции (`//export`).

### 5.1. Сборка C-Shared библиотеки

```bash
# Linux (AMD64)
go build -buildmode=c-shared -o libobsidian.so ./bindings/c

# macOS / iOS (ARM64)
go build -buildmode=c-shared -o libobsidian.dylib ./bindings/c

# Windows (DLL)
go build -buildmode=c-shared -o obsidian.dll ./bindings/c
```

### 5.2. Пример использования в Dart / Flutter (через `dart:ffi`)

```dart
import 'dart:ffi' as ffi;
import 'package:ffi/ffi.dart';

typedef StartTunnelNative = ffi.Pointer<Utf8> Function(
    ffi.Pointer<Utf8> uri,
    ffi.Int32 tunFd,
    ffi.Int32 mtu,
    ffi.Pointer<ffi.NativeFunction<ffi.Int32 Function(ffi.Int32)>> protectFn,
    ffi.Pointer<ffi.Void> statusFn,
    ffi.Pointer<ffi.Void> statsFn
);

typedef StartTunnelDart = ffi.Pointer<Utf8> Function(
    ffi.Pointer<Utf8> uri,
    int tunFd,
    int mtu,
    ffi.Pointer<ffi.NativeFunction<ffi.Int32 Function(ffi.Int32)>> protectFn,
    ffi.Pointer<ffi.Void> statusFn,
    ffi.Pointer<ffi.Void> statsFn
);

final lib = ffi.DynamicLibrary.open('libobsidian.so');
final startTunnel = lib.lookupFunction<StartTunnelNative, StartTunnelDart>('ObsidianStartTunnelWithFd');
final stopTunnel = lib.lookupFunction<ffi.Int32 Function(ffi.Pointer<Utf8>), int Function(ffi.Pointer<Utf8>)>('ObsidianStopTunnel');
final freeString = lib.lookupFunction<ffi.Void Function(ffi.Pointer<Utf8>), void Function(ffi.Pointer<Utf8>)>('ObsidianFreeString');
```

---

## 6. Режим локального прокси (Local SOCKS5 Proxy)

Если клиенту требуется перенаправлять трафик только конкретного приложения, браузера или WebView без прав администратора и без установки системного VPN-профиля (например, при тестировании в симуляторе):

```go
// В Go:
proxy, err := client.StartSocks5Proxy("127.0.0.1:10808")
defer proxy.Close()
```

В Mobile SDK:
```kotlin
// Android / Kotlin:
Mobile.startLocalProxy("127.0.0.1:10808")
// ...
Mobile.stopLocalProxy()
```

```swift
// iOS / Swift:
MobileStartLocalProxy("127.0.0.1:10808", nil)
// ...
MobileStopLocalProxy(nil)
```

---

## 7. Спецификация формата ключей и URI

Поддерживаются три взаимозаменяемых формата:
1. `obsidian://<base64url>?label=MyServer`
2. `vpn://<base64url>?label=MyServer`
3. `OBSDN-<base32>` (компактный текстовый ключ)

Для декодирования и инспекции конфигурации в JSON используйте:
```go
jsonStr, err := mobile.ParseConfigURI("obsidian://...")
```

Поля конфигурации JSON:
| Поле | Тип | Описание |
| :--- | :--- | :--- |
| `server_host` | string | IP адрес или хостнейм VPN-сервера |
| `server_port` | string | TCP/REALITY порт сервера (обычно 443) |
| `server_public_key` | string | 64-символьный hex X25519 публичный ключ сервера |
| `client_private_key`| string | Опциональный клиентский ключ (если пуст, генерируется ephemeral) |
| `reality_sni` | string | Домен маскировки REALITY (например `www.microsoft.com`) |
| `reality_auth_key` | string | Ключ аутентификации REALITY HMAC |
| `enable_udp_data` | bool | Включение скоростного WebRTC UDP канала данных |
| `udp_port` | string | UDP порт сервера |
| `port_pool` | []int | Пул портов для динамического Port Hopping |
| `tun_address` | string | CIDR адрес виртуального интерфейса (`10.8.0.2/24`) |
| `dns` | string | Первичный DNS сервер (`1.1.1.1`) |
