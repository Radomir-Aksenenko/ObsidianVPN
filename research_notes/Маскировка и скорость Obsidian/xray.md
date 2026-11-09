# Xray REALITY и XHTTP для Obsidian

## Каков актуальный upstream и что он реально делает

### Takeaway

На 9 ноября 2026 latest — Xray v26.11.9. Сильнейшее практическое отличие от нашего v5: upstream выполняет полный TLS handshake и проверку специального сертификата, а не оборачивает произвольный поток в синтетические записи. Это основание для maintained transport adapter, но не доказательство неразличимости в РФ. [Релиз](https://github.com/XTLS/Xray-core/releases/tag/v26.11.9), [официальный клиент](https://github.com/XTLS/Xray-core/blob/v26.11.9/transport/internet/reality/reality.go).

### Cited Findings

- GitHub API `releases/latest` вернул v26.11.9, published 2026-11-09T05:31:16Z; release commit `676eaf66f8f05d4d558ee7a74b4736623d3feeb9`. Release notes сообщают о default Chrome 155+ fingerprint и называют его ещё не таргетируемым ТСПУ: это утверждение разработчика, не независимая валидация. [Релиз](https://github.com/XTLS/Xray-core/releases/tag/v26.11.9), [API](https://api.github.com/repos/XTLS/Xray-core/releases/latest).
- Server REALITY — форк Go TLS; сам проект направляет разработчиков клиента к Xray, а не предоставляет эквивалентный standalone Client в своём README. [REALITY README](https://github.com/XTLS/REALITY/blob/main/README.en.md).
- Клиентский `UClient` использует uTLS и вызывает `HandshakeContext`. В SessionID передаётся AEAD-защищённая служебная информация с ключом из ECDH и HKDF. При успешной REALITY-проверке возвращается зашифрованный `net.Conn`; полученный настоящий сертификат сайта запускает HTTP spider и завершается ошибкой, а не разрешением VPN-доступа. [Исходник клиента](https://github.com/XTLS/Xray-core/blob/v26.11.9/transport/internet/reality/reality.go).
- Сервер допускает клиента по имени, short ID, версии и временному окну; не прошедший проверку поток пересылается цели. `MaxTimeDiff == 0` означает отсутствие ограничения времени, поэтому параметр нужно задавать осознанно. Самостоятельного утверждения о глобальном replay-cache из прочитанного кода делать нельзя. [Сервер](https://github.com/XTLS/REALITY/blob/4bb46b2afd8b/tls.go).

### Inferences

- Реальный TLS record layer снимает необходимость самим рассчитывать Finished, угадывать завершение flight по 120 мс и обслуживать cipher-suite вариации. Сохранить внутренний ML-KEM туннель возможно, передавая его байты уже по authenticated upstream conn; это архитектурный вывод, ещё не результат нашего интеграционного теста. [Сопоставление с API клиента](https://github.com/XTLS/Xray-core/blob/v26.11.9/transport/internet/reality/reality.go).
- Внутренний Obsidian поверх RAW REALITY не получает автоматически все свойства VLESS Vision, XHTTP, CDN или browser HTTP поведения. Его распределения трафика остаются отдельной задачей. [Разделение транспортов в документации](https://xtls.github.io/en/config/transports/reality.html).

### Gaps

- Независимых многопровайдерных измерений доступности именно v26.11.9 в России не найдено. Поиск OONI не дал подходящего сравнительного теста этого релиза; нельзя превращать developer release note в гарантию работы.
- Не измерены CPU, throughput и память при добавлении upstream REALITY к нашему внутреннему шифрованию, особенно iOS/Android. Заявления о ускорении XTLS Vision нельзя переносить на наш raw inner tunnel. [Область заявлений upstream](https://xtls.github.io/en/config/transports/reality.html).

## Как интегрировать без копирования TLS и криптографии

### Takeaway

Можно импортировать официальный server package и client adapter, оставив собственные TUN/ML-KEM/framer. Нужны Go 1.27, зафиксированные module revisions, новый набор полей REALITY и тесты с настоящими TCP sockets. [Xray go.mod](https://github.com/XTLS/Xray-core/blob/v26.11.9/go.mod), [REALITY go.mod](https://github.com/XTLS/REALITY/blob/4bb46b2afd8b/go.mod).

### Cited Findings

- `go list -m -json github.com/xtls/xray-core@676eaf6` в исследовательской среде разрешился в **`github.com/xtls/xray-core v1.260327.1-0.20261109052709-676eaf66f8f0`**. Это корректный Go pin релизного commit; tag v26.11.9 не следует механически трактовать как semver совместимого module path. Release `go.mod` закрепляет **`github.com/xtls/reality v0.0.0-20261108101329-4bb46b2afd8b`**, Go 1.27 и uTLS pseudo-version `v1.8.3-0.20261108164504-a13c59ffe98b`. [Релизный go.mod](https://github.com/XTLS/Xray-core/blob/v26.11.9/go.mod), [commit API](https://api.github.com/repos/XTLS/Xray-core/commits/v26.11.9).
- Минимальные импорты клиента: `github.com/xtls/xray-core/transport/internet/reality` и `github.com/xtls/xray-core/common/net`. API: `UClient(rawConn, *Config, ctx, dest) (net.Conn,error)`. `rawConn` можно открыть существующим dialer с Android SocketProtector в `Control`, затем передать adapter; при ошибке закрывать raw socket. [API клиента](https://github.com/XTLS/Xray-core/blob/v26.11.9/transport/internet/reality/reality.go), [upstream dialer](https://github.com/XTLS/Xray-core/blob/v26.11.9/transport/internet/tcp/dialer.go).
- Client `Config`: `ServerName:sni`, `Fingerprint:"chrome"`, `PublicKey:serverPublic32`, `ShortId:shortID8`, `SpiderX:"/"`, `SpiderY:make([]int64,10)`. Нулевые десять значений соответствуют default builder. **Нельзя оставить SpiderY nil:** fallback индексирует его. `dest` строится как `xnet.TCPDestination(xnet.ParseAddress(serverHost),xnet.Port(port))`. Это пример полей, не проверенная сборка адаптера. [Proto-поля](https://github.com/XTLS/Xray-core/blob/v26.11.9/transport/internet/reality/config.pb.go), [default builder](https://github.com/XTLS/Xray-core/blob/v26.11.9/infra/conf/transport_security.go).
- Server импорт: `github.com/xtls/reality`. API: `Server(ctx, tcpConn, config) (*Conn,error)`. Основные поля Config: `DialContext`, `Type:"tcp"`, `Dest:targetHostPort`, `ServerNames:map[string]bool{sni:true}`, `PrivateKey:*ecdh.PrivateKey`, `ShortIds:map[[8]byte]bool{shortID:true}`, `MaxTimeDiff:30*time.Second`. Private key X25519 генерируется сервером; клиенту передаются его public bytes и тот же short ID/SNI. Это другой механизм, чем наш старый shared HMAC key. [Config](https://github.com/XTLS/REALITY/blob/4bb46b2afd8b/common.go), [Xray mapping](https://github.com/XTLS/Xray-core/blob/v26.11.9/transport/internet/reality/config.go).
- **Два обязательных ограничения server API:** перед самостоятельным `Server` нужен вызов `DetectPostHandshakeRecordsLens(config)`; входящий conn должен реализовывать `CloseWrite()` (подходит `*net.TCPConn`, но не голый `net.Pipe`). Внутри есть type assertion. [Server API](https://github.com/XTLS/REALITY/blob/4bb46b2afd8b/tls.go).
- **Критичный default для low-level server Config:** необходимо установить `SessionTicketsDisabled:true`, как делает официальный `GetREALITYConfig`; также оставить `NextProtos:nil` согласно upstream mapping. Родительский агент подтвердил интеграционным тестом: без отключения tickets Dial мог завершиться успешно, но первое чтение падало с `tls: unexpected message` / negative padding при генерации ticket. После согласования defaults прошли полный Go TLS cover → REALITY → внутренний ML-KEM roundtrip и ordinary HTTPS fallback. Это результат нашего интеграционного теста, а не заявление о работе через ТСПУ. [Официальные defaults](https://github.com/XTLS/Xray-core/blob/v26.11.9/transport/internet/reality/config.go).
- `DetectPostHandshakeRecordsLens` асинхронно запускает пробы цели для нескольких ALPN. Он использует собственный `net.Dial`, не `config.DialContext`; это важно для диагностики и тестов. После подключения ставится 10-секундный deadline. [Probe implementation](https://github.com/XTLS/REALITY/blob/4bb46b2afd8b/record_detect.go).
- Xray и REALITY лицензированы MPL-2.0; REALITY также сохраняет исходные Go copyright notices и LICENSE-Go. При использовании зависимости сохранять лицензии/notices и проверять условия распространения; не копировать файлы с заменой авторства. [Xray LICENSE](https://github.com/XTLS/Xray-core/blob/v26.11.9/LICENSE), [REALITY LICENSE](https://github.com/XTLS/REALITY/blob/4bb46b2afd8b/LICENSE), [LICENSE-Go](https://github.com/XTLS/REALITY/blob/4bb46b2afd8b/LICENSE-Go).

### Inferences

- Минимальная последовательность изменения build: поднять go directive/toolchain до доступной Go 1.27; `go get github.com/xtls/xray-core@v1.260327.1-0.20261109052709-676eaf66f8f0`; зафиксировать go.mod/go.sum; проверить native Windows/Linux/mobile builds. Не делать floating main dependency. Dependency может подтянуть значительный graph, хотя импортируется только transport. [Основание pin/dependencies](https://github.com/XTLS/Xray-core/blob/v26.11.9/go.mod).
- Вместо переноса примерно сотен строк uTLS internals, unsafe certificate access и spider лучше непосредственно импортировать upstream adapter: исправления сертификатной логики останутся upstream ответственностью. [Клиентский исходник](https://github.com/XTLS/Xray-core/blob/v26.11.9/transport/internet/reality/reality.go).

### Gaps

- В рамках исследования продуктовый код не менялся и adapter не компилировался. Нужно отдельно проверить недоступность цели, wrong key/shortID/SNI, replayed ClientHello, cancellation/deadlines, TCP socket protection, probe behavior и limits на concurrent unauthenticated connections.
- Server получает ctx, но внутренний handshake-state использует background context; полагаться только на отмену ctx вместо socket deadlines нельзя без теста. [Реализация Server](https://github.com/XTLS/REALITY/blob/4bb46b2afd8b/tls.go).

## Что взять из XHTTP и что известно о России

### Takeaway

XHTTP — полноценный отдельный HTTP transport, а не набор случайных TLS-заголовков. Для быстрой итерации maintained RAW REALITY adapter проще; XHTTP стоит держать отдельным совместимым режимом, а не имитировать внешние признаки без HTTP semantics. [Объяснение автора XHTTP](https://github.com/XTLS/Xray-core/discussions/4113).

### Cited Findings

- XHTTP поддерживает packet-up, stream-up, stream-one; последняя схема — двунаправленный streaming POST, stream-up разделяет направления, packet-up использует несколько POST. Возможны HTTP/2, HTTP/3 и CDN/раздельные пути; применимость зависит от TLS/REALITY и reverse proxy. [Официальное обсуждение конструкции](https://github.com/XTLS/Xray-core/discussions/4113).
- XMUX регулирует конкуренцию, reuse и срок HTTP-соединений диапазонами вместо одной вечной связи; автор также предупреждает, что произвольная рандомизация keepalive сама может стать признаком. Транспорт поддерживает header padding. [Объяснение XMUX](https://github.com/XTLS/Xray-core/discussions/4113).
- В актуальном source есть управляемые payload placements, padding и диапазоны размеров/интервалов. Нельзя считать, что старое описание 2024 полностью задаёт все defaults релиза 2026 — они проверяются по pinned source. [Конфигурационная реализация](https://github.com/XTLS/Xray-core/blob/v26.11.9/transport/internet/splithttp/config.go).
- GitHub issue с первичными сообщениями пользователей описывает блокировку старых Chrome fingerprints в России и collateral damage старым браузерам; это полезный сигнал изменчивости фильтров, но не репрезентативная статистика. [Issue #6273](https://github.com/XTLS/Xray-core/issues/6273).

### Inferences

- Для Obsidian переносимые принципы: настоящий поддерживаемый TLS stack, свежий реальный browser fingerprint, осмысленные limits reuse/concurrency, совместимая веб-семантика fallback. Без испытаний не добавлять миллисекундный шум каждому пакету и не переносить числа XMUX как магическую защиту. [Аргументация дизайна](https://github.com/XTLS/Xray-core/discussions/4113).
- RAW REALITY решает TLS correctness, но не превращает собственный raw UDP channel в QUIC; для stealth profile raw UDP нужно отдельно отключать/прятать в поддерживаемый transport, а fast UDP profile оценивать отдельно. Это вывод о разделении транспортов, не гарантия обхода. [Поддерживаемые сочетания](https://xtls.github.io/en/config/transports/reality.html).

### Gaps

- Нет измерения «лучший протокол России» с одинаковыми регионами, ASN, нагрузкой и временем. Форумные success/failure и слова релиза не позволяют ранжировать маскировку статистически.
- Не установлено, даст ли XHTTP лучшую скорость/задержку для наших TUN-пакетов, чем RAW REALITY, и сколько памяти потребуется на мобильных платформах. Нужен собственный controlled benchmark и слепая pcap классификация, затем полевая проверка в РФ.
