# Альтернативные транспорты и проверка маскировки

Проверено 9 ноября 2026. Только первичные источники. Показатели доступности в конкретной российской сети в этой работе не измерялись. Упоминание функции в исходнике не доказывает нераспознаваемость ТСПУ.

## Какие альтернативы дают подходящую основу?

### Takeaway

Для основного пути разумнее завершённый настоящий TLS и настоящий HTTP/2 с обслуживанием обычного сайта, чем дальнейшая имитация TLS-записей. QUIC/Hysteria полезен как отдельный быстрый путь, но не как единственный: российская цензура умеет разбирать QUIC Initial/SNI. Это проектный вывод, не результат сравнительного полевого теста.

### Cited Findings

- **NaiveProxy:** официальный stable на момент проверки — `v154.0.8037.49-5` от 22 октября 2026. Реиспользует Chromium network stack, HTTP/2 multiplexing, padding/fragmentation и routing по авторизации на обычном frontend. Заявления об устойчивости здесь принадлежат разработчику, а не независимому российскому измерению. Пользователям рекомендуют актуальный stable, поскольку сетевые сигнатуры должны следовать Chrome. — [Release](https://github.com/klzgrad/naiveproxy/releases/tag/v154.0.8037.49-5), [официальный README](https://raw.githubusercontent.com/klzgrad/naiveproxy/v154.0.8037.49-5/README.md).
- Naive CLI предоставляет локальный SOCKS/HTTP listener и HTTPS/QUIC proxy chain. Параметр `insecure-concurrency` увеличивает число внешних соединений; upstream прямо предупреждает, что это ухудшает устойчивость к анализу трафика. — [USAGE](https://raw.githubusercontent.com/klzgrad/naiveproxy/master/USAGE.txt).
- **ShadowTLS v3:** строгий режим использует TLS 1.3 handshake target; клиент заканчивает настоящее TLS-рукопожатие, после переключения библиотека TLS уже не участвует в forwarding. Собственные записи имеют цепочечную HMAC-аутентификацию и защиту от изменения/склейки. Это не шифрование содержимого и не forward secrecy: требуется зашифрованный внутренний протокол. Stable upstream `v0.2.25` опубликован в декабре 2023, поэтому называть именно этот репозиторий часто обновляемым нельзя. — [спецификация v3](https://raw.githubusercontent.com/ihciah/shadow-tls/master/docs/protocol-v3-en.md), [официальная wiki с ограничением целей](https://github.com/ihciah/shadow-tls/wiki/V3-Protocol), [release](https://github.com/ihciah/shadow-tls/releases/tag/v0.2.25).
- **Hysteria 2:** stable `app/v2.13.0` опубликован 5 октября 2026. Использует QUIC и HTTP/3 masquerade: неаутентифицированный запрос должен обслуживаться как обычный HTTP/3. Salamander — необязательный слой обфускации QUIC, а не замена его криптографии. — [release](https://github.com/HyNetworks/hysteria/releases/tag/app/v2.13.0), [спецификация](https://v2.hysteria.network/docs/developers/Protocol/).
- В stable `app/v2.13.0` уже есть **ChromeParrot** и нулевая source Connection ID на клиенте; это подтверждено именно исходниками тега, не только master. — [client.go stable](https://raw.githubusercontent.com/HyNetworks/hysteria/app/v2.13.0/core/client/client.go).
- В том же stable уже есть **Gecko** поверх Salamander: фрагментирует только QUIC long-header packets, оставляет short-header data packets без фрагментации. Defaults: фрагменты 512–1200 bytes, reassembly TTL 8s, не более 4096 незавершённых сборок и 8 на источник. — [gecko.go stable](https://raw.githubusercontent.com/HyNetworks/hysteria/app/v2.13.0/extras/obfs/gecko.go).
- **TUIC v5** ориентирован на мультиплексируемый TLS-encrypted transport, преимущественно QUIC. Клиентская аутентификация использует TLS key exporter; предусмотрены отдельные TCP streams и UDP relay commands. — [официальная спецификация TUIC](https://raw.githubusercontent.com/tuic-protocol/tuic/master/SPEC.md).

### Inferences

- Для Obsidian первый приоритет — заменить эвристику «похожего flight» на транспорт с настоящей TLS state machine. Тогда внутренний открытый ML-KEM handshake естественно шифруется внешним TLS, а не требует ещё одного самостоятельно спроектированного криптослоя.
- Простая обёртка открытого `BuildHello` в ShadowTLS проблему ML-KEM не решает: payload после переключения обязан уже выглядеть зашифрованным. Нельзя автоматически переносить свойство «настоящее рукопожатие» на конфиденциальность всего последующего потока.
- Идея Gecko полезнее постоянного случайного sleep: целевое изменение начального обмена оставляет bulk path быстрым. Но ни Gecko, ни Salamander не превращают UDP в настоящий HTTP/3 для наблюдателя, знающего PSK; после обфускации «выглядит как QUIC» и «скрывает QUIC» — разные режимы, их нельзя обещать одновременно.
- Обычный HTTPS path требует подходящего собственного домена/сертификата и правдоподобного frontend. Подмена SNI чужим доменом не создаёт такое свойство.

### Gaps

- Не найдено независимое свежее исследование, позволяющее честно расположить NaiveProxy, ShadowTLS v3, Hysteria2 и TUIC в рейтинге «работает во всех российских сетях 9 ноября 2026».
- Нет сопоставимых CPU/Мбит/с/потерь на данном VPS/телефоне. Upstream архитектура не заменяет локальный benchmark.

## Как интегрировать и сохранить скорость?

### Takeaway

Самый лёгкий Go API среди рассмотренных готовых QUIC вариантов — Hysteria core, но он добавляет отдельный QUIC fork и требует полевого тестирования. Для TLS/HTTP2 важно согласованное поведение TLS **и** HTTP2: одна uTLS ClientHello-маска ещё не означает Chromium stack.

### Cited Findings

- Hysteria stable core: `client.NewClient(*Config)` возвращает `Client`; `Client.TCP(addr)` возвращает `net.Conn`, `Client.UDP()` — интерфейс datagram relay. Клиентский `ConnFactory.New` даёт точку создания packet socket; server Config принимает `net.PacketConn`, `Authenticator`, `MasqHandler`, `Outbound` и `RequestHook`. — [client API](https://raw.githubusercontent.com/HyNetworks/hysteria/app/v2.13.0/core/client/client.go), [server Config](https://raw.githubusercontent.com/HyNetworks/hysteria/app/v2.13.0/core/server/config.go).
- Stable Hysteria core требует Go 1.26 и pin fork `github.com/apernet/quic-go v0.63.1-0.20261004180939-a10df75c260c`. У master уже другой pseudo-version от 9 ноября; для повторяемой интеграции следует фиксировать stable tag/зависимости. Лицензия Hysteria — MIT. — [go.mod stable](https://raw.githubusercontent.com/HyNetworks/hysteria/app/v2.13.0/core/go.mod), [license](https://raw.githubusercontent.com/HyNetworks/hysteria/app/v2.13.0/LICENSE.md).
- Stable sing-box — `v1.14.4` от 24 октября 2026. Naive outbound существует с 1.13 и в stable реализован через **cronet-go**, с отдельным build tag; это не маленькая реализация Chromium на чистом Go. — [release](https://github.com/SagerNet/sing-box/releases/tag/v1.14.4), [stable source](https://raw.githubusercontent.com/SagerNet/sing-box/v1.14.4/protocol/naive/outbound.go).
- Официальная документация Naive sing-box перечисляет native `libcronet.so`/`libcronet.dll` для некоторых сборок, платформенные ограничения; предупреждает против самоподписанных сертификатов и лишних parallel tunnel connections. Для HTTP2 receive window указан default 4 MB на iOS и 128 MB на остальных платформах; эти rolling docs нужно сверять со stable исходниками, а не копировать вслепую. — [Naive docs](https://sing-box.sagernet.org/configuration/outbound/naive/).
- В rolling документации sing-box HTTP outbound HTTP/2/3 version selectors помечены **Since 1.15.0**, а проверенный latest stable — 1.14.4. Следовательно, конкретные новые selectors нельзя выдавать за stable API. Сам sing-box GPLv3-or-later с дополнительным ограничением использования имени/ассоциации производными работами. — [HTTP docs](https://sing-box.sagernet.org/configuration/outbound/http/), [stable LICENSE](https://raw.githubusercontent.com/SagerNet/sing-box/v1.14.4/LICENSE).
- NaiveProxy верхнеуровневый LICENSE разрешительный BSD-style с сохранением уведомлений; Chromium/native distribution требует учитывать состав third-party notices. ShadowTLS package объявляет MIT/Apache-2.0 и использует Rust TLS/runtime forks. — [Naive LICENSE](https://raw.githubusercontent.com/klzgrad/naiveproxy/v154.0.8037.49-5/LICENSE), [ShadowTLS Cargo.toml](https://raw.githubusercontent.com/ihciah/shadow-tls/master/Cargo.toml).
- HTTP2 flow-control window меньше bandwidth-delay product ограничивает receive throughput; обе стороны должны своевременно читать управляющие frames и отправлять WINDOW_UPDATE. — [RFC 9113 §5.2](https://www.rfc-editor.org/rfc/rfc9113.html#section-5.2).
- QUIC/HTTP3 обеспечивает независимое продвижение streams при потере пакетов в другом stream. HTTP3 specification также предупреждает: случайный padding с предсказуемым распределением даёт мало защиты; избыточный padding способен ухудшить результат. — [RFC 9114 §2 и §10.7](https://www.rfc-editor.org/rfc/rfc9114.html#section-10.7).

### Inferences

- Практическая архитектура: отдельный transport abstraction (`net.Conn` + optional datagram API), неизменённый внутренний authenticated Obsidian tunnel; основной реальный TLS/HTTP путь и отдельный быстрый QUIC путь при доступном UDP. Переход между ними должен быть явным/диагностируемым, без отката к raw известному формату.
- Go HTTP2 streaming POST/CONNECT можно адаптировать к `net.Conn`, но это **собственный HTTP2 fingerprint**, пока его SETTINGS, HPACK, window updates и TLS поведение не сравнены с выбранным browser baseline. Не называть это эквивалентом NaiveProxy.
- Для HTTP2 receiver следует измерить окно и память под RTT 30/80/150ms, ограничивать очереди, разделять latency-sensitive и bulk без постоянного sleep. Одно TCP соединение сохраняет TCP-level head-of-line blocking; множество соединений тоже может облегчить traffic analysis. Универсального значения concurrency нет.
- Внедрение Hysteria через TCP API может принять внутренний байтовый туннель. Для UDP data path полезен datagram API, иначе пакеты снова попадут в reliable ordered stream и потеряют часть преимуществ QUIC. Socket protection Android/iOS нужно подключать до установления сокета, используя предусмотренную factory, а не создавать транспорт за спиной текущей route logic.
- На мобильных устройствах native Cronet даёт лучшее основание для browser parity, но увеличивает размер приложения/сложность ABI и сборки. Не следует незаметно втащить весь GPL sing-box в независимый продукт ради одной функции; можно выбрать отдельную разрешительную библиотеку или совместимую самостоятельную transport implementation с собственной проверкой.

### Gaps

- API нет общего долгосрочного compatibility guarantee: pin version, adapter integration tests и осмысленное обновление обязательны.
- В рамках исследования не собран прототип; приведённые способы интеграции — вывод по официальным API, а не обещание drop-in замены.

## Что известно про Россию и как измерять результат?

### Takeaway

Первичные измерения подтверждают разбор QUIC/SNI российскими ТСПУ и ограничения простой рандомизации трафика, но не гарантируют доступность конкретной VPN реализации. Нужен слепой тест на настоящих pcap с отдельными TPR и FPR, а затем проверка из нескольких сетей РФ.

### Cited Findings

- FOCI 2026, Heitmann et al., измерения марта–апреля 2026 из трёх российских городов к контролируемой точке в Германии: QUICv1 Initial/SNI анализируется, запрещённые SNI вызывают packet dropping и residual censorship; в исследованной конфигурации residual interval 420s сбрасывался новыми пакетами, QUICv2 не попадал под тот же фильтр. Это наблюдение конкретного периода/выборки, не универсальная лазейка на будущее. Авторы публикуют pcap. — [оригинальная работа](https://www.petsymposium.org/foci/2026/foci-2026-0010.pdf), [исходные результаты](https://github.com/UPB-SysSec/RussiaQuicResults).
- NDSS 2025, Xue et al.: расхождение RTT между transport/application слоями даёт дополнительный fingerprint обфусцированных proxy. Авторы проверяли controlled flows и реальные ISP traces; padding одних длин не закрывает timing signal, а искусственные задержки могут сами создавать новые признаки. Это исследование общего класса атак, не доказательство того, что именно такой детектор применён к нашему IP. — [оригинальная работа](https://ensa.fi/papers/rtt-fingerprinting.pdf).
- OONI фиксирует в России TLS interference, включая разрывы после ClientHello; однако доступность сайтов VPN-провайдеров не равна доступности их tunnel protocol. — [OONI report](https://labs.ooni.io/ru/post/2024-russia-report/).

### Inferences

Предлагаемый ограниченный acceptance test, не чужой опубликованный benchmark:

1. Собрать по одной методике реальные capture у клиента и сервера: direct browser HTTPS/HTTP2, обычный HTTP3, текущий Obsidian v5, candidate transports. Одинаковые downloads/uploads, browsing, chat, idle и game-like UDP; отдельные короткие/длинные flows. Не генерировать labels из искусственного симулятора.
2. Оставить тестирующему только первые 20/60/200 пакетов, sizes/directions/interarrival, TLS/QUIC visible metadata. Маскировать IP/port/domain в одной серии, сохранить их в отдельной operational series, чтобы classifier не выучил просто наш IP.
3. Разделить train/test **по дню, серверу и провайдеру**, не по случайным кускам одной сессии. Подбирать параметры только на train/validation; сравнивать с простыми baselines и воспроизводимым classifier, а не одной субъективной оценкой ассистента.
4. Считать TPR при заданных FPR 1%, 0.1%, 0.01%, ROC/PR, confusion matrix и confidence intervals, а не только accuracy. Для заявления FPR <0.1% даже ноль ошибок на малой выборке не годится: желательно хотя бы 3000 независимых negative flows (rule-of-three даёт верхнюю 95% границу около 0.1% при нуле), для 0.01% — примерно 30000. Это статистический критерий планирования, не готовый достигнутый результат.
5. Функциональные gates: сертификат/hostname verification, отсутствие plaintext ML-KEM в capture, реальные TLS parser/handshake success, raw downgrade disabled, fallback/prober response comparison, replay/corruption/fragmentation tests, memory/reassembly bounds.
6. Performance gates: throughput и p50/p95 latency под RTT 30/80/150ms, loss 0/0.1/1%, MTU 1280/1420/1500, UDP fully dropped, abrupt NAT/network change; CPU/RSS/battery отдельно. Сравнивать при одинаковой нагрузке, фиксировать padding bandwidth overhead и reconnect rate. На ПК за рубежом нельзя подтвердить российскую доступность.
7. Минимальный полевой этап: несколько независимых российских AS/mobile/fixed networks, paired controls с обычным HTTPS на том же endpoint и внешняя контрольная точка, timestamped captures + серверные логи. Разделять «TCP SYN не дошёл», «TLS blocked», «application auth failed», «UDP blackhole».

### Gaps

- Нет pcap из затронутой российской сети и доинцидентной контрольной записи; истинная причина уже произошедшей блокировки остаётся неустановленной.
- Ни одна из найденных первичных работ не сертифицирует «невидимость» нового транспорта Obsidian; проверка должна предшествовать подобным заявлениям.
