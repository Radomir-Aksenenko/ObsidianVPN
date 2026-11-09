# AmneziaWG 3.1: применимые механизмы и пределы доказательств

## Что действительно реализовано к 9 ноября 2026

### Takeaway

AmneziaWG 3.1 меняет не только сигнатуры пакета, но и служебное поведение соединения. Полезный образец для Obsidian — секретная защита метаданных и ограниченная рандомизация размеров/таймеров при неизменном проверенном криптографическом ядре, а не обещание «невидимости». [Официальная документация](https://docs.amnezia.org/documentation/amnezia-wg/)

### Cited Findings

- Проверенные официальные теги: userspace Go `v3.1.20260828`, commit `b5928efb6ca19f0153958460c3d141f04abc5c2e`; Linux kernel module `v3.1.20260906`, commit `4569c4c67f3a57414969260cafbbd04694fbaae0`. API releases у этих двух репозиториев пуст, поэтому нельзя подменять версии Go/kernel версией приложения. [Go tag API](https://api.github.com/repos/amnezia-vpn/amneziawg-go/git/ref/tags/v3.1.20260828), [kernel tag API](https://api.github.com/repos/amnezia-vpn/amneziawg-linux-kernel-module/git/ref/tags/v3.1.20260906)
- Последний найденный stable-релиз приложения — `5.1.0.6`, опубликованный 2 ноября 2026. В его заметках написано об улучшении стабильности, но отсутствует количественное сравнение пропускной способности AWG 3.1 с WireGuard/2.0. [Официальный релиз](https://github.com/amnezia-vpn/amnezia-client/releases/tag/5.1.0.6)
- Header protection использует ChaCha20: ключ отдельно задан в `HeaderProtectionKey`, nonce берётся из первых 12 случайных байт соответствующего S-префикса. Поэтому `S1–S4 >= 12`. Скрываются initiation/response/cookie и 16-байтовый transport header; статический receiver/counter больше не виден в открытом виде. [Документация](https://docs.amnezia.org/documentation/amnezia-wg/), [реализация cipher](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/noise-protocol.go#L647-L655), [receive](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/receive.go#L135-L178)
- В transport send path сперва выбирается `ContentPaddingAddition`, при отсутствии — `RandomTrailers`, и только при отсутствии обоих — обычное округление WireGuard до кратности 16. Нельзя складывать эти три механизма и приписывать им суммарный эффект: в коде это взаимоисключающие ветви. [Send path](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/send.go#L528-L640)
- Дополнительное transport padding — нули внутри зашифрованного внутреннего IP-пакета; на проводе они становятся ciphertext. Для handshake используется случайный внешний хвост. Размер дополняется только до доступного UDP window, а не бесконтрольно за MTU. [Send path](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/send.go#L140-L169), [padding and encryption](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/send.go#L528-L640)
- Реальные defaults приложения 5.1.0.6: `ContentPaddingAddition=10-100`, `RekeyAfterTime=100-120`, `RekeyTimeout=3-7`, `RejectAfterTime=150-180`, `KeepaliveTimeout=5-15`, `MaxHandshakeAttempts=15-20`, `PersistentKeepalive=25-35`, `RandomTrailers=on`, `DisableCookies=on`; H1–H4 оставлены 1/2/3/4, а S-padding — 12. Это defaults upstream, не рекомендация слепо копировать их в Obsidian. [Pinned constants, строки 244–284](https://github.com/amnezia-vpn/amnezia-client/blob/5.1.0.6/client/core/utils/constants/protocolConstants.h#L244-L284), [config template](https://github.com/amnezia-vpn/amnezia-client/blob/5.1.0.6/client/server_scripts/awg/template.conf)
- Таймеры не реализованы глобальным sleep перед каждым DATA-пакетом. Выбираются значения диапазонов при установке соответствующих служебных событий; отправка аутентифицированных данных отменяет ожидаемый keepalive, а persistent keepalive переносится при authenticated traversal. [Timers](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/timers.go#L129-L201), [range selection](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/timers.go#L228-L317)
- У текущего Go кода есть важная цена `DisableCookies`: обходится весь under-load блок с MAC2 challenge и IP rate limiter, а не только отправка узнаваемого cookie reply. Этот факт явно отражён последним коммитом. Нельзя считать отключение cookies бесплатным anti-probing улучшением. [Commit b5928ef](https://github.com/amnezia-vpn/amneziawg-go/commit/b5928efb6ca19f0153958460c3d141f04abc5c2e), [receive underload branch](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/receive.go#L360-L387)
- Go-репозиторий помечен MIT; kernel module — GPL-2.0. Если заимствуется именно реализация, а не общий принцип, требуется учитывать лицензию выбранного компонента; Go MIT notice необходимо сохранять в существенных копиях. [Go LICENSE](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/LICENSE), [kernel license metadata](https://api.github.com/repos/amnezia-vpn/amneziawg-linux-kernel-module/license)

### Inferences

- Защищать тип, routing ID, counter и handshake содержимое полезнее, чем перебирать узнаваемые magic values: upstream оставляет стандартные H1–H4 именно при включённом secret header protection. Это применимо как инженерный принцип, не как доказательство устойчивости конкретного потока к ТСПУ. [Constants](https://github.com/amnezia-vpn/amnezia-client/blob/5.1.0.6/client/core/utils/constants/protocolConstants.h#L244-L284), [header protection](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/noise-protocol.go#L647-L655)
- Параметры рандомизации должны быть согласованы с NAT, key lifetime и MTU. Полный случайный выбор без этих ограничений способен ухудшить доступность; upstream специально использует верхние/нижние границы таймеров для истечения и повторной установки событий. [Timer bounds](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/timers.go#L248-L317)

### Gaps

- Не найден публичный современный формальный security proof или слепой классификационный эксперимент, показывающий, что AWG 3.1 неотличим от разрешённых UDP-протоколов на российских линиях. Документация описывает уменьшение узнаваемости, не предоставляет такую гарантию. [Docs](https://docs.amnezia.org/documentation/amnezia-wg/)

## Что перенести в Obsidian и как оценивать скорость

### Takeaway

Переносить стоит механизм и проверяемые ограничения: распределения служебных таймеров, MTU-aware padding с бюджетом и отсутствие ответов на неаутентифицированные пробы при сохранении защиты ресурсов. Не стоит переносить весь набор AWG-настроек или полагать, что случайные UDP-байты становятся настоящим QUIC. [Timers](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/timers.go), [send](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/send.go), [receive](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/receive.go)

### Cited Findings

- В upstream есть `BenchmarkLatency` и `BenchmarkThroughput`, но это ping-пара на искусственных TUN queues, без реального интернета. В inspected source нет таблицы результатов stock WG vs AWG 3.1 с одинаковыми hardware/RTT/loss/профилями. Нельзя превращать наличие benchmark в опубликованную цифру overhead. [Benchmark source](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/device_test.go#L415-L470)
- FAQ сервиса указывает «до 200 Mbps» и перечисляет зависимость от ISP/маршрута/сети. Это характеристика Premium, не предел протокола, не сравнение с Obsidian и не доказательство накладных расходов header protection. [Official FAQ](https://docs.amnezia.org/faq/#what-speeds-does-amnezia-premium-provide)
- Есть воспроизводимое upstream issue #186 о потере transport пакетов при `RandomTrailers=on` и широких диапазонах H1–H3: receiver проверяет handshake branches до data branch. Автор сообщает 25% ping loss на 100 пробах и 0% при сужении диапазонов; математическое моделирование заявлено 16.082% против расчётных 16.113% для другого набора испытаний. Это результаты автора issue, не наш независимый сетевой замер. [Original issue #186](https://github.com/amnezia-vpn/amneziawg-go/issues/186)
- Актуальная проверенная версия source всё ещё перебирает init/response/cookie до transport с условием допуска длинных пакетов при random trailers. Поэтому принцип риска подтверждается чтением кода, даже если конкретный пользовательский процент потерь нельзя обобщать. [Current pinned classifier](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/receive.go#L605-L658)

### Inferences

- Для Obsidian разумно сначала рандомизировать **service events**, а не тормозить каждый DATA-пакет: это сокращает регулярные гребёнки на idle/reconnect/rekey при малой цене throughput. Изменение должно измеряться на фиксированных трассах и отдельно на активном и idle traffic. [Timers model](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/timers.go)
- Padding следует ограничивать не только MTU, но и overhead budget для маленьких пакетов: арифметический пример для равномерного 10–100 даёт среднее добавление 55 байт до ограничения MTU — около 3.9% для payload 1400 и около 92% для payload 60 байт. Это **расчёт для примера**, не измерение AWG. На полном MTU фактическое добавление может обрезаться до нуля. [Distribution default](https://github.com/amnezia-vpn/amnezia-client/blob/5.1.0.6/client/core/utils/constants/protocolConstants.h#L276-L284), [MTU clipping](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/send.go#L528-L545)
- Не следует вводить фиксированный для всех сессий набор padding bins или одинаковый random seed: это может создать новый общий fingerprint. Эффект разных распределений надо проверять слепым анализом, а не считать увеличение энтропии автоматической победой. Это наш инженерный вывод, мотивированный тем, что сам upstream допускает настройку диапазонов и предупреждает о повторяемости поведения. [Official rationale](https://docs.amnezia.org/documentation/amnezia-wg/)
- При неоднозначном распознавании длины/заголовка нельзя окончательно отбрасывать пакет до аутентификации кандидата. Для O(1) mux Obsidian нужно тестировать коллизии масок/декодеров и malformed input; добавление нового «похожего» формата не должно терять корректные data packets. [Classifier issue and suggested fall-through](https://github.com/amnezia-vpn/amneziawg-go/issues/186)
- Криптографическую защиту полезно оставить на стандартных AEAD/HKDF и менять транспорт/паддинг, как AWG оставляет базовое WireGuard data encryption. Новый самодельный cipher не является необходимой частью этих улучшений. [WireGuard-fork source](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/send.go#L622-L640)

### Gaps

- Численные CPU/latency/energy затраты AWG 3.1 на hardware пользователя не измерялись. В этой исследовательской подзадаче код Obsidian не менялся и сеть российского пользователя не использовалась.
- Нет основания обещать, что MTU-aware padding совместим с текущим Obsidian GSO без потери эффективности: разные длины уменьшают длину групп equal-size UDP segments; потребуется отдельный benchmark реализаций.

## Что известно о работе в России и что остаётся заявлением

### Takeaway

AWG 3.1 — актуальный upstream вариант против обнаружения, но сам разработчик признаёт различия по сети и невозможность гарантии доступности. Надёжного первичного исследования, доказывающего всеобщую работоспособность именно 3.1 в России на 9 ноября, в этой проверке не найдено. [Developer explanation](https://amnezia.org/blog/amnezia-vpn-no-connection-what-to-do)

### Cited Findings

- Amnezia объясняет современную блокировку сочетанием whitelist policy, DPI, статистики соединений, API/domain blocking и IP/subnet blocking. Разработчик отдельно предупреждает, что даже хорошо замаскированный VPN может не проходить whitelist-only режим, и что результат зависит от региона, ISP и типа сети. Это объяснение оператора сервиса, не независимая расшифровка правил ТСПУ. [Official incident/limitations article](https://amnezia.org/blog/amnezia-vpn-no-connection-what-to-do)
- В актуальном FAQ AmneziaWG 3.1 стоит по умолчанию, но пользователю предлагается переходить на XRay VLESS Reality при проблемах скорости/соединения. Наличие запасного транспорта — конкретное продуктовое свидетельство того, что один AWG-профиль не рассматривается как универсальный. [Official FAQ](https://docs.amnezia.org/faq/#which-protocols-does-amnezia-premium-use)
- Отчёт 7ASecurity 2025 — независимый security audit предыдущего состояния продукта, а не проверка anti-DPI свойств 3.1, появившейся в 2026. Ссылаться на него как на подтверждение невидимости 3.1 было бы неверно. [Original audit](https://www.opentech.fund/wp-content/uploads/2025/10/AVP-03-AmneziaVPN-Software-Audit-Report-Public-RC1.1.pdf), [3.1 Go tag](https://github.com/amnezia-vpn/amneziawg-go/tree/v3.1.20260828)

### Inferences

- Для нашего решения полезны **два разных транспорта**, например быстрый скрывающий метаданные UDP и настоящий TLS carrier для сетей, блокирующих произвольный UDP. Это вывод из признаваемых upstream ограничений и существования у Amnezia запасного XRay, а не гарантия какого-либо конкретного дизайна Obsidian. [Official FAQ](https://docs.amnezia.org/faq/), [blocking model](https://amnezia.org/blog/amnezia-vpn-no-connection-what-to-do)
- Реальный criterion acceptance для Obsidian: не «похож на AWG 3.1», а измеренный false-positive rate на независимом HTTPS/QUIC фоне, pcap из нескольких российских ISP и скорость/задержка под loss/RTT. Этот критерий является нашей рекомендацией, а не опубликованным результатом Amnezia.

### Gaps

- Найденные поиском пользовательские сообщения, сторонние установщики и обзорные VPN-рейтинги намеренно не использованы как доказательство текущей работоспособности: нет надёжной привязки к версии, ISP, маршруту, параметрам и дате теста.
- Первичный GreatFire результат с подтверждённой AWG 3.1 configuration и полным протоколом измерения получить не удалось. Нельзя переносить агрегированную доступность бренда Amnezia на его конкретный транспорт.
