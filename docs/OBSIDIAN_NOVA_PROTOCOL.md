# Obsidian Nova Protocol v0 — экспериментальная спецификация

> Статус: черновик новой исследовательской ветки. Цель — спроектировать полностью новую архитектуру транспорта и туннеля, не ломая текущий рабочий ObsidianVPN. Документ описывает направление для экспериментов, бенчмарков и будущего прототипа.

## 1. Зачем нужен Obsidian Nova

Текущий ObsidianVPN уже имеет рабочую базу: TUN, handshake, TCP/UDP data path, padding, noise, GUI. Но если цель — сделать что-то принципиально новое, быстрое и технологически сильное, лучше не пытаться бесконечно патчить старую модель туннеля.

Obsidian Nova предлагается как отдельная исследовательская ветка:

- новый транспорт;
- новый tunnel core;
- новая модель пакетов;
- новый scheduler;
- новая архитектура надёжности;
- новая модель adaptive protection;
- экспериментальная crypto-ветка;
- production crypto-ветка на проверенных primitive.

Главная идея:

> Не строить ещё один VPN-туннель. Строить encrypted packet fabric: зашифрованную пакетную ткань, где каждый пакет имеет intent, priority, deadline, reliability policy и может быть отправлен через лучший доступный carrier.

## 2. Почему не стоит сразу ломать текущий протокол

Новый протокол почти всегда сначала хуже старого:

- больше багов;
- меньше тестов;
- неизвестные bottleneck;
- неизвестные security risks;
- сложнее отладка;
- нет реальных данных о скорости.

Поэтому Nova нужно делать рядом с текущим кодом, а не вместо него.

Правильная стратегия:

1. Старый Obsidian остаётся baseline.
2. Nova развивается в отдельной папке/модуле.
3. Пишутся бенчмарки: old vs nova.
4. Пишутся симуляторы потерь, latency, MTU, packet reorder.
5. Только после превосходства по скорости/стабильности отдельные идеи переносятся в основной продукт.

## 3. Главные цели Nova

### 3.1. Скорость

Nova должен быть быстрым не только по raw throughput, но и по ощущению пользователя.

Цели:

- низкая задержка для interactive traffic;
- высокий throughput для bulk traffic;
- отсутствие TCP-over-TCP проблемы на fast path;
- micro-batching мелких пакетов;
- zero-copy/buffer pools где возможно;
- UDP-first architecture;
- scheduler с приоритетами;
- adaptive MTU;
- отсутствие лишних retransmit там, где они вредны.

### 3.2. Безопасность

Цели:

- strong encryption;
- forward secrecy;
- anti-replay;
- key separation;
- rekey epochs;
- secure session migration;
- active probing resistance;
- no fixed magic bytes;
- no obvious packet type in plaintext;
- no visible stable session id.

### 3.3. Адаптивность

Цели:

- automatic carrier selection;
- path health tracking;
- fallback без действий пользователя;
- per-flow policy;
- adaptive padding budget;
- adaptive FEC;
- adaptive reliability.

### 3.4. Исследовательская свобода

Nova должен позволять экспериментировать с собственными идеями:

- custom packet format;
- custom scheduling;
- custom congestion control;
- custom reliability;
- custom research cipher;
- custom handshake flow.

Но всё, что относится к production security, должно иметь safe branch на проверенных primitive.

## 4. Non-goals v0

На версии v0 не надо сразу делать:

- идеальную anti-censorship camouflage;
- полноценную замену QUIC;
- полноценный MASQUE;
- GUI;
- коммерческий keyserver;
- идеальную криптографию с нуля;
- mobile clients;
- multipath packet striping;
- сложную per-app классификацию.

v0 должна доказать базовую идею:

> encrypted cells + UDP carrier + scheduler + TUN forwarding могут быть быстрыми, управляемыми и расширяемыми.

## 5. Архитектурная модель

Обычный VPN часто выглядит так:

```text
TUN packet -> encrypt -> send over one tunnel -> decrypt -> TUN
```

Nova должна выглядеть так:

```text
TUN packet
  -> classify
  -> assign intent
  -> assign priority
  -> assign deadline
  -> choose reliability policy
  -> fragment into cells
  -> schedule
  -> bundle
  -> encrypt
  -> send over best carrier
  -> receive
  -> decrypt
  -> reorder/reassemble if needed
  -> write to TUN
```

То есть Nova — не просто транспорт, а packet operating system.

## 6. Основные компоненты

### 6.1. Nova Engine

Главный runtime-компонент.

Отвечает за:

- session state;
- packet queues;
- scheduler;
- carrier manager;
- reliability manager;
- crypto epochs;
- path health;
- metrics;
- rekey;
- shutdown/reconnect.

### 6.2. Carrier Layer

Carrier — внешний способ доставить encrypted bundles.

Возможные carriers:

- raw UDP;
- TCP stream;
- TLS stream;
- HTTP/2 stream;
- HTTP/3 stream;
- WebSocket;
- future WebRTC relay.

Для Nova Engine carrier должен выглядеть как абстракция:

```text
SendBundle(bundle)
RecvBundle() -> bundle
PathInfo() -> RTT/loss/MTU/state
```

v0 carrier:

- UDP only.

v1 carriers:

- UDP;
- TCP fallback.

v2 carriers:

- HTTP/2;
- QUIC/H3.

### 6.3. Cell Layer

Cell — внутренняя минимальная единица Nova.

Cell может быть:

- data;
- control;
- ack;
- path challenge;
- path response;
- fec;
- key update;
- noise.

Важно: тип cell не виден снаружи. Он находится внутри encrypted bundle.

### 6.4. Bundle Layer

Bundle — набор cells, который отправляется одним network packet/datagram.

Плюсы bundles:

- меньше overhead;
- можно объединять ACK + DATA;
- можно делать padding;
- можно лучше использовать MTU;
- можно coalesce маленькие пакеты.

### 6.5. Scheduler

Scheduler — сердце скорости Nova.

Он решает:

- что отправить первым;
- что можно подождать 1–2 мс для coalescing;
- что нельзя задерживать;
- что уже просрочено;
- где нужен retransmit;
- где retransmit вреден;
- где нужен FEC;
- где можно добавить padding/noise.

### 6.6. Reliability Manager

Отвечает за:

- ACK ranges;
- packet loss detection;
- selective retransmit;
- control reliability;
- optional data reliability;
- no-retransmit policy for realtime;
- FEC decisions.

### 6.7. Crypto Epoch Manager

Отвечает за:

- session keys;
- per-direction keys;
- header protection keys;
- route tags;
- rekey;
- key deletion;
- anti-replay windows.

## 7. Intent-aware model

Nova должен понимать не только packet size, но и intent.

Примеры intent:

| Intent | Что это | Политика |
|---|---|---|
| control | handshake, rekey, path check | maximum reliability, high priority |
| dns | DNS query/response | low latency, reliable retry |
| interactive | browsing, SSH-like traffic | low latency |
| realtime | voice/game/video call UDP | no old retransmits, low latency |
| bulk | download/upload | throughput, batching |
| background | updates/sync | low priority |
| sensitive | traffic requiring stronger protection | stronger padding/camouflage budget |
| unknown | всё непонятное | balanced |

В v0 можно начать просто:

- control;
- data;
- ack;
- noise.

Позже расширить классификацию.

## 8. Priority model

Приоритеты:

| Priority | Назначение |
|---|---|
| P0 | critical control, rekey, close |
| P1 | DNS, TCP ACK, interactive |
| P2 | normal user traffic |
| P3 | bulk traffic |
| P4 | background |
| PX | noise/filler |

Правило:

- P0 нельзя блокировать bulk traffic;
- P1 должен иметь низкую задержку;
- P3/P4 можно batch/coalesce;
- PX отправляется только если есть protection budget.

## 9. Deadline-aware delivery

Каждая cell может иметь deadline.

Зачем:

- realtime-пакет через 500 мс уже может быть бесполезен;
- control-пакет нельзя терять;
- bulk-пакет можно восстановить позже;
- DNS нужен быстро.

Пример:

| Traffic | Deadline |
|---|---:|
| control | strict, reliable |
| DNS | 1000–2000 ms |
| interactive | 200–800 ms |
| realtime | 50–200 ms |
| bulk | long/no strict deadline |
| noise | discard anytime |

Если cell просрочена, scheduler может её выбросить вместо бессмысленной доставки.

## 10. Split reliability

Главная идея:

> Надёжность должна быть не свойством всего туннеля, а свойством конкретного cell/flow.

Примеры:

| Traffic | Reliability |
|---|---|
| control | reliable + duplicate maybe |
| key update | reliable |
| DNS | reliable quick retry |
| TCP inside VPN | usually no tunnel retransmit, TCP already handles it |
| UDP realtime | no old retransmit |
| bulk UDP | optional selective recovery/FEC |
| noise | unreliable |

Это может повысить скорость, потому что туннель не будет бездумно восстанавливать всё подряд.

## 11. FEC strategy

FEC нельзя включать всегда: это overhead.

Nova должен включать FEC адаптивно:

| Loss | FEC policy |
|---:|---|
| 0–1% | off |
| 1–5% | light FEC for selected flows |
| 5–15% | stronger FEC or path switch |
| 15%+ | path degraded, switch carrier/endpoint |

v0:

- без FEC.

v1:

- experimental XOR/parity FEC для small groups.

v2:

- более серьёзный FEC после бенчмарков.

## 12. Micro-batching и packet coalescing

Мелкие пакеты дают много overhead.

Nova может ждать очень короткое окно, например 0–2 мс, чтобы собрать несколько cells в один bundle.

Это полезно для:

- TCP ACK;
- DNS;
- messenger packets;
- control + ACK;
- small UDP packets.

Правило:

- P0/P1 почти не задерживать;
- P2 можно задержать минимально;
- P3/P4 можно coalesce агрессивнее;
- realtime не задерживать сверх deadline.

## 13. Header privacy

Внешний packet не должен раскрывать:

- packet type;
- session id;
- exact packet number;
- direction;
- cell kind;
- flow id;
- version;
- magic bytes.

Visible header должен быть минимальным.

Пример Nova Datagram v0:

| Поле | Размер | Видимость |
|---|---:|---|
| route_tag | 4–8 bytes | visible but rotating/pseudorandom |
| masked_header | 8–16 bytes | protected/masked |
| ciphertext | variable | encrypted |
| auth_tag | 16 bytes | AEAD tag |

В v0 можно сделать проще, но принцип должен остаться: никаких фиксированных magic bytes.

## 14. Route tag

Серверу нужно быстро понять, к какой session относится UDP packet.

Но нельзя светить постоянный session id.

Решение:

- route tag derived from session secret;
- route tag changes per epoch;
- route tag short, pseudorandom;
- unknown tag silently ignored or handled as probe noise.

Пример derivation для production branch:

```text
route_tag = Truncate(HMAC(route_tag_key, epoch_id || direction), 64 bits)
```

Для research branch можно экспериментировать, но production должен иметь понятную security story.

## 15. Crypto architecture

### 15.1. Две ветки

Nova должна иметь две crypto-ветки.

#### Production Crypto Branch

Для реального использования:

- X25519 or hybrid KEM;
- HKDF/BLAKE3/KMAC for derivation;
- ChaCha20-Poly1305 or AES-GCM-SIV;
- separate keys per direction/purpose;
- AEAD everywhere;
- strict nonce discipline;
- rekey epochs;
- anti-replay.

#### Research Crypto Branch

Для экспериментов:

- custom sponge/duplex;
- custom stream cipher;
- custom MAC;
- custom ratchet;
- custom packet protection.

Research branch нельзя считать безопасной без анализа.

### 15.2. Почему так

Полностью новая криптография может быть интересной, но почти наверняка опасна без многолетнего анализа.

Новизна Nova должна быть прежде всего в:

- cell fabric;
- scheduler;
- split reliability;
- transport abstraction;
- adaptive protection;
- session migration;
- performance architecture.

А production security лучше строить на проверенных primitive.

## 16. Nova Handshake v0

Рабочие названия этапов:

1. ClientSpark.
2. ServerEmber.
3. ClientSeal.
4. SecureFabric.

### 16.1. ClientSpark

Клиент отправляет первый пакет.

Цели:

- не иметь fixed magic;
- передать ephemeral key material;
- передать encrypted client hint/token;
- защититься от replay;
- дать серверу возможность быстро отличить вероятного клиента от мусора.

Снаружи ClientSpark выглядит как случайный blob переменной длины.

### 16.2. ServerEmber

Сервер отвечает.

Цели:

- подтвердить server identity;
- дать server ephemeral material;
- выбрать параметры;
- выдать encrypted session parameters;
- возможно выдать retry/path token.

### 16.3. ClientSeal

Клиент подтверждает:

- ключи совпали;
- он авторизован;
- параметры приняты;
- fabric можно открывать.

### 16.4. SecureFabric

После handshake открываются:

- control cells;
- data cells;
- ack cells;
- path challenge/response;
- key update.

## 17. Key schedule

Production branch должна иметь key separation.

Минимальные ключи:

| Key | Назначение |
|---|---|
| k_data_c2s | data encryption client -> server |
| k_data_s2c | data encryption server -> client |
| k_hdr_c2s | header protection client -> server |
| k_hdr_s2c | header protection server -> client |
| k_route_c2s | route tag client -> server |
| k_route_s2c | route tag server -> client |
| k_ack | ACK/control auth if needed |
| k_rekey | next epoch derivation |
| k_path | path migration tokens |

Rekey triggers:

- time;
- packet count;
- byte count;
- path migration;
- manual/security event.

## 18. Anti-replay

Для UDP/session packets нужен anti-replay window.

Принцип:

- packet number внутри protected header;
- receiver держит sliding window;
- old packets reject;
- duplicate packets reject;
- epoch-aware replay windows;
- handshake timestamp/token protection.

## 19. Session migration

Nova должен быть connectionless-friendly.

Если клиент сменил IP/порт:

1. Клиент отправляет packet с valid route tag и path proof.
2. Сервер проверяет ключ/токен.
3. Сервер обновляет address для session.
4. Data продолжается.

Это важно для:

- мобильных сетей;
- Wi-Fi -> LTE;
- NAT rebinding;
- роуминга;
- sleep/wake.

v0 можно сделать простую NAT rebinding поддержку.

## 20. Congestion control

Nova не должен просто заливать UDP без контроля.

v0 congestion control:

- RTT measurement;
- basic pacing;
- simple congestion window;
- reduce on loss/RTT spike;
- never block control behind bulk;
- per-path stats.

v1:

- BBR-like estimator;
- latency mode;
- throughput mode;
- path score.

## 21. MTU strategy

Начальный MTU лучше консервативный:

- 1280 для максимальной совместимости;
- 1320–1380 как balanced;
- auto probing для повышения.

Nova должен уметь:

- не фрагментировать слишком большие bundles;
- fragment IP packets into cells;
- reassemble safely;
- detect blackhole;
- clamp TCP MSS в будущем.

## 22. Nova v0 packet lifecycle

```text
TUN packet arrives
  -> classify packet
  -> assign flow id
  -> assign priority
  -> assign deadline
  -> choose reliability policy
  -> fragment into cells
  -> enqueue cells
  -> scheduler selects cells
  -> bundle cells into datagram
  -> derive nonce/header mask
  -> encrypt bundle
  -> send via UDP carrier
  -> receiver decrypts
  -> receiver parses cells
  -> receiver reassembles IP packet
  -> write to TUN
```

## 23. Suggested module layout

Вариант структуры рядом с текущим кодом:

```text
nova/
  crypto/
  handshake/
  cell/
  bundle/
  session/
  scheduler/
  reliability/
  carrier/
    udp/
    tcp/
  tun/
  sim/
  bench/
  cmd/
    nova-client/
    nova-server/
```

Если удобнее внутри Go module:

```text
obsidian/nova
cmd/nova-client
cmd/nova-server
```

## 24. Nova v0.1 implementation plan

Цель: минимальный работающий прототип.

Задачи:

1. Создать package `nova`.
2. Описать `Cell` struct.
3. Описать `Bundle` struct.
4. Реализовать encode/decode plaintext для тестов.
5. Реализовать production crypto wrapper на AEAD.
6. Реализовать UDP carrier.
7. Реализовать simple session.
8. Реализовать packet number + anti-replay.
9. Реализовать route tag.
10. Реализовать basic client/server handshake.
11. Реализовать TUN echo mode или memory TUN test.
12. Реализовать scheduler priority queue.
13. Реализовать micro-batching 0–2 ms.
14. Добавить benchmark throughput/latency.
15. Сравнить с текущим UDPChannel.

## 25. Nova v0.2 implementation plan

Цель: проверить, даёт ли scheduler преимущество.

Задачи:

- classify IPv4/IPv6 packets;
- detect TCP ACK;
- detect DNS packets;
- priority scheduling;
- deadline drop;
- ACK ranges;
- basic loss detection;
- optional retransmit only for control;
- MTU probing draft;
- loss simulator.

## 26. Nova v0.3 implementation plan

Цель: начать более смелые эксперименты.

Задачи:

- session migration token;
- rekey epochs;
- FEC experiment;
- TCP fallback carrier;
- research crypto branch `NovaFlux`;
- fuzz tests;
- packet reorder simulator;
- path health scoring.

## 27. Почему это не должно ударить по скорости

Правильно реализованная Nova может быть быстрее или ощущаться быстрее, потому что:

- UDP-first design избегает TCP-over-TCP;
- scheduler не даёт bulk traffic блокировать DNS/control/interactive packets;
- micro-batching снижает overhead мелких пакетов;
- split reliability не делает лишних retransmit;
- deadline-aware logic не тратит канал на устаревшие realtime packets;
- adaptive MTU уменьшает fragmentation/loss;
- buffer pools и batching могут снизить CPU/GC overhead;
- FEC включается только когда loss делает его выгодным.

Что может ударить по скорости:

- слишком много padding;
- слишком сложная crypto на hot path;
- частые allocations;
- тяжёлый scheduler;
- FEC always-on;
- excessive ACK/control traffic;
- неправильный MTU;
- debug logging в data path.

Поэтому v0 должна с самого начала иметь benchmarks и performance budget.

## 28. Почему это не должно ударить по безопасности

Если разделить research и production crypto, безопасность не должна пострадать.

Production branch должна использовать проверенные primitives и строгие правила:

- AEAD for packets;
- no nonce reuse;
- key separation;
- anti-replay;
- forward secrecy;
- rekey epochs;
- no fixed magic;
- encrypted packet types;
- route tags вместо явных session ids;
- constant-time checks where needed;
- fuzzing decode paths;
- reject malformed packets safely.

Research crypto branch можно использовать только для лаборатории и тестов.

Главное правило:

> Новизна должна быть в архитектуре, scheduling, transport fabric и адаптации. Production crypto должна оставаться проверяемой.

## 29. Риски

### 29.1. Complexity risk

Nova сложнее обычного VPN.

Меры:

- делать v0 маленькой;
- много тестов;
- простые interfaces;
- benchmark после каждого этапа;
- не добавлять multipath до стабильного single-path.

### 29.2. Security risk

Новый protocol format может иметь ошибки.

Меры:

- fuzzing;
- test vectors;
- clear spec;
- no custom crypto in production;
- code review;
- threat model;
- минимальный plaintext metadata.

### 29.3. Performance risk

Scheduler и cell fabric могут добавить overhead.

Меры:

- zero-copy где можно;
- sync.Pool/ring buffers;
- fixed-size hot structs;
- avoid reflection/interface allocations in hot path;
- pprof;
- benchmark old vs nova.

### 29.4. Compatibility risk

Raw UDP могут блокировать.

Меры:

- сначала v0 UDP-only для скорости;
- затем carrier abstraction;
- TCP/H2/H3 fallback позже.

## 30. Критерии успеха Nova v0

Nova v0 считается удачной, если:

- работает client/server packet forwarding;
- handshake устанавливает encrypted session;
- packets encrypted/authenticated;
- anti-replay работает;
- TUN packets проходят туда-обратно;
- throughput не хуже текущего UDPChannel больше чем на 10–15%;
- latency для small packets лучше или равна текущему туннелю;
- scheduler показывает преимущество при mixed traffic;
- код можно расширять без переписывания всего ядра.

## 31. Краткий итог

Obsidian Nova стоит делать потому, что это может дать принципиально новую основу:

- не stream tunnel, а encrypted cell fabric;
- не одинаковая надёжность для всего, а split reliability;
- не FIFO, а priority/deadline scheduler;
- не один transport forever, а carrier abstraction;
- не fixed mode, а adaptive protection;
- не custom crypto в production, а новая архитектура поверх проверяемой криптографической базы.

Если сделать аккуратно, это не должно ударить по скорости. Наоборот, Nova может дать лучшую субъективную скорость за счёт scheduler, UDP-first path, micro-batching и отсутствия лишних retransmit.

Если сделать аккуратно, это не должно ударить по безопасности. Главное — не использовать экспериментальную самодельную криптографию как production security до серьёзного анализа.
