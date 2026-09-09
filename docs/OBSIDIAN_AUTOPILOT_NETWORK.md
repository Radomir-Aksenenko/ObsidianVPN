# Obsidian Autopilot Network — подробная концепция

> Статус: идея отложена на будущее. Сейчас основной фокус может быть на экспериментах с собственным протоколом, шифрованием и туннелем. Этот документ нужен как подробная заметка, чтобы не потерять направление продукта.

## 1. Главная мысль

Obsidian не должен быть просто ещё одним VPN-протоколом. Сильная продуктовая идея — сделать **однокнопочный VPN с сетевым автопилотом**.

Пользователь не должен выбирать:

- UDP или TCP;
- QUIC или HTTP/2;
- быстрый режим или скрытный режим;
- MTU;
- DNS;
- padding;
- jitter;
- server fallback;
- split tunnel;
- transport fallback.

Пользователь должен видеть примерно следующее:

```text
[ Подключиться ]
Статус: защищено
Скорость: высокая
Режим: Autopilot
```

Вся сложность должна быть внутри клиента и протокола.

Ключевая формула:

> Obsidian — это не просто туннель. Это self-optimizing privacy network: VPN, который сам понимает сеть, сам выбирает транспорт, сам усиливает защиту при риске блокировки и сам сохраняет скорость.

## 2. Почему это может быть сильнее обычного VPN

Большинство VPN конкурируют одинаково:

- много серверов;
- WireGuard/OpenVPN;
- no logs;
- скидки;
- приложения для всех платформ.

Obsidian может отличаться иначе:

- одна кнопка;
- автоматический выбор транспорта;
- автоматическое восстановление;
- умная защита без ручных режимов;
- per-flow routing;
- адаптация под конкретную сеть пользователя;
- приватная телеметрия без слежки;
- проверяемая приватность.

Позиционирование:

> Fast when possible. Invisible when needed. Automatic always.

Или:

> Obsidian — VPN with a network autopilot.

## 3. Главное ограничение

Нельзя честно обещать одновременно абсолютную скорость и абсолютную скрытность в любой сети.

Причина:

- максимальная скорость требует минимального overhead;
- максимальная маскировка иногда требует padding, noise, fallback через web-like transport;
- UDP обычно быстрее, но может блокироваться;
- TCP/HTTP/2 совместимее, но хуже для VPN data plane;
- WebSocket удобен как последний fallback, но медленнее;
- heavy jitter портит latency.

Поэтому правильная идея — не дать пользователю ручной выбор, а сделать адаптивный движок, который сам балансирует скорость и защиту.

## 4. Obsidian Autopilot Engine

### 4.1. Что это такое

Autopilot Engine — локальный движок принятия решений внутри клиента.

Он управляет:

- выбором транспорта;
- выбором data path;
- fallback;
- reconnect;
- MTU;
- DNS mode;
- padding budget;
- jitter;
- noise;
- routing per app/per flow;
- server/endpoint selection;
- protection level;
- network profile cache.

Пользователь нажимает одну кнопку, а Autopilot делает всё остальное.

### 4.2. Общая схема

```text
User presses one button
        |
        v
Autopilot Engine
        |
        +-- Network Profiler
        |     - UDP available?
        |     - QUIC available?
        |     - TCP/TLS stable?
        |     - MTU?
        |     - RTT?
        |     - packet loss?
        |     - DNS health?
        |
        +-- Transport Racing
        |     - custom UDP fast path
        |     - QUIC/H3
        |     - HTTP/2 stream
        |     - WebSocket/TLS fallback
        |
        +-- Flow Classifier
        |     - browser
        |     - video
        |     - messenger
        |     - game/voice
        |     - OS update
        |     - sensitive site
        |
        +-- Protection Budget Manager
        |     - padding
        |     - jitter
        |     - noise
        |     - camouflage strength
        |
        +-- Self-Healing Manager
        |     - reconnect
        |     - migration
        |     - fallback
        |     - endpoint switch
        |
        +-- Privacy Policy Engine
              - DNS protection
              - kill switch
              - leak protection
              - per-app policy
```

## 5. Базовая архитектура протокола

### 5.1. Control channel

Control channel должен быть максимально похож на обычный HTTPS-трафик.

Задачи control channel:

- первичное подключение;
- authentication;
- key exchange;
- capability negotiation;
- выдача параметров data channel;
- keepalive;
- rekey;
- fallback coordination;
- server health;
- command/control messages.

Возможные реализации:

1. TLS 1.3 + uTLS Chrome-like fingerprint.
2. Настоящий HTTP/2 stream.
3. В будущем HTTP/3 stream.
4. В будущем ECH, если станет удобно и реально deployable.

Важно: control channel не обязан быть самым быстрым, потому что основной трафик может идти по data channel.

### 5.2. Data channel

Data channel должен быть быстрым.

Порядок предпочтения:

1. QUIC DATAGRAM / MASQUE-like mode — идеальная будущая цель.
2. Custom UDP channel — текущий быстрый путь.
3. HTTP/3 stream — если DATAGRAM недоступен.
4. HTTP/2 stream — если UDP заблокирован.
5. WebSocket/TLS — последний fallback для жёстких сетей.

Правильная модель:

```text
control: web-like, stable, hard to probe
   data: fastest available path
fallback: invisible to user
```

### 5.3. Почему control и data стоит разделять

Если гнать всё через один поток:

- труднее переключаться;
- хуже восстановление;
- TCP-over-TCP может ухудшить скорость;
- сложнее менять transport на лету.

Если разделить:

- control остаётся стабильным;
- data можно менять;
- UDP можно использовать только когда он работает;
- fallback можно делать невидимым;
- rekey и migration проще.

## 6. Transport racing

### 6.1. Суть

При подключении клиент не должен слепо выбирать один transport.

Он должен быстро проверить несколько вариантов:

- работает ли UDP;
- работает ли QUIC/H3;
- стабилен ли TCP/TLS;
- проходит ли HTTP/2;
- нужен ли WebSocket fallback;
- какой RTT;
- какие потери;
- какой throughput.

Проверка должна занимать примерно 1–3 секунды и не требовать действий пользователя.

### 6.2. Пример порядка

```text
1. Establish TLS/uTLS control channel to server:443
2. Authenticate and negotiate capabilities
3. Start UDP probe
4. Start optional QUIC/H3 probe
5. Measure RTT/loss/timeout
6. Select best data path
7. Start VPN data forwarding
8. Keep probing fallback paths in background, carefully
```

### 6.3. Scoring

Каждый transport получает score.

Пример v1:

| Фактор | Вес |
|---|---:|
| UDP доступен | +40 |
| QUIC доступен | +30 |
| RTT < 80 ms | +20 |
| Packet loss < 1% | +20 |
| Хороший throughput | +20 |
| Предыдущий успех в этой сети | +15 |
| Web-like camouflage | +10 |
| UDP timeout | -50 |
| TLS reset | -40 |
| Высокий loss | -30 |
| Сервер перегружен | -30 |
| Частые reconnect | -25 |

Выбирается транспорт с лучшим score, но с учётом минимального уровня защиты.

## 7. Adaptive Protection Budget

### 7.1. Идея

Это одна из самых важных идей.

Вместо режимов `fast`, `balanced`, `stealth` для пользователя, внутри должен быть динамический budget защиты.

Autopilot сам решает:

- сколько padding можно добавить;
- нужен ли noise;
- нужен ли jitter;
- когда усилить camouflage;
- когда снизить overhead ради скорости.

### 7.2. Принцип

```text
Если сеть спокойная:
  overhead минимальный
  скорость максимальная

Если есть признаки блокировки:
  усилить camouflage
  увеличить padding/noise осторожно
  попробовать другой transport

Если скорость падает слишком сильно:
  уменьшить лишний overhead
  сменить path
  снизить shaping
```

### 7.3. Пример budget

| Уровень | Overhead | Назначение |
|---|---:|---|
| Low | 1–3% | обычная сеть, максимум скорости |
| Medium | 3–8% | дефолтная защита |
| High | 8–20% | признаки фильтрации |
| Emergency | 20%+ | только если иначе не работает |

### 7.4. Важное правило

Heavy protection не должна быть включена всегда.

Иначе продукт станет медленным и пользователь уйдёт.

Правильная маркетинговая формула:

> Protection when needed. Speed when possible.

## 8. Per-flow Intelligence

### 8.1. Почему обычный VPN тупой

Обычный VPN часто гонит весь трафик одинаково.

Но трафик разный:

- видео любит throughput;
- игры любят latency;
- мессенджеры любят стабильность и privacy;
- DNS должен быть защищён;
- banking/local services иногда лучше bypass;
- sensitive browsing требует stronger privacy.

### 8.2. Что должен делать Obsidian

Autopilot может классифицировать потоки и выбирать для них политику.

Пример:

| Тип трафика | Policy |
|---|---|
| Video/streaming | быстрый path, минимум padding |
| Game/voice | low latency path, минимум jitter |
| Messenger | stronger privacy for small packets |
| Browser sensitive | full tunnel, protected DNS |
| Banking/local services | optional bypass/local route |
| Downloads | high throughput path |
| DNS | always protected |
| OS updates | можно direct или cheap route |

### 8.3. Источники классификации

Возможные источники:

- приложение/process name;
- домен из DNS resolver cache;
- IP/category mapping;
- port/protocol;
- traffic pattern;
- user policy;
- route list;
- local rules.

Важно: классификация должна быть локальной. Не надо отправлять историю сайтов на сервер.

## 9. Multipath VPN

### 9.1. Идея

Один VPN-сеанс может использовать несколько путей одновременно.

Например:

- UDP fast path;
- H3 path;
- H2 fallback;
- backup endpoint;
- возможно Wi-Fi + LTE в будущем.

### 9.2. Что это даёт

- меньше обрывов;
- быстрее recovery;
- можно дублировать важные control packets;
- можно распределять data;
- можно мигрировать при смене сети;
- можно продолжать работу при блокировке одного path.

### 9.3. MVP-вариант

Для начала не нужен полноценный multipath packet scheduler.

Достаточно:

- основной path;
- standby fallback path;
- health check;
- быстрый switch при деградации.

Позже можно добавить:

- packet striping;
- FEC;
- duplicate critical packets;
- path-aware congestion control.

## 10. Network Profile Cache

### 10.1. Идея

Клиент должен запоминать особенности сети пользователя локально.

Например:

- дома работает UDP;
- в офисе UDP заблокирован;
- на мобильном операторе MTU лучше 1280;
- в кафе нужен HTTP/2 fallback;
- конкретный сервер даёт лучший RTT;
- конкретный DNS upstream нестабилен.

### 10.2. Что хранить

Только технические параметры:

- network fingerprint, без лишней приватной информации;
- last successful transport;
- measured MTU;
- average RTT;
- loss bucket;
- UDP availability;
- QUIC availability;
- fallback history;
- server score.

### 10.3. Что не хранить

Не хранить:

- историю сайтов;
- полный DNS log;
- содержимое трафика;
- user identity;
- чувствительные домены.

### 10.4. Польза

Маркетинговая идея:

> The VPN gets faster every time you use it.

## 11. Self-Healing / Zero-click Recovery

### 11.1. Цель

Пользователь не должен вручную чинить VPN.

Если что-то сломалось, клиент должен сам:

- переподключиться;
- сменить transport;
- сменить endpoint;
- уменьшить MTU;
- переключить DNS;
- восстановить routes;
- поднять TUN;
- пережить sleep/wake;
- пережить смену Wi-Fi/LTE.

### 11.2. События

Autopilot должен реагировать на:

- UDP timeout;
- TLS reset;
- packet loss spike;
- route failure;
- DNS failure;
- captive portal;
- network interface change;
- server overload;
- failed handshake;
- MTU black hole;
- sleep/wake.

### 11.3. UX

Пользователь видит не ошибку, а спокойный статус:

```text
Optimizing connection...
Reconnected securely
Protected
```

## 12. Privacy-preserving telemetry

### 12.1. Зачем

Чтобы построить сильную сеть, полезно знать:

- где UDP блокируется;
- где QUIC работает;
- какие сервера перегружены;
- какие регионы имеют высокий loss;
- где нужен fallback;
- какие MTU чаще работают.

Но нельзя превращать VPN в систему слежки.

### 12.2. Правильная модель

Телеметрия должна быть:

- opt-in;
- анонимной;
- агрегированной;
- без сайтов;
- без payload;
- без user id;
- с local preview;
- с differential privacy/noise;
- открыто задокументированной.

### 12.3. Что можно отправлять

Примеры допустимых сигналов:

- country/region bucket;
- ISP bucket, если безопасно;
- UDP available true/false;
- QUIC available true/false;
- RTT bucket;
- loss bucket;
- transport selected;
- generic failure category;
- server health metrics.

### 12.4. Что нельзя отправлять

- посещённые домены;
- IP пользователя в сыром виде;
- DNS queries;
- URL;
- SNI;
- payload;
- persistent user tracking id.

## 13. Censorship Weather Map

На базе privacy-preserving telemetry можно сделать внутреннюю или публичную карту состояния сети.

Она показывает:

- где UDP работает;
- где нужен HTTP/2 fallback;
- где высокий packet loss;
- какие сервера доступны;
- где блокируются endpoints;
- где лучше использовать bridges.

Это может стать data moat продукта.

Главное — не жертвовать приватностью.

## 14. Trustless / Verifiable Privacy

### 14.1. Почему это важно

VPN рынок страдает от проблемы доверия.

Пользователь должен верить, что VPN его не логирует.

Чтобы выиграть рынок, лучше не просить верить, а дать возможность проверять.

### 14.2. Идеи

- open-source client core;
- reproducible builds;
- independent security audits;
- public threat model;
- public protocol spec;
- transparency reports;
- warrant canary;
- RAM-only servers;
- minimal logs;
- blind tokens;
- anonymous account mode;
- key rotation;
- device keys вместо паролей;
- local telemetry preview.

### 14.3. Слоган

> Don't trust us. Verify us.

## 15. BlindPass Access

### 15.1. Идея

Обычная VPN-авторизация часто связывает пользователя, оплату, устройство и серверные подключения.

Можно сделать лучше:

- пользователь получает blind token;
- сервер может проверить, что токен действителен;
- сервер не может легко связать токен с личностью/покупкой;
- устройство использует device key;
- токены можно отзывать/обновлять.

### 15.2. Польза

- лучше приватность;
- меньше доверия к серверу;
- проще no-log story;
- сильнее маркетинг.

## 16. Personal Exit + Global Exit hybrid

### 16.1. Идея

Obsidian может поддерживать два мира:

1. Коммерческая VPN-сеть.
2. Личные приватные nodes пользователя.

### 16.2. Режимы

- Global Exit — обычные общие серверы.
- Personal Node — пользователь поднимает свой сервер.
- Trusted Circle — приватный сервер для семьи/команды.
- Business Gateway — private gateway для компании.

### 16.3. Преимущество

Один клиент, один протокол, разные сценарии.

Слоган:

> Your VPN. Your node. Your rules.

## 17. Local Privacy Firewall

### 17.1. Что добавить в клиент

- DNS leak protection;
- IPv6 leak protection;
- kill switch;
- app firewall;
- tracker blocking;
- malware DNS blocking;
- local network allow/block;
- per-app VPN;
- WebRTC leak warning;
- block internet if VPN down.

### 17.2. UX

Не делать 100 настроек на первом экране.

Сделать простой Privacy Health Score:

```text
VPN: protected
DNS: protected
IPv6: protected
Kill switch: enabled
Trackers blocked: 128
Privacy score: 96/100
```

## 18. Возможные пользовательские режимы

Для обычного пользователя — только Autopilot.

В advanced можно оставить понятные persona-пресеты:

- Auto;
- Streaming;
- Work;
- Travel;
- Privacy;
- Gaming.

Но это не должны быть технические переключатели transport/protocol.

Это должны быть intent-based настройки.

## 19. Roadmap

### Phase 1 — One-click Autopilot MVP

Цель: сделать продукт ощущаемо простым и самовосстанавливающимся.

Задачи:

- убрать технические настройки из основного GUI;
- оставить одну кнопку Connect;
- TLS/uTLS control channel;
- текущий custom UDP как fast data path;
- TCP fallback;
- automatic UDP probe;
- simple transport scoring;
- invisible fallback;
- DNS leak protection;
- базовый kill switch;
- network profile cache;
- базовая диагностика в GUI.

### Phase 2 — Smart Transport

Цель: сделать внешний трафик более web-like и устойчивый.

Задачи:

- настоящий HTTP/2 stream fallback;
- fake website / camouflage origin;
- better active probing behavior;
- QUIC/H3 prototype;
- MTU probing;
- path health checks;
- key rotation;
- cleaner transport interface.

### Phase 3 — QUIC / MASQUE-like

Цель: быстрый и более легитимный UDP-based transport.

Задачи:

- QUIC/H3 support;
- QUIC DATAGRAM;
- CONNECT-UDP-like mode;
- CONNECT-IP-like mode;
- UDP/443 default;
- H3 fallback;
- PMTU/DPLPMTUD;
- congestion/pacing tuning.

### Phase 4 — Per-flow Intelligence

Цель: routing по типу трафика.

Задачи:

- app-aware routing;
- domain-aware routing через локальный DNS cache;
- latency-sensitive policy;
- streaming policy;
- privacy-sensitive policy;
- local services bypass;
- GUI policy editor for advanced users.

### Phase 5 — Verifiable Privacy

Цель: доверие как конкурентное преимущество.

Задачи:

- open-source client core;
- reproducible builds;
- protocol spec;
- threat model;
- security audit;
- blind tokens;
- transparency report;
- local telemetry preview.

### Phase 6 — Network Moat

Цель: сеть, которая становится умнее со временем.

Задачи:

- opt-in private telemetry;
- censorship weather map;
- server health map;
- adaptive endpoint selection;
- bridge/private node system;
- endpoint rotation;
- privacy-preserving aggregate learning.

## 20. Что не делать

### 20.1. Не изобретать непроверенную криптографию для production

Можно экспериментировать, но production должен использовать проверенные primitive:

- X25519;
- HKDF;
- ChaCha20-Poly1305;
- AES-GCM;
- TLS 1.3;
- QUIC.

Новизна должна быть не в опасной самодельной крипте, а в:

- адаптации;
- routing intelligence;
- self-healing;
- UX;
- transport orchestration;
- privacy architecture.

### 20.2. Не показывать пользователю 100 настроек

Сложность внутри, снаружи одна кнопка.

### 20.3. Не делать WebSocket основным fast path

WebSocket хорош как fallback, но не как основной скоростной режим.

### 20.4. Не обещать абсолютную неблокируемость

Правильнее:

> Harder to block. Faster to recover. Automatic to use.

## 21. Связь с текущим кодом

Текущий проект уже имеет полезные части:

- собственный handshake;
- X25519/HKDF/ChaCha20-Poly1305;
- dynamic magic;
- padding/junk/noise;
- TCP tunnel;
- custom UDP data channel;
- TUN;
- split tunnel;
- GUI.

Для Autopilot MVP можно использовать текущую базу:

```text
control: existing TCP/TLS/uTLS path
   data: existing UDPChannel
fallback: existing TCP tunnel
     UX: one button, Auto mode only
```

Потом постепенно заменить/добавить:

- настоящий HTTP/2 fallback;
- QUIC/H3;
- MASQUE-like data;
- per-flow routing;
- privacy-preserving telemetry.

## 22. Краткая финальная формулировка

Obsidian Autopilot Network — это VPN нового поколения, где пользователь нажимает одну кнопку, а локальный Autopilot Engine сам выбирает транспорт, маршрут, DNS, MTU, уровень обфускации и fallback для каждого потока, сохраняя скорость и усиливая защиту только когда это необходимо.

Ключевые обещания:

- one-click UX;
- высокая скорость;
- адаптивная защита;
- невидимый fallback;
- self-healing соединение;
- per-flow intelligence;
- проверяемая приватность.

Главная продуктовая идея:

> Not just a VPN tunnel — a self-optimizing privacy network.
