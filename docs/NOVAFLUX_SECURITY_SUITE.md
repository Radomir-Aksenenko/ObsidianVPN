# NovaFlux Security Suite — исследовательская криптографическая концепция

> Статус: research/lab design. Этот документ описывает собственную экспериментальную криптографическую систему для Obsidian Nova. Она нужна для исследований, бенчмарков и экспериментов. До независимого анализа, тестирования и аудита её нельзя считать production-безопасной.

## 1. Главная идея

NovaFlux Security Suite — это не просто один шифр. Это полный слой безопасности для Obsidian Nova Protocol.

Он должен покрывать:

- шифрование пакетов;
- аутентификацию пакетов;
- защиту заголовков;
- route/session tags;
- key derivation;
- rekey/ratchet;
- anti-replay;
- handshake proofs;
- session migration tokens;
- active probing resistance;
- traffic analysis mitigation hooks.

Рабочая философия:

> Мы можем экспериментировать со своей криптографией, но должны отделять research crypto от production crypto. Новизна может жить в архитектуре, packet protection, scheduling, ratchet и transport fabric, а production-безопасность позже должна опираться на проверенные primitives или пройти серьёзный аудит.

## 2. Компоненты NovaFlux Security Suite

| Компонент | Назначение |
|---|---|
| `NovaFlux` | потоковое шифрование / экспериментальный AEAD |
| `NovaSponge` | sponge/hash/KDF/MAC construction |
| `NovaSeal` | защита одного packet/bundle |
| `NovaMask` | header protection |
| `NovaTag` | route/session tag derivation |
| `NovaRatchet` | rekey и epoch rotation |
| `NovaProof` | handshake proof / transcript proof |
| `NovaWindow` | anti-replay sliding window |
| `NovaPuzzle` | optional anti-abuse puzzle |
| `NovaNoise` | генерация indistinguishable noise cells |

## 3. Research vs Production

### 3.1. Research Crypto Branch

Research branch может включать:

- полностью свой stream cipher;
- свой sponge;
- свой MAC;
- свой ratchet;
- собственный handshake flow;
- экспериментальный KEM;
- нестандартные header protection схемы.

Но это должно быть явно помечено:

> Experimental. Not for production security.

### 3.2. Production Crypto Branch

Production branch должна иметь такую же внешнюю архитектуру, но внутренние primitives должны быть проверенными.

Возможные primitives:

- X25519 / hybrid KEM;
- HKDF / KMAC / BLAKE3-based KDF;
- ChaCha20-Poly1305;
- AES-GCM-SIV;
- SHA-3/SHA-2/BLAKE3;
- standard constant-time implementations.

Важный принцип:

> Даже если NovaFlux как cipher не пойдёт в production, NovaSeal, NovaRatchet, route tags, packet fabric, scheduler и protocol architecture останутся ценными.

## 4. Почему не блочный шифр

Не начинаем с собственного аналога AES.

Причины:

- блочные шифры сложнее проектировать;
- нужны S-box или сложные нелинейные слои;
- нужен дифференциальный и линейный анализ;
- высок риск незаметной уязвимости;
- без аппаратного ускорения можно проиграть по скорости.

Вместо этого NovaFlux строится как ARX/sponge/duplex design.

ARX:

- Addition;
- Rotation;
- XOR.

Плюсы:

- быстро на CPU;
- удобно писать на Go/Rust/C;
- нет lookup tables;
- проще соблюдать constant-time;
- хорошо подходит для потокового шифрования.

## 5. NovaFlux AEAD — общая концепция

NovaFlux — экспериментальный потоковый AEAD.

Он работает как duplex sponge:

1. Инициализирует внутреннее состояние.
2. Впитывает domain tag.
3. Впитывает key.
4. Впитывает nonce.
5. Впитывает associated data.
6. Генерирует keystream.
7. XOR keystream с plaintext.
8. Впитывает ciphertext для authentication.
9. Финализирует состояние.
10. Выдаёт authentication tag.

Цель:

- encryption;
- authentication;
- flexible KDF/MAC reuse через domain separation;
- packet-oriented API;
- in-place encryption where possible;
- no secret-dependent memory lookup.

## 6. NovaFlux параметры v0

| Параметр | Значение |
|---|---:|
| State size | 1024 bit |
| Words | 16 × uint64 |
| Key size | 256 bit / 32 bytes |
| Nonce size | 192 bit / 24 bytes |
| Default tag | 128 bit / 16 bytes |
| Optional high-security tag | 192/256 bit |
| Rate | 512 bit |
| Capacity | 512 bit |
| Default rounds | 16 |
| Fast test rounds | 12 |
| Paranoid rounds | 24 |

Почему так:

- 1024-bit state даёт исследовательский запас;
- 64-bit words быстры на современных CPU;
- 192-bit nonce снижает риск повторов;
- 512-bit capacity даёт большой запас для sponge;
- 512-bit rate позволяет обрабатывать данные блоками по 64 bytes.

## 7. State layout

Внутреннее состояние:

```text
s[0..15] uint64
```

Концептуальное назначение:

| Word | Назначение |
|---|---|
| `s0..s3` | absorbed key material |
| `s4..s6` | nonce material |
| `s7` | counter/domain/control word |
| `s8..s11` | constants / session salt |
| `s12..s15` | accumulator/auth state |

Важно: key не должен просто лежать в state без перемешивания. Key должен быть absorbed и перемешан permutation.

## 8. NovaPerm-16

NovaPerm-16 — permutation над 16 × uint64.

Один round состоит из:

1. Column mixing.
2. Diagonal mixing.
3. Rotation layer.
4. Optional nonlinear add/multiply layer.
5. Constant injection.
6. Word permutation.

Режимы:

| Mode | Rounds | Назначение |
|---|---:|---|
| `Flux12` | 12 | быстрые лабораторные тесты |
| `Flux16` | 16 | default research mode |
| `Flux24` | 24 | paranoid/research margin |

## 9. Quarter Mix

Базовая функция смешивания четырёх слов.

Концептуальный вариант ARX-only:

```text
Mix(a, b, c, d):
  a = a + b
  d = rotl(d xor a, 32)
  c = c + d
  b = rotl(b xor c, 27)

  a = a + b
  d = rotl(d xor a, 19)
  c = c + d
  b = rotl(b xor c, 13)

  a = a + rotl(c, 41)
  d = d xor rotl(b, 17)
```

Экспериментальный ARXM-вариант может добавить multiplication mixing:

```text
ARXM extra:
  a = a xor low64(c * C1)
  d = d + rotl(b, 41)
```

Но multiplication спорный:

Плюсы:

- может улучшить avalanche;
- добавляет нелинейность;
- может быстрее смешивать state.

Минусы:

- сложнее анализ;
- возможная разная производительность на CPU;
- потенциальные side-channel вопросы на некоторых платформах;
- может быть медленнее.

Начальный baseline: **ARX-only**.

## 10. Domain separation

Один и тот же sponge/permutation нельзя использовать одинаково для разных целей.

Каждая операция имеет domain tag.

| Domain | Назначение |
|---|---|
| `0x01` | packet encryption |
| `0x02` | packet authentication/finalization |
| `0x03` | header masking |
| `0x04` | route tag derivation |
| `0x05` | key derivation |
| `0x06` | handshake proof |
| `0x07` | ratchet |
| `0x08` | path token |
| `0x09` | padding/noise generation |
| `0x0A` | transcript hash |
| `0x0B` | anti-abuse puzzle |

Каждый API вызов должен явно принимать domain/purpose label.

## 11. NovaSponge

NovaSponge — обобщённая sponge/duplex construction на NovaPerm-16.

Используется для:

- KDF;
- MAC;
- route tags;
- transcript hash;
- handshake proof;
- padding randomness;
- challenge tokens;
- ratchet derivation.

Концептуальный API:

```text
Init(domain)
Absorb(context)
Absorb(input)
Permute(rounds)
Squeeze(n)
Reset/Wipe
```

Правила:

- всегда использовать domain separation;
- включать lengths в transcript там, где важна однозначность;
- не смешивать разные protocol purposes без labels;
- wipe state после использования, если в нём key material.

## 12. NovaFlux Encrypt

Вход:

- `key[32]`;
- `nonce[24]`;
- `aad`;
- `plaintext`;
- `domain`;
- `rounds`.

Шаги:

```text
1. Initialize state with constants.
2. Absorb domain.
3. Absorb key.
4. Absorb nonce.
5. Permute.
6. Absorb AAD length and AAD.
7. Permute.
8. For each plaintext block:
     keystream = Squeeze(rate)
     ciphertext_block = plaintext_block xor keystream
     Absorb(ciphertext_block)
     Permute as needed
9. Absorb final lengths.
10. Absorb finalization domain.
11. Permute.
12. Squeeze tag.
13. Return ciphertext || tag.
```

## 13. NovaFlux Decrypt

Вход:

- `key`;
- `nonce`;
- `aad`;
- `ciphertext`;
- `tag`.

Шаги:

```text
1. Initialize the same state.
2. Generate the same keystream.
3. Decrypt internally: plaintext = ciphertext xor keystream.
4. Recompute authentication tag.
5. Constant-time compare tag.
6. If tag invalid: return generic authentication failure.
7. If tag valid: return plaintext.
```

Важное правило:

> API верхнего уровня не должен отдавать plaintext до успешной проверки tag.

## 14. Tag sizes

| Mode | Tag size |
|---|---:|
| lab-fast | 128 bit |
| default | 128 bit |
| high-security research | 192 bit |
| paranoid research | 256 bit |

Для VPN default 128-bit tag достаточно как practical target, но research branch может поддерживать больше.

## 15. NovaSeal packet protection

NovaSeal защищает один Nova bundle.

Вход:

- epoch keys;
- direction;
- epoch id;
- packet number;
- carrier id;
- plaintext bundle;
- visible metadata;
- padding policy.

Выход:

- route tag;
- masked header;
- ciphertext;
- auth tag.

## 16. Nova Datagram security format

Внешний packet format:

| Поле | Размер | Комментарий |
|---|---:|---|
| `route_tag` | 8 bytes | pseudorandom lookup tag |
| `masked_header` | 12 bytes | protected epoch/pn/flags/carrier |
| `ciphertext` | variable | encrypted bundle |
| `auth_tag` | 16 bytes default | authentication tag |

Default overhead:

```text
8 + 12 + 16 = 36 bytes
```

Это немного больше текущего UDP overhead, но даёт:

- epoch support;
- masked packet number;
- route lookup;
- future migration;
- better anti-replay;
- hidden packet metadata.

## 17. Header plaintext до masking

До masking header содержит:

| Поле | Размер |
|---|---:|
| `epoch_id` | 2 bytes |
| `packet_number` | 8 bytes |
| `flags` | 1 byte |
| `carrier_id` | 1 byte |

Итого: 12 bytes.

Этот header никогда не должен уходить наружу plaintext.

## 18. NovaMask header protection

NovaMask скрывает header.

Идея:

```text
sample = first 16/32 bytes of ciphertext
mask = NovaSponge/NovaFlux(k_mask, domain=header_mask, sample, route_tag)[:12]
masked_header = header xor mask
```

Без ключа нельзя увидеть:

- epoch id;
- packet number;
- flags;
- carrier id.

Правила:

- sample должен существовать даже для маленьких packets;
- для короткого ciphertext можно использовать padded sample;
- failure не должен раскрывать причину.

## 19. NovaTag route tag

Серверу нужен быстрый lookup session, но стабильный session id светить нельзя.

Route tag:

```text
route_tag = Truncate64(NovaSponge(domain=route_tag, k_route, epoch_id, direction, optional_time_bucket))
```

Свойства:

- выглядит pseudorandom;
- меняется при epoch rotation;
- может иметь overlap window для migration/reorder;
- unknown tags silently ignored или обрабатываются как noise/probe.

## 20. Nonce discipline

Главное правило:

> Один и тот же nonce не должен повторяться с одним и тем же key.

NovaSeal nonce:

```text
nonce = base_nonce_for_epoch
nonce[16..23] xor= packet_number
nonce[14..15] xor= epoch_id
nonce[13] xor= direction
nonce[12] xor= carrier_id
```

Альтернативный дорогой вариант:

```text
nonce = NovaSponge(k_nonce, epoch_id || packet_number || direction || carrier_id)[:24]
```

Для hot path лучше использовать base nonce + packet number mixing.

Правила:

- packet number monotonic per direction/epoch;
- no reuse after restart;
- epoch keys rotate before packet number exhaustion;
- persistent sessions должны хранить enough state или делать новый handshake.

## 21. NovaRatchet

Сессия делится на epochs.

Каждый epoch имеет отдельные ключи.

| Key | Назначение |
|---|---|
| `k_seal_c2s` | packet encryption client -> server |
| `k_seal_s2c` | packet encryption server -> client |
| `k_mask_c2s` | header mask client -> server |
| `k_mask_s2c` | header mask server -> client |
| `k_route_c2s` | route tag client -> server |
| `k_route_s2c` | route tag server -> client |
| `k_path` | migration/path token |
| `k_noise` | padding/noise generation |
| `k_next` | next epoch derivation |

## 22. Rekey triggers

Epoch меняется по:

| Триггер | Значение |
|---|---|
| Time | каждые 5–15 минут |
| Bytes | каждые 512 MB / 1 GB |
| Packets | до nonce safety limit |
| Migration | optional forced rekey |
| Suspicion | forced rekey при подозрительных событиях |
| Reconnect | новый epoch/session |

## 23. Forward secrecy и future secrecy

### 23.1. Symmetric ratchet

Если каждый epoch derived так:

```text
next_secret = NovaSponge(domain=ratchet, current_secret, transcript, epoch_id)
```

и старый secret удаляется, то компрометация текущего secret не раскрывает прошлые epochs.

### 23.2. Ограничение

Если attacker получил текущий secret и ratchet purely symmetric, он может вычислять будущие secrets.

### 23.3. Решение

Для future secrecy нужен периодический asymmetric refresh:

- DH refresh;
- KEM refresh;
- post-quantum hybrid refresh в будущем;
- или новый full handshake.

Research v0:

- symmetric ratchet.

Research v1:

- optional asymmetric refresh.

Production:

- проверенный DH/KEM refresh.

## 24. NovaWindow anti-replay

Для каждого direction/epoch receiver держит sliding window.

Параметры:

| Параметр | Значение |
|---|---:|
| Default window | 4096 packets |
| Small/lab window | 2048 packets |
| Large/high reorder | 8192 packets |

Правила:

1. Packet сначала аутентифицируется.
2. Header unmask после получения candidate session keys.
3. Packet number проверяется anti-replay window.
4. Duplicate reject.
5. Too old reject.
6. Future packet within range accepted and advances window.

Важно:

> Replay check желательно делать после authentication, чтобы не давать oracle по packet number.

## 25. NovaProof handshake authentication

Handshake proof должен связывать:

- client random;
- server random;
- selected params;
- transcript;
- token/PSK/client secret;
- server identity или verifier;
- protocol version inside encrypted transcript.

Цель:

- mutual confirmation;
- no fixed magic;
- no obvious reject;
- replay resistance;
- active probing resistance.

## 26. Handshake modes

### 26.1. NovaPSK

Самый простой research mode.

Стороны заранее знают PSK/token.

Плюсы:

- простой;
- быстрый;
- позволяет тестировать NovaFlux/NovaSeal/NovaRatchet;
- нет сложной asymmetric crypto.

Минусы:

- плохая масштабируемость;
- PSK compromise опасен;
- forward secrecy ограничена без DH/KEM;
- token distribution становится критичным.

### 26.2. NovaStatic

Research mode с server identity и client token/verifier.

Цель:

- клиент знает server identity;
- сервер проверяет client token/proof;
- handshake не раскрывает явный protocol marker;
- active probe не получает полезного ответа.

Без проверенной asymmetric primitive полноценная PFS ограничена.

### 26.3. NovaHybrid

Будущий production-oriented mode.

Сочетает:

- проверенный DH/KEM;
- NovaSeal/NovaRatchet/NovaMask packet layer;
- optional NovaFlux research cipher only in lab.

## 27. NovaPSK Handshake v0

Этапы:

1. ClientSpark.
2. ServerEmber.
3. ClientSeal.
4. SecureFabric.

### 27.1. ClientSpark

Клиент отправляет random-looking blob.

Содержимое после обработки:

- client nonce;
- timestamp bucket;
- supported params;
- encrypted client proof;
- random padding.

Нет fixed magic.

### 27.2. ServerEmber

Сервер отвечает random-looking blob.

Содержимое:

- server nonce;
- selected params;
- encrypted server proof;
- initial epoch info;
- optional retry/path token;
- padding.

### 27.3. ClientSeal

Клиент подтверждает:

- transcript proof;
- selected params accepted;
- session keys match;
- ready for SecureFabric.

### 27.4. Key derivation

Conceptual:

```text
transcript = Hash(ClientSpark || ServerEmber || ClientSealParams)
master = NovaSponge(domain=KDF, psk, client_nonce, server_nonce, transcript)
epoch0_secret = NovaSponge(domain=ratchet, master, "epoch0")
keys = Expand(epoch0_secret, labels...)
```

## 28. Experimental asymmetric idea: NovaLattice-Lab

Если хочется исследовать полностью свой asymmetric primitive, можно сделать отдельный toy/lab KEM.

Идея направления:

- module-lattice style KEM;
- public matrix from seed;
- secret vector;
- noisy linear transform;
- encapsulation with noise;
- decapsulation with reconciliation.

Важно:

> NovaLattice-Lab нельзя использовать для VPN security без серьёзной cryptanalysis. Параметры, side-channel resistance и failure behavior критичны.

Для практического прототипа сначала лучше NovaPSK + NovaFlux/NovaSeal.

## 29. NovaPuzzle anti-abuse

NovaPuzzle нужен только при перегрузке или подозрительном поведении.

Принцип:

- сервер даёт challenge;
- клиент ищет nonce;
- proof должен иметь N leading zero bits или другой condition;
- сложность адаптивная.

Использовать только если:

- слишком много failed handshakes;
- сервер под нагрузкой;
- IP/subnet подозрительный;
- нужно защитить CPU-heavy операции.

Не использовать always-on, чтобы не портить UX и батарейку.

## 30. Active probing resistance

Правила:

1. Нет fixed magic bytes.
2. Первый packet выглядит как random blob.
3. Разные reject причины не дают разные явные ответы.
4. Invalid packets чаще silently drop.
5. Rate limit expensive paths.
6. Optional delayed response для suspicious peers.
7. Optional fake response/fallback на stream carriers.
8. Handshake errors не логировать наружу подробно.
9. Timing reject path должен быть по возможности выровнен.

## 31. Traffic analysis hooks

Криптография не скрывает:

- размеры;
- timing;
- направления;
- burst patterns.

Поэтому NovaFlux Security Suite должен поддерживать hooks:

- length buckets;
- padding budget;
- cover cells;
- adaptive noise;
- packet coalescing;
- burst shaping;
- idle camouflage.

Но heavy mode нельзя включать всегда.

## 32. Length hiding

Bucket strategy:

| Реальная длина | Bucket |
|---:|---:|
| 1–64 | 64 |
| 65–128 | 128 |
| 129–256 | 256 |
| 257–512 | 512 |
| 513–1024 | 1024 |
| 1025–MTU | MTU |

Default policy:

- small packets bucketized lightly;
- bulk packets minimal padding;
- suspicious network increases padding;
- strict overhead budget.

## 33. Noise generation

Noise cells должны быть неотличимы от data cells на уровне encrypted cell kind.

Снаружи всё равно видны size/timing, поэтому noise policy должна быть adaptive.

Policy:

- idle noise low;
- handshake noise medium;
- suspicious network noise higher;
- never exceed protection budget;
- noise dropped first under congestion.

## 34. Side-channel rules

Даже research implementation должна соблюдать:

- constant-time tag compare;
- no secret-dependent branches in crypto core;
- no secret-dependent table lookup;
- no S-box tables;
- no early plaintext return before auth;
- generic decrypt errors;
- wipe key material where possible;
- no secret logging;
- fuzz malformed packets;
- decode limits before allocations.

## 35. Decode safety

Любой decode path должен иметь ограничения:

- max packet size;
- max cells per bundle;
- max fragments per flow;
- max reassembly buffer;
- max handshake size;
- timeout for partial state;
- per-peer rate limits;
- global CPU limits for expensive operations.

## 36. Fragment safety

Защита от memory exhaustion через fragments:

- fragment id random/large enough;
- max pending fragments per session;
- max pending bytes per session;
- fragment timeout;
- duplicate fragment handling;
- reject impossible fragment layouts;
- cleanup on session close/rekey.

## 37. Logging hygiene

Нельзя логировать:

- PSK;
- tokens;
- session secrets;
- epoch keys;
- raw decrypted packets;
- full handshakes;
- route keys;
- path tokens.

Можно логировать:

- generic failure category;
- counters;
- RTT/loss buckets;
- selected carrier;
- session short debug id derived for logs only, not network-visible.

## 38. Test plan

### 38.1. Correctness

- encrypt/decrypt roundtrip;
- empty plaintext;
- empty AAD;
- large plaintext;
- wrong tag reject;
- wrong AAD reject;
- wrong nonce reject/garbage;
- wrong key reject;
- truncated ciphertext;
- corrupted route tag;
- corrupted masked header;
- epoch transition;
- replay reject;
- packet reorder accept within window.

### 38.2. Avalanche tests

Flip one bit in:

- key;
- nonce;
- AAD;
- plaintext;
- domain;
- state word.

Expected research target:

- around 50% output bit change after enough rounds.

### 38.3. Statistical smoke tests

- bit frequency;
- byte frequency;
- runs;
- serial correlation;
- chi-square;
- repeated nonce detection tests;
- similar input differential smoke tests.

### 38.4. Fuzzing

Fuzz:

- NovaFlux decrypt;
- NovaSeal open;
- header unmask;
- bundle decode;
- handshake parser;
- fragment reassembly;
- anti-replay window.

Inputs:

- random bytes;
- truncated packets;
- oversized packets;
- malformed lengths;
- random route tags;
- old epoch ids;
- huge cell counts;
- corrupted ciphertext.

### 38.5. Benchmarks

Measure:

- MB/s encryption;
- packets/s for 64-byte packets;
- packets/s for 1500-byte packets;
- allocations/op;
- ns/op seal/open;
- latency added per packet;
- overhead vs current UDPChannel;
- compare NovaFlux vs ChaCha20-Poly1305 baseline.

## 39. Performance goals

Initial goals:

| Metric | Target |
|---|---:|
| Seal/Open allocations | 0–1 alloc/op |
| Small packet overhead | acceptable under benchmark |
| 1500-byte packet latency | near current AEAD path |
| Throughput vs current UDPChannel | not worse by >10–15% in v0 |
| Route lookup | O(1) map by route tag |
| Anti-replay check | O(1) |

Optimization principles:

- in-place encryption where possible;
- buffer pools;
- no reflection in hot path;
- no debug logging in hot path;
- fixed-size structs;
- avoid per-packet heap allocation;
- pprof early.

## 40. Concrete v0 proposal

### 40.1. NovaFlux-16

- state: 16 × uint64;
- key: 32 bytes;
- nonce: 24 bytes;
- tag: 16 bytes;
- rounds: 16;
- operation: ARX-only;
- mode: duplex AEAD;
- no lookup tables;
- no secret-dependent branches.

### 40.2. NovaSeal-v0

- route tag: 8 bytes;
- masked header: 12 bytes;
- auth tag: 16 bytes;
- packet number: uint64;
- epoch: uint16;
- anti-replay window: 4096;
- packet types hidden inside encrypted bundle.

### 40.3. NovaRatchet-v0

- PSK/session secret initial;
- derive epoch keys with NovaSponge;
- rekey every 10 minutes or 1 GB;
- keep previous epoch for short overlap;
- wipe expired keys.

### 40.4. NovaHandshake-v0

- PSK/token based;
- ClientSpark / ServerEmber / ClientSeal;
- no fixed magic;
- random padding;
- transcript hash via NovaSponge;
- session keys via NovaSponge;
- generic failure behavior.

## 41. Почему это может быть быстрым

NovaFlux/NovaSeal может быть быстрым, потому что:

- ARX operations дешёвые;
- потоковый режим без block padding;
- packet encryption can be in-place;
- header masking короткий;
- route tag lookup O(1);
- no table lookups;
- no asymmetric crypto на data path;
- rekey не на каждый packet;
- nonce derivation дешёвая через base nonce + packet number.

Риски для скорости:

- Go-реализация может проиграть оптимизированному ChaCha20;
- 1024-bit state может быть тяжелее;
- слишком много rounds;
- KDF per packet слишком дорогой;
- лишние allocations;
- heavy padding/noise;
- debug logging.

Поэтому обязательно сравнение с baseline.

## 42. Почему это может быть безопасным как исследование

Системно закладываются правильные свойства:

- AEAD-like API;
- nonce discipline;
- key separation;
- anti-replay;
- ratchet;
- protected headers;
- no fixed magic;
- route tags instead of session ids;
- constant-time checks;
- decode limits;
- fuzzing.

Но сам NovaFlux как новый cipher не считается доказанно безопасным.

Жёсткое правило:

> NovaFlux можно использовать для лаборатории и бенчмарков. Для production либо нужен длительный криптоанализ и аудит, либо замена внутреннего cipher на проверенный AEAD при сохранении NovaSeal/NovaRatchet архитектуры.

## 43. Первые шаги реализации

1. Создать `obsidian/nova/crypto`.
2. Описать интерфейс AEAD-like cipher.
3. Реализовать baseline wrapper на ChaCha20-Poly1305 для сравнения.
4. Реализовать skeleton NovaSponge.
5. Реализовать NovaPerm-16 ARX-only.
6. Реализовать NovaFlux seal/open.
7. Реализовать test vectors.
8. Реализовать avalanche tests.
9. Реализовать NovaSeal packet format.
10. Реализовать anti-replay window.
11. Реализовать benchmarks.
12. Сравнить NovaFlux против baseline.

## 44. Итог

NovaFlux Security Suite — это исследовательская попытка создать собственный security layer для Obsidian Nova:

- свой stream/duplex AEAD;
- свой sponge/KDF/MAC;
- свой packet protection;
- protected headers;
- rotating route tags;
- epoch ratchet;
- anti-replay;
- active probing resistance hooks.

Это даст свободу экспериментов и может привести к сильной новой архитектуре.

Но принципиально важно:

> Своё шифрование — research. Новая архитектура — потенциальное production-преимущество. Production-безопасность должна быть либо проверенной, либо независимо доказанной и audited.
