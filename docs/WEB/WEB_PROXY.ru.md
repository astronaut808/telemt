# WEB-режим прокси

[English](WEB_PROXY.en.md) | [Русский](WEB_PROXY.ru.md) | [Deutsch](WEB_PROXY.de.md)

WEB-режим переносит обычные MTProxy-потоки через bounded HTTPS или WebSocket carriers, совместимые с типом прокси `WEB` в Telegram Desktop. Telemt не терминирует TLS: публичный сертификат обслуживает NGINX или HAProxy, который передаёт обычный HTTP/1.1 на приватный listener Telemt.

> [!IMPORTANT]
>
> WEB-режим реализован и настраивается в текущем дереве исходного кода. Для первого развёртывания нужен бинарный файл, собранный из ревизии с этой реализацией, и перезапуск процесса Telemt. Готовый пакет можно использовать только после проверки, что он содержит эту ревизию. Сквозная проверка с целевой сборкой Telegram Desktop и реальным публичным TLS endpoint остаётся обязательным приёмочным шагом оператора.

## Путь трафика

```text
Telegram Desktop
    | HTTPS или WSS :443
    v
NGINX или HAProxy (TLS termination, канонический Host и один адрес X-Forwarded-For)
    | обычный HTTP/1.1 в приватной сети
    v
WEB-listener Telemt
    |-- аутентифицированный carrier --> bounded logical MTProxy relays --> Telegram
    `-- обычный или некорректный запрос --> настроенный decoy site
```

Направляйте в Telemt весь публичный vhost. Если TLS-терминатор будет выделять только известные carrier paths, поведение обычных и аутентифицированных запросов станет наблюдаемо различным, а decoy policy Telemt будет обойдена.

## Поддерживаемый контракт клиента

- Публичный endpoint всегда имеет вид `https://HOST:443`.
- Поддерживаются 16-байтовые MTProxy-секреты `plain` и `dd`. FakeTLS-секреты `ee` в WEB-режиме не поддерживаются.
- `web.carrier` выбирает единственный carrier при выключенном auto-negotiation и последний fallback при включённом. `https` использует сериализованные HTTPS uplink и long polling. `https-lanes` использует независимые HTTPS sequencing и polling для каждого logical stream. `websocket` использует один упорядоченный WebSocket для всех streams. `websocket-lanes` использует отдельный WebSocket с независимым ownership для каждого ненулевого logical stream.
- Отсутствующий `web.carriers` или `web.carriers = false` отключает auto-negotiation и обучение. Непустой массив включает только стартовый последовательный перебор; уже committed session никогда не мигрирует.
- Нативные клиенты без канонических headers carrier negotiation используют настроенный фиксированный `carrier`, даже когда `carriers` включает negotiation для поддерживающих его клиентов. Текущий Telegram iOS поддерживает только `https`, поэтому для metadata-free iOS оператор должен задать `web.carrier = "https"`; `https-lanes` этим клиентом не поддерживается. User-Agent, включая CFNetwork или Darwin, никогда не выводит capabilities неявно. Если нативный iOS всё же отправляет явные negotiation metadata, Telemt пересекает их с server-authoritative ceiling `{https}` и отклоняет пустой результат; остальные явные клиенты используют заявленный capability set.
- Capability, bootstrap и session credentials — отдельные значения с ограниченным сроком жизни. Carrier credentials считаются секретами и не должны попадать в access logs.
- Bootstrap является bearer credential, а не token с привязкой к source address. Адрес клиента и его IP-семейство могут измениться между загрузкой bridge и созданием session. Адрес выдачи продолжает учитываться в лимите неиспользованных bootstrap, а владельцем session становится адрес первого корректного запроса создания.
- Внутренняя MTProxy-аутентификация ограничена пользователем и режимом секрета, выбранными профилем vhost. Некорректный внутренний handshake закрывает только свой logical stream и никогда не попадает в TCP masking path.

В WEB-ссылках Telegram Desktop нет порта, потому что клиент требует порт 443:

```text
tg://webproxy?server=proxy.example.com&secret=0123456789abcdef0123456789abcdef
tg://webproxy?server=proxy.example.com&secret=dd0123456789abcdef0123456789abcdef
```

Telemt печатает ссылки для WEB-профилей, выбранных в `[general.links].show`, через существующий log target `telemt::links`.

## Предварительные требования

- Отдельный публичный FQDN и действующий TLS-сертификат на NGINX или HAProxy.
- Стабильный публичный IP этого hostname. В `public_addr` должен быть указан именно этот конкретный IP с портом 443, поскольку адрес участвует во внутреннем destination tuple relay.
- Приватный или loopback HTTP-путь от TLS-терминатора до Telemt.
- Обычный decoy site: приватный HTTP origin либо immutable snapshot локального каталога.
- Совместимая сборка Telegram Desktop с типом прокси `WEB`.

Forwarded client address может принадлежать другому IP-семейству, чем `public_addr`, и изменяться в течение срока жизни bootstrap. При этом `public_addr` должен по-прежнему указывать точный публичный endpoint внутреннего MTProxy route.

## Минимальная конфигурация Telemt

В примере WEB-listener остаётся на loopback, а decoy использует приватный HTTP origin:

```toml
[general.links]
show = ["web-user"]

[access.users]
web-user = "0123456789abcdef0123456789abcdef"

[[server.listeners]]
ip = "127.0.0.1"
port = 18080
transport = "web"
proxy_protocol = false
web_client_ip_source = "x_forwarded_for"
web_trusted_proxy_cidrs = ["127.0.0.1/32"]

[web]
enabled = true
carrier = "https-lanes"

[[web.vhosts]]
host = "proxy.example.com"
public_addr = "203.0.113.10:443"

[web.vhosts.decoy]
mode = "http_upstream"
upstream = "http://127.0.0.1:18081"

[[web.vhosts.profiles]]
user = "web-user"
secret_mode = "dd"
max_sessions = 8
max_streams = 512
max_streams_per_session = 64
```

## Server-side negotiation carrier

Auto-negotiation необязателен и выключен, пока `carriers` не задан явным непустым массивом. Настроенный `carrier` остаётся последним fallback и добавляется ровно один раз, даже если уже присутствует в массиве:

```toml
[web]
enabled = true
carrier = "https"
carriers = ["websocket-lanes", "websocket", "https-lanes"]
carrier_learning = true
carrier_negotiation_aggressiveness = "conservative"

[web.timeouts]
carrier_negotiation_deadlines_secs = [3, 5, 8, 12]
carrier_health_secs = 30
carrier_learning_secs = 600
bridge_request_secs = 10
bridge_retry_secs = 90
carrier_probe_coalesce_ms = 0
```

Сгенерированный bridge отправляет канонические headers `X-Carrier-Capabilities`, `X-Carrier-Attempt` и, после первой попытки, `X-Carrier-Failure` в запросе `/session`. Каждый успешный automatic response возвращает `X-Carrier-Mode`, `X-Carrier-Attempt`, `X-Carrier-Candidate-Count`, `X-Carrier-Deadline` и `X-Carrier-State`. Bridge запускает локальный cumulative clock непосредственно перед первым запросом `/session`, а сервер фиксирует отдельный absolute chain deadline при приёме первой automatic attempt. Оба используют настроенные offsets и не сбрасываются при replacement. Для одного, двух, трёх и четырёх effective candidates checkpoints attempts равны соответственно `[d3]`, `[d0, d3]`, `[d0, d1, d3]` и `[d0, d1, d2, d3]`; финальному candidate всегда принадлежит `d3`. Successor остаётся допустимым до собственного checkpoint. Состояния: `provisional`, `committed` и `healthy`.

Попытки строго последовательны. Принятый прогресс `OPEN` или `DATA` немедленно фиксирует выбранный carrier и окончательно закрывает границу replacement. Аутентифицированный `409` для committed chain повторяет metadata зафиксированного carrier и является terminal response, а не разрешением перейти дальше. Точный replay `/session` применяется только пока результат этого запроса неоднозначен. После аутентифицированного выбора provisional carrier transport failure сразу запрашивает следующую attempt; если предыдущий probe всё же успел committed, сервер возвращает terminal `409` и не разрешает небезопасный replacement. Финальный абсолютный deadline на сервере также ограничивает lifetime successor, ответ которого клиент не получил. Динамическое post-commit переключение намеренно не поддерживается: для смены carrier требуется новая сессия.

Каждая HTTP-операция bridge имеет абсолютный budget `bridge_retry_secs` и не более девяти attempts. `bridge_request_secs` охватывает Fetch response head и полное чтение response body; для downlink attempt дополнительно разрешён настроенный long-poll interval. Network failures и ответы `408`, `429`, `502`, `503` или `504` используют bounded exponential backoff, а `Retry-After` не может расширить абсолютный budget. При `carrier_probe_coalesce_ms = 0` первый упорядоченный probe с `OPEN` отправляется немедленно. Значение до 10 мс позволяет включить соответствующий `DATA`, пришедший в этом окне; multiplexed carriers сохраняют весь предшествующий порядок frames, а lane carriers забирают только выбранную lane. HTTP downlink не запускается до acknowledgement probe. Multiplexed WebSocket Upgrade может начаться сразу после его выбора ответом `/session` и затем включить queued probe data; lane WebSocket ждёт известного stream ID.

Automatic WebSocket использует `tproxy-auto-v1.<session-token>` или `tproxy-auto-lane-v1.<session-token>.<stream-id>`. Первое принятое binary message с реальным прогрессом `OPEN` или `DATA` фиксирует carrier; затем сервер пишет пустой binary commit ACK именно в это connection. Ping/Pong не фиксирует carrier и не считается learning evidence.

Committed attempt становится healthy, только когда transport-specific двунаправленный evidence остаётся корректным в течение `carrier_health_secs`. HTTPS требует принятый `DATA`, подтверждённый непустой post-commit downlink batch и аутентифицированную активность не раньше health deadline. WebSocket требует записи точного commit ACK, последующего принятого `OPEN` или `DATA` от того же owner и сохранения этого owner живым до конца интервала. Более раннее закрытие нейтрально и не записывает результат обучения.

Обучение process-local, in-memory, positive-only и ограничено `max_carrier_learning_entries`. Оно ранжирует только поддерживаемые клиентом настроенные candidates, всегда оставляет fallback последним и сохраняет настроенный порядок при равных scores. Evidence User-Agent и профиля имеет основной вес; допустимый IP служит только tie-breaker. Для IP evidence требуется ровно один явный глобально маршрутизируемый `X-Forwarded-For`; private, loopback, link-local, carrier-grade NAT, documentation, multicast и их IPv4-mapped эквиваленты исключаются. Категории ошибок от клиента и request latency используются только для диагностики и не создают отрицательный или ranking evidence. `conservative` требует 3 outcomes User-Agent или 8 outcomes профиля в 4 cohorts и отключает IP evidence; `balanced` использует соответственно 2, 6 в 3 cohorts и 3 outcomes допустимого IP; `aggressive` — 1, 4 в 2 cohorts и 1 outcome IP. Выключение обучения или смена policy при reload очищает несовместимый evidence, не меняя уже начатые сессии.

`https` остаётся default и сохраняет исходное сериализованное поведение. В `https-lanes` lane zero отведена под session control, а каждому ненулевому logical stream соответствует своя lane. У каждой lane собственные uplink sequence, retry digest, downlink cursor, unacknowledged replay batch, очередь и lifecycle newest-poll-wins. Поэтому медленный stream не блокирует другой stream на уровне WEB-протокола.

Это устраняет сериализацию между WEB-streams на уровне приложения. Публичный HTTP/2 всё ещё работает поверх одного или нескольких TCP-connections, поэтому потеря пакетов может вызвать transport-level head-of-line blocking; `https-lanes` не является HTTP/3- или QUIC-carrier.

Все lane queues и resident response bodies входят в существующие per-session и process-wide byte/item budgets. Telemt дополнительно ограничивает одну lane значениями `pending_bytes_per_lane` и `pending_items_per_lane`; сгенерированный bridge ограничивает свои очереди 8 MiB и 1024 элементами. Lane long polls могут занимать не более половины `web.limits.max_http_handlers`, оставляя handler capacity для session creation, uplink, DELETE и другой control work. Для `https` требуется `max_http_handlers >= 2`, для `https-lanes` — `max_http_handlers >= 4`.

Paths `/api/v1/up` и `/api/v1/down` не меняются. В `https-lanes` каждый запрос к ним содержит один канонический десятичный `X-Lane-ID`. Uplink sequence начинается с `1`, а downlink cursor — с `0` независимо для каждой lane. Lane zero принимает только session `PONG`; все frames ненулевой lane должны иметь тот же stream ID, а новая lane должна начинаться с `OPEN`. Канонический downlink с cursor zero, пришедший немного раньше `OPEN` своей lane, ждёт до `lane_open_wait_secs` без создания lane state; число таких ожиданий ограничено per-session и process auxiliary permits. Истечение таймаута возвращает пустой `204`, а отсутствующая lane с продвинутым cursor остаётся protocol failure и уходит в decoy. После отправки всей queued и unacknowledged downlink data закрытой lane Telemt возвращает пустой ответ с `X-Lane-Closed: 1`, и bridge прекращает её polling. Retry остаются byte-identical и повторяют исходный acknowledgement или downlink batch.

Оба WebSocket carrier по-прежнему создают и удаляют parent session через HTTPS, после чего используют строгий bodyless Upgrade-запрос `GET /api/v1/ws`. `websocket` передаёт в `Sec-WebSocket-Protocol` ровно `tproxy-v1.<session-token>`; binary messages являются упорядоченными carrier batches, а ошибка протокола, deadline или connection закрывает всю parent session. `websocket-lanes` передаёт ровно `tproxy-lane-v1.<session-token>.<stream-id>`, где stream ID записан каноническим десятичным числом из диапазона `1..=16777215`. Первое binary message должно начинаться с `OPEN`, все frames должны содержать этот stream ID, а сбой после Upgrade закрывает только данную lane. Lane-zero WebSocket отсутствует: HTTPS переносит `HELLO` и `WELCOME`, а liveness connection обеспечивает RFC 6455 Ping/Pong.

До HTTP `101` reservation WebSocket lane привязывается к точным process connection и incarnation lane; принятый `OPEN` передаёт ownership точному incarnation stream до запуска его backend task. Поздний poll, close или drop reservation от старого socket не может подтвердить, закрыть или освободить replacement, повторно использующий тот же числовой lane ID.

WebSocket codec buffers и находящиеся в обработке read/write messages делят process-owned `pending_bytes_global` с carrier queues и дополнительно ограничены `websocket_bytes_global`. Admission оставляет `websocket_http_connection_reserve` принятых connections для обычного HTTP и decoy. При admission replacement сначала глобально выбираются dead active connections, затем применяются уровни locality: та же session, тот же profile owner и тот же client IP. Не связанный с ними healthy victim допустим только когда requester использует меньше своей fair byte share, а owner victim — больше. Внутри одного уровня locality claimed или upgraded connections идут перед active lanes, lanes — перед active multiplexed sessions; дальнейший порядок детерминируют время последнего прогресса, создания и connection ID. Cleanup при memory pressure использует тот же dead-first и lifecycle-порядок, предпочитая owners выше fair share, но продолжает eviction, если все owners находятся на своей share или ниже. `max_websocket_evictions_in_flight` ограничивает одновременные точные eviction claims. Deadlines Upgrade, первого message, write, backpressure и eviction заморожены из parent session. После `long_poll_secs` без peer activity отправляется transport Ping, в том числе при непрерывном downlink traffic, а отсутствие peer activity в течение удвоенного creation-time интервала делает active connection кандидатом на cleanup.

Любая ошибка authentication, shape, lane reservation или capacity до Upgrade следует по очищенному decoy path и не раскрывает WebSocket-специфичный status. Точный subprotocol содержит session bearer и не должен попадать в logs.

Для WEB-listener обязательны `proxy_protocol = false` и `reuse_allow = false`. В нём нельзя использовать `client_mss`, `synlimit`, `announce` и `announce_ip`. Массив `web_trusted_proxy_cidrs` должен быть непустым и содержать только непосредственные адреса NGINX или HAProxy; сети `/0` запрещены.

HTTP decoy origin должен быть loopback, link-local или private IP literal. Для обычных запросов Telemt сохраняет method, path, query, headers, streamed body, response status, headers и body, удаляя hop-by-hop headers. Перед отправкой некорректного carrier-запроса в decoy Telemt удаляет из него carrier credentials и body.

Вместо origin можно использовать immutable snapshot статического сайта:

```toml
[web.vhosts.decoy]
mode = "static_directory"
directory = "/var/lib/telemt/public"
index = "index.html"
```

Статические файлы читаются при запуске и успешном reload конфигурации. Число элементов, размер одного файла и общий размер snapshot ограничены `[web.limits]`. Symlinks и пути с выходом из настроенного каталога запрещены. Не изменяйте каталог одновременно с построением snapshot в Telemt.

Все WEB-ключи и defaults перечислены в [справочнике конфигурации](../Config_params/CONFIG_PARAMS.ru.md#web).

## Терминация TLS на NGINX

```nginx
map $http_upgrade $telemt_connection_upgrade {
    default upgrade;
    ''      '';
}

upstream telemt_web {
    server 127.0.0.1:18080;
    keepalive 64;
}

server {
    listen 443 ssl;
    http2 on;
    server_name proxy.example.com;
    access_log off;

    ssl_certificate     /etc/letsencrypt/live/proxy.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/proxy.example.com/privkey.pem;

    client_max_body_size 2m;

    location / {
        proxy_pass http://telemt_web;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $telemt_connection_upgrade;

        proxy_connect_timeout 5s;
        proxy_send_timeout 65s;
        proxy_read_timeout 65s;
        proxy_request_buffering off;
        proxy_buffering off;
        proxy_next_upstream off;
    }
}
```

Разместите `map` в контексте `http` NGINX. `client_max_body_size` должен быть не меньше `web.limits.max_body_bytes`. Read, send и client timeouts должны превышать как default long poll в 25 секунд, так и удвоенный WebSocket liveness interval; 65 секунд покрывают defaults. Перезаписывайте `X-Forwarded-For`, а не дополняйте его. Telemt принимает один корректно разбираемый IP-адрес; если доверенный TLS-терминатор не передал header, Telemt использует адрес непосредственного peer, но per-client limits и source policy тогда видят терминатор вместо реального клиента. Не включайте upstream retries: bridge выполняет byte-identical HTTPS retries, но установленный WebSocket никогда не replay’ится прозрачно.

Для `https-lanes` обязателен публичный HTTP/2; используйте эквивалентную HTTP/2-директиву, поддерживаемую установленной версией NGINX. WebSocket Upgrade требует HTTP/1.1, поэтому публичный endpoint должен также разрешать HTTP/1.1, а приватный hop NGINX-to-Telemt остаётся HTTP/1.1. Сохраняйте `Connection`, `Upgrade` и `Sec-WebSocket-*` ровно как в примере. Upstream connection capacity должна выдерживать ожидаемое число одновременных lane polls или WebSocket lanes; `keepalive` управляет idle pool и не является лимитом concurrency.

## Терминация TLS на HAProxy

```haproxy
frontend public_https
    mode http
    no log
    bind :443 ssl crt /etc/haproxy/certs/proxy.example.com.pem alpn h2,http/1.1
    acl telemt_web_host hdr(host) -i proxy.example.com proxy.example.com:443
    use_backend telemt_web if telemt_web_host

backend telemt_web
    mode http
    option http-keep-alive
    retries 0
    timeout connect 5s
    timeout server 65s
    http-request set-header Host proxy.example.com
    http-request del-header X-Forwarded-For
    http-request set-header X-Forwarded-For %[src]
    server telemt_web_1 127.0.0.1:18080 check
```

Во frontend или секции `defaults` также задайте `timeout client 65s` или больше для default WebSocket liveness interval. Для `https-lanes` публичный ALPN HAProxy должен содержать `h2`, а для WebSocket Upgrade — `http/1.1`. Сохраняйте `Connection`, `Upgrade` и `Sec-WebSocket-*`; не переписывайте path, raw query, body и carrier headers `Authorization`, `Content-Type`, `X-Up-Seq`, `X-Down-Cursor`, `X-Lane-ID`.

## Lifecycle и reload

| Конфигурация | Поведение runtime |
| --- | --- |
| Состав WEB-listeners, bind address и trust policy | Принадлежат процессу; перезапустите Telemt. |
| Любое значение `[web.limits]` | Process-owned контракт памяти и ресурсов; перезапустите Telemt. |
| `web.enabled`, policy carrier/negotiation, `web.debug`, timeouts, vhosts, profiles и decoys | Применяются config watcher или runtime generation reload. |
| Существующие HTTP connections и WEB sessions | Сохраняют HTTP idle limit, carrier candidates, лимиты, body timeout, lifetime replay-marker закрытого token и абсолютные session/negotiation deadlines своего момента создания; каждый выданный bridge содержит собственные request, retry и probe-coalescing значения. WebSocket Upgrade, open, write, backpressure и eviction operations используют замороженные deadlines parent session. Новые bridges получают активную policy, а новые logical streams используют активное relay generation. |
| Завершение процесса | Один раз фиксирует последнее применённое значение `web.timeouts.shutdown_secs` и использует единый абсолютный deadline для listener acceptors и connections, WEB sessions и auxiliary tasks. Последовательные компоненты не получают отдельные полные бюджеты. |

Каждый logical stream сохраняет client IP своей сессии и владеет уникальным в пределах процесса ненулевым synthetic source port до завершения relay. Это сохраняет один стабильный непересекающийся source/destination tuple для Direct и Middle-End KDF routing.

HTTP idle accounting защищает только явно ограниченные фазы request body, long poll, подключения/response head decoy и ожидания Upgrade. Собственный deadline операции остаётся точным; если в этот момент её lease ещё существует, connection watchdog даёт запланированной задаче не более одного connection-idle interval для публикации timeout/result, после чего принудительно закрывает connection. Между обменами и после готовности response head прогресс сбрасывает idle-таймер, а зависший response body остаётся ограничен idle timeout. Завершение старой фазы не может снять deadline-защиту, которой уже владеет новая фаза.

`OPEN` резервирует bounded ownership logical stream и tuple, но не занимает permit `max_connections` relay generation. Telemt получает этот permit только после первого внутреннего байта; замороженный first-byte deadline и stream limits ограничивают silent opens, а исчерпание capacity закрывает только затронутый stream.

## Управление через API

Конфигурация WEB, статус runtime и bounded runtime-управление доступны на одном аутентифицированном API-listener. `/web-status` остаётся read-only HTML-диагностикой; операции, изменяющие состояние, существуют только под `/v1/runtime/web`.

| Операция | Поддержка API |
| --- | --- |
| Чтение или изменение `[web]`, vhosts, profiles, decoys, timeouts или limits | Да, через `GET` или `PATCH /v1/config`. Производный snapshot `web.runtime` не возвращается и недоступен для записи. Вложенные tables сливаются по полям; arrays целиком заменяют прежний array. Любое изменение `[web.limits]` принимается как desired configuration, но помечается deferred до перезапуска процесса. |
| Сохранение `server.listeners` | Да, через `PATCH /v1/config`, но изменённый WEB-listener остаётся deferred до перезапуска процесса. |
| Применение WEB-конфигурации, изменённой вне API | Да, через `POST /v1/system/reload` с последующей проверкой статуса операции. |
| Просмотр bounded серверных WEB request- и lifecycle-деталей | Да, через аутентифицированный `GET /web-status`. |
| Просмотр lifecycle, capacity planes, состояния learning/debug и активных сессий | Да, через `GET /v1/runtime/web/status` и `/v1/runtime/web/sessions`. |
| Закрытие выбранных активных WEB-сессий | Да, через асинхронную операцию `POST /v1/runtime/web/sessions/close`. |
| Очистка debug-записей или сброс carrier learning | Да, через соответствующие runtime POST endpoints. |
| Управление `[access.users]` | Да, через `/v1/users`. Создание пользователя не создаёт WEB-профиль. |
| Отзыв отдельного пользователя | Да. `/v1/users/{username}/disable` немедленно обновляет admission и завершает активные сессии пользователя. |

Привяжите API к loopback, оставьте узким whitelist непосредственных peers, настройте точное значение authorization header и используйте `read_only = false` только там, где нужны мутации:

```toml
[server.api]
enabled = true
listen = "127.0.0.1:9091"
whitelist = ["127.0.0.0/8"]
auth_header = "Bearer replace-with-a-random-control-token"
read_only = false
```

API whitelist проверяет непосредственный TCP peer и не доверяет `X-Forwarded-For`. Изменения самой секции `[server.api]` требуют перезапуска процесса.

### Статус и управление runtime

`GET /v1/runtime/web/status` всегда возвращает опубликованный lifecycle (`starting`, `no_web_listener`, `running`, `draining`, `drained` или `deadline_exceeded`), его epoch и возраст, эффективные адреса listeners и доступность. Пока process-owned WEB runtime существует, поле `runtime` добавляет случайный 128-битный `runtime_instance`, активное поколение, неизменяемые limits, capacity counters отдельных planes, epochs carrier-learning/debug и суммарные counters. Status собирается неблокирующим чтением каждого plane: занятый plane пропускается и указывается в `partial`; endpoint никогда не ожидает data plane, не выполняет cleanup и не изменяет его.

`GET /v1/runtime/web/sessions` возвращает не более 50 сессий по умолчанию и не более 200 при заданном `limit`. Упорядоченный scan ограничен 1000 кандидатами. `cursor` и `session_ref` имеют opaque canonical вид `ws1.<runtime-instance>.<lowercase-hex-id>`; точный `session_ref` нельзя сочетать с `cursor` или `limit`. Доступны фильтры `ip`, `host`, `user`, `user_agent_id`, `key_id`, `carrier` и `state`; повторяющиеся или неизвестные query fields отклоняются. Детальная операция — `GET /v1/runtime/web/sessions/{session_ref}`. Сохранённый tombstone закрытой сессии возвращает `410`; занятый точный snapshot — `503 web_snapshot_busy`. Ответы содержат только bounded несекретные metadata и никогда не раскрывают bootstrap/session bearers, capabilities, hashes секретов или synthetic/KDF ports.

Каждый runtime POST требует ровно `Content-Type: application/json`, отклоняет неизвестные JSON fields, наследует API authentication, whitelist и `read_only`, а также содержит текущий `runtime_instance` как ABA-fence. Доступные операции:

- `POST /v1/runtime/web/sessions/close` с одним selector: `{"kind":"refs","session_refs":[...]}`, `{"kind":"filter",...}` или `{"kind":"all"}`. Точные refs ограничены 200, filter должен быть непустым, одновременно выполняется не более одной close operation, а `all` отклоняется, пока effective issuance включён. Ответ `202` содержит `operation_id`; опрашивайте `GET /v1/runtime/web/operations/{operation_id}`. Операция chunks по 128 сканирует только сессии не выше submission high-water mark.
- `POST /v1/runtime/web/debug/clear` с `{"runtime_instance":"..."}`. Ответ содержит число удалённых записей, bytes, всё ещё удерживаемые уже отрисовываемыми snapshots, и новый epoch. In-flight writers старого epoch не могут снова заполнить ring.
- `POST /v1/runtime/web/carrier-learning/reset` с тем же body. Операция очищает сохранённый process-local evidence и увеличивает learning epoch; уже замороженные attempt chains и активные сессии не изменяются.

Для детерминированного close-all отправьте patch `{"web":{"enabled":false}}` с включённым runtime reload, дождитесь `runtime.manager.issuance_enabled = false`, отправьте selector `all` с тем же `runtime_instance` и опрашивайте operation до terminal state. Отключение WEB прекращает новую выдачу bootstrap/session credentials, но никогда не закрывает существующие сессии неявно.

### Серверная WEB-отладка

Включите bounded сбор в конфигурационном файле, которому принадлежит эта секция:

```toml
[web.debug]
enabled = true
capture_lifecycle = true
capture_headers = true
capture_timings = true
capture_frames = true
body_capture = "metadata"
body_prefix_bytes = 4096
decoy_body_prefix_bytes = 4096
default_window_secs = 180
max_window_secs = 3600
```

Откройте `http://127.0.0.1:9091/web-status`, используя те же whitelist непосредственных peers и точный header `Authorization`, что и для API. Завершающий slash разрешён. Допускается только `GET`. Страница поддерживает фильтры `window_secs`, канонический `ip`, числовой `session`, регистронезависимый `user_agent` и `key`. Повторяйте `group_by=ip`, `group_by=session`, `group_by=user_agent` или `group_by=key` для построения сгруппированных сводок; `limit` ограничен диапазоном `1..=1000`. HTTP rows раскрываются от request до response с method, path, очищенными headers, метаданными или байтами body, timing points, frames и типизированными lifecycle events, включая carrier attempt, commit, healthy и reported-failure transitions. Для WebSocket добавляются очищенный handshake `GET` → `101` и bounded per-message direction, message type, payload/body capture, processing time, connection/lane identifiers и разобранные inner frames. Raw subprotocol и session tokens никогда не сохраняются.

Process-owned кольцевой буфер переживает замену runtime generation. Изменения capture policy очищают несовместимые сохранённые записи; изменения только окна наблюдения этого не делают. По умолчанию кольцо ограничено 65536 записями и 64 MiB сохранённых плюс находящихся в обработке данных, HTML-response — 8 MiB, grouping — 1024 группами; одновременно page permits могут удерживать не более двух response bodies. Изменяйте `web.limits.debug_records_capacity` или `web.limits.debug_bytes_global` только с перезапуском процесса. Hot prefix, который помещается только в одновременно увеличенную restart-only ёмкость, откладывается до этого перезапуска.

`body_capture = "off"` исключает bodies, `metadata` сохраняет длину и terminal state, `prefix` — настроенные prefixes, а `full` — распознанные carrier bodies до `web.limits.max_body_bytes`. Обычные decoy bodies даже в режиме `full` ограничены `decoy_body_prefix_bytes`. Queries и raw capabilities никогда не сохраняются; значения credential headers исключаются; известные WEB capabilities и bearer tokens удаляются из захваченных bodies; отображаемый ключ является несекретным domain-separated fingerprint. Timing заканчивается на polling Hyper body и не означает kernel flush или TCP acknowledgment.

После атомарного изменения TOML-файла администратором или системой управления конфигурацией задайте в `TELEMT_API_AUTH` точное значение `auth_header` и отправьте наблюдаемый generation reload:

```bash
curl -sS -X POST http://127.0.0.1:9091/v1/system/reload \
  -H "Authorization: ${TELEMT_API_AUTH}" \
  -H 'Content-Type: application/json' \
  -d '{"mode":"drain","timeout_secs":30,"failure_policy":"rollback"}'

# Use data.reload_id from the response.
curl -sS http://127.0.0.1:9091/v1/system/reload/RELOAD_ID \
  -H "Authorization: ${TELEMT_API_AUTH}"
```

Терминальный статус `succeeded` подтверждает активацию runtime. Изменённые carrier, candidates, deadlines или learning policy используют новые bridge sessions; существующие сессии и начатые attempt chains не мигрируют. Если `deferred_process_fields` содержит `server.listeners` или `web.limits`, файл валиден и сохранён, но эти настройки всё ещё требуют перезапуска Telemt.

Операции с access users используют существующие endpoints, например:

```bash
curl -sS -X POST http://127.0.0.1:9091/v1/users/web-user/disable \
  -H "Authorization: ${TELEMT_API_AUTH}"

curl -sS -X POST http://127.0.0.1:9091/v1/users/web-user/rotate-secret \
  -H "Authorization: ${TELEMT_API_AUTH}" \
  -H 'Content-Type: application/json' \
  -d '{}'
```

После ротации секрета config watcher перестраивает WEB capabilities. Users API возвращает секрет, но не URL `tg://webproxy`; соберите ссылку из настроенного hostname и представления `plain` или `dd` соответствующего профиля. Перед удалением пользователя, на которого ссылается WEB-профиль, сначала удалите и примените этот профиль, чтобы итоговая конфигурация оставалась валидной.

Полный контракт запросов, revisions, ошибок и всех user endpoints приведён в [документации Control API](../Architecture/API/API.md).

## Инварианты развёртывания

- Никогда не публикуйте plain HTTP WEB-listener в недоверенной сети. Закрепите это host firewall rules, даже если listener использует loopback.
- Отключите логирование request target и authorization на TLS-терминаторе либо используйте проверенный формат с редактированием. Raw queries содержат bridge capabilities, а `Authorization` — bootstrap или session bearer credentials.
- Сохраняйте один стабильный публичный адрес на vhost. Если DNS возвращает несколько ingress addresses, каждый deployment должен использовать адрес своего внешнего пути.
- Bootstrap- и session-registries локальны для процесса. Для multi-process или multi-host upstream pool нужна affinity всего vhost: bridge GET, создание сессии, uplink, downlink и DELETE. Одному процессу Telemt дополнительная affinity не нужна.
- Неиспользованный bootstrap переживает reload конфигурации, только если остаётся активной точная identity профиля: host, `public_addr`, user, secret mode, carrier candidates, negotiation deadlines и capability. Уже созданные sessions сохраняют неизменные carrier и identity профиля и остаются lifecycle-bounded.
- Decoy входит в anti-probing contract. До распространения ссылок проверьте через публичный TLS endpoint его обычный ответ 404 и response timing.

## Первичная проверка

1. Запустите пересобранный Telemt с WEB-конфигурацией и убедитесь, что приватный listener привязан.
2. Через публичный TLS endpoint проверьте, что `GET /`, неизвестный path и некорректный query `bridge` возвращают настроенный decoy site.
3. Убедитесь, что Telemt получает один корректно разбираемый адрес `X-Forwarded-For` и `Host: proxy.example.com` либо `Host: proxy.example.com:443`.
4. Импортируйте напечатанную ссылку `tg://webproxy` в целевую сборку Telegram Desktop и установите соединение через прокси.
5. Для `https-lanes` подтвердите согласование HTTP/2 на публичном connection и проверьте как минимум два одновременных logical streams; приватный hop к Telemt остаётся HTTP/1.1.
6. Для `websocket` подтвердите один response `101`, binary relay traffic и RFC 6455 Ping/Pong после 25 секунд. Для `websocket-lanes` проверьте как минимум два одновременных stream sockets и убедитесь, что закрытие или повреждение одной lane не закрывает sibling или parent session.
7. Проверьте reconnect и как минимум один long poll длительнее 25 секунд, чтобы frontend timeouts не обрывали carrier.
8. Проверяйте лимиты пользователя и logical MTProxy connections по logical-stream counters, а не по числу HTTP connections.
9. При включённом auto-negotiation проверьте настроенную последовательность, replay точно той же попытки после намеренно потерянного response, terminal-поведение после commit и lifecycle rows `carrier_committed`/`carrier_healthy` в `/web-status`. Убедитесь, что нативный клиент без metadata использует фиксированный `carrier` без automatic response headers, а явные capabilities остаются неизменными.

## Диагностика

| Симптом | Что проверить |
| --- | --- |
| WEB-конфигурация валидна на диске, но поведение listener’а не изменилось | Проверьте `deferred_process_fields`; listener и `[web.limits]` требуют перезапуска. |
| Carrier-запросы попадают в decoy | Проверьте точный vhost, secret mode ссылки, CIDR непосредственного proxy и единственное корректно разбираемое значение `X-Forwarded-For`. |
| Downlink `https-lanes`, участвующий в гонке, попадает в decoy с `404` | Убедитесь, что он начинается с `X-Down-Cursor: 0`, сохраняйте `X-Lane-ID` и задайте `lane_open_wait_secs` выше наблюдаемого разрыва down-before-`OPEN`. Продвинутый cursor отсутствующей lane намеренно закрывается fail-closed. |
| Auto-negotiation переходит дальше после уже принятого трафика | Такое поведение некорректно. Проверьте аутентифицированный replay `X-Carrier-State` и lifecycle row commit carrier; ответ `committed` или `healthy` terminal и требует новой сессии. |
| Long polls разрываются через фиксированный интервал | Поднимите client, server, send и read timeouts NGINX/HAProxy выше `web.timeouts.long_poll_secs`. |
| WebSocket Upgrade попадает в decoy вместо `101` | Сохраните HTTP/1.1 `Connection: Upgrade`, `Upgrade: websocket`, единственный точный `Sec-WebSocket-Protocol` и канонический bodyless request `/api/v1/ws`. Также проверьте соответствие carrier/session и process connection reserve. |
| Один stream `websocket-lanes` закрылся, а siblings остались подключены | Это штатная failure boundary. Проверьте message/frame rows этой lane в `/web-status`; malformed, cross-lane, write-timeout и backend-close закрывают только затронутую lane. |
| `/web-status` пуст | Убедитесь, что `[web.debug].enabled = true`, примените конфигурацию, выберите окно в пределах `max_window_secs` и создайте новый WEB-трафик после изменения policy. |
| `https-lanes` работает, но streams всё ещё блокируют друг друга | Проверьте согласование публичного HTTP/2, сохранение `X-Lane-ID` и достаточное число upstream connections TLS-терминатора для параллельных приватных HTTP/1.1 polls. |
| Telegram Desktop отклоняет ссылку | Не указывайте порт, используйте валидный FQDN, внешний порт 443 и только `plain` или `dd`. |
| Один узел работает, но load-balanced pool нестабилен | Настройте affinity всего vhost: WEB credential registries локальны для процесса. |
