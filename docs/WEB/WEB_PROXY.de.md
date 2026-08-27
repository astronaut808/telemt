# WEB-Proxy-Modus

[English](WEB_PROXY.en.md) | [Русский](WEB_PROXY.ru.md) | [Deutsch](WEB_PROXY.de.md)

Der WEB-Modus transportiert gewöhnliche MTProxy-Streams über begrenzte HTTPS- oder WebSocket-Carrier, die mit dem Proxy-Typ `WEB` von Telegram Desktop kompatibel sind. Telemt terminiert TLS nicht selbst: NGINX oder HAProxy verwaltet das öffentliche Zertifikat und leitet unverschlüsseltes HTTP/1.1 an einen privaten Telemt-Listener weiter.

> [!IMPORTANT]
>
> Der WEB-Modus ist im aktuellen Quellcode implementiert und konfigurierbar. Für die erste Bereitstellung sind ein Binary aus einer Revision mit dieser Implementierung und ein Neustart des Telemt-Prozesses erforderlich. Veröffentlichte Pakete dürfen erst verwendet werden, nachdem geprüft wurde, dass sie dieselbe Revision enthalten. Die Ende-zu-Ende-Prüfung mit dem vorgesehenen Telegram-Desktop-Build und dem realen öffentlichen TLS-Endpunkt bleibt ein Abnahmeschritt des Betreibers.

## Datenpfad

```text
Telegram Desktop
    | HTTPS oder WSS :443
    v
NGINX oder HAProxy (TLS-Terminierung, kanonischer Host und eine X-Forwarded-For-Adresse)
    | unverschlüsseltes HTTP/1.1 in einem privaten Netz
    v
Telemt-WEB-Listener
    |-- authentifizierter Carrier --> begrenzte logische MTProxy-Relays --> Telegram
    `-- gewöhnlicher oder ungültiger Request --> konfigurierte Decoy-Site
```

Leiten Sie den vollständigen öffentlichen vhost an Telemt weiter. Wenn der TLS-Terminator nur bekannte Carrier-Pfade trennt, unterscheiden sich gewöhnliches und authentifiziertes Verhalten beobachtbar und Telemt kann seine Decoy-Richtlinie nicht durchsetzen.

## Unterstützter Client-Vertrag

- Der öffentliche Endpunkt ist immer `https://HOST:443`.
- Unterstützt werden 16-Byte-MTProxy-Secrets in den Modi `plain` und `dd`. FakeTLS-Secrets mit `ee` werden im WEB-Modus nicht unterstützt.
- `web.carrier` wählt den einzigen Carrier bei deaktivierter Auto-Negotiation und den letzten Fallback bei aktivierter Negotiation. `https` verwendet serialisierte HTTPS-Uplinks und Long Polling. `https-lanes` verwendet unabhängige HTTPS-Sequenzen und Polls pro logischem Stream. `websocket` verwendet einen geordneten WebSocket für alle Streams. `websocket-lanes` verwendet einen unabhängig verwalteten WebSocket für jeden logischen Stream ungleich null.
- Ein fehlendes `web.carriers` oder `web.carriers = false` deaktiviert Auto-Negotiation und Lernen. Ein nicht leeres Array aktiviert ausschließlich die sequenzielle Start-Negotiation; eine bereits festgeschriebene Sitzung wird nie migriert.
- Native Clients ohne kanonische Carrier-Negotiation-Header verwenden den konfigurierten festen `carrier`, auch wenn `carriers` die Negotiation für fähige Clients aktiviert. Das aktuelle Telegram iOS unterstützt nur `https`; für metadatafreies iOS muss der Betreiber daher `web.carrier = "https"` setzen, `https-lanes` wird nicht unterstützt. User-Agent-Werte einschließlich CFNetwork oder Darwin leiten niemals Capabilities ab. Sendet ein nativer iOS-Client explizite Negotiation-Metadaten, schneidet Telemt sie mit der serverautoritativen Obergrenze `{https}` und lehnt ein leeres Ergebnis ab; andere explizite Clients verwenden ihren angegebenen Capability-Satz.
- Capability-, Bootstrap- und Session-Zugangsdaten sind getrennte Werte mit begrenzter Lebensdauer. Carrier-Zugangsdaten sind geheim und dürfen nicht in Access-Logs erscheinen.
- Ein Bootstrap ist ein Bearer-Token und nicht an eine Quelladresse gebunden. Client-Adresse und IP-Familie dürfen sich zwischen dem Laden der Bridge und der Sitzungserstellung ändern. Die Ausstellungsadresse bleibt dem Limit ungenutzter Bootstraps zugeordnet; die Adresse des ersten gültigen Erstellungs-Requests wird der Sitzung zugeordnet.
- Die innere MTProxy-Authentifizierung ist auf den Benutzer und Secret-Modus des vhost-Profils beschränkt. Ein ungültiger innerer Handshake schließt nur seinen logischen Stream und gelangt niemals in den TCP-Masking-Pfad.

Telegram-Desktop-WEB-Links enthalten keinen Port, da der Client Port 443 voraussetzt:

```text
tg://webproxy?server=proxy.example.com&secret=0123456789abcdef0123456789abcdef
tg://webproxy?server=proxy.example.com&secret=dd0123456789abcdef0123456789abcdef
```

Telemt gibt Links für die durch `[general.links].show` ausgewählten WEB-Profile über das vorhandene Log-Target `telemt::links` aus.

## Voraussetzungen

- Ein eigener öffentlicher FQDN und ein gültiges TLS-Zertifikat auf NGINX oder HAProxy.
- Eine stabile öffentliche IP für diesen Hostnamen. `public_addr` muss genau diese konkrete IP auf Port 443 enthalten, da die Adresse Teil des Ziel-Tupels des inneren Relays ist.
- Ein privater oder lokaler HTTP-Pfad vom TLS-Terminator zu Telemt.
- Eine gewöhnliche Decoy-Site als privater HTTP-Origin oder unveränderlicher Snapshot eines lokalen Verzeichnisses.
- Ein kompatibler Telegram-Desktop-Build mit dem Proxy-Typ `WEB`.

Die weitergeleitete Client-Adresse darf eine andere IP-Familie als `public_addr` verwenden und sich während der Bootstrap-Lebensdauer ändern. `public_addr` muss weiterhin den exakten öffentlichen Endpoint der inneren MTProxy-Route bezeichnen.

## Minimale Telemt-Konfiguration

Das Beispiel bindet den WEB-Listener an Loopback und verwendet einen privaten HTTP-Decoy-Origin:

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

## Serverseitige Carrier-Negotiation

Auto-Negotiation ist optional und bleibt deaktiviert, solange `carriers` nicht als explizites, nicht leeres Array gesetzt ist. Der konfigurierte `carrier` bleibt der letzte Fallback und wird genau einmal angehängt, auch wenn er bereits im Array steht:

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

Die erzeugte Bridge sendet bei `/session` die kanonischen Header `X-Carrier-Capabilities`, `X-Carrier-Attempt` und ab dem zweiten Versuch `X-Carrier-Failure`. Jede erfolgreiche automatische Response liefert `X-Carrier-Mode`, `X-Carrier-Attempt`, `X-Carrier-Candidate-Count`, `X-Carrier-Deadline` und `X-Carrier-State`. Die Bridge startet ihre lokale kumulative Uhr unmittelbar vor dem ersten `/session`-Request; der Server friert seine separate absolute Chain-Deadline bei Annahme des ersten automatischen Versuchs ein. Beide verwenden die konfigurierten Offsets und werden bei Ersatzversuchen nicht zurückgesetzt. Für einen bis vier effektive Kandidaten lauten die Attempt-Checkpoints entsprechend `[d3]`, `[d0, d3]`, `[d0, d1, d3]` und `[d0, d1, d2, d3]`; der letzte Kandidat verwendet immer `d3`. Ein Nachfolger bleibt bis zu seinem eigenen Checkpoint zulässig. Die Zustände sind `provisional`, `committed` und `healthy`.

Versuche laufen streng sequenziell. Akzeptierter `OPEN`- oder `DATA`-Fortschritt schreibt den gewählten Carrier sofort fest und schließt die Ersatzgrenze endgültig. Ein authentifiziertes `409` für eine festgeschriebene Kette wiederholt deren Metadaten und ist terminal; es erlaubt keinen weiteren Versuch. Das exakte Replay von `/session` wird nur verwendet, solange dessen Ergebnis mehrdeutig ist. Nach der authentifizierten Auswahl eines provisional Carriers fordert ein Transportfehler direkt den nächsten Versuch an; wurde der vorherige Probe doch committed, antwortet der Server terminal mit `409`, statt einen unsicheren Ersatz zuzulassen. Die endgültige absolute Server-Deadline begrenzt auch einen Nachfolger, dessen Response den Client nie erreicht hat. Dynamisches Umschalten nach dem Commit wird absichtlich nicht unterstützt; dafür ist eine neue Sitzung erforderlich.

Jede HTTP-Operation der Bridge besitzt ein absolutes Budget `bridge_retry_secs` und höchstens neun Versuche. `bridge_request_secs` umfasst sowohl den Fetch-Response-Head als auch das vollständige Lesen des Response-Bodys; ein Downlink-Versuch erhält zusätzlich das konfigurierte Long-Poll-Intervall. Netzwerkfehler und Antworten mit `408`, `429`, `502`, `503` oder `504` verwenden begrenzten exponentiellen Backoff, während `Retry-After` das absolute Budget nicht verlängern kann. `carrier_probe_coalesce_ms = 0` sendet den ersten geordneten `OPEN`-Probe sofort. Ein Wert bis 10 ms kann passendes `DATA` aus diesem Fenster aufnehmen; multiplexierte Carrier bewahren die vollständige vorhergehende Frame-Reihenfolge, Lane-Carrier beanspruchen nur die ausgewählte Lane. Vor der Probe-Bestätigung startet kein HTTP-Downlink. Ein multiplexierter WebSocket-Upgrade kann unmittelbar nach seiner Auswahl durch `/session` beginnen und danach eingereihte Probe-Daten aufnehmen; ein Lane-WebSocket wartet auf die bekannte Stream-ID.

Automatische WebSockets verwenden `tproxy-auto-v1.<session-token>` beziehungsweise `tproxy-auto-lane-v1.<session-token>.<stream-id>`. Die erste akzeptierte Binärnachricht mit echtem `OPEN`- oder `DATA`-Fortschritt schreibt den Carrier fest; danach schreibt der Server eine leere binäre Commit-Bestätigung auf genau diese Verbindung. Ping/Pong schreibt keinen Carrier fest und zählt nicht als Learning-Evidenz.

Ein festgeschriebener Versuch wird erst healthy, wenn transportspezifische bidirektionale Evidenz für `carrier_health_secs` gültig bleibt. HTTPS erfordert akzeptiertes `DATA`, einen bestätigten nicht leeren Post-Commit-Downlink-Batch sowie authentifizierte Aktivität an oder nach der Health-Deadline. WebSocket erfordert die geschriebene exakte Commit-Bestätigung, danach akzeptiertes `OPEN` oder `DATA` desselben Owners und einen bis zum Ende des Intervalls lebenden Owner. Ein früheres Schließen ist neutral und erzeugt kein Lernergebnis.

Das Lernen ist prozesslokal, speicherresident, ausschließlich positiv und durch `max_carrier_learning_entries` begrenzt. Es sortiert nur vom Client unterstützte konfigurierte Kandidaten, hält den konfigurierten Fallback stets zuletzt und bewahrt bei gleichen Scores die Konfigurationsreihenfolge. User-Agent- und Profilevidenz haben Primärgewicht; eine zulässige IP dient nur als Tie-Breaker. IP-Evidenz erfordert genau eine explizite, global routbare `X-Forwarded-For`-Adresse; private, Loopback-, Link-Local-, Carrier-Grade-NAT-, Dokumentations-, Multicast- und entsprechende IPv4-Mapped-Adressen sind ausgeschlossen. Vom Client gemeldete Fehlerkategorien und Request-Latenz sind ausschließlich diagnostisch und erzeugen weder negative noch Ranking-Evidenz. `conservative` erfordert 3 User-Agent-Ergebnisse oder 8 Profilergebnisse aus 4 Kohorten und deaktiviert IP-Evidenz; `balanced` verwendet 2, 6 aus 3 Kohorten und 3 zulässige IP-Ergebnisse; `aggressive` verwendet 1, 4 aus 2 Kohorten und 1 IP-Ergebnis. Deaktiviertes Lernen oder eine geänderte Richtlinie verwirft beim Reload inkompatible Evidenz, ohne laufende Sitzungen zu verändern.

`https` bleibt der Default und behält das ursprüngliche serialisierte Verhalten bei. Bei `https-lanes` ist Lane null für Session-Steuerung reserviert, und jeder logische Stream ungleich null erhält eine eigene Lane. Jede Lane besitzt eigene Uplink-Sequenzen, Retry-Digests, Downlink-Cursor, nicht bestätigte Replay-Batches, Queues und einen Newest-Poll-Wins-Lebenszyklus. Ein langsamer Stream blockiert daher keinen anderen Stream auf der WEB-Protokollebene.

Damit entfällt die Serialisierung zwischen WEB-Streams auf Anwendungsebene. Öffentliches HTTP/2 läuft weiterhin über eine oder mehrere TCP-Verbindungen, sodass Paketverlust Head-of-Line-Blocking auf Transportebene verursachen kann; `https-lanes` ist kein HTTP/3- oder QUIC-Carrier.

Alle Lane-Queues und residenten Response-Bodys bleiben innerhalb der vorhandenen Byte-/Item-Budgets pro Sitzung und Prozess. Telemt begrenzt jede Lane zusätzlich durch `pending_bytes_per_lane` und `pending_items_per_lane`; die erzeugte Bridge begrenzt ihre entsprechenden Queues auf 8 MiB und 1024 Elemente. Lane-Long-Polls dürfen höchstens die Hälfte von `web.limits.max_http_handlers` belegen, sodass Handler-Kapazität für Sitzungserstellung, Uplink, DELETE und andere Steuerarbeit verbleibt. `https` erfordert `max_http_handlers >= 2`, `https-lanes` erfordert `max_http_handlers >= 4`.

Die Pfade `/api/v1/up` und `/api/v1/down` ändern sich nicht. Bei `https-lanes` enthält jeder Request an diese Pfade genau einen kanonischen dezimalen `X-Lane-ID`-Header. Die Uplink-Sequenz beginnt pro Lane unabhängig bei `1`, der Downlink-Cursor bei `0`. Lane null akzeptiert nur Session-`PONG`; jeder Frame einer Lane ungleich null muss dieselbe Stream-ID tragen, und eine neue Lane muss mit `OPEN` beginnen. Ein kanonischer Cursor-null-Downlink, der kurz vor dem `OPEN` seiner Lane eintrifft, wartet bis zu `lane_open_wait_secs`, ohne Lane-Zustand anzulegen; Grenzen pro Sitzung und prozessweite Hilfs-Permits begrenzen diese Wartefälle. Nach Ablauf folgt eine leere `204`-Response, während eine fehlende Lane mit fortgeschrittenem Cursor weiterhin als Protokollfehler über den Decoy-Pfad behandelt wird. Nachdem eingereihte und nicht bestätigte Downlink-Daten einer geschlossenen Lane vollständig abgearbeitet sind, antwortet Telemt leer mit `X-Lane-Closed: 1`, und die Bridge beendet deren Polling. Wiederholungen bleiben byte-identisch und spielen die ursprüngliche Bestätigung oder den Downlink-Batch erneut aus.

Beide WebSocket-Carrier erstellen und löschen die übergeordnete Sitzung weiterhin über HTTPS und verwenden danach einen strikten Upgrade-Request ohne Body an `GET /api/v1/ws`. `websocket` übermittelt in `Sec-WebSocket-Protocol` exakt `tproxy-v1.<session-token>`; binäre Messages sind geordnete Carrier-Batches, und ein Protokoll-, Deadline- oder Verbindungsfehler schließt die gesamte übergeordnete Sitzung. `websocket-lanes` übermittelt exakt `tproxy-lane-v1.<session-token>.<stream-id>`, wobei die Stream-ID kanonisch dezimal im Bereich `1..=16777215` steht. Die erste binäre Message muss mit `OPEN` beginnen, alle Frames müssen diese Stream-ID verwenden und ein Fehler nach dem Upgrade schließt nur diese Lane. Es gibt keinen Lane-null-WebSocket: HTTPS transportiert `HELLO` und `WELCOME`, während RFC-6455-Ping/Pong die Verbindungsliveness gewährleistet.

Vor HTTP `101` wird eine WebSocket-Lane-Reservierung an die exakte Prozessverbindung und Lane-Inkarnation gebunden; ein akzeptiertes `OPEN` überträgt die Ownership auf die exakte Stream-Inkarnation, bevor deren Backend-Task laufen kann. Ein verspäteter Poll, Close oder Reservierungs-Drop eines älteren Sockets kann einen Ersatz mit derselben numerischen Lane-ID weder bestätigen noch schließen oder freigeben.

WebSocket-Codec-Puffer und laufende Read-/Write-Messages teilen das prozesseigene Budget `pending_bytes_global` mit den Carrier-Queues und sind zusätzlich durch `websocket_bytes_global` begrenzt. Admission reserviert `websocket_http_connection_reserve` angenommene Verbindungen für gewöhnliches HTTP und Decoys. Bei einem Admission-Ersatz werden zuerst global tote aktive Verbindungen ausgewählt; danach gelten die Lokalitätsstufen gleiche Sitzung, gleicher Profil-Owner und gleiche Client-IP. Ein davon unabhängiges gesundes Opfer ist nur zulässig, wenn der Anforderer unter seinem fairen Byte-Anteil und der Owner des Opfers darüber liegt. Innerhalb einer Lokalitätsstufe stehen beanspruchte oder auf WebSocket hochgestufte Verbindungen vor aktiven Lanes und diese vor aktiven multiplexierten Sitzungen; letzter Fortschritt, Erstellungsreihenfolge und Verbindungs-ID lösen Gleichstände deterministisch auf. Das Cleanup bei Speicherdruck verwendet dieselbe Dead-first- und Lebenszyklusreihenfolge und bevorzugt Owner über ihrem fairen Anteil, setzt die Verdrängung aber auch fort, wenn alle Owner ihren Anteil einhalten. `max_websocket_evictions_in_flight` begrenzt gleichzeitige exakte Verdrängungs-Claims. Upgrade-, Erstnachrichten-, Write-, Backpressure- und Eviction-Deadlines stammen unveränderlich aus der Parent-Sitzung. Nach `long_poll_secs` ohne Peer-Aktivität wird auch bei kontinuierlichem Downlink-Verkehr ein Transport-Ping gesendet; fehlende Peer-Aktivität während des doppelten, beim Verbindungsaufbau festgelegten Intervalls macht eine aktive Verbindung zum Cleanup-Kandidaten.

Jeder Authentifizierungs-, Shape-, Lane-Reservierungs- oder Kapazitätsfehler vor dem Upgrade folgt dem bereinigten Decoy-Pfad und legt keinen WebSocket-spezifischen Status offen. Das exakte Subprotokoll enthält den Session-Bearer und darf nicht protokolliert werden.

Der WEB-Listener muss `proxy_protocol = false` und `reuse_allow = false` verwenden. `client_mss`, `synlimit`, `announce` und `announce_ip` sind nicht zulässig. `web_trusted_proxy_cidrs` muss nicht leer sein und darf nur die unmittelbar vorgeschalteten NGINX- oder HAProxy-Peers enthalten; `/0`-Netze werden abgelehnt.

Der HTTP-Decoy-Origin muss eine Loopback-, Link-Local- oder private IP-Adresse als Literal verwenden. Telemt bewahrt bei gewöhnlichen Requests Methode, Pfad, Query, Header, gestreamten Body, Response-Status, Header und Body und entfernt Hop-by-Hop-Header. Vor dem Fallback auf den Decoy entfernt Telemt Carrier-Zugangsdaten und Bodys aus fehlerhaften Carrier-Requests.

Alternativ kann ein unveränderlicher Snapshot einer statischen Site verwendet werden:

```toml
[web.vhosts.decoy]
mode = "static_directory"
directory = "/var/lib/telemt/public"
index = "index.html"
```

Statische Dateien werden beim Start und bei einem erfolgreichen Konfigurations-Reload gelesen. Eintragszahl, Dateigröße und Gesamtgröße des Snapshots werden durch `[web.limits]` begrenzt. Symlinks und Pfade außerhalb des konfigurierten Verzeichnisses werden abgelehnt. Ändern Sie das Verzeichnis nicht gleichzeitig, während Telemt einen Snapshot erstellt.

Alle WEB-Schlüssel und Defaults sind in der [Konfigurationsreferenz](../Config_params/CONFIG_PARAMS.de.md#web) aufgeführt.

## TLS-Terminierung mit NGINX

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

Platzieren Sie `map` im NGINX-Kontext `http`. `client_max_body_size` muss mindestens `web.limits.max_body_bytes` entsprechen. Read-, Send- und Client-Timeouts müssen sowohl den standardmäßigen 25-Sekunden-Long-Poll als auch das doppelte WebSocket-Liveness-Intervall überschreiten; 65 Sekunden decken die Defaults ab. Überschreiben Sie `X-Forwarded-For`, statt einen Wert anzuhängen. Telemt akzeptiert eine syntaktisch gültige IP-Adresse; fehlt der Header bei einem vertrauenswürdigen TLS-Terminator, verwendet Telemt die Adresse des direkten Peers, doch clientbezogene Limits und Quellrichtlinien sehen dann den Terminator statt des echten Clients. Aktivieren Sie keine Upstream-Wiederholungen: Die Bridge führt byte-identische HTTPS-Wiederholungen aus, ein etablierter WebSocket wird jedoch nie transparent wiederholt.

Öffentliches HTTP/2 ist für `https-lanes` obligatorisch; verwenden Sie die entsprechende HTTP/2-Direktive der installierten NGINX-Version. WebSocket-Upgrade erfordert HTTP/1.1, daher muss der öffentliche Endpunkt auch HTTP/1.1 zulassen und der private Hop von NGINX zu Telemt bleibt HTTP/1.1. Bewahren Sie `Connection`, `Upgrade` und `Sec-WebSocket-*` wie gezeigt unverändert. Die Upstream-Verbindungskapazität muss die erwarteten gleichzeitigen Lane-Polls oder WebSocket-Lanes tragen; `keepalive` steuert den Idle-Pool und ist keine Nebenläufigkeitsgrenze.

## TLS-Terminierung mit HAProxy

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

Im Frontend oder im Abschnitt `defaults` muss für das standardmäßige WebSocket-Liveness-Intervall auch `timeout client 65s` oder länger gesetzt sein. Für `https-lanes` muss das öffentliche HAProxy-ALPN `h2`, für WebSocket-Upgrade außerdem `http/1.1` enthalten. Bewahren Sie `Connection`, `Upgrade` und `Sec-WebSocket-*` unverändert; Pfad, Raw Query, Body sowie die Carrier-Header `Authorization`, `Content-Type`, `X-Up-Seq`, `X-Down-Cursor` und `X-Lane-ID` dürfen nicht umgeschrieben werden.

## Lebenszyklus und Reload-Verhalten

| Konfiguration | Runtime-Verhalten |
| --- | --- |
| Bestand der WEB-Listener, Bind-Adresse und Vertrauensrichtlinie | Prozesseigen; Telemt neu starten. |
| Jeder Wert in `[web.limits]` | Prozesseigener Speicher- und Ressourcenvertrag; Telemt neu starten. |
| `web.enabled`, Carrier-/Negotiation-Richtlinie, `web.debug`, Timeouts, vhosts, Profile und Decoys | Werden vom Config-Watcher oder durch einen Runtime-Generations-Reload angewendet. |
| Bestehende HTTP-Verbindungen und WEB-Sitzungen | Behalten HTTP-Idle-Grenze, Carrier-Kandidaten, Grenzen, Body-Timeout, Lebensdauer des Replay-Markers geschlossener Token sowie absolute Session-/Negotiation-Deadlines ihres Erstellungszeitpunkts; jede ausgegebene Bridge enthält ihre Request-, Retry- und Probe-Coalescing-Werte. WebSocket-Upgrade-, Open-, Write-, Backpressure- und Eviction-Vorgänge verwenden die unveränderlichen Deadlines der Parent-Sitzung. Neue Bridges verwenden die aktive Richtlinie, neue logische Streams die aktive Relay-Generation. |
| Beenden des Prozesses | Erfasst den zuletzt geladenen Wert von `web.timeouts.shutdown_secs` einmalig und verwendet dieselbe absolute Deadline für Listener-Acceptoren und Verbindungen sowie WEB-Sitzungen und Hilfstasks. Aufeinanderfolgende Komponenten erhalten keine separaten vollständigen Budgets. |

Jeder logische Stream behält die Client-IP seiner Sitzung und besitzt während der gesamten Relay-Lebensdauer einen prozessweit eindeutigen, von null verschiedenen synthetischen Quellport. Damit bleibt für Direct- und Middle-End-KDF-Routing ein stabiles, kollisionsfreies Quell-/Ziel-Tupel erhalten.

Die HTTP-Idle-Erfassung schützt nur explizit begrenzte Request-Body-, Long-Poll-, Decoy-Verbindungs-/Response-Head- und ausstehende Upgrade-Phasen. Die eigene Deadline der Operation bleibt exakt; besteht ihre Lease in diesem Moment noch, gewährt der Verbindungs-Watchdog dem eingeplanten Task höchstens ein Connection-Idle-Intervall zur Veröffentlichung seines Timeouts/Ergebnisses, bevor er die Verbindung erzwingend schließt. Zwischen Austauschvorgängen und nach Bereitstellung eines Response-Heads setzt Fortschritt den Idle-Timer zurück, während ein blockierter Response-Body weiterhin durch den Idle-Timeout begrenzt bleibt. Der Abschluss einer älteren Phase kann den Deadline-Schutz einer neueren Phase nicht freigeben.

Ein `OPEN` reserviert die begrenzte Eigentümerschaft für logischen Stream und Tupel, verbraucht jedoch noch kein `max_connections`-Permit der Relay-Generation. Telemt erwirbt dieses Permit erst nach dem ersten inneren Byte; die unveränderliche First-Byte-Deadline und Stream-Grenzen begrenzen stille Opens, und erschöpfte Kapazität schließt anschließend nur den betroffenen Stream.

## Verwaltung über die API

WEB-Konfiguration, Runtime-Status und begrenzte Runtime-Steuerung verwenden denselben authentifizierten API-Listener. `/web-status` bleibt eine schreibgeschützte HTML-Diagnose; zustandsverändernde Operationen existieren ausschließlich unter `/v1/runtime/web`.

| Operation | API-Unterstützung |
| --- | --- |
| `[web]`, vhosts, Profile, Decoys, Timeouts oder Limits lesen oder ändern | Ja, über `GET` oder `PATCH /v1/config`. Der abgeleitete Snapshot `web.runtime` wird weder ausgegeben noch kann er geschrieben werden. Verschachtelte Tabellen werden feldweise zusammengeführt; Arrays ersetzen das bisherige Array vollständig. Jede Änderung an `[web.limits]` wird als gewünschte Konfiguration angenommen, aber bis zum Prozessneustart als zurückgestellt gemeldet. |
| `server.listeners` speichern | Ja, über `PATCH /v1/config`; ein geänderter WEB-Listener bleibt jedoch bis zum Prozessneustart zurückgestellt. |
| Außerhalb der API geänderte WEB-Konfiguration anwenden | Ja, über `POST /v1/system/reload` und anschließende Abfrage des Vorgangsstatus. |
| Begrenzte serverseitige WEB-Request- und Lifecycle-Details untersuchen | Ja, über ein authentifiziertes `GET /web-status`. |
| Lifecycle, Kapazitätsebenen, Learning-/Debug-Zustand und aktive Sitzungen untersuchen | Ja, über `GET /v1/runtime/web/status` und `/v1/runtime/web/sessions`. |
| Ausgewählte aktive WEB-Sitzungen schließen | Ja, über die asynchrone Operation `POST /v1/runtime/web/sessions/close`. |
| Debug-Datensätze löschen oder Carrier-Learning zurücksetzen | Ja, über die entsprechenden Runtime-POST-Endpunkte. |
| `[access.users]` verwalten | Ja, über `/v1/users`. Das Erstellen eines Benutzers erzeugt kein WEB-Profil. |
| Einen Benutzer widerrufen | Ja. `/v1/users/{username}/disable` aktualisiert die Admission sofort und beendet die aktiven Sitzungen dieses Benutzers. |

Binden Sie die API an Loopback, halten Sie die Whitelist direkter Peers eng, konfigurieren Sie einen exakten Authorization-Header und verwenden Sie `read_only = false` nur dort, wo Mutationen erforderlich sind:

```toml
[server.api]
enabled = true
listen = "127.0.0.1:9091"
whitelist = ["127.0.0.0/8"]
auth_header = "Bearer replace-with-a-random-control-token"
read_only = false
```

Die API-Whitelist prüft den direkten TCP-Peer und vertraut `X-Forwarded-For` nicht. Änderungen an `[server.api]` selbst erfordern einen Prozessneustart.

### Runtime-Status und Steuerung

`GET /v1/runtime/web/status` liefert immer den veröffentlichten Lifecycle (`starting`, `no_web_listener`, `running`, `draining`, `drained` oder `deadline_exceeded`), dessen Epoche und Alter, die effektiven Listener-Adressen und die Verfügbarkeit. Solange die prozesseigene WEB-Runtime lebt, ergänzt `runtime` die zufällige 128-Bit-`runtime_instance`, die aktive Generation, unveränderliche Limits, ebenenlokale Kapazitätszähler, Carrier-Learning-/Debug-Epochen und Summen. Die Statuserfassung liest jede Ebene nicht blockierend: Eine umkämpfte Ebene wird ausgelassen und in `partial` benannt; der Endpunkt wartet nie auf die Datenebene, bereinigt sie nicht und verändert sie nicht.

`GET /v1/runtime/web/sessions` liefert standardmäßig höchstens 50 und bei gesetztem `limit` höchstens 200 Sitzungen. Der geordnete Scan ist auf 1000 Kandidaten begrenzt. `cursor` und `session_ref` verwenden die undurchsichtige kanonische Form `ws1.<runtime-instance>.<lowercase-hex-id>`; ein exakter `session_ref` darf nicht mit `cursor` oder `limit` kombiniert werden. Filter sind `ip`, `host`, `user`, `user_agent_id`, `key_id`, `carrier` und `state`; doppelte oder unbekannte Query-Felder werden abgelehnt. Der Detailpfad lautet `GET /v1/runtime/web/sessions/{session_ref}`. Ein gespeicherter Tombstone einer geschlossenen Sitzung ergibt `410`; ein umkämpfter exakter Snapshot ergibt `503 web_snapshot_busy`. Antworten enthalten nur begrenzte, nicht geheime Metadaten und niemals Bootstrap-/Session-Bearer, Capabilities, Secret-Hashes oder synthetische KDF-Ports.

Jeder Runtime-POST verlangt exakt `Content-Type: application/json`, lehnt unbekannte JSON-Felder ab, beachtet API-Authentifizierung, Whitelist und `read_only` und enthält die aktuelle `runtime_instance` als ABA-Sperre. Verfügbare Steuerungen:

- `POST /v1/runtime/web/sessions/close` mit genau einem Selektor: `{"kind":"refs","session_refs":[...]}`, `{"kind":"filter",...}` oder `{"kind":"all"}`. Exakte Referenzen sind auf 200 begrenzt, ein Filter darf nicht leer sein, nur eine Close-Operation darf laufen, und `all` wird abgelehnt, solange die effektive Ausgabe aktiviert ist. Die `202`-Antwort liefert `operation_id`; fragen Sie `GET /v1/runtime/web/operations/{operation_id}` ab. Die Operation scannt in Blöcken von 128 nur Sitzungen bis einschließlich ihres beim Start fixierten High-Water-Marks.
- `POST /v1/runtime/web/debug/clear` mit `{"runtime_instance":"..."}`. Die Antwort meldet gelöschte Datensätze, weiterhin von bereits gerenderten Snapshots gehaltene Bytes und die neue Epoche. Laufende Writer der alten Epoche können den Ring nicht erneut füllen.
- `POST /v1/runtime/web/carrier-learning/reset` mit derselben Body-Form. Der Endpunkt löscht gespeicherte prozesslokale Evidenz und erhöht die Learning-Epoche; bereits fixierte Versuchsketten und aktive Sitzungen bleiben unverändert.

Für ein deterministisches Close-all patchen Sie `{"web":{"enabled":false}}` mit aktiviertem Runtime-Reload, warten auf `runtime.manager.issuance_enabled = false`, senden den Selektor `all` mit derselben `runtime_instance` und fragen die Operation bis zu einem Endzustand ab. Das Deaktivieren von WEB stoppt neue Bootstrap-/Session-Ausgabe, schließt bestehende Sitzungen aber niemals implizit.

### Serverseitige WEB-Debug-Ansicht

Aktivieren Sie die begrenzte Erfassung in der zuständigen Konfigurationsdatei:

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

Öffnen Sie `http://127.0.0.1:9091/web-status` mit derselben Whitelist direkter Peers und demselben exakten `Authorization`-Header wie für die API. Ein abschließender Slash wird akzeptiert. Nur `GET` ist zulässig. Die Seite unterstützt die Filter `window_secs`, kanonische `ip`, numerische `session`, `user_agent` ohne Beachtung der Groß-/Kleinschreibung und `key`. Wiederholen Sie `group_by=ip`, `group_by=session`, `group_by=user_agent` oder `group_by=key`, um gruppierte Zusammenfassungen zu erstellen; `limit` ist auf `1..=1000` beschränkt. HTTP-Zeilen lassen sich vom Request bis zur Response zu Methode, Pfad, bereinigten Headern, Body-Metadaten oder -Bytes, Zeitpunkten, Frames und typisierten Lifecycle-Ereignissen einschließlich Carrier-Versuch, Commit, Healthy und gemeldetem Fehler aufklappen. Für WebSocket kommen der bereinigte Handshake `GET` → `101` sowie begrenzte Angaben pro Message zu Richtung, Message-Typ, Payload-/Body-Erfassung, Verarbeitungszeit, Verbindungs-/Lane-ID und geparsten inneren Frames hinzu. Rohe Subprotokolle und Session-Tokens werden nie gespeichert.

Der prozesseigene Ring übersteht den Austausch einer Runtime-Generation. Änderungen der Erfassungs-Policy löschen inkompatible gespeicherte Datensätze; reine Änderungen des Beobachtungsfensters tun dies nicht. Der Ring ist standardmäßig auf 65536 Datensätze und 64 MiB gespeicherte plus in Verarbeitung befindliche Daten begrenzt, die HTML-Response auf 8 MiB und die Gruppierung auf 1024 Gruppen; gleichzeitig dürfen höchstens zwei Response-Bodys Seiten-Permits halten. Ändern Sie `web.limits.debug_records_capacity` oder `web.limits.debug_bytes_global` nur zusammen mit einem Prozessneustart. Ein hot-reload-fähiger Präfix, der nur in eine gleichzeitig erhöhte neustartpflichtige Kapazität passt, wird bis zu diesem Neustart zurückgestellt.

`body_capture = "off"` lässt Bodys aus, `metadata` speichert Längen und Endzustände, `prefix` die konfigurierten Präfixe und `full` erkannte Carrier-Bodys bis `web.limits.max_body_bytes`. Gewöhnliche Decoy-Bodys bleiben auch in `full` auf `decoy_body_prefix_bytes` begrenzt. Queries und rohe Capabilities werden nie gespeichert; Werte von Credential-Headern werden ausgelassen; bekannte WEB-Capabilities und Bearer-Tokens werden aus erfassten Bodys entfernt; der angezeigte Schlüssel ist ein nicht geheimer, domänengetrennter Fingerprint. Die Zeitmessung endet beim Polling des Hyper-Bodys und behauptet weder einen Kernel-Flush noch eine TCP-Bestätigung.

Nachdem ein Administrator oder Konfigurationssystem die TOML-Datei atomar aktualisiert hat, setzen Sie `TELEMT_API_AUTH` auf den exakten Wert von `auth_header` und starten Sie einen beobachtbaren Generations-Reload:

```bash
curl -sS -X POST http://127.0.0.1:9091/v1/system/reload \
  -H "Authorization: ${TELEMT_API_AUTH}" \
  -H 'Content-Type: application/json' \
  -d '{"mode":"drain","timeout_secs":30,"failure_policy":"rollback"}'

# Use data.reload_id from the response.
curl -sS http://127.0.0.1:9091/v1/system/reload/RELOAD_ID \
  -H "Authorization: ${TELEMT_API_AUTH}"
```

Der terminale Status `succeeded` bestätigt die Runtime-Aktivierung. Geänderte Carrier-, Kandidaten-, Deadline- oder Learning-Richtlinien werden von neu ausgegebenen Bridge-Sitzungen verwendet; bestehende Sitzungen und laufende Versuchsketten werden nicht migriert. Enthält `deferred_process_fields` den Wert `server.listeners` oder `web.limits`, ist die Datei gültig und gespeichert, diese Einstellungen erfordern aber weiterhin einen Telemt-Neustart.

Operationen für Access-Benutzer verwenden die vorhandenen Endpunkte, zum Beispiel:

```bash
curl -sS -X POST http://127.0.0.1:9091/v1/users/web-user/disable \
  -H "Authorization: ${TELEMT_API_AUTH}"

curl -sS -X POST http://127.0.0.1:9091/v1/users/web-user/rotate-secret \
  -H "Authorization: ${TELEMT_API_AUTH}" \
  -H 'Content-Type: application/json' \
  -d '{}'
```

Nach einer Secret-Rotation erstellt der Config-Watcher die WEB-Capabilities neu. Die Users-API liefert das Secret, aber keine `tg://webproxy`-URL. Erstellen Sie den Link mit dem konfigurierten Hostnamen und der `plain`- oder `dd`-Darstellung des Profils. Entfernen und aktivieren Sie vor dem Löschen eines Benutzers zuerst das WEB-Profil, das auf ihn verweist, damit die resultierende Konfiguration gültig bleibt.

Der vollständige Vertrag für Requests, Revisionen, Fehler und alle Benutzer-Endpunkte steht in der [Dokumentation der Control API](../Architecture/API/API.md).

## Bereitstellungsinvarianten

- Veröffentlichen Sie den unverschlüsselten HTTP-WEB-Listener niemals in einem nicht vertrauenswürdigen Netz. Erzwingen Sie diese Einschränkung auch bei einer Loopback-Bindung mit Host-Firewall-Regeln.
- Deaktivieren Sie am TLS-Terminator die Protokollierung von Request-Target und Authorization oder verwenden Sie ein geprüftes, redigiertes Format. Raw Queries enthalten Bridge-Capabilities und `Authorization` enthält Bootstrap- oder Session-Bearer-Zugangsdaten.
- Verwenden Sie pro vhost eine stabile öffentliche Adresse. Wenn DNS mehrere Ingress-Adressen liefert, muss jede Bereitstellung die Adresse ihres externen Pfads verwenden.
- Bootstrap- und Session-Register sind prozesslokal. Ein Multi-Prozess- oder Multi-Host-Upstream-Pool benötigt Affinität für den vollständigen vhost: Bridge-GET, Sitzungserstellung, Uplink, Downlink und DELETE. Ein einzelner Telemt-Prozess benötigt keine zusätzliche Affinität.
- Ein ungenutzter Bootstrap übersteht einen Konfigurations-Reload nur, wenn die exakte Profilidentität aktiv bleibt: Host, `public_addr`, Benutzer, Secret-Modus, Carrier-Kandidaten, Negotiation-Deadlines und Capability. Bereits erstellte Sitzungen behalten ihren unveränderlichen Carrier und ihre Profilidentität und bleiben lifecycle-bounded.
- Der Decoy gehört zum Anti-Probing-Vertrag. Prüfen Sie sein gewöhnliches 404-Verhalten und die Antwortzeiten über den öffentlichen TLS-Endpunkt, bevor Sie Links verteilen.

## Erstprüfung

1. Starten Sie das neu erstellte Telemt-Binary mit der WEB-Konfiguration und prüfen Sie, dass der private Listener gebunden ist.
2. Prüfen Sie über den öffentlichen TLS-Endpunkt, dass `GET /`, ein unbekannter Pfad und eine ungültige `bridge`-Query die konfigurierte Decoy-Site zurückgeben.
3. Prüfen Sie, dass Telemt genau eine syntaktisch gültige `X-Forwarded-For`-Adresse und `Host: proxy.example.com` oder `Host: proxy.example.com:443` erhält.
4. Importieren Sie den ausgegebenen `tg://webproxy`-Link in den vorgesehenen Telegram-Desktop-Build und stellen Sie eine Proxy-Verbindung her.
5. Bestätigen Sie für `https-lanes`, dass die öffentliche Verbindung HTTP/2 ausgehandelt hat, und testen Sie mindestens zwei gleichzeitige logische Streams; der private Hop zu Telemt bleibt HTTP/1.1.
6. Bestätigen Sie für `websocket` eine `101`-Response, binären Relay-Datenverkehr und RFC-6455-Ping/Pong nach 25 Sekunden. Testen Sie für `websocket-lanes` mindestens zwei gleichzeitige Stream-Sockets und prüfen Sie, dass das Schließen oder Beschädigen einer Lane weder Geschwister noch die übergeordnete Sitzung schließt.
7. Testen Sie einen Reconnect und mindestens einen Long Poll über 25 Sekunden, um sicherzustellen, dass Frontend-Timeouts den Carrier nicht abbrechen.
8. Prüfen Sie Benutzer- und logische MTProxy-Verbindungslimits anhand der Logical-Stream-Zähler und nicht anhand der Zahl der HTTP-Verbindungen.
9. Prüfen Sie bei aktivierter Auto-Negotiation die konfigurierte Reihenfolge, das Replay exakt desselben Versuchs nach einer absichtlich verlorenen Response, das terminale Verhalten nach dem Commit sowie die Lifecycle-Zeilen `carrier_committed` und `carrier_healthy` in `/web-status`. Prüfen Sie, dass ein nativer Client ohne Metadaten den festen `carrier` ohne automatische Response-Header verwendet und explizite Capabilities unverändert bleiben.

## Fehlerbehebung

| Symptom | Prüfung |
| --- | --- |
| WEB-Konfiguration ist auf dem Datenträger gültig, aber das Listener-Verhalten hat sich nicht geändert | Prüfen Sie `deferred_process_fields`; Listener- und `[web.limits]`-Änderungen erfordern einen Neustart. |
| Carrier-Requests erreichen den Decoy | Prüfen Sie den exakten vhost, den Secret-Modus des Links, das CIDR des direkten Proxys und genau einen syntaktisch gültigen `X-Forwarded-For`-Wert. |
| Ein konkurrierender `https-lanes`-Downlink erreicht den Decoy mit `404` | Prüfen Sie, dass er mit `X-Down-Cursor: 0` beginnt, bewahren Sie `X-Lane-ID` und setzen Sie `lane_open_wait_secs` über den beobachteten Abstand zwischen Downlink und `OPEN`. Fortgeschrittene Cursor fehlender Lanes schlagen absichtlich fail-closed fehl. |
| Auto-Negotiation wechselt weiter, nachdem Daten bereits akzeptiert wurden | Das ist ungültig. Prüfen Sie das authentifizierte `X-Carrier-State`-Replay und das Carrier-Commit-Lifecycle-Ereignis; `committed` oder `healthy` ist terminal und erfordert eine neue Sitzung. |
| Long Polls werden nach einem festen Intervall getrennt | Setzen Sie Client-, Server-, Sende- und Lese-Timeouts von NGINX/HAProxy über `web.timeouts.long_poll_secs`. |
| WebSocket-Upgrade erreicht statt `101` den Decoy | Bewahren Sie HTTP/1.1 `Connection: Upgrade`, `Upgrade: websocket`, das einzelne exakte `Sec-WebSocket-Protocol` und den kanonischen bodylosen Request `/api/v1/ws`. Prüfen Sie außerdem Carrier-/Session-Kompatibilität und die Prozess-Verbindungsreserve. |
| Ein `websocket-lanes`-Stream wurde geschlossen, Geschwister bleiben aber verbunden | Dies ist die beabsichtigte Fehlergrenze. Prüfen Sie die Message-/Frame-Zeilen dieser Lane in `/web-status`; fehlerhafte oder lane-fremde Frames, Write-Timeouts und Backend-Close schließen nur die betroffene Lane. |
| `/web-status` ist leer | Prüfen Sie, dass `[web.debug].enabled = true` gesetzt ist, wenden Sie die Konfiguration an, wählen Sie ein Fenster innerhalb von `max_window_secs` und erzeugen Sie nach der Policy-Änderung neuen WEB-Datenverkehr. |
| `https-lanes` funktioniert, Streams blockieren sich aber weiterhin | Prüfen Sie die öffentliche HTTP/2-Aushandlung, die unveränderte Weitergabe von `X-Lane-ID` und genügend TLS-Terminator-Upstream-Verbindungen für parallele private HTTP/1.1-Polls. |
| Telegram Desktop lehnt den Link ab | Lassen Sie den Port weg und verwenden Sie einen gültigen FQDN, extern Port 443 sowie ausschließlich `plain` oder `dd`. |
| Ein Knoten funktioniert, ein Load-Balancing-Pool aber nur sporadisch | Konfigurieren Sie Affinität für den gesamten vhost; WEB-Zugangsdatenregister sind prozesslokal. |
