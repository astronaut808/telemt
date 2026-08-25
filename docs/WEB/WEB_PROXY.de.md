# WEB-Proxy-Modus

[English](WEB_PROXY.en.md) | [Русский](WEB_PROXY.ru.md) | [Deutsch](WEB_PROXY.de.md)

Der WEB-Modus transportiert gewöhnliche MTProxy-Streams über begrenzte HTTPS-Carrier, die mit dem Proxy-Typ `WEB` von Telegram Desktop kompatibel sind. Telemt terminiert TLS nicht selbst: NGINX oder HAProxy verwaltet das öffentliche Zertifikat und leitet unverschlüsseltes HTTP/1.1 an einen privaten Telemt-Listener weiter.

> [!IMPORTANT]
>
> Der WEB-Modus ist im aktuellen Quellcode implementiert und konfigurierbar. Für die erste Bereitstellung sind ein Binary aus einer Revision mit dieser Implementierung und ein Neustart des Telemt-Prozesses erforderlich. Veröffentlichte Pakete dürfen erst verwendet werden, nachdem geprüft wurde, dass sie dieselbe Revision enthalten. Die Ende-zu-Ende-Prüfung mit dem vorgesehenen Telegram-Desktop-Build und dem realen öffentlichen TLS-Endpunkt bleibt ein Abnahmeschritt des Betreibers.

## Datenpfad

```text
Telegram Desktop
    | HTTPS :443
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
- `web.carrier = "https"` wählt serialisierte HTTPS-Uplinks und Long Polling. `web.carrier = "https-lanes"` wählt unabhängige HTTPS-Sequenzen und Polls pro logischem Stream. WebSocket-Carrier werden nicht angeboten.
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

`https` bleibt der Default und behält das ursprüngliche serialisierte Verhalten bei. Bei `https-lanes` ist Lane null für Session-Steuerung reserviert, und jeder logische Stream ungleich null erhält eine eigene Lane. Jede Lane besitzt eigene Uplink-Sequenzen, Retry-Digests, Downlink-Cursor, nicht bestätigte Replay-Batches, Queues und einen Newest-Poll-Wins-Lebenszyklus. Ein langsamer Stream blockiert daher keinen anderen Stream auf der WEB-Protokollebene.

Damit entfällt die Serialisierung zwischen WEB-Streams auf Anwendungsebene. Öffentliches HTTP/2 läuft weiterhin über eine oder mehrere TCP-Verbindungen, sodass Paketverlust Head-of-Line-Blocking auf Transportebene verursachen kann; `https-lanes` ist kein HTTP/3- oder QUIC-Carrier.

Alle Lane-Queues bleiben innerhalb der vorhandenen Byte-/Item-Budgets pro Sitzung und Prozess. Die Bridge begrenzt jede Lane zusätzlich auf 8 MiB und 1024 eingereihte Elemente. Lane-Long-Polls dürfen höchstens die Hälfte von `web.limits.max_http_handlers` belegen, sodass Handler-Kapazität für Sitzungserstellung, Uplink, DELETE und andere Steuerarbeit verbleibt. `https-lanes` erfordert `max_http_handlers >= 2`.

Die Pfade `/api/v1/up` und `/api/v1/down` ändern sich nicht. Bei `https-lanes` enthält jeder Request an diese Pfade genau einen kanonischen dezimalen `X-Lane-ID`-Header. Die Uplink-Sequenz beginnt pro Lane unabhängig bei `1`, der Downlink-Cursor bei `0`. Lane null akzeptiert nur Session-`PONG`; jeder Frame einer Lane ungleich null muss dieselbe Stream-ID tragen, und eine neue Lane muss mit `OPEN` beginnen. Nachdem eingereihte und nicht bestätigte Downlink-Daten einer geschlossenen Lane vollständig abgearbeitet sind, antwortet Telemt leer mit `X-Lane-Closed: 1`, und die Bridge beendet deren Polling. Wiederholungen bleiben byte-identisch und spielen die ursprüngliche Bestätigung oder den Downlink-Batch erneut aus.

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
        proxy_set_header Connection "";

        proxy_connect_timeout 5s;
        proxy_send_timeout 35s;
        proxy_read_timeout 35s;
        proxy_request_buffering off;
        proxy_buffering off;
        proxy_next_upstream off;
    }
}
```

`client_max_body_size` muss mindestens `web.limits.max_body_bytes` entsprechen. `proxy_read_timeout` und `proxy_send_timeout` müssen größer als `web.timeouts.long_poll_secs` sein, dessen Default 25 Sekunden beträgt. Überschreiben Sie `X-Forwarded-For`, statt einen Wert anzuhängen. Telemt akzeptiert eine syntaktisch gültige IP-Adresse; fehlt der Header bei einem vertrauenswürdigen TLS-Terminator, verwendet Telemt die Adresse des direkten Peers, doch clientbezogene Limits und Quellrichtlinien sehen dann den Terminator statt des echten Clients. Aktivieren Sie keine Upstream-Wiederholungen: Der Bridge-Transport führt byte-identische Wiederholungen über sein eigenes Sequenzprotokoll aus.

Öffentliches HTTP/2 ist für `https-lanes` obligatorisch; verwenden Sie die entsprechende HTTP/2-Direktive der installierten NGINX-Version. Der private Hop von NGINX zu Telemt bleibt absichtlich HTTP/1.1. Die Upstream-Verbindungskapazität muss die erwarteten gleichzeitigen Lane-Polls tragen; `keepalive` steuert den Idle-Pool und ist keine Nebenläufigkeitsgrenze.

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
    timeout server 35s
    http-request set-header Host proxy.example.com
    http-request del-header X-Forwarded-For
    http-request set-header X-Forwarded-For %[src]
    server telemt_web_1 127.0.0.1:18080 check
```

Im Frontend oder im Abschnitt `defaults` muss auch `timeout client` oberhalb der Long-Poll-Deadline liegen. Für `https-lanes` muss das öffentliche HAProxy-ALPN `h2` enthalten. Pfad, Raw Query, Body sowie die Carrier-Header `Authorization`, `Content-Type`, `X-Up-Seq`, `X-Down-Cursor` und `X-Lane-ID` dürfen nicht umgeschrieben werden.

## Lebenszyklus und Reload-Verhalten

| Konfiguration | Runtime-Verhalten |
| --- | --- |
| Bestand der WEB-Listener, Bind-Adresse und Vertrauensrichtlinie | Prozesseigen; Telemt neu starten. |
| Jeder Wert in `[web.limits]` | Prozesseigener Speicher- und Ressourcenvertrag; Telemt neu starten. |
| `web.enabled`, `web.carrier`, Timeouts, vhosts, Profile und Decoys | Werden vom Config-Watcher oder durch einen Runtime-Generations-Reload angewendet. |
| Bestehende HTTP-Verbindungen und WEB-Sitzungen | Behalten Carrier, Grenzen und Deadlines ihres Erstellungszeitpunkts; neu ausgegebene Bridge-Sitzungen verwenden den aktiven Carrier. Neue logische Streams verwenden die aktive Relay-Generation. |
| Beenden des Prozesses | Verwendet den zuletzt geladenen Wert von `web.timeouts.shutdown_secs`. |

Jeder logische Stream behält die Client-IP seiner Sitzung und besitzt während der gesamten Relay-Lebensdauer einen prozessweit eindeutigen, von null verschiedenen synthetischen Quellport. Damit bleibt für Direct- und Middle-End-KDF-Routing ein stabiles, kollisionsfreies Quell-/Ziel-Tupel erhalten.

## Verwaltung über die API

API-Verwaltung ist verfügbar, aber absichtlich eingeschränkt. Es gibt weder einen eigenen Endpunkt `/v1/web` noch einen WEB-spezifischen Runtime-Statistik-Endpunkt.

| Operation | API-Unterstützung |
| --- | --- |
| `[web]`, vhosts, Profile, Decoys, Timeouts oder Limits lesen oder ändern | Nein. `GET /v1/config` lässt `[web]` aus; `PATCH /v1/config` antwortet für `web` mit `400 section_not_editable`. |
| `server.listeners` speichern | Ja, über `PATCH /v1/config`; ein geänderter WEB-Listener bleibt jedoch bis zum Prozessneustart zurückgestellt. |
| Außerhalb der API geänderte WEB-Konfiguration anwenden | Ja, über `POST /v1/system/reload` und anschließende Abfrage des Vorgangsstatus. |
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

Der terminale Status `succeeded` bestätigt die Runtime-Aktivierung. Ein geänderter `web.carrier` wird von neu ausgegebenen Bridge-Sitzungen verwendet; bestehende Sitzungen werden nicht migriert. Enthält `deferred_process_fields` den Wert `server.listeners` oder `web.limits`, ist die Datei gültig und gespeichert, diese Einstellungen erfordern aber weiterhin einen Telemt-Neustart.

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
- Ein ungenutzter Bootstrap übersteht einen Konfigurations-Reload nur, wenn die exakte Profilidentität aktiv bleibt: Host, `public_addr`, Benutzer, Secret-Modus, Carrier und Capability. Bereits erstellte Sitzungen behalten ihren unveränderlichen Carrier und ihre Profilidentität und bleiben lifecycle-bounded.
- Der Decoy gehört zum Anti-Probing-Vertrag. Prüfen Sie sein gewöhnliches 404-Verhalten und die Antwortzeiten über den öffentlichen TLS-Endpunkt, bevor Sie Links verteilen.

## Erstprüfung

1. Starten Sie das neu erstellte Telemt-Binary mit der WEB-Konfiguration und prüfen Sie, dass der private Listener gebunden ist.
2. Prüfen Sie über den öffentlichen TLS-Endpunkt, dass `GET /`, ein unbekannter Pfad und eine ungültige `bridge`-Query die konfigurierte Decoy-Site zurückgeben.
3. Prüfen Sie, dass Telemt genau eine syntaktisch gültige `X-Forwarded-For`-Adresse und `Host: proxy.example.com` oder `Host: proxy.example.com:443` erhält.
4. Importieren Sie den ausgegebenen `tg://webproxy`-Link in den vorgesehenen Telegram-Desktop-Build und stellen Sie eine Proxy-Verbindung her.
5. Bestätigen Sie für `https-lanes`, dass die öffentliche Verbindung HTTP/2 ausgehandelt hat, und testen Sie mindestens zwei gleichzeitige logische Streams; der private Hop zu Telemt bleibt HTTP/1.1.
6. Testen Sie einen Reconnect und mindestens einen Long Poll über 25 Sekunden, um sicherzustellen, dass Frontend-Timeouts den Carrier nicht abbrechen.
7. Prüfen Sie Benutzer- und logische MTProxy-Verbindungslimits anhand der Logical-Stream-Zähler und nicht anhand der Zahl der HTTP-Verbindungen.

## Fehlerbehebung

| Symptom | Prüfung |
| --- | --- |
| WEB-Konfiguration ist auf dem Datenträger gültig, aber das Listener-Verhalten hat sich nicht geändert | Prüfen Sie `deferred_process_fields`; Listener- und `[web.limits]`-Änderungen erfordern einen Neustart. |
| Carrier-Requests erreichen den Decoy | Prüfen Sie den exakten vhost, den Secret-Modus des Links, das CIDR des direkten Proxys und genau einen syntaktisch gültigen `X-Forwarded-For`-Wert. |
| Long Polls werden nach einem festen Intervall getrennt | Setzen Sie Client-, Server-, Sende- und Lese-Timeouts von NGINX/HAProxy über `web.timeouts.long_poll_secs`. |
| `https-lanes` funktioniert, Streams blockieren sich aber weiterhin | Prüfen Sie die öffentliche HTTP/2-Aushandlung, die unveränderte Weitergabe von `X-Lane-ID` und genügend TLS-Terminator-Upstream-Verbindungen für parallele private HTTP/1.1-Polls. |
| Telegram Desktop lehnt den Link ab | Lassen Sie den Port weg und verwenden Sie einen gültigen FQDN, extern Port 443 sowie ausschließlich `plain` oder `dd`. |
| Ein Knoten funktioniert, ein Load-Balancing-Pool aber nur sporadisch | Konfigurieren Sie Affinität für den gesamten vhost; WEB-Zugangsdatenregister sind prozesslokal. |
