# WEB proxy mode

[English](WEB_PROXY.en.md) | [Русский](WEB_PROXY.ru.md) | [Deutsch](WEB_PROXY.de.md)

WEB mode carries ordinary MTProxy streams through bounded HTTPS carriers compatible with Telegram Desktop's `WEB` proxy type. Telemt does not terminate TLS: NGINX or HAProxy owns the public certificate and forwards plain HTTP/1.1 to a private Telemt listener.

> [!IMPORTANT]
>
> WEB mode is implemented and configurable in the current source tree. The first deployment requires a binary built from a revision containing this implementation and a Telemt process restart. Published packages can be used only after verifying that they contain the same revision. End-to-end validation with the intended Telegram Desktop build and the real public TLS endpoint remains an operator acceptance step.

## Traffic path

```text
Telegram Desktop
    | HTTPS :443
    v
NGINX or HAProxy (TLS termination, canonical Host and one X-Forwarded-For address)
    | plain HTTP/1.1 on a private network
    v
Telemt WEB listener
    |-- authenticated carrier --> bounded logical MTProxy relays --> Telegram
    `-- ordinary or invalid request --> configured decoy site
```

Route the complete public vhost to Telemt. Splitting only recognized carrier paths at the TLS terminator would make ordinary and authenticated behavior observably different and would bypass Telemt's decoy policy.

## Supported client contract

- The public endpoint is always `https://HOST:443`.
- `plain` and `dd` 16-byte MTProxy secrets are supported. `ee` FakeTLS secrets are not supported by WEB mode.
- `web.carrier = "https"` selects serialized HTTPS uplink and long polling. `web.carrier = "https-lanes"` selects independent HTTPS sequencing and polling per logical stream. WebSocket carriers are not advertised.
- Capability, bootstrap, and session credentials are separate bounded-lifetime values. Carrier credentials must be treated as secrets and must not appear in access logs.
- A bootstrap is a bearer credential, not a source-address-bound token. The client address and IP family may change between bridge loading and session creation. The issuing address retains unused-bootstrap accounting, while the address on the first valid creation request owns the session.
- Inner MTProxy authentication is restricted to the user and secret mode selected by the vhost profile. Invalid inner handshakes close only their logical stream and never enter the TCP masking path.

Telegram Desktop WEB links omit a port because the client requires port 443:

```text
tg://webproxy?server=proxy.example.com&secret=0123456789abcdef0123456789abcdef
tg://webproxy?server=proxy.example.com&secret=dd0123456789abcdef0123456789abcdef
```

Telemt prints links for WEB profiles selected by `[general.links].show` through the existing `telemt::links` log target.

## Prerequisites

- A dedicated public FQDN and valid TLS certificate on NGINX or HAProxy.
- A stable public IP for that hostname. `public_addr` must be that concrete IP on port 443 because it participates in the inner relay destination tuple.
- A private or loopback HTTP path from the TLS terminator to Telemt.
- A normal decoy site, either a private HTTP origin or an immutable local directory snapshot.
- A compatible Telegram Desktop build with the `WEB` proxy type.

The forwarded client address may differ in family from `public_addr` and may change while a bootstrap is live. `public_addr` must still identify the exact public endpoint used by the inner MTProxy route.

## Minimal Telemt configuration

The example keeps the WEB listener on loopback and uses a private HTTP decoy origin:

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

`https` remains the default and preserves the original serialized behavior. `https-lanes` assigns lane zero to session control and one lane to every non-zero logical stream. Each lane has its own uplink sequence, retry digest, downlink cursor, unacknowledged replay batch, queue, and newest-poll-wins lifecycle. A slow stream therefore does not block another stream at the WEB protocol layer.

This removes application-level serialization between WEB streams. Public HTTP/2 still runs over one or more TCP connections, so packet loss can cause transport-level head-of-line blocking; `https-lanes` is not an HTTP/3 or QUIC carrier.

All lane queues remain inside the existing per-session and process-wide byte/item budgets. The bridge also limits each lane to 8 MiB and 1024 queued items. Telemt permits lane long polls to occupy at most half of `web.limits.max_http_handlers`, preserving handler capacity for session creation, uplink, DELETE, and other control work. `https-lanes` requires `max_http_handlers >= 2`.

The `/api/v1/up` and `/api/v1/down` paths do not change. In `https-lanes`, every request on those paths carries one canonical decimal `X-Lane-ID`. Uplink sequence starts at `1` and downlink cursor at `0` independently for each lane. Lane zero accepts only session `PONG`; every frame in a non-zero lane must have the same stream ID, and a new lane must begin with `OPEN`. After a closed lane's queued and unacknowledged downlink data is drained, Telemt returns an empty response with `X-Lane-Closed: 1`, and the bridge stops polling it. Retries remain byte-identical and replay the original acknowledgement or downlink batch.

The WEB listener must use `proxy_protocol = false` and `reuse_allow = false`. It cannot use `client_mss`, `synlimit`, `announce`, or `announce_ip`. `web_trusted_proxy_cidrs` must be non-empty and must contain only the immediate NGINX or HAProxy peers; `/0` networks are rejected.

The HTTP decoy origin must be a loopback, link-local, or private IP literal. Telemt preserves ordinary request method, path, query, headers, streamed body, response status, headers, and body while removing hop-by-hop headers. Malformed carrier requests have carrier credentials and bodies removed before falling back to the decoy.

An immutable static-site snapshot can be used instead:

```toml
[web.vhosts.decoy]
mode = "static_directory"
directory = "/var/lib/telemt/public"
index = "index.html"
```

Static files are read at startup and successful configuration reload. Entry count, per-file size, and total snapshot size are bounded by `[web.limits]`. Symlinks and paths escaping the configured directory are rejected. Do not mutate the directory concurrently while Telemt builds a snapshot.

All WEB keys and defaults are listed in the [configuration reference](../Config_params/CONFIG_PARAMS.en.md#web).

## NGINX TLS termination

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

`client_max_body_size` must be at least `web.limits.max_body_bytes`. `proxy_read_timeout` and `proxy_send_timeout` must exceed `web.timeouts.long_poll_secs`, which defaults to 25 seconds. Overwrite, rather than append to, `X-Forwarded-For`. Telemt accepts one parseable IP address; if a trusted terminator omits the header, Telemt falls back to the direct peer address, but per-client limits and source policy then see the terminator rather than the real client. Do not enable upstream retries: the bridge performs byte-identical retries through its own sequence protocol.

Public HTTP/2 is mandatory for `https-lanes`; use the equivalent HTTP/2 directive supported by the installed NGINX release. The private NGINX-to-Telemt hop intentionally remains HTTP/1.1. Ensure the upstream connection capacity can sustain the expected simultaneous lane polls; `keepalive` controls the idle pool and is not a concurrency limit.

## HAProxy TLS termination

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

The frontend or `defaults` section must also set `timeout client` above the long-poll deadline. HAProxy's public ALPN must include `h2` for `https-lanes`. Do not rewrite the path, raw query, body, or the `Authorization`, `Content-Type`, `X-Up-Seq`, `X-Down-Cursor`, and `X-Lane-ID` carrier headers.

## Lifecycle and reload behavior

| Configuration | Runtime behavior |
| --- | --- |
| WEB listener inventory, bind address, and trust policy | Process-owned; restart Telemt. |
| Any `[web.limits]` value | Process-owned memory/resource contract; restart Telemt. |
| `web.enabled`, `web.carrier`, timeouts, vhosts, profiles, and decoys | Applied by the config watcher or a runtime generation reload. |
| Existing HTTP connections and WEB sessions | Keep their acquisition-time carrier, limits, and deadlines; newly issued bridge sessions use the active carrier. New logical streams use the active relay generation. |
| Process shutdown | Uses the latest reloaded `web.timeouts.shutdown_secs`. |

Each logical stream keeps its session's creation-time client IP and owns a process-unique, non-zero synthetic source port for the complete relay lifetime. This preserves one stable, non-colliding source/destination tuple for Direct and Middle-End KDF routing.

## API management

API management is available, but it is intentionally partial. There is no dedicated `/v1/web` endpoint and no WEB-specific runtime statistics endpoint.

| Operation | API support |
| --- | --- |
| Read or patch `[web]`, vhosts, profiles, decoys, timeouts, or limits | No. `GET /v1/config` omits `[web]`; `PATCH /v1/config` returns `400 section_not_editable` for `web`. |
| Persist `server.listeners` | Yes, through `PATCH /v1/config`, but a changed WEB listener remains deferred until process restart. |
| Apply an externally edited WEB configuration | Yes, through `POST /v1/system/reload`, then inspect the operation status. |
| Manage `[access.users]` | Yes, through `/v1/users`. User creation does not create a WEB profile. |
| Revoke one user | Yes. `/v1/users/{username}/disable` updates admission immediately and cancels that user's active sessions. |

Bind the API to loopback, keep its direct-peer whitelist narrow, configure an exact authorization header, and leave `read_only = false` only when mutation is required:

```toml
[server.api]
enabled = true
listen = "127.0.0.1:9091"
whitelist = ["127.0.0.0/8"]
auth_header = "Bearer replace-with-a-random-control-token"
read_only = false
```

The API whitelist checks the direct TCP peer and does not trust `X-Forwarded-For`. Changes to `[server.api]` itself require a process restart.

After an administrator or configuration system atomically updates the TOML file, set `TELEMT_API_AUTH` to the exact value configured in `auth_header` and submit an observable generation reload:

```bash
curl -sS -X POST http://127.0.0.1:9091/v1/system/reload \
  -H "Authorization: ${TELEMT_API_AUTH}" \
  -H 'Content-Type: application/json' \
  -d '{"mode":"drain","timeout_secs":30,"failure_policy":"rollback"}'

# Use data.reload_id from the response.
curl -sS http://127.0.0.1:9091/v1/system/reload/RELOAD_ID \
  -H "Authorization: ${TELEMT_API_AUTH}"
```

A terminal `succeeded` status confirms runtime activation. A changed `web.carrier` is used by newly issued bridge sessions; existing sessions are not migrated. If `deferred_process_fields` contains `server.listeners` or `web.limits`, the file is valid and persisted but those settings still require a Telemt restart.

Access-user operations use the existing endpoints, for example:

```bash
curl -sS -X POST http://127.0.0.1:9091/v1/users/web-user/disable \
  -H "Authorization: ${TELEMT_API_AUTH}"

curl -sS -X POST http://127.0.0.1:9091/v1/users/web-user/rotate-secret \
  -H "Authorization: ${TELEMT_API_AUTH}" \
  -H 'Content-Type: application/json' \
  -d '{}'
```

The config watcher rebuilds WEB capabilities after a secret rotation. The users API returns the secret, not a `tg://webproxy` URL; construct the link with the configured hostname and the profile's `plain` or `dd` representation. Before deleting a user referenced by a WEB profile, remove and apply that profile first so the resulting configuration remains valid.

See the complete [Control API contract](../Architecture/API/API.md) for request envelopes, revisions, failure modes, and all user endpoints.

## Deployment invariants

- Never expose the plain HTTP WEB listener to an untrusted network. Enforce the restriction with host firewall rules even when it binds to loopback.
- Disable request-target and authorization logging at the TLS terminator, or use a verified redacted format. Raw queries contain bridge capabilities and `Authorization` contains bootstrap or session bearer credentials.
- Keep one stable public address per vhost. If DNS returns several ingress addresses, each deployment must use the address matching its external path.
- Bootstrap and session registries are process-local. A multi-process or multi-host upstream pool requires affinity for the complete vhost: bridge GET, session creation, uplink, downlink, and DELETE. A single Telemt process needs no extra affinity.
- An unused bootstrap survives a configuration reload only when the exact profile identity remains active: host, `public_addr`, user, secret mode, carrier, and capability. Existing created sessions retain their immutable carrier and profile identity and remain lifecycle-bounded.
- The decoy is part of the anti-probing contract. Verify its ordinary 404 behavior and response timing through the public TLS endpoint before distributing links.

## Initial verification

1. Start the rebuilt Telemt binary with the WEB configuration and confirm that the private listener is bound.
2. Confirm through the public TLS endpoint that `GET /`, an unknown path, and an invalid `bridge` query return the configured decoy site.
3. Confirm that Telemt receives one parseable `X-Forwarded-For` address and `Host: proxy.example.com` or `Host: proxy.example.com:443`.
4. Import the printed `tg://webproxy` link in the intended Telegram Desktop build and establish a proxy connection.
5. For `https-lanes`, confirm that the public connection negotiated HTTP/2 and exercise at least two simultaneous logical streams; the private Telemt hop remains HTTP/1.1.
6. Exercise reconnect and at least one long poll beyond 25 seconds to prove the frontend timeouts do not truncate the carrier.
7. Verify user and logical MTProxy connection limits using logical-stream counters, not the number of HTTP connections.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| WEB configuration is valid on disk but listener behavior did not change | Inspect reload `deferred_process_fields`; listener and `[web.limits]` changes require restart. |
| Carrier requests reach the decoy | Verify exact vhost, link secret mode, direct proxy CIDR, and one parseable `X-Forwarded-For` value. |
| Long polls disconnect near a fixed interval | Raise NGINX/HAProxy client, server, send, and read timeouts above `web.timeouts.long_poll_secs`. |
| `https-lanes` works but streams still block each other | Confirm public HTTP/2 negotiation, preserve `X-Lane-ID`, and provide enough TLS-terminator upstream connections for concurrent private HTTP/1.1 polls. |
| Telegram Desktop rejects the link | Omit the port, use a valid FQDN, port 443 externally, and only `plain` or `dd` secret mode. |
| One node works but a load-balanced pool is intermittent | Add complete-vhost affinity; WEB credential registries are process-local. |
