# Gatekey

**Keep your LLM API keys out of your app.**

Gatekey is a single-binary reverse proxy that sits between your client application and your AI provider. Your app calls Gatekey; Gatekey adds the real API key and forwards the request. The key never leaves your server.

*[Version française](README.fr.md)*

```
   your app                     Gatekey                     provider
  ┌──────────┐   X-App-Token   ┌─────────┐  Authorization  ┌──────────┐
  │ iOS      │ ───────────────►│ quotas  │ ───────────────►│ OpenAI   │
  │ web      │                 │ limits  │   (real key)    │ Anthropic│
  │ backend  │ ◄───────────────│ metrics │ ◄───────────────│ Groq …   │
  └──────────┘    streamed     └─────────┘     streamed    └──────────┘
```

- **No database.** State lives in two small JSON files, written atomically.
- **No SDK to adopt.** Change the base URL of the provider SDK you already use.
- **No inference of ours.** You bring your own provider keys; Gatekey only relays.
- **16 MB of RAM idle**, ~1 ms added before the first byte, measured — see [Performance](#performance).

---

## Table of contents

- [Why](#why)
- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Client integration](#client-integration)
- [Configuration](#configuration)
- [Endpoints](#endpoints)
- [Operating Gatekey](#operating-gatekey)
- [Performance](#performance)
- [Security model](#security-model)
- [Project layout](#project-layout)
- [Open core and licence](#open-core-and-licence)

---

## Why

An API key shipped inside a mobile, desktop or web app can be extracted from the
binary or read off the network. Once it leaks, someone else spends your provider
credit, and the only fix is to rotate the key and ship a new build.

Putting a server in front solves that, but a plain proxy only moves the problem:
whatever credential the app now carries becomes the new thing worth stealing.
Gatekey makes that credential cheap to lose.

| | Provider key in the app | Gatekey token |
| --- | --- | --- |
| Lifetime | unlimited | 15 minutes, renewed automatically |
| Scope | the whole account | one route |
| Damage if stolen | your entire credit | the budget you set |
| Revoking it | rotate the key, ship a new build | one line in a denylist, applied on reload |

On top of that, Gatekey counts what every caller spends, caps it and rate-limits
it — the part a hand-written proxy never has.

---

## Quick start

Five minutes, from an empty directory to a proxied call.

**1. Build**

```bash
go build -o gatekey ./cmd/gatekey
```

**2. Write `config.yaml`**

```yaml
server:
  listen: ":8080"

tokens:
  signing_key: "${GATEKEY_SIGNING_KEY}"

routes:
  - path_prefix: "/openai"
    target_url: "https://api.openai.com"
    rate_limit:
      requests_per_minute: 60
    quota:
      max_budget_usd: 2.00        # per installation
      total_budget_usd: 100.00    # every installation together
      reset: "monthly"
      pricing_per_million:
        prompt_usd: 2.50
        completion_usd: 10.00
    inject_headers:
      Authorization: "Bearer ${OPENAI_API_KEY}"
```

**3. Run it**

```bash
export GATEKEY_SIGNING_KEY=$(./gatekey genkey)
export OPENAI_API_KEY="sk-proj-…"
./gatekey -config config.yaml
```

**4. Issue a token for a caller**

```bash
./gatekey issue -install my-app -route /openai
```

**5. Call the provider through Gatekey**

```bash
curl -X POST http://localhost:8080/openai/v1/chat/completions \
  -H "X-App-Token: gk1.…" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-5","stream":true,"messages":[{"role":"user","content":"Hello!"}]}'
```

Gatekey verifies the token, strips it from the request, injects your provider
key, and streams the answer back as it arrives.

---

## How it works

**Routes.** A route maps a path prefix to one provider, with its own key, quotas
and limits. One provider per route: your app already knows which provider it is
talking to, and Gatekey never rewrites request formats. Use several providers by
declaring several routes.

**Tokens.** Clients authenticate with a signed token in `X-App-Token`. Nothing is
stored server-side: the token carries its installation ID, its route and its
expiry, and Gatekey checks the signature. Callers come in two shapes.

- An **application** takes a short-lived access token plus a long-lived refresh
  token, and renews itself through `POST /-/refresh`.
- A **backend or cron job**, which has nowhere to run a renewal loop, takes one
  long-lived token: `gatekey issue -install cron -route /openai -ttl 87600h`. It
  is still named and still revocable, unlike a constant written by hand.

**Installations.** Quotas, rate limits and metrics are keyed by the token's
install ID, so renewing a token never resets a budget. What an installation means
is your choice: one for the whole application, or one per device if you want to
give each of your users their own budget.

**Usage accounting.** Gatekey reads the provider's own usage report as it streams
past, without buffering the response. It understands the OpenAI, Anthropic and
Gemini shapes, and reassembles counters split across TCP chunks.

**Quotas are soft.** A model only reports what it consumed once the answer is
written, so requests already in flight when a cap is reached all go through. Size
a budget as a circuit breaker, with margin, not as an exact accounting ceiling.

---

## Client integration

Point the provider SDK at Gatekey and add the token header. Nothing else changes.

**JavaScript / TypeScript**

```js
import OpenAI from "openai";

const client = new OpenAI({
  baseURL: "http://localhost:8080/openai/v1",
  apiKey: "unused",                             // required by the SDK, never sent
  defaultHeaders: { "X-App-Token": appToken },
});
```

**Python**

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8080/openai/v1",
    api_key="unused",
    default_headers={"X-App-Token": app_token},
)
```

**Renewing the token**

```bash
curl -X POST http://localhost:8080/-/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"gk1.…"}'
# → {"access_token":"gk1.…","expires_at":"…","expires_in":900}
```

Keep the refresh token in the OS keychain rather than in local storage, and renew
shortly before expiry. In a desktop app (Tauri, Electron), hold the token on the
native side and call from there: the web view then never sees it.

**Browser callers.** A web page may only call Gatekey if its origin is allowed:

```yaml
server:
  cors_origins: ["https://app.example.com"]   # "*" allows any origin
```

CORS is off by default — native apps and backends do not need it — and it is
never applied to `/metrics` or `/-/reload`. Preflights are answered by Gatekey
itself, without a token, and never reach the provider.

---

## Configuration

[`config.example.yaml`](config.example.yaml) documents every option. The ones you
will actually use:

| Key | What it does |
| --- | --- |
| `server.listen` | Listen address. If the port is taken, the next ones are tried. |
| `server.auth_header` | Header carrying the client token (default `X-App-Token`). |
| `server.state_dir` | Where `quotas.json` and `metrics.json` are written. Required on a read-only filesystem. |
| `server.cors_origins` | Web origins allowed to call from a browser. Empty means no CORS headers at all. |
| `server.request_timeout`, `response_header_timeout` | Ceiling on a whole exchange, and on the wait for the provider's first byte. |
| `tokens.signing_key` | Signs every issued token. Rotating it invalidates all of them. |
| `tokens.access_ttl` / `refresh_ttl` | 15 minutes and 30 days by default. |
| `tokens.denylist` | Install IDs cut off at the next reload. |
| `routes[].path_prefix` / `target_url` | The prefix to serve, and the provider behind it. |
| `routes[].inject_headers` | Headers added upstream, usually the provider key. |
| `routes[].rate_limit` | `requests_per_minute` and `burst`, per installation. |
| `routes[].quota` | `max_tokens` and `max_budget_usd` per installation; `total_max_tokens` and `total_budget_usd` for the route as a whole; `reset: never\|daily\|monthly`; per-model pricing. |
| `routes[].forward_headers` | Caller headers relayed upstream. Everything else is dropped, including the caller's own credential. |
| `routes[].credential` | A provider credential Gatekey renews by itself, instead of a static header. |

`${VAR}` references are read from the environment and substituted into values
only, after the YAML is parsed: a reference inside a comment is left alone, and a
secret containing a quote or a newline cannot rewrite the structure around it. An
undefined variable fails the load rather than silently shipping an empty
`Authorization: Bearer `. Write `$$` for a literal dollar sign.

---

## Endpoints

| Endpoint | Who may call it | What it does |
| --- | --- | --- |
| `/<prefix>/…` | Any caller with a valid token | Proxies to the provider. |
| `POST /-/refresh` | Anyone | Exchanges a refresh token for a fresh access token. Every failure answers the same opaque 401. |
| `GET /healthz` | Anyone | Liveness probe. |
| `GET /metrics` | **Loopback only** | Traffic per route and per installation, with history per minute over 24 h, per hour over 30 days and per day over a year. It lists installations and spend. |
| `POST /-/reload` | **Loopback only** | Re-reads the configuration. |

Responses carry `X-Quota-Tokens-Limit`, `X-Quota-Tokens-Used`,
`X-Quota-Budget-Limit`, `X-Quota-Budget-Used`, `X-RateLimit-Limit` and
`X-RateLimit-Remaining`, so a client can show its own consumption.

Errors always share one shape:

```json
{"error": {"code": "token_quota_exceeded", "message": "…", "status": 402}}
```

`401` unauthorised · `402` quota or budget exhausted · `403` forbidden · `404` no
route · `413` body too large · `429` rate limited · `502` provider unreachable.

---

## Operating Gatekey

**Reloading.** Gatekey watches its configuration file and applies a valid change
within two seconds, without dropping a connection. `SIGHUP` and `POST /-/reload`
do the same on demand. An invalid file is refused and the running configuration
stays in place.

**State files**, all `0600`:

| File | Contents |
| --- | --- |
| `quotas.json` + `quotas.json.log` | Usage counters. Every 5 s the log takes only the counters that changed; it is folded back into the snapshot on a clean stop, once a day, or when it grows to the snapshot's size. Counters survive a crash. |
| `metrics.json` | Traffic report, rewritten every minute and only when something changed. A full year of history is about 265 KB and never grows past that. |
| `credentials.json` | Provider refresh tokens, for a route that renews its own credential. |

All three name installations and spend. Keep them out of version control.

**Containers.** With Podman and a systemd Quadlet unit:

```ini
[Container]
Image=localhost/gatekey:latest
PublishPort=8080:8080
Environment=OPENAI_API_KEY=sk-…
Memory=512m
Environment=GOMEMLIMIT=460MiB
Volume=%h/gatekey/config.yaml:/etc/gatekey/config.yaml:ro,Z
```

Sizing: about **100 KB per answer in flight**, plus 16 MB at rest. `GOMEMLIMIT`
just under the container ceiling makes the garbage collector work harder instead
of the process being killed.

**Tests**

```bash
go test -race ./...
go vet ./... && gofmt -l .
```

**Load testing.** `cmd/loadtest` drives the real binary against a fake provider,
then checks that nothing was lost:

```bash
go run ./cmd/loadtest mock -addr 127.0.0.1:9100
go run ./cmd/loadtest run -target http://127.0.0.1:8095/mock/v1/chat/completions \
  -config config.yaml -mode stream -conc 5000 -duration 45s -pid <gatekey pid>
go run ./cmd/loadtest verify -state ./state -record record.jsonl
```

**Profiling**, compiled in only on request, never in a release binary:

```bash
go build -tags pprof -o gatekey ./cmd/gatekey
GATEKEY_PPROF=127.0.0.1:6060 ./gatekey -config config.yaml
go tool pprof http://127.0.0.1:6060/debug/pprof/heap
```

---

## Performance

Measured with `cmd/loadtest` on one 12-core machine, against a provider that
streams for 10 s. The generator, the proxy and the provider share that machine,
so these numbers are conservative.

| Concurrent streams | First byte, via Gatekey | Direct to provider | Memory | Errors |
| --- | --- | --- | --- | --- |
| 1 000 | 1.5 ms p50 · 2.9 ms p99 | 0.5 ms p50 · 1.3 ms p99 | 173 MB | 0 |
| 5 000 | 1.4 ms p50 · 5.9 ms p99 | — | 436 MB with `GOMEMLIMIT` | 0 |
| 20 000 | 0.5 s p50 — machine saturated | — | 3.1 GB | 0 |

So Gatekey adds about **1 ms** before the first byte, against the hundreds of
milliseconds a model takes to start answering. Non-streaming requests reach
~18 000 req/s on that machine. Refusing a forged token costs 0.09 ms; answering a
CORS preflight costs 0.02 ms.

Across those runs — 3.3 million requests — the usage counters and the metrics
matched the generator exactly: no call and no token went unrecorded.

---

## Security model

**What Gatekey protects**

- The provider key never reaches the client and never appears in a response.
- The caller's own credential is never forwarded upstream, whatever
  `forward_headers` says.
- Tokens are signed, scoped to one route, short-lived and revocable by install ID.
- A stolen token is capped by its own quota, by the route total and by the rate
  limit.
- Tokens are verified in constant time, and every refresh failure looks the same
  from the outside.
- `/metrics` and `/-/reload` refuse anything that is not loopback.

**What it does not protect, by design**

- **Anyone who can obtain a token can use it.** How a fresh installation gets its
  first token is the operator's decision; the proxy does not attest devices. Cap
  what an abuser can spend with `total_budget_usd`.
- **CORS is enforced by browsers, not by Gatekey.** It stops another website from
  using your users' browsers. It stops no script.
- **Quotas are soft.** See [How it works](#how-it-works).
- **Gatekey does not read or store prompts.** It only reads the usage block of a
  response as it goes past.

---

## Project layout

```text
cmd/
  gatekey/      CLI: run the server, genkey, issue
  loadtest/     fake provider, load generator, loss verification
internal/
  proxy/        routing, authentication, CORS, streaming, usage observation
  token/        signed tokens: issue, verify, refresh, denylist
  quota/        counters, budgets, and their crash-safe journal
  limiter/      token-bucket rate limiting
  metrics/      traffic report and history
  credential/   self-renewing provider credentials
  config/       YAML configuration, validation, hot reload
  routes/       HTTP endpoints
  apierror/     one JSON error shape
```

Built on the Go standard library alone: `net/http` and
`net/http/httputil.ReverseProxy`, no web framework.

---

## Open core and licence

This repository holds the proxy, under the Apache 2.0 licence: use it, host it,
change it. The hosted service, its dashboard and its provisioning are separate
and are not part of this repository.

See [LICENSE](LICENSE).
