# Gatekey

**Gardez vos clés d'API d'IA hors de votre application.**

Gatekey est un reverse-proxy d'un seul binaire, placé entre votre application cliente et votre fournisseur d'IA. Votre app appelle Gatekey ; Gatekey ajoute la vraie clé d'API et transmet la requête. La clé ne quitte jamais votre serveur.

*[English version](README.md)*

```
   votre app                    Gatekey                    fournisseur
  ┌──────────┐   X-App-Token   ┌──────────┐  Authorization  ┌──────────┐
  │ iOS      │ ───────────────►│ quotas   │ ───────────────►│ OpenAI   │
  │ web      │                 │ limites  │  (vraie clé)    │ Anthropic│
  │ backend  │ ◄───────────────│ métriques│ ◄───────────────│ Groq …   │
  └──────────┘    streaming    └──────────┘    streaming    └──────────┘
```

- **Aucune base de données.** L'état tient dans deux petits fichiers JSON écrits atomiquement.
- **Aucun SDK à adopter.** Vous changez l'URL de base du SDK que vous utilisez déjà.
- **Aucune IA de notre côté.** Vous apportez vos propres clés ; Gatekey ne fait que relayer.
- **16 Mo de RAM au repos**, ~1 ms ajoutée avant le premier octet, mesuré — voir [Performances](#performances).

---

## Sommaire

- [Pourquoi](#pourquoi)
- [Démarrage rapide](#démarrage-rapide)
- [Fonctionnement](#fonctionnement)
- [Intégration côté client](#intégration-côté-client)
- [Configuration](#configuration)
- [Points d'entrée](#points-dentrée)
- [Exploitation](#exploitation)
- [Performances](#performances)
- [Modèle de sécurité](#modèle-de-sécurité)
- [Organisation du projet](#organisation-du-projet)
- [Open core et licence](#open-core-et-licence)

---

## Pourquoi

Une clé d'API livrée dans une app mobile, desktop ou web s'extrait du binaire ou
se lit sur le réseau. Une fois qu'elle fuit, quelqu'un d'autre dépense votre
crédit, et la seule issue est de changer la clé puis de republier l'app.

Mettre un serveur devant règle ce point, mais un simple proxy ne fait que
déplacer le problème : le nouveau secret embarqué dans l'app devient à son tour
la chose à voler. Gatekey rend ce secret peu coûteux à perdre.

| | Clé du fournisseur dans l'app | Token Gatekey |
| --- | --- | --- |
| Durée de vie | illimitée | 15 minutes, renouvelée automatiquement |
| Portée | tout le compte | une seule route |
| Dégâts en cas de vol | tout votre crédit | le budget que vous avez fixé |
| Révocation | changer la clé, republier l'app | une ligne de denylist, appliquée au rechargement |

À cela s'ajoute ce qu'un proxy écrit à la main n'a jamais : Gatekey compte ce que
chaque appelant dépense, le plafonne et limite son débit.

---

## Démarrage rapide

Cinq minutes, d'un dossier vide au premier appel relayé.

**1. Compiler**

```bash
go build -o gatekey ./cmd/gatekey
```

**2. Écrire `config.yaml`**

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
      max_budget_usd: 2.00        # par installation
      total_budget_usd: 100.00    # toutes installations confondues
      reset: "monthly"
      pricing_per_million:
        prompt_usd: 2.50
        completion_usd: 10.00
    inject_headers:
      Authorization: "Bearer ${OPENAI_API_KEY}"
```

**3. Lancer**

```bash
export GATEKEY_SIGNING_KEY=$(./gatekey genkey)
export OPENAI_API_KEY="sk-proj-…"
./gatekey -config config.yaml
```

**4. Émettre un token pour un appelant**

```bash
./gatekey issue -install mon-app -route /openai
```

**5. Appeler le fournisseur via Gatekey**

```bash
curl -X POST http://localhost:8080/openai/v1/chat/completions \
  -H "X-App-Token: gk1.…" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-5","stream":true,"messages":[{"role":"user","content":"Bonjour !"}]}'
```

Gatekey vérifie le token, le retire de la requête, injecte votre clé et renvoie
la réponse en streaming, au fur et à mesure.

---

## Fonctionnement

**Les routes.** Une route associe un préfixe d'URL à un fournisseur, avec sa clé,
ses quotas et ses limites. Un seul fournisseur par route : votre app sait déjà à
qui elle parle, et Gatekey ne réécrit jamais les formats de requête. Pour
plusieurs fournisseurs, déclarez plusieurs routes.

**Les tokens.** Les clients s'authentifient avec un token signé dans
`X-App-Token`. Rien n'est stocké côté serveur : le token porte son identifiant
d'installation, sa route et son expiration, et Gatekey vérifie la signature. Il y
a deux sortes d'appelants.

- Une **application** reçoit un token d'accès court et un token de renouvellement
  long, et se renouvelle seule via `POST /-/refresh`.
- Un **backend ou une tâche planifiée**, qui n'a nulle part où faire tourner une
  boucle de renouvellement, prend un token à longue durée de vie :
  `gatekey issue -install cron -route /openai -ttl 87600h`. Il reste nommé et
  révocable, contrairement à une constante écrite à la main.

**Les installations.** Quotas, rate limit et métriques sont indexés sur
l'identifiant d'installation du token : un renouvellement ne remet donc jamais un
budget à zéro. Ce que représente une installation, c'est votre choix : une seule
pour toute l'application, ou une par appareil si vous voulez donner un budget à
chacun de vos utilisateurs.

**Le décompte de consommation.** Gatekey lit au vol le rapport d'usage du
fournisseur pendant qu'il défile, sans jamais mettre la réponse en tampon. Il
comprend les formats OpenAI, Anthropic et Gemini, et réassemble les compteurs
coupés entre deux morceaux TCP.

**Les quotas sont souples.** Un modèle ne déclare sa consommation qu'une fois la
réponse écrite : les requêtes déjà en vol au moment où un plafond est atteint
passent donc toutes. Dimensionnez un budget comme un disjoncteur, avec de la
marge, pas comme un plafond comptable exact.

---

## Intégration côté client

Pointez le SDK du fournisseur vers Gatekey et ajoutez l'en-tête du token. Rien
d'autre ne change.

**JavaScript / TypeScript**

```js
import OpenAI from "openai";

const client = new OpenAI({
  baseURL: "http://localhost:8080/openai/v1",
  apiKey: "unused",                             // exigé par le SDK, jamais envoyé
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

**Renouveler le token**

```bash
curl -X POST http://localhost:8080/-/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"gk1.…"}'
# → {"access_token":"gk1.…","expires_at":"…","expires_in":900}
```

Rangez le token de renouvellement dans le trousseau de l'OS plutôt que dans le
stockage local, et renouvelez un peu avant l'expiration. Dans une app desktop
(Tauri, Electron), gardez le token côté natif et faites les appels depuis là : la
webview ne le voit alors jamais.

**Appels depuis un navigateur.** Une page web ne peut appeler Gatekey que si son
origine est autorisée :

```yaml
server:
  cors_origins: ["https://app.example.com"]   # "*" autorise toute origine
```

Le CORS est désactivé par défaut — une app native ou un backend n'en a pas besoin
— et il n'est jamais appliqué à `/metrics` ni à `/-/reload`. Les préflights sont
traités par Gatekey lui-même, sans token, et n'atteignent jamais le fournisseur.

---

## Configuration

[`config.example.yaml`](config.example.yaml) documente chaque option. Les
principales :

| Clé | Rôle |
| --- | --- |
| `server.listen` | Adresse d'écoute. Si le port est pris, les suivants sont essayés. |
| `server.auth_header` | En-tête portant le token client (par défaut `X-App-Token`). |
| `server.state_dir` | Où sont écrits `quotas.json` et `metrics.json`. Indispensable sur un système de fichiers en lecture seule. |
| `server.cors_origins` | Origines web autorisées depuis un navigateur. Vide = aucun en-tête CORS. |
| `server.request_timeout`, `response_header_timeout` | Plafond sur un échange entier, et sur l'attente du premier octet du fournisseur. |
| `tokens.signing_key` | Signe tous les tokens émis. La changer les invalide tous. |
| `tokens.access_ttl` / `refresh_ttl` | 15 minutes et 30 jours par défaut. |
| `tokens.denylist` | Installations coupées au prochain rechargement. |
| `routes[].path_prefix` / `target_url` | Le préfixe servi et le fournisseur derrière. |
| `routes[].inject_headers` | En-têtes ajoutés vers le fournisseur, en général la clé. |
| `routes[].rate_limit` | `requests_per_minute` et `burst`, par installation. |
| `routes[].quota` | `max_tokens` et `max_budget_usd` par installation ; `total_max_tokens` et `total_budget_usd` pour toute la route ; `reset: never\|daily\|monthly` ; tarification par modèle. |
| `routes[].forward_headers` | En-têtes de l'appelant relayés. Tout le reste est supprimé, y compris son propre token. |
| `routes[].credential` | Une identification que Gatekey renouvelle lui-même, à la place d'un en-tête fixe. |

Les références `${VAR}` sont lues dans l'environnement et remplacées **dans les
valeurs seulement**, après lecture du YAML : une référence écrite dans un
commentaire est ignorée, et un secret contenant un guillemet ou un retour à la
ligne ne peut pas modifier la structure autour de lui. Une variable non définie
fait échouer le chargement au lieu de produire un `Authorization: Bearer ` vide.
Écrivez `$$` pour un dollar littéral.

---

## Points d'entrée

| Point d'entrée | Qui peut l'appeler | Rôle |
| --- | --- | --- |
| `/<prefixe>/…` | Tout appelant muni d'un token valide | Relaie vers le fournisseur. |
| `POST /-/refresh` | Tout le monde | Échange un token de renouvellement contre un token d'accès neuf. Tous les échecs renvoient le même 401 opaque. |
| `GET /healthz` | Tout le monde | Sonde de vie. |
| `GET /metrics` | **Machine locale uniquement** | Trafic par route et par installation, avec historique à la minute sur 24 h, à l'heure sur 30 jours, au jour sur un an. Expose les installations et les dépenses. |
| `POST /-/reload` | **Machine locale uniquement** | Relit la configuration. |

Les réponses portent `X-Quota-Tokens-Limit`, `X-Quota-Tokens-Used`,
`X-Quota-Budget-Limit`, `X-Quota-Budget-Used`, `X-RateLimit-Limit` et
`X-RateLimit-Remaining`, pour qu'un client affiche sa propre consommation.

Les erreurs ont toujours la même forme :

```json
{"error": {"code": "token_quota_exceeded", "message": "…", "status": 402}}
```

`401` non authentifié · `402` quota ou budget épuisé · `403` interdit · `404`
aucune route · `413` corps trop volumineux · `429` débit dépassé · `502`
fournisseur injoignable.

---

## Exploitation

**Rechargement.** Gatekey surveille son fichier de configuration et applique un
changement valide en moins de deux secondes, sans couper une seule connexion.
`SIGHUP` et `POST /-/reload` font la même chose à la demande. Un fichier invalide
est refusé, et la configuration en cours reste active.

**Fichiers d'état**, tous en `0600` :

| Fichier | Contenu |
| --- | --- |
| `quotas.json` + `quotas.json.log` | Compteurs de consommation. Toutes les 5 s, le journal ne reçoit que les compteurs modifiés ; il est replié dans l'instantané à l'arrêt propre, une fois par jour, ou quand il atteint la taille de l'instantané. Les compteurs survivent à un crash. |
| `metrics.json` | Rapport de trafic, réécrit chaque minute et seulement si quelque chose a changé. Une année complète d'historique tient en ~265 Ko et ne grossit jamais au-delà. |
| `credentials.json` | Jetons de renouvellement des fournisseurs, pour une route qui renouvelle elle-même son identification. |

Ces trois fichiers nomment des installations et des dépenses. Ne les committez
pas.

**Conteneurs.** Avec Podman et une unité systemd Quadlet :

```ini
[Container]
Image=localhost/gatekey:latest
PublishPort=8080:8080
Environment=OPENAI_API_KEY=sk-…
Memory=512m
Environment=GOMEMLIMIT=460MiB
Volume=%h/gatekey/config.yaml:/etc/gatekey/config.yaml:ro,Z
```

Dimensionnement : environ **100 Ko par réponse en cours**, plus 16 Mo au repos.
`GOMEMLIMIT` réglé juste sous le plafond du conteneur fait travailler le
ramasse-miettes davantage plutôt que de faire tuer le process.

**Tests**

```bash
go test -race ./...
go vet ./... && gofmt -l .
```

**Test de charge.** `cmd/loadtest` lance le vrai binaire contre un faux
fournisseur, puis vérifie que rien n'a été perdu :

```bash
go run ./cmd/loadtest mock -addr 127.0.0.1:9100
go run ./cmd/loadtest run -target http://127.0.0.1:8095/mock/v1/chat/completions \
  -config config.yaml -mode stream -conc 5000 -duration 45s -pid <pid de gatekey>
go run ./cmd/loadtest verify -state ./state -record record.jsonl
```

**Profilage**, compilé uniquement à la demande, jamais dans un binaire publié :

```bash
go build -tags pprof -o gatekey ./cmd/gatekey
GATEKEY_PPROF=127.0.0.1:6060 ./gatekey -config config.yaml
go tool pprof http://127.0.0.1:6060/debug/pprof/heap
```

---

## Performances

Mesuré avec `cmd/loadtest` sur une machine à 12 cœurs, contre un fournisseur qui
diffuse pendant 10 s. Le générateur, le proxy et le fournisseur se partagent
cette machine : ces chiffres sont donc pessimistes.

| Streams simultanés | Premier octet, via Gatekey | En direct | Mémoire | Erreurs |
| --- | --- | --- | --- | --- |
| 1 000 | 1,5 ms p50 · 2,9 ms p99 | 0,5 ms p50 · 1,3 ms p99 | 173 Mo | 0 |
| 5 000 | 1,4 ms p50 · 5,9 ms p99 | — | 436 Mo avec `GOMEMLIMIT` | 0 |
| 20 000 | 0,5 s p50 — machine saturée | — | 3,1 Go | 0 |

Gatekey ajoute donc environ **1 ms** avant le premier octet, face aux centaines
de millisecondes que met un modèle à commencer à répondre. Hors streaming,
environ 18 000 requêtes/s sur cette machine. Refuser un faux token coûte
0,09 ms ; répondre à un préflight CORS, 0,02 ms.

Sur l'ensemble de ces essais — 3,3 millions de requêtes — les compteurs de
consommation et les métriques correspondaient exactement au générateur : aucun
appel ni aucun token n'a été oublié.

---

## Modèle de sécurité

**Ce que Gatekey protège**

- La clé du fournisseur n'atteint jamais le client et n'apparaît dans aucune
  réponse.
- Le token de l'appelant n'est jamais transmis au fournisseur, quoi que dise
  `forward_headers`.
- Les tokens sont signés, limités à une route, de courte durée, et révocables par
  installation.
- Un token volé est plafonné par son quota, par le total de la route et par le
  rate limit.
- Les tokens sont vérifiés en temps constant, et tous les échecs de
  renouvellement sont indistinguables de l'extérieur.
- `/metrics` et `/-/reload` refusent tout ce qui ne vient pas de la machine
  locale.

**Ce qu'il ne protège pas, volontairement**

- **Quiconque obtient un token peut s'en servir.** La façon dont une nouvelle
  installation reçoit son premier token est une décision de l'exploitant ; le
  proxy ne vérifie pas l'appareil. Plafonnez ce qu'un abus peut coûter avec
  `total_budget_usd`.
- **Le CORS est appliqué par le navigateur, pas par Gatekey.** Il empêche un
  autre site d'utiliser le navigateur de vos utilisateurs. Il n'arrête aucun
  script.
- **Les quotas sont souples.** Voir [Fonctionnement](#fonctionnement).
- **Gatekey ne lit ni ne conserve les prompts.** Il ne lit que le bloc d'usage
  d'une réponse au passage.

---

## Organisation du projet

```text
cmd/
  gatekey/      CLI : lancer le serveur, genkey, issue
  loadtest/     faux fournisseur, générateur de charge, vérification des pertes
internal/
  proxy/        routage, authentification, CORS, streaming, lecture de l'usage
  token/        tokens signés : émission, vérification, renouvellement, denylist
  quota/        compteurs, budgets et leur journal résistant aux crashs
  limiter/      rate limiting (token bucket)
  metrics/      rapport de trafic et historique
  credential/   identifications renouvelées automatiquement
  config/       configuration YAML, validation, rechargement à chaud
  routes/       points d'entrée HTTP
  apierror/     une seule forme d'erreur JSON
```

Construit uniquement sur la bibliothèque standard de Go : `net/http` et
`net/http/httputil.ReverseProxy`, sans framework web.

---

## Open core et licence

Ce dépôt contient le proxy, sous licence Apache 2.0 : utilisez-le, hébergez-le,
modifiez-le. Le service hébergé, son dashboard et sa mise en service sont
séparés et ne font pas partie de ce dépôt.

Voir [LICENSE](LICENSE).
