# Gatekey

**Gatekey** est un micro reverse-proxy HTTP ultra-léger, modulaire et agnostique écrit en Go, conçu comme un **gardien de clés d'API (API Key Guard)**.

Il permet d'exposer des points d'accès unifiés et sécurisés vers n'importe quelle API distante (fournisseurs d'IA comme OpenAI, Anthropic, Mistral, ou vos propres microservices et LLMs locaux comme vLLM ou Ollama), en injectant les secrets d'amont en toute sécurité sans jamais les divulguer aux clients.

---

## Fonctionnalités Clés

- **Bibliothèque standard pure (KISS) :** Conçu sans framework tiers lourd (pas de Gin, Echo ou Fiber) avec `net/http` et `net/http/httputil.ReverseProxy`.
- **Zéro allocation superflue :** Le corps des requêtes et des réponses n'est ni décodé ni bufférisé en mémoire. Idéal pour le streaming en temps réel (**Server-Sent Events / SSE** pour les tokens LLM avec `FlushInterval: -1`).
- **Suivi des Coûts et Quotas Hybrides (Tokens & USD) :**
  - Extraction non-bloquante au vol de l'usage LLM (Prompt + Completion) dans les flux SSE et JSON standard, sans mise en mémoire tampon.
  - Compatible avec les trois conventions de nommage : OpenAI (`prompt_tokens`/`completion_tokens`), Anthropic (`input_tokens` en `message_start` puis `output_tokens` en `message_delta`) et Gemini natif (`usageMetadata.promptTokenCount`/`candidatesTokenCount`). Les compteurs fragmentés sur plusieurs chunks TCP sont réassemblés.
  - Double seuil configurable par route : en nombre total de tokens (`max_tokens`) et/ou en budget financier (`max_budget_usd`).
  - Budget total par route, toutes installations confondues (`total_max_tokens`, `total_budget_usd`) : une requête doit tenir dans son quota d'installation **et** dans le total. Au-delà, erreur `402 total_quota_exceeded`, sans aucun montant exposé à l'appelant.
  - Tarification personnalisée par route (`prompt_usd` et `completion_usd` par million de tokens).
  - Coupure stricte par code HTTP RFC standard `402 Payment Required` dès l'épuisement.
  - En-têtes télémétriques transmis aux clients : `X-Quota-Tokens-Limit`, `X-Quota-Tokens-Used`, `X-Quota-Budget-Limit`, `X-Quota-Budget-Used`.
  - **Application « souple » (soft) :** un LLM ne déclare sa consommation qu'une fois la réponse produite. Le contrôle ne voit donc que ce que les requêtes précédentes ont déjà consommé : des requêtes concurrentes lancées près du plafond passent toutes, et la limite peut être dépassée d'environ un lot de requêtes en vol. À dimensionner comme un disjoncteur, pas comme un plafond comptable exact.
  - Persistance sur disque en journal (`quotas.json` + `quotas.json.log`, permissions `0600`) : toutes les 5 s, seuls les compteurs modifiés sont ajoutés au journal, puis le journal est replié dans `quotas.json` à l'arrêt propre, une fois par jour, ou quand il atteint la taille de l'instantané. Les compteurs survivent à un redémarrage comme à un crash. Le fichier est indexé par `<route>:<token client>` : il contient des identifiants, ne le committez pas.
- **Gestion Centralisée et Typée des Erreurs (`internal/apierror`) :**
  - Format JSON unifié et prédictible pour les clients : `{"error": {"code": "...", "message": "...", "status": ...}}`.
  - Couvre l'authentification (401), l'accès refusé (403), le routage (404), le rate limiting (429), les quotas (402), la taille payload (413) et les erreurs amont (502).
- **Rate Limiting en Go pur (Token Bucket) :**
  - Algorithme Token Bucket en mémoire vive (RAM pure, sans dépendance externe ni Redis).
  - Configurable par route dans le YAML (`requests_per_minute` et `burst`).
  - Isolation stricte par token client (les abus d'un client ne pénalisent pas les autres).
  - En-têtes HTTP standards émis : `429 Too Many Requests`, `Retry-After`, `X-RateLimit-Limit`, `X-RateLimit-Remaining`.
- **Cache de Tokens Centralisé & Sécurisé :**
  - **TTL de 15 minutes** en mémoire par token validé (lookup en 65 nanosecondes, 0 allocation).
  - Vérification en **temps constant** (`crypto/subtle.ConstantTimeCompare`) pour immuniser contre les attaques temporelles (timing attacks).
  - Éviction automatique en arrière-plan des entrées expirées.
  - **Invalidation immédiate** des tokens révoqués ou des routes supprimées lors des rechargements de configuration.
- **Sélection Automatique de Port (Port Hunting) :**
  - Si le port configuré (ex: `8080`) est déjà occupé, Gatekey bascule automatiquement et de manière transparente sur les ports suivants (`8081`, `8082`...).
- **Rechargement à chaud sans coupure (Hot Reload sans redémarrage) :**
  - Surveillance automatique par métadonnées `os.Stat` (~300 nanosecondes, 0 I/O disque si inchangé).
  - Sous Linux/Unix : Écoute du signal POSIX `SIGHUP`.
  - Via HTTP : Endpoint d'administration sécurisé `POST /-/reload` (restreint strictement à l'interface loopback `127.0.0.1` / `[::1]`).
- **Healthcheck & Télémétrie / Métriques natives :**
  - Route ultra-légère `GET /healthz` pour les sondes Kubernetes et conteneurs Podman.
  - Route `GET /metrics` avec historique à trois résolutions — par minute sur 24 h, par heure sur 30 jours, par jour sur un an — et persistance atomique sur disque (`metrics.json`, `0600`). L'historique complet tient en ~265 Ko et ne grossit jamais. **Restreinte à l'interface loopback** (`127.0.0.1` / `[::1]`) au même titre que `/-/reload` : elle expose les routes actives, l'usage par installation et les dépenses.
- **Support des variables d'environnement :** Substitution automatique `${VAR}` dans le fichier YAML. Une variable non définie **fait échouer le chargement** au lieu de produire silencieusement un `Authorization: Bearer ` vide ; utilisez `$$` pour un dollar littéral. Lors d'un rechargement à chaud, l'ancienne configuration valide reste active.

---

## Architecture du Projet

```text
.
├── cmd/
│   └── gatekey/
│       ├── main.go           # Point d'entrée CLI minimaliste (35 lignes : flags et app.Run)
│       └── main_test.go      # Test d'amorçage de l'application
├── internal/
│   ├── apierror/
│   │   ├── apierror.go       # Enveloppe d'erreur JSON centralisée et codes typés
│   │   └── apierror_test.go  # Tests unitaires des erreurs API
│   ├── app/
│   │   ├── app.go            # Superviseur de cycle de vie (wiring, signaux OS, auto-watcher, graceful shutdown)
│   │   └── app_test.go       # Tests unitaires du cycle de vie
│   ├── config/
│   │   ├── config.go         # Structures, parsing YAML, expansion ENV stricte et ConfigManager atomique
│   │   └── config_test.go    # Tests de validation et de reload
│   ├── limiter/
│   │   ├── limiter.go        # Rate limiter en mémoire vive (algorithme Token Bucket, auto-pruning)
│   │   └── limiter_test.go   # Tests unitaires du rate limiter
│   ├── metrics/
│   │   ├── collector.go      # Télémétrie non-bloquante, agrégats et persistance metrics.json
│   │   └── collector_test.go # Tests unitaires du collecteur
│   ├── token/
│   │   ├── token.go          # Tokens HMAC-SHA256 sans état : émission, vérification, refresh, denylist
│   │   └── token_test.go     # Tests unitaires de signature, expiration, confusion de type et révocation
│   ├── netutil/
│   │   ├── listener.go       # ListenWithFallback (port hunting dynamique)
│   │   └── listener_test.go  # Tests unitaires réseau et fallback
│   ├── proxy/
│   │   ├── handler.go        # ReverseProxy httputil, streaming SSE, injection d'en-têtes, quotas et rate limiting
│   │   ├── handler_test.go   # Tests de flux HTTP, SSE, réécriture, quotas et rate limiting
│   │   └── middleware.go     # Middleware anti-panic centralisé et structured access logging
│   ├── quota/
│   │   ├── quota.go          # Suivi d'usage, calcul de coûts USD
│   │   ├── journal.go        # Persistance : instantané quotas.json + journal quotas.json.log
│   │   ├── parser.go         # Accumulateur d'usage multi-fournisseurs (JSON, SSE, chunks fragmentés)
│   │   ├── parser_test.go    # Tests des formats OpenAI, Anthropic et Gemini
│   │   └── quota_test.go     # Tests unitaires des quotas et budgets
│   └── routes/
│       ├── routes.go         # Enregistrement et handlers (/healthz, /metrics, /-/reload, /)
│       └── routes_test.go    # Tests unitaires des endpoints
├── config.example.yaml       # Fichier de configuration modèle documenté
├── Containerfile             # Multi-stage build minimaliste (scratch + certificats SSL, 8 Mo)
├── go.mod
├── go.sum
└── README.md
```

---

## Configuration (`config.yaml`)

Créez votre fichier `config.yaml` en vous basant sur `config.example.yaml` :

```yaml
server:
  listen: ":8080"
  auth_header: "X-App-Token" # En-tête attendu du client externe
  max_body_size_mb: 50       # Plafond de taille de payload (protection anti-DoS, défaut 50 Mo)

tokens:
  # Généré par "gatekey genkey". Unique mécanisme d'authentification client.
  signing_key: "${GATEKEY_SIGNING_KEY}"
  access_ttl: "15m"    # le token envoyé à chaque requête
  refresh_ttl: "720h"  # le token gardé dans le trousseau, échangé sur /-/refresh
  denylist: []         # install_id révoqués, coupés au prochain reload

routes:
  # Relais OpenAI avec Quota & Budget
  - path_prefix: "/openai"
    target_url: "https://api.openai.com"
    strip_prefix: true # Transforme "/openai/v1/chat/completions" -> "/v1/chat/completions"
    rate_limit:
      requests_per_minute: 60
      burst: 10
    quota:
      max_tokens: 1000000       # Plafond de tokens LLM (0 = illimite)
      max_budget_usd: 50.00     # Coupure si depasse 50 $ (0 = illimite)
      total_budget_usd: 500.00  # Toutes installations confondues (0 = illimite)
      pricing_per_million:
        prompt_usd: 2.50        # Cout par 1M tokens d'entree
        completion_usd: 10.00   # Cout par 1M tokens de sortie
    inject_headers:
      Authorization: "Bearer ${OPENAI_API_KEY}"

  # Relais Anthropic
  - path_prefix: "/anthropic"
    target_url: "https://api.anthropic.com"
    strip_prefix: true
    inject_headers:
      x-api-key: "${ANTHROPIC_API_KEY}"
      anthropic-version: "2023-06-01"

  # Relais vLLM / Ollama Local
  - path_prefix: "/vllm"
    target_url: "http://127.0.0.1:8000"
    strip_prefix: false
    inject_headers:
      Authorization: "Bearer internal-cluster-secret"
```

---

## Démarrage Rapide

### 1. Compilation & Exécution locale

```bash
# Compiler le binaire
go build -o gatekey ./cmd/gatekey

# Définir vos clés d'API dans l'environnement
export OPENAI_API_KEY="sk-proj-..."
export ANTHROPIC_API_KEY="sk-ant-..."

# Lancer Gatekey
./gatekey -config config.yaml
```

### 2. Tests automatisés

Exécuter la suite complète de tests avec détection de concurrence :

```bash
go test -count=1 -v -race ./...
```

---

## Utilisation

### Appel à l'API OpenAI via le proxy

```bash
curl -X POST http://localhost:8080/openai/v1/chat/completions \
  -H "X-App-Token: app-frontend-client-token" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o",
    "stream": true,
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

*Gatekey valide le token `X-App-Token`, le purge de la requête, injecte `Authorization: Bearer <OPENAI_API_KEY>`, ajuste le `Host: api.openai.com` et retransmet le flux SSE en direct sans buffering.*

### Intégration Client Python (avec uv)

Exécutez directement sans créer d'environnement virtuel :

```bash
uv run --with openai python client_demo.py
```

Code Python équivalent :

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8080/groq/v1", # Pointe sur Gatekey
    api_key="dummy",                         # Requis par le SDK mais non envoyé
    default_headers={"X-App-Token": "mon-client-token-secret"},
)

response = client.chat.completions.create(
    model="openai/gpt-oss-20b",
    messages=[{"role": "user", "content": "Bonjour !"}],
    stream=True,
)

for chunk in response:
    content = chunk.choices[0].delta.content
    if content:
        print(content, end="", flush=True)
```

### Rechargement à chaud (Hot Reload sans redémarrage)

Lorsque vous ajoutez, modifiez ou révoquez une clé d'API ou un token client dans `config.yaml`, **le serveur ne redémarre pas**. Il recharge sa configuration en mémoire vive instantanément sans couper les connexions existantes ni fermer le socket TCP :

1. **Méthode Automatique (Activée par défaut) :**
   Gatekey surveille le fichier de configuration (via `-watch=true`, polling d'empreinte SHA-256 toutes les 2 secondes, compatible avec les bind-mounts Podman). Dès que vous sauvegardez votre fichier YAML avec une nouvelle clé, **Gatekey l'applique automatiquement et immédiatement** !

2. **Méthode Manuelle (Signal POSIX SIGHUP) :**
   ```bash
   kill -HUP $(pidof gatekey)
   # Ou avec Podman :
   podman kill -s SIGHUP gatekey
   ```

3. **Méthode HTTP (Endpoint local restreint à 127.0.0.1) :**
   ```bash
   curl -X POST http://127.0.0.1:8080/-/reload
   ```

Lors de ce rechargement :
1. Le fichier YAML est relu et validé.
2. La table de routage en mémoire est mise à jour sous verrouillage `sync.RWMutex`.
3. Le cache mémoire est synchronisé : les nouvelles clés sont prêtes, et les clés révoquées sont immédiatement invalidées du cache.
4. Si le nouveau fichier est invalide, l'ancienne configuration est conservée sans aucune interruption.

### Sonde de santé (Healthcheck)

```bash
curl http://localhost:8080/healthz
```

### Métriques et Télémétrie en direct

Gatekey intègre un collecteur de métriques asynchrone (worker non-bloquant en RAM, zéro impact sur les performances).

Pour consulter les métriques complètes (statistiques globales, métriques par route, par installation et historique time-series). L'endpoint n'est accessible que depuis la machine hôte ; un appel distant reçoit un `403 Forbidden` :

```bash
curl -s http://127.0.0.1:8080/metrics
```

> Si vous devez les collecter à distance, passez par un tunnel SSH ou exposez-les derrière un reverse-proxy authentifié — ne publiez jamais ce port.

Les métriques sont également sauvegardées sur disque dans `metrics.json` pour conserver l'historique lors des redémarrages — seulement quand quelque chose a changé, si bien qu'un serveur inactif n'écrit rien. Les installations inactives depuis 30 jours sont retirées des statistiques par installation.

### Suivi des Coûts, Quotas et En-têtes Télémétriques

Gatekey inspecte au vol les réponses des modèles LLM (OpenAI, Groq, vLLM, etc.) que ce soit en mode unitaire JSON standard ou en streaming continu **Server-Sent Events (SSE)**, sans mise en mémoire tampon.

Les en-têtes retournés aux clients permettent aux frontends et SDKs de suivre leur consommation en temps réel :

- `X-Quota-Tokens-Limit` : Plafond configuré en nombre de tokens.
- `X-Quota-Tokens-Used` : Nombre total cumulé de tokens consommés par ce client.
- `X-Quota-Budget-Limit` : Budget financier alloué en dollars USD.
- `X-Quota-Budget-Used` : Dépense totale cumulée en dollars USD calculée au prorata des tokens d'entrée et de sortie.

En cas de dépassement, la requête est immédiatement rejetée avec le code HTTP **402 Payment Required** et un code d'erreur explicite (`token_quota_exceeded` ou `budget_quota_exceeded`).

Les consommations sont persistées en deux fichiers `0600`, tous deux en JSON lisible :

- **`quotas.json.log`** — toutes les 5 secondes, une ligne par compteur modifié depuis la dernière écriture, puis `fsync`. Le coût d'une écriture suit donc le trafic, pas le nombre d'installations : environ 0,3 ms pour 200 compteurs modifiés, que le fichier en contienne 1 000 ou 500 000.
- **`quotas.json`** — l'instantané complet. Le journal y est replié (écriture dans un fichier temporaire, `fsync`, `rename`, puis suppression du journal) à l'arrêt propre, une fois par jour, ou quand le journal atteint la taille de l'instantané. C'est aussi à ce moment que les compteurs des périodes échues sont supprimés.

Chaque ligne porte la valeur complète du compteur, et au chargement c'est l'état le plus récent qui l'emporte (période la plus récente, puis compteur le plus élevé). Rejouer une ligne deux fois ne change donc rien, ce qui rend chaque crash sans conséquence : ligne coupée en fin de journal, écriture retentée, ou journal survivant à la compaction qui devait le supprimer.

Rien de tout ça n'a lieu sur le chemin de requête : le verrou n'est tenu que le temps de copier les compteurs modifiés (quelques dizaines de microsecondes), l'encodage et le disque viennent après. Pendant une compaction, les vérifications de quota continuent de passer ; seul l'enregistrement de fin de réponse attend.

**Limite connue — l'application est souple.** Le contrôle a lieu *avant* l'appel amont, alors que la consommation n'est connue qu'*après*. Cinquante requêtes lancées simultanément à 49,99 $ passeront toutes les contrôles. Traitez `max_budget_usd` comme un disjoncteur de sécurité, avec une marge, et non comme un plafond exact. C'est encore plus vrai pour `total_budget_usd` : le dépassement possible y est celui de toutes les installations en vol à la fois.

---

## Format Standardisé des Erreurs API

Toutes les erreurs générées par Gatekey répondent au standard JSON suivant :

```json
{
  "error": {
    "code": "token_quota_exceeded",
    "message": "Token quota exceeded: consumed 1002500 tokens out of allowed 1000000 tokens.",
    "status": 402
  }
}
```

| Code HTTP | Code d'erreur interne | Signification |
| :--- | :--- | :--- |
| `401 Unauthorized` | `missing_token` | L'en-tête d'authentification est absent de la requête. |
| `401 Unauthorized` | `invalid_token` | Le token fourni n'est pas autorisé pour cette route. |
| `402 Payment Required` | `token_quota_exceeded` | Le plafond de tokens alloué à cette clé a été atteint. |
| `402 Payment Required` | `budget_quota_exceeded` | Le budget financier (USD) alloué à cette clé a été dépassé. |
| `403 Forbidden` | `forbidden` | Accès interdit (ex: appel d'un endpoint local depuis une IP distante). |
| `404 Not Found` | `route_not_found` | Aucun préfixe de route correspondant trouvé. |
| `405 Method Not Allowed` | `method_not_allowed` | Méthode HTTP non supportée pour cet endpoint. |
| `413 Payload Too Large` | `payload_too_large` | Le corps de la requête dépasse la limite `max_body_size_mb`. |
| `429 Too Many Requests` | `rate_limit_exceeded` | Dépassement de la fréquence autorisée (en-tête `Retry-After` fourni). |
| `502 Bad Gateway` | `bad_gateway` | L'API distante upstream est inaccessible ou a refusé la connexion. |
| `500 Internal Error` | `internal_server_error` | Incident interne non intercepté. |

---

## Conteneurisation avec Podman

Le `Containerfile` utilise un build multi-stage produisant une image minimale `scratch` avec les certificats racines CA et un utilisateur non-privilégié (`UID 10001`), conçu spécifiquement pour une exécution **Podman rootless**.

### 1. Construction de l'image

```bash
podman build -t gatekey -f Containerfile .
```

### 2. Exécution avec Podman (Rootless & SELinux)

Notez l'utilisation de `:ro,Z` pour le montage du volume, indispensable pour la conformité des labels SELinux avec Podman :

```bash
podman run -d \
  --name gatekey \
  -p 8080:8080 \
  -e OPENAI_API_KEY="sk-..." \
  -e ANTHROPIC_API_KEY="sk-ant-..." \
  -v $(pwd)/config.yaml:/etc/gatekey/config.yaml:ro,Z \
  gatekey
```

Pour déclencher le rechargement à chaud dans Podman sans redémarrer le conteneur :

```bash
podman kill -s SIGHUP gatekey
```

### 3. Déploiement en tant que service utilisateur systemd (Podman Quadlet)

Pour gérer Gatekey automatiquement via systemd avec Podman, créez un fichier `~/.config/containers/systemd/gatekey.container` :

```ini
[Unit]
Description=Gatekey API Key Guard Proxy
After=network-online.target

[Container]
Image=localhost/gatekey:latest
PublishPort=8080:8080
Environment=OPENAI_API_KEY=sk-...
Volume=%h/gatekey/config.yaml:/etc/gatekey/config.yaml:ro,Z

[Install]
WantedBy=default.target
```

Puis rechargez systemd :
```bash
systemctl --user daemon-reload
systemctl --user start gatekey
```
