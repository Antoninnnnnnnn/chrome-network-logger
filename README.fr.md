# Chrome Network Logger v3

[![Tests](https://github.com/Antoninnnnnnnn/chrome-network-logger/actions/workflows/tests.yml/badge.svg)](https://github.com/Antoninnnnnnnn/chrome-network-logger/actions/workflows/tests.yml)
[![CodeQL](https://github.com/Antoninnnnnnnn/chrome-network-logger/actions/workflows/codeql.yml/badge.svg)](https://github.com/Antoninnnnnnnn/chrome-network-logger/actions/workflows/codeql.yml)

[🇬🇧 English version](https://github.com/Antoninnnnnnnn/chrome-network-logger/blob/main/README.md)

Outil Python pour capturer le **trafic applicatif visible par Chrome** avec le Chrome DevTools Protocol (CDP), sans Selenium ni Playwright. Il lance un profil Chrome dédié, se connecte au **target navigateur**, puis attache tous les targets page, popup, iframe hors processus, webview et worker pris en charge et exposés par Chrome.

> Ce n'est pas un sniffer de paquets. DNS/TCP/TLS/QUIC brut et WebRTC média/DataChannel ne sont pas exposés ici ; les octets multipart ne sont disponibles que lorsque CDP les fournit explicitement.

## Ce qui change dans la v3

- Un seul point d'entrée : `python chrome_network_logger.py` ou `chrome-network-logger` après installation.
- Connexion CDP au niveau navigateur pour couvrir les onglets et popups indépendants.
- Identifiants namespacés par `sessionId`, `requestId` et hop de redirection.
- Chaque hop 3xx est conservé séparément, avec ses `ExtraInfo`.
- Arrêt propre : requêtes, WebSockets et WebTransport ouverts sont marqués `incomplete` puis sauvegardés.
- Bodies externes, compressés, limités par body et par session, puis dédupliqués par SHA-256.
- WebSocket et SSE écrits au fil de l'eau, sans accumulation illimitée en mémoire.
- Une seule source canonique : `network/requests.jsonl`.
- Timestamps normalisés (`epochMs`, ISO local et horloge monotone CDP quand disponible).
- Cookies et `localStorage`/`sessionStorage` photographiés au début et à la fin.
- Console, exceptions, logs navigateur et navigations enregistrés dans des fichiers dédiés.
- Script d’interactions installé dans un monde JavaScript isolé ; en mode sûr, toutes les valeurs de formulaire sont masquées et aucun `outerHTML` brut n’est exporté.
- Secrets masqués par défaut avec une longueur et un HMAC propre à la session, sans perdre l'information qu'une valeur existait.
- Relay proxy réécrit : sockets correctement suivis/fermés, IPv6, proxy HTTP ou HTTPS, bascule directe en live sous Windows.
- Les erreurs fatales CDP/writer produisent un manifeste `error` et un code de sortie non nul, sans faux succès.
- Payloads d’interaction, `ExtraInfo` en attente, connexions proxy et file du writer sont bornés.
- Package typé, 96 tests, couverture imposée, validation du paquet, Dependabot, CodeQL et CI Windows/Linux/macOS sur Python 3.10 à 3.14.
- Si aucun Chrome local n’existe, téléchargement et mise en cache automatiques du Chrome for Testing Stable officiel, sans ChromeDriver.

## Installation

```bash
python -m pip install -e .
```

Pour contribuer :

```bash
python -m pip install -e .[dev]
python -m ruff check .
python -m ruff format --check .
python -m bandit -q -r chrome_logger chrome_network_logger.py -s B404,B603
python -m pytest --cov=chrome_logger
python -m build
python -m twine check dist/*
```

Prérequis : Python 3.10+. Un Chrome/Chromium déjà installé est utilisé en priorité ; sinon l’outil récupère le [Chrome for Testing Stable officiel](https://googlechromelabs.github.io/chrome-for-testing/).

## Utilisation

```bash
python chrome_network_logger.py
```

Au premier lancement, un profil isolé et persistant est créé dans `./capture_profile`. Les sessions et connexions de ton Chrome principal ne sont pas utilisées. Si Chrome est absent, le binaire Stable officiel est téléchargé une seule fois dans le cache utilisateur (`%LOCALAPPDATA%\chrome-network-logger` sous Windows) puis réutilisé hors ligne. Aucun ChromeDriver, Selenium ou Playwright n’est installé.

Il s’agit d’un vrai processus Chrome visible, lancé sans mode headless, sans WebDriver, sans `--enable-automation` et avec un port CDP loopback non nul pour que Chrome ne force pas `navigator.webdriver=true`. Cela évite les marqueurs propres à Selenium/Playwright, mais **ne garantit pas l’indétectabilité** : un site peut toujours inférer un profil neuf, une instrumentation CDP, des extensions, le réseau ou d’autres caractéristiques de l’environnement.

Exemples :

```bash
# Bodies des XHR/Fetch/Documents, secrets masqués — valeurs par défaut
python chrome_network_logger.py --body-mode api --sensitive safe

# Capture réseau plus large
python chrome_network_logger.py --body-mode all

# Aucun body, seulement métadonnées/headers/timings
python chrome_network_logger.py --body-mode none

# Valeurs brutes : mots de passe, cookies et tokens seront enregistrés
python chrome_network_logger.py --sensitive raw

# Dossier et profil explicites
python chrome_network_logger.py --output-dir captures/shein --profile-dir profiles/shein

# Mode automatisé, sans questions, finalisé après 60 secondes
python chrome_network_logger.py --non-interactive --output-dir captures --duration 60
```

Options importantes :

| Option | Effet |
|---|---|
| `--body-mode none\|api\|all` | Politique des bodies HTTP et des payloads WebSocket/SSE |
| `--max-body-mb 32` | Taille stockée maximale par body ; `0` = illimité |
| `--max-session-body-mb 2048` | Total maximal de bodies uniques stockés par session ; `0` = illimité |
| `--sensitive safe\|raw` | Masquage par défaut ou conservation brute |
| `--no-interactions` | Désactive clics, inputs, formulaires et navigation SPA injectée |
| `--capture-clipboard` | Capture les collages ; masqués en mode `safe` |
| `--no-console` | Désactive console, exceptions et domaine `Log` |
| `--no-storage` | Désactive snapshots cookies/localStorage/sessionStorage |
| `--snapshot-interval 30` | Rafraîchit les snapshots cookies/storage toutes les N secondes pour garder un état récent si le navigateur est fermé ; `0` désactive |
| `--keep-chrome` | Laisse Chrome ouvert après avoir désactivé Fetch, l'auto-attach et les listeners injectés |
| `--duration SECONDES` | Arrête et finalise automatiquement ; valeur finie et positive ou nulle |
| `--start-url URL` | Page initiale ; `about:blank` par défaut évite le trafic spontané du nouvel onglet |
| `--proxy N\|random\|none` | Active explicitement un proxy ; `none`/connexion directe par défaut |
| `--chrome-path PATH` | Chemin Chrome/Chromium explicite |
| `--managed-chrome-dir PATH` | Emplacement du Chrome Stable officiel géré par l’outil |
| `--no-download-chrome` | Refuse le téléchargement automatique si Chrome est absent |
| `--refresh-managed-chrome` | Recherche une version Stable gérée plus récente lorsque le secours est utilisé |
| `--version` | Affiche la version installée |

## Sortie

```text
session_YYYYMMDD_HHMMSS_mmm_PID_ALÉA/
├── manifest.json
├── timeline.jsonl
├── network/
│   ├── requests.jsonl
│   └── bodies/
│       ├── <sha256>.json.gz
│       ├── <sha256>.html.gz
│       └── <sha256>.bin
├── realtime/
│   ├── websocket_connections.jsonl
│   ├── websocket_frames.jsonl
│   ├── websocket_errors.jsonl
│   ├── sse_messages.jsonl
│   └── webtransport.jsonl
├── interactions/
│   ├── events.jsonl
│   └── forms.jsonl
├── browser/
│   ├── targets.jsonl
│   ├── navigations.jsonl
│   ├── console.jsonl
│   ├── exceptions.jsonl
│   ├── log.jsonl
│   ├── protocol_errors.jsonl
│   ├── protocol_capabilities.jsonl
│   └── proxy_toggles.jsonl
├── snapshots/
│   ├── cookies_start.json
│   ├── cookies_end.json
│   ├── storage_start.jsonl
│   └── storage_end.jsonl
└── reports/
    ├── summary.txt
    ├── stats.txt
    ├── requests.csv
    └── interactions.html
```

`requests.jsonl` est canonique : il n'existe plus deux copies `full` et `filtered`. Le champ `isApi` permet de filtrer sans doubler les bodies sur disque.

Les références de body contiennent notamment :

- leur chemin relatif ;
- le SHA-256 ;
- la taille d'origine et la taille enregistrée ;
- le MIME type ;
- l'état `truncated`, `compressed` et `redacted` ;
- l’encodage textuel détecté ;
- un court aperçu uniquement pour les petites réponses textuelles.

Lorsque la limite globale est atteinte, les métadonnées restent présentes avec `omittedReason: "sessionBodyLimit"`, mais aucun faux chemin de fichier n’est annoncé. Le [schéma de capture](https://github.com/Antoninnnnnnnn/chrome-network-logger/blob/main/docs/CAPTURE_SCHEMA.md) décrit les champs et garanties de stabilité.

## Masquage des secrets

Le mode par défaut `--sensitive safe` masque notamment :

- `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie` ;
- mots de passe, secrets, clés API, tokens d'accès/refresh/ID ;
- OTP, PIN, CVV/CVC et champs assimilés ;
- paramètres sensibles dans les URL ;
- JSON et formulaires URL-encoded structurés ;
- URLs `data:`/`javascript:`, attributs HTML sensibles, stockage Web, toutes les valeurs de contrôles/formulaires et presse-papiers.

Une valeur masquée ressemble à :

```text
<redacted len=123 hmac=4ab31c8702ef>
```

Le HMAC utilise une clé aléatoire créée pour chaque capture : deux valeurs identiques sont comparables **dans une même session**, mais pas entre deux sessions. La clé n’est pas écrite dans les logs. Les valeurs d’input et de formulaire sont masquées directement dans le monde isolé de la page sous la forme `<redacted len=N source=browser>` : la valeur brute ne traverse jamais le binding CDP et ce marqueur de longueur ne permet pas de comparer deux secrets. Le markup de l’élément devient un placeholder limité au nom du tag. Le mode `raw` doit être choisi explicitement.

Le mode `safe` est une protection par défaut, pas une garantie absolue : un format propriétaire, payload binaire ou chiffré par l’application, ou une valeur sensible au nom inhabituel peut rester visible. Toute capture reste confidentielle. Consulte le [modèle de menace](https://github.com/Antoninnnnnnnn/chrome-network-logger/blob/main/docs/THREAT_MODEL.md).

## Proxy

Place `proxy.txt` à côté du script. Formats acceptés :

```text
host:port
host:port:user:password
user:password@host:port
http://host:port
https://user:password@host:port
socks5://host:port
[2001:db8::1]:8080
host port
host port user password
```

Sélection :

```bash
python chrome_network_logger.py --proxy random
python chrome_network_logger.py --proxy 2
python chrome_network_logger.py --proxy none
python chrome_network_logger.py --proxy-prompt
python chrome_network_logger.py --proxy-file autre.txt
```

Pour les proxies HTTP/HTTPS, Chrome se connecte à un relay local sur `127.0.0.1`. Le relay ajoute l'authentification sans popup et peut être basculé entre proxy et connexion directe avec **P sous Windows**. Toutes les connexions actives sont alors fermées afin que le nouvel itinéraire soit réellement utilisé.

Les proxies SOCKS sans authentification sont passés directement à Chrome. L'authentification SOCKS n'est pas simulée silencieusement : elle est refusée avec une erreur claire. La validation TLS d'un proxy HTTPS reste active, sauf option explicite `--proxy-insecure-tls`.

La présence de `proxy.txt` n’active jamais un proxy à elle seule : le routage reste direct tant qu’un sélecteur explicite n’est pas fourni. Le relay borne aussi le nombre de connexions simultanées et répond `503` en cas de saturation.

## Fiabilité et limites CDP

- `Network.getRequestPostData` omet les octets des fichiers envoyés en multipart. Lorsque Chrome fournit séparément des `postDataEntries.bytes`, le logger les externalise ; leur présence dépend toutefois de ce que CDP expose pour la requête concernée.
- Le domaine Network expose le cycle de vie WebTransport, pas les payloads streams/datagrammes.
- Les réponses très volumineuses ou streaming peuvent dépasser les buffers CDP ou la limite choisie.
- Les bodies des redirections HTTP ne sont pas exposés par `Fetch.getResponseBody` ; chaque hop reste néanmoins conservé avec sa réponse et ses headers.
- WebRTC média/DataChannel et le trafic paquet brut restent hors périmètre.
- L'interception `Fetch` est limitée aux réponses `Document` afin d'améliorer les navigations sans suspendre toutes les requêtes du navigateur.
- Les capacités expérimentales optionnelles sont consignées dans `browser/protocol_capabilities.jsonl`. L’échec ou le timeout d’un domaine requis (`Network`, `Runtime`, `Page`, `Fetch` ou auto-attach) rend la capture invalide et donne un code de sortie non nul.

Références officielles : [Network](https://chromedevtools.github.io/devtools-protocol/tot/Network/), [Target](https://chromedevtools.github.io/devtools-protocol/tot/Target/), [Fetch](https://chromedevtools.github.io/devtools-protocol/tot/Fetch/).

## Architecture du code

```text
chrome_logger/
├── cli.py                 # cycle de vie du programme
├── cdp.py                 # client CDP, targets, commandes pendantes, arrêt
├── network_capture.py     # HTTP, redirections, ExtraInfo et bodies
├── realtime_capture.py    # WebSocket, SSE et WebTransport
├── browser_capture.py     # interactions, console, navigation et snapshots
├── registry.py            # identité session/request/hop et ordre des ExtraInfo
├── storage.py             # writer thread, JSONL, bodies et rapports
├── redaction.py           # masquage contextuel
├── proxy.py               # parsing et relay HTTP(S)
├── managed_chrome.py      # téléchargement/cache officiel et extraction sûre
└── chrome.py              # lancement/nettoyage du profil dédié
```

`chrome_network_logger.py` reste un wrapper compatible. Les tests couvrent registres, frontières de sécurité CDP, cycles HTTP/Fetch/temps réel, timestamps, santé et limites du stockage, redaction, proxy, installation gérée de Chrome, codes de sortie CLI et script d’interactions. Consulte [CONTRIBUTING.md](https://github.com/Antoninnnnnnnn/chrome-network-logger/blob/main/CONTRIBUTING.md) avant toute contribution.

## Sécurité et autorisation

Utilise l'outil uniquement sur des applications, comptes et systèmes que tu possèdes ou que tu es autorisé à inspecter. Même en mode `safe`, une capture peut contenir des données privées, des URLs internes et des métadonnées de session. Les dossiers `session_*`, `capture_profile` et `proxy.txt` sont ignorés par Git.

## Licence

MIT
