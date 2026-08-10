# Chrome Network Logger

[🇬🇧 English version](README.md)

Outil Python léger pour capturer le **trafic applicatif de Chrome** via le Chrome DevTools Protocol (CDP), sans Selenium ni Playwright. Il utilise un profil Chrome dédié afin de ne pas toucher à ton profil principal.

Le repo contient maintenant deux points d'entrée :

- `chrome_network_logger.py` — capture généraliste/complète avec interactions utilisateur.
- `api_network_logger.py` — **recommandé pour analyser une API** : sortie plus propre, multi-onglets plus fiable, métadonnées réseau enrichies et snapshots à l'arrêt.

## Mode analyse API

```bash
pip install websocket-client psutil
python api_network_logger.py
```

Le mode API réutilise le même `capture_profile` et les mêmes fonctions proxy que le logger principal.

### Ce que le mode API capture

| Catégorie | Détails |
|---|---|
| **HTTP(S)** | URL, méthode, headers standards, headers CDP `ExtraInfo`, initiateur et contexte onglet/target |
| **Body des requêtes** | `postData` + fallback `Network.getRequestPostData` si Chrome ne l'inclut pas dans l'événement |
| **Réponses** | Status, headers, body, protocole/timing/cache/service worker/sécurité exposés par CDP |
| **Échecs** | Erreurs réseau, blocage, annulation et détails CORS |
| **Redirections** | Chaque hop est conservé au lieu d'être écrasé par la requête suivante |
| **Cookies** | Informations envoyées/reçues + snapshot final de tous les cookies du navigateur |
| **Storage** | Snapshot final de `localStorage` et `sessionStorage` pour les pages attachées |
| **WebSocket** | Handshake + frames envoyées/reçues + erreurs de frames |
| **SSE / EventSource** | Messages avec nom d'événement, ID et data |
| **WebTransport** | Création / connexion / fermeture ; CDP n'expose pas ici le contenu des streams/datagrammes |
| **Onglets / workers** | Découverte CDP au niveau navigateur pour les onglets/popups indépendants, puis attachement récursif aux iframes/workers/service workers |
| **Erreurs console** | Exceptions et `warning/error/assert`, séparées des logs réseau |

La vue `api/requests.jsonl` conserve XHR, Fetch, Document, WebSocket, EventSource, Ping/beacon, les méthodes d'écriture ainsi que les preflights CORS. `full/requests.jsonl` garde le flux CDP plus large.

## Améliorations de fiabilité du mode API

- Les `requestId` sont namespacés par session CDP afin d'éviter les collisions entre onglets/workers.
- Les bodies de réponse utilisent des buffers plus larges et le stockage durable CDP quand Chrome le supporte.
- L'interception des réponses est limitée à `Document`, `XHR` et `Fetch` : les images/CSS/fonts ne sont plus mises en pause inutilement.
- Les WebSockets, SSE et requêtes encore ouvertes sont flushés lors de l'arrêt au lieu de disparaître.
- Une erreur de récupération de body est écrite explicitement dans l'entrée au lieu de ressembler à un body vide réussi.
- Les données `requestWillBeSentExtraInfo` / `responseReceivedExtraInfo` sont conservées, notamment les cookies bloqués et l'état de sécurité client.

## Sortie

```text
session_api_YYYYMMDD_HHMMSS/
├── full/
│   ├── requests.jsonl
│   └── summary.txt
├── api/
│   ├── requests.jsonl
│   ├── summary.txt
│   └── webtransport.jsonl        # seulement si utilisé
└── meta/
    ├── cookies_shutdown.json
    ├── storage_shutdown.jsonl
    └── console_errors.jsonl      # seulement si pertinent
```

## Mode général

```bash
python chrome_network_logger.py
```

Le mode historique reste utile lorsque tu veux le réseau **et une chronologie détaillée des interactions utilisateur** : clics, inputs/changes, formulaires, navigation, etc.

## Support proxy

Place un `proxy.txt` à côté des scripts. Formats acceptés notamment :

```text
host:port
host:port:user:pass
user:pass@host:port
http://host:port
https://user:pass@host:port
socks5://host:port
host port user pass
```

Options utiles :

```bash
python api_network_logger.py --proxy random
python api_network_logger.py --proxy 2
python api_network_logger.py --proxy none
python api_network_logger.py --proxy-prompt
python api_network_logger.py --proxy-file other.txt
```

## Périmètre et limites

C'est un logger **applicatif CDP**, pas un sniffer de paquets. Il ne mélange volontairement pas DNS/TCP/TLS/QUIC brut avec les logs API. Le contenu média/DataChannel de WebRTC reste également hors de cette capture.

CDP a aussi ses propres limites : `Network.getRequestPostData` n'inclut pas les octets des fichiers uploadés en multipart, certaines très grosses ressources ou réponses streaming peuvent rester indisponibles, et les événements WebTransport du domaine Network donnent surtout le cycle de vie, pas le contenu des streams/datagrammes.

Pour reconstruire une API, cette vue est souvent plus pratique qu'un PCAP car Chrome fournit le contenu HTTP après déchiffrement HTTPS.

## Sécurité & légal

Les captures peuvent contenir **mots de passe, bearer tokens, clés API, cookies de session et tokens stockés dans localStorage/sessionStorage**. Utilise l'outil uniquement sur des applications/systèmes que tu possèdes ou que tu es autorisé à inspecter. Garde les captures privées et ne les commit jamais dans un repo public.

## Licence

MIT

---

> 🤖 **Transparence :** ce projet est développé par [@Antoninnnnnnnn](https://github.com/Antoninnnnnnnn) avec une forte assistance de pair-programming IA.
