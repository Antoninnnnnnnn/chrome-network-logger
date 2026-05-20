# Chrome Network Logger

[🇬🇧 English version](README.md)

Script Python autonome et **léger en dépendances** qui capture **tout** ce qui se passe dans Chrome via le Chrome DevTools Protocol (CDP) — pas de Selenium, pas de Playwright. Il utilise un profil Chrome dédié et isolé, ton navigateur principal n'est jamais touché.

## ✨ Ce qui est capturé

| Catégorie | Détails |
|---|---|
| **Requêtes HTTP** | URL, méthode, headers, `postData` (corps POST/PUT/formulaire) |
| **Réponses HTTP** | Status, headers, **body complet** (JSON, HTML, images, binaire…) |
| **Cookies** | Vrais headers `Set-Cookie` via `ExtraInfo`, headers `Cookie` sortants, dump complet post-login |
| **WebSocket** | Frames envoyées **et** reçues, opcode/flag binaire, handshake request/response (cookies de l'upgrade), erreurs de frame |
| **Server-Sent Events** | Tous les messages SSE avec event name + data |
| **Interactions utilisateur** | Chaque `click`, `change` (checkboxes, radios, selects, dates), `input` (texte tapé y compris emails & mots de passe), touches spéciales (`Enter`, `Tab`, `Esc`, raccourcis Ctrl/Meta), `paste` & `copy` (contenu presse-papier), `focus`, navigation SPA (`popstate`, `hashchange`, `beforeunload`) |
| **Form submit** | `FormData` complet sérialisé (formulaires de login, etc.) |
| **Erreurs JS & console** | Tous `console.log/warn/error`, exceptions non capturées |
| **Multi-onglets / workers** | Auto-attach aux nouveaux onglets, iframes, popups (récursif), workers et service workers |
| **Événements de navigation** | `Page.frameNavigated` pour une chronologie précise |

## 🥷 Stealth

- Profil Chrome dédié (aucune interférence avec ton navigateur principal)
- Les interactions utilisateur passent par un **binding** CDP avec un nom aléatoire (régénéré à chaque run), pas par `console.log` → non détectable par les scripts anti-bot classiques qui surveillent la console
- Le nom du binding est supprimé de `window` immédiatement après installation
- `FORM_INTERCEPT_JS` utilise aussi le binding (pas de marqueurs `console.log`)

## 📦 Installation

```bash
pip install websocket-client psutil
```

Chrome doit être installé à l'un des chemins Windows par défaut (auto-détection).

## 🚀 Utilisation

```bash
python chrome_network_logger.py
```

**Première utilisation** : le script crée un profil vide dans `./capture_profile/`. Chrome s'ouvre, tu te logges sur le site cible, configures les cookies, etc. `Ctrl+C` pour sauvegarder.

**Lancements suivants** : ton profil + cookies/sessions sont réutilisés tels quels.

Un sous-dossier de session te sera demandé (utile pour grouper par site).
## 🌐 Support proxy

Dépose un fichier `proxy.txt` à côté du script. La première ligne non vide est parsée automatiquement. Tous ces formats fonctionnent :

```
host:port
host:port:user:pass
user:pass@host:port
http://host:port
https://user:pass@host:port
socks5://host:port
socks4://user:pass@host:port
```

Si des identifiants sont présents, une petite extension Chrome non packée est générée à la volée pour les fournir via `webRequest.onAuthRequired` (pas de pop-up d'auth).

Pas de `proxy.txt` ? Chrome se lance en connexion directe.
## 📁 Structure de sortie

```
session_YYYYMMDD_HHMMSS/
├── README.txt                     # Description auto-générée
├── full/
│   ├── requests.jsonl             # TOUT (CSS, fonts, images, XHR, WS…)
│   └── summary.txt                # Résumé lisible
├── filtered/
│   ├── requests.jsonl             # Uniquement XHR/Fetch/Document/WebSocket/EventSource
│   └── summary.txt
├── events/
│   ├── full/events.jsonl          # Toutes les interactions avec détail COMPLET
│   │                              # (cssPath, xpath, attrs, outerHTML, value…)
│   └── summary/
│       ├── events.jsonl           # Version allégée
│       └── events.html            # Vue HTML visualisable
├── form_submit_captured.json      # Formulaires soumis (FormData inc. mdp)
└── cookies_<label>.json           # Dumps de cookies (auto post-login + manuel)
```

## ⚠️ Sécurité & légal

Cet outil capture en **clair** les mots de passe, tokens, cookies de session, et tout ce que tu tapes ou colles. Il est destiné à :

- Debug de tes propres applis web
- Reverse-engineering d'APIs que tu as le droit d'inspecter
- Recherche en sécurité sur tes propres systèmes

**N'utilise pas** cet outil sur des services qui ne t'appartiennent pas ou que tu n'as pas le droit d'inspecter. Stocke les dossiers `session_*` sur du stockage chiffré et ne les commit jamais dans un repo public.

## 🛠️ Fonctionnement

1. Lance Chrome avec `--remote-debugging-port=<libre>` pointant sur le profil dédié
2. Se connecte au CDP via WebSocket
3. Active : `Network`, `Page`, `Runtime`, `Fetch` (intercepte toutes les URLs pour le `postData` des navigations form), `Target` (auto-attach aux nouveaux onglets/workers)
4. Enregistre un `Runtime.addBinding` et injecte du JS qui forwarde les interactions via ce binding
5. Écoute tous les événements CDP, écrit une entrée par requête en JSONL

## 📜 Licence

MIT

---

> 🤖 **Transparence totale :** Ce projet a été fait par [@Antoninnnnnnnn](https://github.com/Antoninnnnnnnn) qui avoue volontiers ne comprendre aucune ligne de ce code. Le vrai MVP ici, c'est le pair programming avec l'IA. Il s'avère qu'on n'a pas besoin de savoir coder pour livrer du code. Bienvenue en 2026.
