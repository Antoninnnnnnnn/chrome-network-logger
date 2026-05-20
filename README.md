# Chrome Network Logger

[🇫🇷 Version française](#-version-française)

A standalone, **dependency-light** Python script that captures **everything** happening inside a Chrome browser via the Chrome DevTools Protocol (CDP) — no Selenium, no Playwright. It uses a dedicated, isolated Chrome profile so your main browser is never touched.

## ✨ What it captures

| Category | Details |
|---|---|
| **HTTP requests** | URL, method, headers, `postData` (POST/PUT/form bodies) |
| **HTTP responses** | Status, headers, **full body** (JSON, HTML, images, binary…) |
| **Cookies** | Real `Set-Cookie` headers via `ExtraInfo`, outgoing `Cookie` headers, full cookie dump after login |
| **WebSocket** | Frames sent **and** received, opcode/binary flag, handshake request/response (cookies on upgrade), frame errors |
| **Server-Sent Events** | All SSE messages with event name & data |
| **User interactions** | Every `click`, `change` (checkboxes, radios, selects, dates), `input` (typed text including emails & passwords), special keys (`Enter`, `Tab`, `Esc`, Ctrl/Meta combos), `paste` & `copy` (clipboard content), `focus`, SPA navigation (`popstate`, `hashchange`, `beforeunload`) |
| **Form submits** | Full `FormData` serialized (login forms, etc.) |
| **JS errors & console** | All `console.log/warn/error`, uncaught exceptions |
| **Multi-tab / workers** | Auto-attach to new tabs, iframes, popups (recursive), workers and service workers |
| **Navigation events** | `Page.frameNavigated` for accurate timeline |

## 🥷 Stealth

- Dedicated Chrome profile (no interference with your main browser)
- User interactions go through a CDP **binding** with a random name (re-generated each run), not `console.log` → not detectable by classic anti-bot scripts that monitor the console
- The binding name is removed from `window` immediately after install
- `FORM_INTERCEPT_JS` also uses the binding (no `console.log` markers)

## 📦 Install

```bash
pip install websocket-client psutil
```

Chrome must be installed at one of the default Windows paths (the script auto-detects).

## 🚀 Usage

```bash
python chrome_network_logger.py
```

**First run**: the script creates an empty profile under `./capture_profile/`. Chrome opens, you log in to your target site, configure cookies, etc. Press `Ctrl+C` to save.

**Subsequent runs**: your profile + cookies/sessions are reused as-is.

You'll be prompted for a session subfolder name (useful to group sessions per site).

## 📁 Output layout

```
session_YYYYMMDD_HHMMSS/
├── README.txt                     # Auto-generated description
├── full/
│   ├── requests.jsonl             # EVERYTHING (CSS, fonts, images, XHR, WS…)
│   └── summary.txt                # Human-readable summary
├── filtered/
│   ├── requests.jsonl             # Only XHR/Fetch/Document/WebSocket/EventSource
│   └── summary.txt
├── events/
│   ├── full/events.jsonl          # All user interactions with FULL detail
│   │                              # (cssPath, xpath, attrs, outerHTML, value…)
│   └── summary/
│       ├── events.jsonl           # Slim version (event/ts/url/outerHTML)
│       └── events.html            # Browsable HTML view
├── form_submit_captured.json      # All submitted forms (FormData incl. password)
└── cookies_<label>.json           # Cookie dumps (auto post-login + manual)
```

## ⚠️ Security & Legal Notice

This tool captures **plaintext passwords, tokens, session cookies, and any text you type or paste**. It is intended for:

- Debugging your own web applications
- Reverse-engineering APIs you have permission to access
- Security research on your own systems

**Do not** use it on services you don't own or don't have explicit permission to inspect. Store the `session_*` folders on encrypted storage and never commit them to a public repo.

## 🛠️ How it works

1. Launches Chrome with `--remote-debugging-port=<free>` pointing at the dedicated profile
2. Connects to CDP over WebSocket
3. Enables: `Network`, `Page`, `Runtime`, `Fetch` (intercepts all URLs to grab `postData` on form navigations), `Target` (auto-attach to new tabs/workers)
4. Registers a `Runtime.addBinding` and injects JS to forward user interactions via that binding
5. Listens to all CDP events, writes one entry per request to JSONL

## 📜 License

MIT

---

## 🇫🇷 Version française

Script Python autonome et **léger en dépendances** qui capture **tout** ce qui se passe dans Chrome via le Chrome DevTools Protocol (CDP) — pas de Selenium, pas de Playwright. Il utilise un profil Chrome dédié et isolé, ton navigateur principal n'est jamais touché.

### ✨ Ce qui est capturé

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

### 🥷 Stealth

- Profil Chrome dédié (aucune interférence avec ton navigateur principal)
- Les interactions utilisateur passent par un **binding** CDP avec un nom aléatoire (régénéré à chaque run), pas par `console.log` → non détectable par les scripts anti-bot classiques qui surveillent la console
- Le nom du binding est supprimé de `window` immédiatement après installation
- `FORM_INTERCEPT_JS` utilise aussi le binding (pas de marqueurs `console.log`)

### 📦 Installation

```bash
pip install websocket-client psutil
```

Chrome doit être installé à l'un des chemins Windows par défaut (auto-détection).

### 🚀 Utilisation

```bash
python chrome_network_logger.py
```

**Première utilisation** : le script crée un profil vide dans `./capture_profile/`. Chrome s'ouvre, tu te logges sur le site cible, configures les cookies, etc. `Ctrl+C` pour sauvegarder.

**Lancements suivants** : ton profil + cookies/sessions sont réutilisés tels quels.

Un sous-dossier de session te sera demandé (utile pour grouper par site).

### 📁 Structure de sortie

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

### ⚠️ Sécurité & légal

Cet outil capture en **clair** les mots de passe, tokens, cookies de session, et tout ce que tu tapes ou colles. Il est destiné à :

- Debug de tes propres applis web
- Reverse-engineering d'APIs que tu as le droit d'inspecter
- Recherche en sécurité sur tes propres systèmes

**N'utilise pas** cet outil sur des services qui ne t'appartiennent pas ou que tu n'as pas le droit d'inspecter. Stocke les dossiers `session_*` sur du stockage chiffré et ne les commit jamais dans un repo public.

### 🛠️ Fonctionnement

1. Lance Chrome avec `--remote-debugging-port=<libre>` pointant sur le profil dédié
2. Se connecte au CDP via WebSocket
3. Active : `Network`, `Page`, `Runtime`, `Fetch` (intercepte toutes les URLs pour le `postData` des navigations form), `Target` (auto-attach aux nouveaux onglets/workers)
4. Enregistre un `Runtime.addBinding` et injecte du JS qui forwarde les interactions via ce binding
5. Écoute tous les événements CDP, écrit une entrée par requête en JSONL

### 📜 Licence

MIT
