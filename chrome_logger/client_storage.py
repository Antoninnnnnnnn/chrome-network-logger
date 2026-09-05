from __future__ import annotations

import copy
import json
import time
from typing import Any
from urllib.parse import urlsplit

from .constants import PAGE_TYPES
from .models import PendingCommand

CLIENT_STORAGE_DEBOUNCE_SECONDS = 0.5


def storage_origin(url: str | None) -> str | None:
    """Return the origin a page's client storage is keyed by, if it has one."""
    parsed = urlsplit(str(url or ""))
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


class ClientStorageMixin:
    """Capture IndexedDB and Cache Storage contents from Storage-domain events.

    Neither store is reachable once the browser exits, and neither shows up in
    network traffic, so a capture that only watches HTTP misses everything an
    application keeps locally. Chrome reports when a database or cache changes,
    which is used here to re-dump exactly the scope that moved instead of
    polling everything.

    Dumps are bounded: `max_idb_entries` records per object store and
    `max_cache_entries` entries per cache, per dump. Cached response bodies are
    metadata-only — the entries carry their URL, headers, and times.
    """

    def track_client_storage(self, session_id: str, target_info: dict[str, Any]) -> None:
        origin = storage_origin(target_info.get("url"))
        if not origin:
            return
        with self.state_lock:
            known = origin in self._client_storage_origins
            self._client_storage_origins.add(origin)
        if known:
            return
        for method in ("Storage.trackIndexedDBForOrigin", "Storage.trackCacheStorageForOrigin"):
            self.send(
                method,
                {"origin": origin},
                session_id,
                PendingCommand("capability", {"method": method, "sessionId": session_id}, time.monotonic()),
            )
        self.request_client_storage_dump(origin, "indexeddb", reason="targetAttached")
        self.request_client_storage_dump(origin, "cachestorage", reason="targetAttached")

    def request_client_storage_dump(
        self,
        origin: str,
        scope: str,
        *,
        reason: str,
        database: str | None = None,
        store: str | None = None,
        cache: str | None = None,
    ) -> None:
        """Queue a bounded re-dump of the scope Chrome says has changed."""
        if not self.config.capture_client_storage or not self.is_live():
            return
        with self.state_lock:
            self._client_storage_requests[(origin, scope, database, store, cache)] = reason
            if not self._client_storage_earliest:
                self._client_storage_earliest = time.monotonic() + CLIENT_STORAGE_DEBOUNCE_SECONDS

    def _client_storage_session(self, origin: str) -> str | None:
        """Pick an attached page session that shares the origin.

        The IndexedDB and CacheStorage domains only exist on page targets, so a
        dump has to travel through one of them. Any live page of the same origin
        will do, which keeps dumps working after the page that first showed the
        origin has gone.
        """
        with self.state_lock:
            for session_id, info in self.targets.items():
                if info.get("type") not in PAGE_TYPES:
                    continue
                if session_id not in self.enabled_sessions:
                    continue
                if storage_origin(info.get("url")) == origin:
                    return session_id
        return None

    def _process_client_storage(self) -> None:
        if not self.config.capture_client_storage or self._quiescing:
            return
        now = time.monotonic()
        with self.state_lock:
            if not self._client_storage_requests or not self._client_storage_earliest:
                return
            if now < self._client_storage_earliest:
                return
            requests = dict(self._client_storage_requests)
            self._client_storage_requests.clear()
            self._client_storage_earliest = 0.0
        for (origin, scope, database, store, cache), reason in requests.items():
            session_id = self._client_storage_session(origin)
            if not session_id:
                self.stats["clientStorageSkipped"] += 1
                continue
            if scope == "indexeddb":
                if database and store:
                    self._send_idb_data(session_id, origin, database, store, reason)
                elif database:
                    self._send_idb_database(session_id, origin, database, reason)
                else:
                    self._send_idb_names(session_id, origin, reason)
            elif cache:
                self._send_cache_entries(session_id, origin, cache, reason)
            else:
                self._send_cache_names(session_id, origin, reason)

    # ----------------------------------------------------------------- senders

    def _idb_scope(self, origin: str, use_storage_key: bool) -> dict[str, Any]:
        # securityOrigin is deprecated but still accepted; storageKey is the
        # replacement and the only form some builds answer.
        return {"storageKey": origin + "/"} if use_storage_key else {"securityOrigin": origin}

    def _send_idb_names(self, session_id: str, origin: str, reason: str, use_storage_key: bool = False) -> None:
        self.send(
            "IndexedDB.requestDatabaseNames",
            self._idb_scope(origin, use_storage_key),
            session_id,
            PendingCommand(
                "idb_names",
                {"origin": origin, "reason": reason, "storageKey": use_storage_key, "sessionId": session_id},
                time.monotonic(),
            ),
        )

    def _send_idb_database(
        self, session_id: str, origin: str, database: str, reason: str, use_storage_key: bool = False
    ) -> None:
        params = self._idb_scope(origin, use_storage_key)
        params["databaseName"] = database
        self.send(
            "IndexedDB.requestDatabase",
            params,
            session_id,
            PendingCommand(
                "idb_database",
                {"origin": origin, "database": database, "reason": reason, "storageKey": use_storage_key},
                time.monotonic(),
            ),
        )

    def _send_idb_data(
        self,
        session_id: str,
        origin: str,
        database: str,
        store: str,
        reason: str,
        use_storage_key: bool = False,
    ) -> None:
        # IndexedDB.requestData answers with RemoteObject references whose
        # contents are never inlined, so the records would come back as
        # {"type": "object", "description": "Object"} and carry no data. Reading
        # the store from the page returns the structured-clone values instead.
        params: dict[str, Any] = {
            "expression": self._idb_dump_script(database, store, self.config.max_idb_entries),
            "returnByValue": True,
            "awaitPromise": True,
        }
        context_id = self._isolated_context(session_id)
        if context_id is not None:
            params["contextId"] = context_id
        self.send(
            "Runtime.evaluate",
            params,
            session_id,
            PendingCommand(
                "idb_data",
                {
                    "origin": origin,
                    "database": database,
                    "store": store,
                    "reason": reason,
                    "storageKey": use_storage_key,
                },
                time.monotonic(),
            ),
        )

    def _isolated_context(self, session_id: str) -> int | None:
        """Prefer the isolated world so the page cannot observe the read."""
        with self.state_lock:
            contexts = sorted(self.interaction_contexts.get(session_id, set()))
        return contexts[-1] if contexts else None

    @staticmethod
    def _idb_dump_script(database: str, store: str, limit: int) -> str:
        template = r"""
(async () => {
  const DATABASE = __DATABASE__;
  const STORE = __STORE__;
  const LIMIT = __LIMIT__;
  const wrap = (request) => new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  const describe = (value, depth) => {
    if (value === null || typeof value !== 'object') return value;
    if (depth > 6) return {__type: 'depthLimit'};
    if (value instanceof Blob) return {__type: 'Blob', size: value.size, mime: value.type};
    if (value instanceof ArrayBuffer) return {__type: 'ArrayBuffer', byteLength: value.byteLength};
    if (ArrayBuffer.isView(value)) return {__type: value.constructor.name, byteLength: value.byteLength};
    if (value instanceof Date) return {__type: 'Date', iso: value.toISOString()};
    if (value instanceof Map) return {__type: 'Map', entries: [...value].slice(0, LIMIT).map(([k, v]) => [describe(k, depth + 1), describe(v, depth + 1)])};
    if (value instanceof Set) return {__type: 'Set', values: [...value].slice(0, LIMIT).map((v) => describe(v, depth + 1))};
    if (Array.isArray(value)) return value.slice(0, LIMIT).map((item) => describe(item, depth + 1));
    const output = {};
    for (const key of Object.keys(value).slice(0, 500)) {
      try { output[key] = describe(value[key], depth + 1); } catch (error) { output[key] = {__type: 'unreadable', error: String(error)}; }
    }
    return output;
  };
  let db;
  try {
    db = await new Promise((resolve, reject) => {
      const request = indexedDB.open(DATABASE);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
      request.onblocked = () => reject(new Error('open blocked'));
    });
  } catch (error) {
    return {ok: false, error: String(error)};
  }
  try {
    if (!db.objectStoreNames.contains(STORE)) return {ok: false, error: 'missing object store'};
    const objectStore = db.transaction(STORE, 'readonly').objectStore(STORE);
    const keys = await wrap(objectStore.getAllKeys(undefined, LIMIT + 1));
    const values = await wrap(objectStore.getAll(undefined, LIMIT + 1));
    const truncated = keys.length > LIMIT;
    const records = [];
    for (let i = 0; i < Math.min(keys.length, LIMIT); i++) {
      records.push({key: describe(keys[i], 0), value: describe(values[i], 0)});
    }
    return {ok: true, truncated, records, keyPath: describe(objectStore.keyPath, 0), version: db.version};
  } catch (error) {
    return {ok: false, error: String(error)};
  } finally {
    try { db.close(); } catch (_) {}
  }
})()
"""
        return (
            template.replace("__DATABASE__", json.dumps(database))
            .replace("__STORE__", json.dumps(store))
            .replace("__LIMIT__", str(int(limit)))
        )

    def _send_cache_names(self, session_id: str, origin: str, reason: str) -> None:
        self.send(
            "CacheStorage.requestCacheNames",
            {"securityOrigin": origin},
            session_id,
            PendingCommand(
                "cache_names",
                {"origin": origin, "reason": reason, "sessionId": session_id},
                time.monotonic(),
            ),
        )

    def _send_cache_entries(self, session_id: str, origin: str, cache_id: str, reason: str) -> None:
        self.send(
            "CacheStorage.requestEntries",
            {"cacheId": cache_id, "skipCount": 0, "pageSize": self.config.max_cache_entries},
            session_id,
            PendingCommand(
                "cache_entries",
                {"origin": origin, "cacheId": cache_id, "reason": reason},
                time.monotonic(),
            ),
        )

    # ---------------------------------------------------------------- handlers

    def _client_storage_error(self, kind: str, data: dict[str, Any], error: Any) -> bool:
        """Log a failed dump; retry IndexedDB once with the storageKey form."""
        if kind.startswith("idb_") and not data.get("storageKey"):
            origin = str(data.get("origin") or "")
            session_id = self._client_storage_session(origin)
            reason = str(data.get("reason") or "retry")
            if not session_id:
                self.stats["clientStorageSkipped"] += 1
                return True
            if kind == "idb_names":
                self._send_idb_names(session_id, origin, reason, use_storage_key=True)
            elif kind == "idb_database":
                self._send_idb_database(session_id, origin, str(data.get("database")), reason, use_storage_key=True)
            else:
                self._send_idb_data(
                    session_id,
                    origin,
                    str(data.get("database")),
                    str(data.get("store")),
                    reason,
                    use_storage_key=True,
                )
            return True
        self.stats["clientStorageErrors"] += 1
        self.store.write_jsonl(
            "browser/protocol_errors.jsonl",
            {
                "time": self.timestamps.normalize(),
                "method": kind,
                "phase": "clientStorage",
                "scope": {key: value for key, value in data.items() if key != "reason"},
                "error": error,
            },
            redact=True,
        )
        return False

    def _handle_client_storage_response(
        self, kind: str, data: dict[str, Any], error: Any, result: dict[str, Any]
    ) -> None:
        if error:
            self._client_storage_error(kind, data, error)
            return
        origin = str(data.get("origin") or "")
        reason = str(data.get("reason") or "unknown")
        if kind == "idb_names":
            names = [str(name) for name in result.get("databaseNames") or []]
            self.store.write_jsonl(
                "storage/indexeddb.jsonl",
                {
                    "time": self.timestamps.normalize(),
                    "kind": "databases",
                    "origin": origin,
                    "reason": reason,
                    "databases": names,
                },
                redact=True,
            )
            for name in names:
                self.request_client_storage_dump(origin, "indexeddb", reason=reason, database=name)
            return
        if kind == "idb_database":
            database = copy.deepcopy(result.get("databaseWithObjectStores") or {})
            self.store.write_jsonl(
                "storage/indexeddb.jsonl",
                {
                    "time": self.timestamps.normalize(),
                    "kind": "schema",
                    "origin": origin,
                    "reason": reason,
                    "database": database,
                },
                redact=True,
            )
            for store in database.get("objectStores") or []:
                name = store.get("name")
                if name:
                    self.request_client_storage_dump(
                        origin,
                        "indexeddb",
                        reason=reason,
                        database=str(data.get("database") or database.get("name") or ""),
                        store=str(name),
                    )
            return
        if kind == "idb_data":
            dump = (result.get("result") or {}).get("value")
            exception = result.get("exceptionDetails")
            if exception or not isinstance(dump, dict) or not dump.get("ok"):
                detail = exception or {"message": (dump or {}).get("error") if isinstance(dump, dict) else "no result"}
                self._client_storage_error("idb_data", {**data, "storageKey": True}, detail)
                return
            entries = dump.get("records") or []
            self.stats["idbEntries"] += len(entries)
            self.store.write_jsonl(
                "storage/indexeddb.jsonl",
                {
                    "time": self.timestamps.normalize(),
                    "kind": "entries",
                    "origin": origin,
                    "reason": reason,
                    "database": data.get("database"),
                    "objectStore": data.get("store"),
                    "keyPath": dump.get("keyPath"),
                    "databaseVersion": dump.get("version"),
                    "entryCount": len(entries),
                    "hasMore": bool(dump.get("truncated")),
                    "limit": self.config.max_idb_entries,
                    "entries": entries,
                },
                redact=True,
            )
            return
        if kind == "cache_names":
            caches = copy.deepcopy(result.get("caches") or [])
            self.store.write_jsonl(
                "storage/cache_storage.jsonl",
                {
                    "time": self.timestamps.normalize(),
                    "kind": "caches",
                    "origin": origin,
                    "reason": reason,
                    "caches": caches,
                },
                redact=True,
            )
            for cache in caches:
                cache_id = cache.get("cacheId")
                if cache_id:
                    self.request_client_storage_dump(origin, "cachestorage", reason=reason, cache=str(cache_id))
            return
        if kind == "cache_entries":
            entries = copy.deepcopy(result.get("cacheDataEntries") or [])
            self.stats["cacheEntries"] += len(entries)
            self.store.write_jsonl(
                "storage/cache_storage.jsonl",
                {
                    "time": self.timestamps.normalize(),
                    "kind": "entries",
                    "origin": origin,
                    "reason": reason,
                    "cacheId": data.get("cacheId"),
                    "entryCount": len(entries),
                    "returnCount": result.get("returnCount"),
                    "limit": self.config.max_cache_entries,
                    "entries": entries,
                },
                redact=True,
            )

    def _storage_domain_event(self, session_id: str | None, method: str, params: dict[str, Any]) -> None:
        origin = str(params.get("origin") or "").rstrip("/")
        if not origin:
            storage_key = str(params.get("storageKey") or "")
            origin = storage_key.rstrip("/")
        if not origin:
            return
        if method == "Storage.indexedDBListUpdated":
            self.request_client_storage_dump(origin, "indexeddb", reason="indexedDBListUpdated")
        elif method == "Storage.indexedDBContentUpdated":
            database = params.get("databaseName")
            store = params.get("objectStoreName")
            self.request_client_storage_dump(
                origin,
                "indexeddb",
                reason="indexedDBContentUpdated",
                database=str(database) if database else None,
                store=str(store) if store else None,
            )
        elif method == "Storage.cacheStorageListUpdated":
            self.request_client_storage_dump(origin, "cachestorage", reason="cacheStorageListUpdated")
        elif method == "Storage.cacheStorageContentUpdated":
            # A cache id is required to read entries, so refresh the list.
            self.request_client_storage_dump(origin, "cachestorage", reason="cacheStorageContentUpdated")
