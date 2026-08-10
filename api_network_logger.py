"""API-focused companion for chrome_network_logger.py.

Uses browser-level CDP attachment so independent tabs/popups are captured too.
Keeps only application-layer data useful to reconstruct/debug a web API.
"""
from __future__ import annotations

import argparse, json, os, signal, subprocess, threading, time, urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any

import websocket

from chrome_network_logger import (
    DEDICATED_PROFILE_DIR, PROXY_FILE, _active_relays, _start_proxy_keyboard_thread,
    build_proxy_chrome_args, cleanup_locks, find_chrome, find_free_port,
    kill_orphan_chromes_using_profile, load_all_proxies, safe_append, select_proxy,
)

TARGET_TYPES = {"page", "iframe", "webview", "worker", "service_worker", "shared_worker"}
PAGE_TYPES = {"page", "iframe", "webview"}
API_TYPES = {"XHR", "Fetch", "Document", "WebSocket", "EventSource", "Ping"}
BODY_TYPES = ("Document", "XHR", "Fetch")
MAX_TOTAL = 256 * 1024 * 1024
MAX_RESOURCE = 128 * 1024 * 1024
MAX_POST = 16 * 1024 * 1024


def setup_dirs(parent: Path):
    base = parent / ("session_api_" + datetime.now().strftime("%Y%m%d_%H%M%S"))
    full, api, meta = base / "full", base / "api", base / "meta"
    for p in (full, api, meta): p.mkdir(parents=True, exist_ok=True)
    return base, full, api, meta


def prompt_parent() -> Path:
    raw = input("Sous-dossier de capture (vide = courant) : ").strip()
    if not raw: return Path.cwd()
    bad = '<>:"/\\|?*'
    name = "".join("_" if c in bad else c for c in raw).rstrip(". ") or "capture"
    p = Path.cwd() / name; p.mkdir(parents=True, exist_ok=True); return p


class APICapture:
    def __init__(self, full: Path, api: Path, meta: Path, port: int):
        self.full, self.api, self.meta, self.port = full, api, meta, port
        self.ws = None; self.running = True; self.msg_id = 0
        self.send_lock = threading.Lock(); self.lock = threading.RLock()
        self.requests: dict[str, dict[str, Any]] = {}
        self.extra: dict[str, dict[str, Any]] = {}
        self.targets: dict[str, dict[str, Any]] = {}
        self.enabled: set[str] = set(); self.attached_targets: set[str] = set()
        self.pending_body: dict[int, str] = {}; self.pending_fetch: dict[int, tuple[str,str,str|None]] = {}
        self.pending_post: dict[int, str] = {}; self.pending_cookie: dict[int, str] = {}
        self.pending_storage: dict[int, tuple[str,dict[str,Any]]] = {}; self.fetch_done: set[str] = set()
        self.transports: dict[str, dict[str, Any]] = {}
        self.stats = {"requests":0,"responses":0,"bodies":0,"body_errors":0,"failures":0,"ws_frames":0,"sse":0,"flushed":0}

    def key(self, sid, rid): return f"{sid or 'root'}::{rid}"
    def next_id(self):
        with self.send_lock:
            self.msg_id += 1; return self.msg_id
    def send(self, method, params=None, sid=None):
        mid = self.next_id(); msg = {"id":mid,"method":method,"params":params or {}}
        if sid: msg["sessionId"] = sid
        if self.ws:
            try:
                with self.send_lock: self.ws.send(json.dumps(msg))
            except Exception as e:
                if self.running: print(f"[!] {method}: {e}")
        return mid
    def target(self, sid):
        t = self.targets.get(sid or "")
        return {k:t.get(k) for k in ("targetId","type","url","title") if t and t.get(k) is not None} if t else None

    def connect(self):
        try:
            version = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{self.port}/json/version", timeout=3).read())
            initial = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{self.port}/json", timeout=3).read())
            self.ws = websocket.create_connection(version["webSocketDebuggerUrl"], timeout=None)
        except Exception as e:
            print(f"[!] Browser CDP: {e}"); return False
        filt = [{"type":t} for t in sorted(TARGET_TYPES)]
        self.send("Target.setDiscoverTargets", {"discover":True,"filter":filt})
        self.send("Target.setAutoAttach", {"autoAttach":True,"waitForDebuggerOnStart":False,"flatten":True,"filter":filt})
        for t in initial:
            if t.get("type") in TARGET_TYPES and t.get("id"):
                self.send("Target.attachToTarget", {"targetId":t["id"],"flatten":True})
        return True

    def enable_session(self, sid, info):
        if sid in self.enabled: return
        self.enabled.add(sid); self.targets[sid] = info
        self.send("Network.enable", {"maxTotalBufferSize":MAX_TOTAL,"maxResourceBufferSize":MAX_RESOURCE,"maxPostDataSize":MAX_POST}, sid)
        self.send("Network.configureDurableMessages", {"maxTotalBufferSize":MAX_TOTAL,"maxResourceBufferSize":MAX_RESOURCE}, sid)
        self.send("Runtime.enable", sid=sid)
        filt = [{"type":t} for t in sorted(TARGET_TYPES)]
        self.send("Target.setAutoAttach", {"autoAttach":True,"waitForDebuggerOnStart":False,"flatten":True,"filter":filt}, sid)
        if info.get("type") in PAGE_TYPES:
            self.send("Page.enable", sid=sid)
            self.send("Fetch.enable", {"patterns":[{"urlPattern":"*","requestStage":"Response","resourceType":t} for t in BODY_TYPES]}, sid)
        print(f"[TARGET] {info.get('type')} {(info.get('url') or '')[:90]}")

    def is_api(self, e):
        req = e.get("request") or {}; method = str(req.get("method") or "").upper()
        if e.get("type") in API_TYPES or method in {"POST","PUT","PATCH","DELETE","OPTIONS"}: return True
        h = {str(k).lower():str(v).lower() for k,v in (req.get("headers") or {}).items()}
        return "json" in h.get("content-type","") or "graphql" in h.get("content-type","")

    def write(self, e):
        line = json.dumps(e, ensure_ascii=False, default=str) + "\n"
        safe_append(self.full / "requests.jsonl", line)
        if self.is_api(e): safe_append(self.api / "requests.jsonl", line)
    def merge_extra(self, key, e):
        x = self.extra.pop(key, None)
        if x: e["extraInfo"] = x
    def finalize(self, key, reason=None):
        e = self.requests.pop(key, None)
        if not e: return
        self.merge_extra(key, e)
        if reason: e["finalizeReason"] = reason
        self.write(e)

    def command_response(self, msg):
        mid = msg.get("id")
        if mid in self.pending_body:
            key = self.pending_body.pop(mid); e = self.requests.get(key)
            if e:
                if msg.get("error"): e["responseBodyError"] = msg["error"]; self.stats["body_errors"] += 1
                else:
                    r = msg.get("result") or {}; e["responseBody"] = r.get("body"); e["responseBodyBase64"] = bool(r.get("base64Encoded")); self.stats["bodies"] += 1
                self.finalize(key)
            return True
        if mid in self.pending_fetch:
            key, fid, sid = self.pending_fetch.pop(mid); e = self.requests.get(key)
            if e:
                if msg.get("error"): e["responseBodyError"] = msg["error"]; self.stats["body_errors"] += 1
                else:
                    r = msg.get("result") or {}; e["responseBody"] = r.get("body"); e["responseBodyBase64"] = bool(r.get("base64Encoded")); self.fetch_done.add(key); self.stats["bodies"] += 1
            self.send("Fetch.continueResponse", {"requestId":fid}, sid); return True
        if mid in self.pending_post:
            key = self.pending_post.pop(mid); e = self.requests.get(key)
            if e:
                if msg.get("error"): e["requestPostDataError"] = msg["error"]
                else:
                    r = msg.get("result") or {}; e.setdefault("request",{})["postData"] = r.get("postData"); e["request"]["postDataBase64"] = bool(r.get("base64Encoded"))
            return True
        if mid in self.pending_cookie:
            label = self.pending_cookie.pop(mid)
            if not msg.get("error"):
                (self.meta / f"cookies_{label}.json").write_text(json.dumps((msg.get("result") or {}).get("cookies",[]), indent=2, ensure_ascii=False), encoding="utf-8")
            return True
        if mid in self.pending_storage:
            label, target = self.pending_storage.pop(mid); out = {"label":label,"target":target}
            if msg.get("error"): out["error"] = msg["error"]
            else:
                raw = (((msg.get("result") or {}).get("result") or {}).get("value"))
                try: out["storage"] = json.loads(raw) if isinstance(raw,str) else raw
                except Exception: out["raw"] = raw
            safe_append(self.meta / f"storage_{label}.jsonl", json.dumps(out, ensure_ascii=False, default=str)+"\n"); return True
        return False

    def handle(self, msg):
        if self.command_response(msg): return
        m, p, sid = msg.get("method"), msg.get("params") or {}, msg.get("sessionId")
        if m == "Target.attachedToTarget":
            ns, info = p.get("sessionId"), p.get("targetInfo") or {}; tid = info.get("targetId")
            if tid: self.attached_targets.add(tid)
            if ns and info.get("type") in TARGET_TYPES: self.enable_session(ns, info)
            return
        if m == "Target.targetCreated":
            info = p.get("targetInfo") or {}; tid = info.get("targetId")
            if tid and info.get("type") in TARGET_TYPES and tid not in self.attached_targets:
                self.send("Target.attachToTarget", {"targetId":tid,"flatten":True})
            return
        if m == "Target.detachedFromTarget":
            ds = p.get("sessionId"); self.enabled.discard(ds); self.targets.pop(ds, None); return
        if m == "Fetch.requestPaused":
            fid, nid = p.get("requestId"), p.get("networkId")
            if p.get("responseStatusCode") is not None and fid and nid:
                key = self.key(sid,nid); mid = self.send("Fetch.getResponseBody", {"requestId":fid}, sid); self.pending_fetch[mid]=(key,fid,sid)
            elif fid: self.send("Fetch.continueRequest", {"requestId":fid}, sid)
            return
        if m == "Network.requestWillBeSent":
            rid = p.get("requestId")
            if not rid: return
            key, req, redir = self.key(sid,rid), dict(p.get("request") or {}), p.get("redirectResponse")
            if redir is not None and key in self.requests:
                old=self.requests[key]; old["response"]=dict(redir); old["isRedirect"]=True; old["redirectTo"]=req.get("url"); old["responseBodyUnavailableReason"]="redirect hop has no loadingFinished"; self.finalize(key,"redirect")
            self.requests[key] = {"requestId":rid,"sessionId":sid,"target":self.target(sid),"timestamp":p.get("timestamp"),"wallTime":p.get("wallTime"),"loaderId":p.get("loaderId"),"type":p.get("type","Other"),"request":req,"initiator":p.get("initiator"),"documentURL":p.get("documentURL"),"frameId":p.get("frameId")}; self.stats["requests"] += 1
            if req.get("hasPostData") and not req.get("postData"):
                mid=self.send("Network.getRequestPostData", {"requestId":rid}, sid); self.pending_post[mid]=key
            return
        if m == "Network.requestWillBeSentExtraInfo":
            rid=p.get("requestId")
            if rid: self.extra.setdefault(self.key(sid,rid),{})["request"]={"headers":p.get("headers") or {},"associatedCookies":p.get("associatedCookies") or [],"connectTiming":p.get("connectTiming"),"clientSecurityState":p.get("clientSecurityState"),"siteHasCookieInOtherPartition":p.get("siteHasCookieInOtherPartition")}
            return
        if m == "Network.responseReceived":
            rid=p.get("requestId"); key=self.key(sid,rid) if rid else None; e=self.requests.get(key) if key else None
            if e: e["response"]=p.get("response") or {}; e["type"]=p.get("type",e.get("type")); e["hasExtraInfo"]=p.get("hasExtraInfo"); self.stats["responses"] += 1
            return
        if m == "Network.responseReceivedExtraInfo":
            rid=p.get("requestId")
            if rid: self.extra.setdefault(self.key(sid,rid),{})["response"]={"statusCode":p.get("statusCode"),"headers":p.get("headers") or {},"blockedCookies":p.get("blockedCookies") or [],"resourceIPAddressSpace":p.get("resourceIPAddressSpace"),"cookiePartitionKey":p.get("cookiePartitionKey"),"cookiePartitionKeyOpaque":p.get("cookiePartitionKeyOpaque")}
            return
        if m == "Network.requestServedFromCache":
            rid=p.get("requestId"); key=self.key(sid,rid) if rid else None
            if key in self.requests: self.requests[key]["servedFromCache"] = True
            return
        if m == "Network.loadingFinished":
            rid=p.get("requestId"); key=self.key(sid,rid) if rid else None; e=self.requests.get(key) if key else None
            if not e: return
            e["encodedDataLength"] = p.get("encodedDataLength")
            if key in self.fetch_done: self.fetch_done.discard(key); self.finalize(key); return
            mid=self.send("Network.getResponseBody", {"requestId":rid}, sid); self.pending_body[mid]=key; return
        if m == "Network.loadingFailed":
            rid=p.get("requestId"); key=self.key(sid,rid) if rid else None; e=self.requests.get(key) if key else None
            if e: e["failed"]={k:p.get(k) for k in ("timestamp","type","errorText","canceled","blockedReason","corsErrorStatus")}; self.stats["failures"]+=1; self.finalize(key,"loadingFailed")
            return
        if m == "Network.webSocketCreated":
            rid=p.get("requestId")
            if rid: self.requests[self.key(sid,rid)]={"requestId":rid,"sessionId":sid,"target":self.target(sid),"type":"WebSocket","url":p.get("url"),"initiator":p.get("initiator"),"timestamp":p.get("timestamp"),"wsFrames":[]}; self.stats["requests"]+=1
            return
        if m == "Network.webSocketWillSendHandshakeRequest":
            rid=p.get("requestId"); e=self.requests.get(self.key(sid,rid)) if rid else None
            if e: e["handshakeRequest"] = p.get("request") or {}
            return
        if m == "Network.webSocketHandshakeResponseReceived":
            rid=p.get("requestId"); e=self.requests.get(self.key(sid,rid)) if rid else None
            if e: e["handshakeResponse"] = p.get("response") or {}; self.stats["responses"]+=1
            return
        if m in {"Network.webSocketFrameSent","Network.webSocketFrameReceived"}:
            rid=p.get("requestId"); e=self.requests.get(self.key(sid,rid)) if rid else None
            if e:
                f=p.get("response") or {}; e["wsFrames"].append({"direction":"sent" if m.endswith("Sent") else "received","timestamp":p.get("timestamp"),"opcode":f.get("opcode"),"mask":f.get("mask"),"payloadData":f.get("payloadData")}); self.stats["ws_frames"]+=1
            return
        if m == "Network.webSocketFrameError":
            rid=p.get("requestId"); e=self.requests.get(self.key(sid,rid)) if rid else None
            if e: e.setdefault("wsErrors",[]).append({"timestamp":p.get("timestamp"),"errorMessage":p.get("errorMessage")})
            return
        if m == "Network.webSocketClosed":
            rid=p.get("requestId"); key=self.key(sid,rid) if rid else None
            if key in self.requests: self.requests[key]["closedTimestamp"]=p.get("timestamp"); self.finalize(key,"webSocketClosed")
            return
        if m == "Network.eventSourceMessageReceived":
            rid=p.get("requestId"); e=self.requests.get(self.key(sid,rid)) if rid else None
            if e: e.setdefault("sseMessages",[]).append({"timestamp":p.get("timestamp"),"eventName":p.get("eventName"),"eventId":p.get("eventId"),"data":p.get("data")}); self.stats["sse"]+=1
            return
        if m == "Network.webTransportCreated":
            tid=p.get("transportId")
            if tid: self.transports[self.key(sid,tid)]={"type":"WebTransport","transportId":tid,"sessionId":sid,"target":self.target(sid),"url":p.get("url"),"createdTimestamp":p.get("timestamp"),"initiator":p.get("initiator"),"payloadCapture":"not exposed by CDP Network events"}
            return
        if m == "Network.webTransportConnectionEstablished":
            tid=p.get("transportId"); t=self.transports.get(self.key(sid,tid)) if tid else None
            if t: t["establishedTimestamp"]=p.get("timestamp")
            return
        if m == "Network.webTransportClosed":
            tid=p.get("transportId"); t=self.transports.pop(self.key(sid,tid),None) if tid else None
            if t: t["closedTimestamp"]=p.get("timestamp"); safe_append(self.api/"webtransport.jsonl",json.dumps(t,ensure_ascii=False,default=str)+"\n")
            return
        if m == "Runtime.exceptionThrown":
            x=p.get("exceptionDetails") or {}; safe_append(self.meta/"console_errors.jsonl",json.dumps({"kind":"exception","sessionId":sid,"target":self.target(sid),"timestamp":p.get("timestamp"),"text":x.get("text"),"url":x.get("url"),"exception":(x.get("exception") or {}).get("description")},ensure_ascii=False,default=str)+"\n")
            return
        if m == "Runtime.consoleAPICalled" and p.get("type") in {"error","warning","warn","assert"}:
            args=[a.get("value",a.get("description")) for a in (p.get("args") or [])]; safe_append(self.meta/"console_errors.jsonl",json.dumps({"kind":"console","level":p.get("type"),"sessionId":sid,"target":self.target(sid),"timestamp":p.get("timestamp"),"args":args},ensure_ascii=False,default=str)+"\n")

    def loop(self):
        while self.running and self.ws:
            try:
                raw=self.ws.recv()
                if raw: self.handle(json.loads(raw))
            except websocket.WebSocketConnectionClosedException: break
            except Exception as e:
                if self.running: print(f"[!] CDP loop: {e}")

    def snapshot(self, label="shutdown"):
        mid=self.send("Storage.getCookies"); self.pending_cookie[mid]=label
        expr="""(() => {const d=s=>{const o={};for(let i=0;i<s.length;i++){const k=s.key(i);o[k]=s.getItem(k)}return o};return JSON.stringify({url:location.href,origin:location.origin,localStorage:d(localStorage),sessionStorage:d(sessionStorage)})})()"""
        for sid,info in list(self.targets.items()):
            if info.get("type") in PAGE_TYPES:
                mid=self.send("Runtime.evaluate", {"expression":expr,"returnByValue":True}, sid); self.pending_storage[mid]=(label,self.target(sid) or {})

    def flush(self):
        for key in list(self.requests):
            self.requests[key]["incomplete"]=True; self.requests[key]["incompleteReason"]="shutdown"; self.stats["flushed"]+=1; self.finalize(key,"shutdown")
        for key,t in list(self.transports.items()):
            t["incomplete"]=True; safe_append(self.api/"webtransport.jsonl",json.dumps(t,ensure_ascii=False,default=str)+"\n"); self.transports.pop(key,None)

    def summary(self):
        for name,d in (("full",self.full),("api",self.api)):
            src=d/"requests.jsonl"
            if not src.exists(): continue
            rows=[]
            for line in src.read_text(encoding="utf-8").splitlines():
                try: rows.append(json.loads(line))
                except Exception: pass
            with open(d/"summary.txt","w",encoding="utf-8") as f:
                for e in rows:
                    r=e.get("request") or {}; method=r.get("method","WS" if e.get("type")=="WebSocket" else "?"); url=r.get("url") or e.get("url") or "?"; status=(e.get("response") or {}).get("status","—")
                    f.write(f"[{e.get('type','?'):>11}] {str(method):7} {str(status):>4} {url}\n")

    def stop(self):
        self.running=False
        if self.ws:
            try:self.ws.close()
            except Exception:pass


def main():
    ap=argparse.ArgumentParser(description="Chrome Network Logger — API mode")
    ap.add_argument("--proxy",default=None,metavar="N|random|none"); ap.add_argument("--proxy-prompt",action="store_true"); ap.add_argument("--proxy-file",default=PROXY_FILE)
    a=ap.parse_args(); profile=Path(DEDICATED_PROFILE_DIR); profile.mkdir(parents=True,exist_ok=True); kill_orphan_chromes_using_profile(profile); cleanup_locks(profile)
    base,full,api,meta=setup_dirs(prompt_parent()); port=find_free_port(); proxies=load_all_proxies(a.proxy_file)
    choice=None
    if a.proxy is not None:
        x=a.proxy.lower(); choice=x if x in {"random","none"} else int(x)
    proxy=select_proxy(proxies,cli_index=choice,prompt=a.proxy_prompt)
    cmd=[find_chrome(),f"--remote-debugging-port={port}",f"--user-data-dir={profile}","--remote-allow-origins=*","--no-first-run","--no-default-browser-check"]+build_proxy_chrome_args(proxy)
    proc=subprocess.Popen(cmd,creationflags=(0x00000200|0x00000008) if os.name=="nt" else 0,close_fds=True)
    for _ in range(40):
        try:
            if urllib.request.urlopen(f"http://127.0.0.1:{port}/json/version",timeout=1).status==200: break
        except Exception: time.sleep(.25)
    cap=APICapture(full,api,meta,port)
    if not cap.connect(): raise SystemExit(1)
    threading.Thread(target=cap.loop,daemon=True).start(); stopkbd=threading.Event()
    if _active_relays: _start_proxy_keyboard_thread(_active_relays[0],base/"proxy_toggles.jsonl",stopkbd)
    print(f"[+] API capture active: {base}\n[+] Ctrl+C pour terminer")
    closing=False
    def shutdown(*_):
        nonlocal closing
        if closing:return
        closing=True; cap.snapshot(); time.sleep(.3); cap.flush(); cap.summary(); cap.stop(); stopkbd.set()
        print(f"[+] Stats: {cap.stats}\n[+] Logs: {base.resolve()}")
        try: proc.terminate()
        except Exception: pass
        raise SystemExit(0)
    signal.signal(signal.SIGINT,shutdown); signal.signal(signal.SIGTERM,shutdown)
    try:
        while True:
            if proc.poll() is not None: shutdown()
            time.sleep(1)
    except KeyboardInterrupt: shutdown()

if __name__ == "__main__": main()
