#!/usr/bin/env python3
import argparse
import json
import re
import time
from collections import defaultdict, deque
from pathlib import Path
from urllib.parse import urlparse

RESET="\033[0m"; RED="\033[91m"; YELLOW="\033[93m"; CYAN="\033[96m"
GREEN="\033[92m"; WHITE="\033[97m"; DIM="\033[2m"

KEYWORDS = {
    "otp","verify","verification","one-time","one_time",
    "sms","call","login","register","authenticate","auth",
    "password","passcode","code"
}

def banner():
    print(CYAN + r"""
╔══════════════════════════════════════════════════════════╗
║              NET OTP / SMS / CALL WATCH                 ║
║        DEFENSIVE NETWORK BEHAVIOR MONITOR v2             ║
╚══════════════════════════════════════════════════════════╝
""" + RESET)

def load_iocs(path):
    try:
        data=json.loads(Path(path).read_text())
        return {d.lower().strip().rstrip(".") for d in data.get("domains", []) if d.strip()}
    except Exception as e:
        print(YELLOW + f"[WARN] IOC file not loaded: {e}" + RESET)
        return set()

def norm_domain(d):
    if not d: return ""
    d=d.lower().strip().rstrip(".")
    if "://" in d:
        d=urlparse(d).hostname or ""
    return d

def domain_match(domain, iocs):
    domain=norm_domain(domain)
    for ioc in iocs:
        if domain == ioc or domain.endswith("." + ioc):
            return True
    return False

def keyword_hits(text):
    t=(text or "").lower()
    return sorted({k for k in KEYWORDS if k in t})

def extract_event(line):
    try:
        e=json.loads(line)
    except Exception:
        return None
    if not isinstance(e, dict):
        return None

    et=e.get("event_type")
    if et not in {"http","dns","tls","flow","alert"}:
        return None

    src=e.get("src_ip") or e.get("src")
    domain=""
    uri=""
    if et=="http":
        h=e.get("http") or {}
        domain=norm_domain(h.get("hostname") or h.get("host") or "")
        uri=h.get("url") or h.get("uri") or ""
    elif et=="dns":
        d=e.get("dns") or {}
        rr=d.get("rrname") or ""
        domain=norm_domain(rr)
    elif et=="tls":
        t=e.get("tls") or {}
        domain=norm_domain(t.get("sni") or "")
    elif et=="alert":
        a=e.get("alert") or {}
        return {
            "type":"alert", "src":src or "?", "domain":"",
            "text":a.get("signature") or "Suricata alert",
            "sid":a.get("signature_id")
        }
    else:
        domain=norm_domain(e.get("dest_ip") or "")

    return {"type":et,"src":src or "?","domain":domain,"uri":uri}

def level(score):
    if score >= 10: return "HIGH", RED
    if score >= 5: return "MEDIUM", YELLOW
    return "LOW", GREEN

def print_alert(src, domain, reason, score, extra=""):
    lvl, color=level(score)
    print(f"{color}[{lvl}] {src}  {domain or '-'}  score={score}  {reason}{extra}{RESET}")

def main():
    ap=argparse.ArgumentParser(description="Read-only Suricata behavior monitor")
    ap.add_argument("--eve", default="/var/log/suricata/eve.json")
    ap.add_argument("--iocs", default="data/indicators.json")
    ap.add_argument("--demo", action="store_true")
    ap.add_argument("--once", action="store_true", help="read current file once")
    args=ap.parse_args()

    banner()
    iocs=load_iocs(args.iocs)
    print(DIM + f"[MONITOR] IOC domains loaded: {len(iocs)}" + RESET)

    # Per source: recent (timestamp, domain, keyword-hit-set)
    history=defaultdict(deque)
    last_alert={}

    def handle(evt):
        now=time.time()
        src=evt["src"]
        domain=evt.get("domain","")
        uri=evt.get("uri","")
        text=(domain+" "+uri+" "+evt.get("text","")).lower()

        if evt["type"]=="alert":
            print_alert(src, domain, "Suricata signature", 10,
                        f" | SID={evt.get('sid') or '?'}")
            return

        hits=keyword_hits(text)
        score=0
        reasons=[]
        if domain_match(domain,iocs):
            score += 6; reasons.append("IOC domain")
        if hits:
            score += 2; reasons.append("auth/OTP keyword")

        h=history[src]
        h.append((now,domain,hits))
        while h and now-h[0][0] > 60:
            h.popleft()

        domains={x[1] for x in h if x[1]}
        if len(h) >= 12 and len(domains) >= 6:
            score += 5; reasons.append(f"burst: {len(h)} events/{len(domains)} domains")

        # Stronger repeated behavior from one host, without inspecting message contents.
        keyword_events=sum(1 for x in h if x[2])
        if keyword_events >= 8:
            score += 3; reasons.append(f"auth-event burst: {keyword_events}/60s")

        if score:
            lvl,_=level(score)
            key=(src,domain,lvl)
            if last_alert.get(key,0) < now-30:
                last_alert[key]=now
                print_alert(src,domain,", ".join(reasons),score)

    if args.demo:
        now=time.time()
        demo=[
            {"event_type":"dns","src_ip":"192.168.56.10","dns":{"rrname":"login.example.test"}},
            {"event_type":"http","src_ip":"192.168.56.10","http":{"hostname":"login.example.test","uri":"/verify"}},
        ]
        # Add synthetic distinct domains to trigger behavior detection.
        for i in range(12):
            demo.append({"event_type":"dns","src_ip":"192.168.56.10",
                         "dns":{"rrname":f"service{i}.example.test"}})
        for e in demo:
            handle(extract_event(json.dumps(e)))
        print(GREEN+"[DEMO] Finished. No network traffic was generated."+RESET)
        return

    p=Path(args.eve)
    if not p.exists():
        print(RED+f"[ERROR] Suricata EVE file not found: {p}"+RESET)
        print("Start Suricata first, then run this monitor.")
        return

    print(GREEN+f"[LIVE] Reading {p}"+RESET)
    with p.open("r",errors="replace") as f:
        if not args.once:
            f.seek(0,2)
        while True:
            line=f.readline()
            if not line:
                if args.once: break
                time.sleep(0.25); continue
            evt=extract_event(line)
            if evt: handle(evt)

if __name__=="__main__":
    main()
