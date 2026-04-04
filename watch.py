#!/usr/bin/env python3
"""
EvePulse — Defensive Network Security & Suricata Behavior Monitor
Watches Suricata EVE logs, evaluates behavioral anomalies, calculates threat risk,
records incidents to SQLite, sends alert webhooks, and serves a live SOC web dashboard.
"""

import argparse
import json
import sys
import time
from collections import defaultdict, deque
from pathlib import Path
from urllib.parse import urlparse

from evepulse.db import EventDatabase
from evepulse.export import export_to_csv, export_to_json, export_to_markdown_report
from evepulse.notifier import AlertNotifier
from evepulse.replay import replay_log_file
from evepulse.rules import RuleConfig
from evepulse.web import start_web_server

RESET = "\033[0m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
GREEN = "\033[92m"
WHITE = "\033[97m"
DIM = "\033[2m"


def banner():
    print(CYAN + r"""
╔══════════════════════════════════════════════════════════╗
║                    EVEPULSE MONITOR                      ║
║        DEFENSIVE NETWORK BEHAVIOR MONITOR v0.3.0         ║
╚══════════════════════════════════════════════════════════╝
""" + RESET)


def load_iocs(path):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return {d.lower().strip().rstrip(".") for d in data.get("domains", []) if d.strip()}
    except Exception as e:
        print(YELLOW + f"[WARN] IOC file not loaded: {e}" + RESET)
        return set()


def norm_domain(d):
    if not d:
        return ""
    d = d.lower().strip().rstrip(".")
    if "://" in d:
        d = urlparse(d).hostname or ""
    return d


def domain_match(domain, iocs):
    domain = norm_domain(domain)
    for ioc in iocs:
        if domain == ioc or domain.endswith("." + ioc):
            return True
    return False


def keyword_hits(text, keywords):
    t = (text or "").lower()
    return sorted({k for k in keywords if k in t})


def extract_event(line):
    if isinstance(line, str):
        try:
            e = json.loads(line)
        except Exception:
            return None
    elif isinstance(line, dict):
        e = line
    else:
        return None

    if not isinstance(e, dict):
        return None

    et = e.get("event_type")
    if et not in {"http", "dns", "tls", "flow", "alert"}:
        return None

    src = e.get("src_ip") or e.get("src")
    dest = e.get("dest_ip") or e.get("dest") or ""
    domain = ""
    uri = ""

    if et == "http":
        h = e.get("http") or {}
        domain = norm_domain(h.get("hostname") or h.get("host") or "")
        uri = h.get("url") or h.get("uri") or ""
    elif et == "dns":
        d = e.get("dns") or {}
        rr = d.get("rrname") or ""
        domain = norm_domain(rr)
    elif et == "tls":
        t = e.get("tls") or {}
        domain = norm_domain(t.get("sni") or "")
    elif et == "alert":
        a = e.get("alert") or {}
        return {
            "type": "alert",
            "src": src or "?",
            "dest": dest,
            "domain": "",
            "text": a.get("signature") or "Suricata alert",
            "sid": a.get("signature_id"),
            "raw": e,
        }
    else:
        domain = norm_domain(dest)

    return {"type": et, "src": src or "?", "dest": dest, "domain": domain, "uri": uri, "raw": e}


def get_severity(score, cfg: RuleConfig):
    thresholds = cfg.thresholds
    if score >= thresholds.get("medium_cutoff", 9) + 1:
        return "HIGH", RED
    if score >= thresholds.get("low_cutoff", 4) + 1:
        return "MEDIUM", YELLOW
    return "LOW", GREEN


def print_alert(src, domain, reason, score, extra="", color=RED, lvl="HIGH"):
    print(f"{color}[{lvl}] {src}  {domain or '-'}  score={score}  {reason}{extra}{RESET}")


def main():
    ap = argparse.ArgumentParser(description="EvePulse: Defensive Suricata Behavior Monitor")
    ap.add_argument("--eve", default="/var/log/suricata/eve.json", help="Path to live eve.json file")
    ap.add_argument("--iocs", default="data/indicators.json", help="Path to IOC indicators file")
    ap.add_argument("--rules", default="rules/custom_rules.json", help="Path to detection rules config")
    ap.add_argument("--db", default="data/evepulse.db", help="Path to SQLite event database")
    ap.add_argument("--demo", action="store_true", help="Run simulated test alerts")
    ap.add_argument("--once", action="store_true", help="Read current file once and exit")
    ap.add_argument("--web", action="store_true", help="Start embedded web SOC dashboard on port 8088")
    ap.add_argument("--port", type=int, default=8088, help="Web server port (default 8088)")
    ap.add_argument("--webhook", type=str, default=None, help="Discord/Slack webhook URL for alerts")
    ap.add_argument("--replay", type=str, default=None, help="Replay and analyze an offline eve.json file")
    ap.add_argument("--export-report", type=str, default=None, help="Export markdown audit report to file")
    args = ap.parse_args()

    banner()
    rule_cfg = RuleConfig(args.rules)
    iocs = load_iocs(args.iocs)
    db = EventDatabase(args.db)
    notifier = AlertNotifier(args.webhook)

    print(DIM + f"[MONITOR] IOC domains loaded: {len(iocs)}" + RESET)
    print(DIM + f"[DATABASE] SQLite event store: {args.db}" + RESET)
    print(DIM + f"[RULES] Loaded {len(rule_cfg.keywords)} behavioral keywords" + RESET)

    if args.web:
        start_web_server(db, port=args.port)
        print(GREEN + f"[WEB] SOC Web Dashboard running at http://127.0.0.1:{args.port}" + RESET)

    history = defaultdict(deque)
    last_alert = {}

    def handle(evt):
        if not evt:
            return
        now = time.time()
        src = evt["src"]
        dest = evt.get("dest", "")
        domain = evt.get("domain", "")
        uri = evt.get("uri", "")
        raw = evt.get("raw")
        text = (domain + " " + uri + " " + evt.get("text", "")).lower()

        # Check whitelist
        if src in rule_cfg.whitelisted_ips:
            return

        db.insert_event(
            event_type=evt.get("type", "unknown"),
            src_ip=src,
            dest_ip=dest,
            domain=domain,
            uri=uri,
            raw=raw,
        )

        if evt["type"] == "alert":
            score = rule_cfg.scores.get("suricata_alert", 10)
            lvl = "HIGH"
            color = RED
            reasons = f"Suricata signature | SID={evt.get('sid') or '?'}"
            print_alert(src, domain, "Suricata signature", score, f" | SID={evt.get('sid') or '?'}", color, lvl)
            db.insert_alert(src, domain, lvl, score, reasons, evt.get("text", ""))
            notifier.dispatch({"src_ip": src, "domain": domain, "severity": lvl, "score": score, "reasons": reasons})
            return

        hits = keyword_hits(text, rule_cfg.keywords)
        score = 0
        reasons = []

        if domain_match(domain, iocs):
            score += rule_cfg.scores.get("ioc_domain", 6)
            reasons.append("IOC domain")

        if hits:
            score += rule_cfg.scores.get("auth_keyword", 2)
            reasons.append(f"auth/OTP keyword: {','.join(hits)}")

        h = history[src]
        h.append((now, domain, hits))
        window = rule_cfg.thresholds.get("burst_window_seconds", 60)
        while h and now - h[0][0] > window:
            h.popleft()

        domains = {x[1] for x in h if x[1]}
        burst_evts = rule_cfg.thresholds.get("burst_events", 12)
        burst_doms = rule_cfg.thresholds.get("burst_domains", 6)
        if len(h) >= burst_evts and len(domains) >= burst_doms:
            score += rule_cfg.scores.get("burst_anomaly", 5)
            reasons.append(f"burst: {len(h)} events/{len(domains)} domains")

        keyword_events = sum(1 for x in h if x[2])
        auth_thresh = rule_cfg.thresholds.get("auth_event_threshold", 8)
        if keyword_events >= auth_thresh:
            score += rule_cfg.scores.get("auth_burst", 3)
            reasons.append(f"auth-event burst: {keyword_events}/{window}s")

        if score:
            lvl, color = get_severity(score, rule_cfg)
            key = (src, domain, lvl)
            if last_alert.get(key, 0) < now - 30:
                last_alert[key] = now
                reason_str = ", ".join(reasons)
                print_alert(src, domain, reason_str, score, color=color, lvl=lvl)
                db.insert_alert(src, domain, lvl, score, reason_str, uri)
                notifier.dispatch({
                    "src_ip": src,
                    "domain": domain,
                    "severity": lvl,
                    "score": score,
                    "reasons": reason_str,
                })

    if args.replay:
        print(CYAN + f"[REPLAY] Analyzing offline log: {args.replay}" + RESET)
        count = replay_log_file(args.replay, lambda e: handle(extract_event(e)))
        print(GREEN + f"[REPLAY] Finished. Processed {count} events." + RESET)
        stats = db.get_statistics()
        print(CYAN + f"[STATS] High: {stats['severity_counts']['HIGH']} | Med: {stats['severity_counts']['MEDIUM']} | Low: {stats['severity_counts']['LOW']}" + RESET)
        if args.export_report:
            alerts = db.get_recent_alerts(limit=500)
            report = export_to_markdown_report(stats, alerts)
            Path(args.export_report).write_text(report, encoding="utf-8")
            print(GREEN + f"[REPORT] Exported security audit report to {args.export_report}" + RESET)
        return

    if args.demo:
        demo = [
            {"event_type": "dns", "src_ip": "192.168.56.10", "dns": {"rrname": "login.example.test"}},
            {"event_type": "http", "src_ip": "192.168.56.10", "http": {"hostname": "login.example.test", "uri": "/verify/otp"}},
            {"event_type": "http", "src_ip": "192.168.56.10", "http": {"hostname": "example-suspicious-domain.test", "uri": "/api/auth"}},
        ]
        for i in range(12):
            demo.append({
                "event_type": "dns",
                "src_ip": "192.168.56.10",
                "dns": {"rrname": f"service{i}.example.test"},
            })
        for e in demo:
            handle(extract_event(e))
        print(GREEN + "[DEMO] Finished. Events recorded to database." + RESET)

        if args.export_report:
            stats = db.get_statistics()
            alerts = db.get_recent_alerts(limit=100)
            report = export_to_markdown_report(stats, alerts)
            Path(args.export_report).write_text(report, encoding="utf-8")
            print(GREEN + f"[REPORT] Exported report to {args.export_report}" + RESET)
        return

    p = Path(args.eve)
    if not p.exists():
        print(RED + f"[ERROR] Suricata EVE file not found: {p}" + RESET)
        print("Start Suricata first, or run with --demo or --replay <file>.")
        return

    print(GREEN + f"[LIVE] Reading {p}" + RESET)
    with p.open("r", encoding="utf-8", errors="replace") as f:
        if not args.once:
            f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                if args.once:
                    break
                time.sleep(0.25)
                continue
            evt = extract_event(line)
            if evt:
                handle(evt)


if __name__ == "__main__":
    main()
