# NET OTP / SMS / CALL WATCH v2

Defensive, read-only network behavior monitor for authorized networks.

## What changed

- Reads Suricata EVE `http`, `dns`, `tls`, and `alert` events.
- Watches TLS SNI/DNS metadata, so HTTPS traffic can still provide useful destination metadata without decrypting message contents.
- Detects repeated OTP/auth-related keywords.
- Detects high request/event bursts from one source.
- Detects one host touching many domains quickly.
- Consumes Suricata signature alerts.
- Supports a local IOC domain list.
- Alerts are rate-limited to reduce terminal spam.
- `--demo` uses fake local events only.

## Run

```bash
chmod +x run.sh install.sh
./install.sh
./run.sh --demo
sudo systemctl enable --now suricata
sudo ./run.sh
```

Default Suricata log:

`/var/log/suricata/eve.json`

Read current events once:

```bash
sudo ./run.sh --once
```

## IOC list

Edit:

`data/indicators.json`

Only add domains you are authorized to monitor.

Do NOT put cookies, session IDs, passwords, API keys, CSRF tokens, or other secrets in the IOC file.

## Detection

Risk is based on metadata and behavior:

- IOC domain: +6
- OTP/auth keyword: +2
- 12+ events and 6+ domains in 60s: +5
- 8+ keyword-bearing events in 60s: +3
- Suricata signature alert: HIGH

Thresholds:

- LOW: 0–4
- MEDIUM: 5–9
- HIGH: 10+

This is a heuristic detector, not proof of abuse. Expect false positives and tune it for your network.

## Safety

The project does not send SMS, make calls, attack websites, generate requests, or modify packets.
