# NET OTP / SMS / CALL WATCH

**Defensive Network Behavior Monitor**

A read-only network security tool that detects suspicious OTP, SMS, call, authentication, and verification-related behavior using **Suricata + Python**, with a live SOC-style terminal dashboard.

---

## Screenshots

<img width="520" height="243" alt="image" src="https://github.com/user-attachments/assets/edfeb11c-6fd8-4c03-8a05-64d54fd4b4e7" />

---

## What Is This?

**NET OTP / SMS / CALL WATCH** is a defensive network monitoring tool. It watches **Suricata EVE JSON logs** and looks for suspicious patterns such as:

- OTP-related requests
- SMS-related activity
- Call-related activity
- Authentication/verification patterns
- Repeated requests
- One device contacting many domains
- Suspicious domains from a local IOC list
- Suricata security alerts

The goal is simple:

```
Detect suspicious behavior → Analyze it → Calculate risk → Show alert
```

---

## Architecture

```
┌──────────────────┐
│      NETWORK      │
└─────────┬─────────┘
          ↓
┌──────────────────┐
│      SURICATA      │
│   Network IDS/IPS   │
└─────────┬─────────┘
          ↓
┌──────────────────┐
│      eve.json      │
│   Network Events    │
└─────────┬─────────┘
          ↓
┌──────────────────┐
│      watch.py       │
│  Detection Engine   │
└─────────┬─────────┘
          ↓
┌──────────────────┐
│   Risk Analysis    │
└─────────┬─────────┘
          ↓
┌──────────────────┐
│   SOC Dashboard     │
│  LOW / MEDIUM / HIGH │
└──────────────────┘
```

---

## Features

### Network Monitoring

Reads Suricata events from:

```
/var/log/suricata/eve.json
```

Supports:

- HTTP
- DNS
- TLS/SNI
- Suricata alerts

### Behavioral Detection

Looks for keywords such as:

```
OTP, VERIFY, SMS, CALL, LOGIN, REGISTER, AUTH, PASSCODE
```

Also detects:

- High event bursts
- Multiple domains contacted by a single host
- Repeated authentication activity
- Known IOC domains

---

## Risk Scoring

The detector uses a simple heuristic scoring system.

| Indicator                          | Score |
| ----------------------------------- | ----: |
| IOC domain                          |   +6  |
| OTP/Auth keyword                    |   +2  |
| 12+ events + 6+ domains / 60 sec    |   +5  |
| 8+ auth events / 60 sec             |   +3  |
| Suricata alert                      |  HIGH |

### Severity Thresholds

| Score  | Severity |
| ------ | -------- |
| 0–4    | LOW      |
| 5–9    | MEDIUM   |
| 10+    | HIGH     |

**Example alert:**

```
[HIGH]
Source: 192.168.0.194
Reason: Burst + OTP keyword
Score: 10
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/anshnarsale/EvePulse
cd net-otp-watch
```

Make scripts executable:

```bash
chmod +x install.sh run.sh
```

Install dependencies:

```bash
./install.sh
```

---

## Run Demo

Test the dashboard without generating network traffic:

```bash
./run.sh --demo
```

Demo mode uses **fake local events only**:

```
DEMO FINISHED — NO NETWORK TRAFFIC GENERATED
```

---

## Run Live Monitor

Start Suricata:

```bash
sudo systemctl enable --now suricata
```

Start the monitor:

```bash
sudo ./run.sh
```

The dashboard will continuously monitor:

```
/var/log/suricata/eve.json
```

Stop with `CTRL + C`.

---

## Safe Lab Testing

Test the detection pipeline using a local HTTP server.

**Terminal 1:**

```bash
python3 -m http.server 8080 --bind 0.0.0.0
```

**Terminal 2:**

```bash
for i in {1..20}; do
    curl -s "http://YOUR_KALI_IP:8080/verify/otp" > /dev/null
    sleep 1
done
```

**Monitor:**

```bash
sudo ./run.sh
```

This test stays inside your lab and does not contact any real SMS/OTP providers.

---

## IOC Configuration

IOC file location:

```
data/indicators.json
```

Example:

```json
{
  "source": "local defensive IOC list",
  "domains": [
    "example-suspicious-domain.test"
  ]
}
```

> Only add domains you are authorized to monitor.

**Never put the following into the IOC file:**

- Passwords
- API keys
- Cookies
- Session tokens
- CSRF tokens
- Credentials
- Request bodies
- Personal data

---

## Terminal Dashboard

The live dashboard provides:

- STATUS
- EVENTS
- DOMAINS
- ALERTS
- EVENT RATE

And a live event table:

```
TIME       SOURCE          DESTINATION       TYPE    RISK
03:35:13   192.168.0.194   example.com       HTTP    LOW
03:35:14   192.168.0.194   test.com          DNS     NORMAL
03:35:15   192.168.0.194   suspicious.test   HTTP    HIGH
```

---

## Project Structure

```
net-otp-watch/
├── watch.py
├── run.sh
├── install.sh
├── README.md
├── data/
│   └── indicators.json
└── rules/
    └── local.rules
```

---

## Security Model

This project is **defensive and read-only**.

**It does NOT:**

- ❌ Send SMS
- ❌ Make phone calls
- ❌ Send OTP requests
- ❌ Spam websites
- ❌ Attack third-party services
- ❌ Modify packets
- ❌ Perform exploitation

**It only:**

- ✅ Reads network security logs
- ✅ Analyzes metadata
- ✅ Detects suspicious patterns
- ✅ Calculates risk
- ✅ Generates alerts

---

## Limitations

This is a **heuristic detection system**. A LOW/MEDIUM/HIGH alert does not automatically prove malicious activity — false positives can occur.

Detection quality depends on:

- Suricata configuration
- Network interface
- Available EVE events
- TLS visibility
- IOC quality
- Detection thresholds

Tune the rules for your own authorized environment.

---

## Use Cases

- Cybersecurity labs
- SOC learning
- Network monitoring
- IDS experimentation
- Blue-team projects
- Security research
- Incident detection
- Final-year cybersecurity projects

---

## Tech Stack

- Python 3
- Suricata
- Rich
- JSON
- Linux / Kali Linux

---

## Roadmap

- [x] Suricata integration
- [x] HTTP detection
- [x] DNS detection
- [x] TLS/SNI detection
- [x] IOC support
- [x] Behavioral detection
- [x] Risk scoring
- [x] Live terminal dashboard
- [x] Demo mode
- [ ] Historical statistics
- [ ] Alert export
- [ ] PCAP analysis
- [ ] Email/desktop notifications
- [ ] SQLite event database
- [ ] Web dashboard
- [ ] Custom detection rules

---

## Disclaimer

Use this tool only on networks and systems you own or have explicit permission to monitor. This project is designed for **defensive security monitoring and authorized security testing**.

---

## Author

**Ansh Narsale**
Computer Engineering — Cybersecurity • Networking • Linux • AI

---

## ⭐ Support

If this project helped you learn network security, consider giving the repository a star.
