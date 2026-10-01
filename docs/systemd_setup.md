# EvePulse Systemd Service Configuration

```ini
[Unit]
Description=EvePulse Suricata Monitor
After=network.target suricata.service

[Service]
ExecStart=/usr/bin/python3 /opt/EvePulse/watch.py --web
Restart=always

[Install]
WantedBy=multi-user.target
```
