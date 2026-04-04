"""
Offline Forensics & Replay Engine for EvePulse
Enables security analysts to run threat detection and behavioral analysis
on historical eve.json files or exported Suricata logs without needing a live network.
"""

import json
from pathlib import Path
from typing import Any, Callable, Dict, List


def replay_log_file(file_path: str, event_callback: Callable[[Dict[str, Any]], None], max_events: int = 0) -> int:
    """
    Reads an offline Suricata EVE log line-by-line and feeds parsed events to the callback.
    Returns the count of successfully processed events.
    """
    p = Path(file_path)
    if not p.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    processed = 0
    with p.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                raw_evt = json.loads(line)
                event_callback(raw_evt)
                processed += 1
                if 0 < max_events <= processed:
                    break
            except Exception:
                continue

    return processed
