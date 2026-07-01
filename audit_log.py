"""
audit_log.py
-------------
Lightweight append-only audit trail: every scan and every question asked is
logged with a timestamp. In a real deployment this would go to a proper
datastore; here it's a local JSONL file, which is enough to demonstrate the
concept for a prototype.
"""

import json
import os
from datetime import datetime, timezone

LOG_PATH = os.path.join(os.path.dirname(__file__), "audit_log.jsonl")


def log_event(event_type: str, details: dict):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event_type,
        **details,
    }
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass  # logging must never crash the app


def read_log(limit: int = 50):
    if not os.path.exists(LOG_PATH):
        return []
    with open(LOG_PATH, "r", encoding="utf-8") as f:
        lines = f.readlines()[-limit:]
    return [json.loads(line) for line in lines]
