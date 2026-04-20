"""Alert deduplication and management for CIPHER SIEM."""
import hashlib
from datetime import datetime, timedelta

_seen: dict[str, datetime] = {}
DEDUP_WINDOW_SECONDS = 300


def dedup_key(alert: dict) -> str:
    parts = "|".join([
        alert.get("correlation_type", alert.get("rule_id", "")),
        alert.get("src_ip", ""),
        alert.get("hostname", ""),
        alert.get("username", ""),
    ])
    return hashlib.md5(parts.encode()).hexdigest()


def is_duplicate(alert: dict) -> bool:
    key = dedup_key(alert)
    now = datetime.utcnow()
    cutoff = now - timedelta(seconds=DEDUP_WINDOW_SECONDS)
    # Prune old entries
    stale = [k for k, ts in _seen.items() if ts < cutoff]
    for k in stale:
        del _seen[k]
    if key in _seen:
        return True
    _seen[key] = now
    return False
