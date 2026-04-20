"""Event correlator — detects patterns across multiple log events."""
from datetime import datetime, timedelta
from collections import defaultdict
import threading

_lock = threading.Lock()

# In-memory sliding window store: keyed by (pattern_key) → list of events
_window: dict[str, list] = defaultdict(list)
WINDOW_SECONDS = 300  # 5 minute correlation window


def _prune(now: datetime):
    cutoff = now - timedelta(seconds=WINDOW_SECONDS)
    with _lock:
        for key in list(_window.keys()):
            _window[key] = [e for e in _window[key] if e["_ts"] > cutoff]
            if not _window[key]:
                del _window[key]


def correlate(event: dict) -> list[dict]:
    """
    Check event against correlation rules.
    Returns list of correlation alerts triggered.
    """
    now = datetime.utcnow()
    _prune(now)

    event["_ts"] = now
    alerts = []

    alerts.extend(_brute_force_check(event, now))
    alerts.extend(_privilege_escalation_check(event, now))
    alerts.extend(_lateral_movement_check(event, now))
    alerts.extend(_data_staging_check(event, now))

    return alerts


def _brute_force_check(event: dict, now: datetime) -> list[dict]:
    """5+ failed logins from same source within 5 minutes."""
    alerts = []
    if event.get("event_id") == 4625 or (
        event.get("severity") == "CRITICAL" and "fail" in event.get("message", "").lower()
    ):
        src = event.get("src_ip") or event.get("hostname", "unknown")
        key = f"failed_login:{src}"
        with _lock:
            _window[key].append(event)
            count = len(_window[key])
        if count >= 5:
            alerts.append({
                "correlation_type": "brute_force",
                "severity": "HIGH",
                "title": f"Brute Force Detected from {src}",
                "description": f"{count} failed logins from {src} in {WINDOW_SECONDS}s",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "T1110",
                "src_ip": src,
                "event_count": count,
            })
    return alerts


def _privilege_escalation_check(event: dict, now: datetime) -> list[dict]:
    """Privilege escalation: process creation after special privileges assigned."""
    alerts = []
    host = event.get("hostname", "")
    if not host:
        return alerts

    if event.get("event_id") == 4672:
        with _lock:
            _window[f"priv:{host}"].append(event)

    if event.get("event_id") == 4688:
        key = f"priv:{host}"
        with _lock:
            priv_events = list(_window.get(key, []))
        if priv_events:
            process = event.get("process", "unknown")
            alerts.append({
                "correlation_type": "privilege_escalation",
                "severity": "HIGH",
                "title": f"Privilege Escalation on {host}",
                "description": f"Process {process} created shortly after privilege assignment",
                "mitre_tactic": "Privilege Escalation",
                "mitre_technique": "T1068",
                "hostname": host,
                "event_count": len(priv_events) + 1,
            })
    return alerts


def _lateral_movement_check(event: dict, now: datetime) -> list[dict]:
    """Same user authenticating to 3+ different hosts in 5 min."""
    alerts = []
    user = event.get("username", "")
    if not user or user in ("-", "SYSTEM", "LOCAL SERVICE"):
        return alerts

    if event.get("event_id") in (4624, 4648):
        key = f"lateral:{user}"
        host = event.get("hostname", "")
        with _lock:
            events = _window[key]
            events.append(event)
            hosts = {e.get("hostname") for e in events if e.get("hostname")}

        if len(hosts) >= 3:
            alerts.append({
                "correlation_type": "lateral_movement",
                "severity": "HIGH",
                "title": f"Lateral Movement by {user}",
                "description": f"User {user} authenticated to {len(hosts)} hosts: {', '.join(list(hosts)[:5])}",
                "mitre_tactic": "Lateral Movement",
                "mitre_technique": "T1021",
                "username": user,
                "event_count": len(hosts),
            })
    return alerts


def _data_staging_check(event: dict, now: datetime) -> list[dict]:
    """Object access + archive process = potential data staging."""
    alerts = []
    host = event.get("hostname", "")
    if not host:
        return alerts

    if event.get("event_id") == 4663:
        with _lock:
            _window[f"obj_access:{host}"].append(event)

    staging_procs = ["7z.exe", "zip.exe", "rar.exe", "tar", "robocopy.exe", "xcopy.exe"]
    process = (event.get("process") or "").lower()
    if event.get("event_id") == 4688 and any(p in process for p in staging_procs):
        key = f"obj_access:{host}"
        with _lock:
            obj_events = list(_window.get(key, []))
        if obj_events:
            alerts.append({
                "correlation_type": "data_staging",
                "severity": "MEDIUM",
                "title": f"Potential Data Staging on {host}",
                "description": f"Archive process {process} after {len(obj_events)} object access events",
                "mitre_tactic": "Collection",
                "mitre_technique": "T1074",
                "hostname": host,
                "event_count": len(obj_events) + 1,
            })
    return alerts
