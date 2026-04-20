"""Syslog (RFC 3164 / RFC 5424) log parser."""
import re
from datetime import datetime

# RFC 3164: <priority>MMM DD HH:MM:SS hostname process[pid]: message
_RFC3164 = re.compile(
    r"<(\d+)>(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)"
)
# RFC 5424: <priority>version timestamp hostname app msgid - message
_RFC5424 = re.compile(
    r"<(\d+)>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)"
)

FACILITY_MAP = {0: "kern", 1: "user", 3: "daemon", 4: "auth", 9: "cron", 16: "local0"}
SEVERITY_MAP = {0: "EMERGENCY", 1: "ALERT", 2: "CRITICAL", 3: "ERROR",
                4: "WARNING", 5: "NOTICE", 6: "INFO", 7: "DEBUG"}


def _decode_priority(pri: int) -> dict:
    facility = pri >> 3
    severity = pri & 0x07
    return {
        "facility": FACILITY_MAP.get(facility, f"facility{facility}"),
        "severity": SEVERITY_MAP.get(severity, "INFO"),
    }


def parse(raw: str) -> dict | None:
    raw = raw.strip()
    m = _RFC5424.match(raw)
    if m:
        pri, ver, ts, host, app, msgid, _, msg = m.groups()
        decoded = _decode_priority(int(pri))
        return {
            "log_source": "syslog",
            "raw": raw,
            "timestamp": ts,
            "hostname": host,
            "process": app,
            "message": msg.strip(),
            "severity": decoded["severity"],
            "facility": decoded["facility"],
        }
    m = _RFC3164.match(raw)
    if m:
        pri, ts, host, proc, pid, msg = m.groups()
        decoded = _decode_priority(int(pri))
        return {
            "log_source": "syslog",
            "raw": raw,
            "timestamp": ts,
            "hostname": host,
            "process": proc,
            "pid": pid,
            "message": msg.strip(),
            "severity": decoded["severity"],
            "facility": decoded["facility"],
        }
    # Fallback: unstructured
    return {
        "log_source": "syslog",
        "raw": raw,
        "timestamp": datetime.utcnow().isoformat(),
        "message": raw,
        "severity": "INFO",
        "facility": "user",
    }
