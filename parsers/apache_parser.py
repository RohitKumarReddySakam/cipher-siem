"""Apache/Nginx Combined Log Format parser."""
import re
from datetime import datetime

# Combined Log Format: IP - user [time] "method path proto" status bytes "referer" "ua"
_COMBINED = re.compile(
    r'(\S+)\s+-\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d+)\s+(\d+|-)\s+"([^"]*)"\s+"([^"]*)"'
)
# Common Log Format (no referer/UA)
_COMMON = re.compile(
    r'(\S+)\s+-\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d+)\s+(\d+|-)'
)

SUSPICIOUS_PATHS = [
    "/etc/passwd", "/../", "/cmd=", "/.env", "/wp-admin", "/.git",
    "/phpmyadmin", "/shell", "/eval(", "/base64_decode",
]


def parse(raw: str) -> dict | None:
    raw = raw.strip()
    m = _COMBINED.match(raw) or _COMMON.match(raw)
    if not m:
        return {
            "log_source": "apache",
            "raw": raw,
            "timestamp": datetime.utcnow().isoformat(),
            "message": raw,
            "severity": "INFO",
        }

    groups = m.groups()
    client_ip = groups[0]
    user = groups[1]
    timestamp = groups[2]
    method = groups[3]
    path = groups[4]
    proto = groups[5]
    status = int(groups[6])
    size = groups[7]

    severity = _http_severity(status, path)

    return {
        "log_source": "apache",
        "raw": raw,
        "timestamp": timestamp,
        "src_ip": client_ip,
        "username": user if user != "-" else None,
        "method": method,
        "path": path,
        "protocol": proto,
        "status_code": status,
        "response_bytes": int(size) if size != "-" else 0,
        "message": f"{method} {path} → {status}",
        "severity": severity,
        "suspicious": any(p in path for p in SUSPICIOUS_PATHS),
    }


def _http_severity(status: int, path: str) -> str:
    if any(p in path for p in SUSPICIOUS_PATHS):
        return "HIGH"
    if status >= 500:
        return "ERROR"
    if status == 401 or status == 403:
        return "WARNING"
    if status >= 400:
        return "INFO"
    return "INFO"
