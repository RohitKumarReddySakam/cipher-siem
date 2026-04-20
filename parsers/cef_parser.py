"""CEF (Common Event Format) log parser."""
import re

# CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extensions
_CEF_HEADER = re.compile(
    r"CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(\d+)\|(.*)"
)
_KV_PAIR = re.compile(r'(\w+)=((?:[^\\=\s]|\\.)+)')

CEF_SEVERITY_MAP = {
    0: "INFO", 1: "INFO", 2: "INFO", 3: "LOW",
    4: "LOW", 5: "MEDIUM", 6: "MEDIUM", 7: "HIGH",
    8: "HIGH", 9: "CRITICAL", 10: "CRITICAL",
}


def parse(raw: str) -> dict | None:
    raw = raw.strip()
    m = _CEF_HEADER.match(raw)
    if not m:
        return None

    version, vendor, product, dev_version, sig_id, name, severity_int, extensions = m.groups()
    severity_int = int(severity_int)
    severity = CEF_SEVERITY_MAP.get(severity_int, "INFO")

    ext = {}
    for key, val in _KV_PAIR.findall(extensions):
        ext[key] = val.replace("\\=", "=").replace("\\\\", "\\")

    return {
        "log_source": "cef",
        "raw": raw,
        "timestamp": ext.get("rt") or ext.get("end") or ext.get("start", ""),
        "vendor": vendor,
        "product": product,
        "signature_id": sig_id,
        "name": name,
        "severity": severity,
        "severity_int": severity_int,
        "src_ip": ext.get("src"),
        "dst_ip": ext.get("dst"),
        "src_port": ext.get("spt"),
        "dst_port": ext.get("dpt"),
        "username": ext.get("suser") or ext.get("duser"),
        "message": name,
        "extensions": ext,
    }
