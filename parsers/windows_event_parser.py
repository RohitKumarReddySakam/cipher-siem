"""Windows Event Log (JSON/dict format) parser."""
from datetime import datetime

# Map of common event IDs to human-readable descriptions and MITRE tactics
EVENT_CATALOG = {
    4624: ("Successful Logon", "Initial Access"),
    4625: ("Failed Logon", "Credential Access"),
    4634: ("Logoff", None),
    4648: ("Logon with Explicit Credentials", "Lateral Movement"),
    4656: ("Object Handle Requested", "Collection"),
    4663: ("Object Access Attempt", "Collection"),
    4672: ("Special Privileges Assigned", "Privilege Escalation"),
    4688: ("New Process Created", "Execution"),
    4697: ("Service Installed", "Persistence"),
    4698: ("Scheduled Task Created", "Persistence"),
    4720: ("User Account Created", "Persistence"),
    4732: ("User Added to Security Group", "Privilege Escalation"),
    4756: ("User Added to Universal Group", "Privilege Escalation"),
    4776: ("NTLM Authentication Attempt", "Credential Access"),
    7045: ("New Service Installed", "Persistence"),
    8004: ("NTLM Auth in Domain", "Credential Access"),
}


def parse(event: dict) -> dict | None:
    """Parse a Windows event dict (from WinRM/Winlogbeat/JSON export)."""
    if not isinstance(event, dict):
        return None

    event_id = event.get("EventID") or event.get("event_id") or event.get("id")
    try:
        event_id = int(event_id)
    except (TypeError, ValueError):
        event_id = 0

    description, mitre_tactic = EVENT_CATALOG.get(event_id, ("Unknown Event", None))

    timestamp = (
        event.get("TimeCreated") or
        event.get("timestamp") or
        datetime.utcnow().isoformat()
    )

    return {
        "log_source": "windows_event",
        "raw": str(event),
        "timestamp": str(timestamp),
        "event_id": event_id,
        "description": description,
        "hostname": event.get("Computer") or event.get("hostname", ""),
        "username": event.get("SubjectUserName") or event.get("username", ""),
        "process": event.get("NewProcessName") or event.get("process", ""),
        "message": event.get("Message") or description,
        "severity": _event_severity(event_id),
        "mitre_tactic": mitre_tactic,
        "channel": event.get("Channel") or event.get("channel", "Security"),
    }


def _event_severity(event_id: int) -> str:
    critical_ids = {4625, 4648, 4672, 4697, 4698, 4776, 7045}
    high_ids = {4688, 4720, 4732, 4756}
    if event_id in critical_ids:
        return "CRITICAL"
    if event_id in high_ids:
        return "HIGH"
    return "INFO"
