"""Tests for CIPHER SIEM rule engine, parsers, correlator, and alert manager."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.rule_engine import SIEMRuleEngine
from core.alert_manager import dedup_key, is_duplicate
from parsers.syslog_parser import parse as parse_syslog
from parsers.windows_event_parser import parse as parse_windows
from parsers.apache_parser import parse as parse_apache
from parsers.cef_parser import parse as parse_cef

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")


# ─── Rule Engine ──────────────────────────────────────────────────

def test_rule_engine_loads():
    engine = SIEMRuleEngine(RULES_DIR)
    assert engine.rule_count > 0


def test_detects_failed_login():
    engine = SIEMRuleEngine(RULES_DIR)
    event = {"log_source": "syslog", "message": "Failed password for root", "severity": "CRITICAL"}
    matches = engine.evaluate(event)
    assert any("login" in m["rule_name"].lower() or "auth" in m["rule_name"].lower() for m in matches)


def test_detects_powershell_encoded():
    engine = SIEMRuleEngine(RULES_DIR)
    event = {"log_source": "windows_event", "process": "powershell.exe",
             "message": "powershell.exe -enc SQBFAFgA", "severity": "HIGH"}
    matches = engine.evaluate(event)
    assert any("powershell" in m["rule_name"].lower() for m in matches)


def test_detects_mimikatz():
    engine = SIEMRuleEngine(RULES_DIR)
    event = {"log_source": "windows_event",
             "message": "sekurlsa::logonpasswords mimikatz", "severity": "CRITICAL"}
    matches = engine.evaluate(event)
    assert any("credential" in m["rule_name"].lower() or "mimikatz" in m["rule_name"].lower() for m in matches)


def test_no_match_benign():
    engine = SIEMRuleEngine(RULES_DIR)
    event = {"log_source": "syslog", "message": "systemd: Started cron service", "severity": "INFO"}
    matches = engine.evaluate(event)
    assert len(matches) == 0


# ─── Syslog Parser ────────────────────────────────────────────────

def test_syslog_rfc3164():
    raw = "<34>Nov 15 10:23:15 webserver01 sshd[1234]: Failed password for root from 192.168.1.5 port 22 ssh2"
    result = parse_syslog(raw)
    assert result is not None
    assert result["log_source"] == "syslog"
    assert "failed password" in result["message"].lower()
    assert result["hostname"] == "webserver01"


def test_syslog_fallback():
    raw = "some unparsed log line here"
    result = parse_syslog(raw)
    assert result is not None
    assert result["log_source"] == "syslog"


# ─── Windows Event Parser ─────────────────────────────────────────

def test_windows_event_4625():
    event = {"EventID": 4625, "Computer": "DC01", "SubjectUserName": "john",
             "TimeCreated": "2024-01-15T10:00:00Z", "Message": "Failed logon"}
    result = parse_windows(event)
    assert result["event_id"] == 4625
    assert result["severity"] == "CRITICAL"
    assert result["hostname"] == "DC01"


def test_windows_event_4688():
    event = {"EventID": 4688, "Computer": "WS01", "NewProcessName": "cmd.exe"}
    result = parse_windows(event)
    assert result["event_id"] == 4688
    assert result["process"] == "cmd.exe"


def test_windows_event_invalid():
    result = parse_windows("not a dict")
    assert result is None


# ─── Apache Parser ────────────────────────────────────────────────

def test_apache_combined_log():
    raw = '192.168.1.10 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326 "http://example.com/" "Mozilla/5.0"'
    result = parse_apache(raw)
    assert result["src_ip"] == "192.168.1.10"
    assert result["status_code"] == 200
    assert result["method"] == "GET"


def test_apache_suspicious_path():
    raw = '10.0.0.1 - - [01/Jan/2024:00:00:00 +0000] "GET /etc/passwd HTTP/1.1" 404 100 "-" "-"'
    result = parse_apache(raw)
    assert result["suspicious"] is True
    assert result["severity"] == "HIGH"


# ─── CEF Parser ───────────────────────────────────────────────────

def test_cef_parse():
    raw = 'CEF:0|ArcSight|SmartConnector|7.0|100|Login Failure|8|src=192.168.1.50 dst=10.0.0.1 spt=54321 dpt=22 suser=admin'
    result = parse_cef(raw)
    assert result is not None
    assert result["src_ip"] == "192.168.1.50"
    assert result["severity"] == "HIGH"
    assert result["name"] == "Login Failure"


def test_cef_invalid():
    result = parse_cef("not a cef log at all")
    assert result is None


# ─── Alert Manager ────────────────────────────────────────────────

def test_dedup_key_consistent():
    alert = {"rule_id": "auth-001", "src_ip": "10.0.0.1", "hostname": "dc01"}
    k1 = dedup_key(alert)
    k2 = dedup_key(alert)
    assert k1 == k2


def test_dedup_different_alerts():
    a1 = {"rule_id": "auth-001", "src_ip": "10.0.0.1", "hostname": "dc01"}
    a2 = {"rule_id": "proc-002", "src_ip": "10.0.0.2", "hostname": "ws01"}
    assert dedup_key(a1) != dedup_key(a2)
