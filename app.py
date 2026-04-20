"""
CIPHER SIEM — Security Information and Event Management Platform
Author: Rohit Kumar Reddy Sakam
GitHub: https://github.com/RohitKumarReddySakam
Version: 1.0.0

Log ingestion, event correlation, Sigma-like rule detection, and alerting.
"""

from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit
from datetime import datetime
import os
import uuid
import threading
import logging
import json
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
sio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ─── Models ───────────────────────────────────────────────────────
class LogEvent(db.Model):
    __tablename__ = "log_events"
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    log_source = db.Column(db.String(50))
    severity = db.Column(db.String(20))
    hostname = db.Column(db.String(200))
    username = db.Column(db.String(200))
    src_ip = db.Column(db.String(50))
    process = db.Column(db.String(300))
    message = db.Column(db.Text)
    raw = db.Column(db.Text)
    timestamp = db.Column(db.String(50))
    received_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id, "log_source": self.log_source, "severity": self.severity,
            "hostname": self.hostname, "username": self.username, "src_ip": self.src_ip,
            "process": self.process, "message": self.message,
            "timestamp": self.timestamp,
            "received_at": self.received_at.isoformat() if self.received_at else None,
        }


class SIEMAlert(db.Model):
    __tablename__ = "siem_alerts"
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    alert_type = db.Column(db.String(50))  # rule | correlation
    rule_id = db.Column(db.String(100))
    rule_name = db.Column(db.String(300))
    severity = db.Column(db.String(20))
    title = db.Column(db.String(300))
    description = db.Column(db.Text)
    mitre_tactic = db.Column(db.String(100))
    mitre_technique = db.Column(db.String(50))
    src_ip = db.Column(db.String(50))
    hostname = db.Column(db.String(200))
    username = db.Column(db.String(200))
    status = db.Column(db.String(30), default="open")
    event_count = db.Column(db.Integer, default=1)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    log_event_id = db.Column(db.String(36), db.ForeignKey("log_events.id"), nullable=True)

    def to_dict(self):
        return {
            "id": self.id, "alert_type": self.alert_type,
            "rule_id": self.rule_id, "rule_name": self.rule_name,
            "severity": self.severity, "title": self.title,
            "description": self.description, "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "src_ip": self.src_ip, "hostname": self.hostname, "username": self.username,
            "status": self.status, "event_count": self.event_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


# ─── Routes — Pages ───────────────────────────────────────────────
@app.route("/")
def dashboard():
    total_events = LogEvent.query.count()
    open_alerts = SIEMAlert.query.filter_by(status="open").count()
    critical_alerts = SIEMAlert.query.filter(
        SIEMAlert.severity == "CRITICAL", SIEMAlert.status == "open"
    ).count()
    recent_alerts = SIEMAlert.query.order_by(SIEMAlert.created_at.desc()).limit(10).all()
    sources = db.session.query(
        LogEvent.log_source, db.func.count(LogEvent.id)
    ).group_by(LogEvent.log_source).all()
    return render_template("index.html",
        total_events=total_events, open_alerts=open_alerts,
        critical_alerts=critical_alerts, recent_alerts=recent_alerts,
        sources=sources)


@app.route("/events")
def events_page():
    source_filter = request.args.get("source", "")
    q = LogEvent.query
    if source_filter:
        q = q.filter_by(log_source=source_filter)
    events = q.order_by(LogEvent.received_at.desc()).limit(300).all()
    return render_template("events.html", events=events, source_filter=source_filter)


@app.route("/alerts")
def alerts_page():
    alerts = SIEMAlert.query.order_by(SIEMAlert.created_at.desc()).all()
    return render_template("alerts.html", alerts=alerts)


# ─── Routes — API ─────────────────────────────────────────────────
@app.route("/api/ingest", methods=["POST"])
def ingest_log():
    """Ingest a raw log line or parsed event dict."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data"}), 400

    from core.rule_engine import SIEMRuleEngine
    from core.correlator import correlate
    from core.alert_manager import is_duplicate

    raw_log = data.get("raw", "")
    log_source = data.get("source", "unknown")
    parsed = _parse_log(raw_log, log_source, data)

    event = LogEvent(
        log_source=parsed.get("log_source", log_source),
        severity=parsed.get("severity", "INFO"),
        hostname=parsed.get("hostname", ""),
        username=parsed.get("username", ""),
        src_ip=parsed.get("src_ip", ""),
        process=parsed.get("process", ""),
        message=parsed.get("message", raw_log[:500] if raw_log else ""),
        raw=raw_log[:2000] if raw_log else "",
        timestamp=parsed.get("timestamp", datetime.utcnow().isoformat()),
    )
    db.session.add(event)
    db.session.commit()

    rule_engine = _get_rule_engine()
    created_alerts = []

    # Rule-based detection
    for match in rule_engine.evaluate(parsed):
        alert_data = {
            "rule_id": match["rule_id"],
            "hostname": parsed.get("hostname", ""),
            "src_ip": parsed.get("src_ip", ""),
            "username": parsed.get("username", ""),
        }
        if not is_duplicate(alert_data):
            alert = SIEMAlert(
                alert_type="rule",
                rule_id=match["rule_id"],
                rule_name=match["rule_name"],
                severity=match["severity"],
                title=match["rule_name"],
                description=match["description"],
                mitre_tactic=match["mitre_tactic"],
                mitre_technique=match["mitre_technique"],
                src_ip=parsed.get("src_ip", ""),
                hostname=parsed.get("hostname", ""),
                username=parsed.get("username", ""),
                log_event_id=event.id,
            )
            db.session.add(alert)
            db.session.commit()
            created_alerts.append(alert.to_dict())
            sio.emit("new_alert", alert.to_dict())

    # Correlation-based detection
    for corr in correlate(parsed):
        if not is_duplicate(corr):
            alert = SIEMAlert(
                alert_type="correlation",
                rule_id=corr.get("correlation_type", ""),
                rule_name=corr.get("title", ""),
                severity=corr["severity"],
                title=corr["title"],
                description=corr["description"],
                mitre_tactic=corr.get("mitre_tactic", ""),
                mitre_technique=corr.get("mitre_technique", ""),
                src_ip=corr.get("src_ip", ""),
                hostname=corr.get("hostname", ""),
                username=corr.get("username", ""),
                event_count=corr.get("event_count", 1),
            )
            db.session.add(alert)
            db.session.commit()
            created_alerts.append(alert.to_dict())
            sio.emit("new_alert", alert.to_dict())

    return jsonify({"event_id": event.id, "alerts_created": len(created_alerts)}), 201


@app.route("/api/ingest/batch", methods=["POST"])
def ingest_batch():
    data = request.get_json()
    if not isinstance(data, list):
        return jsonify({"error": "Expected list of log events"}), 400
    results = []
    for item in data[:200]:
        with app.test_request_context("/api/ingest", method="POST",
                                       content_type="application/json",
                                       data=json.dumps(item)):
            resp = ingest_log()
    return jsonify({"processed": len(data)}), 201


@app.route("/api/events")
def get_events():
    source = request.args.get("source")
    q = LogEvent.query
    if source:
        q = q.filter_by(log_source=source)
    events = q.order_by(LogEvent.received_at.desc()).limit(200).all()
    return jsonify({"events": [e.to_dict() for e in events]})


@app.route("/api/alerts")
def get_alerts():
    alerts = SIEMAlert.query.order_by(SIEMAlert.created_at.desc()).limit(200).all()
    return jsonify({"alerts": [a.to_dict() for a in alerts]})


@app.route("/api/alert/<alert_id>", methods=["PATCH"])
def update_alert(alert_id):
    alert = SIEMAlert.query.get_or_404(alert_id)
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data"}), 400
    if "status" in data:
        alert.status = data["status"]
    db.session.commit()
    return jsonify(alert.to_dict())


@app.route("/api/stats")
def get_stats():
    total_events = LogEvent.query.count()
    open_alerts = SIEMAlert.query.filter_by(status="open").count()
    critical_alerts = SIEMAlert.query.filter(
        SIEMAlert.severity == "CRITICAL", SIEMAlert.status == "open"
    ).count()
    sources = db.session.query(
        LogEvent.log_source, db.func.count(LogEvent.id)
    ).group_by(LogEvent.log_source).all()
    tactics = db.session.query(
        SIEMAlert.mitre_tactic, db.func.count(SIEMAlert.id)
    ).group_by(SIEMAlert.mitre_tactic).all()
    return jsonify({
        "total_events": total_events,
        "open_alerts": open_alerts,
        "critical_alerts": critical_alerts,
        "sources": dict(sources),
        "mitre_tactics": dict(tactics),
        "rule_count": _get_rule_engine().rule_count,
    })


@app.route("/health")
def health():
    return jsonify({"status": "healthy", "version": "1.0.0",
                    "timestamp": datetime.utcnow().isoformat()})


@sio.on("connect")
def on_connect():
    logger.info("Client connected")


# ─── Helpers ──────────────────────────────────────────────────────
_rule_engine_instance = None
_re_lock = threading.Lock()


def _get_rule_engine():
    global _rule_engine_instance
    with _re_lock:
        if _rule_engine_instance is None:
            from core.rule_engine import SIEMRuleEngine
            _rule_engine_instance = SIEMRuleEngine(app.config["RULES_DIR"])
    return _rule_engine_instance


def _parse_log(raw: str, source: str, data: dict) -> dict:
    """Route raw log to the appropriate parser."""
    if source == "syslog" and raw:
        from parsers.syslog_parser import parse
        return parse(raw) or data
    if source == "windows_event":
        from parsers.windows_event_parser import parse
        return parse(data) or data
    if source in ("apache", "nginx") and raw:
        from parsers.apache_parser import parse
        return parse(raw) or data
    if source == "cef" and raw:
        from parsers.cef_parser import parse
        return parse(raw) or data
    # Generic fallback
    return {
        "log_source": source,
        "raw": raw,
        "timestamp": data.get("timestamp", datetime.utcnow().isoformat()),
        "hostname": data.get("hostname", ""),
        "username": data.get("username", ""),
        "src_ip": data.get("src_ip", ""),
        "process": data.get("process", ""),
        "message": raw or data.get("message", ""),
        "severity": data.get("severity", "INFO"),
    }


def _seed_demo_data():
    """Seed demonstration events and alerts."""
    from parsers.syslog_parser import parse as syslog_parse
    samples = [
        "<34>Nov 15 10:23:15 webserver01 sshd[1234]: Failed password for root from 185.220.101.45 port 51234 ssh2",
        "<34>Nov 15 10:23:16 webserver01 sshd[1235]: Failed password for root from 185.220.101.45 port 51235 ssh2",
        "<86>Nov 15 10:25:00 appserver02 sudo[5678]: admin : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash",
        "<14>Nov 15 10:30:00 dc01 security[4688]: New process created: powershell.exe -enc SQBFAFgA",
    ]
    for raw in samples:
        parsed = syslog_parse(raw)
        ev = LogEvent(
            log_source="syslog",
            severity=parsed.get("severity", "INFO"),
            hostname=parsed.get("hostname", ""),
            message=parsed.get("message", ""),
            raw=raw,
            timestamp=parsed.get("timestamp", ""),
        )
        db.session.add(ev)

    demo_alert = SIEMAlert(
        alert_type="rule",
        rule_id="auth-001",
        rule_name="Multiple Failed Logins",
        severity="HIGH",
        title="Multiple Failed Logins",
        description="Repeated SSH failures from 185.220.101.45",
        mitre_tactic="Credential Access",
        mitre_technique="T1110",
        src_ip="185.220.101.45",
        hostname="webserver01",
    )
    db.session.add(demo_alert)
    db.session.commit()


def create_app():
    with app.app_context():
        os.makedirs(os.path.join(app.root_path, "instance"), exist_ok=True)
        db.create_all()
        if LogEvent.query.count() == 0:
            _seed_demo_data()
    return app


if __name__ == "__main__":
    create_app()
    port = int(os.environ.get("PORT", 5006))
    sio.run(app, host="0.0.0.0", port=port, debug=False)
