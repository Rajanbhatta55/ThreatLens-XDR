"""SQLite-backed storage layer for ThreatLens."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Sequence

from threatlens.models import Alert, Severity


def _json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if is_dataclass(value):
        return asdict(value)
    return str(value)


def _dump(value: Any) -> str:
    return json.dumps(value, default=_json_default, sort_keys=True)


def _load_alert(row: sqlite3.Row) -> Alert:
    payload = json.loads(row["payload"])
    timestamp = datetime.fromisoformat(payload["timestamp"])
    severity = Severity(payload["severity"])
    return Alert(
        rule_name=payload["rule_name"],
        severity=severity,
        description=payload["description"],
        timestamp=timestamp,
        evidence=list(payload.get("evidence", [])),
        mitre_tactic=payload.get("mitre_tactic", ""),
        mitre_technique=payload.get("mitre_technique", ""),
        recommendation=payload.get("recommendation", ""),
    )


class ThreatLensStore:
    """SQLite persistence for alerts, incidents, reports, and hash chains."""

    def __init__(self, db_path: Path | str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _initialize(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    rule_name TEXT NOT NULL,
                    mitre_tactic TEXT,
                    mitre_technique TEXT,
                    payload TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    host TEXT,
                    user TEXT,
                    ip TEXT,
                    risk_score REAL NOT NULL,
                    payload TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    report_type TEXT NOT NULL,
                    output_path TEXT,
                    payload TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS hash_chain (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    mitre_mapping TEXT NOT NULL DEFAULT 'T1565'
                );

                CREATE TABLE IF NOT EXISTS mitre_mappings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    source TEXT NOT NULL,
                    tactic TEXT,
                    technique TEXT,
                    payload TEXT NOT NULL
                );
                """
            )

    def save_alerts(self, alerts: Sequence[Alert]) -> int:
        if not alerts:
            return 0
        with self._connect() as conn:
            conn.executemany(
                """
                INSERT INTO alerts (created_at, severity, rule_name, mitre_tactic, mitre_technique, payload)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        datetime.now().isoformat(),
                        alert.severity.value,
                        alert.rule_name,
                        alert.mitre_tactic,
                        alert.mitre_technique,
                        _dump(alert.to_dict()),
                    )
                    for alert in alerts
                ],
            )
            for alert in alerts:
                if alert.mitre_tactic or alert.mitre_technique:
                    conn.execute(
                        """
                        INSERT INTO mitre_mappings (created_at, source, tactic, technique, payload)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            datetime.now().isoformat(),
                            "alert",
                            alert.mitre_tactic,
                            alert.mitre_technique,
                            _dump({
                                "rule_name": alert.rule_name,
                                "mitre_tactic": alert.mitre_tactic,
                                "mitre_technique": alert.mitre_technique,
                            }),
                        ),
                    )
        return len(alerts)

    def load_alerts(self, limit: int | None = None) -> list[Alert]:
        sql = "SELECT payload FROM alerts ORDER BY id ASC"
        params: tuple[Any, ...] = ()
        if limit is not None:
            sql += " LIMIT ?"
            params = (limit,)
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [_load_alert(row) for row in rows]

    def save_incidents(self, incidents: Sequence[dict[str, Any]]) -> int:
        if not incidents:
            return 0
        with self._connect() as conn:
            conn.executemany(
                """
                INSERT INTO incidents (created_at, host, user, ip, risk_score, payload)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        datetime.now().isoformat(),
                        incident.get("host", ""),
                        incident.get("user", ""),
                        incident.get("ip", ""),
                        float(incident.get("risk_score", 0.0)),
                        _dump(incident),
                    )
                    for incident in incidents
                ],
            )
        return len(incidents)

    def load_incidents(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT payload FROM incidents ORDER BY id ASC").fetchall()
        return [json.loads(row["payload"]) for row in rows]

    def save_report(self, report_type: str, output_path: Path | str, payload: dict[str, Any]) -> int:
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO reports (created_at, report_type, output_path, payload)
                VALUES (?, ?, ?, ?)
                """,
                (datetime.now().isoformat(), report_type, str(output_path), _dump(payload)),
            )
            return int(cursor.lastrowid or 0)

    def load_reports(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT payload FROM reports ORDER BY id ASC").fetchall()
        return [json.loads(row["payload"]) for row in rows]

    def save_hash_record(self, record: dict[str, Any]) -> int:
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO hash_chain (created_at, event_type, event_hash, previous_hash, payload)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    datetime.now().isoformat(),
                    record.get("event_type", "event"),
                    record["event_hash"],
                    record.get("previous_hash", ""),
                    _dump(record),
                ),
            )
            return int(cursor.lastrowid or 0)

    def load_hash_records(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT payload FROM hash_chain ORDER BY id ASC").fetchall()
        return [json.loads(row["payload"]) for row in rows]

    def save_mitre_mapping(self, source: str, tactic: str, technique: str, payload: dict[str, Any] | None = None) -> int:
        record = payload or {"source": source, "tactic": tactic, "technique": technique}
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO mitre_mappings (created_at, source, tactic, technique, payload)
                VALUES (?, ?, ?, ?, ?)
                """,
                (datetime.now().isoformat(), source, tactic, technique, _dump(record)),
            )
            return int(cursor.lastrowid or 0)

    def load_mitre_mappings(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT payload FROM mitre_mappings ORDER BY id ASC").fetchall()
        return [json.loads(row["payload"]) for row in rows]
