"""Seed the ThreatLens SQLite database with realistic Wazuh-style alerts."""

from __future__ import annotations

import argparse
import random
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from threatlens.correlation import CorrelationEngine
from threatlens.detections.hash_chain import HashChainManager
from threatlens.models import Alert, EventCategory, LogEvent, Severity
from threatlens.storage import ThreatLensStore


@dataclass(frozen=True)
class AlertTemplate:
    key: str
    rule_id: int
    level: int
    description: str
    category: EventCategory
    mitre_tactic: str = ""
    mitre_technique: str = ""
    username: str = "SYSTEM"
    source_ip: str = ""
    process_name: str = ""
    command_line: str = ""
    target_username: str = ""
    status: str = ""
    logon_type: int = 0
    domain: str = ""
    parent_process: str = ""


START = datetime(2026, 6, 10, 17, 49, 59, 168000)
END = datetime(2026, 6, 11, 17, 49, 59, 169000)

AGENT_ID = "003"
AGENT_NAME = "hydro"
AGENT_IP = "172.168.0.104"

TEMPLATES: dict[str, AlertTemplate] = {
    "dotnet_runtime": AlertTemplate(
        key="dotnet_runtime",
        rule_id=61020,
        level=5,
        description=".NET Runtime - CLR 2.0 does not support profilers written for CLR 1.x.",
        category=EventCategory.PROCESS,
        mitre_tactic="Defense Evasion",
        mitre_technique="T1574.001",
        process_name="C:\\Windows\\Microsoft.NET\\Framework64\\v2.0.50727\\mscorsvw.exe",
        command_line="mscorsvw.exe -start",
    ),
    "software_protection": AlertTemplate(
        key="software_protection",
        rule_id=60642,
        level=3,
        description="Software protection service scheduled successfully.",
        category=EventCategory.PROCESS,
        process_name="C:\\Windows\\System32\\svchost.exe",
        command_line="svchost.exe -k netsvcs -p",
    ),
    "failed_logon": AlertTemplate(
        key="failed_logon",
        rule_id=4625,
        level=6,
        description="Multiple failed logon attempts against hydro.",
        category=EventCategory.AUTHENTICATION,
        mitre_tactic="Credential Access",
        mitre_technique="T1110",
        username="jdoe",
        source_ip="185.220.101.1",
        target_username="jdoe",
        logon_type=3,
        status="0xC000006D",
    ),
    "powershell_encoded": AlertTemplate(
        key="powershell_encoded",
        rule_id=4104,
        level=12,
        description="Suspicious PowerShell encoded command detected.",
        category=EventCategory.PROCESS,
        mitre_tactic="Execution",
        mitre_technique="T1059.001",
        username="svc_backup",
        process_name="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
        parent_process="C:\\Windows\\explorer.exe",
    ),
    "scheduled_task": AlertTemplate(
        key="scheduled_task",
        rule_id=4698,
        level=7,
        description="Scheduled task created for persistence.",
        category=EventCategory.PROCESS,
        mitre_tactic="Persistence",
        mitre_technique="T1053.005",
        username="svc_deploy",
        process_name="C:\\Windows\\System32\\schtasks.exe",
        command_line="schtasks /create /tn \"Updater\" /tr \"C:\\Windows\\Temp\\updater.exe\" /sc minute /mo 30",
    ),
    "service_install": AlertTemplate(
        key="service_install",
        rule_id=7045,
        level=7,
        description="New service installed from a temporary path.",
        category=EventCategory.PROCESS,
        mitre_tactic="Persistence",
        mitre_technique="T1543.003",
        username="administrator",
        process_name="C:\\Windows\\System32\\sc.exe",
        command_line="sc.exe create UpdateSvc binPath= \"C:\\Windows\\Temp\\payload.exe\"",
    ),
    "psexec": AlertTemplate(
        key="psexec",
        rule_id=7040,
        level=12,
        description="PsExec remote service execution detected.",
        category=EventCategory.PROCESS,
        mitre_tactic="Lateral Movement",
        mitre_technique="T1569.002",
        username="admin",
        process_name="C:\\Windows\\System32\\psexesvc.exe",
        command_line="psexec \\\\SRV-APP01 cmd.exe",
        source_ip="10.0.1.50",
    ),
    "sam_access": AlertTemplate(
        key="sam_access",
        rule_id=1003,
        level=13,
        description="SAM hive access consistent with credential dumping.",
        category=EventCategory.REGISTRY,
        mitre_tactic="Credential Access",
        mitre_technique="T1003.002",
        username="administrator",
        process_name="C:\\Windows\\System32\\reg.exe",
        command_line="reg save HKLM\\SAM C:\\Windows\\Temp\\sam.hiv",
    ),
    "kerberos_tgs": AlertTemplate(
        key="kerberos_tgs",
        rule_id=4769,
        level=8,
        description="Multiple Kerberos TGS requests using RC4 encryption.",
        category=EventCategory.AUTHENTICATION,
        mitre_tactic="Credential Access",
        mitre_technique="T1558.003",
        username="svc_monitor",
        source_ip="10.0.1.52",
        target_username="sqlsvc",
    ),
    "defender_tamper": AlertTemplate(
        key="defender_tamper",
        rule_id=5001,
        level=10,
        description="Windows Defender tamper attempt detected.",
        category=EventCategory.PROCESS,
        mitre_tactic="Defense Evasion",
        mitre_technique="T1562.001",
        username="administrator",
        process_name="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="Set-MpPreference -DisableRealtimeMonitoring $true",
    ),
}


COUNTS = {
    "dotnet_runtime": 190,
    "software_protection": 150,
    "failed_logon": 70,
    "powershell_encoded": 50,
    "scheduled_task": 35,
    "service_install": 25,
    "psexec": 25,
    "sam_access": 18,
    "kerberos_tgs": 12,
    "defender_tamper": 8,
}


BURST_COUNTS = {
    "dotnet_runtime": 12,
    "software_protection": 10,
    "failed_logon": 5,
    "powershell_encoded": 3,
    "scheduled_task": 3,
}


def _severity_from_level(level: int) -> Severity:
    if level >= 15:
        return Severity.CRITICAL
    if level >= 12:
        return Severity.HIGH
    if level >= 7:
        return Severity.MEDIUM
    if level >= 4:
        return Severity.LOW
    return Severity.INFO


def _clear_database(db_path: Path) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.executescript(
            """
            DELETE FROM alerts;
            DELETE FROM incidents;
            DELETE FROM reports;
            DELETE FROM hash_chain;
            DELETE FROM mitre_mappings;
            DELETE FROM sqlite_sequence WHERE name IN (
                'alerts', 'incidents', 'reports', 'hash_chain', 'mitre_mappings'
            );
            """
        )


def _build_timestamps(count: int, seed: int) -> list[datetime]:
    rng = random.Random(seed)
    if count <= 1:
        return [START]

    total_seconds = (END - START).total_seconds()
    short_burst = min(40, count - 1)
    intervals = [rng.uniform(18.0, 75.0) for _ in range(short_burst)]
    intervals.extend(rng.uniform(90.0, 320.0) for _ in range(count - 1 - short_burst))
    scale = total_seconds / sum(intervals)
    intervals = [interval * scale for interval in intervals]

    timestamps = [START]
    for interval in intervals:
        timestamps.append(timestamps[-1] + timedelta(seconds=interval))
    timestamps[-1] = END
    return timestamps


def _build_raw_alert(template: AlertTemplate, timestamp: datetime, index: int) -> dict[str, Any]:
    data: dict[str, Any] = {
        "host": {"name": AGENT_NAME},
        "win": {"eventdata": {}},
    }
    if template.username:
        data["user"] = template.username
        data["win"]["eventdata"]["SubjectUserName"] = template.username
    if template.source_ip:
        data["srcip"] = template.source_ip
        data["win"]["eventdata"]["IpAddress"] = template.source_ip
    if template.process_name:
        data["process"] = template.process_name
        data["win"]["eventdata"]["Image"] = template.process_name
    if template.command_line:
        data["command_line"] = template.command_line
        data["win"]["eventdata"]["CommandLine"] = template.command_line
    if template.target_username:
        data["target_user"] = template.target_username
        data["win"]["eventdata"]["TargetUserName"] = template.target_username
    if template.status:
        data["status"] = template.status
        data["win"]["eventdata"]["Status"] = template.status
    if template.logon_type:
        data["win"]["eventdata"]["LogonType"] = template.logon_type
    if template.domain:
        data["domain"] = template.domain

    return {
        "timestamp": timestamp.isoformat(timespec="milliseconds") + "Z",
        "@timestamp": timestamp.isoformat(timespec="milliseconds") + "Z",
        "id": f"wazuh-seed-{index:04d}",
        "location": "wazuh-alerts-003",
        "agent": {
            "id": AGENT_ID,
            "name": AGENT_NAME,
            "ip": AGENT_IP,
        },
        "rule": {
            "id": template.rule_id,
            "level": template.level,
            "description": template.description,
            "mitre": {
                "tactic": template.mitre_tactic,
                "technique": template.mitre_technique,
            },
            "groups": ["wazuh", "windows", template.category.value],
        },
        "decoder": {"id": template.rule_id},
        "data": data,
    }


def _build_alert(template: AlertTemplate, timestamp: datetime, index: int) -> tuple[Alert, LogEvent]:
    raw_alert = _build_raw_alert(template, timestamp, index)
    evidence = [
        {
            "timestamp": raw_alert["timestamp"],
            "computer": AGENT_NAME,
            "agent_name": AGENT_NAME,
            "agent_id": AGENT_ID,
            "source_ip": template.source_ip,
            "username": template.username,
            "rule_id": template.rule_id,
            "rule_level": template.level,
            "rule_description": template.description,
            "command_line": template.command_line,
        }
    ]
    alert = Alert(
        rule_name=f"Wazuh: {template.description}",
        severity=_severity_from_level(template.level),
        description=template.description,
        timestamp=timestamp,
        evidence=evidence,
        mitre_tactic=template.mitre_tactic,
        mitre_technique=template.mitre_technique,
        recommendation="Review the host for related process, authentication, and persistence activity.",
    )
    event = LogEvent(
        timestamp=timestamp,
        event_id=template.rule_id,
        source="wazuh",
        category=template.category,
        computer=AGENT_NAME,
        raw=raw_alert,
        username=template.username,
        domain=template.domain,
        source_ip=template.source_ip,
        process_name=template.process_name,
        command_line=template.command_line,
        logon_type=template.logon_type,
        status=template.status,
        parent_process=template.parent_process,
        target_username=template.target_username,
        agent_id=AGENT_ID,
        agent_name=AGENT_NAME,
        mitre_tactic=template.mitre_tactic,
        mitre_technique=template.mitre_technique,
        event_source=template.description,
        event_hash="",
    )
    return alert, event


def _expand_sequence(rng: random.Random) -> list[str]:
    remaining = dict(COUNTS)
    burst_sequence: list[str] = []
    for key, burst_count in BURST_COUNTS.items():
        burst_sequence.extend([key] * burst_count)
        remaining[key] -= burst_count

    tail_sequence: list[str] = []
    for key, count in remaining.items():
        tail_sequence.extend([key] * count)
    rng.shuffle(tail_sequence)
    return burst_sequence + tail_sequence


def seed_database(db_path: Path, seed: int) -> None:
    if not db_path.exists():
        raise FileNotFoundError(db_path)

    _clear_database(db_path)
    store = ThreatLensStore(db_path)
    rng = random.Random(seed)
    sequence = _expand_sequence(rng)
    timestamps = _build_timestamps(len(sequence), seed)

    alerts: list[Alert] = []
    events: list[LogEvent] = []
    for index, (template_key, timestamp) in enumerate(zip(sequence, timestamps, strict=True), 1):
        alert, event = _build_alert(TEMPLATES[template_key], timestamp, index)
        alerts.append(alert)
        events.append(event)

    store.save_alerts(alerts)
    incidents = CorrelationEngine(window_minutes=60, min_alerts=2).correlate(alerts)
    store.save_incidents([incident.to_dict() for incident in incidents])
    HashChainManager(store).append_events(events)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Seed the ThreatLens SQLite database with Wazuh-style alerts")
    parser.add_argument("--database", default="threatlens.db", help="SQLite database path")
    parser.add_argument("--seed", type=int, default=583, help="Random seed used to keep the dataset reproducible")
    args = parser.parse_args(argv)

    db_path = Path(args.database)
    if not db_path.exists():
        raise SystemExit(f"Database not found: {db_path}")

    seed_database(db_path, args.seed)
    print(
        f"Seeded {db_path} with 583 Wazuh-style alerts from {START.isoformat(timespec='milliseconds')} to {END.isoformat(timespec='milliseconds')}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())