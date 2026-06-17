"""Attack correlation engine for ThreatLens."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from threatlens.models import Alert, Severity


@dataclass(slots=True)
class CorrelatedIncident:
    """A correlated multi-alert incident."""

    incident_id: str
    title: str
    created_at: datetime
    host: str = ""
    user: str = ""
    ip: str = ""
    risk_score: int = 0
    alerts: list[Alert] = field(default_factory=list)
    stages: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "created_at": self.created_at.isoformat(),
            "host": self.host,
            "user": self.user,
            "ip": self.ip,
            "risk_score": self.risk_score,
            "alert_count": len(self.alerts),
            "stages": self.stages,
            "mitre_tactics": self.mitre_tactics,
            "mitre_techniques": self.mitre_techniques,
            "alerts": [alert.to_dict() for alert in self.alerts],
        }


_PROCESS_KEYWORDS = {
    "powershell": "PowerShell Execution",
    "encodedcommand": "Encoded Command",
    "-enc": "Encoded Command",
    "downloadstring": "Network Connection",
    "downloadfile": "Network Connection",
    "curl": "Network Connection",
    "wget": "Network Connection",
    "schtasks": "Persistence Event",
    "service": "Persistence Event",
    "psexec": "Lateral Movement",
}


def _alert_key(alert: Alert) -> str:
    raw = hashlib.sha256()
    raw.update(alert.rule_name.encode("utf-8"))
    raw.update(alert.timestamp.isoformat().encode("utf-8"))
    raw.update(alert.description.encode("utf-8"))
    return raw.hexdigest()


def _extract_context(alert: Alert) -> tuple[str, str, str]:
    host = ""
    user = ""
    ip = ""
    for evidence in alert.evidence:
        if not isinstance(evidence, dict):
            continue
        host = host or str(evidence.get("computer", "") or evidence.get("host", ""))
        user = user or str(evidence.get("username", "") or evidence.get("user", "") or evidence.get("target_username", ""))
        ip = ip or str(evidence.get("source_ip", "") or evidence.get("ip", ""))
    return host, user, ip


def _stage_for_alert(alert: Alert) -> str:
    text = f"{alert.rule_name} {alert.description} {alert.mitre_technique}".lower()
    for keyword, stage in _PROCESS_KEYWORDS.items():
        if keyword in text:
            return stage
    if alert.mitre_technique:
        return alert.mitre_technique
    return "General Alert"


class CorrelationEngine:
    """Group related alerts into attack incidents."""

    def __init__(self, window_minutes: int = 60, min_alerts: int = 2):
        self.window_minutes = window_minutes
        self.min_alerts = min_alerts

    def correlate(self, alerts: list[Alert]) -> list[CorrelatedIncident]:
        if not alerts:
            return []

        by_host: dict[str, list[Alert]] = defaultdict(list)
        by_user: dict[str, list[Alert]] = defaultdict(list)
        by_ip: dict[str, list[Alert]] = defaultdict(list)

        for alert in alerts:
            host, user, ip = _extract_context(alert)
            if host:
                by_host[host.lower()].append(alert)
            if user:
                by_user[user.lower()].append(alert)
            if ip:
                by_ip[ip].append(alert)

        incidents: list[CorrelatedIncident] = []
        seen_keys: set[str] = set()
        for bucket_name, bucket in (("host", by_host), ("user", by_user), ("ip", by_ip)):
            for entity, entity_alerts in bucket.items():
                if len(entity_alerts) < self.min_alerts:
                    continue
                sorted_alerts = sorted(entity_alerts, key=lambda alert: alert.timestamp)
                group = self._within_window(sorted_alerts)
                if len(group) < self.min_alerts:
                    continue
                key = self._incident_key(bucket_name, entity, group)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                incidents.append(self._build_incident(bucket_name, entity, group))

        incidents.sort(key=lambda incident: (incident.risk_score, incident.created_at), reverse=True)
        return incidents

    def _within_window(self, alerts: list[Alert]) -> list[Alert]:
        if not alerts:
            return []
        selected = [alerts[0]]
        start = alerts[0].timestamp
        for alert in alerts[1:]:
            if (alert.timestamp - start).total_seconds() <= self.window_minutes * 60:
                selected.append(alert)
            else:
                break
        return selected

    def _incident_key(self, bucket_name: str, entity: str, alerts: list[Alert]) -> str:
        digest = hashlib.sha256()
        digest.update(bucket_name.encode("utf-8"))
        digest.update(entity.encode("utf-8"))
        for alert in alerts:
            digest.update(_alert_key(alert).encode("utf-8"))
        return digest.hexdigest()

    def _build_incident(self, bucket_name: str, entity: str, alerts: list[Alert]) -> CorrelatedIncident:
        host = ""
        user = ""
        ip = ""
        if bucket_name == "host":
            host = entity
        elif bucket_name == "user":
            user = entity
        elif bucket_name == "ip":
            ip = entity

        stages = []
        mitre_tactics = []
        mitre_techniques = []
        for alert in alerts:
            stage = _stage_for_alert(alert)
            if stage not in stages:
                stages.append(stage)
            if alert.mitre_tactic and alert.mitre_tactic not in mitre_tactics:
                mitre_tactics.append(alert.mitre_tactic)
            if alert.mitre_technique and alert.mitre_technique not in mitre_techniques:
                mitre_techniques.append(alert.mitre_technique)

        severity_weight = {
            Severity.LOW: 10,
            Severity.MEDIUM: 20,
            Severity.HIGH: 35,
            Severity.CRITICAL: 50,
        }
        score = sum(severity_weight.get(alert.severity, 0) for alert in alerts)
        score += min(25, len(stages) * 5)
        score = min(100, score)

        title = f"Correlated {bucket_name.title()} Incident: {entity}"
        incident_id = hashlib.sha256(f"{bucket_name}:{entity}:{alerts[0].timestamp.isoformat()}".encode("utf-8")).hexdigest()[:16]
        return CorrelatedIncident(
            incident_id=incident_id,
            title=title,
            created_at=alerts[0].timestamp,
            host=host,
            user=user,
            ip=ip,
            risk_score=score,
            alerts=alerts,
            stages=stages,
            mitre_tactics=mitre_tactics,
            mitre_techniques=mitre_techniques,
        )
