"""Wazuh API bridge for ThreatLens.

This module treats Wazuh as the primary telemetry source. It authenticates to
the Wazuh API, retrieves alerts from ``/alerts``, and converts them into
ThreatLens ``LogEvent`` objects so the existing detector stack can continue to
operate.
"""

from __future__ import annotations

import base64
import json
import logging
import ssl
import time
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from threatlens.models import EventCategory, LogEvent, Severity

log = logging.getLogger("threatlens")


@dataclass(slots=True)
class WazuhBridgeConfig:
    """Connection settings for the Wazuh API."""

    url: str
    username: str | None = None
    password: str | None = None
    token: str | None = None
    verify_ssl: bool = True
    timeout: float = 30.0
    retries: int = 3
    retry_delay: float = 0.75
    page_limit: int = 1000
    agent_id: str | None = None
    since_id: int | None = None
    ca_cert: str | None = None


def wazuh_level_to_severity(level: int) -> Severity:
    """Map a Wazuh rule level to a ThreatLens severity."""

    if level >= 15:
        return Severity.CRITICAL
    if level >= 12:
        return Severity.HIGH
    if level >= 7:
        return Severity.MEDIUM
    if level >= 4:
        return Severity.LOW
    return Severity.INFO


def _severity_label(level: int) -> str:
    if level >= 15:
        return "critical"
    if level >= 12:
        return "high"
    if level >= 7:
        return "medium"
    if level >= 4:
        return "low"
    return "info"


def _parse_timestamp(raw_value: Any) -> datetime:
    text = str(raw_value or "").strip()
    if not text:
        return datetime.now(timezone.utc).replace(tzinfo=None)

    candidates = [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
    ]
    for fmt in candidates:
        try:
            parsed = datetime.strptime(text, fmt)
            return parsed.replace(tzinfo=None)
        except ValueError:
            continue

    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed.replace(tzinfo=None)
    except ValueError:
        return datetime.now(timezone.utc).replace(tzinfo=None)


def _walk_values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, dict):
        items: list[str] = []
        for item in value.values():
            items.extend(_walk_values(item))
        return items
    if isinstance(value, list):
        items: list[str] = []
        for item in value:
            items.extend(_walk_values(item))
        return items
    text = str(value).strip()
    return [text] if text else []


def _extract(raw: dict[str, Any], *paths: str, default: str = "") -> str:
    for path in paths:
        node: Any = raw
        for part in path.split("."):
            if not isinstance(node, dict) or part not in node:
                node = None
                break
            node = node[part]
        if node not in (None, ""):
            if isinstance(node, (dict, list)):
                flattened = _walk_values(node)
                if flattened:
                    return flattened[0]
            else:
                return str(node)
    return default


def _extract_int(raw: dict[str, Any], *paths: str, default: int = 0) -> int:
    value = _extract(raw, *paths, default=str(default))
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _extract_mitre(raw: dict[str, Any]) -> tuple[str, str]:
    tactic = _extract(raw, "rule.mitre.tactic", "rule.groups", default="")
    technique = _extract(raw, "rule.mitre.id", "rule.mitre.technique", default="")
    if tactic == "rule.groups":
        tactic = ""
    return tactic, technique


def _classify_category(event_id: int, process_name: str, command_line: str, source_ip: str, username: str) -> EventCategory:
    if process_name or command_line:
        return EventCategory.PROCESS
    if source_ip:
        return EventCategory.NETWORK
    if event_id in {4624, 4625, 4648, 4776} or username:
        return EventCategory.AUTHENTICATION
    return EventCategory.UNKNOWN


def _build_event(raw_alert: dict[str, Any]) -> LogEvent:
    rule = raw_alert.get("rule", {}) if isinstance(raw_alert.get("rule", {}), dict) else {}
    agent = raw_alert.get("agent", {}) if isinstance(raw_alert.get("agent", {}), dict) else {}
    data = raw_alert.get("data", {}) if isinstance(raw_alert.get("data", {}), dict) else {}

    level = _extract_int(raw_alert, "rule.level", default=0)
    timestamp = _parse_timestamp(
        _extract(raw_alert, "timestamp", "@timestamp", "rule.firedtimes", default="")
    )
    event_id = _extract_int(raw_alert, "rule.id", "decoder.id", default=0)
    source = _extract(raw_alert, "location", "rule.groups", default="wazuh") or "wazuh"
    computer = _extract(raw_alert, "agent.name", "agent.hostname", "data.host.name", default="wazuh-agent")
    username = _extract(
        raw_alert,
        "data.user",
        "data.username",
        "data.win.eventdata.SubjectUserName",
        "data.win.eventdata.TargetUserName",
        "user.name",
        default="",
    )
    domain = _extract(raw_alert, "data.domain", "data.win.eventdata.TargetDomainName", default="")
    source_ip = _extract(
        raw_alert,
        "srcip",
        "source.ip",
        "data.srcip",
        "data.win.eventdata.IpAddress",
        default="",
    )
    process_name = _extract(
        raw_alert,
        "data.process",
        "data.win.eventdata.Image",
        "data.win.system.providerName",
        "rule.groups",
        default="",
    )
    command_line = _extract(
        raw_alert,
        "data.command_line",
        "data.win.eventdata.CommandLine",
        "data.process.command_line",
        default="",
    )
    logon_type = _extract_int(raw_alert, "data.win.eventdata.LogonType", "data.logon_type", default=0)
    status = _extract(raw_alert, "data.status", "data.win.eventdata.Status", default="")
    parent_process = _extract(raw_alert, "data.parent_process", "data.win.eventdata.ParentImage", default="")
    target_username = _extract(
        raw_alert,
        "data.win.eventdata.TargetUserName",
        "data.target_user",
        default="",
    )
    mitre_tactic, mitre_technique = _extract_mitre(raw_alert)

    category = _classify_category(event_id, process_name, command_line, source_ip, username)
    rule_description = _extract(raw_alert, "rule.description", default="Wazuh alert")
    severity = wazuh_level_to_severity(level)

    return LogEvent(
        timestamp=timestamp,
        event_id=event_id,
        source=source,
        category=category,
        computer=computer,
        raw=raw_alert,
        username=username,
        domain=domain,
        source_ip=source_ip,
        process_name=process_name,
        command_line=command_line,
        logon_type=logon_type,
        status=status,
        parent_process=parent_process,
        target_username=target_username,
        agent_id=str(agent.get("id", "")) if isinstance(agent, dict) else "",
        agent_name=str(agent.get("name", "")) if isinstance(agent, dict) else "",
        mitre_tactic=mitre_tactic,
        mitre_technique=mitre_technique,
        event_source=rule_description,
        event_hash="",
    )


def _unwrap_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []

    for key in ("affected_items", "items", "alerts", "data"):
        node = payload.get(key)
        if isinstance(node, list):
            return [item for item in node if isinstance(item, dict)]
        if isinstance(node, dict):
            nested = node.get("affected_items") or node.get("items") or node.get("alerts")
            if isinstance(nested, list):
                return [item for item in nested if isinstance(item, dict)]
            if all(isinstance(v, dict) for v in node.values()):
                return list(node.values())
    return []


class WazuhBridge:
    """Authenticated Wazuh API client."""

    def __init__(self, config: WazuhBridgeConfig):
        self.config = config
        self._token = config.token
        if config.verify_ssl:
            self._ssl_context = ssl.create_default_context()
            if config.ca_cert:
                self._load_ca_cert(config.ca_cert)
        else:
            self._ssl_context = ssl._create_unverified_context()

    def _load_ca_cert(self, ca_cert: str) -> None:
        """Load a CA certificate, retrying with a sanitized PEM body if needed."""

        cert_path = Path(ca_cert)
        if not cert_path.is_file():
            raise FileNotFoundError(f"Wazuh CA certificate not found: {cert_path}")

        try:
            self._ssl_context.load_verify_locations(cafile=str(cert_path))
            return
        except ssl.SSLError:
            pass

        pem_text = cert_path.read_text(encoding="utf-8", errors="ignore")
        lines = []
        for line in pem_text.splitlines():
            if line.startswith("-----BEGIN") or line.startswith("-----END"):
                lines.append(line.strip())
                continue
            cleaned = "".join(ch for ch in line.strip() if ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
            if cleaned:
                lines.append(cleaned)

        sanitized = "\n".join(lines).strip() + "\n"
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False, encoding="utf-8") as temp_file:
            temp_file.write(sanitized)
            temp_path = Path(temp_file.name)

        try:
            self._ssl_context.load_verify_locations(cafile=str(temp_path))
        except ssl.SSLError as exc:
            raise ssl.SSLError(
                f"Unable to load Wazuh CA certificate from {cert_path}. The PEM file appears invalid."
            ) from exc

    @property
    def base_url(self) -> str:
        return self.config.url.rstrip("/")

    def authenticate(self) -> str:
        """Return a bearer token using the configured auth mode."""

        if self._token:
            return self._token
        if not self.config.username or not self.config.password:
            raise ValueError("Wazuh authentication requires either a token or username/password")

        auth_header = base64.b64encode(f"{self.config.username}:{self.config.password}".encode("utf-8")).decode("ascii")
        request = Request(
            f"{self.base_url}/security/user/authenticate",
            headers={"Authorization": f"Basic {auth_header}", "Content-Type": "application/json"},
            method="POST",
        )

        response = self._request(request)
        token = self._extract_token(response)
        if not token:
            raise RuntimeError("Wazuh authentication succeeded but no token was returned")
        self._token = token
        return token

    def _extract_token(self, payload: dict[str, Any]) -> str:
        if not isinstance(payload, dict):
            return ""
        for path in ("data.token", "token", "data.auth_token", "data.result.token"):
            node: Any = payload
            for part in path.split("."):
                if not isinstance(node, dict) or part not in node:
                    node = None
                    break
                node = node[part]
            if isinstance(node, str) and node:
                return node
        return ""

    def _build_request(self, path: str, method: str, token: str | None, params: dict[str, Any] | None, payload: dict[str, Any] | None) -> Request:
        url = f"{self.base_url}{path}"
        if params:
            url = f"{url}?{urlencode(params)}"
        headers: dict[str, str] = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        data = None
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        return Request(url, data=data, headers=headers, method=method)

    def _request(self, request: Request) -> dict[str, Any]:
        last_error: Exception | None = None
        for attempt in range(1, self.config.retries + 1):
            try:
                with urlopen(request, timeout=self.config.timeout, context=self._ssl_context) as response:
                    body = response.read().decode("utf-8")
                    return json.loads(body) if body else {}
            except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
                last_error = exc
                if attempt >= self.config.retries:
                    break
                time.sleep(self.config.retry_delay * attempt)
        raise RuntimeError(f"Wazuh request failed after {self.config.retries} attempt(s): {last_error}") from last_error

    def pull_alerts(self, limit: int | None = None, max_pages: int | None = None) -> list[dict[str, Any]]:
        """Fetch alerts from the Wazuh API with pagination."""

        token = self.authenticate()
        page_limit = limit or self.config.page_limit
        offset = 0
        page = 0
        alerts: list[dict[str, Any]] = []

        while True:
            page += 1
            request = self._build_request(
                "/alerts",
                "GET",
                token,
                {
                    "limit": page_limit,
                    "offset": offset,
                    **({"agent_id": self.config.agent_id} if self.config.agent_id else {}),
                    **({"q": f"id>{self.config.since_id}"} if self.config.since_id is not None else {}),
                },
                None,
            )
            payload = self._request(request)
            batch = _unwrap_payload(payload)
            if not batch:
                break
            alerts.extend(batch)
            if len(batch) < page_limit:
                break
            offset += page_limit
            if max_pages is not None and page >= max_pages:
                break

        return alerts

    def pull_agent_alerts(self, agent_id: str, limit: int | None = None, max_pages: int | None = None) -> list[dict[str, Any]]:
        """Convenience wrapper to pull alerts for a single agent."""

        original_agent = self.config.agent_id
        try:
            self.config.agent_id = agent_id
            return self.pull_alerts(limit=limit, max_pages=max_pages)
        finally:
            self.config.agent_id = original_agent

    def pull_events(self, limit: int | None = None, max_pages: int | None = None) -> list[LogEvent]:
        """Fetch Wazuh alerts and convert them to ThreatLens events."""

        return [self._build_event(alert) for alert in self.pull_alerts(limit=limit, max_pages=max_pages)]

    def iter_events(self, limit: int | None = None, max_pages: int | None = None):
        """Yield converted Wazuh events one by one."""

        for alert in self.pull_alerts(limit=limit, max_pages=max_pages):
            yield self._build_event(alert)

    @staticmethod
    def event_severity(alert: dict[str, Any]) -> Severity:
        level = _extract_int(alert, "rule.level", default=0)
        return wazuh_level_to_severity(level)


def load_wazuh_alerts(path: Path) -> list[dict[str, Any]]:
    """Load raw Wazuh alert payloads from a JSON file."""

    raw = json.loads(path.read_text(encoding="utf-8"))
    return _unwrap_payload(raw)
