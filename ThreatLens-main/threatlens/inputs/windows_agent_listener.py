"""Windows agent log listener for ThreatLens.

This collector is designed for local Windows endpoints. It polls native event
channels, normalizes each record into the existing ThreatLens LogEvent shape,
and can persist the result as JSON Lines so the existing scan pipeline can read
it without any new parser logic.
"""

from __future__ import annotations

import json
import logging
import subprocess
import time
import ctypes
import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from threatlens.detections import ALL_DETECTORS
from threatlens.models import EventCategory, LogEvent
from threatlens.report import export_json

log = logging.getLogger("threatlens")


@dataclass(slots=True)
class WindowsAgentListenerConfig:
    """Configuration for the Windows agent collector."""

    channels: list[str] = field(
        default_factory=lambda: [
            "Security",
            "System",
            "Application",
            "Microsoft-Windows-PowerShell/Operational",
        ]
    )
    output_path: Path = Path("windows-agent-logs.jsonl")
    interval_seconds: float = 5.0
    max_events_per_channel: int = 500
    use_wevtutil: bool = True
    buffer_size: int = 1000


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def _classify_channel(channel: str, event_id: int, message: str) -> EventCategory:
    channel_lower = channel.lower()
    message_lower = message.lower()
    if event_id in {4624, 4625, 4648, 4776} or "logon" in message_lower or "authentication" in message_lower:
        return EventCategory.AUTHENTICATION
    if event_id in {4688, 4689, 1} or "powershell" in channel_lower or "process" in message_lower or "command" in message_lower:
        return EventCategory.PROCESS
    if event_id in {3, 5156, 5157} or "network" in message_lower or "connection" in message_lower:
        return EventCategory.NETWORK
    if event_id in {11, 4663}:
        return EventCategory.FILE
    if event_id in {12, 13}:
        return EventCategory.REGISTRY
    if event_id in {4672, 4673, 4674} or "privilege" in message_lower or "admin" in message_lower:
        return EventCategory.PRIVILEGE
    return EventCategory.UNKNOWN


def _parse_timestamp(value: Any) -> datetime:
    text = _normalize_text(value)
    if not text:
        return datetime.min
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return datetime.min


def _parse_wevtutil_record(raw_xml: str, channel: str) -> LogEvent | None:
    """Convert a raw XML event into a ThreatLens LogEvent."""

    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(raw_xml)
    except ET.ParseError:
        return None

    ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    system = root.find(f"{ns}System")
    event_data = root.find(f"{ns}EventData")
    if system is None:
        return None

    event_id_el = system.find(f"{ns}EventID")
    time_el = system.find(f"{ns}TimeCreated")
    computer_el = system.find(f"{ns}Computer")
    provider_el = system.find(f"{ns}Provider")

    event_id = 0
    if event_id_el is not None and event_id_el.text:
        try:
            event_id = int(event_id_el.text)
        except ValueError:
            event_id = 0

    data: dict[str, Any] = {}
    if event_data is not None:
        for item in event_data:
            name = item.get("Name")
            if name:
                data[name] = item.text or ""

    username = data.get("TargetUserName") or data.get("SubjectUserName") or data.get("User") or ""
    source_ip = data.get("IpAddress") or data.get("SourceAddress") or ""
    process_name = data.get("NewProcessName") or data.get("Image") or data.get("ProcessName") or ""
    command_line = data.get("CommandLine") or ""
    category = _classify_channel(channel, event_id, f"{process_name} {command_line} {json.dumps(data)}")

    raw = {
        "EventID": event_id,
        "TimeCreated": time_el.get("SystemTime") if time_el is not None else "",
        "Source": _normalize_text(provider_el.get("Name") if provider_el is not None else channel) or channel,
        "Computer": _normalize_text(computer_el.text if computer_el is not None else "") or "localhost",
        "Channel": channel,
        "EventData": data,
    }

    return LogEvent(
        timestamp=_parse_timestamp(time_el.get("SystemTime") if time_el is not None else ""),
        event_id=event_id,
        source=raw["Source"],
        category=category,
        computer=raw["Computer"],
        raw=raw,
        username=_normalize_text(username),
        source_ip=_normalize_text(source_ip),
        process_name=_normalize_text(process_name),
        command_line=_normalize_text(command_line),
        target_username=_normalize_text(username),
    )


def _event_fingerprint(event: LogEvent) -> str:
    payload = {
        "timestamp": event.timestamp.isoformat(),
        "event_id": event.event_id,
        "source": event.source,
        "category": event.category.value,
        "computer": event.computer,
        "username": event.username,
        "domain": event.domain,
        "source_ip": event.source_ip,
        "process_name": event.process_name,
        "command_line": event.command_line,
        "logon_type": event.logon_type,
        "status": event.status,
        "parent_process": event.parent_process,
        "target_username": event.target_username,
        "agent_id": event.agent_id,
        "agent_name": event.agent_name,
        "mitre_tactic": event.mitre_tactic,
        "mitre_technique": event.mitre_technique,
        "event_source": event.event_source,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _wevtutil_query(channel: str, count: int) -> str:
    query = [
        "wevtutil",
        "qe",
        channel,
        f"/c:{count}",
        "/f:xml",
        "/rd:true",
    ]
    completed = subprocess.run(query, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or f"wevtutil failed for channel {channel}")
    return completed.stdout.strip()


def collect_windows_events(config: WindowsAgentListenerConfig) -> list[LogEvent]:
    """Collect recent Windows events from the configured channels."""

    events: list[LogEvent] = []
    is_admin = _is_admin()
    for channel in config.channels:
        if channel.lower() == "security" and not is_admin:
            log.warning(
                "Skipping channel Security because it requires an elevated shell or Event Log Readers privileges."
            )
            continue

        try:
            raw_xml = _wevtutil_query(channel, config.max_events_per_channel) if config.use_wevtutil else ""
        except Exception as exc:
            log.warning("Failed to query channel %s: %s", channel, exc)
            continue

        if not raw_xml:
            continue

        for fragment in raw_xml.split("<Event xmlns="):
            if not fragment.strip():
                continue
            xml_text = "<Event xmlns=" + fragment
            if not xml_text.endswith("</Event>"):
                xml_text = f"{xml_text}</Event>"
            event = _parse_wevtutil_record(xml_text, channel)
            if event is not None:
                events.append(event)

    events.sort(key=lambda event: event.timestamp)
    return events


def collect_new_windows_events(config: WindowsAgentListenerConfig, seen_hashes: set[str]) -> list[LogEvent]:
    """Collect only events that have not been seen before."""

    fresh_events: list[LogEvent] = []
    for event in collect_windows_events(config):
        fingerprint = _event_fingerprint(event)
        if fingerprint in seen_hashes:
            continue
        event.event_hash = fingerprint
        seen_hashes.add(fingerprint)
        fresh_events.append(event)
    return fresh_events


def save_windows_events(config: WindowsAgentListenerConfig, events: list[LogEvent] | None = None) -> Path:
    """Save collected Windows events in ThreatLens JSONL format."""

    collected = events if events is not None else collect_windows_events(config)
    output_path = Path(config.output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as handle:
        for event in collected:
            handle.write(json.dumps(event.raw, default=str))
            handle.write("\n")

    return output_path


def _run_detectors(events: list[LogEvent]) -> list[dict[str, Any]]:
    """Run the built-in detector set against a batch of events."""

    alerts = []
    for detector_cls in ALL_DETECTORS:
        detector = detector_cls()
        try:
            alerts.extend(detector.analyze(events))
        except Exception as exc:
            log.warning("Detector %s failed during Windows listening: %s", detector_cls.__name__, exc)
    return alerts


def _save_alert_report(output_path: Path, alerts: list[Any], total_events: int) -> Path:
    alert_report = output_path.with_name(f"{output_path.stem}-alerts.json")
    export_json(alerts, alert_report, total_events)
    return alert_report


def run_windows_agent_listener(config: WindowsAgentListenerConfig) -> Path:
    """Continuously collect and save Windows events until interrupted."""

    output_path = Path(config.output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    seen_hashes: set[str] = set()
    buffer: list[LogEvent] = []
    total_collected = 0
    total_alerts = 0

    print(f"Listening for Windows events. Writing JSONL to {output_path}. Press Ctrl+C to stop.")
    try:
        while True:
            fresh_events = collect_new_windows_events(config, seen_hashes)
            if fresh_events:
                buffer.extend(fresh_events)
                buffer.sort(key=lambda event: event.timestamp)
                if len(buffer) > config.buffer_size:
                    buffer = buffer[-config.buffer_size:]

                with output_path.open("a", encoding="utf-8") as handle:
                    for event in fresh_events:
                        handle.write(json.dumps(event.raw, default=str))
                        handle.write("\n")

                total_collected += len(fresh_events)
                alerts = _run_detectors(buffer)
                if alerts:
                    total_alerts += len(alerts)
                    report_path = _save_alert_report(output_path, alerts, total_collected)
                    print(
                        f"Detected {len(alerts)} alert(s) from {len(buffer)} buffered event(s). Saved alert report to {report_path}"
                    )
                else:
                    print(f"Collected {len(fresh_events)} new Windows event(s); total={total_collected}")

            time.sleep(max(config.interval_seconds, 0.5))
    except KeyboardInterrupt:
        print(
            f"\nStopped Windows listener. Collected {total_collected} event(s) and generated {total_alerts} alert batch(es)."
        )

    return output_path
