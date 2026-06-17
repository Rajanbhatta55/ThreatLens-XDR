"""Tamper-evident SHA-256 event hash chain for ThreatLens."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Sequence

from threatlens.models import LogEvent
from threatlens.storage import ThreatLensStore


@dataclass(slots=True)
class HashRecord:
    event_type: str
    event_hash: str
    previous_hash: str
    created_at: str
    payload: dict[str, Any]


def _canonical_event(event: LogEvent | dict[str, Any]) -> dict[str, Any]:
    if isinstance(event, LogEvent):
        return {
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
            "raw": event.raw,
        }
    return event


def _hash_payload(payload: dict[str, Any], previous_hash: str) -> str:
    digest = hashlib.sha256()
    digest.update(previous_hash.encode("utf-8"))
    digest.update(json.dumps(payload, sort_keys=True, default=str).encode("utf-8"))
    return digest.hexdigest()


class HashChainManager:
    """Persist and verify a SHA-256 hash chain in SQLite."""

    def __init__(self, store: ThreatLensStore | Path | str):
        self.store = store if isinstance(store, ThreatLensStore) else ThreatLensStore(store)

    def append_event(self, event: LogEvent | dict[str, Any], event_type: str = "event") -> HashRecord:
        payload = _canonical_event(event)
        previous_hash = self.latest_hash()
        event_hash = _hash_payload(payload, previous_hash)
        record = HashRecord(
            event_type=event_type,
            event_hash=event_hash,
            previous_hash=previous_hash,
            created_at=datetime.now().isoformat(),
            payload=payload,
        )
        self.store.save_hash_record({
            "event_type": record.event_type,
            "event_hash": record.event_hash,
            "previous_hash": record.previous_hash,
            "created_at": record.created_at,
            "payload": record.payload,
            "mitre_mapping": "T1565",
        })
        return record

    def append_events(self, events: Sequence[LogEvent | dict[str, Any]]) -> list[HashRecord]:
        return [self.append_event(event) for event in events]

    def load_records(self) -> list[dict[str, Any]]:
        return self.store.load_hash_records()

    def latest_hash(self) -> str:
        records = self.load_records()
        if not records:
            return ""
        return str(records[-1].get("event_hash", ""))

    def verify_chain(self) -> tuple[bool, list[str]]:
        records = self.load_records()
        previous_hash = ""
        errors: list[str] = []
        for index, record in enumerate(records, 1):
            payload = record.get("payload", {})
            expected = _hash_payload(payload if isinstance(payload, dict) else {}, previous_hash)
            actual = str(record.get("event_hash", ""))
            if expected != actual:
                errors.append(f"Record {index} hash mismatch")
            if str(record.get("previous_hash", "")) != previous_hash:
                errors.append(f"Record {index} previous hash mismatch")
            previous_hash = actual
        return (len(errors) == 0, errors)
