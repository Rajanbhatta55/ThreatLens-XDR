"""Forensic PDF report generation for ThreatLens."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from textwrap import wrap
from typing import Any

from threatlens import __version__
from threatlens.models import Alert, Severity


def _require_fpdf():
    try:
        from fpdf import FPDF
        return FPDF
    except ImportError as exc:  # pragma: no cover - dependency guard
        raise RuntimeError("fpdf2 is required for PDF reporting") from exc


def _severity_summary(alerts: list[Alert]) -> dict[str, int]:
    counts = Counter(alert.severity.value for alert in alerts)
    return {severity.value: counts.get(severity.value, 0) for severity in Severity}


def _write_section(pdf: Any, title: str, lines: list[str]) -> None:
    available_width = pdf.w - pdf.l_margin - pdf.r_margin
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(17, 24, 39)
    pdf.cell(0, 9, title, ln=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(31, 41, 55)
    for line in lines:
        wrapped_lines = wrap(line, width=120, break_long_words=True, break_on_hyphens=False) or [line]
        for wrapped_line in wrapped_lines:
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(available_width, 6, wrapped_line)
    pdf.ln(2)


def export_pdf_report(
    alerts: list[Alert],
    incidents: list[dict[str, Any]],
    output_path: Path,
    database_path: Path | None = None,
) -> None:
    """Create a forensic PDF report with alert, incident, and MITRE summaries."""

    FPDF = _require_fpdf()
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(17, 24, 39)
    pdf.cell(0, 12, "ThreatLens Forensic Report", ln=True)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(55, 65, 81)
    pdf.cell(0, 8, f"Generated: {datetime.now().isoformat(timespec='seconds')}", ln=True)
    pdf.cell(0, 8, f"ThreatLens version: {__version__}", ln=True)
    if database_path is not None:
        pdf.cell(0, 8, f"SQLite database: {database_path}", ln=True)
    pdf.ln(2)

    summary = _severity_summary(alerts)
    total_alerts = len(alerts)
    critical = summary[Severity.CRITICAL.value]
    high = summary[Severity.HIGH.value]
    medium = summary[Severity.MEDIUM.value]
    low = summary[Severity.LOW.value]
    total_incidents = len(incidents)

    _write_section(
        pdf,
        "Executive Summary",
        [
            f"Total alerts: {total_alerts}",
            f"Correlated incidents: {total_incidents}",
            f"Critical: {critical} | High: {high} | Medium: {medium} | Low: {low}",
        ],
    )

    if incidents:
        lines = []
        for incident in incidents[:10]:
            lines.append(
                f"- {incident.get('title', 'Incident')} | risk {incident.get('risk_score', 0)} | alerts {incident.get('alert_count', len(incident.get('alerts', [])))}"
            )
        _write_section(pdf, "Correlated Incidents", lines)

    mitre_counter = Counter()
    for alert in alerts:
        if alert.mitre_tactic:
            mitre_counter[alert.mitre_tactic] += 1
        if alert.mitre_technique:
            mitre_counter[alert.mitre_technique] += 1
    if mitre_counter:
        lines = [f"- {name}: {count}" for name, count in mitre_counter.most_common(20)]
        _write_section(pdf, "MITRE ATT&CK Mapping", lines)

    if alerts:
        lines = []
        for alert in alerts[:20]:
            lines.append(
                f"- {alert.timestamp_str} | {alert.severity.value.upper()} | {alert.rule_name} | {alert.mitre_tactic} / {alert.mitre_technique}"
            )
        _write_section(pdf, "Alert Timeline", lines)

        evidence_lines = []
        for alert in alerts[:10]:
            evidence_lines.append(
                f"- {alert.timestamp_str} | {alert.rule_name} | evidence items {len(alert.evidence)}"
            )
        _write_section(pdf, "Evidence Hashes", evidence_lines)

    _write_section(
        pdf,
        "Recommendations",
        [
            "- Isolate affected hosts and validate account usage patterns.",
            "- Review the correlated incident timeline for multi-stage attack progression.",
            "- Preserve chain-of-custody for exported evidence and signed reports.",
        ],
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(output_path))
