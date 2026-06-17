"""ThreatLens command-line interface."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Any

# Re-export symbols that existing code and tests import from cli
from threatlens import __version__
from threatlens.allowlist import _alert_allowed, load_allowlist  # noqa: F401
from threatlens.config import (  # noqa: F401
    _FORMAT_EXTENSIONS,
    _build_detectors,
    collect_log_files,
    load_rules_config,
)
from threatlens.correlation import CorrelationEngine
from threatlens.detections import ALL_DETECTORS
from threatlens.inputs import WazuhBridge, WazuhBridgeConfig
from threatlens.inputs import WindowsAgentListenerConfig, run_windows_agent_listener
from threatlens.follower import _flush_follow_buffer, run_follow  # noqa: F401
from threatlens.report import print_banner
from threatlens.scanner import run_scan
from threatlens.security import (
    decrypt_artifact,
    encrypt_artifact,
    generate_aes_key,
    generate_rsa_keypair,
    sign_artifact,
    verify_artifact,
)
from threatlens.storage import ThreatLensStore

logger = logging.getLogger("threatlens")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="threatlens",
        description="ThreatLens - Log Analysis & Threat Hunting CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  threatlens scan logs/security.json\n"
            "  threatlens scan logs/evidence.evtx\n"
            "  threatlens scan logs/ --output report.html --format html\n"
            "  threatlens scan events.json --min-severity high --verbose\n"
            "  threatlens scan logs/ --custom-rules my_rules/\n"
            "  threatlens scan logs/ --timeline attack_timeline.html\n"
            "  threatlens seed-db --database threatlens.db\n"
            "  threatlens wazuh-pull --url https://wazuh:55000 --user analyst --password secret\n"
            "  threatlens windows-agent-listen --output windows-agent-logs.jsonl\n"
            "  threatlens correlate --database threatlens.db\n"
            "  threatlens forensic-report --database threatlens.db --output incident.pdf\n"
            "  threatlens verify-chain --database threatlens.db\n"
            "  threatlens sign-report report.pdf --private-key key.pem\n"
            "  threatlens encrypt-report report.pdf --key-file report.key\n"
            "  threatlens weekly-report --database threatlens.db --smtp-host smtp.gmail.com\n"
            "  threatlens rules\n"
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"threatlens {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- scan command ---
    scan_parser = subparsers.add_parser("scan", help="Analyze log files for threats")
    scan_parser.add_argument("path", type=str, help="Path to a log file or directory of log files")
    scan_parser.add_argument("--output", "-o", type=str, default=None, help="Output file path for the report")
    scan_parser.add_argument("--format", "-f", choices=["json", "csv", "html", "md"], default="json", help="Output format (default: json)")
    scan_parser.add_argument("--min-severity", choices=["info", "low", "medium", "high", "critical"], default="low", help="Minimum severity level to report (default: low)")
    scan_parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed evidence for each alert")
    scan_parser.add_argument("--quiet", "-q", action="store_true", help="Suppress banner and only show alerts")
    scan_parser.add_argument("--rules-file", type=str, default=None, help="Path to a YAML rules configuration file (default: rules/default_rules.yaml)")
    scan_parser.add_argument("--input-format", choices=["json", "evtx", "syslog"], default=None, help="Force input format instead of auto-detecting from extension")
    scan_parser.add_argument("--custom-rules", type=str, default=None, help="Path to a YAML custom rules file or directory")
    scan_parser.add_argument("--sigma-rules", type=str, default=None, help="Path to a Sigma rule file or directory of Sigma rules")
    scan_parser.add_argument("--elastic-url", type=str, default=None, help="Deprecated: retained for compatibility; no longer sends data to Elasticsearch")
    scan_parser.add_argument("--elastic-index", type=str, default="threatlens-alerts", help="Deprecated: retained for compatibility")
    scan_parser.add_argument("--elastic-api-key", type=str, default=None, help="Deprecated: retained for compatibility")
    scan_parser.add_argument("--timeline", type=str, default=None, help="Output path for HTML attack timeline visualization")
    scan_parser.add_argument("--fail-on", choices=["info", "low", "medium", "high", "critical"], default=None, help="Exit with code 2 if any alert meets or exceeds this severity")
    scan_parser.add_argument("--no-color", action="store_true", help="Disable colored output (useful for CI/piped output)")
    scan_parser.add_argument("--recursive", "-r", action="store_true", help="Recursively scan subdirectories for log files")
    scan_parser.add_argument("--summary-only", action="store_true", help="Show only the summary table, suppress individual alerts")
    scan_parser.add_argument("--allowlist", type=str, default=None, help="Path to a YAML allowlist file for suppressing known-good alerts")
    scan_parser.add_argument("--profile", action="store_true", help="Output timing for each scan phase")
    scan_parser.add_argument("--plugin-dir", type=str, default=None, help="Path to a directory of custom Python detector plugins")
    scan_parser.add_argument("--exclude", action="append", default=None, metavar="DETECTOR", help="Disable a built-in detector by name (may be repeated). Match is case-insensitive substring against detector class or display name.")
    scan_parser.add_argument("--splunk-url", type=str, default=None, help="Splunk HEC URL (e.g. https://splunk:8088)")
    scan_parser.add_argument("--splunk-token", type=str, default=None, help="Splunk HEC token")
    scan_parser.add_argument("--splunk-index", type=str, default="main", help="Splunk HEC index (default: main)")
    scan_parser.add_argument("--splunk-sourcetype", type=str, default="threatlens:alert", help="Splunk sourcetype")
    scan_parser.add_argument("--navigator-layer", type=str, default=None, help="Write an ATT&CK Navigator JSON layer to this path")
    scan_parser.add_argument("--stix", type=str, default=None, help="Write a STIX 2.1 bundle to this path")
    scan_parser.add_argument("--insecure", action="store_true", help="Skip TLS verification for Splunk")

    # --- follow command ---
    follow_parser = subparsers.add_parser("follow", help="Real-time log tailing mode (like tail -f with detection)")
    follow_parser.add_argument("path", type=str, help="Path to a log file to tail")
    follow_parser.add_argument("--input-format", choices=["json", "syslog"], default=None, help="Force input format (default: auto-detect from extension)")
    follow_parser.add_argument("--min-severity", choices=["info", "low", "medium", "high", "critical"], default="low", help="Minimum severity level to report (default: low)")
    follow_parser.add_argument("--rules-file", type=str, default=None, help="Path to a YAML rules configuration file")
    follow_parser.add_argument("--custom-rules", type=str, default=None, help="Path to custom YAML rules file or directory")
    follow_parser.add_argument("--sigma-rules", type=str, default=None, help="Path to a Sigma rule file or directory")
    follow_parser.add_argument("--buffer-size", type=int, default=100, help="Number of events to buffer before running detection (default: 100)")
    follow_parser.add_argument("--flush-interval", type=float, default=5.0, help="Seconds between detection flushes (default: 5.0)")

    # --- rules command ---
    subparsers.add_parser("rules", help="List all available detection rules")

    # --- summary command ---
    summary_parser = subparsers.add_parser(
        "summary",
        help="Print a summary of a previously generated JSON report",
    )
    summary_parser.add_argument("report", type=str, help="Path to a ThreatLens JSON report")
    summary_parser.add_argument("--no-color", action="store_true", help="Disable colored output")

    # --- dashboard command ---
    dash_parser = subparsers.add_parser("dashboard", help="Launch the Streamlit dashboard for a JSON report")
    dash_parser.add_argument("report", type=str, help="Path to a ThreatLens JSON report")
    dash_parser.add_argument("--port", type=int, default=8501, help="Port to bind the dashboard to (default: 8501)")
    dash_parser.add_argument("--headless", action="store_true", help="Run Streamlit in headless mode (no browser auto-open)")
    dash_parser.add_argument("--workdir", type=str, default=None, help="Directory to materialize the dashboard app into")

    seed_parser = subparsers.add_parser("seed-db", help="Seed the SQLite database with realistic Wazuh-style alerts")
    seed_parser.add_argument("--database", default="threatlens.db", type=str, help="SQLite database path")
    seed_parser.add_argument("--seed", type=int, default=583, help="Random seed used to keep the dataset reproducible")

    wazuh_parser = subparsers.add_parser("wazuh-pull", help="Pull alerts from the Wazuh API and store them in SQLite")
    wazuh_parser.add_argument("--url", required=True, type=str, help="Wazuh API URL (e.g. https://wazuh:55000)")
    wazuh_parser.add_argument("--user", type=str, default=None, help="Wazuh API username")
    wazuh_parser.add_argument("--password", type=str, default=None, help="Wazuh API password")
    wazuh_parser.add_argument("--token", type=str, default=None, help="Pre-issued Wazuh API bearer token")
    wazuh_parser.add_argument("--database", default="threatlens.db", type=str, help="SQLite database path")
    wazuh_parser.add_argument("--limit", type=int, default=1000, help="Page size for Wazuh alert retrieval")
    wazuh_parser.add_argument("--pages", type=int, default=None, help="Maximum pages to pull")
    wazuh_parser.add_argument("--agent-id", type=str, default="003", help="Wazuh agent id to collect from (default: 003)")
    wazuh_parser.add_argument("--since-id", type=int, default=None, help="Only collect alerts with an id greater than this value")
    wazuh_parser.add_argument("--ca-cert", type=str, default=None, help="Path to the Wazuh CA certificate PEM file")
    wazuh_parser.add_argument("--insecure", action="store_true", help="Skip TLS verification")

    windows_parser = subparsers.add_parser(
        "windows-agent-listen",
        help="Continuously listen to Windows event logs and save ThreatLens JSONL plus alert reports",
    )
    windows_parser.add_argument("--output", type=str, default="windows-agent-logs.jsonl", help="Output JSONL path")
    windows_parser.add_argument("--channels", type=str, default="Security,System,Application,Microsoft-Windows-PowerShell/Operational", help="Comma-separated Windows channels to collect")
    windows_parser.add_argument("--max-events", type=int, default=500, help="Maximum events to collect per channel")
    windows_parser.add_argument("--buffer-size", type=int, default=1000, help="Maximum buffered events used for detection")
    windows_parser.add_argument("--interval", type=float, default=5.0, help="Polling interval in seconds")

    correlate_parser = subparsers.add_parser("correlate", help="Correlate stored alerts into incidents")
    correlate_parser.add_argument("--database", default="threatlens.db", type=str, help="SQLite database path")
    correlate_parser.add_argument("--window-minutes", type=int, default=60, help="Correlation window in minutes")
    correlate_parser.add_argument("--min-alerts", type=int, default=2, help="Minimum related alerts required")

    forensic_parser = subparsers.add_parser("forensic-report", help="Generate a forensic PDF report from SQLite data")
    forensic_parser.add_argument("--database", default="threatlens.db", type=str, help="SQLite database path")
    forensic_parser.add_argument("--output", required=True, type=str, help="Output PDF path")

    verify_parser = subparsers.add_parser("verify-chain", help="Verify the stored SHA-256 hash chain")
    verify_parser.add_argument("--database", default="threatlens.db", type=str, help="SQLite database path")

    encrypt_parser = subparsers.add_parser("encrypt-report", help="Encrypt a report or evidence file with AES-256")
    encrypt_parser.add_argument("input", type=str, help="Input file path")
    encrypt_parser.add_argument("--output", required=True, type=str, help="Encrypted output path")
    encrypt_parser.add_argument("--key-file", required=True, type=str, help="Path to the AES key file")

    sign_parser = subparsers.add_parser("sign-report", help="Sign a report or evidence file with RSA-2048")
    sign_parser.add_argument("input", type=str, help="Input file path")
    sign_parser.add_argument("--signature", required=True, type=str, help="Signature file path")
    sign_parser.add_argument("--private-key", required=True, type=str, help="Private key PEM path")
    sign_parser.add_argument("--passphrase", type=str, default=None, help="Optional private-key passphrase")

    weekly_parser = subparsers.add_parser("weekly-report", help="Email a weekly forensic report")
    weekly_parser.add_argument("--database", default="threatlens.db", type=str, help="SQLite database path")
    weekly_parser.add_argument("--output", default="weekly-report.pdf", type=str, help="PDF output path")
    weekly_parser.add_argument("--smtp-host", required=True, type=str, help="SMTP server host")
    weekly_parser.add_argument("--smtp-port", type=int, default=587, help="SMTP server port")
    weekly_parser.add_argument("--smtp-user", type=str, default=None, help="SMTP username")
    weekly_parser.add_argument("--smtp-password", type=str, default=None, help="SMTP password")
    weekly_parser.add_argument("--from-address", default=None, type=str, help="Sender email address (defaults to SMTP username)")
    weekly_parser.add_argument(
        "--to-address",
        type=str,
        default="rajanbhatta010@gmail.com",
        help="Recipient email address (default: rajanbhatta010@gmail.com)",
    )
    weekly_parser.add_argument("--subject", type=str, default="ThreatLens Weekly Forensic Report", help="Email subject")
    weekly_parser.add_argument("--use-gmail", action="store_true", help="Use Gmail-friendly SMTP settings")
    weekly_parser.add_argument("--use-outlook", action="store_true", help="Use Outlook-friendly SMTP settings")
    weekly_parser.add_argument("--use-ssl", action="store_true", help="Use SSL instead of TLS")
    weekly_parser.add_argument("--no-tls", action="store_true", help="Disable TLS/SSL")

    return parser


def run_rules() -> int:
    """List all available detection rules."""
    print_banner()
    print("  Available Detection Rules:\n")
    for detector_cls in ALL_DETECTORS:
        d = detector_cls()
        print(f"  - {d.name}")
        print(f"    {d.description}")
        if d.mitre_technique:
            print(f"    MITRE: {d.mitre_tactic} / {d.mitre_technique}")
        print()
    return 0


def run_summary(args: argparse.Namespace) -> int:
    """Print a brief summary of an existing JSON report without re-scanning."""
    import json
    from pathlib import Path

    from threatlens.utils import set_no_color

    if getattr(args, "no_color", False):
        set_no_color(True)

    report_path = Path(args.report)
    if not report_path.is_file():
        logger.error("Report file not found: %s", report_path)
        return 1

    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("Failed to read JSON report %s: %s", report_path, exc)
        return 1

    meta = data.get("report_metadata", {}) if isinstance(data, dict) else {}
    severity_summary = (
        data.get("severity_summary", {}) if isinstance(data, dict) else {}
    )
    alerts = data.get("alerts", []) if isinstance(data, dict) else []

    print_banner()
    print(f"  Report:        {report_path}")
    if meta.get("generated_at"):
        print(f"  Generated:     {meta['generated_at']}")
    if meta.get("version"):
        print(f"  Tool version:  {meta['version']}")
    total_events = meta.get("total_events_analyzed", "?")
    total_alerts = meta.get("total_alerts", len(alerts))
    print(f"  Events:        {total_events}")
    print(f"  Alerts:        {total_alerts}")
    print()
    print("  Severity breakdown:")
    for sev in ("critical", "high", "medium", "low"):
        count = severity_summary.get(sev, 0)
        print(f"    {sev.upper():<10} {count}")
    print()

    # Top rules by frequency
    rule_counts: dict[str, int] = {}
    for alert in alerts:
        name = alert.get("rule_name", "Unknown") if isinstance(alert, dict) else "Unknown"
        rule_counts[name] = rule_counts.get(name, 0) + 1

    if rule_counts:
        print("  Top rules:")
        ranked = sorted(rule_counts.items(), key=lambda x: -x[1])[:5]
        for name, count in ranked:
            print(f"    {count:>4}  {name}")
        print()
    return 0


def _store_alert_artifacts(store: ThreatLensStore, alerts: list[Any]) -> None:
    store.save_alerts(alerts)


def run_seed_db(args: argparse.Namespace) -> int:
    from threatlens.seed_wazuh_db import seed_database

    db_path = Path(args.database)
    if not db_path.exists():
        logger.error("Database not found: %s", db_path)
        return 1

    try:
        seed_database(db_path, int(getattr(args, "seed", 583)))
    except Exception as exc:
        logger.error("Database seeding failed: %s", exc)
        return 1

    print(f"Seeded {db_path} with realistic Wazuh-style alerts")
    return 0


def _build_wazuh_bridge(args: argparse.Namespace) -> WazuhBridge:
    return WazuhBridge(
        WazuhBridgeConfig(
            url=args.url,
            username=getattr(args, "user", None),
            password=getattr(args, "password", None),
            token=getattr(args, "token", None),
            verify_ssl=not getattr(args, "insecure", False),
            agent_id=getattr(args, "agent_id", None),
            since_id=getattr(args, "since_id", None),
            ca_cert=getattr(args, "ca_cert", None),
        )
    )


def run_wazuh_pull(args: argparse.Namespace) -> int:
    store = ThreatLensStore(args.database)
    bridge = _build_wazuh_bridge(args)
    try:
        events = bridge.pull_events(limit=getattr(args, "limit", 1000), max_pages=getattr(args, "pages", None))
    except Exception as exc:
        logger.error("Wazuh pull failed: %s", exc)
        return 1

    from threatlens.config import _build_detectors
    detectors = _build_detectors(argparse.Namespace(exclude=None, custom_rules=None, sigma_rules=None, plugin_dir=None), {})
    alerts = []
    for detector in detectors:
        try:
            alerts.extend(detector.analyze(events))
        except Exception as exc:
            logger.warning("Detector failed during Wazuh pull: %s", exc)
    store.save_alerts(alerts)
    from threatlens.detections.hash_chain import HashChainManager
    chain = HashChainManager(store)
    chain.append_events(events)
    print(f"Stored {len(events)} Wazuh event(s) and {len(alerts)} alert(s) in {args.database}")
    return 0


def run_windows_agent_listen(args: argparse.Namespace) -> int:
    if sys.platform != "win32":
        logger.error("windows-agent-listen must be run on Windows")
        return 1

    config = WindowsAgentListenerConfig(
        output_path=Path(args.output),
        channels=[channel.strip() for channel in str(args.channels).split(",") if channel.strip()],
        max_events_per_channel=int(getattr(args, "max_events", 500)),
        interval_seconds=float(getattr(args, "interval", 5.0)),
        buffer_size=int(getattr(args, "buffer_size", 1000)),
    )
    try:
        output_path = run_windows_agent_listener(config)
    except Exception as exc:
        logger.error("Windows agent collection failed: %s", exc)
        return 1

    print(f"Saved Windows agent logs to {output_path}")
    return 0


def run_correlate(args: argparse.Namespace) -> int:
    store = ThreatLensStore(args.database)
    alerts = store.load_alerts()
    engine = CorrelationEngine(window_minutes=getattr(args, "window_minutes", 60), min_alerts=getattr(args, "min_alerts", 2))
    incidents = engine.correlate(alerts)
    store.save_incidents([incident.to_dict() for incident in incidents])
    print(f"Correlated {len(incidents)} incident(s) from {len(alerts)} alert(s)")
    for incident in incidents:
        print(f"  - {incident.title} (risk={incident.risk_score})")
    return 0


def run_forensic_report(args: argparse.Namespace) -> int:
    store = ThreatLensStore(args.database)
    alerts = store.load_alerts()
    incidents = store.load_incidents()
    from threatlens.outputs.pdf_report import export_pdf_report
    output_path = Path(args.output)
    export_pdf_report(alerts=alerts, incidents=incidents, output_path=output_path, database_path=Path(args.database))
    store.save_report("pdf", output_path, {"alerts": len(alerts), "incidents": len(incidents), "output": str(output_path)})
    print(f"PDF report saved to {output_path}")
    return 0


def run_verify_chain(args: argparse.Namespace) -> int:
    from threatlens.detections.hash_chain import HashChainManager
    manager = HashChainManager(args.database)
    ok, errors = manager.verify_chain()
    if ok:
        print("Hash chain integrity verified")
        return 0
    print("Hash chain integrity failed")
    for error in errors:
        print(f"  - {error}")
    return 1


def run_encrypt_report(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    output_path = Path(args.output)
    key_file = Path(args.key_file)
    if key_file.exists():
        key = key_file.read_bytes()
    else:
        key = generate_aes_key()
        key_file.write_bytes(key)
    encrypt_artifact(input_path, output_path, key)
    print(f"Encrypted {input_path} -> {output_path}")
    return 0


def run_sign_report(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    signature_path = Path(args.signature)
    private_key_path = Path(args.private_key)
    sign_artifact(input_path, signature_path, private_key_path, getattr(args, "passphrase", None))
    print(f"Signed {input_path} -> {signature_path}")
    return 0


def run_weekly_report(args: argparse.Namespace) -> int:
    from threatlens.outputs.email_alerter import EmailAlerter
    report_args = argparse.Namespace(database=args.database, output=args.output)
    run_forensic_report(report_args)
    sender_address = getattr(args, "from_address", None) or getattr(args, "smtp_user", None) or "threatlens@localhost"
    use_ssl = getattr(args, "use_ssl", False)
    use_tls = not getattr(args, "no_tls", False)
    alerter = EmailAlerter(
        smtp_host=args.smtp_host,
        smtp_port=args.smtp_port,
        username=args.smtp_user,
        password=args.smtp_password,
        use_tls=use_tls,
        use_ssl=use_ssl,
    )
    try:
        alerter.send_report(
            from_address=sender_address,
            to_address=args.to_address,
            subject=args.subject,
            body="ThreatLens weekly forensic report attached.",
            attachment_path=Path(args.output),
        )
        print(f"Weekly report emailed to {args.to_address}")
    except Exception as exc:
        logger.warning("Weekly report email delivery failed: %s", exc)
        print(f"Weekly report generated at {args.output}")
    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    # Configure logging based on --verbose
    log_level = logging.DEBUG if getattr(args, "verbose", False) else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(levelname)s: %(message)s",
        stream=sys.stderr,
    )

    if args.command == "scan":
        return run_scan(args)
    elif args.command == "follow":
        return run_follow(args)
    elif args.command == "rules":
        return run_rules()
    elif args.command == "summary":
        return run_summary(args)
    elif args.command == "dashboard":
        from threatlens.dashboard import run_dashboard
        return run_dashboard(args)
    elif args.command == "seed-db":
        return run_seed_db(args)
    elif args.command == "wazuh-pull":
        return run_wazuh_pull(args)
    elif args.command == "windows-agent-listen":
        return run_windows_agent_listen(args)
    elif args.command == "correlate":
        return run_correlate(args)
    elif args.command == "forensic-report":
        return run_forensic_report(args)
    elif args.command == "verify-chain":
        return run_verify_chain(args)
    elif args.command == "encrypt-report":
        return run_encrypt_report(args)
    elif args.command == "sign-report":
        return run_sign_report(args)
    elif args.command == "weekly-report":
        return run_weekly_report(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
