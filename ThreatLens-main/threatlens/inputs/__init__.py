"""Input connectors for ThreatLens."""

from threatlens.inputs.wazuh_bridge import WazuhBridge, WazuhBridgeConfig, wazuh_level_to_severity
from threatlens.inputs.windows_agent_listener import (
    WindowsAgentListenerConfig,
    collect_windows_events,
    run_windows_agent_listener,
    save_windows_events,
)

__all__ = [
    "WazuhBridge",
    "WazuhBridgeConfig",
    "WindowsAgentListenerConfig",
    "collect_windows_events",
    "run_windows_agent_listener",
    "save_windows_events",
    "wazuh_level_to_severity",
]
