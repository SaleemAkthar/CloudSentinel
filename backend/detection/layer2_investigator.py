"""
Layer 2 Investigator — Cloud Sentinel
=======================================
On-demand forensic investigation triggered when an analyst clicks
the 'Investigate' button on the Real-Time Alerts dashboard.

Wraps the existing Layer2Scanner with alert-aware context:
  - Pulls stored packet data and Layer 1 result from the alert
  - Runs the full Layer 2 scan pipeline
  - Returns a structured investigation report ready for the frontend

This module is intentionally kept thin. All heavy analysis logic
lives in the Layer 2 sub-modules (ip_analyzer, packet_analyzer,
attack_patterns, network_topology, risk_scorer).
"""

from datetime import datetime
from typing import Optional

from backend.detection.layer2_scanner import Layer2Scanner


# Shared scanner instance — reused across all investigation calls
_scanner = Layer2Scanner()


class Layer2Investigator:
    """
    Forensic investigator for flagged Lambda execution alerts.

    Called once per alert when the analyst requests a deep investigation.
    Results are cached on the alert object to avoid redundant scans.
    """

    def investigate(self, alert: dict) -> dict:
        """
        Run a full Layer 2 investigation on a flagged alert.

        Args:
            alert: The alert dict from AlertStore, must contain
                   '_raw_packet' and optionally '_layer1_result'.

        Returns:
            Investigation report dict with scan results and metadata.
        """
        alert_id     = alert.get("id", "unknown")
        raw_packet   = alert.get("_raw_packet", {})
        layer1_result = alert.get("_layer1_result", {})

        # Run the full Layer 2 scan pipeline
        scan_report = _scanner.scan(raw_packet, layer1_result)

        # Attach investigation metadata to the report
        scan_report["investigated_at"] = datetime.utcnow().isoformat() + "Z"
        scan_report["alert_id"]        = alert_id
        scan_report["triggered_by"]    = "analyst"  # vs "automatic" in future

        return scan_report

    def is_available(self) -> bool:
        """Returns True — confirms this module loaded successfully."""
        return True
