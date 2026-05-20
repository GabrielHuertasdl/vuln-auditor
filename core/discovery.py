"""
Discovery Engine — extracts technical evidence and fingerprinting data.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from core.schemas import AssetDiscovery, Confidence, DiscoveryType, RawFinding


class DiscoveryEngine:
    """
    Extracts signals from raw scanner outputs and findings.
    """

    def extract(self, scan_id: str, raw_findings: list[RawFinding]) -> list[AssetDiscovery]:
        """
        Processes raw findings to find technical signals (headers, TLS, stack).
        """
        discovery_items: list[AssetDiscovery] = []

        seen_signals = set()

        for raw in raw_findings:
            # ── TLS Signals (Nmap/Nikto) ──────────────────────────────────────
            if "SSL" in raw.title or "TLS" in raw.title:
                protocol = "unknown"
                for p in ["TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3"]:
                    if p in (raw.description or "") or p in raw.title:
                        protocol = p
                        break

                signal_key = f"tls:{protocol}"
                if signal_key not in seen_signals:
                    discovery_items.append(
                        AssetDiscovery(
                            id=str(uuid.uuid4()),
                            scan_id=scan_id,
                            type=DiscoveryType.TLS,
                            data={"protocol": protocol, "raw_title": raw.title},
                            confidence=Confidence.HIGH if protocol != "unknown" else Confidence.LOW,
                            discovered_at=datetime.now(UTC),
                        )
                    )
                    seen_signals.add(signal_key)

            # ── Header Signals ────────────────────────────────────────────────
            if "Header" in raw.title:
                # Attempt to extract header name
                # "X-Content-Type-Options Header Missing" -> "X-Content-Type-Options"
                header_name = raw.title.split(" ")[0].strip()
                if "-" in header_name:
                    status = "missing" if "missing" in raw.title.lower() else "present"
                    signal_key = f"header:{header_name}:{status}"
                    if signal_key not in seen_signals:
                        discovery_items.append(
                            AssetDiscovery(
                                id=str(uuid.uuid4()),
                                scan_id=scan_id,
                                type=DiscoveryType.HEADER,
                                data={"name": header_name, "status": status},
                                confidence=Confidence.MEDIUM,
                                discovered_at=datetime.now(UTC),
                            )
                        )
                        seen_signals.add(signal_key)

            # ── Tech Stack Signals ────────────────────────────────────────────
            if raw.tool == "nikto" and "server" in raw.title.lower():
                server = raw.description.strip() if raw.description else "unknown"
                signal_key = f"tech:server:{server}"
                if signal_key not in seen_signals:
                    discovery_items.append(
                        AssetDiscovery(
                            id=str(uuid.uuid4()),
                            scan_id=scan_id,
                            type=DiscoveryType.TECH,
                            data={"category": "server", "value": server},
                            confidence=Confidence.HIGH,
                            discovered_at=datetime.now(UTC),
                        )
                    )
                    seen_signals.add(signal_key)

        return discovery_items
