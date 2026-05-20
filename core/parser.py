"""Converts raw scanner output to lists of RawFinding objects."""
from __future__ import annotations

import json
import logging
import re
import urllib.parse
import xml.etree.ElementTree as ET

from core.schemas import RawFinding, ToolName

log = logging.getLogger(__name__)


def parse_nmap(raw_xml: str, scan_id: str) -> list[RawFinding]:
    findings: list[RawFinding] = []
    try:
        root = ET.fromstring(raw_xml)
    except ET.ParseError as e:
        log.warning("Failed to parse nmap XML: %s", e)
        return findings

    for host_el in root.findall("host"):
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host_el.find("address")
        addr = addr_el.get("addr", "unknown") if addr_el is not None else "unknown"

        # Hostname fallback
        hostname_el = host_el.find(".//hostname")
        display_host = hostname_el.get("name", addr) if hostname_el is not None else addr

        ports_el = host_el.find("ports")
        if ports_el is None:
            continue

        for port_el in ports_el.findall("port"):
            port_id = int(port_el.get("portid", 0))
            protocol = port_el.get("protocol", "tcp")
            state_el = port_el.find("state")
            state = state_el.get("state", "unknown") if state_el is not None else "unknown"

            if state != "open":
                continue

            service_el = port_el.find("service")
            service_name = service_el.get("name", "unknown") if service_el is not None else "unknown"
            product = service_el.get("product", "") if service_el is not None else ""
            version = service_el.get("version", "") if service_el is not None else ""
            service_desc = f"{service_name} {product} {version}".strip()

            # Open port informational finding
            findings.append(RawFinding(
                id=f"nmap_{addr}_{port_id}_{protocol}",
                tool=ToolName.NMAP,
                host=display_host,
                port=port_id,
                path="/",
                title=f"Open port {port_id}/{protocol} ({service_name})",
                description=f"Port {port_id}/{protocol} is open. Service: {service_desc}",
                raw_severity="informational",
                raw_confidence="high",
            ))

            # Vuln script findings
            for script_el in port_el.findall("script"):
                script_id = script_el.get("id", "unknown")
                script_output = script_el.get("output", "")
                if not script_output:
                    continue

                title = f"{script_id.replace('-', ' ').title()} on port {port_id}"
                findings.append(RawFinding(
                    id=f"nmap_{addr}_{port_id}_{script_id}",
                    tool=ToolName.NMAP,
                    host=display_host,
                    port=port_id,
                    path="/",
                    title=title,
                    description=script_output[:2000],
                    evidence=script_output[:500],
                    raw_severity=_nmap_script_severity(script_id, script_output),
                    raw_confidence="medium",
                ))

    log.info("Parsed %d nmap findings", len(findings))
    return findings


def _nmap_script_severity(script_id: str, output: str) -> str:
    output_lower = output.lower()
    if "vulnerable" in output_lower or "critical" in output_lower:
        return "high"
    if "cve-" in output_lower or "exploit" in output_lower:
        return "medium"
    return "low"


def parse_zap(raw_json: str, scan_id: str) -> list[RawFinding]:
    findings: list[RawFinding] = []
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError as e:
        log.warning("Failed to parse ZAP JSON: %s", e)
        return findings

    alerts = data.get("alerts", [])
    for alert in alerts:
        url = alert.get("url", "/")
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or url
        path = parsed.path or "/"

        cwe_raw = alert.get("cweid", "0")
        cwe_id = int(cwe_raw) if cwe_raw and cwe_raw != "0" else None

        refs = [r.strip() for r in re.split(r"[\n,]", alert.get("reference", "")) if r.strip()]

        findings.append(RawFinding(
            id=f"zap_{alert.get('alertRef', alert.get('pluginId', ''))}",
            tool=ToolName.ZAP,
            host=host,
            port=parsed.port,
            path=path,
            method=alert.get("method"),
            parameter=alert.get("param"),
            title=alert.get("name", "Unknown ZAP Alert"),
            description=alert.get("description", ""),
            evidence=alert.get("evidence"),
            raw_severity=str(alert.get("riskcode", "0")),
            raw_confidence=str(alert.get("confidence", "1")),
            cwe_id=cwe_id,
            wasc_id=int(alert.get("wascid", 0)) or None,
            solution=alert.get("solution"),
            references=refs,
        ))

    log.info("Parsed %d ZAP findings", len(findings))
    return findings


def parse_nikto(raw_json: str, scan_id: str) -> list[RawFinding]:
    findings: list[RawFinding] = []
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError as e:
        log.warning("Failed to parse Nikto JSON: %s", e)
        return findings

    # Nikto JSON can be a list of scan objects or a single object
    if isinstance(data, list):
        scans = data
    else:
        scans = [data]

    for scan in scans:
        host = scan.get("host", "unknown")
        port = int(scan.get("port", 80))
        vulns = scan.get("vulnerabilities", [])

        for vuln in vulns:
            msg = vuln.get("msg", "")
            title = msg.split(".")[0][:120] if msg else "Nikto finding"
            vuln_url = vuln.get("url", "/")
            path = urllib.parse.urlparse(vuln_url).path or "/"

            osvdb = vuln.get("OSVDB", "")
            finding_id = f"nikto_{vuln.get('id', osvdb or title[:20].replace(' ', '_'))}"

            findings.append(RawFinding(
                id=finding_id,
                tool=ToolName.NIKTO,
                host=host,
                port=port,
                path=path,
                method=vuln.get("method"),
                title=title,
                description=msg,
                evidence=msg[:500],
                raw_severity=_nikto_severity(msg),
                raw_confidence="medium",
            ))

    log.info("Parsed %d Nikto findings", len(findings))
    return findings


def _nikto_severity(msg: str) -> str:
    lower = msg.lower()
    if any(k in lower for k in ("sql injection", "remote code", "rce", "command injection")):
        return "high"
    if any(k in lower for k in ("xss", "cross-site", "csrf", "path traversal")):
        return "medium"
    return "low"


def parse_raw(tool: ToolName, raw_output: str, scan_id: str) -> list[RawFinding]:
    """Dispatch to the correct parser based on tool name."""
    if tool == ToolName.NMAP:
        return parse_nmap(raw_output, scan_id)
    if tool == ToolName.ZAP:
        return parse_zap(raw_output, scan_id)
    if tool == ToolName.NIKTO:
        return parse_nikto(raw_output, scan_id)
    return []
