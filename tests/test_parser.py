"""Tests for core/parser.py."""
import pytest

from core.parser import parse_nmap, parse_zap, parse_nikto
from core.schemas import ToolName


def test_parse_nmap_finds_open_ports(nmap_xml: str) -> None:
    findings = parse_nmap(nmap_xml, "scan-001")
    ports = [f for f in findings if "Open port" in f.title]
    assert len(ports) == 2  # ports 80 and 443 are open; 22 is filtered
    assert all(f.tool == ToolName.NMAP for f in findings)


def test_parse_nmap_finds_vuln_scripts(nmap_xml: str) -> None:
    findings = parse_nmap(nmap_xml, "scan-001")
    vuln_findings = [f for f in findings if "vuln" in f.id.lower() or "cve" in f.id.lower()]
    assert len(vuln_findings) >= 1
    # The CVE-2017-5638 script should produce a high severity finding
    high_sev = [f for f in vuln_findings if f.raw_severity == "high"]
    assert len(high_sev) >= 1


def test_parse_nmap_invalid_xml_returns_empty() -> None:
    findings = parse_nmap("this is not xml", "scan-001")
    assert findings == []


def test_parse_zap_returns_correct_count(zap_json: str) -> None:
    findings = parse_zap(zap_json, "scan-001")
    assert len(findings) == 4


def test_parse_zap_sql_injection(zap_json: str) -> None:
    findings = parse_zap(zap_json, "scan-001")
    sqli = next(f for f in findings if "SQL" in f.title)
    assert sqli.cwe_id == 89
    assert sqli.raw_severity == "3"
    assert sqli.tool == ToolName.ZAP
    assert sqli.host == "example.com"
    assert sqli.path == "/login"


def test_parse_zap_invalid_json_returns_empty() -> None:
    findings = parse_zap("{invalid json", "scan-001")
    assert findings == []


def test_parse_nikto_returns_findings(nikto_json: str) -> None:
    findings = parse_nikto(nikto_json, "scan-001")
    assert len(findings) == 3
    assert all(f.tool == ToolName.NIKTO for f in findings)
    assert all(f.host == "example.com" for f in findings)
