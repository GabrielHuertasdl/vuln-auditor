"""Tests for Phase 3 modules: EPSS, KEV, SCA parser, IaC parser, ASPM endpoints."""
from __future__ import annotations

import json
import pytest

from core.epss import epss_risk_level, _chunked
from core.kev_cache import is_in_kev, get_kev_entry, _kev_set, _kev_meta
from scanner.sca_runner import _parse_trivy, _parse_npm_audit, _parse_pip_audit
from scanner.iac_runner import _parse_checkov, _parse_jsonlines
from scanner.semgrep_runner import _parse_semgrep


# ── EPSS ──────────────────────────────────────────────────────────────────────

class TestEpssRiskLevel:
    def test_critical(self):
        assert epss_risk_level(0.9) == "critical"

    def test_high(self):
        assert epss_risk_level(0.1) == "high"

    def test_medium(self):
        assert epss_risk_level(0.05) == "medium"

    def test_low(self):
        assert epss_risk_level(0.001) == "low"

    def test_none(self):
        assert epss_risk_level(0.0) == "none"

    def test_boundary_critical(self):
        assert epss_risk_level(0.5) == "critical"

    def test_boundary_high(self):
        assert epss_risk_level(0.1) == "high"


class TestChunked:
    def test_exact_multiple(self):
        result = list(_chunked([1, 2, 3, 4], 2))
        assert result == [[1, 2], [3, 4]]

    def test_remainder(self):
        result = list(_chunked([1, 2, 3], 2))
        assert result == [[1, 2], [3]]

    def test_empty(self):
        assert list(_chunked([], 5)) == []


# ── KEV cache ─────────────────────────────────────────────────────────────────

class TestKevCache:
    def setup_method(self):
        # Inject synthetic KEV data
        _kev_set.clear()
        _kev_set.add("CVE-2021-44228")
        _kev_meta["CVE-2021-44228"] = {
            "cve_id": "CVE-2021-44228",
            "vendor": "Apache",
            "product": "Log4j",
            "name": "Log4Shell",
            "due_date": "2021-12-24",
        }

    def teardown_method(self):
        _kev_set.clear()
        _kev_meta.clear()

    def test_is_in_kev_true(self):
        assert is_in_kev("CVE-2021-44228") is True

    def test_is_in_kev_false(self):
        assert is_in_kev("CVE-9999-00001") is False

    def test_case_insensitive(self):
        assert is_in_kev("cve-2021-44228") is True

    def test_get_entry(self):
        entry = get_kev_entry("CVE-2021-44228")
        assert entry is not None
        assert entry["vendor"] == "Apache"
        assert entry["due_date"] == "2021-12-24"

    def test_get_entry_missing(self):
        assert get_kev_entry("CVE-0000-00000") is None


# ── Trivy parser ──────────────────────────────────────────────────────────────

_TRIVY_DATA = {
    "Results": [
        {
            "Target": "requirements.txt",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2021-1234",
                    "PkgName": "requests",
                    "InstalledVersion": "2.25.0",
                    "FixedVersion": "2.27.0",
                    "Severity": "HIGH",
                    "Title": "Requests SSRF",
                    "Description": "SSRF vulnerability in requests",
                    "CweIDs": ["CWE-918"],
                    "References": [{"URL": "https://nvd.nist.gov/vuln/detail/CVE-2021-1234"}],
                }
            ],
        }
    ]
}


class TestTrivyParser:
    def test_parses_cve(self):
        findings = _parse_trivy(_TRIVY_DATA, "scan-001")
        assert len(findings) == 1
        f = findings[0]
        assert "CVE-2021-1234" in f.references
        assert f.raw_severity == "high"
        assert f.cwe_id == 918
        assert "requests" in (f.solution or "")

    def test_empty_results(self):
        assert _parse_trivy({"Results": []}, "scan-001") == []


# ── npm audit parser ──────────────────────────────────────────────────────────

_NPM_DATA = {
    "vulnerabilities": {
        "lodash": {
            "severity": "critical",
            "via": [
                {
                    "title": "Prototype Pollution",
                    "overview": "Lodash allows prototype pollution",
                    "cve": ["CVE-2020-8203"],
                    "url": "https://npmjs.com/advisories/1523",
                }
            ],
            "range": "<4.17.21",
        }
    }
}


class TestNpmAuditParser:
    def test_parses_vuln(self):
        findings = _parse_npm_audit(_NPM_DATA, "scan-002")
        assert len(findings) == 1
        f = findings[0]
        assert f.raw_severity == "critical"
        assert "CVE-2020-8203" in f.references

    def test_empty(self):
        assert _parse_npm_audit({"vulnerabilities": {}}, "scan-002") == []


# ── pip-audit parser ──────────────────────────────────────────────────────────

_PIP_DATA = [
    {
        "name": "django",
        "version": "3.2.0",
        "vulns": [
            {
                "id": "PYSEC-2021-99",
                "fix_versions": ["3.2.14"],
                "description": "SQL injection in QuerySet",
                "aliases": ["CVE-2021-9999"],
            }
        ],
    }
]


class TestPipAuditParser:
    def test_parses_vuln(self):
        findings = _parse_pip_audit(_PIP_DATA, "scan-003")
        assert len(findings) == 1
        f = findings[0]
        assert f.tool.value == "pip_audit"
        assert "CVE-2021-9999" in f.references
        assert "3.2.14" in (f.solution or "")

    def test_empty(self):
        assert _parse_pip_audit([], "scan-003") == []


# ── Checkov parser ────────────────────────────────────────────────────────────

_CHECKOV_STDOUT = json.dumps({
    "results": {
        "passed_checks": [],
        "failed_checks": [
            {
                "check_id": "CKV_AWS_21",
                "check_type": "terraform",
                "resource": "aws_s3_bucket.data",
                "file_path": "main.tf",
                "file_line_range": [10, 20],
                "check": {
                    "name": "Ensure S3 bucket has versioning enabled",
                    "guideline": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html",
                },
            }
        ],
    }
})


class TestCheckovParser:
    def test_parse_jsonlines_single(self):
        data = _parse_jsonlines(_CHECKOV_STDOUT)
        assert len(data) == 1

    def test_parses_failed_check(self):
        data = _parse_jsonlines(_CHECKOV_STDOUT)
        findings = _parse_checkov(data, "scan-004")
        assert len(findings) == 1
        f = findings[0]
        assert "CKV_AWS_21" in f.description
        assert f.tool.value == "checkov"
        assert "main.tf" in f.path

    def test_empty(self):
        assert _parse_checkov([{"results": {"failed_checks": []}}], "scan-004") == []


# ── Semgrep parser ────────────────────────────────────────────────────────────

_SEMGREP_DATA = {
    "results": [
        {
            "check_id": "python.lang.security.audit.formatted-sql-query.formatted-sql-query",
            "path": "app/db.py",
            "start": {"line": 42},
            "extra": {
                "severity": "ERROR",
                "message": "Detected SQL query formatted with user input. This could lead to SQL injection.",
                "lines": "cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
                "metadata": {
                    "cwe": ["CWE-89 - SQL Injection"],
                    "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
                },
            },
        }
    ]
}


class TestSemgrepParser:
    def test_parses_finding(self):
        findings = _parse_semgrep(_SEMGREP_DATA, "scan-005")
        assert len(findings) == 1
        f = findings[0]
        assert f.raw_severity == "high"
        assert f.cwe_id == 89
        assert f.tool.value == "semgrep"

    def test_empty(self):
        assert _parse_semgrep({"results": []}, "scan-005") == []
