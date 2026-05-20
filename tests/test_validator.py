"""Tests for the TargetValidator component."""
import pytest
from core.validator import TargetValidator

def test_validator_blocks_loopback():
    v = TargetValidator()
    result = v.validate_url("http://127.0.0.1")
    assert result.is_valid is False
    assert "Loopback" in result.reason

def test_validator_blocks_private_ip():
    v = TargetValidator(allow_private_ips=False)
    result = v.validate_url("http://192.168.1.1")
    assert result.is_valid is False
    assert "Private/Internal IP" in result.reason

def test_validator_allows_authorized_external():
    v = TargetValidator()
    # example.com resolves to public IPs
    result = v.validate_url("https://example.com")
    assert result.is_valid is True

def test_validator_explicit_blocklist():
    v = TargetValidator(blocked_hosts=["evil.com"])
    result = v.validate_url("http://evil.com")
    assert result.is_valid is False
    assert "explicitly blocked" in result.reason

def test_validator_allowlist_mode():
    v = TargetValidator(allowed_hosts=["good.com"])
    assert v.validate_url("http://good.com").is_valid is True
    assert v.validate_url("http://other.com").is_valid is False
    assert "not in the allowlist" in v.validate_url("http://other.com").reason
