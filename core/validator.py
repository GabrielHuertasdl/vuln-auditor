"""
Target validation logic — prevents SSRF and unauthorized internal scanning.

Enterprise-grade auditors must ensure they only touch authorized external
targets or specific internal segments. This module provides guards against:
  - Scanning loopback addresses (127.0.0.1, localhost)
  - Scanning private/internal networks (RFC 1918)
  - Scanning link-local or multicast addresses
  - DNS rebinding (via IP resolution check)
"""
from __future__ import annotations

import ipaddress
import logging
import socket
import urllib.parse
from dataclasses import dataclass
from typing import Iterable

log = logging.getLogger(__name__)

@dataclass(frozen=True)
class ValidationResult:
    is_valid: bool
    reason: str | None = None
    resolved_ip: str | None = None

class TargetValidator:
    def __init__(
        self,
        allowed_hosts: Iterable[str] | None = None,
        blocked_hosts: Iterable[str] | None = None,
        allow_private_ips: bool = False,
    ) -> None:
        self.allowed_hosts = set(allowed_hosts or [])
        self.blocked_hosts = set(blocked_hosts or [])
        self.allow_private_ips = allow_private_ips

    def validate_url(self, url: str) -> ValidationResult:
        """
        Comprehensive URL validation.
        1. Parse URL structure.
        2. Check against explicit blocklists/allowlists.
        3. Resolve DNS and check against network boundaries.
        """
        try:
            parsed = urllib.parse.urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                return ValidationResult(False, "Invalid URL structure (missing scheme or host)")

            if parsed.scheme not in ("http", "https"):
                return ValidationResult(False, f"Unsupported scheme: {parsed.scheme}")

            hostname = parsed.hostname
            if not hostname:
                return ValidationResult(False, "Could not extract hostname")

            # 1. Explicit Hostname Checks
            if hostname in self.blocked_hosts:
                return ValidationResult(False, f"Hostname '{hostname}' is explicitly blocked")

            if self.allowed_hosts and hostname not in self.allowed_hosts:
                return ValidationResult(False, f"Hostname '{hostname}' is not in the allowlist")

            # 2. IP Resolution and Network Boundary Check
            try:
                # We use getaddrinfo to get all associated IPs
                addr_info = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
                ips = {info[4][0] for info in addr_info}
            except socket.gaierror:
                return ValidationResult(False, f"Could not resolve hostname: {hostname}")

            for ip_str in ips:
                try:
                    ip = ipaddress.ip_address(ip_str)
                except ValueError:
                    continue # Should not happen with getaddrinfo results

                # Security Guards
                if ip.is_loopback:
                    return ValidationResult(False, "Loopback addresses are not allowed")

                if ip.is_link_local:
                    return ValidationResult(False, "Link-local addresses are not allowed")

                if ip.is_multicast:
                    return ValidationResult(False, "Multicast addresses are not allowed")

                if not self.allow_private_ips and ip.is_private:
                    return ValidationResult(False, f"Private/Internal IP {ip_str} is not allowed")

            return ValidationResult(True, resolved_ip=list(ips)[0] if ips else None)

        except Exception as e:
            log.error("Unexpected error during target validation: %s", e)
            return ValidationResult(False, f"Internal validation error: {str(e)}")

# Global instance with default settings
validator = TargetValidator()
