"""Nmap scanner adapter — runs nmap as a subprocess and returns raw XML."""
import asyncio
import logging
import shutil
import urllib.parse
from pathlib import Path

from core.config import settings
from scanner.exceptions import ScannerExecutionError, SubprocessTimeoutError, ToolUnavailableError

log = logging.getLogger(__name__)


def _extract_host(target: str) -> str:
    parsed = urllib.parse.urlparse(target)
    return parsed.hostname or target


async def run_nmap(target: str, scan_dir: Path, scan_mode: str = "full") -> tuple[str, Path]:
    binary = shutil.which("nmap")
    if not binary:
        raise ToolUnavailableError("nmap")

    host = _extract_host(target)
    output_path = scan_dir / "raw" / "nmap_raw.xml"

    if scan_mode == "quick":
        flags = getattr(settings, "nmap_quick_flags", "-T4 -F").split()
        timeout = 120
    else:
        flags = settings.nmap_flags.split()
        timeout = settings.nmap_timeout

    log.info("Starting nmap scan on %s", host)
    proc = await asyncio.create_subprocess_exec(
        binary,
        "-oX", "-",
        *flags,
        host,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        raise SubprocessTimeoutError("nmap", timeout)

    if proc.returncode != 0:
        raise ScannerExecutionError("nmap", proc.returncode, stderr.decode())

    raw_xml = stdout.decode()
    output_path.write_text(raw_xml, encoding="utf-8")
    log.info("Nmap scan complete, saved to %s", output_path)
    return raw_xml, output_path
