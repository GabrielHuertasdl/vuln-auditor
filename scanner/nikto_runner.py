"""Nikto scanner adapter — runs nikto as a subprocess and returns raw JSON."""
import asyncio
import json
import logging
import shutil
import urllib.parse
from pathlib import Path

from core.config import settings
from scanner.exceptions import ScannerExecutionError, SubprocessTimeoutError, ToolUnavailableError

log = logging.getLogger(__name__)


def _extract_host_port(target: str) -> tuple[str, str]:
    parsed = urllib.parse.urlparse(target)
    host = parsed.hostname or target
    port = str(parsed.port) if parsed.port else ("443" if parsed.scheme == "https" else "80")
    return host, port


async def run_nikto(target: str, scan_dir: Path) -> tuple[str, Path]:
    binary = shutil.which("nikto")
    if not binary:
        raise ToolUnavailableError("nikto")

    host, port = _extract_host_port(target)
    output_path = (scan_dir / "raw" / "nikto_raw.json").resolve()
    # Nikto appends .json automatically when -Format json is used,
    # so pass the stem only to avoid nikto_raw.json.json.
    # Use absolute path — some nikto versions fail with relative paths.
    output_arg = (scan_dir / "raw" / "nikto_raw").resolve()
    timeout = settings.scan_timeout_seconds

    log.info("Starting nikto scan on %s:%s", host, port)
    proc = await asyncio.create_subprocess_exec(
        binary,
        "-h", host,
        "-p", port,
        "-Format", "json",
        "-o", str(output_arg),
        "-nointeractive",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        raise SubprocessTimeoutError("nikto", timeout)

    # Nikto exits non-zero even on success in some versions; check file existence
    if not output_path.exists():
        stderr_text = stderr.decode() if stderr else ""
        raise ScannerExecutionError("nikto", proc.returncode or -1, stderr_text)

    raw_json = output_path.read_text(encoding="utf-8")
    log.info("Nikto scan complete, saved to %s", output_path)
    return raw_json, output_path
