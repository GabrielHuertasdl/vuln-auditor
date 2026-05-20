"""OWASP ZAP scanner adapter — uses ZAP REST API (local daemon or remote)."""
import asyncio
import json
import logging
import shutil
import urllib.parse
from pathlib import Path

import httpx

from core.config import settings
from scanner.exceptions import ScannerExecutionError, SubprocessTimeoutError, ToolUnavailableError

log = logging.getLogger(__name__)

_ZAP_DAEMON_PORT = 8090


async def _wait_for_zap(base_url: str, retries: int = 30) -> None:
    async with httpx.AsyncClient() as client:
        for _ in range(retries):
            try:
                r = await client.get(f"{base_url}/JSON/core/view/version/", timeout=2)
                if r.status_code == 200:
                    return
            except Exception:
                pass
            await asyncio.sleep(2)
    raise ScannerExecutionError("zap", -1, "ZAP daemon did not become ready in time")


async def _poll_until_done(client: httpx.AsyncClient, status_url: str, scan_id_str: str, timeout: int) -> None:
    elapsed = 0
    while elapsed < timeout:
        r = await client.get(status_url, params={"scanId": scan_id_str}, timeout=10)
        status = r.json().get("status", "0")
        if status == "100":
            return
        await asyncio.sleep(3)
        elapsed += 3
    log.warning("ZAP scan %s did not finish within %ds, collecting partial results", scan_id_str, timeout)


async def run_zap(target: str, scan_dir: Path) -> tuple[str, Path]:
    zap_url = settings.zap_api_url
    daemon_proc: asyncio.subprocess.Process | None = None

    if not zap_url:
        binary = shutil.which("zap.sh") or shutil.which("zaproxy")
        if not binary:
            raise ToolUnavailableError("zap")
        zap_url = f"http://127.0.0.1:{_ZAP_DAEMON_PORT}"
        log.info("Starting ZAP daemon on port %d", _ZAP_DAEMON_PORT)
        daemon_proc = await asyncio.create_subprocess_exec(
            binary,
            "-daemon",
            "-host", "127.0.0.1",
            "-port", str(_ZAP_DAEMON_PORT),
            "-config", "api.disablekey=true",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await _wait_for_zap(zap_url)

    output_path = scan_dir / "raw" / "zap_raw.json"

    try:
        async with httpx.AsyncClient(base_url=zap_url, timeout=30) as client:
            # Spider
            r = await client.get("/JSON/spider/action/scan/", params={"url": target, "recurse": "true"})
            spider_id = r.json().get("scan", "0")
            await _poll_until_done(client, "/JSON/spider/view/status/", spider_id, settings.zap_spider_timeout)

            # Active scan
            r = await client.get("/JSON/ascan/action/scan/", params={"url": target, "recurse": "true"})
            ascan_id = r.json().get("scan", "0")
            await _poll_until_done(client, "/JSON/ascan/view/status/", ascan_id, settings.zap_ascan_timeout)

            # Collect alerts
            r = await client.get(
                "/JSON/alert/view/alerts/",
                params={"baseurl": target, "start": "0", "count": "5000"},
            )
            raw_data = r.json()
    finally:
        if daemon_proc:
            try:
                async with httpx.AsyncClient(base_url=zap_url, timeout=5) as c:
                    await c.get("/JSON/core/action/shutdown/")
            except Exception:
                pass
            daemon_proc.kill()

    raw_json = json.dumps(raw_data, indent=2)
    output_path.write_text(raw_json, encoding="utf-8")
    log.info("ZAP scan complete, %d alerts, saved to %s", len(raw_data.get("alerts", [])), output_path)
    return raw_json, output_path
