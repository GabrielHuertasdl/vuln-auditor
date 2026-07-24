"""
Shallow git repo cloner for SAST analysis.

CALLER must delete the returned path in a finally block:
    shutil.rmtree(path, ignore_errors=True)
"""
from __future__ import annotations

import asyncio
import logging
import shutil
import tempfile
from pathlib import Path

log = logging.getLogger(__name__)


async def clone_repo(repo_url: str, timeout: int = 120) -> Path:
    """
    Shallow-clone a git repo into a fresh temp directory.
    Returns the Path of the cloned directory.

    Raises ValueError for non-https:// URLs (SSRF guard).
    Raises RuntimeError if git clone fails.
    """
    if not repo_url.startswith("https://"):
        raise ValueError(
            f"Only https:// repos are supported, got: {repo_url!r}"
        )

    tmpdir = Path(tempfile.mkdtemp(prefix="vulnaudit-sast-"))
    try:
        proc = await asyncio.create_subprocess_exec(
            "git", "clone",
            "--depth=1",
            "--single-branch",
            repo_url,
            str(tmpdir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise RuntimeError(
                f"git clone timed out after {timeout}s for {repo_url}"
            )

        if proc.returncode != 0:
            err = stderr.decode(errors="replace")[:400]
            raise RuntimeError(
                f"git clone failed (exit {proc.returncode}): {err}"
            )

        log.info("Cloned %s → %s", repo_url, tmpdir)
        return tmpdir

    except Exception:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise
