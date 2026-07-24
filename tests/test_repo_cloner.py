"""Tests for core/repo_cloner.py."""
from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.repo_cloner import clone_repo


class TestCloneRepoValidation:
    async def test_rejects_file_url(self):
        with pytest.raises(ValueError, match="https://"):
            await clone_repo("file:///etc/passwd")

    async def test_rejects_ssh_url(self):
        with pytest.raises(ValueError, match="https://"):
            await clone_repo("git@github.com:user/repo.git")

    async def test_rejects_git_protocol(self):
        with pytest.raises(ValueError, match="https://"):
            await clone_repo("git://github.com/user/repo")

    async def test_rejects_bare_path(self):
        with pytest.raises(ValueError, match="https://"):
            await clone_repo("/home/user/myrepo")

    async def test_accepts_https_url(self):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))

        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=mock_proc)):
            result = await clone_repo("https://github.com/user/repo")
        assert isinstance(result, Path)
        # Cleanup
        import shutil
        shutil.rmtree(result, ignore_errors=True)


class TestCloneRepoSuccess:
    async def test_returns_path_on_success(self):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))

        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=mock_proc)) as mock_exec:
            result = await clone_repo("https://github.com/user/repo")

        assert isinstance(result, Path)
        assert result.exists()

        # Verify git args
        call_args = mock_exec.call_args[0]
        assert "git" in call_args
        assert "--depth=1" in call_args
        assert "--single-branch" in call_args
        assert "https://github.com/user/repo" in call_args

        import shutil
        shutil.rmtree(result, ignore_errors=True)

    async def test_tmpdir_prefix(self):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))

        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=mock_proc)):
            result = await clone_repo("https://example.com/repo")

        assert "vulnaudit-sast-" in result.name

        import shutil
        shutil.rmtree(result, ignore_errors=True)


class TestCloneRepoFailure:
    async def test_raises_runtime_error_on_nonzero_exit(self):
        mock_proc = MagicMock()
        mock_proc.returncode = 128
        mock_proc.communicate = AsyncMock(return_value=(b"", b"repository not found"))

        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=mock_proc)):
            with pytest.raises(RuntimeError, match="git clone failed"):
                await clone_repo("https://github.com/user/private-repo")

    async def test_cleans_tmpdir_on_failure(self):
        """Temp directory must not leak when clone fails."""
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.communicate = AsyncMock(return_value=(b"", b"error"))

        created_paths: list[Path] = []
        original_mkdtemp = __import__("tempfile").mkdtemp

        def capturing_mkdtemp(**kwargs):
            path = original_mkdtemp(**kwargs)
            created_paths.append(Path(path))
            return path

        with patch("tempfile.mkdtemp", side_effect=capturing_mkdtemp):
            with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=mock_proc)):
                with pytest.raises(RuntimeError):
                    await clone_repo("https://github.com/bad/repo")

        # The created tmpdir must have been cleaned up
        for p in created_paths:
            assert not p.exists(), f"Leaked tmpdir: {p}"

    async def test_raises_runtime_error_on_timeout(self):
        mock_proc = MagicMock()
        mock_proc.kill = MagicMock()
        mock_proc.wait = AsyncMock(return_value=None)
        # Simulate wait_for raising TimeoutError (communicate takes too long)
        mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError)

        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=mock_proc)):
            with pytest.raises(RuntimeError, match="timed out"):
                await clone_repo("https://github.com/slow/repo", timeout=1)
