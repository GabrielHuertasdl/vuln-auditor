"""Disk-based persistence for scan results (MVP: no database)."""
import json
import logging
from pathlib import Path

from core.schemas import Finding, ScanResult

log = logging.getLogger(__name__)


class ScanStore:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.scans_dir = data_dir / "scans"
        self.scans_dir.mkdir(parents=True, exist_ok=True)

    def _scan_path(self, scan_id: str) -> Path:
        return self.scans_dir / scan_id

    def create_scan_dir(self, scan_id: str) -> Path:
        scan_dir = self._scan_path(scan_id)
        (scan_dir / "raw").mkdir(parents=True, exist_ok=True)
        return scan_dir

    def scan_exists(self, scan_id: str) -> bool:
        return self._scan_path(scan_id).exists()

    def get_raw_path(self, scan_id: str) -> Path:
        return self._scan_path(scan_id) / "raw"

    def _atomic_write(self, path: Path, content: str) -> None:
        tmp = path.with_suffix(".tmp")
        tmp.write_text(content, encoding="utf-8")
        tmp.replace(path)

    def save_scan_meta(self, result: ScanResult) -> None:
        meta = result.model_dump(exclude={"findings"})
        path = self._scan_path(result.scan_id) / "scan.json"
        self._atomic_write(path, json.dumps(meta, default=str, indent=2))

    def load_scan_meta(self, scan_id: str) -> ScanResult:
        path = self._scan_path(scan_id) / "scan.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        return ScanResult(**data)

    def save_findings(self, scan_id: str, findings: list[Finding]) -> None:
        path = self._scan_path(scan_id) / "normalized.json"
        data = [f.model_dump(mode="json") for f in findings]
        self._atomic_write(path, json.dumps(data, default=str, indent=2))

    def load_findings(self, scan_id: str) -> list[Finding]:
        path = self._scan_path(scan_id) / "normalized.json"
        if not path.exists():
            return []
        data = json.loads(path.read_text(encoding="utf-8"))
        return [Finding(**f) for f in data]

    def load_full_scan(self, scan_id: str) -> ScanResult:
        result = self.load_scan_meta(scan_id)
        result.findings = self.load_findings(scan_id)
        return result

    def save_report(self, scan_id: str, content: str) -> Path:
        path = self._scan_path(scan_id) / "report.md"
        self._atomic_write(path, content)
        return path

    def load_report(self, scan_id: str) -> str:
        path = self._scan_path(scan_id) / "report.md"
        return path.read_text(encoding="utf-8")
