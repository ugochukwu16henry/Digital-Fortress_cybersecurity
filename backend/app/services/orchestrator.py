import json
import subprocess
from datetime import datetime, timezone

from app.schemas.scan import NormalizedFinding


class DigitalFortressScanner:
    def __init__(self, target_url: str):
        self.target = target_url

    def run_nuclei(self) -> str:
        cmd = ["nuclei", "-u", self.target, "-json"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return result.stdout

    def run_zap(self) -> str:
        # TODO: Replace with ZAP API integration.
        return ""


def normalize_finding(tool_name: str, raw_data: dict) -> NormalizedFinding:
    return NormalizedFinding(
        source=tool_name,
        severity=raw_data.get("severity", "unknown"),
        description=raw_data.get("description", ""),
        timestamp=datetime.now(timezone.utc),
    )


def orchestrate_scan(target_url: str, include_nuclei: bool = True, include_zap: bool = True) -> list[NormalizedFinding]:
    scanner = DigitalFortressScanner(target_url)
    normalized: list[NormalizedFinding] = []

    if include_nuclei:
        nuclei_raw = scanner.run_nuclei().splitlines()
        for line in nuclei_raw:
            if not line.strip():
                continue
            try:
                normalized.append(normalize_finding("nuclei", json.loads(line)))
            except json.JSONDecodeError:
                continue

    if include_zap:
        # Placeholder until ZAP adapter returns structured JSON.
        _ = scanner.run_zap()

    return normalized
