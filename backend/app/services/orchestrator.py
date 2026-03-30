import json
import subprocess
from datetime import datetime, timezone

from app.core.config import settings
from app.schemas.scan import NormalizedFinding


class DigitalFortressScanner:
    def __init__(self, target_url: str):
        self.target = target_url

    def run_nuclei(self) -> str:
        docker_cmd = [
            "docker",
            "exec",
            settings.nuclei_docker_container,
            "nuclei",
            "-u",
            self.target,
            "-json",
            "-silent",
        ]
        host_cmd = ["nuclei", "-u", self.target, "-json", "-silent"]

        if settings.nuclei_use_docker:
            try:
                result = subprocess.run(docker_cmd, capture_output=True, text=True, check=False, timeout=600)
                if result.returncode == 0:
                    return result.stdout
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        try:
            result = subprocess.run(host_cmd, capture_output=True, text=True, check=False, timeout=600)
            if result.returncode == 0:
                return result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return ""

        return ""

    def run_zap(self) -> str:
        # TODO: Replace with ZAP API integration.
        return ""


def normalize_finding(tool_name: str, raw_data: dict) -> NormalizedFinding:
    info = raw_data.get("info", {}) if isinstance(raw_data.get("info"), dict) else {}
    title = info.get("name") or raw_data.get("name") or raw_data.get("template-id") or ""
    description = info.get("description") or raw_data.get("description") or ""
    severity = info.get("severity") or raw_data.get("severity") or "unknown"

    return NormalizedFinding(
        source=tool_name,
        severity=str(severity).lower(),
        title=str(title),
        description=str(description),
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
