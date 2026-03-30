from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, HttpUrl


class ScanRunRequest(BaseModel):
    target_url: HttpUrl
    include_zap: bool = True
    include_nuclei: bool = True


class NormalizedFinding(BaseModel):
    source: Literal["zap", "nuclei", "sast"]
    severity: str = Field(default="unknown")
    title: str = Field(default="")
    description: str = Field(default="")
    timestamp: datetime


class ScanRunResponse(BaseModel):
    scan_run_id: str
    tenant_id: str
    findings: list[NormalizedFinding]
