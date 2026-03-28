from fastapi import APIRouter
from pydantic import BaseModel

from app.core.config import settings

router = APIRouter(prefix="/settings", tags=["settings"])


class ComplianceModeResponse(BaseModel):
    compliance_mode_default: bool
    note: str


@router.get("/compliance-mode", response_model=ComplianceModeResponse)
def get_compliance_mode() -> ComplianceModeResponse:
    return ComplianceModeResponse(
        compliance_mode_default=settings.compliance_mode_default,
        note="Advanced attribution telemetry must remain consent-gated per tenant.",
    )
