from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.db.session import get_db, set_tenant_context
from app.schemas.scan import ScanRunRequest, ScanRunResponse
from app.services.orchestrator import orchestrate_scan

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("/run", response_model=ScanRunResponse)
def run_scan(payload: ScanRunRequest, request: Request, db: Session = Depends(get_db)) -> ScanRunResponse:
    tenant_id = request.state.tenant_id
    set_tenant_context(db, tenant_id)

    findings = orchestrate_scan(
        target_url=str(payload.target_url),
        include_nuclei=payload.include_nuclei,
        include_zap=payload.include_zap,
    )
    return ScanRunResponse(tenant_id=tenant_id, findings=findings)
