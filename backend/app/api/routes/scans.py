from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.db.models import Finding, ScanRun
from app.db.session import ensure_tenant_organization, get_db, set_tenant_context
from app.schemas.scan import ScanRunRequest, ScanRunResponse
from app.services.event_bus import publish_scan_completed_event
from app.services.orchestrator import orchestrate_scan

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("/run", response_model=ScanRunResponse)
def run_scan(payload: ScanRunRequest, request: Request, db: Session = Depends(get_db)) -> ScanRunResponse:
    tenant_id = request.state.tenant_id
    set_tenant_context(db, tenant_id)
    ensure_tenant_organization(db, tenant_id)

    started_at = datetime.now(timezone.utc)

    findings = orchestrate_scan(
        target_url=str(payload.target_url),
        include_nuclei=payload.include_nuclei,
        include_zap=payload.include_zap,
    )

    scan_run = ScanRun(
        tenant_id=tenant_id,
        target_url=str(payload.target_url),
        status="completed",
        findings_count=len(findings),
        started_at=started_at,
        completed_at=datetime.now(timezone.utc),
    )
    db.add(scan_run)

    for finding in findings:
        db.add(
            Finding(
                tenant_id=tenant_id,
                source=finding.source,
                severity=finding.severity,
                title=finding.title,
                description=finding.description,
            )
        )

    db.commit()
    db.refresh(scan_run)

    publish_scan_completed_event(
        tenant_id=tenant_id,
        scan_run_id=scan_run.id,
        target_url=str(payload.target_url),
        findings_count=len(findings),
    )

    return ScanRunResponse(scan_run_id=scan_run.id, tenant_id=tenant_id, findings=findings)
