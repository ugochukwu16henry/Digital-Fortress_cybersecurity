import json
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Honeytoken, Incident, ThreatActor
from app.db.session import ensure_tenant_organization, get_db, set_tenant_context
from app.schemas.honeytoken import (
    HoneytokenCallbackRequest,
    HoneytokenCallbackResponse,
    HoneytokenGenerateRequest,
    HoneytokenGenerateResponse,
)
from app.services.event_bus import publish_incident_created_event

router = APIRouter(prefix="/honeytokens", tags=["honeytokens"])


@router.post("/generate", response_model=HoneytokenGenerateResponse)
def generate_honeytoken(
    payload: HoneytokenGenerateRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> HoneytokenGenerateResponse:
    tenant_id = request.state.tenant_id
    set_tenant_context(db, tenant_id)
    ensure_tenant_organization(db, tenant_id)

    token_value = f"dfh_{secrets.token_urlsafe(24)}"
    now = datetime.now(timezone.utc)

    honeytoken = Honeytoken(
        tenant_id=tenant_id,
        token_value=token_value,
        target_hint=payload.target_hint,
        planted_at=now,
        is_active=True,
    )
    db.add(honeytoken)
    db.commit()
    db.refresh(honeytoken)

    return HoneytokenGenerateResponse(
        honeytoken_id=honeytoken.id,
        token_value=honeytoken.token_value,
        callback_path=f"/api/v1/honeytokens/callback/{honeytoken.token_value}",
        planted_at=honeytoken.planted_at,
    )


@router.post("/callback/{token_value}", response_model=HoneytokenCallbackResponse)
def honeytoken_callback(
    token_value: str,
    payload: HoneytokenCallbackRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> HoneytokenCallbackResponse:
    tenant_id = request.state.tenant_id
    set_tenant_context(db, tenant_id)
    ensure_tenant_organization(db, tenant_id)

    honeytoken = db.scalar(
        select(Honeytoken).where(
            Honeytoken.tenant_id == tenant_id,
            Honeytoken.token_value == token_value,
            Honeytoken.is_active.is_(True),
        )
    )
    if honeytoken is None:
        raise HTTPException(status_code=404, detail="Honeytoken not found or inactive")

    actor = db.scalar(
        select(ThreatActor).where(
            ThreatActor.tenant_id == tenant_id,
            ThreatActor.hardware_id == payload.hardware_id,
        )
    )

    now = datetime.now(timezone.utc)
    captured_ip = payload.captured_ip or (request.client.host if request.client else "")
    user_agent = payload.user_agent or request.headers.get("user-agent", "")

    if actor is None:
        actor = ThreatActor(
            tenant_id=tenant_id,
            hardware_id=payload.hardware_id,
            first_seen=now,
            last_seen=now,
            reputation_score=-10,
            known_vpns=captured_ip,
        )
        db.add(actor)
        db.flush()
    else:
        actor.last_seen = now
        actor.reputation_score = actor.reputation_score - 10
        known = {part for part in actor.known_vpns.split(",") if part}
        if captured_ip:
            known.add(captured_ip)
        actor.known_vpns = ",".join(sorted(known))

    incident = Incident(
        tenant_id=tenant_id,
        actor_id=actor.id,
        honeytoken_id=honeytoken.id,
        captured_ip=captured_ip,
        user_agent=user_agent,
        location_data=json.dumps(payload.location_data),
        created_at=now,
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)

    publish_incident_created_event(
        tenant_id=tenant_id,
        incident_id=incident.id,
        actor_id=actor.id,
        honeytoken_id=honeytoken.id,
    )

    return HoneytokenCallbackResponse(
        incident_id=incident.id,
        actor_id=actor.id,
        block_recommended=True,
    )
