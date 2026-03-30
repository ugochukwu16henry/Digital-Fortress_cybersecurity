from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from app.services.bunkerweb import BunkerWebAPI

router = APIRouter(prefix="/bunkerweb", tags=["bunkerweb"])

class BlockRequest(BaseModel):
    ip: str
    reason: str = ""

class ChallengeRequest(BaseModel):
    ip: str
    reason: str = ""

@router.post("/block")
def block_ip(request: BlockRequest):
    api = BunkerWebAPI()
    if not api.block_ip(request.ip, request.reason):
        raise HTTPException(status_code=502, detail="BunkerWeb block failed")
    return {"status": "blocked", "ip": request.ip}

@router.post("/challenge")
def challenge_ip(request: ChallengeRequest):
    api = BunkerWebAPI()
    if not api.challenge_ip(request.ip, request.reason):
        raise HTTPException(status_code=502, detail="BunkerWeb challenge failed")
    return {"status": "challenged", "ip": request.ip}