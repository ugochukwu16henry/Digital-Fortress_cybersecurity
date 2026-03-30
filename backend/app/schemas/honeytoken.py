from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class HoneytokenGenerateRequest(BaseModel):
    target_hint: str = Field(default="", max_length=2048)


class HoneytokenGenerateResponse(BaseModel):
    honeytoken_id: str
    token_value: str
    callback_path: str
    planted_at: datetime


class HoneytokenCallbackRequest(BaseModel):
    hardware_id: str = Field(default="unknown", max_length=255)
    captured_ip: str | None = Field(default=None, max_length=45)
    user_agent: str | None = None
    location_data: dict[str, Any] = Field(default_factory=dict)


class HoneytokenCallbackResponse(BaseModel):
    incident_id: str
    actor_id: str
    block_recommended: bool
