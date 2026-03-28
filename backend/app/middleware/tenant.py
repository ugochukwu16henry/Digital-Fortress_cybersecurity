from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.core.config import settings


class TenantContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        tenant_id = request.headers.get("X-Tenant-ID")

        if settings.require_tenant_header and not tenant_id:
            return JSONResponse(
                status_code=400,
                content={"detail": "Missing X-Tenant-ID header."},
            )

        request.state.tenant_id = tenant_id
        return await call_next(request)
