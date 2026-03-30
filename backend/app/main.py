from fastapi import FastAPI

from app.api.routes.health import router as health_router
from app.api.routes.honeytokens import router as honeytokens_router
from app.api.routes.scans import router as scans_router
from app.api.routes.settings import router as settings_router
from app.core.config import settings
from app.middleware.tenant import TenantContextMiddleware

app = FastAPI(title=settings.app_name)
app.add_middleware(TenantContextMiddleware)

app.include_router(health_router, prefix=settings.api_prefix)
app.include_router(scans_router, prefix=settings.api_prefix)
app.include_router(settings_router, prefix=settings.api_prefix)
app.include_router(honeytokens_router, prefix=settings.api_prefix)
