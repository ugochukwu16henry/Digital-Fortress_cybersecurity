# Digital Fortress Backend Skeleton

This backend skeleton implements the first development slice for Phase 0 and Phase 1:

- FastAPI API foundation.
- Tenant-aware request context.
- PostgreSQL RLS-ready SQL migration.
- Compliance mode and advanced monitoring toggles.
- Scanner orchestration endpoint stub.
- Scan run persistence and finding storage.
- Structured scan and incident event emission through Redis.
- Honeytoken generator and callback ingestion endpoints.

## Quick start

1. Create a virtual environment and install dependencies.
2. Set environment variables:
   - `DATABASE_URL`
   - `JWT_SECRET`
   - `COMPLIANCE_MODE_DEFAULT` (`true` or `false`)
3. Start API:
   - `uvicorn app.main:app --reload`

## Run with Docker Compose wrapper

From repository root:

- `docker compose -f docker-compose.digital-fortress.yml up --build`

This starts:

- `bw` (BunkerWeb)
- `scanner` (Nuclei container)
- `db` (PostgreSQL with baseline schema init)
- `redis` (event bus pub/sub)
- `api` (FastAPI backend)

## New API endpoints

- `POST /api/v1/scans/run`
- `POST /api/v1/honeytokens/generate`
- `POST /api/v1/honeytokens/callback/{token_value}`

## Important security notes

- Tenant isolation is enforced in DB by RLS policy in `sql/001_init.sql`.
- API sessions should set `app.current_tenant_id` for every request.
- Advanced attribution telemetry must be gated by explicit consent and compliance mode.
