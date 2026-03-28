# Digital Fortress Backend Skeleton

This backend skeleton implements the first development slice for Phase 0 and Phase 1:

- FastAPI API foundation.
- Tenant-aware request context.
- PostgreSQL RLS-ready SQL migration.
- Compliance mode and advanced monitoring toggles.
- Scanner orchestration endpoint stub.

## Quick start

1. Create a virtual environment and install dependencies.
2. Set environment variables:
   - `DATABASE_URL`
   - `JWT_SECRET`
   - `COMPLIANCE_MODE_DEFAULT` (`true` or `false`)
3. Start API:
   - `uvicorn app.main:app --reload`

## Important security notes

- Tenant isolation is enforced in DB by RLS policy in `sql/001_init.sql`.
- API sessions should set `app.current_tenant_id` for every request.
- Advanced attribution telemetry must be gated by explicit consent and compliance mode.
