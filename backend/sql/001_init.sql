-- Digital Fortress baseline schema and RLS policies.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS tenant_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    compliance_mode BOOLEAN NOT NULL DEFAULT TRUE,
    advanced_monitoring_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    notice_required BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scan_targets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    target_type VARCHAR(32) NOT NULL,
    target_value VARCHAR(2048) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    source VARCHAR(32) NOT NULL,
    severity VARCHAR(16) NOT NULL DEFAULT 'unknown',
    title VARCHAR(255) NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    target_url VARCHAR(2048) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'completed',
    findings_count INTEGER NOT NULL DEFAULT 0,
    error_message TEXT NOT NULL DEFAULT '',
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS threat_actors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    hardware_id VARCHAR(255) NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reputation_score INTEGER NOT NULL DEFAULT 0,
    known_vpns TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS honeytokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    token_value VARCHAR(255) NOT NULL UNIQUE,
    target_hint VARCHAR(2048) NOT NULL DEFAULT '',
    planted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    actor_id UUID REFERENCES threat_actors(id) ON DELETE SET NULL,
    honeytoken_id UUID REFERENCES honeytokens(id) ON DELETE SET NULL,
    captured_ip VARCHAR(45) NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    location_data TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE tenant_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_actors ENABLE ROW LEVEL SECURITY;
ALTER TABLE honeytokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_settings_isolation ON tenant_settings;
CREATE POLICY tenant_settings_isolation ON tenant_settings
USING (tenant_id::text = current_setting('app.current_tenant_id', true));

DROP POLICY IF EXISTS scan_targets_isolation ON scan_targets;
CREATE POLICY scan_targets_isolation ON scan_targets
USING (tenant_id::text = current_setting('app.current_tenant_id', true));

DROP POLICY IF EXISTS findings_isolation ON findings;
CREATE POLICY findings_isolation ON findings
USING (tenant_id::text = current_setting('app.current_tenant_id', true));

DROP POLICY IF EXISTS scan_runs_isolation ON scan_runs;
CREATE POLICY scan_runs_isolation ON scan_runs
USING (tenant_id::text = current_setting('app.current_tenant_id', true));

DROP POLICY IF EXISTS threat_actors_isolation ON threat_actors;
CREATE POLICY threat_actors_isolation ON threat_actors
USING (tenant_id::text = current_setting('app.current_tenant_id', true));

DROP POLICY IF EXISTS honeytokens_isolation ON honeytokens;
CREATE POLICY honeytokens_isolation ON honeytokens
USING (tenant_id::text = current_setting('app.current_tenant_id', true));

DROP POLICY IF EXISTS incidents_isolation ON incidents;
CREATE POLICY incidents_isolation ON incidents
USING (tenant_id::text = current_setting('app.current_tenant_id', true));
