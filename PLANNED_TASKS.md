# Digital Fortress Planned Tasks

This file converts the product roadmap into execution-ready tasks: what to build first, what to use, and how each phase is validated.

## 1) Build Order (What to Build First)

1. Program Guardrails and Architecture Baseline (Week 1)

- Build first because every later feature depends on policy, tenancy, and secure defaults.
- Output: threat model, consent model, data retention policy, tenant isolation rules, environment topology.

2. Core Platform Foundation (Weeks 1-3)

- Identity and multi-tenancy must exist before scanners, WAF, billing, and automation.
- Output: auth, RBAC, org onboarding, asset onboarding, event contracts, base database schema.

3. Scanner MVP + Command Center (Weeks 3-8)

- First revenue and proof-of-value milestone.
- Output: DAST/SAST scan triggers, normalized findings, real-time dashboard, triage workflow.

Priority insertion (Week 4): Hardware ID Engine

- Build a device fingerprint service for authorized, defensive attribution workflows.
- Output: stable hardware/browser fingerprint confidence score with consent and audit logging.

4. Site Shield and Bot Defense (Weeks 9-14)

- Turns visibility into active protection.
- Output: WAF policy management, bot scoring, challenge/block actions, rollback controls.

Priority insertion (Week 10): Third-Party API and Nth-Party Monitor

- Build an inventory graph for vendor scripts, SDKs, packages, and transitive dependencies.
- Output: supplier-risk alerts when an upstream package or service is compromised.

5. Deception + Dark Web Monitoring (Weeks 9-20, parallel tracks)

- Adds attribution and breach-intelligence differentiation.
- Output: honeytoken lifecycle, trigger pipeline, breach provider integrations, confidence scoring.

6. Automatic Kill Switch (Weeks 15-20)

- High-value automation for rapid containment.
- Output: policy engine, auto-actions, audit logs, recovery mechanisms.

Priority insertion (Week 16): JARM/TLS Profiler

- Add TLS handshake fingerprinting for tool-profile attribution in authorized environments.
- Output: enrichment signal indicating likely automation/tooling family.

7. Billing and Entitlements (Weeks 21-26)

- Productization and scale.
- Output: plan tiers, usage metering, Stripe, limits, upgrade paths.

8. AI-Assisted Remediation (Post-26 weeks)

- Start with safe recommendation mode before auto pull requests.
- Output: fix suggestions, Git provider integration, gated rollout controls.

## 2) Technology Choices (What to Use)

## Core App Stack

- Frontend: React + TypeScript
- UI: Tailwind CSS
- Realtime: Socket.io or WebSocket gateway
- Backend API: FastAPI (Python)
- Async jobs: Celery + Redis or RabbitMQ
- Database: PostgreSQL
- Cache/session/rate data: Redis
- API auth: JWT + refresh tokens + RBAC
- Cloud: AWS-first

## Security Engines and Integrations

- DAST: OWASP ZAP API
- Additional DAST templates: Nuclei
- SAST: provider adapter approach (Snyk or equivalent first integration)
- WAF: AWS WAF first adapter, optional NGINX + ModSecurity for self-managed mode
- Dark web monitoring: licensed commercial provider APIs from day 1
- Deception: honeytoken generator + callback ingestion service
- Geolocation/WHOIS enrichment: external enrichment API providers
- Supply-chain graph: CycloneDX SBOM + package manifest parser + dependency graph store
- Nth-party exposure intelligence: OSV + vendor advisory feeds + exploit intel connectors
- Attribution enrichment: JARM/TLS profiling, clock skew estimator, consent-based browser telemetry

## Platform Operations

- Containerization: Docker
- Orchestration: ECS Fargate or EKS
- CI/CD: GitHub Actions
- Observability: OpenTelemetry + Prometheus + Grafana + centralized logs
- Secrets: AWS Secrets Manager
- Object storage: Amazon S3 (reports, artifacts)
- Evidence locker: isolated sandbox workers + immutable evidence storage (S3 object lock)

## 3) Phase-by-Phase Task Backlog

## Phase 0: Program Setup and Guardrails

1. Define tenant security model and row-level data isolation.
2. Define legal/compliance policy for fingerprinting and deception modules.
3. Define consent UX and auditability requirements.
4. Finalize AWS account layout for dev/staging/prod.
5. Establish repo conventions, branching strategy, and release process.

Definition of done:

- Security and compliance baseline approved.
- Environment and deployment strategy documented.

## Phase 1: Core Foundation

1. Implement auth service (signup/login/invite/mfa-ready).
2. Implement RBAC roles: owner, admin, analyst, viewer.
3. Implement tenant and organization management.
4. Implement target onboarding (URL, domain, API target).
5. Create findings/event schema and migration scripts.
6. Create scan orchestration API contracts.

Definition of done:

- Multi-tenant users can onboard assets and call protected APIs.

## Phase 1A: Scanner MVP

1. Build ZAP adapter service and scan trigger endpoint.
2. Build Nuclei adapter for template-driven scans.
3. Build SAST adapter abstraction and first provider implementation.
4. Normalize scanner output to a shared findings model.
5. Implement severity mapping, deduplication v1, and scan history.
6. Add queue workers for scan jobs and retries.

Definition of done:

- Customer can run scans and view normalized findings by severity.

## Phase 1C: Proof of Exploit and Evidence Locker

1. Build isolated sandbox runner for safe exploit validation of selected findings.
2. Add exploit verification policy (allowed checks, blocked checks, target isolation rules).
3. Capture reproducible evidence artifacts (screenshots, logs, request/response traces).
4. Store artifacts in immutable evidence locker with retention policies.
5. Attach proof status to findings: unverified, verified, inconclusive.

Definition of done:

- High-risk findings can be validated with reproducible evidence and auditable chain-of-custody.

## Phase 1B: Command Center MVP

1. Build real-time event stream for scan and alert updates.
2. Build findings table with filtering and triage states.
3. Build timeline view linking events, findings, and responses.
4. Build high-level metrics cards and trend charts.
5. Add map view for event geospatial context.

Definition of done:

- Analysts can monitor, triage, and track incident flow in one dashboard.

## Phase 2: Site Shield and Bot Defense

1. Build WAF policy CRUD and deployment pipeline.
2. Implement rate-limiting policy presets.
3. Implement bot behavior scoring pipeline.
4. Implement challenge/block action engine.
5. Add simulation mode and rollback controls.

Definition of done:

- Policies can be deployed safely and reversed quickly.

## Phase 2A: Deception and Attribution

1. Build honeytoken templates (credential, link, file marker).
2. Build trigger callback API and validation pipeline.
3. Build enrichment pipeline (IP metadata, ASN, reputation signal).
4. Build actor correlation model linking repeated patterns.
5. Build attribution dashboard widgets.
6. Add TLS fingerprinting (JARM) enrichment for tool-signature attribution.
7. Add clock-skew analysis as a supporting geotemporal signal.
8. Add consent-based WebRTC leak-check telemetry in controlled and authorized scenarios.

Definition of done:

- Triggered tokens generate correlated, analyst-readable actor profiles.

## Phase 2C: Supply Chain and Nth-Party Risk Mapping

1. Build inventory graph for direct and transitive dependencies across code and runtime assets.
2. Ingest package manifests and generate SBOM snapshots per release.
3. Correlate vendor advisories, CVEs, and exploit signals to graph nodes.
4. Build customer alerting for supplier compromise and blast-radius impact.
5. Add remediation guidance with priority based on exposure and exploitability.

Definition of done:

- Customers receive early-warning alerts when upstream suppliers or dependencies are compromised.

## Phase 2B: Dark Web and Identity Monitoring

1. Integrate licensed breach-feed APIs.
2. Build scheduled ingestion and deduplication pipeline.
3. Add confidence scoring and signal prioritization.
4. Build customer alerting and remediation messaging.
5. Add evidence and timeline export for incidents.

Definition of done:

- Verified exposure events appear with confidence and actionable remediation.

## Phase 3: Automatic Kill Switch

1. Build policy-based response rules engine.
2. Implement automated actions: block, revoke, isolate, rotate.
3. Add idempotency and replay-safe execution handling.
4. Add action audit log with full traceability.
5. Add emergency recovery and rollback workflows.

Definition of done:

- High-confidence incidents trigger automatic containment with full audit traces.

## Phase 4: Monetization and Entitlements

1. Implement plan catalog: Guard, Hunter, Fortress.
2. Implement feature entitlements and usage limits.
3. Integrate Stripe checkout, subscriptions, invoices, webhooks.
4. Implement usage metering dashboards and overage handling.
5. Add free-trial and upgrade flows.

Definition of done:

- Customers can subscribe, use features by tier, and upgrade seamlessly.

## Phase 5: AI-Assisted Remediation

1. Implement finding-to-fix recommendation engine.
2. Implement framework-aware patch templates.
3. Integrate Git provider APIs for pull request generation.
4. Add human approval gate before PR creation in early rollout.
5. Track fix acceptance and regression metrics.
6. Add Shadow Fix mode: AI proposes fix, independent non-AI security engine validates before merge.
7. Add anti-poisoning checks for malicious training/context artifacts in code and prompts.

Definition of done:

- Platform proposes reliable code fixes and can open controlled PRs.

## 4) Parallel Team Plan

1. Platform Team

- Auth, tenancy, events, API contracts, core schema.

2. Detection Team

- DAST/SAST adapters, normalization, deduplication, proof-of-exploit sandbox.

3. Protection Team

- WAF engine, bot scoring, kill-switch automation.

4. Intelligence Team

- Dark web ingestion, confidence scoring, attribution correlation, supply-chain graph intelligence.

5. Frontend Team

- Command center UI, triage UX, map and analytics.

## 5) First 30 Days Sprint Tasks

## Sprint 1 (Days 1-14)

1. Set up repo structure and CI/CD.
2. Implement auth, RBAC, organization model.
3. Implement target onboarding endpoints.
4. Implement findings schema and migrations.
5. Implement scan orchestration API stubs.

## Sprint 2 (Days 15-30)

1. Integrate ZAP adapter and initial scan execution.
2. Integrate Nuclei adapter and result parsing.
3. Build dashboard shell with live event feed.
4. Build findings list with severity filters.
5. Add queue worker retries and failure handling.
6. Start hardware fingerprint confidence service (week 4 target) with consent and audit events.

Success metric at Day 30:

- A new tenant can sign in, add a target, run a scan, and see normalized findings in the dashboard.

## 6) Key Dependencies and Gate Rules

1. No active fingerprinting module ships without explicit customer consent controls.
2. No automatic kill switch rule ships without audit trail and rollback workflow.
3. No paid tier launches without entitlement enforcement and usage metering.
4. No AI remediation auto-PR launches without recommendation quality baseline and approval gates.
5. No proof-of-exploit sandbox runs against non-authorized targets or without strict isolation policy.
6. No AI-generated fix merges without Shadow Fix validation and anti-poisoning checks.

## 7) Immediate Next Build Command

Start with this exact build target:

- Build Phase 1 foundation plus Scanner MVP vertical slice:
  - Auth + tenancy + target onboarding
  - ZAP/Nuclei scan trigger
  - Findings normalization
  - Basic command center triage screen

Immediate implementation artifact (Python orchestrator skeleton):

```python
import json
import subprocess
from datetime import datetime


class DigitalFortressScanner:
  def __init__(self, target_url: str):
    self.target = target_url
    self.results = []

  def run_nuclei(self) -> str:
    cmd = ["nuclei", "-u", self.target, "-json"]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return result.stdout

  def run_zap(self) -> str:
    # TODO: call ZAP API adapter when wired into backend services.
    return ""


def normalize_finding(tool_name: str, raw_data: dict) -> dict:
  return {
    "source": tool_name,
    "severity": raw_data.get("severity", "unknown"),
    "description": raw_data.get("description", ""),
    "timestamp": datetime.utcnow().isoformat() + "Z",
  }


def orchestrate_scan(target_url: str) -> list[dict]:
  scanner = DigitalFortressScanner(target_url)
  normalized = []

  nuclei_raw = scanner.run_nuclei().splitlines()
  for line in nuclei_raw:
    if not line.strip():
      continue
    try:
      normalized.append(normalize_finding("nuclei", json.loads(line)))
    except json.JSONDecodeError:
      continue

  return normalized
```

Next coding step after this skeleton:

- Wrap this orchestrator behind a FastAPI endpoint and push normalized findings to the queue/event bus.

This gives the fastest route to a working, demoable, and monetizable core product.
