# Phase 17.2-Z: Investigation Intelligence Explainability, Provenance, & Analyst Decision Workflow

## Overview
This phase introduces a robust, resilient explainability layer to the existing Case Intelligence workflow. It ensures that every automated correlation is fully auditable and that analysts have a dedicated mechanism for reviewing, confirming, and escalating system-generated findings. The phase strictly avoided schema bloat by leveraging existing, scalable audit log architectures.

## Completed Capabilities

### 1. External Threat Intelligence Integration (CTI)
- Created a `ResilientCTIProvider` abstraction (`services/api/src/utils/cti.ts`) that mocks resilient interactions with external threat providers (e.g., VirusTotal, AbuseIPDB).
- Integrated hash enrichment directly into the intelligence aggregation pipeline.
- Implemented concurrent batch resolution (`Promise.all`) for hash lookups to maintain deterministic performance guarantees and bounded execution times.
- Designed the provider interface to gracefully degrade (`swallow and ignore`) on network failures without crashing the core Investigation workspace.

### 2. Provenance & Explainability
- Upgraded the correlation engine to embed strict `provenance` metadata arrays within each correlation finding.
- Provenance strictly maps back to exact `sourceType` (e.g., `EMAIL`, `EVIDENCE`, `EXTERNAL_CTI`), original `sourceId`, and specific matching fields (e.g., `sha256`, `senderAddress`).
- This allows analysts to verify *why* a correlation was flagged and precisely *where* the data originated in the underlying DB.

### 3. Analyst Decision Workflow
- Developed a new RESTful endpoint `POST /api/v1/cases/:caseId/investigations/:investigationId/decisions` enabling analysts to explicitly record decisions on intelligence targets (`REVIEWED`, `CONFIRMED`, `DISMISSED`, `ESCALATED`).
- Implemented `GET /api/v1/cases/:caseId/investigations/:investigationId/decisions` to retrieve a chronological, tenant-isolated history of all decisions made within an investigation context.
- Avoided unnecessary database migrations by heavily leveraging the existing `AuditLog` table, utilizing a new `CASE_INVESTIGATION_DECISION_RECORDED` event type for event-sourcing analytical actions.

## Engineering & Security Highlights
- **No Schema Bloat:** Zero database schema modifications were necessary; extended the application strictly via API logic and AuditLog reuse.
- **Tenant Isolation:** Enforced strict `x-organization-id` header validation and RBAC permission checks across all new endpoints.
- **Test Coverage:** Introduced comprehensive integration tests verifying the Analyst Decision workflow, ensuring proper data recording, retrieval, and cross-tenant isolation boundaries. All 236 monorepo tests pass.
- **Clean Baseline:** Maintained zero warnings on `git diff --check`.

## Next Steps
The Intelligence Pipeline now supports collection, correlation, enrichment, and human-in-the-loop validation. Future phases can expand on automated remediation actions based on these confirmed analyst decisions.
