# Phase 8: MIME & Email Header Forensics Implementation Plan

## 1. Current Architecture
Phase 7 established a robust ingestion pipeline where raw `.eml` files are securely uploaded, deduplicated, and stored locally. The worker currently verifies the integrity of the file and its storage references but performs no analysis. The database `Email` table tracks basic metadata (`sha256`, `organizationId`) but lacks deep forensic structure and an explicit analysis state machine.

## 2. Existing Reusable Components
- **`@ciperscope/storage`**: `RawEmailStore` for streaming the `.eml` bytes safely.
- **`@ciperscope/queue`**: Tenant-scoped worker wrapper and `IdempotencyManager` for reliable job execution.
- **`@ciperscope/logger`**: Request/trace context injection.
- **RBAC Plugin**: `requirePermission` system for API access control.

## 3. Required Database Changes
We must create a new Prisma migration (`phase8_forensics`) without bypassing history.
**New Enums:**
- `AnalysisState` (PENDING, PROCESSING, COMPLETED, PARTIAL, FAILED)
**Modified Models:**
- `Email`: Add `analysisStatus AnalysisState @default(PENDING)`. Add fields for structural extraction if needed.
- `EmailHeader`: Add `index Int` to preserve original order and duplicate headers.
- `RelayHop`: Add fields for parsing Received headers: `receivingHost`, `sendingHost`, `fromHost`, `byHost`, `protocol`, `parsedConfidence`.
**New Models:**
- `MimePart`: Hierarchical structure representing the MIME tree (`partIndex`, `contentType`, `contentDisposition`, `filename`, `contentId`, `transferEncoding`, `sizeBytes`, `isAttachment`).
- `EmailAddress`: Normalized representations of addresses from From, To, Cc, etc. (`headerName`, `displayName`, `address`, `localPart`, `domain`, `raw`).

## 4. Required Parser Components
We will implement an `EmailForensicParser` in a new package or within the worker service.
- **Library:** Use `mailparser` / `mailsplit` with strict forensic configuration (no network requests, no HTML rendering).
- **Header Parsing:** Maintain an ordered array of headers. Special logic to interpret `Received` hops and extract IPs, hosts, and timestamps.
- **MIME Parsing:** Recursive extraction of boundaries while strictly enforcing depth limits to prevent recursion exhaustion attacks.
- **Security Constraint:** Explicitly prohibit fetching remote images, DNS/WHOIS lookups, or executing JavaScript/attachments.

## 5. Required Queue/Worker Changes
- **Phase 8 Analysis Job:** The existing `email-processing` queue logic in `services/worker` will be expanded.
- **Workflow:** 
  1. Lock job via `IdempotencyManager`.
  2. Update `analysisStatus` to `PROCESSING`.
  3. Stream raw `.eml` from `RawEmailStore`.
  4. Pass stream to `EmailForensicParser`.
  5. Transactionally insert `EmailHeader`, `MimePart`, `EmailAddress`, and `RelayHop` records.
  6. Update `analysisStatus` to `COMPLETED` (or `FAILED` on error).

## 6. Required API Changes
Expose new GET endpoints in `@ciperscope/api` under `services/api/src/modules/email/`:
- `GET /api/v1/emails/:emailId/analysis` (summary & status)
- `GET /api/v1/emails/:emailId/headers` (ordered raw headers)
- `GET /api/v1/emails/:emailId/received-hops` (transport trace)
- `GET /api/v1/emails/:emailId/mime-parts` (tree structure)

*Security:* All endpoints will validate `x-organization-id`, check tenant ownership, and require the `EMAIL_READ` permission.

## 7. Required Web Changes
Upgrade `EmailAnalysis.tsx` in `apps/web`:
- Display **Header Forensics** (From, To, Subject, etc.).
- Display **Authentication Observations** (raw Authentication-Results, clearly marked as unverified until Phase 9).
- Display **Transport Trace** (timeline/graph of Received hops).
- Display **MIME Tree** (tree representation of the email's structure).

## 8. Required Mobile Changes
Update `apps/mobile/lib/features/email_analysis/` (Flutter):
- Implement screens or widgets for displaying basic headers, authentication observations, transport trace, and MIME summary.
- Note: This will be display-only, fetching from the backend API.

## 9. Security Boundaries
- **Local Parsing Only:** The parser operates strictly locally.
- **Observed Data:** All parsed fields are treated as *observations*, not truths. No external intelligence lookups will occur.
- **Resource Limits:** Maximum limits enforced for header count, header size, MIME nesting depth, and string lengths to prevent memory exhaustion and DoS.
- **SSRF Prevention:** Absolute restriction on network access during the parsing phase.

## 10. Test Strategy
- **Unit Tests:** Parser tests against raw `.eml` files with complex structures (nested MIME, Unicode, quoted-printable, malformed headers, massive nested parts).
- **Integration Tests:** Worker tests simulating end-to-end ingestion and parsing using real PostgreSQL and Redis.
- **Security Tests:** SSRF simulation testing to ensure malicious URLs/IPs in the email do not trigger outbound connections. Verify idempotency handling on failures.

## 11. Migration Strategy
1. Modify `schema.prisma`.
2. Generate migration (`pnpm --filter @ciperscope/database prisma migrate dev --name phase8_forensics`).
3. Apply migration to the local development DB.
4. Implement the changes incrementally, running existing Phase 1-7 regression tests at each step.
