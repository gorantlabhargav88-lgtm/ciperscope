# CiperScope Phase 7A — Complete Reality Audit

Read-only. No application code was modified to produce this document. Every claim below is traced to file:line evidence gathered by direct source reads and four parallel read-only research passes over the actual repository (branch `feature/ciperscope-hardening`, same verified state as the end of Phase 6.1). Where something could not be confirmed, it is explicitly marked **NOT VERIFIED FROM REPOSITORY** rather than assumed.

---

## A. Gmail Integration

**Status: REAL + PARTIAL**

- **Exact implementation**: `services/api/src/modules/integration/integration.routes.ts` (OAuth routes), `services/worker/src/integration/gmail-sync.ts` (sync worker), `packages/database/prisma/schema.prisma` (`Integration`, `Email` models).
- **Real execution path**: UI connect button → `GET /gmail/auth` (real `google.auth.OAuth2` + `generateAuthUrl`, scope `gmail.readonly` only) → Google consent → `GET /gmail/callback` (real token exchange, `Integration` row created) → `gmail.users.watch` → Google Pub/Sub push → `POST /gmail/webhook` (real, decodes Pub/Sub envelope) → real BullMQ `gmail-sync` job → `GmailSyncWorker` calls real `gmail.users.history.list`/`messages.get(format:'raw')` → decodes raw MIME → same `Email` creation + `email-processing` queue used by manual upload. Every step is real except the invalid/expired-historyId fallback, which logs "full sync (not fully implemented)" and silently skips re-fetching messages (real data-loss gap, not a stub of the whole feature).
- **Backend routes**: `GET/POST /api/v1/integrations/gmail/{auth,callback,webhook}`.
- **Service**: logic lives directly in route handlers (no separate service layer).
- **Worker**: `GmailSyncWorker`, queue `gmail-sync`, concurrency 2.
- **Database models**: `Integration` (plaintext `accessToken`/`refreshToken` columns — no encryption), `Email`.
- **External provider**: Google Gmail API + Pub/Sub, via `googleapis`.
- **Frontend**: `apps/web/src/pages/Integrations.tsx` — connect button only; no list/status/disconnect UI, and no `GET /integrations` endpoint exists for it to call.
- **Tests**: **NONE** — zero test files reference "gmail" anywhere in the repository.
- **Known limitations**: no disconnect/revoke endpoint at all; no proactive token-refresh-before-expiry (only opportunistic rotation-on-use via the SDK's `tokens` event); invalid-historyId path drops messages silently.
- **Security risks**: refresh/access tokens stored in **plaintext** in Postgres; OAuth `state` parameter is base64-encoded but **not signed/HMAC'd** (tenant-confusion/CSRF risk — a tampered state could attach a stolen auth code to a different `organizationId`); the webhook handler looks up `Integration` by `emailAddress` only, **not scoped by `organizationId`** (cross-tenant lookup risk); no Pub/Sub JWT/OIDC verification on the webhook (spoofable trigger, though blast radius is limited to enqueueing a sync for a real, already-connected integration).
- **Performance risks**: `messages.get` called serially per message, no batching.

## B. Email Ingestion

**Status: REAL + COMPLETE**

- Manual upload (`POST /api/v1/emails/ingest`) and Gmail sync both funnel into the same real pipeline: Fastify multipart (30MB hard limit enforced by the parser itself, not just app code) → streamed SHA-256 → tenant-scoped dedup (DB unique constraint) → `RawEmailStore` (local or S3) → `Email` row → `email-processing` BullMQ job.
- Tests: real integration tests exist (`services/api/src/modules/email/tests/ingestion.integration.test.ts`), live-DB.
- No known gaps beyond what's noted for Gmail's historyId fallback above.

## C. Authentication Analysis (SPF/DKIM/DMARC)

**Status: REAL (SPF, DMARC) + SCHEMA-ONLY/SIMULATED (DKIM)**

- SPF: real recursive RFC 7208 evaluator with real DNS resolution (`services/worker/src/verifier/SpfVerifier.ts`).
- DMARC: real DNS lookup + org-domain resolution (`psl`) + alignment logic (`DmarcVerifier.ts`).
- **DKIM: still simulated, unchanged from all prior phases.** `DkimVerifier.ts:67-88` performs a real DNS TXT public-key lookup but then explicitly skips cryptographic verification. Quoted from the file itself: *"In a full production implementation, we would perform exact simple/relaxed canonicalization... and use crypto.verify()... we will validate the structure... and simulate the cryptographic verification"* — the actual check is `signature.length > 32` / `bodyHash.length > 16`. No `crypto.verify()`/`createVerify` call exists anywhere in the file.
- This is enforced honestly downstream: `packages/api-client/src/client.ts` hard-injects `cryptographicallyVerified: false` on every DKIM row regardless of backend result, and this exact behavior is unit-tested (`packages/api-client/src/client.test.ts`, test *"injects cryptographicallyVerified: false on every DKIM row regardless of backend result"*).
- Frontend (`EmailAnalysis.tsx`) displays an explicit "NOT VERIFIED" banner on the DKIM panel.

## D. ML Classification

**Status: REAL (pretrained model, real inference), not a custom-trained model**

- Model: `spotproject/spot-distilbert-phishing`, a public pretrained HuggingFace checkpoint, pinned revision, loaded via `AutoModelForSequenceClassification`. **No fine-tuning evidence exists** in the repo — `services/ml-worker/eval/` contains only evaluation scripts (`evaluate.py`, `validate_dataset.py`), not a training pipeline or custom weights file. This must never be described as a custom-trained CiperScope model.
- Real inference path: tokenize → model forward → softmax → argmax → label mapping (`main.py:172-194`).
- Failure/timeout handling: real. `MLClassifier.ts` (Node side) calls the ML service with a 30s abort timeout; failures map to `TIMEOUT`/`FAILED` and are persisted honestly. `MLInference.status` defaults to `"NOT_AVAILABLE"` in the schema itself — signaling this is the expected common case when the service is unreachable.
- Worker/queue: real, `email-ml-classification` queue, feeds into `FusionEngine` for scoring.
- Tests: unit tests on the classifier/fusion logic exist; **no test exercises the actual ml-worker model load** from the Node side (would require the Python service running).

## E. Threat Scoring / P1-P2-P3 Priority

**Status: REAL + COMPLETE**

- `FusionEngine` computes a transparent, explainable additive score from real `RiskFactor` rows.
- `calculateThreatPriority()` (in `packages/types`, reused verbatim by both the frontend and — since Phase 5 — the backend's `GET /cases/:caseId/forensic-timeline` endpoint) is the single source of truth for P1/P2/P3. 27 unit tests cover every boundary. This is a deterministic operational policy, explicitly documented as not a scientifically validated model.

## F. CTI Enrichment

**Status: REAL + PARTIAL (2 of many possible providers)**

- Real HTTP integrations for exactly **two** providers: AbuseIPDB (IP reputation) and VirusTotal (domain/hash reputation), both with real API-key auth, real 5s timeouts, real 429→`rate_limited` mapping, real Redis caching (1-hour TTL).
- Fully automatic trigger chain: ingestion → auth → threat-analysis → `email-cti-enrichment` → IOC extraction (URLs/relay-hop IPs/attachment hashes, capped 50/10/10) → `ioc-cti-enrichment` per-indicator jobs → persisted `Indicator`/`ThreatIntelObservation`. No manual trigger needed.
- **Gap**: the SSRF-hardened `HttpClient` (`packages/http-client`, real `isPrivateIp`/DNS-rebinding-safe lookup/redirect validation) is **never actually used** by the CTI provider calls — they use raw global `fetch()` instead. Practical exposure is currently low (hardcoded provider hostnames), but the protected client is effectively dead code for its main intended purpose.
- **Gap**: no in-flight request coalescing — two concurrent lookups for the same indicator before the first completes both hit the external API.
- **Gap**: `IocNormalizer` does not filter private/reserved IPs before considering them for lookup.
- **Gap (flagged by security audit)**: `GET /emails/:emailId/threat-indicators` queries `ThreatIntelObservation` with no `organizationId` filter after the initial email-ownership check — since `Indicator`/`ThreatIntelObservation` are global (not per-org) tables by schema design, this is architecturally consistent (shared threat intel), but worth a deliberate design confirmation rather than an assumption.

## G. Geolocation

**Status: MISSING (100% null, always)**

- `CtiConfig.getGeoProvider` always wraps `NullGeoProvider`, whose `.lookup()` unconditionally returns `null`. No MaxMind/ip-api/ipinfo dependency exists anywhere in the repo.
- The surrounding `ReliableGeoProvider` (caching/circuit-breaker/timeout machinery) is architecturally complete but wraps a provider that can never produce real data — confirmed zero code path returns a non-null geolocation for any IP.
- Frontend correctly shows "No Geolocation data available" rather than fabricating a location.

## H. DKIM Verification

See §C — confirmed unchanged: DNS lookup real, cryptographic verification simulated.

## I. URL Analysis

**Status: REAL (extraction/heuristics) — no active fetching**

- `UrlExtractor.ts` extracts and analyzes URLs from text/HTML (obfuscation heuristics, normalization) but **never fetches** them — no redirect resolution, no screenshotting, no live reputation check beyond CTI indicator matching on the hostname string. This is a deliberate, honest scope (avoids an entire SSRF surface) but means "URL analysis" is static-only.

## J. Attachment Analysis

**Status: REAL + COMPLETE (for what it claims)**

- Real SHA-256, magic-byte MIME-mismatch detection, and genuine zip-bomb defenses: `MAX_ARCHIVE_ENTRIES = 1000`, `MAX_UNCOMPRESSED_SIZE = 50MB`, both enforced with early abort. Path-traversal entry names are detected/flagged (not exploitable since archives are never extracted to disk).

## K. Evidence Integrity (SHA-256)

**Status: REAL + COMPLETE**

- SHA-256 computed at ingestion time, `Evidence.sha256` has a DB-level unique constraint. Verified end-to-end across Phases 2-6.

## L. Chain of Custody

**Status: REAL + COMPLETE**

- `ChainOfCustodyEvent` append-only linked list (`previousEventId`), real actor attribution, real custody actions (COLLECTED/UPLOADED/HASHED/ANALYZED/EXPORTED/VERIFIED/ACCESSED/BLOCKCHAIN_ANCHORED). Live-tested via `GET /cases/:caseId/evidence/:evidenceId/custody`, surfaced in the frontend `ChainOfCustody.tsx` component (Phase 4). `BLOCKCHAIN_ANCHORED` is a real enum value but never actually reached by any code path (see §M).

## M. Blockchain Anchoring

**Status: SCHEMA-ONLY**

- `BlockchainAnchor` Prisma model + exactly one demo seed row (`network: 'HyperledgerFabric', status: 'PENDING'`) that no code ever transitions to `CONFIRMED`. `infra/blockchain/` is a genuinely empty directory. Zero web3/ethers/Hyperledger SDK code anywhere in the repository.
- **Assessment of value vs. SHA-256 + chain-of-custody**: the existing SHA-256 integrity + append-only custody linked list already provides tamper-evidence for anyone with DB access trust; a real blockchain anchor would only add value against a threat model where the *database itself* is not trusted (e.g., proving evidence wasn't altered by a privileged insider after the fact) — a meaningfully different and much larger undertaking (external chain client, key management, gas/transaction costs or a permissioned ledger to stand up). This is a genuine architecture decision, not a quick win.

## N. Automated Forensic Reporting

**Status: SCHEMA-ONLY**

- `Report` model + CRUD exists, but the caller must supply `contentHtml` directly — **no generation/PDF export/templating code exists anywhere.**

## O. Audit Logging

**Status: REAL + COMPLETE**

- `AuditLog` table, written on essentially every read/write route via `logAuditEvent()`, with `scrubMetadata()` stripping credential-like keys before persistence. Powers both the raw per-case activity log (`GET /cases/:caseId/timeline`) and (since Phase 5) the correlated unified forensic timeline.

## P. RBAC

**Status: REAL + COMPLETE**

- 13 enforced permission actions, single shared manifest (`packages/database/src/permissions.ts`), `SYSTEM_ADMIN` seeded with all 13 (Phase 1 fix), live-tested repeatedly (401/403/permission-denied paths) through Phase 6.1's 253 passing API tests.

## Q. Tenant Isolation

**Status: REAL + COMPLETE (one flagged exception)**

- Enforced at two layers: JWT `orgs` claim check (`rbac.ts`) before any DB access, and Prisma compound-unique-key lookups (`id_organizationId`) for case/email routes. Live-verified via dedicated 403 tests in every phase since Phase 5.
- **Flagged exception**: the Gmail webhook's `Integration` lookup by `emailAddress` alone, without `organizationId` scoping (§A).
- **Flagged for design confirmation, not necessarily a bug**: `ThreatIntelObservation` queries are global, not org-scoped (§F) — consistent with global threat-intel design, but should be a deliberate decision, not an oversight.

## R. Rate Limiting

**Status: REAL + PARTIAL**

- Genuinely Redis-backed (`INCR`/`EXPIRE`/`TTL`), with configurable fail-open (ingestion routes only, by explicit design comment) vs. fail-closed (unexpected errors → 503) behavior.
- **Gap**: only wired on `auth` and `email` routes (`multiRateLimit` grep-confirmed) — case/investigation/evidence read routes have no rate limiting at all.

## S. SSRF Protection

**Status: REAL infrastructure, PARTIALLY UNUSED**

- `packages/http-client` implements genuine SSRF hardening (private-IP blocking, DNS-rebinding-safe custom lookup, redirect re-validation) — but it is **not used** by the CTI provider calls, which use raw `fetch()` instead (see §F). No code path fetches attacker-controlled URLs from parsed emails at all (§I), which is the main mitigating factor.

## T. OAuth/Token Security

**Status: PARTIAL — see §A for full detail.**

- Real pino redaction list covers top-level `accessToken`/`refreshToken`/etc. keys; no call site was found logging a full token object. Plaintext DB storage and the unsigned OAuth `state` are the two concrete gaps.

## U. Background Workers

**Status: REAL + COMPLETE**

- Real BullMQ pipeline: `email-processing` → `email-authentication` → `email-threat-analysis` → `email-cti-enrichment` → (fan-out) `ioc-cti-enrichment` + `email-ml-classification`, plus `gmail-sync`. Real retry (3 attempts, exponential backoff), real Redis-backed idempotency locking (`SET NX EX` + Postgres `IdempotencyOperation`).

## V. Redis Queues

**Status: REAL, HARD DEPENDENCY**

- No in-memory/no-op fallback exists anywhere. If Redis is unreachable, queue construction and job enqueuing fail/hang — this is a genuine dependency, not degraded-mode software.

## W. PostgreSQL Persistence

**Status: REAL, HARD DEPENDENCY**

- `DATABASE_URL` has no default; config validation calls `process.exit(1)` outside test mode if it's missing/invalid. The application cannot start without Postgres.

---

## Gap Table

| Feature | Status | Real Backend | Real Frontend | External Dependency | Tests | Main Gap |
|---|---|---|---|---|---|---|
| Gmail OAuth + sync | REAL+PARTIAL | Yes | Connect-only | Google API | **None** | Plaintext tokens, unsigned state, org-unscoped webhook lookup, no disconnect |
| Email ingestion | REAL+COMPLETE | Yes | Yes | — | Yes (live) | None significant |
| SPF | REAL | Yes | Yes | DNS | Indirect | None |
| DMARC | REAL | Yes | Yes | DNS | Indirect | None |
| DKIM | SCHEMA-ONLY/SIMULATED | Partial (DNS only) | Honestly labeled | DNS | Yes (honesty test) | No real crypto.verify() |
| ML classification | REAL (pretrained) | Yes | Yes | HF model (public) | Partial | Not a custom-trained model; no fine-tuning evidence |
| Threat scoring / P1-P2-P3 | REAL+COMPLETE | Yes | Yes | — | Yes (27 tests) | None |
| CTI enrichment | REAL+PARTIAL | Yes (2 providers) | Yes | AbuseIPDB, VirusTotal | Partial | SSRF-hardened client unused; no dedup coalescing; only 2 providers |
| Geolocation | MISSING | No | Honestly empty | None | Indirect | 100% null, no real provider |
| URL analysis | REAL (static only) | Yes | Yes | — | Yes | Never fetches URLs (by design) |
| Attachment analysis | REAL+COMPLETE | Yes | Yes | — | Yes | None significant |
| Evidence integrity (SHA-256) | REAL+COMPLETE | Yes | Yes | — | Yes | None |
| Chain of custody | REAL+COMPLETE | Yes | Yes | — | Yes (live) | None |
| Forensic timeline (unified) | REAL+COMPLETE | Yes | Yes | — | Yes (live) | No pagination |
| Investigation workspace | REAL+PARTIAL | Yes | Yes | — | Partial | No dedicated case-detail route |
| Analyst decisions | REAL+COMPLETE | Yes | Yes | — | Yes (live) | None significant |
| Automated reporting | SCHEMA-ONLY | CRUD only | No | — | No | No generation/PDF logic |
| Blockchain anchoring | SCHEMA-ONLY | No | Honestly labeled | None | No | Zero client SDK |
| Audit logging | REAL+COMPLETE | Yes | Partial | — | Indirect | None |
| RBAC | REAL+COMPLETE | Yes | N/A (backend-authoritative) | — | Yes (live) | None |
| Tenant isolation | REAL+COMPLETE | Yes | N/A | — | Yes (live) | Gmail webhook lookup exception |
| Rate limiting | REAL+PARTIAL | Yes | N/A | Redis | Yes | Only auth + email routes covered |
| SSRF protection | REAL infra, partly unused | Partial | N/A | — | Yes (http-client) | CTI calls bypass it |

---

## 1. Top 10 highest-impact missing/incomplete capabilities
1. Gmail token encryption at rest (currently plaintext).
2. Gmail OAuth `state` signing (tenant-confusion risk).
3. Gmail webhook organizationId scoping.
4. Gmail disconnect/revoke endpoint (doesn't exist).
5. Route the CTI providers' HTTP calls through the already-built SSRF-hardened `HttpClient` instead of raw `fetch`.
6. Real DKIM cryptographic verification (highest-impact correctness gap, unchanged since the project's earliest audits).
7. Rate limiting on case/investigation/evidence routes.
8. Real geolocation provider (currently 100% absent).
9. Automated report generation (currently CRUD-only).
10. Gmail integration test coverage (currently zero).

## 2. Security-critical gaps
Gmail plaintext token storage; unsigned OAuth state; webhook tenant-scoping; CTI calls bypassing the SSRF-hardened client; rate-limiting coverage gaps on non-ingestion routes.

## 3. Data-integrity gaps
Gmail's invalid-historyId fallback silently drops messages instead of doing a real full resync (a genuine forensic gap — an investigator could be missing emails without any error surfaced).

## 4. Performance/scalability gaps
No in-flight CTI request coalescing (duplicate concurrent lookups double-hit external APIs); Gmail message fetches are serial, not batched; forensic-timeline endpoint has hard caps, not cursor pagination.

## 5. Demo/schema-only functionality
DKIM cryptographic verification, blockchain anchoring, automated report generation, geolocation.

## 6. Features already production-capable — must NOT be rewritten
Email ingestion pipeline, SPF/DMARC evaluators, attachment forensics (zip-bomb/path-traversal defenses), evidence integrity + chain of custody, the unified forensic timeline and its server-side correlation, RBAC, tenant isolation, audit logging, the BullMQ worker pipeline, threat scoring + P1/P2/P3, analyst decision recording — and, more surprisingly than expected, the **Gmail OAuth + incremental sync + shared-ingestion-pipeline** core, which is genuinely real end-to-end and should be hardened, not replaced.

## 7. Recommended implementation order
1. Gmail security hardening (encrypt tokens, sign state, scope webhook lookup, add disconnect) — small, high-impact, isolated.
2. Route CTI calls through the existing `HttpClient` — small, mechanical, closes a real gap with code that already exists.
3. Real DKIM cryptographic verification — the single most consequential correctness fix in the whole system.
4. Rate limiting expansion to remaining routes.
5. Geolocation real provider integration.
6. Automated report generation.
7. Blockchain anchoring — lowest priority; revisit only after an explicit threat-model discussion per §M.

---

## Testing status summary
44 test files repo-wide (~300-500 individual test cases, order of magnitude — not run/counted precisely in this audit). All `services/api` "integration" tests use Fastify's in-process `server.inject()` against a real server + live DB — **not** a true external-HTTP end-to-end test, and **none** cross API → queue → worker → DB → response in a single test. Zero Gmail tests. Zero frontend component-render tests (all `apps/web` tests are pure logic/data-transformation). **No CI/CD exists anywhere** (`.github` absent, no other CI config found) — nothing runs these tests automatically today.
