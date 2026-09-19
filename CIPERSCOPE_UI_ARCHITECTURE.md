# CiperScope UI Architecture — Phase 1 Audit & Implementation Plan

Generated from a direct source-code audit (not from the repo's own `docs/PHASE_30_*` / `docs/MASTER_*` reports, which describe capabilities more optimistically than the code supports). Every claim below was verified against `services/api`, `services/worker`, `services/ml-worker`, `packages/database/prisma/schema.prisma`, and `apps/web/src`.

## 1. Executive summary

The backend is genuinely mature: real RBAC, real JWT/session/refresh-token security, a real SPF/DMARC evaluator, real SHA-256-based evidence integrity and chain-of-custody, a real (if unweighted-by-training) DistilBERT ML classifier with honest fail-closed behavior, and a real AbuseIPDB/VirusTotal CTI integration. This is not a toy backend.

The frontend, by contrast, is a thin shell: **12 of 21 defined routes render a generic `PlaceholderPage`**. The pages that do exist (`Overview`, `EmailAnalysis`, `Alerts`, `Cases`, `Integrations`, `InvestigationWorkspace`) are functional but inconsistent (mixed data-fetching patterns, `any`-typed API responses, duplicated inline severity-badge logic, two unused component files, a broken/half-wired Tailwind theme, dead code such as `DemoModeBanner` and `ThreatScore`/`SeverityBadge`/`IntegrityBadge`).

Three of the shared `packages/*` the monorepo layout implies (`types`, `api-client`, `ui`) are **completely empty** — not partially built, empty. `apps/web` imports nothing from `@ciperscope/*`. This means: no shared types today, and building them is part of this redesign, not a pre-existing asset to "integrate."

Some backend capabilities the product spec asks the UI to represent are **schema-only or explicitly simulated**, and the UI must not present them as live:
- **DKIM "verification"** is a length-based simulation, not cryptographic (`services/worker/src/verifier/DkimVerifier.ts`).
- **Blockchain evidence anchoring** exists only as a Prisma model + demo seed row; no code path ever creates a real anchor.
- **Geolocation** has a full provider abstraction but the only implementation (`NullGeoProvider`) always returns `null` — there is no live IP geolocation anywhere in the pipeline today.
- **CTI verdicts** depend on optional API keys; without them, verdicts are `UNKNOWN`/`not_configured`, not fabricated.
- **No P1/P2/P3 vocabulary exists anywhere in the codebase.** The real severity vocabulary is `Priority` enum = `LOW | MEDIUM | HIGH | CRITICAL` (on `Case`, `RiskAssessment.riskLevel`) and a separate `AlertSeverity` = `INFO | LOW | MEDIUM | HIGH | CRITICAL` (on `Alert` only). The redesign will present these as **P1 (Critical) / P2 (High) / P3 (Medium+Low)** in the UI layer as a presentation mapping, without inventing a new backend concept.
- **No WebSocket/SSE exists.** Any "live activity feed" must poll `GET /api/v1/dashboard/overview` (currently the only dashboard endpoint) or be explicitly labeled as demo/simulated per product rule #16.
- **No search endpoint, no settings endpoints, no report-generation code, no report PDF export** — these need new backend work; the UI will ship clearly-labeled "not yet available" states, not fake ones.

## 2. Verified backend capability matrix

| Capability | Status | Evidence |
|---|---|---|
| Auth (login/refresh/logout/me), JWT+session+RBAC | **Real** | `services/api/src/modules/auth`, `plugins/rbac.ts` |
| Email ingest + forensic parsing (headers, MIME, relay hops, addresses) | **Real** | `email.routes.ts`, `EmailForensicParser.ts` (mailparser) |
| SPF | **Real** (RFC 7208 hand-rolled evaluator) | `SpfVerifier.ts` |
| DMARC | **Real** (org-domain + alignment) | `DmarcVerifier.ts` |
| DKIM | **Simulated** (length check, not crypto) | `DkimVerifier.ts` L67-87 |
| URL extraction + obfuscation heuristics | **Real** (deterministic rules, no reputation scoring here) | `UrlExtractor.ts` |
| Attachment analysis (SHA-256, magic-byte sniffing, zip-bomb/path-traversal checks) | **Real** | `AttachmentAnalyzer.ts` |
| ML classification (DistilBERT phishing model) | **Real**, but pulls a public HF model with no fine-tuned weights; fails closed to `NOT_AVAILABLE` | `services/ml-worker`, `MLClassifier.ts` |
| Threat scoring / risk level (`FusionEngine`) | **Real, transparent additive formula** | `services/worker/src/analyzer/FusionEngine.ts` |
| CTI (AbuseIPDB, VirusTotal) | **Real**, requires API keys, Redis-cached | `packages/providers/src/cti/index.ts` |
| Evidence SHA-256 + chain of custody | **Real** (append-only linked list, DB-enforced uniqueness) | `ingestion.service.ts`, `ChainOfCustodyEvent` model |
| Blockchain evidence anchor | **Schema-only / demo seed only** | `BlockchainAnchor` model, `seed.ts` |
| Geolocation | **Abstraction exists, no live implementation** (`NullGeoProvider`) | `ReliableGeoProvider.ts`, `NullProvider.ts` |
| Gmail OAuth connect + webhook + sync | **Real** (googleapis, real token storage, BullMQ-driven sync) | `integration.routes.ts`, `gmail-sync.ts` |
| Investigation "intelligence" / correlation | **Real, computed in-request** (hash match, shared sender, CTI hash match against already-persisted observations) | `case.routes.ts` intelligence endpoint |
| Reports | **CRUD only** — caller supplies `contentHtml`; no generation/PDF export exists | `Report` model, no report-generation code anywhere |
| Search | **Does not exist** | grep-confirmed, no `/search` route |
| Settings | **Does not exist** (`SystemSetting` model unused by any route) | — |
| WebSocket/SSE/live push | **Does not exist** | grep-confirmed |
| Priority vocabulary | **`LOW/MEDIUM/HIGH/CRITICAL` only** — no P1/P2/P3 in code | `schema.prisma` `enum Priority` |

## 3. Data model → UI field mapping (verbatim enum values)

These are the actual Prisma enum values; the frontend's presentation layer must map onto them exactly rather than inventing new ones.

- `Priority`: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` → UI: P3 (Low), P3 (Medium) *or split as its own tier*, P2 (High), P1 (Critical). **Decision needed** — see §9.
- `AlertSeverity` (separate enum, only on `Alert`): `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
- `CaseStatus`: `OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `CLOSED`
- `EmailClassification`: `UNKNOWN`, `LEGITIMATE`, `SUSPICIOUS`, `PHISHING`, `IMPERSONATION`, `BEC`, `FRAUD`, `MALWARE`
- `AuthResultStatus` (SPF/DKIM/DMARC): `PASS`, `FAIL`, `SOFTFAIL`, `NEUTRAL`, `NONE`, `TEMPERROR`, `PERMERROR`
- `IndicatorType`: `IP`, `DOMAIN`, `URL`, `HASH`, `EMAIL_ADDRESS`, `ASN`
- `ThreatVerdict`: `CLEAN`, `SUSPICIOUS`, `MALICIOUS`, `UNKNOWN`
- `EvidenceType`: `RAW_EMAIL`, `HEADER`, `ATTACHMENT`, `URL`, `IP`, `DOMAIN`, `SCREENSHOT`, `REPORT`, `LOG`, `OTHER`
- `EvidenceStatus`: `ACTIVE`, `ARCHIVED`, `DELETED`
- `CustodyAction`: `COLLECTED`, `UPLOADED`, `HASHED`, `ANALYZED`, `EXPORTED`, `VERIFIED`, `BLOCKCHAIN_ANCHORED`, `ACCESSED`
- `BlockchainAnchorStatus`: `PENDING`, `SUBMITTED`, `CONFIRMED`, `FAILED`, `VERIFICATION_FAILED` (display as "Chain of Custody / Evidence Integrity", never claim a real anchor exists)
- `AnalysisState`: `PENDING`, `PROCESSING`, `COMPLETED`, `PARTIAL`, `FAILED`

Route → resource map (see full inventory in the audit output already collected this session): `/api/v1/{auth,emails,cases,alerts,investigations,evidence,dashboard,integrations}`. There is no standalone IP-intelligence, domain-intelligence, or IOC-CRUD endpoint — indicators only surface nested inside case "intelligence" and email "threat-indicators."

## 4. Current frontend state (routes)

| Path | Component | Real / Stub |
|---|---|---|
| `/login` | `Login.tsx` | Real |
| `/overview` | `Overview.tsx` | Real (dashboard) |
| `/investigations`, `/investigations/:id` | `PlaceholderPage` | Stub |
| `/alerts` | `Alerts.tsx` | Real |
| `/cases` | `Cases.tsx` | Real |
| `/cases/:caseId/investigations/:investigationId/workspace` | `InvestigationWorkspace.tsx` | Real |
| `/email-analysis`, `/email-analysis/:id` | `EmailAnalysis.tsx` | Real (`:id` unused) |
| `/indicators`, `/infrastructure`, `/geo-intelligence` | `PlaceholderPage` | Stub |
| `/evidence`, `/evidence/:id`, `/chain-of-custody`, `/verification` | `PlaceholderPage` | Stub |
| `/timeline` | `PlaceholderPage` | Stub |
| `/reports`, `/analytics` | `PlaceholderPage` | Stub |
| `/integrations`, `/settings/integrations` | `Integrations.tsx` | Real |
| `/audit-log`, `/users`, `/settings` | `PlaceholderPage` | Stub |

Known defects to fix as part of the redesign (not before): missing `/unauthorized` route, dead `auth:unauthorized` listener, unreachable `VITE_API_URL` fallback string bug in `EmailAnalysis.tsx`, two colliding `Badge` exports (`ui/badge.tsx` vs `ui/Badges.tsx`), unused `recharts` dependency, non-functional `CommandPalette`/header search/notification bell, half-wired Tailwind theme (`index.css` HSL vars not mapped into `tailwind.config.js`).

## 5. Design system plan

Keep and consolidate what exists rather than replacing it:
- Fix the Tailwind/shadcn variable wiring (map `--background`, `--primary`, etc. into `tailwind.config.js` `colors`, or migrate fully to Tailwind v4 `@theme` syntax — pick one, not both).
- Promote the existing `security.*` semantic tokens (critical/high/medium/low/info/verified) to be the single source of truth for severity color, and delete the ad hoc inline Tailwind color classes duplicated across `Overview`, `Alerts`, `Cases`, `EmailAnalysis`.
- Merge `ui/badge.tsx` and `ui/Badges.tsx` into one badge module; wire the currently-dead `ThreatScore`/`SeverityBadge`/`IntegrityBadge` into real usage instead of the duplicated inline logic.
- Add the missing primitives the app is hand-rolling today: `Table`, `Dialog`, `Input`, `Select`, `Tabs`, `Tooltip`, `Toast`. No new dependency is required to be idiomatic here, but `class-variance-authority` + minimal Radix primitives (`@radix-ui/react-dialog`, `-tabs`, `-tooltip`, `-select`) are the natural, low-risk additions given the existing shadcn-style pattern.
- Introduce a `PriorityBadge` component that maps `Priority`/`AlertSeverity` enum values to the P1/P2/P3 presentation layer described in §9, so "P1/P2/P3" stays a UI-only concept layered over real enum data.
- Populate `packages/types` with hand-written types re-exported from `@prisma/client` (via `packages/database`) plus API response DTOs, and have `apps/web` depend on it — closing the "empty shared package" gap identified in the audit.

## 6. Component architecture (target)

```
apps/web/src/components/
  layout/        AppLayout, Sidebar, Header, Breadcrumbs (existing, refine)
  ui/            Button, Card, Badge, Alert, Table, Dialog, Input, Select, Tabs, Tooltip, Toast (consolidate)
  dashboard/     StatCard, PriorityDistribution, ThreatActivityFeed, RecentIncidents
  threats/       PriorityBadge, ThreatScore, SeverityIndicator, ThreatFactorList
  email/         EmailHeaderPanel, AuthenticationPanel, UrlList, AttachmentList, RawEmailViewer, MimeTree
  investigation/ InvestigationHeader, NotesPanel, DecisionLog
  evidence/      EvidenceCard, CustodyTimeline, IntegrityBadge
  graph/         EvidenceGraph (new)
  timeline/      TimelineEvent, Timeline (consolidate the two hand-rolled copies in EmailAnalysis + ForensicTimeline)
  intelligence/  EntityDrawer, IpIntelCard, DomainIntelCard, IndicatorCard
  reports/       ReportCard, ReportGenerateDialog (UI-ready, backend-pending)
  integrations/  GmailConnectionCard (exists, refine)
  security/      SessionsList, AuditLogTable (new)
  audit/         AuditLogRow (new)
```

## 7. Routing plan

Preserve every existing path exactly (no breaking changes to bookmarks/links already in use); replace `PlaceholderPage` usages one feature at a time with real implementations as backend support allows. Add `/unauthorized`. Do not add new top-level routes beyond what's already declared in `routes.tsx` unless a phase specifically requires it (e.g. `/threat-intelligence/ip/:ip` for the entity drawer's full-page fallback).

## 8. Feature status vs. product spec's 50 requested capabilities

- **Buildable now with real data**: Command Center stats, Email forensics (headers/MIME/URLs/attachments/raw), SPF/DMARC (honest PASS/FAIL), Cases list/detail, Alerts, Gmail integration flow, Evidence CRUD + chain-of-custody timeline, Investigation "intelligence" correlations, RBAC-aware navigation, audit log (via Case `/history` + a new global audit endpoint if needed).
- **UI-ready, must show honest partial state**: DKIM (label as heuristic, not cryptographic, with an explanatory tooltip), ML classification (show `NOT_AVAILABLE` gracefully), CTI verdicts (show `UNKNOWN`/`not_configured` gracefully), threat score factors (only real `RiskFactor` rows, no invented factors).
- **UI-ready but explicitly demo/future-state, never presented as live**: Geolocation map (no coordinates exist — show "Geolocation not yet available" empty state, not a fake pin), Blockchain evidence anchor (present as "Chain of Custody" only; do not fabricate a transaction hash), P1/P2/P3 vocabulary (presentation-layer mapping, not a backend field).
- **Needs new backend work before it can be real**: Global search, Settings page, Report generation/export/PDF, WebSocket/SSE live feed (dashboard will poll instead and be labeled accordingly), standalone IP/domain intelligence endpoints, IOC CRUD.

## 9. Decisions (resolved with the user)

1. **P1/P2/P3 mapping**: P1 = CRITICAL, P2 = HIGH, P3 = MEDIUM + LOW combined. Implemented as a presentation-only mapping in `apps/web/src/types/severity.ts` (`toPriorityTier`) — the backend `Priority` enum is untouched.
2. **Scope for this pass**: design system fixes + shell polish (CommandPalette/search/notifications) + Command Center dashboard rebuild. Stub pages (Investigations, Evidence Vault, Timeline, etc.) are deferred to a follow-up pass.
3. **Dependencies**: added `class-variance-authority` + `@radix-ui/react-{dialog,tabs,tooltip,select}` to `apps/web`. Dialog and Tooltip are wired in this pass; Tabs and Select are ready primitives for the stub-page pass.

## 10. Phase 2-4 implementation record (this pass)

- **Theme**: migrated `apps/web/src/index.css` to Tailwind v4 native `@theme` (removed the unwired `tailwind.config.js`); `security.*` severity tokens and the shadcn HSL variables are now a single source of truth and actually resolve.
- **UI kit**: consolidated the two colliding `Badge` implementations into one `components/ui/badge.tsx` (cva-based); moved the domain-specific badges into `components/threats/{PriorityBadge,SeverityBadge,ThreatScore}.tsx` and `components/evidence/IntegrityBadge.tsx`; added `Dialog`, `Tooltip`, `Tabs`, `Select` primitives; deleted dead `DemoModeBanner.tsx`.
- **Shell**: `CommandPalette` is now a real, working Ctrl/Cmd+K dialog (Radix Dialog, filters real nav items, navigates on select) shared via `CommandPaletteContext`; `Header`'s search button opens it; the notification bell is honestly disabled with a "coming soon" tooltip instead of being a dead click target; `Sidebar` and `CommandPalette` now share one nav source (`config/navigation.ts`).
- **Auth**: the previously-dead `auth:unauthorized` window event now actually clears session state; added the `/unauthorized` route `ProtectedRoute` already redirected to but which didn't exist.
- **Dashboard**: extended `GET /api/v1/dashboard/overview` (additive, real Prisma counts only) with `priorityBreakdown` (open cases by Priority), `emailsAnalyzed`, and `indicatorsTracked`. Rebuilt `Overview.tsx` with `StatCard`s, a real `PriorityDistribution` chart (finally uses the previously-unused `recharts` dependency), and a `PriorityBadge`-driven recent-incidents list. Removed the old "Threat timeline visualization is currently unavailable" fake placeholder panel in favor of the real priority chart.
- **Verified**: `pnpm --filter web build`, `pnpm --filter @ciperscope/api build`, and `pnpm --filter web lint` all pass. Login page visually confirmed in-browser against the new theme (dev server has no backend running in this environment — Docker Desktop is installed but its daemon isn't running, so the authenticated dashboard/shell could not be visually verified against live data here; someone with the local stack running should do a quick pass).
- **Deferred, not done this pass**: populating `packages/types`/`packages/api-client` as real shared packages; touching `EmailAnalysis.tsx`, `Alerts.tsx`, `Cases.tsx`, `Login.tsx` (still on the old raw `slate-*` classes rather than the new semantic tokens — functions fine, just visually inconsistent until their own pass); the known `EmailAnalysis.tsx` unreachable-fallback-URL bug; all 12 stub pages.

## 10. Testing/verification plan

`pnpm build` and `pnpm test` at the root (turbo-orchestrated) after each phase; manually exercise login → dashboard → email analysis → cases → integrations in the browser preview after each phase; no destructive DB operations planned (read-heavy work against existing seed data).
