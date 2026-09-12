# Phase 9: SPF / DKIM / DMARC Verification Implementation Plan

## 1. Existing Authentication Observations
Phase 8 extracted `Authentication-Results` headers (and others like `Received-SPF`, `DKIM-Signature`) as `EmailHeader` records. These are UNTRUSTED claims. The goal of Phase 9 is to independently verify SPF, DKIM, and DMARC through controlled DNS resolution, completely decoupling the **observed claim** from the **independent verification** and the final **forensic interpretation**.

## 2. SPF Requirements
- Determine source IP from the `RelayHop` chain (e.g., the earliest external untrusted hop connecting to our trusted boundary, following a strict documented policy).
- Retrieve SPF records via `TXT` lookups on the `Return-Path` (or `HELO` domain if `Return-Path` is missing).
- Safely parse and evaluate mechanisms (`ip4`, `ip6`, `a`, `mx`, `include`, `exists`, `all`), modifiers (`redirect`, `exp`), and qualifiers.
- Implement strict recursion depth limits (e.g., max 10 DNS lookups per RFC 7208).
- Handle timeout, `PERMERROR`, `TEMPERROR` explicitly.

## 3. DKIM Requirements
- Extract and parse all `DKIM-Signature` headers independently.
- Derive the public key DNS query: `<selector>._domainkey.<domain>`.
- Retrieve public key via `TXT` lookup.
- Verify canonicalization (relaxed/simple), signed headers, body hash (`bh`), and cryptographic signature (`b`).
- Support common algorithms (e.g., rsa-sha256).
- Handle missing signatures, invalid keys, revoked keys, and multiple signatures independently.
- Never execute or fetch URLs found in DKIM parameters.

## 4. DMARC Requirements
- Determine the Organizational Domain using a safe Public Suffix List strategy (not just naive last two labels).
- Query `_dmarc.<OrganizationalDomain>` via `TXT`.
- Extract policies (`p`, `sp`), alignment modes (`adkim`, `aspf`).
- Evaluate Alignment:
  - **SPF**: Authenticated SPF domain aligns with Header `From` domain (Strict = exact match, Relaxed = org domain match).
  - **DKIM**: Authenticated `d=` domain aligns with Header `From` domain (Strict vs Relaxed).
- DMARC PASS requires at least one aligned and passing mechanism (SPF or DKIM).

## 5. DNS Architecture
- Create a dedicated safe DNS resolver abstraction (`DnsResolver`).
- Centralize all `TXT`, `A`, `AAAA`, `MX` queries here.
- Enforce: Timeout per query (e.g., 2000ms), retry strategy, and size limits on responses.
- Implement local caching per-analysis with strict short TTL to prevent tenant cross-contamination.

## 6. Verification Workflow
1. **Trigger**: A new queue job `email-authentication-verification` is dispatched.
2. **Metadata Gathering**: Worker fetches `Email`, `EmailHeader`, `RelayHop`, `MimePart` from Prisma.
3. **Controlled DNS Verification**: 
   - Perform SPF verification.
   - Perform DKIM verification.
   - Perform DMARC verification based on SPF/DKIM results.
4. **Persistence**: Save results to explicit database tables (`SpfVerification`, `DkimVerification`, `DmarcVerification`).
5. **Inference**: Generate a forensic interpretation (e.g., mismatch between claim and verification).

## 7. Database Changes
Modify `packages/database/prisma/schema.prisma` to normalize authentication evidence.
- Remove the simple `AuthenticationResult` model and replace with:
  - `EmailAuthenticationAnalysis` (Overall status & DMARC alignment result)
  - `SpfVerification` (Result, evaluated IP, domain, matched mechanism, DNS evidence)
  - `DkimVerification` (Result, `d=`, `s=`, body hash result, signature result, DNS evidence)
  - `DmarcVerification` (Result, policy, alignment mode, SPF alignment, DKIM alignment)
  - `DnsObservation` (Query, type, response, TTL)

## 8. Worker Changes
- Create `services/worker/src/verifier/` containing `AuthenticationVerifier.ts`, `SpfVerifier.ts`, `DkimVerifier.ts`, and `DmarcVerifier.ts`.
- Integrate `DnsResolver` with the limits.
- Ensure the worker operates idempotently and uses the `IdempotencyManager`.

## 9. Queue Changes
- Add a new payload type: `EmailAuthenticationVerificationJobPayload`.
- Add a new queue: `email-authentication`.

## 10. API Changes
- Add endpoints to `services/api/src/modules/email/email.routes.ts`:
  - `GET /:emailId/authentication`
  - `GET /:emailId/spf`
  - `GET /:emailId/dkim`
  - `GET /:emailId/dmarc`
- Ensure all endpoints validate `x-organization-id` and check tenant ownership via `EMAIL_READ`.

## 11. UI Changes
- Web (`apps/web/src/pages/EmailAnalysis.tsx`): Add an **Email Authentication** section with dedicated tabs/panels for SPF, DKIM, and DMARC.
- Visually contrast **Header Claims** vs **Independent Verification**.
- Show the **Forensic Interpretation** highlighting inconsistencies.

## 12. Security Boundaries
- **ONLY DNS resolution is allowed**. Absolute prohibition of HTTP/HTTPS/WHOIS/Geolocation.
- Treat all `Authentication-Results` and `DKIM-Signature` values as attacker-controlled.
- No execution of email payloads or JavaScript.

## 13. Caching & Rate Limiting
- Cache DNS responses in a safe `DnsCache` memory store during the lifecycle of a single email verification to avoid redundant lookups (e.g., same include).
- Rate limits: Max DNS lookups per verification (e.g., 50 total).
- Recursion depth limit: 10 for SPF.

## 14. Timeout Handling
- Enforce an absolute global timeout for the entire verification job (e.g., 10 seconds).
- Return explicit `TEMPERROR` or `UNAVAILABLE` on DNS timeout, ensuring failures do not result in false `PASS`.

## 15. Testing Strategy
- **Unit Tests**: Mock `DnsResolver` to test all SPF/DKIM/DMARC scenarios (pass, fail, softfail, limits, cyclic includes, malformed signatures).
- **Integration Tests**: Verify database persistence and API retrieval.
- **Security Tests**: Prove that HTTP URLs inside the email do not trigger HTTP requests (SSRF prevention).
