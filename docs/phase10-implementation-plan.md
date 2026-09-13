# Phase 10 Implementation Plan: URL & Attachment Threat Analysis

## 1. Current Architecture Findings
- **Storage:** Emails are successfully ingested in Phase 7 via `EmailForensicParser`. Raw blobs are stored in an object store (currently `LocalRawEmailStore`) and deduplicated via SHA-256.
- **Parsing:** `EmailForensicParser` safely parses emails using `mailparser` with strict options (`skipImageLinks: true`, `skipHtmlToText: true`). It currently builds a flattened list of MIME parts.
- **Database:** `schema.prisma` already defines `EmailUrl` and `EmailAttachment` models, but they are not fully populated or analyzed by the parser yet. Models for `Indicator` and `ThreatIntelObservation` also exist.
- **Workers:** Job processing follows a robust pattern using BullMQ with `createTenantScopedWorker` and `IdempotencyManager`. The Phase 9 `email-authentication` queue successfully validates emails via DNS passively.

## 2. Phase 10 Goals
- Safely extract URLs from text and HTML MIME parts.
- Distinguish and record the *observed* URL versus the *normalized* URL.
- Implement passive attachment analysis to extract metadata, calculate SHA-256 hashes, and verify magic bytes (file signatures).
- Detect file type mismatches (e.g., an executable disguised as a `.pdf`).
- Safely inspect archive attachments (e.g., ZIP) by reading metadata only, strictly avoiding decompression and execution.
- Persist extracted URLs and attachment metadata to PostgreSQL.

## 3. Explicit Non-Goals
- **No Network Requests:** DO NOT fetch URLs, follow redirects, or resolve hostnames (prevents SSRF).
- **No External APIs:** DO NOT use VirusTotal, Safe Browsing, PhishTank, WHOIS, or Geolocation APIs.
- **No Execution:** DO NOT detonate malware, execute scripts, macros, or launch office applications/browsers.
- **No Advanced AI/Blockchain:** DO NOT implement DistilBERT, Gemini threat explanations, or blockchain anchoring.
- **No URL Reputation Scoring:** DO NOT assign threat verdicts merely because a URL appears unusual.

## 4. URL Extraction Architecture
- Implement a passive `UrlExtractor` service.
- **Inputs:** `MimePart` entries for `text/plain` and `text/html`.
- **Methodology:** Use a safe regex or HTML parser to extract `href` attributes and plain text URLs.
- Exclude `src` attributes of images unless explicitly defining an indicator, but prioritize `href`.

## 5. URL Normalization Architecture
- Retain the **Observed URL** exactly as it appeared in the email.
- Parse the URL using Node.js native `URL` class to generate the **Normalized URL**.
- Filter schemes strictly: Keep only `http:` and `https:`. Reject `javascript:`, `data:`, `file:`, `vbs:`, `blob:`, etc.
- Detect URL obfuscation (percent-encoding, hex IP literals, unusual ports, credentials in URL) and flag them as *indicators* (SUSPICIOUS), not malicious verdicts.

## 6. HTML Safety Model
- Use a safe SAX/DOM parser (e.g., `cheerio` or `htmlparser2`) for HTML extraction.
- **Strictly Passive:** The parser will only walk the DOM tree to extract attributes. It will never execute embedded JavaScript or resolve CSS.
- Input size limits will be enforced to prevent memory exhaustion when parsing large HTML payloads.

## 7. Attachment Analysis Architecture
- Create an `AttachmentAnalyzer` service.
- Will operate on `MimePart` records where `isAttachment` is true.
- Calculate SHA-256 for all attachments based on raw decoded bytes (without modifying them).
- Read the first 4KB of the attachment stream to determine magic bytes/file signatures.
- Do not store raw attachment bytes in PostgreSQL or Redis; keep them in the object store.

## 8. File Signature Strategy
- Compare the declared MIME type and file extension against the actual file signature (magic bytes).
- Flag discrepancies (e.g., declared `application/pdf` but bytes indicate `MZ` executable) as `SUSPICIOUS` mismatches.
- Categorize potentially dangerous types (PE executables, scripts, macros).

## 9. Archive Safety Strategy
- Inspect standard archives (ZIP) using a safe, metadata-only parser (e.g., `yauzl`).
- **No Extraction:** Do not decompress files to disk. Only read the Central Directory.
- **Mitigations:** Reject archives with > 1000 entries, nested archives, or extreme compression ratios (Zip bombs).
- Detect and flag path traversal attempts (e.g., `../../file.exe`) in archive filenames.

## 10. Resource Limits
- **Max Extracted URLs:** 1000 per email.
- **Max URL Length:** 2048 characters.
- **Max HTML Parsing Size:** 5 MB.
- **Max Archive Entries:** 1000 files.
- **Max Uncompressed Size (Metadata check):** 50 MB.
- **Max Nesting Depth:** 0 (reject recursive archives).
- **Execution Time:** Fail safe if parsing exceeds a predefined timeout.

## 11. Queue/Worker Flow
- Introduce a new queue: `email-threat-analysis`.
- Triggered after Phase 9 `email-authentication` or in parallel.
- Job payloads will only contain IDs (`emailId`, `organizationId`).
- Maintains idempotency through the existing `IdempotencyManager`.
- If raw bytes are required for hashing, the worker streams them directly from `LocalRawEmailStore`.

## 12. Database Proposal
Extend existing schema models:
- **EmailUrl:** Add `normalizedUrl`, `isObfuscated`, `indicators` (JSON).
- **EmailAttachment:** Add `actualMimeType`, `isMismatch`, `magicBytes`, `isArchive`, and `archiveMetadata` (JSON).
No major new tables are required; existing models can be enhanced efficiently.

## 13. API Proposal
New endpoints, scoped to `organizationId` with strict RBAC:
- `GET /api/v1/emails/:emailId/urls`
- `GET /api/v1/emails/:emailId/attachments`
- `GET /api/v1/emails/:emailId/attachments/:attachmentId`

## 14. Web UI Proposal
Add a "Threat Analysis" section to `EmailAnalysis.tsx`:
- **URL Indicators:** Table showing Observed vs Normalized URLs, and highlighting suspicious encodings.
- **Attachment Inventory:** Table displaying declared vs actual MIME types, SHA-256 hashes, and mismatched alerts.

## 15. Mobile Proposal
- Consume the new API endpoints.
- Provide a simplified list view of URLs and Attachments on the Email Details screen.

## 16. Security Threat Model
- **SSRF:** Mitigated by prohibiting any external network requests (`fetch`, `axios`).
- **RCE / Malware Execution:** Mitigated by strictly passive file signature and metadata analysis.
- **Resource Exhaustion (Zip Bombs/OOM):** Mitigated by reading only archive metadata, stream-based hashing, and strict limits.
- **Path Traversal:** Mitigated by not writing attachments to the local filesystem and explicitly checking archive entry names.

## 17. Dependency Analysis
- **`file-type`**: Pure JS module to detect magic bytes safely. Maintained, safe, no native bindings.
- **`cheerio` or `htmlparser2`**: Lightweight, non-executing HTML parsers. Safe, well-tested.
- **`yauzl`**: Recommended for safe, unzipping/metadata extraction because it prevents buffering entire files and provides robust zip bomb protections.

## 18. Test Strategy
- **URLs:** Test extraction of malformed URLs, IP literals, dangerous schemes (`javascript:`), and obfuscated paths.
- **HTML:** Test against extremely large HTML and script tags to ensure no execution.
- **Attachments:** Test extension mismatches (fake PDFs), oversized attachments.
- **Archives:** Test zip bombs, recursive zips, and path traversal entries (e.g., `../../bin/sh`).
- **Security:** Ensure no network calls or local file creations occur during the pipeline.

## 19. Migration Strategy
- Write standard Prisma schema updates for `EmailUrl` and `EmailAttachment`.
- Apply migrations using the established `prisma migrate dev` process during the implementation phase.

## 20. Acceptance Criteria
- Phase 10 worker successfully extracts URLs and attachments without executing code or making network calls.
- File type mismatches are correctly identified.
- Archives are safely parsed for metadata without decompression.
- Web UI accurately reflects the extraction data.

## 21. Risks and Mitigations
- *Risk:* Complex URL obfuscation causing false positives.
  *Mitigation:* Clearly label unusual patterns as "Suspicious Indicators," not "Malicious," leaving attribution to later phases.
- *Risk:* Vulnerability in HTML or ZIP parsing libraries.
  *Mitigation:* Use widely vetted, passive libraries and enforce strict resource bounds on input sizes.

## 22. Phase 10 Completion Checklist
- [ ] Prisma schema updates and database migration.
- [ ] Safe URL Extractor implementation.
- [ ] Safe HTML parsing integration.
- [ ] Magic-byte Attachment Analyzer implementation.
- [ ] Metadata-only Archive parser integration.
- [ ] `email-threat-analysis` worker logic.
- [ ] API endpoints implementation.
- [ ] Web UI updates.
- [ ] Mobile UI updates.
- [ ] Security test coverage (SSRF/Zip Bomb prevention).
