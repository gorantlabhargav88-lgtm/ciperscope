# Phase 8: MIME & Email Header Forensics

## Overview
Phase 8 implements the capability to safely extract and parse forensic metadata from ingested raw `.eml` objects. The parsed data is structured and stored in a normalized format in PostgreSQL while adhering to strict security constraints.

## Architecture & Data Models
The `Email` model has been expanded to support a structured forensic graph:
- **`EmailHeader`**: Captures every header with an `index` to preserve exact ordering and duplicate entries.
- **`EmailAddress`**: Stores normalized representations (display name, local part, domain) of structural addresses (From, To, Cc, etc.).
- **`RelayHop`**: Parses `Received` headers to extract network metadata (source IP, receiving/sending hosts, timestamps) to build a transport trace.
- **`MimePart`**: Extracts the hierarchy of the email (text, HTML, and attachments) without saving the raw content inside PostgreSQL, ensuring memory efficiency and protecting the database from excessively large blobs.

An `AnalysisState` enumeration tracks the lifecycle of an email through `PENDING`, `PROCESSING`, `COMPLETED`, `PARTIAL`, and `FAILED` states.

## Security Constraints
The `EmailForensicParser` utilizes `mailparser` under strict configurations to ensure:
- **SSRF Prevention:** The parser absolutely does not fetch external resources like images, CSS, or related parts.
- **Resource Limits:** Streaming is used to read the payload, which is bound by the Phase 7 `30MB` ingestion limit.
- **No Remote Intel:** All parsed properties are treated strictly as *observations*, with no DNS, WHOIS, or live threat-intelligence requests executed during the parse phase.

## Extensibility
The API layer exposes RESTful endpoints (`/analysis`, `/headers`, `/received-hops`, `/mime-parts`) which have been integrated into the frontend `EmailAnalysis.tsx` dashboard. The UI now dynamically polls and presents the structural metadata instantly after ingestion.
